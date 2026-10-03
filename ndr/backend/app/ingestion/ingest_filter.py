"""入库前降噪过滤：命中则**不投检测器**，但事件照常进 Elasticsearch。

为什么作用点选在归一化之后、规则之前：这里挡的是海量已知噪声（内网扫描器、监控探活、
心跳域名、办公网固定 UA），省掉的是「检测器 → 摘要 → 模型」整条链路的钱；而 ES 仍是
全量事实源，被挡下的事件在 NDR 界面上照样查得到，只是不会形成告警。这与「排除过滤」
（`app/ingestion/exclusion.py`，在规则命中之后决定要不要跑模型）是**两道不同的闸门**，
语义必须分清：这里回答「值得进检测器吗」，那里回答「值得花钱分析吗」。

条件语法与规则/排除过滤完全一致（复用 `app.rules.engine.evaluate_conditions`），但作用域
只有日志自身字段 —— 此时规则还没跑，所以没有 hit_rule / rule_source / rule_severity。

失效策略：读配置与求值异常一律 **fail-open（照常投检测器）** —— 一条写错的条件宁可白跑
检测器，也绝不把真实攻击静默挡在检测器之外。
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from app.config import settings
from app.db.base import SessionLocal
from app.db.models import IngestFilter
from app.ingestion.normalizer import normalize, source_of
from app.rules.engine import VIRTUAL_FIELDS, evaluate_conditions, validate_rule_regexes
from app.schemas import UnifiedLog
from app.workers.log import get_logger

log = get_logger(__name__)

# 地址与端口：降噪最常用的维度（「内网某台扫描器打过来的全不要」）
ADDRESS_FIELDS = ("src_ip", "dst_ip", "src_port", "dst_port")

# 协议内容字段：让「某个心跳域名」「监控探活的 UA」这类噪声也能精确表达。
# 刻意不含 raw：原文体积大、结构随来源变，把某次抓包的细节写成条件等于埋雷。
CONTENT_FIELDS = (
    "source_system",
    "log_type",
    "event_type",
    "protocol",
    "conn_state",
    "hostname",
    "user",
    "account",
    "process",
    "command",
    "query",
    "uri_path",
    "query_string",
    "method",
    "body",
    "referer",
    "cookie",
    "user_agent",
    "content_type",
    "status_code",
    "resp_mime",
    "qtype",
    "filename",
    "mime_type",
    "ja3",
    "ja3s",
    "tls_version",
    "cert_issuer",
    "bytes_in",
    "bytes_out",
    "rule_id",
    "rule_groups",
    "mitre",
    "severity",
    "summary",
)

_STATS_KEY = "shentong:ingestfilter:stats"  # hash：过滤器名 -> 命中次数
_SAMPLES_KEY = "shentong:ingestfilter:samples"  # hash：过滤器名 -> JSON 样例列表
_TTL = 30 * 24 * 3600
_MAX_SAMPLES = 3
_DRY_RUN_SAMPLES = 10
_DRY_RUN_LIMIT_MAX = 5000

_cache: tuple[float, list[dict[str, Any]]] = (0.0, [])
_client_cache: Any | None = None


def allowed_fields() -> set[str]:
    """允许在降噪条件里引用的字段：地址 + 端口 + 协议内容 + 内外网方向虚拟字段。

    方向字段（src_internal / dst_internal / src_external / dst_external）让「内外有别」
    的降噪不必写死客户网段。
    """
    return set(ADDRESS_FIELDS) | set(CONTENT_FIELDS) | set(VIRTUAL_FIELDS)


def _walk_fields(conds: Any, out: list[str]) -> None:
    if isinstance(conds, list):
        for item in conds:
            _walk_fields(item, out)
        return
    if not isinstance(conds, dict):
        return
    if "not" in conds:
        _walk_fields(conds["not"], out)
    if conds.get("field"):
        out.append(str(conds["field"]))
    for item in conds.get("rules") or []:
        _walk_fields(item, out)


def validate_conditions(conditions: dict[str, Any] | None) -> list[str]:
    """保存前校验，返回错误列表（空 = 通过）。三道保险防「一条配置静音整条检测链路」。"""
    errors: list[str] = []
    cond = conditions or {}
    if not cond.get("rules"):
        errors.append("降噪条件不能为空（不允许无条件过滤掉一切）")
        return errors

    fields: list[str] = []
    _walk_fields({"rules": cond.get("rules") or []}, fields)
    allowed = allowed_fields()
    unknown = sorted({f for f in fields if f not in allowed})
    if unknown:
        errors.append(f"不支持的字段：{', '.join(unknown)}")

    errors.extend(validate_rule_regexes({"conditions": cond}))
    return errors


def _client() -> Any | None:
    """懒加载 Redis 客户端（命中统计 + 队列取样）；不可用时返回 None（统计降级，不影响过滤）。"""
    global _client_cache
    if _client_cache is not None:
        return _client_cache
    try:
        import redis

        client: Any = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        client.ping()
    except Exception as exc:  # noqa: BLE001
        log.debug("降噪过滤统计不可用（Redis 未就绪）: %s", exc)
        return None
    _client_cache = client
    return client


def load_filters(force: bool = False) -> list[dict[str, Any]]:
    """取启用中的过滤器（按 priority 升序），带缓存；DB 异常时沿用上次缓存。"""
    global _cache
    now = time.time()
    ts, cached = _cache
    if not force and cached and now - ts < max(0, settings.ingest_filter_cache_seconds):
        return cached
    try:
        with SessionLocal() as db:
            rows = (
                db.execute(
                    select(IngestFilter)
                    .where(IngestFilter.enabled.is_(True))
                    .order_by(IngestFilter.priority)
                )
                .scalars()
                .all()
            )
            items = [{"id": r.id, "name": r.name, "conditions": r.conditions or {}} for r in rows]
    except Exception as exc:  # noqa: BLE001
        log.warning("读取降噪过滤器失败，沿用上次配置（%d 条）: %s", len(cached), exc)
        return cached
    _cache = (now, items)
    return items


def invalidate_cache() -> None:
    """清缓存（本进程立即生效；其他进程最迟 ingest_filter_cache_seconds 后生效）。"""
    global _cache
    _cache = (0.0, [])


def match(entry: UnifiedLog) -> str | None:
    """命中则返回过滤器名，否则 None；任何异常都按「未命中」处理（fail-open 投检测器）。"""
    filters = load_filters()
    if not filters:
        return None
    for item in filters:
        cond = item.get("conditions") or {}
        if not cond.get("rules"):
            continue  # 空条件跳过（保存时已拒绝，这里双保险）
        try:
            if evaluate_conditions(cond, entry):
                return str(item.get("name") or "")
        except Exception as exc:  # noqa: BLE001
            log.warning("降噪过滤求值失败（按未命中处理）%s: %s", item.get("name"), exc)
    return None


def record_hit(name: str, entry: UnifiedLog) -> None:
    """记录命中次数与样例（最多 3 条），供界面回答「到底挡掉了什么」。"""
    if not name:
        return
    client = _client()
    if client is None:
        return
    try:
        client.hincrby(_STATS_KEY, name, 1)
        client.hset(_STATS_KEY, "last_hit_at", datetime.now(UTC).isoformat())
        client.expire(_STATS_KEY, _TTL)

        raw = client.hget(_SAMPLES_KEY, name)
        samples: list[dict[str, Any]] = []
        if raw:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    samples = parsed
            except (TypeError, ValueError):
                samples = []
        if len(samples) < _MAX_SAMPLES:
            samples.append(_sample(entry))
            client.hset(_SAMPLES_KEY, name, json.dumps(samples, ensure_ascii=False))
        client.expire(_SAMPLES_KEY, _TTL)
    except Exception as exc:  # noqa: BLE001
        log.debug("写入降噪命中统计失败: %s", exc)


def _sample(entry: UnifiedLog, ref: str = "") -> dict[str, Any]:
    return {
        "at": datetime.now(UTC).isoformat(),
        "ref": ref,
        "ts": entry.ts.isoformat() if entry.ts else "",
        "source_system": entry.source_system,
        "event_type": entry.event_type,
        "src_ip": entry.src_ip or "",
        "dst_ip": entry.dst_ip or "",
        "src_port": entry.src_port,
        "dst_port": entry.dst_port,
        "protocol": entry.protocol or "",
        "summary": (entry.summary or "")[:200],
    }


def get_stats() -> dict[str, Any]:
    """命中统计（过滤器名 -> 次数 + 最近命中时间）。"""
    client = _client()
    out: dict[str, Any] = {"counts": {}, "last_hit_at": None}
    if client is None:
        return out
    try:
        raw = client.hgetall(_STATS_KEY)
        for key, val in raw.items():
            if key == "last_hit_at":
                out["last_hit_at"] = val
            elif str(val).isdigit():
                out["counts"][key] = int(val)
    except Exception as exc:  # noqa: BLE001
        log.warning("读取降噪命中统计失败: %s", exc)
    return out


def get_samples() -> dict[str, list[dict[str, Any]]]:
    """每过滤器最近命中的样例（最多 3 条）。"""
    client = _client()
    out: dict[str, list[dict[str, Any]]] = {}
    if client is None:
        return out
    try:
        for name, raw in client.hgetall(_SAMPLES_KEY).items():
            try:
                parsed = json.loads(raw)
            except (TypeError, ValueError):
                continue
            if isinstance(parsed, list):
                out[name] = parsed
    except Exception as exc:  # noqa: BLE001
        log.warning("读取降噪命中样例失败: %s", exc)
    return out


# ---------- 试运行（干跑） ----------


def _from_queue(client: Any, key: str, limit: int) -> list[tuple[dict[str, Any], str]]:
    """从队列取样（从左端取）。检测器队列里已是归一化文档，采集队列里是原始文档。

    方向说明：检测器队列是我们自己 LPUSH 的（左端最新），采集队列是 Filebeat RPUSH 的
    （左端最旧）。试运行只是取样，两种方向都只是「取到一批最近的样本」，不影响正确性。
    """
    try:
        items = client.lrange(key, 0, max(0, limit - 1))
    except Exception as exc:  # noqa: BLE001
        log.debug("试运行读队列 %s 失败: %s", key, exc)
        return []
    out: list[tuple[dict[str, Any], str]] = []
    for item in items:
        try:
            doc = json.loads(item)
        except (TypeError, ValueError):
            continue
        if isinstance(doc, dict):
            out.append((doc, ""))
    return out


def _recent_docs(hours: int, limit: int) -> tuple[list[tuple[dict[str, Any], str]], str]:
    """取一批「最近的历史事件」给试运行用，返回 (文档+ref, 取样来源)。

    顺序有讲究：**先 ES**（真实全量、能按时间窗筛），ES 没数据或连不上时退到队列
    （刚部署、还没入库时也能先试条件 —— 这正是上线前最需要试的时候）。
    """
    start = datetime.now(UTC) - timedelta(hours=max(1, hours))
    try:
        from app.ingestion import es_config
        from app.ingestion.es_client import get_es

        # 索引名走运行时配置（DB 覆盖 env），与 es_query/wazuh/ndr_tools 一致：
        # 后台改了 es.events_index 后这里必须跟着变，否则会出现「采集有数但试运行查不到」。
        cfg = es_config.current()
        resp = get_es().search(
            index=str(cfg.get("es.events_index") or settings.es_events_index),
            query={"range": {"@timestamp": {"gte": start.isoformat()}}},
            sort=[{"@timestamp": "desc"}],
            size=limit,
        )
        hits = (resp.get("hits") or {}).get("hits") or []
        docs = [
            (h.get("_source") or {}, f"es:{h.get('_index', '')}/{h.get('_id', '')}")
            for h in hits
            if isinstance(h.get("_source"), dict)
        ]
        if docs:
            return docs, "es"
    except Exception as exc:  # noqa: BLE001
        log.info("试运行读 ES 失败，改用队列取样：%s", exc)

    client = _client()
    if client is None:
        return [], "none"
    for key, tag in (
        (settings.detector_raw_queue, "detector_queue"),
        (settings.collector_collect_queue, "collect_queue"),
    ):
        docs = _from_queue(client, key, limit)
        if docs:
            return docs, tag
    return [], "none"


def _as_entry(doc: dict[str, Any]) -> UnifiedLog | None:
    """文档 → UnifiedLog：带齐归一化标记的直接校验，否则当作原始文档再归一化一次。"""
    if "source_system" in doc and "event_type" in doc and "raw" in doc:
        try:
            return UnifiedLog.model_validate(doc)
        except Exception as exc:  # noqa: BLE001
            log.debug("试运行：归一化文档校验失败，按原始文档再归一化一次（%s）", exc)
    try:
        return normalize(source_of(doc), doc)
    except Exception as exc:  # noqa: BLE001
        log.debug("试运行归一化失败: %s", exc)
        return None


def dry_run(
    conditions: dict[str, Any] | None,
    *,
    hours: int = 0,
    limit: int = 0,
    exclude_name: str = "",
) -> dict[str, Any]:
    """试运行：拿最近的历史事件跑一遍条件，回答「启用后大概会挡掉什么」。

    为什么要它：过滤条件是最容易「配错就静默漏报」的一类开关，先看命中样例再启用，
    比事后翻告警找「为什么没告警」便宜得多。
    """
    errors = validate_conditions(conditions)
    if errors:
        return {"error": "；".join(errors), "errors": errors}

    hours = hours or settings.ingest_filter_dry_run_hours
    limit = min(limit or settings.ingest_filter_dry_run_max, _DRY_RUN_LIMIT_MAX)
    docs, source = _recent_docs(hours, limit)
    cond = {"rules": (conditions or {}).get("rules") or []}

    scanned = 0
    matched = 0
    samples: list[dict[str, Any]] = []
    for doc, ref in docs:
        entry = _as_entry(doc)
        if entry is None:
            continue
        scanned += 1
        try:
            if not evaluate_conditions(cond, entry):
                continue
        except Exception as exc:  # noqa: BLE001
            log.debug("试运行求值失败（按未命中处理）: %s", exc)
            continue
        matched += 1
        if len(samples) < _DRY_RUN_SAMPLES:
            samples.append(_sample(entry, ref))

    if source == "none":
        hint = "没取到可试的事件（ES 里还没有数据、队列也是空的）。先让链路跑一会儿再来试。"
    elif matched == 0:
        hint = f"最近 {hours} 小时里没有命中的事件 —— 条件可能写得过窄，或这条噪声还没出现。"
    else:
        hint = (
            f"最近 {hours} 小时的 {scanned} 条事件里会挡掉 {matched} 条"
            "（仍会进 ES，只是不产生告警）。确认样例符合预期再启用。"
        )
    return {
        "source": source,
        "hours": hours,
        "scanned": scanned,
        "matched": matched,
        "ratio": round(matched / scanned, 4) if scanned else 0.0,
        "samples": samples,
        "exclude_name": exclude_name,
        "hint": hint,
    }
