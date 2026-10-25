"""NDR 自己的调查工具：事件、规则、检测器状态、网段、排除过滤、结论写回、基线。

与 `app/investigation/tools.py` 那 10 个「查 ES」的工具不同，这些查的是 **NDR 自身的
运行状态与配置** —— 智能体在别处（案件库、资产、情报、记忆）拿不到，只能问 NDR。

统一签名 `run(params: dict) -> dict`，**没有 ctx**：这些是无状态纯函数，参数进、结果出。
MCP 层拿到结果后统一转成 JSON 文本给模型。
"""

from __future__ import annotations

import base64
import time
from datetime import datetime, timezone
from typing import Any

import redis
from sqlalchemy import select

from app.config import settings
from app.mcpapi import (
    ConclusionRecord,
    ExclusionFilter,
    IngestFilter,
    Rule,
    analysis_anchors,
    analysis_get_trace,
    analysis_log_step,
    analysis_params,
    analysis_queue,
    analysis_search_traces,
    analysis_status_values,
    analysis_subjects,
    analysis_task_state,
    asset_context_by_ips,
    asset_records,
    build_networks,
    catalog,
    conclusion_value_aliases,
    detector_health,
    es_client,
    es_config,
    get_hit_event,
    hit_clusters,
    hit_source_labels,
    hit_stats,
    in_scope,
    is_valid_fuid,
    list_analysis_results,
    list_hit_events,
    list_profiles,
    lookup_extract,
    monitored_nets,
    networks_status,
    record_profile_disposition,
    relay_inventory,
    resolve_extract_path,
    rule_inventory,
    session_factory,
    stats_lookup,
    suppression,
    top_anomalies,
)

#: 抑制允许的匹配字段（唯一来源是 `detector.suppression.ALLOWED_FIELDS`，不另抄一份）
ALLOWED_SUPPRESSION_FIELDS = suppression.ALLOWED_FIELDS

#: 等价于 3.11 的 `datetime.UTC`（本仓库 requires-python >=3.11）；用别名写法
#: 免得按旧语法解析的静态检查工具报「unknown import symbol」。
UTC = timezone.utc


def _client() -> Any:
    """Redis 客户端。

    返回类型刻意写成 `Any`：redis-py 把同步命令的返回注解成 `Awaitable[T] | T`，
    不这么写每处调用都要挂 `# pyright: ignore`（`api/routes/detector.py` 里就是那么干的）。
    """
    return redis.Redis.from_url(settings.redis_url, decode_responses=True)


def _hint(client: Any, key: str, field: str, default: int = 0) -> int:
    try:
        return int(client.hget(key, field) or default)
    except (TypeError, ValueError, redis.RedisError):
        return default


def _hstr(client: Any, key: str, field: str) -> str:
    try:
        return str(client.hget(key, field) or "")
    except (TypeError, redis.RedisError):
        return ""


def _llen(client: Any, key: str) -> int:
    try:
        return int(client.llen(key) or 0)
    except (TypeError, ValueError, redis.RedisError):
        return 0


# ---------- get_event ----------


def _get_event(args: dict[str, Any]) -> dict[str, Any]:
    """按事件ID 或指纹取「这条事件已经有哪些结论」。"""
    event_id = str(args.get("event_id") or "").strip()[:64]
    fingerprint = str(args.get("fingerprint") or "").strip()[:64]
    if not event_id and not fingerprint:
        return {"error": "event_id 与 fingerprint 至少给一个（先用 search_hits 按对象/时间捞事件）"}

    out: dict[str, Any] = {"event_id": event_id, "fingerprint": fingerprint}
    with session_factory() as db:
        rows: list[ConclusionRecord] = []
        if fingerprint:
            rows = list(
                db.execute(
                    select(ConclusionRecord)
                    .where(ConclusionRecord.fingerprint == fingerprint)
                    .order_by(ConclusionRecord.updated_at.desc())
                    .limit(settings.mcp_max_rows)
                )
                .scalars()
                .all()
            )
        if not rows and event_id:
            rows = list(
                db.execute(
                    select(ConclusionRecord)
                    .where(ConclusionRecord.event_id == event_id)
                    .order_by(ConclusionRecord.updated_at.desc())
                    .limit(settings.mcp_max_rows)
                )
                .scalars()
                .all()
            )
        out["conclusions"] = [
            {
                "id": str(r.id),
                "dedup_key": r.dedup_key,
                "event_id": r.event_id,
                "fingerprint": r.fingerprint,
                "thread_id": r.thread_id,
                "status": r.status,
                "severity": r.severity,
                "summary": r.summary,
                "detail": r.detail or {},
                "updated_at": r.updated_at.isoformat() if r.updated_at else "",
            }
            for r in rows
        ]

        if fingerprint:
            # 第 5 期起判重下放到智能体（按事件组指纹），NDR 侧**不再记录投递指纹**，
            # 所以这里没有"被投递过什么"可返回。以前它返回一个只有 note 的 dispatch 块，
            # 看着像有数据实则恒空（2026-10 MCP QA）：改为一句顶层说明，不再放假结构。
            out["delivery_note"] = (
                "NDR 侧不记录投递指纹（判重在智能体侧按事件组指纹做）；"
                "投递/分析状态请看智能体的分析记录。本工具只回结论。"
            )

    if not out["conclusions"]:
        out["note"] = "没有这条事件的结论：ID 可能不对，或结论已过保留期被清掉。"
    return out


# ---------- get_rule ----------


def _get_rule(args: dict[str, Any]) -> dict[str, Any]:
    """按规则名或规则 ID 取规则原文（智能体判断「这条摘要为什么被判可疑」时的依据）。"""
    name = str(args.get("name") or "").strip()[:128]
    rule_id = str(args.get("rule_id") or "").strip()[:64]
    if not name and not rule_id:
        return {"error": "name 与 rule_id 至少给一个"}
    with session_factory() as db:
        row = None
        if rule_id:
            row = db.get(Rule, rule_id)
        if row is None and name:
            row = db.execute(select(Rule).where(Rule.name == name)).scalar_one_or_none()
        if row is None:
            return {"error": f"没有找到规则 {name or rule_id}（规则名要完全一致）"}
        return {
            "id": str(row.id),
            "name": row.name,
            "description": row.description,
            "severity": row.severity,
            "source": row.source,
            "enabled": bool(row.enabled),
            "priority": int(row.priority or 0),
            "conditions": row.conditions or {},
        }


# ---------- detector_status ----------


def _detector_status(args: dict[str, Any]) -> dict[str, Any]:
    """检测器现在的状态：队列积压、吞吐、丢弃/去重/失败计数、主从、内存。

    字段口径与 `api/routes/detector.py` 完全一致（同一个 `shentong:detector:rates` 哈希），
    这样界面看到和智能体看到的不会出现两套数字。
    """
    client = _client()
    raw = settings.detector_raw_queue
    digest = settings.detector_digest_queue
    processing = settings.detector_processing_queue
    interval = _hint(client, "shentong:detector:rates", "interval_seconds", 60)
    interval = max(1, interval)

    def per_min(field: str) -> float:
        # 速率用「区间增量 ÷ 区间秒数」反推：直接拿累计值除以运行时长会算出
        # 远超理论上限的数字（route 里有注释记过这个坑）。
        delta = _hint(client, "shentong:detector:rates", f"d_{field}")
        return round(delta * 60.0 / interval, 2)

    status: dict[str, Any] = {
        "queues": {
            "raw": _llen(client, raw),
            "digest": _llen(client, digest),
            "processing": _llen(client, processing),
            "raw_limit": settings.detector_raw_queue_max,
        },
        "rates_per_minute": {
            "scanned": per_min("scanned"),
            "hit": per_min("hit"),
            "digest": per_min("digest"),
            "delivered": per_min("delivered"),
            "digest_limit": settings.detector_max_digests_per_minute,
        },
        "cumulative": {
            "scanned": _hint(client, "shentong:detector:rates", "scanned"),
            "hit": _hint(client, "shentong:detector:rates", "hit"),
            "digest": _hint(client, "shentong:detector:rates", "digest"),
            "delivered": _hint(client, "shentong:detector:rates", "delivered"),
            "raw_trimmed": _hint(client, "shentong:detector:rates", "raw_trimmed"),
            "requeued": _hint(client, "shentong:detector:rates", "requeued"),
        },
        "dropped": {
            "count": _hint(client, settings.detector_drop_key, "dropped"),
            "last_at": _hstr(client, settings.detector_drop_key, "last_dropped_at"),
        },
        "task_failed": {
            "failed": _hint(client, settings.detector_task_failed_key, "failed"),
            "last_at": _hstr(client, settings.detector_task_failed_key, "last_failed_at"),
        },
    }

    # 选主：只有持锁的那个实例在跑检测，判断「检测器是不是活着」看这里
    try:
        ttl = int(client.ttl(settings.detector_leader_key))
        holder = str(client.get(settings.detector_leader_key) or "")
    except (TypeError, ValueError, redis.RedisError):
        ttl, holder = -2, ""
    status["leader"] = {
        "active": ttl > 0,
        "holder": holder,
        "ttl_seconds": ttl,
    }

    # Redis 内存：NDR 历史上被队列打满过一次，这个数字要能直接看到
    try:
        status["redis_memory"] = detector_health(client)
    except Exception as exc:  # noqa: BLE001
        status["redis_memory"] = {"error": str(exc)}

    # 判重闸门（第 5 期）已退役：投递状态与去重都在智能体侧，NDR 只报投递与丢弃计数
    status["dedup"] = {"enabled": False, "note": "判重已下放到智能体（按事件组指纹）"}

    status["enabled"] = bool(settings.detector_enabled)
    return status


# ---------- list_networks ----------


def _list_networks(args: dict[str, Any]) -> dict[str, Any]:
    """监控网段清单（判定「内网/外网」的依据，也是 Zeek 抓包过滤的条件）。"""
    nets = monitored_nets()
    state = networks_status()
    return {
        "networks": nets,
        "count": len(nets),
        "configured": bool(state.get("configured")),
        "hint": "清单为空时 Zeek 不过滤（抓全部）；内网判定也跟着失效，描述流量时要说明这一点。",
    }


# ---------- list_filters ----------


def _list_filters(args: dict[str, Any]) -> dict[str, Any]:
    """两道过滤闸门的清单：入库前降噪（不投检测器）与排除过滤（跳过分析）。

    为什么要一起给智能体看：这两类配置都会让「某条事件没有告警」，如果智能体不知道
    它们的存在，就容易把「被过滤掉」误读成「本来就没事」——漏报的锅不能扣在配置头上。
    """
    with session_factory() as db:
        rows = (
            db.execute(
                select(ExclusionFilter).order_by(ExclusionFilter.priority, ExclusionFilter.name)
            )
            .scalars()
            .all()
        )
        exclusion = [
            {
                "id": str(r.id),
                "name": r.name,
                "description": r.description,
                "enabled": bool(r.enabled),
                "priority": int(r.priority or 0),
                "conditions": r.conditions or {},
            }
            for r in rows
        ]
        rows = (
            db.execute(select(IngestFilter).order_by(IngestFilter.priority, IngestFilter.name))
            .scalars()
            .all()
        )
        ingest = [
            {
                "id": str(r.id),
                "name": r.name,
                "description": r.description,
                "enabled": bool(r.enabled),
                "priority": int(r.priority or 0),
                "conditions": r.conditions or {},
            }
            for r in rows
        ]
    return {
        "filters": exclusion,
        "ingest_filters": ingest,
        "hint": (
            "两道闸门：`ingest_filters` 命中 = 事件进 ES 但**没进检测器**（所以没有告警）；"
            "`filters` 命中 = 进了检测器但跳过了分析。两类都不产生结论，"
            "别把「被过滤」当成「没有异常」。"
        ),
    }


# ---------- record_conclusion ----------

# 结论状态 / 定级的枚举。以前是把模型给的原字符串截断直接落库，于是库里既有
# "true_positive" 又有 "高危"、还有拼错的词，界面按状态统计/过滤全不准。这里改成
# 「先归一化、再校验」：认识的值统一成规范写法入库，不认识的值报错并列出可选值，
# 让模型自我纠正（与工具集其它参数的 fail-closed 纪律一致）。
# 词表与别名都来自 `analysis.verdicts`（唯一实现）：`complete_task` 的 verdict 走同一份，
# 避免两处各自维护导致同一个值一边认一边不认（本仓已在中文映射上吃过一次两版漂移的亏）。
STATUS_VALUES = analysis_status_values()
_STATUS_ALIASES = conclusion_value_aliases()
SEVERITY_VALUES = ("info", "low", "medium", "high", "critical")
_STATUS_ALIASES = {
    "true_positive": "true_positive",
    "truepositive": "true_positive",
    "tp": "true_positive",
    "真阳性": "true_positive",
    "确认攻击": "true_positive",
    "攻击": "true_positive",
    "false_positive": "false_positive",
    "falsepositive": "false_positive",
    "fp": "false_positive",
    "误报": "false_positive",
    "误判": "false_positive",
    "benign": "benign",
    "正常": "benign",
    "白名单": "benign",
    "无异常": "benign",
    "suspicious": "suspicious",
    "可疑": "suspicious",
    "存疑": "suspicious",
    "inconclusive": "inconclusive",
    "待定": "inconclusive",
    "不确定": "inconclusive",
    "未定": "inconclusive",
    "pending": "pending",
    "处理中": "pending",
    "待处理": "pending",
    "进行中": "pending",
    "done": "done",
    "完成": "done",
    "结案": "done",
    "已结案": "done",
    "已处理": "done",
}
_SEVERITY_ALIASES = {
    "info": "info",
    "信息": "info",
    "提示": "info",
    "low": "low",
    "低": "low",
    "低危": "low",
    "medium": "medium",
    "中": "medium",
    "中危": "medium",
    "moderate": "medium",
    "high": "high",
    "高": "high",
    "高危": "high",
    "critical": "critical",
    "严重": "critical",
    "紧急": "critical",
}


def _enum_value(
    raw: Any,
    *,
    default: str,
    allowed: tuple[str, ...],
    aliases: dict[str, str],
    label: str,
) -> tuple[str, str]:
    """归一化一个枚举参数，返回 ``(规范值, 错误信息)``；空值用默认值，错误信息为空表示通过。"""
    text = str(raw or "").strip()
    if not text:
        return default, ""
    value = aliases.get(text.lower())
    if value is None:
        return "", f"{label} 不认识：{text!r}。只能填：{'、'.join(allowed)}（中文别名也认）"
    return value, ""


def _record_conclusion(args: dict[str, Any]) -> dict[str, Any]:
    """把调查结论写回 NDR（界面可见）。

    **同一事件只留一份**：`dedup_key` = 事件ID（没有就用指纹），再来一次覆盖旧的。
    这里不判重、不拦重复告警 —— 判重的权威在智能体侧，这里只是审计与展示用的副本。
    """
    summary = str(args.get("summary") or "").strip()
    if not summary:
        return {"error": "summary 必填：写清结论本身，界面列表主要看它"}
    event_id = str(args.get("event_id") or "").strip()[:64]
    fingerprint = str(args.get("fingerprint") or "").strip()[:64]
    dedup_key = (event_id or fingerprint)[:64]
    if not dedup_key:
        return {"error": "event_id 与 fingerprint 至少给一个，用它作为结论的归属键"}

    detail = args.get("detail")
    if not isinstance(detail, dict):
        detail = {"text": detail} if detail not in (None, "") else {}

    status, err = _enum_value(
        args.get("status"),
        default="done",
        allowed=STATUS_VALUES,
        aliases=_STATUS_ALIASES,
        label="status",
    )
    if err:
        return {"error": err}
    severity, err = _enum_value(
        args.get("severity"),
        default="info",
        allowed=SEVERITY_VALUES,
        aliases=_SEVERITY_ALIASES,
        label="severity",
    )
    if err:
        return {"error": err}

    now = datetime.now(UTC)
    with session_factory() as db:
        row = db.execute(
            select(ConclusionRecord).where(ConclusionRecord.dedup_key == dedup_key)
        ).scalar_one_or_none()
        created = row is None
        if row is None:
            row = ConclusionRecord(dedup_key=dedup_key, created_at=now)
            db.add(row)
        row.event_id = event_id or row.event_id or ""
        row.fingerprint = fingerprint or row.fingerprint or ""
        row.thread_id = str(args.get("thread_id") or row.thread_id or "")[:64]
        row.status = status[:32]
        row.severity = severity[:16]
        row.summary = summary
        row.detail = detail
        row.updated_at = now
        db.commit()
        row_id = str(row.id)

    return {
        "ok": True,
        "id": row_id,
        "created": created,
        "dedup_key": dedup_key,
        "note": "已写入 NDR；同一事件再次写回会覆盖这一条。" if not created else "已写入 NDR。",
    }


# ---------- fetch_window ----------

# 一次最多交回的条目数。回溯是「把窗口内的东西整批拿走去跑规则」，比查几条要重得多，
# 所以单独给一个更大的上限（智能体自己还有 lookback_max_logs 封顶）。
WINDOW_MAX = 5000


def _str_list(value: Any, cap: int = 200) -> list[str]:
    if isinstance(value, str):
        items = [p.strip() for p in value.replace(",", "\n").splitlines()]
    elif isinstance(value, (list, tuple)):
        items = [str(v).strip() for v in value]
    else:
        items = []
    return [i for i in items if i][:cap]


def _es_index() -> str:
    """当前**运行时**事件索引族。

    后台「系统配置」里 `es.events_index` 是可改的（`ndr/backend/app/ingestion/es_config.py`），
    只读静态 `settings.es_events_index` 会出现「采集已写进新索引族、这里还在查老的」——
    表现为「明明有数据却查不到」。静态值只作兜底。
    """
    return str(es_config().get("es.events_index") or settings.es_events_index)


def _es_path(index: str, field: str) -> str:
    """统一字段名 → ES 精确匹配路径（text 字段必须走 `.keyword`）。"""
    paths = catalog.term_paths(index, catalog.resolve(field) or field)
    return paths[0] if paths else field


def _octet_prefix(net: Any) -> str | None:
    """按字节对齐的 IPv4 网段（/8 /16 /24）→ keyword 前缀串，其他返回 None。

    ``str(network_address)`` 在非对齐网段上会给出「网络地址」而非调用方原串（例如
    10.1.2.5/24 → 10.1.2.0），拿它做前缀会多匹配，所以只接受对齐网段。
    """
    if getattr(net, "version", 0) != 4 or net.prefixlen not in (8, 16, 24):
        return None
    octets = str(net.network_address).split(".")
    return ".".join(octets[: net.prefixlen // 8]) + "."


def _net_clauses(
    index: str, networks: list[Any], paths: tuple[str, str]
) -> tuple[list[dict[str, Any]], list[str]]:
    """把网段尽量下推到 ES，返回 ``(子句列表, 只能取回后本地过滤的网段字符串)``。

    字段是 ES `ip` 类型时用 CIDR term（原生支持）；否则 text/keyword 只能：
    - `/8 /16 /24` 这类按字节对齐的网段 → `prefix`（实测可用）；
    - 单个地址（/32、/128）→ 精确 `term`；
    - 其余（如 /12、/20）→ 下推一定不准，交给调用点本地过滤并在 note 里说明。
    """
    if catalog.es_type(index, "src_ip") == "ip":
        cidrs = [str(n) for n in networks]
        return (
            [
                {
                    "bool": {
                        "should": [{"terms": {paths[0]: cidrs}}, {"terms": {paths[1]: cidrs}}],
                        "minimum_should_match": 1,
                    }
                }
            ],
            [],
        )

    should: list[dict[str, Any]] = []
    local_only: list[str] = []
    for net in networks:
        prefix = _octet_prefix(net)
        if prefix is not None:
            should.extend([{"prefix": {paths[0]: prefix}}, {"prefix": {paths[1]: prefix}}])
        elif net.prefixlen == net.max_prefixlen:
            host = str(net.network_address)
            should.extend([{"term": {paths[0]: host}}, {"term": {paths[1]: host}}])
        else:
            local_only.append(str(net))
    if not should:
        return [], local_only
    # 多个网段是「或」：用 should + minimum_should_match=1 合并成一条子句。
    return [{"bool": {"should": should, "minimum_should_match": 1}}], local_only


def _fetch_window(args: dict[str, Any]) -> dict[str, Any]:
    """按时间窗（可再按网段/IP）整批取回事件条目，交给调用方自己筛。

    与 `search_events` 的分工：那个是「查几条看看」，返回的是摘要字段；
    这个是「把窗口里的条目交出来」，返回完整条目（含 `raw` 原文），条数由调用方限。
    典型用途是回溯：拉历史窗口 → 调用方自己跑规则 → 看这组 IP 以前干过什么。

    每条带 `ref`（`es:<索引>/<文档id>`），可直接当证据引用。
    """
    start = str(args.get("start") or "").strip()
    end = str(args.get("end") or "").strip()
    if not start or not end:
        return {"error": "start 与 end 必填（ISO 时间，如 2026-02-14T00:00:00Z）"}
    try:
        limit = int(args.get("limit") or WINDOW_MAX)
    except (TypeError, ValueError):
        limit = WINDOW_MAX
    limit = max(1, min(limit, WINDOW_MAX))
    ips = _str_list(args.get("ips"))
    nets = build_networks(_str_list(args.get("nets")))

    # 索引取运行时配置：后台「系统配置」能改 es.events_index，只读静态 settings 会
    # 出现「采集写进新索引族、这个工具还在查老的」。（静态值仍作兜底。）
    index = _es_index()
    src_path, dst_path = _es_path(index, "src_ip"), _es_path(index, "dst_ip")

    conditions: list[dict[str, Any]] = [{"range": {"@timestamp": {"gte": start, "lt": end}}}]
    if ips:
        # 指定了 IP 就用它收窄——这正是调用方本来要做的事，放在 ES 侧做省得白拉一堆。
        # 路径必须是 keyword 路径：src_ip 实机是 text（动态映射），对主路径做 terms
        # 只在“分词后恰好留住整串”时才匹配，属于会静默丢结果的坑。
        conditions.append(
            {
                "bool": {
                    "should": [
                        {"terms": {src_path: ips}},
                        {"terms": {dst_path: ips}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        )

    nets_pushed = False
    local_only_nets: list[str] = []
    if nets:
        pushable, local_only_nets = _net_clauses(index, nets, (src_path, dst_path))
        nets_pushed = not local_only_nets
        conditions.extend(pushable)

    query: dict[str, Any] = {"bool": {"filter": conditions}}

    es = es_client()
    try:
        total = int(es.count(index=index, query=query).get("count") or 0)
        resp = es.search(
            index=index,
            query=query,
            size=limit,
            sort=[{"@timestamp": "asc"}],
        )
    except Exception as exc:  # noqa: BLE001
        return {"error": f"取事件窗口失败：{exc}"}

    logs: list[dict[str, Any]] = []
    for hit in resp.get("hits", {}).get("hits", []) or []:
        doc = hit.get("_source") or {}
        if nets and not (in_scope(doc.get("src_ip"), nets) or in_scope(doc.get("dst_ip"), nets)):
            continue
        logs.append({"ref": f"es:{hit.get('_index')}/{hit.get('_id')}", **doc})

    notes: list[str] = []
    if total > len(logs):
        notes.append(f"窗口内共 {total} 条，本次只取回 {len(logs)} 条（按时间从早到晚）")
    if not ips and not nets:
        notes.append("未限定网段/ IP：这是整段时间窗的全量条目")
    if local_only_nets:
        # 下推不了的那部分网段只能取回后本地过滤 —— total 是「下推条件」的计数，
        # 不含这部分，必须说清楚，否则调用方会拿 total 当「返回条数的上限」用。
        notes.append(
            "以下网段无法下推到 ES（字段不是 ip 类型且网段不按字节对齐），"
            f"只在取回后本地过滤：{', '.join(local_only_nets)}；"
            "total 是下推条件下的条数（不含这部分）。"
        )
    return {
        "window": {"start": start, "end": end},
        "index": index,
        "total": total,
        "returned": len(logs),
        "nets_pushed_down": bool(nets) and nets_pushed,
        "logs": logs,
        "notes": notes,
    }


# ---------- baseline_lookup / entity_profile（第 8 期：基线落在 NDR 侧） ----------

BASELINE_MAX = 200
PROFILE_MAX = 50
# 提取件内容：默认回 64 KiB、硬上限 1 MiB（回的是文本，必须封顶，
# 否则一份大文件就能把模型上下文吃光）。要完整文件用 Web 下载入口。
FILE_DEFAULT_BYTES = 65536
FILE_MAX_BYTES = 1048576
_FEATURE_EXAMPLE = "conn_count"


def _cap_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(n, high))


def _baseline_lookup(args: dict[str, Any]) -> dict[str, Any]:
    """查数值基线：某个源 IP 的长期均值/标准差/样本数，以及是否过了观测期。

    三个维度（key 形如 `10.0.0.5:conn_count`）：连接数、不同目的端口数、不同目的 IP 数。
    """
    ip = str(args.get("ip") or "").strip()
    key = str(args.get("key") or "").strip()
    result = stats_lookup(ip=ip, key=key, limit=_cap_int(args.get("limit"), 50, 1, BASELINE_MAX))
    if "error" in result:
        return result
    result["note"] = (
        f"观测期 {settings.baseline_observe_days} 天内的维度 warmed=false，不参与判定；"
        "「没报偏离」不等于正常。判据是 当前值 > mean + "
        f"{settings.baseline_zscore}σ，NDR 只在摘要里打标，定性由智能体做。"
    )
    return result


def _entity_profile(args: dict[str, Any]) -> dict[str, Any]:
    """查账号/会话画像（跨窗口长期基线），可按实体键指名或只看过阈值异常。"""
    kind_raw = str(args.get("kind") or "").strip().lower()
    kind = kind_raw if kind_raw in ("account", "session") else None
    keys = _str_list(args.get("keys"))
    limit = _cap_int(args.get("limit"), 20, 1, PROFILE_MAX)
    try:
        min_risk = max(0.0, min(float(args.get("min_risk") or 0.0), 1.0))
    except (TypeError, ValueError):
        min_risk = 0.0
    if keys:
        result = list_profiles(kind=kind, keys=keys, min_risk=min_risk, limit=limit)
    elif args.get("anomalies_only"):
        result = top_anomalies(limit)
    else:
        result = list_profiles(kind=kind, min_risk=min_risk, limit=limit)
    if "error" in result:
        return result
    result["threshold"] = settings.profile_risk_threshold
    result["note"] = (
        "风险分是加权累加：新源 IP +0.35（v6 只在 /64 前缀也新时算，隐私地址轮换不算）、"
        "新 UA +0.2（非常用时段 +0.15，需画像满 "
        f"{settings.profile_hour_min_age_hours} 小时且见过 ≥{settings.profile_hour_min_coverage} 个时段）、"
        f"新接口路径 +0.25（只算接口形态，已知 ≥{settings.profile_path_min_known} 条才判）、"
        "同族跨 ≥2 个 IP +0.45（v4+v6 双栈不算会话劫持）、"
        "认证失败突增分档：≥5 且多于成功 +0.25 / ≥10 +0.35 / ≥20 且零成功 +0.6（这类基本是脚本在撞，单条即达阈值）；"
        f"达到 {settings.profile_risk_threshold} 才算异常，冷启动（观测不足）不算。"
        "风险分是「当前窗口」的值：本轮无异常会归零并清空，risk_at 是判定时间。"
    )
    return result


# ---------- file_content（提取件内容，采集面批 4） ----------


def _file_content(args: dict[str, Any]) -> dict[str, Any]:
    """取提取件的内容（有界）或元数据。

    为什么需要它：文件提取与下载通道只在 NDR 的 Web API 上（要管理员 JWT），智能体拿不到，
    于是「模型知道有个文件、却看不到文件内容」——采集面做了提取、分析面用不上（2026-10 MCP QA）。
    这里用与下载路由**完全相同**的校验（fuid 格式 + `lookup_extract` + `resolve_extract_path`），
    只把不可变的字节按有界长度回给模型。
    """
    fuid = str(args.get("fuid") or "").strip()
    if not is_valid_fuid(fuid):
        return {"error": "fuid 格式不合法（形如 Fx8HnP1AbCdEfGhIjK，8~64 位 URL 安全字符）"}
    encoding = str(args.get("encoding") or "base64").strip().lower()
    if encoding not in ("text", "base64"):
        return {"error": "encoding 只能是 text 或 base64"}
    try:
        want = int(args.get("max_bytes") or FILE_DEFAULT_BYTES)
    except (TypeError, ValueError):
        want = FILE_DEFAULT_BYTES
    want = max(1, min(want, FILE_MAX_BYTES))

    try:
        doc = lookup_extract(fuid)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"查事件库失败：{exc}"}
    if not doc:
        return {
            "error": f"没有 fuid={fuid} 的提取件（来源不是 HTTP/FTP 明文，或未开启提取、已被清理）"
        }
    path = resolve_extract_path(str(doc.get("extracted") or ""))
    if path is None:
        return {"error": "提取件字段未通过路径校验（拒绝读取）"}
    try:
        if not path.is_file():
            return {
                "error": "提取件已被清理（非白名单类型或超出容量上限，见 zeek/extract_cleanup.py）"
            }
        size = path.stat().st_size
        with path.open("rb") as fh:
            blob = fh.read(want)
    except OSError as exc:
        return {"error": f"读取提取件失败：{exc}"}

    out: dict[str, Any] = {
        "fuid": fuid,
        "filename": str(doc.get("filename") or ""),
        "mime_type": str(doc.get("mime_type") or ""),
        "size_on_disk": size,
        "es_extracted_size": doc.get("extracted_size"),
        "es_extracted_cutoff": bool(doc.get("extracted_cutoff")),
        "read_bytes": len(blob),
        "truncated": size > len(blob),
        "max_bytes": want,
        # 二进制本体不可能全塞进模型上下文：要完整文件得走这个下载入口（需 NDR 登录）
        "download": f"/api/files/{fuid}",
    }
    if encoding == "text":
        out["encoding"] = "text"
        out["content"] = blob.decode("utf-8", errors="replace")
    else:
        out["encoding"] = "base64"
        out["content_base64"] = base64.b64encode(blob).decode("ascii")
    if out["truncated"]:
        out["note"] = (
            f"只读了前 {len(blob)} 字节（文件共 {size} 字节）；需要更多请调大 max_bytes"
            f"（上限 {FILE_MAX_BYTES}），或走 download 取完整文件。"
        )
    return out


# ---------- 事件与既往结论（G1：让智能体看得懂"有哪些事、看过没有"） ----------


def _search_hits(args: dict[str, Any]) -> dict[str, Any]:
    """查命中事件清单（PG，与界面同一份口径）。

    为什么必须给：新架构不再有"推送里带 event_id"这一步，智能体自主规划时要能自己
    按对象/时间/来源把事件捞出来，并且看得到 `cluster_id`（一次扫描的几十个地址
    在簇视角下是**一件事**，逐条看就是噪声）。
    """
    kinds = {
        p.strip()
        for p in str(args.get("source_kinds") or "").replace(",", " ").split()
        if p.strip()
    }
    picked = sorted(kinds & set(hit_source_labels())) if kinds else []
    if kinds and not picked:
        return {
            "error": f"source_kinds 只认：{'、'.join(sorted(hit_source_labels()))}",
            "hint": "feature_match=特征匹配 / behavior_analysis=行为分析 / baseline_deviation=基线偏离",
        }
    out: dict[str, Any] = {"items": [], "total": 0}
    for kind in picked or sorted(hit_source_labels()):
        page = list_hit_events(
            ip=str(args.get("ip") or ""),
            source_kind=kind,
            cluster_id=str(args.get("cluster_id") or ""),
            minutes=_bounded_int(args.get("minutes"), default=0, lo=0, hi=30 * 1440),
            limit=_bounded_int(args.get("limit"), default=50, lo=1, hi=200),
        )
        if "error" in page:
            return page
        out["items"].extend(page.get("items") or [])
        out["total"] += int(page.get("total") or 0)
    out["returned"] = len(out["items"])
    out["source_kind_note"] = (
        "按来源分别取（未指定 source_kinds 时三类都取），避免一次捞太多把上下文塞满"
    )
    return out


def _get_event_detail(args: dict[str, Any]) -> dict[str, Any]:
    """单条命中事件的**完整内容**（规则、源/目的、证据、簇、三类来源）。"""
    hit_id = str(args.get("event_id") or "").strip()
    if not hit_id:
        return {"error": "要 event_id（从 search_hits 的结果里拿）"}
    event = get_hit_event(hit_id)
    if "error" in event:
        return event
    # 顺手把这条事件已有的结论带回去（原来要再调一次 get_event）
    event["conclusions"] = _get_event({"event_id": hit_id, "fingerprint": ""}).get(
        "conclusions", []
    )
    return event


def _prior_findings(args: dict[str, Any]) -> dict[str, Any]:
    """某个对象的既往结论（智能体开工前的"看过没有"检查）。

    这是新架构的省钱关键：**先查再分析**。同一对象连续被判误报，
    反馈层已经会把强度压下来；但只有智能体自己看得见历史，才不会重复领同样的活。
    """
    subject = str(args.get("subject") or "").strip()
    if not subject:
        return {"error": "要 subject（IP / 资产 / 账号 / 对象值）"}
    out = list_analysis_results(
        subject=subject,
        kind=str(args.get("kind") or ""),
        verdict=str(args.get("verdict") or ""),
        limit=_bounded_int(args.get("limit"), default=20, lo=1, hi=100),
        detail=_flag_of(args.get("detail")),
        via_asset=_flag_of(args.get("via_asset")),
    )
    out["verdicts"] = list(analysis_queue.VERDICTS)
    out["note"] = "有既往结论就先读它，别重复分析同一现象（同一现象重复分析白烧预算）"
    return out


# ---------- 抑制现状与撤销（G2） ----------


def _list_suppressions(args: dict[str, Any]) -> dict[str, Any]:
    """看当前精准抑制（含命中数与到期时间）。"""
    return suppression.list_items(
        q=str(args.get("q") or ""),
        enabled_only=bool(args.get("enabled_only")),
        include_expired=bool(args.get("include_expired")),
        limit=_bounded_int(args.get("limit"), default=100, lo=1, hi=500),
    )


def _revoke_suppression(args: dict[str, Any]) -> dict[str, Any]:
    """撤销一条精准抑制（智能体发现自己之前判错时可以主动收回）。

    为什么给它这个权力：抑制只由"真阳性自动回弹"或"到期"解除太被动 ——
    智能体在别处看到反证（例如同一网段出现真实利用行为）时应该能立刻放开。
    """
    item_id = str(args.get("suppression_id") or "").strip()
    if not item_id:
        return {"error": "要 suppression_id（从 list_suppressions 结果里拿）"}
    reason = str(args.get("reason") or "").strip()
    if not reason:
        return {"error": "撤销必须写原因（审计要看是谁、凭什么放开的）"}
    return suppression.set_enabled(item_id, enabled=False, reason=f"agent 撤销：{reason}"[:200])


# ---------- 主动登记线索（G3） ----------


def _add_task(args: dict[str, Any]) -> dict[str, Any]:
    """智能体自己往队列里登记线索（不经过领取就能留痕）。

    为什么需要：`complete_task` 的 `next_tasks` 只能"分析完再派生"，且受深度限制。
    智能体从别处得到线索（外部情报、运维在对话里问它、它自己巡逻发现）时，
    得有个地方把"这事值得看"记下来 —— 否则分析完不留痕，下次依旧是盲区。
    """
    subject = str(args.get("subject") or "").strip()
    if not subject:
        return {"error": "要 subject（IP / 资产 / 账号 / 对象值）"}
    kind = str(args.get("kind") or "structure").strip()
    if kind not in analysis_params.KINDS:
        # 不能静默兜底：那等于把智能体想登记的类型悄悄改掉
        return {"error": f"kind 只认：{'、'.join(analysis_params.KINDS)}"}
    try:
        strength = float(args.get("strength") or 0.6)
    except (TypeError, ValueError):
        return {"error": "strength 要传 0~1 的数字（缺省 0.6）"}
    strength = max(0.0, min(1.0, strength))
    return analysis_queue.manual_task(
        _client(),
        subject_kind=str(args.get("subject_kind") or "ip"),
        subject=subject,
        note=str(args.get("note") or ""),
        kind=kind,
        strength=float(args.get("strength") or 0.6),
    )


# ---------- 派工队列（智能体主动领取，2026-10 改造） ----------


def _kinds_of(value: Any) -> set[str]:
    if isinstance(value, (list, tuple, set)):
        return {str(v).strip() for v in value if str(v).strip()}
    text = str(value or "")
    return {p.strip() for p in text.split(",") if p.strip()}


def _claim_tasks(args: dict[str, Any]) -> dict[str, Any]:
    """领取待分析线索（原子、带配额）。服务端强制预算，不靠智能体自觉。"""
    import time as _time

    client = _client()
    token = str(args.get("_token") or "mcp")
    wait = _bounded_int(args.get("wait_seconds"), default=0, lo=0, hi=30)
    deadline = _time.monotonic() + wait
    out: dict[str, Any] = {}
    while True:
        out = analysis_queue.claim_tasks(
            client,
            token=token,
            limit=int(args.get("limit") or 0),
            kinds=_kinds_of(args.get("kinds")),
            min_strength=float(args.get("min_strength") or 0),
        )
        # 只有"队列空"才值得继续等；预算用尽/并发满了等也没用
        if out.get("tasks") or out.get("error") or out.get("reason") != "queue_empty":
            return out
        if _time.monotonic() >= deadline:
            out["waited_seconds"] = wait
            return out
        _time.sleep(2.0)


def _complete_task(args: dict[str, Any]) -> dict[str, Any]:
    """交回结论（含成本），可选派生追问与提交精准抑制。

    两道校验是这个机制的安全底座：
    - `evidence_refs` **必须是本会话真取回过的引用**（`ctx.valid_refs`）——
      否则"随便编几条引用"就能换到一条永久抑制；
    - `suppression` 走与界面同一套 `suppression.validate_item`（至少 2 个匹配维度 +
      影响面积试算），不把"智能体说了算"变成"智能体说什么算什麼"。
    """
    client = _client()
    token = str(args.get("_token") or "mcp")
    task_id = str(args.get("task_id") or "")
    valid_refs = {str(x) for x in (args.get("_valid_refs") or [])}
    refs = [str(x) for x in (args.get("evidence_refs") or [])][:20]
    out = analysis_queue.complete_task(
        client,
        task_id,
        verdict=str(args.get("verdict") or ""),
        summary=str(args.get("summary") or ""),
        confidence=_bounded_int(args.get("confidence"), default=0, lo=0, hi=1) / 1.0,
        findings=args.get("findings") if isinstance(args.get("findings"), dict) else {},
        evidence_refs=refs,
        tools_used=_bounded_int(args.get("tools_used"), default=0, lo=0, hi=100000),
        duration_ms=_bounded_int(args.get("duration_ms"), default=0, lo=0, hi=10**9),
        terminal_reason=str(args.get("terminal_reason") or ""),
        anchors=args.get("anchors") if isinstance(args.get("anchors"), list) else None,
        token=token,
    )
    if "error" in out:
        return out
    # 追问（受深度与单次上限约束）
    follows = args.get("next_tasks")
    if isinstance(follows, list) and follows:
        out["followups"] = analysis_queue.add_followups(client, task_id, follows, token=token)
    # 抑制（只有判定为误报才允许；引用必须真取过）
    sup = args.get("suppression")
    if isinstance(sup, dict) and sup:
        if str(args.get("verdict") or "") != "false_positive":
            out["suppression"] = {"error": "只有 verdict=false_positive 才能提交抑制"}
        else:
            body = dict(sup)
            body.setdefault("name", f"agent-{task_id[:8]}")
            body.setdefault("source_task_id", task_id)
            body["evidence_refs"] = refs
            body.setdefault("confidence", float(args.get("confidence") or 0))
            out["suppression"] = _apply_suppression(
                body, token=token, refs=refs, valid_refs=valid_refs,
                tool_usage=args.get("_tool_usage") or {},
            )
    return out


def _apply_suppression(
    body: dict[str, Any],
    *,
    token: str,
    refs: list[str],
    valid_refs: set[str],
    tool_usage: dict[str, int],
) -> dict[str, Any]:
    """提交抑制的统一实现（`complete_task` 内联与独立工具共用一份）。

    三道额外核验在这里做（`suppression.validate_item` 只管字段与维度）：
    - 引用必须**本会话真取回过**（`valid_refs`）—— 编造引用换不到一条抑制；
    - 证据要来自**至少 2 种取数工具**（`tool_usage`）—— 只看一段正文下结论不算数；
    - 置信度、理由码、新现象保护期在 `create_item` 里统一判。
    """
    forged = [r for r in refs if valid_refs and r not in valid_refs]
    if forged:
        return {
            "field_errors": [
                {
                    "field": "evidence_refs",
                    "msg": f"这些引用本会话没真取回过：{'、'.join(forged[:3])}",
                }
            ]
        }
    errors = suppression.validate_item(body)
    if errors:
        return {"field_errors": errors}
    try:
        created = suppression.create_item(
            body,
            created_by=token,
            origin=suppression.ORIGIN_AGENT,
            tool_hits=tool_usage,
        )
    except ValueError as exc:
        return {"error": str(exc)}
    return {
        "ok": True,
        "id": created["id"],
        "mode": created["mode"],
        "mode_label": created["mode_label"],
        "dims": created["dims"],
        "trial": created["trial"],
        "expires_at": created["expires_at"],
    }


def _defer_task(args: dict[str, Any]) -> dict[str, Any]:
    """延后重排（数据还没入齐 / 现在不想深挖），必须释放租约。"""
    return analysis_queue.defer_task(
        _client(),
        str(args.get("task_id") or ""),
        reason=str(args.get("reason") or ""),
        retry_after_seconds=_bounded_int(args.get("retry_after_seconds"), default=3600, lo=60, hi=7 * 24 * 3600),
        token=str(args.get("_token") or "mcp"),
    )


def _task_stats(args: dict[str, Any]) -> dict[str, Any]:
    """队列与成本总览：智能体据此自我节流，运维据此看积压与覆盖率。"""
    out = analysis_queue.stats(_client())
    out["coverage"] = analysis_subjects.coverage(
        days=_bounded_int(args.get("days"), default=analysis_params.coverage_stale_days(), lo=1, hi=365),
        kind=str(args.get("kind") or ""),
        limit=int(args.get("limit") or 20),
    )
    return out


def _asset_map(args: dict[str, Any]) -> dict[str, Any]:
    """数据地图之对象清单：见过哪些资产/服务端口/外部对端/协议/签名，各自首次与最近时间。

    智能体"自主找活"的另一条腿：没有这份清单，它只能被动接单，谈不上规划。
    """
    return analysis_subjects.inventory(
        limit_per_kind=_bounded_int(args.get("limit"), default=100, lo=1, hi=1000),
        kind=str(args.get("kind") or ""),
    )


def _coverage_report(args: dict[str, Any]) -> dict[str, Any]:
    """覆盖率与盲区：哪些对象从来没看过、哪些久未看（低强度线索的数据面）。

    `by="asset"` 走**锚点**口径：回答"近 N 天有多少资产被结论覆盖过"，
    与 `by="subject"`（只看 subject 本身）不同 —— 一条"这台是反代"的结论会把
    它锚定的后端资产也算成"已了解"，这才是运维真正关心的覆盖。
    """
    out = analysis_subjects.coverage(
        days=_bounded_int(args.get("days"), default=7, lo=1, hi=365),
        kind=str(args.get("kind") or ""),
        limit=int(args.get("limit") or 100),
    )
    by = str(args.get("by") or "subject").strip().lower()
    if by not in ("subject", "asset"):
        return {"error": f"by 不认识：{by!r}。只能填：subject、asset", "field": "by"}
    if by == "asset":
        try:
            covered = analysis_anchors.covered_asset_count(days=_bounded_int(
                args.get("days"), default=7, lo=1, hi=365
            ))
        except Exception as exc:  # noqa: BLE001 — 覆盖率是增值信息，读失败不打断分析
            return {"error": f"按资产统计覆盖失败：{exc}"}
        out["by"] = "asset"
        out["covered_assets"] = covered
        out["note"] = (
            "covered_assets = 近 N 天有结论通过锚点覆盖到的资产数；"
            "分母仍是 observed_subjects(kind=asset)，两者口径不同不要直接相除"
        )
    else:
        out["by"] = "subject"
    return out


def _task_state(args: dict[str, Any]) -> dict[str, Any]:
    """查单条任务的当前状态（智能体会话结束后用来判断"到底交回没有"）。

    为什么必须有：会话空闲不等于任务完成 —— 模型可能查完就收工、忘了调 complete_task。
    没有这个工具，智能体只能靠"没收到回执"猜，最后任务被租约回收（attempts 累加）。
    """
    task_id = str(args.get("task_id") or "").strip()
    if not task_id:
        return {"error": "task_id 必填", "field": "task_id"}
    return analysis_task_state(task_id)


def _log_step(args: dict[str, Any]) -> dict[str, Any]:
    """记一条过程观察（让后来的任务不必重复取数）。

    只写"值得别人知道的一句话"，不要贴原始报文 —— 原始证据留在 ES，
    这里存正文会让轨迹表变成第二份数据源（又大又会不一致）。
    """
    return analysis_log_step(
        task_id=str(args.get("task_id") or "").strip(),
        tool=str(args.get("tool") or "")[:48],
        summary=str(args.get("summary") or ""),
        detail=str(args.get("detail") or ""),
    )


def _search_traces(args: dict[str, Any]) -> dict[str, Any]:
    """在**别的任务**的过程记录里检索（自动排除自己这条）。

    返回的内容是"他人未经核实的观察"：可以当线索去验证，**不能**当结论、更不能当抑制证据。
    """
    return analysis_search_traces(
        q=str(args.get("q") or ""),
        exclude_task=str(args.get("exclude_task") or args.get("_task_id") or ""),
        subject=str(args.get("subject") or ""),
        limit=_bounded_int(args.get("limit"), default=20, lo=1, hi=50),
    )


def _get_trace(args: dict[str, Any]) -> dict[str, Any]:
    """取某个任务的全部过程步骤（细节交换：先看有哪些任务跑过，再看具体几步）。"""
    task_id = str(args.get("task_id") or "").strip()
    if not task_id:
        return {"error": "task_id 必填", "field": "task_id"}
    return analysis_get_trace(
        task_id=task_id,
        limit=_bounded_int(args.get("limit"), default=20, lo=1, hi=20),
    )


def _submit_suppression(args: dict[str, Any]) -> dict[str, Any]:
    """申请自动抑制：证据够硬就对该类现象**不再派工、不再生成事件**。

    与 `complete_task` 内联提交的区别只是入口：这里可以在"没领任务"时也提交
    （例如巡逻中发现某类噪声，或任务已结束后才攒够证据）。

    服务端六道机械门槛（全部可算，不靠人工审批）：结构化匹配 + 至少 2 个维度 +
    引用真实性 + 证据多样性（≥2 种工具）+ 置信度 + 新现象保护期；
    再叠爆炸半径试算：影响面过大自动降级为 `record_only`（事件仍生成、只不派工）。
    """
    match = args.get("match")
    if not isinstance(match, dict) or not match:
        return {
            "error": "要 match（条件树：{logic, rules:[{field, op, value}]}）",
            "allowed_fields": dict(ALLOWED_SUPPRESSION_FIELDS),
        }
    refs = [str(x) for x in (args.get("evidence_refs") or [])][:20]
    body = {
        "name": str(args.get("name") or f"agent-{int(time.time())}"),
        "match": match,
        "reason_code": str(args.get("reason_code") or ""),
        "note": str(args.get("note") or ""),
        "evidence_refs": refs,
        "confidence": float(args.get("confidence") or 0),
        "ttl_days": args.get("ttl_days"),
        "source_task_id": str(args.get("task_id") or ""),
    }
    return _apply_suppression(
        body,
        token=str(args.get("_token") or "mcp"),
        refs=refs,
        valid_refs={str(x) for x in (args.get("_valid_refs") or [])},
        tool_usage=args.get("_tool_usage") or {},
    )


# ---------- 资产上下文、事件聚合、规则与中继（M1-M6） ----------


def _flag_of(value: Any) -> bool:
    """把模型传来的布尔参数归一（它可能写 "true" / "1" / "是"）。"""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "true", "yes", "on", "是", "y")


def _bounded_int(value: Any, *, default: int, lo: int, hi: int) -> int:
    """模型传来的数字要夹：脏值走默认值，越界走边界（不抛异常炸掉整次调用）。"""
    try:
        number = int(float(value)) if value not in (None, "", 0) else default
    except (TypeError, ValueError):
        number = default
    return max(lo, min(hi, number))


def _asset_context(args: dict[str, Any]) -> dict[str, Any]:
    """资产台账上下文：**判严重度的唯一依据**。

    智能体看到"某台机器被异常访问"时，必须知道这台是什么主机、多重要、归谁管、
    在哪个分组 —— 否则核心业务机和一台测试机在它眼里一模一样。
    没进台账的地址会明确列在 `unknown_ips`，避免把"没登记"误读成"不重要"。
    """
    raw = args.get("ips")
    ips: list[str] = []
    if isinstance(raw, (list, tuple)):
        ips = [str(x) for x in raw]
    elif str(raw or "").strip():
        ips = [x.strip() for x in str(raw).replace(",", " ").split() if x.strip()]
    if ips:
        return asset_context_by_ips(ips)
    if str(args.get("q") or "").strip() or str(args.get("criticality") or "").strip():
        return asset_records(
            q=str(args.get("q") or ""),
            criticality=str(args.get("criticality") or ""),
            limit=_bounded_int(args.get("limit"), default=100, lo=1, hi=1000),
        )
    return {"error": "给 ips（要查的主机）或 q/criticality（按条件筛台账）"}


def _hit_clusters(args: dict[str, Any]) -> dict[str, Any]:
    """告警簇：**一次扫描/爆破是一件事**，不是几十条。

    `search_hits` 只能逐条看，跨页折不起来（前端也折不动）；这里给后端聚合过的视图：
    每簇的事件数、涉及多少不同源、最高级别、首末时间。
    """
    kind = str(args.get("source_kind") or "").strip()
    if kind and kind not in hit_source_labels():
        return {"error": f"source_kind 只认：{'、'.join(sorted(hit_source_labels()))}"}
    return hit_clusters(
        minutes=_bounded_int(args.get("minutes"), default=1440, lo=1, hi=30 * 1440),
        limit=_bounded_int(args.get("limit"), default=20, lo=1, hi=200),
        include_ignored=bool(args.get("include_ignored")),
        source_kind=kind,
    )


def _hit_stats(args: dict[str, Any]) -> dict[str, Any]:
    """事件面统计：总量、按来源/级别分布、TOP 事件归类、趋势。

    为什么要给：自主规划需要知道"这段时间主要在发生哪类事"，才知道预算该往哪投。
    """
    return hit_stats(minutes=_bounded_int(args.get("minutes"), default=1440, lo=1, hi=30 * 1440))


def _list_rules(args: dict[str, Any]) -> dict[str, Any]:
    """检测规则清单：回答"NDR 现在到底在检测什么"。

    没有它，智能体会把"没事件"读成"没攻击"——而真相可能是**根本没规则覆盖**。
    只给概要（名称/来源类别/严重度/是否启用/说明），不把 conditions 全量吐出去。
    """
    kind = str(args.get("source_kind") or "").strip()
    if kind and kind not in hit_source_labels():
        # 校验必须在查库之前：脏参数不该白跑一次 I/O，更不该被读成"没有这类规则"
        return {"error": f"source_kind 只认：{'、'.join(sorted(hit_source_labels()))}"}
    items = rule_inventory()
    if kind:
        items = [r for r in items if str(r.get("source_kind") or "") == kind]
    out: list[dict[str, Any]] = []
    for rule in items:
        out.append(
            {
                "name": rule.get("name"),
                "source_kind": rule.get("source_kind"),
                "source_label": rule.get("source_label"),
                "severity": rule.get("severity"),
                "enabled": rule.get("enabled"),
                "readonly": bool(rule.get("readonly")),
                "description": str(rule.get("description") or "")[:200],
            }
        )
    return {
        "total": len(out),
        "returned": len(out),
        "items": out[: _bounded_int(args.get("limit"), default=200, lo=1, hi=500)],
        "counts_by_kind": _count_by(out, "source_kind"),
    }


def _count_by(items: list[dict[str, Any]], field: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in items:
        key = str(item.get(field) or "")
        out[key] = out.get(key, 0) + 1
    return out


def _relay_nodes(args: dict[str, Any]) -> dict[str, Any]:
    """中继清单与角色：**判横向/外联之前必须先看它**。

    清单里的地址是反代时，事件的 `src_ip` 是代理自己而不是真实客户端；
    不知道这点就会把「外网经代理访问内网网站」误判成「内网机器主动外连」。
    """
    return relay_inventory()


def _record_disposition(args: dict[str, Any]) -> dict[str, Any]:
    """给画像告警打处置（误报→按时间窗降权；确认→仅留档）。

    与精准抑制的分工要说清：
    - `complete_task` 里的 `suppression` 管**事件流**（四元组精准匹配，直接不派工）；
    - 这里管**画像/实体**（某个账号或会话的某一路证据降权，界面上理由仍可见）。
    误报的大头在画像侧（会话实体十万量级），所以这个动作必须有。
    """
    verdict = str(args.get("verdict") or "").strip()
    if verdict not in ("false_positive", "confirm"):
        return {"error": "verdict 只认 false_positive 或 confirm"}
    signal = str(args.get("signal") or "").strip()
    known = {c for c in ("cross_ip", "new_src_ip", "new_ua", "new_path", "unusual_hour",
                        "error_surge", "fail_burst", "fail_burst_hard")}
    if signal and signal not in known:
        return {"error": f"signal 只认：{'、'.join(sorted(known))}（留空=整条告警降权）"}
    out = record_profile_disposition(
        str(args.get("profile_id") or ""),
        verdict,
        signal=signal,
        note=str(args.get("note") or ""),
        operator=str(args.get("_token") or "agent"),
    )
    if "error" in out:
        out["hint"] = "profile_id 可以是画像 UUID，也可以是实体键（账号名 / 会话设备哈希）"
    return out


# ---------- 注册表 ----------

TOOLS: dict[str, dict[str, Any]] = {
    "asset_context": {
        "run": _asset_context,
        "desc": (
            "查资产台账上下文：主机名 / 重要级别(core-high-normal-test) / 责任人 / 分组 / 标签。"
            "**判严重度前先查它**：核心业务机被异常访问和一台测试机被异常访问不是一回事。"
            "没登记的地址会单独列在 unknown_ips，不代表不重要"
        ),
        "params": {
            "ips": "要查的主机 IP，数组或逗号分隔（首选，精确匹配）",
            "q": "按 IP 或主机名模糊筛（ips 省了才用）",
            "criticality": "只看某个重要级别：core / high / normal / test",
            "limit": "模糊筛时最多返回几条（默认 100）",
        },
    },
    "hit_clusters": {
        "run": _hit_clusters,
        "desc": (
            "按**告警簇**看事件：同一事件归类 + 同一网段(/24、v6 /64) + 同一小时折成一件事。"
            "一次扫描会命中几十个地址，逐条读就是噪声；这里给每簇的事件数、涉及源数、"
            "最高级别与首末时间"
        ),
        "params": {
            "minutes": "回看多少分钟（默认 1440=24 小时）",
            "source_kind": "只看一类来源（feature_match/behavior_analysis/baseline_deviation，可省）",
            "limit": "最多返回几个簇（默认 20）",
            "include_ignored": "是否包含已忽略事件（true/false）",
        },
    },
    "hit_stats": {
        "run": _hit_stats,
        "desc": (
            "事件面统计：总量、按三类来源与严重度分布、TOP 事件归类、趋势分桶。"
            "自主规划靠它判断这段时间主要在发生哪类事、预算该往哪投"
        ),
        "params": {"minutes": "回看多少分钟（默认 1440）"},
    },
    "list_rules": {
        "run": _list_rules,
        "desc": (
            "列出 NDR 现在**到底在检测什么**（行为分析规则 + 特征匹配签名，含是否启用）。"
            "缺了它很容易把「没事件」误读成「没攻击」，而真相可能是没有规则覆盖"
        ),
        "params": {
            "source_kind": "只看一类（feature_match/behavior_analysis/baseline_deviation，可省=全部）",
            "limit": "最多返回几条（默认 200，上限 500）",
        },
    },
    "relay_nodes": {
        "run": _relay_nodes,
        "desc": (
            "中继节点清单与角色推算：哪些地址是反向代理、哪些是内网 DNS 转发器、"
            "配对时保留哪一侧，以及已推算出的拓扑关系。**判横向移动与外联前先查它**——"
            "经过反代时事件的 src_ip 是代理本身，不知道就会把「外网访问我们网站」误判成"
            "「内网主机主动外连」"
        ),
        "params": {},
    },
    "record_disposition": {
        "run": _record_disposition,
        "desc": (
            "给一条**画像级**告警打处置：false_positive 会让该实体（或指定那一路证据）在降权窗口内"
            "不再参与打分（理由仍可见），confirm 只留档。与精准抑制分工不同："
            "suppression 管事件流（四元组、直接不派工），这里管账号/会话画像"
        ),
        "params": {
            "profile_id": "画像 UUID 或实体键（账号名 / 会话设备哈希）",
            "verdict": "false_positive（误报，降权）或 confirm（确认，仅留档）",
            "signal": "只降某一路证据：cross_ip / new_src_ip / new_ua / new_path / unusual_hour / "
                      "error_surge / fail_burst / fail_burst_hard；留空=整条告警",
            "note": "依据说明（审计与界面可见，写清你凭什么判它是误报）",
        },
    },
    "search_hits": {
        "run": _search_hits,
        "desc": (
            "查命中事件清单（与界面同一份口径）。新架构下**没有推送**，事件要靠这里自己捞；"
            "返回带 `cluster_id`（一次扫描的几十个地址是**一件事**，按簇看才不会把上下文塞满）"
        ),
        "params": {
            "ip": "只看这个源 IP（可省）",
            "source_kinds": "只看这些来源，逗号分隔：feature_match 特征匹配 / "
            "behavior_analysis 行为分析 / baseline_deviation 基线偏离（省=三类都取）",
            "cluster_id": "只看某个告警簇（可省）",
            "minutes": "回看多少分钟（可省=不限）",
            "limit": "每类来源最多取几条（默认 50）",
        },
    },
    "get_event_detail": {
        "run": _get_event_detail,
        "desc": "取单条命中事件的**完整内容**：事件类型、三类来源、源/客户端/中继、目的 IP:端口、证据、簇 ID，并附带这条事件已有的结论",
        "params": {"event_id": "事件 ID（从 search_hits 结果里拿）"},
    },
    "prior_findings": {
        "run": _prior_findings,
        "desc": (
            "查某个对象的**既往结论**（开工前先问「这台看过没有」）。"
            "同一现象重复分析就是白烧预算；连续被判误报的对象强度也会被自动压低"
        ),
        "params": {
            "subject": "对象（IP / 资产 / 账号 / 对象值）",
            "kind": "只看某类线索的结论（novelty/shift/structure/coverage/hit，可省）",
            "verdict": "只看某种结论（true_positive/false_positive/benign/suspicious/inconclusive，可省）",
            "limit": "最多返回几条（默认 20）",
            "detail": "true=连已折叠进摘要的原始判定一起给（默认只给概览，恒定大小）",
            "via_asset": "true=把锚到同一批资产的结论也带出来（一条「这台是反代」因此能解释它后面的后端）",
        },
    },
    "list_suppressions": {
        "run": _list_suppressions,
        "desc": "看当前的**精准抑制**清单（含命中数与到期时间）。抑制会挡住派工，不看一眼容易误判「为什么没活」",
        "params": {
            "q": "按名称/源IP/规则名模糊筛（可省）",
            "enabled_only": "只看生效中的（true/false）",
            "include_expired": "是否包含已到期的（true/false）",
            "limit": "最多几条（默认 100）",
        },
    },
    "revoke_suppression": {
        "run": _revoke_suppression,
        "desc": (
            "撤销一条精准抑制（发现自己之前判错时主动收回）。"
            "必须写原因：抑制是「关掉一部分检测」，放开同样要留审计"
        ),
        "params": {
            "suppression_id": "抑制条目 ID（从 list_suppressions 拿）",
            "reason": "为什么放开（必填）",
        },
    },
    "add_task": {
        "run": _add_task,
        "desc": (
            "主动登记一条线索进队列（不经过领取也能留痕）。"
            "从外部情报或巡逻中发现「这事值得看」时用；与自动线索同一套去重、容量与配额，不插队"
        ),
        "params": {
            "subject": "对象（IP / 资产 / 账号）",
            "subject_kind": "对象类型：ip / asset / segment / account / protocol / cluster（默认 ip）",
            "kind": "线索类型：novelty/shift/structure/coverage/hit（默认 structure）",
            "note": "为什么值得看（写清依据，界面可见）",
            "strength": "你认为的优先级 0~1（默认 0.6；仍受同族去重与容量约束）",
        },
    },
    "get_event": {
        "run": _get_event,
        "desc": (
            "按事件 ID 或指纹取这条事件**已有的结论**（分析过没有、结论是什么）。"
            "ID 从 search_hits 的结果里拿——新架构不再靠推送带 ID 过来"
        ),
        "params": {
            "event_id": "事件 ID（search_hits 返回的 id）",
            "fingerprint": "指纹（二者至少给一个；没有 ID 时可按现象指纹回溯）",
        },
    },
    "get_rule": {
        "run": _get_rule,
        "desc": "取检测规则原文（判断摘要为什么被判可疑）",
        "params": {"name": "规则名（完全一致）", "rule_id": "规则 ID"},
    },
    "detector_status": {
        "run": _detector_status,
        "desc": "检测器运行状态：队列积压、吞吐、丢弃/去重/失败计数、主从、Redis 内存",
        "params": {},
    },
    "list_networks": {
        "run": _list_networks,
        "desc": "监控网段清单（内网判定依据）",
        "params": {},
    },
    "list_filters": {
        "run": _list_filters,
        "desc": "两道过滤闸门清单：入库前降噪（不投检测器）与排除过滤（跳过分析）",
        "params": {},
    },
    "fetch_window": {
        "run": _fetch_window,
        "desc": "按时间窗整批取回事件条目（可限定网段/IP，含原文），用于回溯：自己跑规则看历史行为",
        "params": {
            "start": "起点（ISO 时间）",
            "end": "终点（ISO 时间）",
            "nets": "网段清单（数组或逗号分隔，可省）",
            "ips": "IP 清单（数组或逗号分隔，可省；给了就用它收窄）",
            "limit": f"最多取回条数（默认与上限都是 {WINDOW_MAX}）",
        },
    },
    "record_conclusion": {
        "run": _record_conclusion,
        "desc": "把调查结论写回 NDR（界面可见；同一事件只留一份，重复写会覆盖）",
        "params": {
            "summary": "结论正文（必填）",
            "event_id": "事件ID",
            "fingerprint": "指纹",
            "status": f"结论状态（可省，默认 done；可选：{'、'.join(STATUS_VALUES)}；中文别名也认）",
            "severity": f"定级（可省，默认 info；可选：{'、'.join(SEVERITY_VALUES)}；中文别名也认）",
            "detail": "对象：证据、处置建议等",
            "thread_id": "分析线程 ID",
        },
    },
    "baseline_lookup": {
        "run": _baseline_lookup,
        "desc": (
            "查数值基线：某个源 IP 的连接数/目的端口数/目的 IP 数的长期均值与标准差，"
            "以及是否过了观测期（判断「这条摘要是不是真的偏离常态」的依据）"
        ),
        "params": {
            "ip": "源 IP（查它的全部维度）",
            "key": f"完整维度键（形如 10.0.0.5:{_FEATURE_EXAMPLE}）",
            "limit": f"最多返回条数（默认 50，上限 {BASELINE_MAX}）",
        },
    },
    "entity_profile": {
        "run": _entity_profile,
        "desc": (
            "查账号/会话画像（跨窗口长期基线）：常用源 IP/UA/路径/时段、成功失败计数、"
            "风险分与异常理由；也能只看过阈值的异常"
        ),
        "params": {
            "kind": "account 或 session（可省，省了两种都查）",
            "keys": "实体键清单（数组或逗号分隔，可省；给了就指名查）",
            "min_risk": "只看风险 ≥ 这个值（0~1）",
            "anomalies_only": "只要过阈值的异常（true/false）",
            "limit": f"最多返回条数（默认 20，上限 {PROFILE_MAX}）",
        },
    },
    "submit_suppression": {
        "run": _submit_suppression,
        "desc": (
            "申请**自动抑制**：证据够硬就对该类现象不再派工、不再生成事件。"
            "六道机械门槛（结构化匹配、≥2 个维度、引用必须本会话真取回、≥2 种取数工具、"
            "置信度达标、新现象保护期）；影响面过大会自动降级成「只不派工、事件仍生成」。"
            "只该在确认是误报时提交 —— 抑制会挡住后续同类事件"
        ),
        "params": {
            "match": "条件树：{logic: 'and', rules: [{field, op, value}]}；字段见 allowed_fields"
                     "（src_ip/dst_ip/dst_port/segment/protocol/rule/signature_id/http.uri/"
                     "http.hostname/user_agent/ja3/fuid），至少 2 个不同字段",
            "reason_code": "理由码：known_service / internal_scanner / vendor_heartbeat / "
                           "business_normal / duplicate_of_task / repeated_after_analysis",
            "evidence_refs": "证据引用数组（必须是本会话真取回过的 es:/ev: 引用，至少 3 条）",
            "confidence": "你的置信度 0~1（低于门槛不会自动生效）",
            "name": "条目名（可省）",
            "note": "依据说明（审计与界面可见）",
            "ttl_days": "有效期天数（可省，默认 14、上限 30）",
            "task_id": "关联的任务 ID（可省）",
        },
    },
    "claim_tasks": {
        "run": _claim_tasks,
        "desc": (
            "领取待分析的**客观线索**（队列）。服务端按令牌强制预算：每小时配额、并发在跑数、"
            "高强度保留名额，响应里回 budget（剩余额度）。领到的任务只含事实（偏离倍数、"
            "是否首见、涉及对象数），不含严重度与结论——判断权在你"
        ),
        "params": {
            "limit": "最多领几个（默认 1，上限 20）",
            "kinds": "只要这些类型的线索，逗号分隔：novelty 首见 / shift 自身基线偏离 / "
            "structure 结构特征 / coverage 盲区 / hit 规则命中（留空=都要）",
            "min_strength": "只要客观强度不低于这个值的线索（0~1，默认 0）",
            "wait_seconds": "队列暂时没线索时最多等多久（0~30 秒长轮询，默认 0 立刻返回）",
        },
    },
    "complete_task": {
        "run": _complete_task,
        "desc": (
            "交回分析结论（写 analysis_results 并释放任务）。可以顺带：next_tasks 追加追问"
            "（受深度上限）、suppression 提交**精准抑制**（只在判为 false_positive 时允许，"
            "要求至少 2 个匹配维度，且证据引用必须是本次会话真取回过的）"
        ),
        "params": {
            "task_id": "任务 ID（claim_tasks 返回的 id）",
            "verdict": "结论：true_positive / false_positive / benign / suspicious / inconclusive（中文别名与 tp/fp 简写也认）",
            "summary": "结论正文（给人看，说清依据）",
            "confidence": "你自己的置信度 0~1",
            "findings": "对象：结构化发现（任意键值）",
            "evidence_refs": "支撑结论的证据引用（必须是本会话真取回过的 es:/ev: 引用）",
            "next_tasks": "数组：还要追加哪些活，每项 {kind, subject_kind, subject, feature, strength, hint}",
            "suppression": "对象：{match, reason_code, note, ttl_days} —— match 是条件树，"
            "reason_code 只认白名单码，只在 false_positive 时允许",
            "anchors": "数组：这条结论影响哪些资产，每项 {kind, value}；"
            "kind 只认 ip / host / domain / endpoint / service（最多 50 个）。"
            "一条「这台是反向代理」要挂到它后面的后端主机上，否则下次分析还得从头查",
            "terminal_reason": "这次是怎么结束的：concluded / budget_exhausted / tool_error / "
            "timeout / aborted（不填按 concluded）",
            "tools_used": "本任务用了多少次工具调用（预算调优的成本口径）",
            "duration_ms": "本任务耗时毫秒",
        },
    },
    "defer_task": {
        "run": _defer_task,
        "desc": "把这个任务延后再领（数据还没入齐、或现在不想深挖）。不算失败，但会释放租约",
        "params": {
            "task_id": "任务 ID",
            "reason": "为什么延后（界面可见）",
            "retry_after_seconds": "多久后可以再领（默认 3600）",
        },
    },
    "task_stats": {
        "run": _task_stats,
        "desc": "队列与成本总览：各状态条数、按类型分布、结论分布、平均成本、覆盖率、当前预算配置",
        "params": {
            "days": "覆盖率回看天数（可省）",
            "kind": "只看某类对象（可省）",
            "limit": "盲区清单最多几条（默认 20）",
        },
    },
    "asset_map": {
        "run": _asset_map,
        "desc": (
            "数据地图之**对象清单**：NDR 见过的资产 / 服务端口 / 外部对端 / 协议 / 签名，"
            "各带首次出现、最近出现、见到次数、被分析次数。用来自己挑分析目标"
        ),
        "params": {
            "kind": "只看某一类：asset 内网资产 / service_port 资产加端口 / peer 外部对端 / "
            "protocol 协议 / signature 签名 / account 账号（留空=每类都取）",
            "limit": "每类最多列多少个（默认 100，上限 1000）",
        },
    },
    "coverage_report": {
        "run": _coverage_report,
        "desc": "覆盖率与盲区：近 N 天有多少对象被分析过、哪些从来没看过、哪些久未看；"
                "by=asset 走锚点口径看「多少资产被结论覆盖过」",
        "params": {
            "by": "统计口径：subject（默认，只看对象本身）/ asset（经锚点统计被结论覆盖的资产数）",
            "days": "回看天数（默认取界面「分析机制」里的盲区判定天数）",
            "kind": "只看某类对象（asset/service_port/peer/protocol/signature/account）",
            "limit": "清单最多几条",
        },
    },
    "file_content": {
        "run": _file_content,
        "desc": (
            "取提取件（Zeek 落盘的明文文件）的**内容或元数据**：按 fuid 取回有界字节；"
            "文本用 encoding=text、二进制用 base64；只要元数据（大小/类型/是否被截断）就调小 max_bytes=1"
        ),
        "params": {
            "fuid": "文件 id（事件里的 extracted/fuid 字段）",
            "encoding": "text 或 base64（默认 base64）",
            "max_bytes": f"最多读多少字节（默认 {FILE_DEFAULT_BYTES}，上限 {FILE_MAX_BYTES}）",
        },
    },
    "task_state": {
        "run": _task_state,
        "desc": (
            "查单条任务的当前状态与结论。**会话结束前先调它**：确认自己到底交回没有 —— "
            "没交回就继续查完再 complete_task，别让任务被租约回收"
        ),
        "params": {"task_id": "任务 ID（claim_tasks 返回的 id）"},
    },
    "log_step": {
        "run": _log_step,
        "desc": (
            "记一条过程观察（一句话），让后来分析别的对象的任务不必重复取数。"
            "只写结论性的发现（如「这 IP 是反向代理」「这条签名在 8080 上噪声大」），"
            "**不要贴原始报文**——原始证据留在 ES，用 es: 引用去取。"
            f"每个任务最多 {20} 条"
        ),
        "params": {
            "task_id": "任务 ID",
            "tool": "产生这条观察的取数工具名（可省）",
            "summary": "一句话观察（≤500 字）",
            "detail": "可选细节（≤2000 字，仍不要贴原始报文）",
        },
    },
    "search_traces": {
        "run": _search_traces,
        "desc": (
            "在**别的任务**的过程记录里检索（自动排除自己这条）：免得把同一个取数再做一遍。"
            "返回的是「他人未经核实的观察」——可以当线索去验证，**不能当结论、不能当抑制证据**"
        ),
        "params": {
            "q": "关键字",
            "exclude_task": "排除哪个任务（通常填自己当前的 task_id）",
            "subject": "只看某个对象的过程记录（可省）",
            "limit": "最多返回条数（默认 20，上限 50）",
        },
    },
    "get_trace": {
        "run": _get_trace,
        "desc": "取某个任务的全部过程步骤（配合 search_traces 做细节交换）",
        "params": {
            "task_id": "要看的任务 ID",
            "limit": "最多返回几步（默认 20）",
        },
    },
}


def tool_names() -> list[str]:
    return sorted(TOOLS)


def dispatch(name: str, params: dict[str, Any]) -> dict[str, Any]:
    """按工具名分派到对应实现；错误一律转成结构化结果（模型自我纠正，不炸掉整次调用）。

    叫 `dispatch` 而不是 `execute`：它分派的是调查工具，与任何 SQL/子进程端点无关；
    名字里带 execute 还会被静态扫描当成动态执行端点（实际参数是工具名）。
    """
    spec = TOOLS.get(name)
    if spec is None:
        return {"error": f"未知工具 {name}。可用工具：{', '.join(tool_names())}"}
    try:
        result = spec["run"](params)
        return result if isinstance(result, dict) else {"result": result}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"工具执行失败：{exc}"}
