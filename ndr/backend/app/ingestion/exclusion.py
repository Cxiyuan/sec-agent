"""用户自定义排除过滤：命中后事件仍落库，但跳过全部模型调用与报告生成。

为什么是"记事件但跳过模型"而不是"直接丢弃"：排除是为了降噪与省模型成本，
但一次配错就把攻击彻底藏起来（连事件都没有、界面看不到）比多花点钱更糟。
所以被排除的事件照常进事件组（带"已排除"标记，界面默认折叠、可切换查看），
只是不跑 LLM 链、不出报告、不进记忆。

条件作用域 = UnifiedLog 全字段 + 命中规则元数据（hit_rule / rule_source / rule_severity），
检查点因此必须在**规则命中之后**；求值直接复用规则引擎（extra 参数注入规则元数据）。

失效策略：配置读取/求值异常一律 **fail-open**（照常分析）—— 宁可多花钱，绝不静默漏报。
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.config import settings
from app.db.base import SessionLocal
from app.db.models import ExclusionFilter
from app.rules.engine import VIRTUAL_FIELDS, evaluate_conditions, validate_rule_regexes
from app.schemas import UnifiedLog
from app.workers.log import get_logger

log = get_logger(__name__)

# 命中规则元数据（虚拟字段，只在排除过滤求值时可用）
EXTRA_FIELDS = ("hit_rule", "rule_source", "rule_severity")

_STATS_KEY = "shentong:exclusion:stats"  # hash：过滤器名 -> 命中次数
_SAMPLES_KEY = "shentong:exclusion:samples"  # hash：过滤器名 -> JSON 样例列表（最多 3 条）
_TTL = 30 * 24 * 3600
_MAX_SAMPLES = 3

_cache: tuple[float, list[dict[str, Any]]] = (0.0, [])
_client_cache: Any | None = None


def allowed_fields() -> set[str]:
    """允许在排除条件里引用的字段：日志字段 + 命中规则元数据 + **内外网方向虚拟字段**。

    方向字段（src_internal / dst_internal / src_external / dst_external）让“内外有别”
    的过滤不必把客户网段写死（不用再写 src_ip contains "172.16."）。
    """
    return set(UnifiedLog.model_fields) | set(EXTRA_FIELDS) | set(VIRTUAL_FIELDS)


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
    """保存前校验，返回错误列表（空 = 通过）。三道保险防"一条配置静音整条链路"。"""
    errors: list[str] = []
    cond = conditions or {}
    if not cond.get("rules"):
        errors.append("排除条件不能为空（不允许无条件排除一切）")
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
    """懒加载 Redis 客户端（用于命中统计）；不可用时返回 None（统计降级，不影响功能）。"""
    global _client_cache
    if _client_cache is not None:
        return _client_cache
    try:
        import redis

        client: Any = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        client.ping()
    except Exception as exc:  # noqa: BLE001
        log.debug("排除过滤统计不可用（Redis 未就绪）: %s", exc)
        return None
    _client_cache = client
    return client


def load_filters(force: bool = False) -> list[dict[str, Any]]:
    """取启用中的过滤器（按 priority 升序），带缓存；DB 异常时沿用上次缓存。"""
    global _cache
    now = time.time()
    ts, cached = _cache
    if not force and cached and now - ts < max(0, settings.exclusion_cache_seconds):
        return cached
    try:
        with SessionLocal() as db:
            rows = (
                db.execute(
                    select(ExclusionFilter)
                    .where(ExclusionFilter.enabled.is_(True))
                    .order_by(ExclusionFilter.priority)
                )
                .scalars()
                .all()
            )
            items = [{"id": r.id, "name": r.name, "conditions": r.conditions or {}} for r in rows]
    except Exception as exc:  # noqa: BLE001
        log.warning("读取排除过滤器失败，沿用上次配置（%d 条）: %s", len(cached), exc)
        return cached
    _cache = (now, items)
    return items


def invalidate_cache() -> None:
    """清缓存（本进程立即生效；其他进程最迟 exclusion_cache_seconds 后生效）。"""
    global _cache
    _cache = (0.0, [])


def check_filter(
    entry: UnifiedLog,
    *,
    rule_name: str | None = None,
    rule_source: str | None = None,
    rule_severity: str | None = None,
) -> str | None:
    """命中则返回过滤器名，否则 None；任何异常都按"未命中"处理（fail-open）。"""
    filters = load_filters()
    if not filters:
        return None
    extra = {
        "hit_rule": rule_name or "",
        "rule_source": rule_source or "",
        "rule_severity": rule_severity or "",
    }
    for item in filters:
        cond = item.get("conditions") or {}
        if not cond.get("rules"):
            continue  # 空条件跳过（保存时已拒绝，这里双保险）
        try:
            if evaluate_conditions(cond, entry, extra=extra):
                return str(item.get("name") or "")
        except Exception as exc:  # noqa: BLE001
            log.warning("排除过滤求值失败（按未命中处理）%s: %s", item.get("name"), exc)
    return None


def record_hit(name: str, entry: UnifiedLog, *, rule_name: str = "") -> None:
    """记录命中次数与样例（最多 3 条），供界面回答"排除了什么"。"""
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
            samples.append(
                {
                    "at": datetime.now(UTC).isoformat(),
                    "ts": entry.ts.isoformat() if entry.ts else "",
                    "rule": rule_name,
                    "src_ip": entry.src_ip or "",
                    "dst_ip": entry.dst_ip or "",
                    "event_type": entry.event_type,
                    "summary": (entry.summary or "")[:200],
                }
            )
            client.hset(_SAMPLES_KEY, name, json.dumps(samples, ensure_ascii=False))
        client.expire(_SAMPLES_KEY, _TTL)
    except Exception as exc:  # noqa: BLE001
        log.debug("写入排除命中统计失败: %s", exc)


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
        log.warning("读取排除命中统计失败: %s", exc)
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
        log.warning("读取排除命中样例失败: %s", exc)
    return out
