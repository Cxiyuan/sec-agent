"""组件 / 服务连接状态（总览页的 8 个呼吸灯）。

**为什么是一个端点**：页面每 15 秒轮询，如果让前端打七个接口，任何一个超时都会拖慢整页，
也让后端的连接数翻七倍。这里一次拿全部，并且**每 `ST_STATUS_PROBE_CACHE_SECONDS`（默认 30s）
才真正探测一轮**（进程内缓存）。页面 15 秒轮询时大约两次里有一次命中缓存。

**判据全部是 `judge_*` 纯函数**（可单测）；每个探测各自 try —— 任何一个失败只影响它自己

`detector/health.py` 的 Redis 体检），避免同一个事实在两处各写一遍再慢慢漂移。
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends

from app.api.deps import get_current_user
from app.api.routes import logstash as logstash_route
from app.config import settings
from app.db.base import SessionLocal
from app.db.models import User
from app.detector import health, push
from app.workers.log import get_logger

#: 等价于 3.11 的 `datetime.UTC`（本仓库 requires-python >=3.11）；用别名写法
#: 免得按旧语法解析的静态检查工具报「unknown import symbol」。
UTC = timezone.utc

log = get_logger(__name__)

router = APIRouter(prefix="/api/health", tags=["health"])

#: 状态四档：ok=正常；degraded=能用但需要注意；down=不可用；unknown=没有足够信息（例如没配）
STATE_OK = "ok"
STATE_DEGRADED = "degraded"
STATE_DOWN = "down"
STATE_UNKNOWN = "unknown"

#: 新鲜度阈值（秒）：网络采集器与归一化服务的「在不在干活」判据
ZEEK_OK_WITHIN = 300.0  # 近 5 分钟有 zeek 文档 = 正常
ZEEK_DEGRADED_WITHIN = 1800.0  # 5~30 分钟没有 = 注意；超过 30 分钟 = 停
NORMALIZER_OK_WITHIN = 120.0  # 归一化是唯一写 ES 的角色，2 分钟没写就是不正常
NORMALIZER_DEGRADED_WITHIN = 900.0

_FRESHNESS_WINDOW = "now-30m"

#: 「采集质量」统计窗口（近 15 分钟的采集类协议异常）
_CAPTURE_WINDOW = "now-15m"

#: 总览页的**展示顺序**（用户列的顺序：网络采集器 / 采集质量 / Redis / Logstash /
#: Elasticsearch / 归一化 / 分析智能体）。构建顺序与展示顺序解耦，前端直接照数组渲染。
_DISPLAY_ORDER: tuple[str, ...] = (
    "zeek",
    "capture",
    "redis",
    "logstash",
    "elasticsearch",
    "normalizer",
    "agent",
)

_cache: dict[str, Any] = {"at": 0.0, "payload": None}
_cache_lock = threading.Lock()


# ---------- 小工具（把「可能脏的外部值」收敛到一处，别在每个判据里各写一遍 try） ----------


def _int_or_none(value: Any) -> int | None:
    """能转 int 就转，否则 None（ES/Redis 的值可能是字符串、缺字段或 null）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# ---------- 判据（纯函数，单测直接打这些） ----------


def judge_age(age: float | None, ok_within: float, degraded_within: float) -> str:
    """按「多久没动静」判灯：未知年龄 → unknown（没有信息不等于坏了）。"""
    if age is None:
        return STATE_UNKNOWN
    if age <= ok_within:
        return STATE_OK
    if age <= degraded_within:
        return STATE_DEGRADED
    return STATE_DOWN


def judge_capture(count: int | None, warn: int, crit: int) -> str:
    """采集类协议异常（镜像口丢包 / 非对称路由 / 网卡 offload 的痕迹）的数量判据。

    为什么它算「健康」而不是「安全」：这类异常说明**采集在丢东西（丢包 = 漏检）**，
    本身不是攻击信号，所以不进摘要、只在这里显示（见 `ingestion/normalizer.py` 的
    `_capture_weird`）。数量突增 = 采集质量在退化。
    """
    if count is None:
        return STATE_UNKNOWN
    if crit > 0 and count >= crit:
        return STATE_DOWN
    if warn > 0 and count >= warn:
        return STATE_DEGRADED
    return STATE_OK


def judge_es(status: str | None) -> str:
    """ES 集群健康：green/yellow 都算能用，red 才是不可用。"""
    """集群健康：green 正常、yellow 注意、red/未知 不可用。"""
    value = str(status or "").strip().lower()
    if value == "green":
        return STATE_OK
    if value == "yellow":
        return STATE_DEGRADED
    if value == "red":
        return STATE_DOWN
    return STATE_UNKNOWN


def judge_redis(reachable: bool, warn: bool) -> str:
    """Redis 可达 = 正常；内存过告警线 = 注意（历史上写满会让整条链路静默卡死）。"""
    if not reachable:
        return STATE_DOWN
    return STATE_DEGRADED if warn else STATE_OK


def judge_logstash(runtime: dict[str, Any] | None) -> str:
    """Logstash：9600 探活；有重载失败 = 注意；不可达 = 停。"""
    if not isinstance(runtime, dict) or not runtime.get("alive"):
        return STATE_DOWN
    failures = _int_or_none(runtime.get("reloads_failures"))
    if failures is not None and failures > 0:
        return STATE_DEGRADED
    return STATE_OK


def judge_agent(active: bool, last_success_at: str, has_error: bool) -> str:
    """分析智能体：没配地址 → unknown（不知道，而不是坏了）；配了但从未成功/有错 → 注意。"""
    if not active:
        return STATE_UNKNOWN
    if has_error and not last_success_at:
        return STATE_DEGRADED
    if not last_success_at:
        return STATE_DEGRADED
    return STATE_OK


# ---------- 探测 ----------


def _redis_client() -> Any:
    import redis

    return redis.Redis.from_url(settings.redis_url, decode_responses=True)


def _es_health() -> tuple[str | None, str]:
    """(集群健康色, 详情)。失败时颜色为 None。"""
    try:
        from app.ingestion.es_client import get_es

        info = get_es().cluster.health()
        status = str(info.get("status") or "")
        nodes = _int_or_none(info.get("number_of_nodes")) or 0
        unassigned = _int_or_none(info.get("unassigned_shards")) or 0
        detail = f"{status or '?'} · {nodes} 节点 · 未分配 {unassigned}"
        return status, detail
    except Exception as exc:  # noqa: BLE001
        return None, f"读 ES 集群健康失败：{str(exc)[:160]}"


def _capture_stats() -> dict[str, Any]:
    """近 15 分钟的**采集类**协议异常：条数 + 最常见的几个异常名。

    数据来源是归一化已经分好类的 `event_type=capture_anomaly`（见 normalizer._capture_weird）。
    """
    out: dict[str, Any] = {"count": None, "top": [], "error": ""}
    try:
        from app.ingestion import es_config
        from app.ingestion.es_client import get_es

        pattern = str(es_config.current().get("es.events_index") or settings.es_events_index)
        query = {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": _CAPTURE_WINDOW}}},
                    {"term": {"event_type.keyword": "capture_anomaly"}},
                ]
            }
        }
        try:
            resp = get_es().search(
                index=pattern,
                size=0,
                query=query,
                aggs={"names": {"terms": {"field": "weird_name.keyword", "size": 5}}},
            )
            names = [
                (str(bucket.get("key")), int(bucket.get("doc_count") or 0))
                for bucket in resp["aggregations"]["names"]["buckets"]
            ]
        except Exception:  # noqa: BLE001 — 字段还没建映射（首次上线的历史索引）时降级成只数条数
            resp = get_es().search(index=pattern, size=0, query=query)
            names = []
        out["count"] = _int_or_none(resp["hits"]["total"]["value"])
        out["top"] = names
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)[:160]
    return out


def _capture_item() -> dict[str, Any]:
    """「采集质量」灯：采集类协议异常（丢包痕迹）当成健康指标看，而不是告警。"""
    stats = _capture_stats()
    count = stats.get("count")
    state = judge_capture(
        count, settings.capture_anomaly_warn_15m, settings.capture_anomaly_crit_15m
    )
    name = "采集质量（采集类协议异常）"
    if count is None:
        detail = f"读不到采集异常统计：{stats.get('error') or '未知原因'}"
    else:
        top = "、".join(f"{key} {value}" for key, value in (stats.get("top") or [])[:3])
        detail = f"近 15 分钟采集类协议异常 {count} 条"
        if top:
            detail += f"（最常见：{top}）"
        detail += "；多为镜像口丢包/非对称路由/网卡 offload —— 突增说明采集在丢包（会漏检）"
    return {"key": "capture", "name": name, "state": state, "detail": detail}


def _es_freshness() -> dict[str, Any]:
    """近 30 分钟：按来源的最新文档时间 + 全局最新时间（一次 ES 往返喂三盏灯）。"""
    out: dict[str, Any] = {"zeek_age": None, "any_age": None, "error": ""}
    try:
        from app.ingestion import es_config
        from app.ingestion.es_client import get_es

        cfg = es_config.current()
        pattern = str(cfg.get("es.events_index") or settings.es_events_index)
        resp = get_es().search(
            index=pattern,
            size=0,
            query={"range": {"@timestamp": {"gte": _FRESHNESS_WINDOW}}},
            aggs={
                "any": {"max": {"field": "@timestamp"}},
                "src": {
                    "terms": {"field": "source_system.keyword", "size": 5},
                    "aggs": {"last": {"max": {"field": "@timestamp"}}},
                },
            },
        )
        now_ms = time.time() * 1000.0

        def _age(value: Any) -> float | None:
            value_ms = _float_or_none(value)
            if value_ms is None:
                return None
            return max(0.0, (now_ms - value_ms) / 1000.0)

        aggs = resp.get("aggregations") or {}
        out["any_age"] = _age((aggs.get("any") or {}).get("value"))
        for bucket in (aggs.get("src") or {}).get("buckets") or []:
            key = str(bucket.get("key") or "")
            if key == "zeek":
                out[f"{key}_age"] = _age((bucket.get("last") or {}).get("value"))
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)[:160]
    return out


def _redis_item(client: Any) -> dict[str, Any]:
    reachable = False
    mem: dict[str, Any] = {}
    try:
        client.ping()
        reachable = True
        mem = health.redis_memory(client)
    except Exception as exc:  # noqa: BLE001
        return {
            "key": "redis",
            "name": "Redis",
            "state": judge_redis(False, False),
            "detail": f"不可达：{str(exc)[:120]}",
            "last_seen": "",
        }
    warn = (
        bool(mem.get("max"))
        and (_float_or_none(mem.get("perc")) or 0.0) >= settings.redis_memory_warn_perc
    )
    detail = health.describe(mem) if mem else "可达（读不到内存信息）"
    return {
        "key": "redis",
        "name": "Redis",
        "state": judge_redis(reachable, warn),
        "detail": detail,
        "last_seen": "",
    }


def _agent_item(client: Any) -> dict[str, Any]:
    try:
        with SessionLocal() as db:
            cfg = push.load_config(db)
        active = push.is_on(cfg)
        st = push.status(client)
    except Exception as exc:  # noqa: BLE001
        return {
            "key": "agent",
            "name": "分析智能体",
            "state": STATE_UNKNOWN,
            "detail": f"读推送状态失败：{str(exc)[:120]}",
            "last_seen": "",
        }
    last_success = str(st.get("last_success_at") or "")
    has_error = bool(st.get("last_error"))
    state = judge_agent(active, last_success, has_error)
    if not active:
        detail = "未配置推送地址（摘要计入未投递，不会进入分析）"
    elif last_success:
        detail = (
            f"最近送达 {last_success.replace('T', ' ')[:19]} · 未投递 {st.get('undelivered', 0)}"
        )
    else:
        detail = f"已配置但还没成功投递过（{str(st.get('last_error') or '等待首次投递')[:60]}）"
    return {
        "key": "agent",
        "name": "分析智能体",
        "state": state,
        "detail": detail,
        "last_seen": last_success,
    }


def _stub(key: str, name: str, state: str, detail: str = "") -> dict[str, Any]:
    """探测不可用时的占位项（有 key/name/state，前端永远有东西可渲染）。"""
    return {"key": key, "name": name, "state": state, "detail": detail, "last_seen": ""}


def _guard(name: str, fn: Any, fallback: dict[str, Any]) -> dict[str, Any]:
    """跑一个探测；**任何异常都只影响这一项**（其余灯照常显示）。

    每个探测函数自己也会吞异常，但这里再兜一层：探测函数内部将来改动引入的意外错误
    不能把整个总览页打空（那是运维页，少一盏灯也比白屏好）。
    """
    try:
        item = fn()
    except Exception as exc:  # noqa: BLE001
        log.debug("组件探测 %s 失败: %s", name, exc)
        return {**fallback, "detail": f"探测失败：{str(exc)[:120]}"}
    return item if isinstance(item, dict) else fallback


def _es_item() -> dict[str, Any]:
    status, detail = _es_health()
    return {
        "key": "elasticsearch",
        "name": "Elasticsearch",
        "state": judge_es(status),
        "detail": detail,
        "last_seen": "",
    }


def _logstash_item() -> dict[str, Any]:
    runtime = logstash_route.pipeline_runtime()
    alive = bool(isinstance(runtime, dict) and runtime.get("alive"))
    return {
        "key": "logstash",
        "name": "Logstash",
        "state": judge_logstash(runtime),
        "detail": (
            f"入库 {runtime.get('events_in')} · 出 {runtime.get('events_out')}"
            f" · 重载失败 {runtime.get('reloads_failures')}"
            if alive
            else f"不可达：{str((runtime or {}).get('error') or '')[:120]}"
        ),
        "last_seen": "",
    }


def _freshness_item(
    fresh: dict[str, Any],
    *,
    key: str,
    name: str,
    age_key: str,
    ok_within: float,
    degraded_within: float,
    prefix: str,
) -> dict[str, Any]:
    """按「入库新鲜度」判的灯（网络采集器 / 归一化服务共用）。"""
    age = _float_or_none(fresh.get(age_key))
    return {
        "key": key,
        "name": name,
        "state": judge_age(age, ok_within, degraded_within),
        "detail": (
            f"{prefix} {round(age)} 秒前"
            if age is not None
            else f"读不到入库时间：{str(fresh.get('error') or '未知')[:100]}"
        ),
        "last_seen": "",
    }


def _collect() -> dict[str, Any]:
    """跑一轮全部探测（不缓存）。每项经 `_guard`，互不牵连。"""
    client: Any = None
    try:
        client = _redis_client()
    except Exception as exc:  # noqa: BLE001
        log.debug("健康探测建 Redis 连接失败: %s", exc)

    items: list[dict[str, Any]] = [
        _guard("elasticsearch", _es_item, _stub("elasticsearch", "Elasticsearch", STATE_UNKNOWN)),
        _guard("logstash", _logstash_item, _stub("logstash", "Logstash", STATE_DOWN)),
    ]

    # Redis / 分析智能体：两者都需要 Redis 连接
    if client is None:
        items.append(_stub("redis", "Redis", STATE_DOWN, "连接失败（读不到地址或驱动异常）"))
        items.append(_stub("agent", "分析智能体", STATE_UNKNOWN, "Redis 不可达，读不到推送状态"))
    else:
        items.append(
            _guard("redis", lambda: _redis_item(client), _stub("redis", "Redis", STATE_DOWN))
        )
        items.append(
            _guard(
                "agent", lambda: _agent_item(client), _stub("agent", "分析智能体", STATE_UNKNOWN)
            )
        )

    # 新鲜度：一次 ES 往返喂两盏灯（`_es_freshness` 自己吞异常，这里再兜一层）
    fresh: dict[str, Any] = {}
    try:
        fresh = _es_freshness()
    except Exception as exc:  # noqa: BLE001
        log.debug("ES 新鲜度探测失败: %s", exc)
        fresh = {"error": str(exc)[:160]}
    items.append(
        _guard(
            "zeek",
            lambda: _freshness_item(
                fresh,
                key="zeek",
                name="网络采集器",
                age_key="zeek_age",
                ok_within=ZEEK_OK_WITHIN,
                degraded_within=ZEEK_DEGRADED_WITHIN,
                prefix="近 30 分钟最新一条",
            ),
            _stub("zeek", "网络采集器", STATE_UNKNOWN),
        )
    )
    items.append(
        _guard(
            "normalizer",
            lambda: _freshness_item(
                fresh,
                key="normalizer",
                name="归一化服务",
                age_key="any_age",
                ok_within=NORMALIZER_OK_WITHIN,
                degraded_within=NORMALIZER_DEGRADED_WITHIN,
                prefix="最近入库",
            ),
            _stub("normalizer", "归一化服务", STATE_UNKNOWN),
        )
    )

    items.append(
        _guard(
            "capture",
            _capture_item,
            _stub("capture", "采集质量（采集类协议异常）", STATE_UNKNOWN),
        )
    )

    return {
        "checked_at": datetime.now(UTC).isoformat(),
        # 按展示顺序输出（不在表里的一律排后面，保证任何情况下都不丢项）
        "items": sorted(
            items,
            key=lambda it: (
                _DISPLAY_ORDER.index(it["key"]) if it.get("key") in _DISPLAY_ORDER else 99
            ),
        ),
        "notes": [],
        "cached": False,
    }


@router.get("/components")
def health_components(_: Annotated[User, Depends(get_current_user)]):
    """七个组件/服务的连接状态（总览页的呼吸灯）。结果进程内缓存 `status_probe_cache_seconds`。"""
    ttl = max(0.0, float(settings.status_probe_cache_seconds))
    now = time.monotonic()
    with _cache_lock:
        cached = _cache.get("payload")
        if ttl > 0 and cached is not None and now - float(_cache.get("at") or 0.0) < ttl:
            return {**cached, "cached": True}
        payload = _collect()
        _cache["at"] = now
        _cache["payload"] = payload
        return payload
