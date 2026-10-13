"""24 小时流量（字节量）与协议占比（总览页的两张图）。

**一次 ES `_search` 拿两块**，因为它们共用同一个时间窗与同一份文档集合：
- `traffic`：`date_histogram`（1 小时）出逐小时字节量与条数。**必须过滤 `log_type=conn`**：
  `bytes_in` 在 HTTP 文档里取自 `response_body_len`（见 `ingestion/normalizer.py` 的
  `_http_fields`），不在 conn 上过滤就会把同一份响应字节重复计一遍，曲线直接虚高。
- `protocols`：**只统计协议识别类日志**（白名单 `ST_STATS_PROTOCOL_LOG_TYPES`，见
  `ingestion/log_types.py`）的 `terms` 占比。不这么限，conn（流记录）/weird（异常）/
  files（文件产物）/syslog（主机日志）会一起进饼图，那张图就不再是「协议占比」而是
  「我们的日志构成」——实机 24h 里 conn 一家就占 56%。另回一个 `excluded_docs`
  （被排除的非协议日志量），好让图上注明「另有 X% 未计入」，不静默消失。

**缓存**：24h 聚合在几百万文档上是秒级操作，而总览页每 15 秒轮询 → 进程内缓存
`ST_STATUS_AGG_CACHE_SECONDS`（默认 300s），命中直接回 `cached=True`，**不许穿透到 ES**。
"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends

from app.api.deps import get_current_user
from app.config import settings
from app.db.models import User
from app.ingestion.log_types import stats_protocol_log_types
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/stats", tags=["stats"])

#: 协议占比取前多少个类型（其余并进「其他」）
PROTOCOL_TOP_N = 15
#: 默认 / 允许的时间窗（小时）
DEFAULT_HOURS = 24
MAX_HOURS = 168
#: 聚合粒度固定 1 小时（总览页的曲线就是按小时的 24 个点）
_INTERVAL = "1h"

_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_cache_lock = threading.Lock()


def clamp_hours(value: Any) -> int:
    """时间窗夹到 `1..MAX_HOURS`；脏值回落默认 24h。"""
    try:
        hours = int(value)
    except (TypeError, ValueError):
        return DEFAULT_HOURS
    return max(1, min(hours, MAX_HOURS))


def build_query(hours: int, *, start: str, end: str) -> dict[str, Any]:
    """构造那一份同时出流量与协议的查询（纯函数，单测直接断言结构）。"""
    return {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": start, "lt": end}}},
        "aggs": {
            # 流量只在 conn 上统计（见模块注释：不过滤会把 HTTP 的 bytes_in 重复计入）
            "traffic": {
                "filter": {"term": {"log_type.keyword": "conn"}},
                "aggs": {
                    "per_hour": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": _INTERVAL,
                            "min_doc_count": 0,
                            "extended_bounds": {"min": start, "max": end},
                        },
                        "aggs": {
                            "bytes_out": {"sum": {"field": "bytes_out"}},
                            "bytes_in": {"sum": {"field": "bytes_in"}},
                        },
                    }
                },
            },
            # 协议占比**只算协议识别类日志**（白名单；理由见模块注释与 log_types.py）：
            # conn/weird/files/syslog 这些「流记录/异常/文件产物/主机日志」不算协议。
            # 用 `include` 而不是拉全部再前端过滤：几百万文档上少传几百个桶。
            "protocols": {
                "terms": {
                    "field": "log_type.keyword",
                    "size": PROTOCOL_TOP_N,
                    "include": sorted(stats_protocol_log_types()),
                }
            },
            # 被排除掉的量（非协议日志）：给图上注明「另有 X% 未计入」，不静默消失。
            "excluded": {
                "filter": {
                    "bool": {
                        "must_not": [
                            {"terms": {"log_type.keyword": sorted(stats_protocol_log_types())}}
                        ]
                    }
                }
            },
        },
    }


def _int_of(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float_of(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def shape_traffic(resp: Any, *, hours: int) -> dict[str, Any]:
    """ES 响应 → 逐小时点（含字节/秒）与合计。"""
    buckets = (((resp.get("aggregations") or {}).get("traffic") or {}).get("per_hour") or {}).get(
        "buckets"
    ) or []
    points: list[dict[str, Any]] = []
    total_bytes = 0
    total_docs = 0
    for bucket in buckets:
        if not isinstance(bucket, dict):
            continue
        bytes_out = _int_of(bucket.get("bytes_out", {}).get("value"))
        bytes_in = _int_of(bucket.get("bytes_in", {}).get("value"))
        docs = _int_of(bucket.get("doc_count"))
        total = bytes_out + bytes_in
        total_bytes += total
        total_docs += docs
        points.append(
            {
                "ts": str(bucket.get("key_as_string") or ""),
                "docs": docs,
                "bytes_out": bytes_out,
                "bytes_in": bytes_in,
                "bytes_total": total,
                # 每小时一个桶 → 字节/秒；前端画曲线用这个（不同小时可比）
                "bytes_per_sec": round(total / 3600.0, 1),
            }
        )
    return {
        "points": points,
        "total_docs": total_docs,
        "total_bytes": total_bytes,
        "avg_bytes_per_sec": round(total_bytes / max(1, hours * 3600), 1),
    }


def shape_protocols(resp: Any) -> dict[str, Any]:
    """ES 响应 → 协议占比（前 N + 其他）；非协议日志另外报一个「未计入」的量。

    分母 = 协议类文档总数（= top N 桶之和 + `sum_other_doc_count`）。
    `excluded_*` 是没算进来的那部分（conn/weird/files/syslog 等），只在图上作一句说明。
    """
    aggs = resp.get("aggregations") or {}
    buckets = (aggs.get("protocols") or {}).get("buckets") or []
    items: list[dict[str, Any]] = []
    listed_docs = 0
    for bucket in buckets:
        if not isinstance(bucket, dict):
            continue
        docs = _int_of(bucket.get("doc_count"))
        listed_docs += docs
        name = str(bucket.get("key") or "").strip() or "(空)"
        items.append({"log_type": name, "docs": docs, "percent": 0.0})

    # 协议总数含 top N 之外的（sum_other_doc_count），百分比的分母必须是它
    other_docs = _int_of((aggs.get("protocols") or {}).get("sum_other_doc_count"))
    total = listed_docs + other_docs
    for item in items:
        item["percent"] = round(item["docs"] * 100.0 / total, 2) if total else 0.0

    # 非协议日志（conn 流记录 / weird 异常 / files 产物 / syslog 主机日志 / 名单外新类型…）
    excluded = _int_of((aggs.get("excluded") or {}).get("doc_count"))
    all_docs = total + excluded
    return {
        "total": total,
        "other_docs": other_docs,
        "items": items,
        "excluded_docs": excluded,
        "excluded_percent": round(excluded * 100.0 / all_docs, 2) if all_docs else 0.0,
    }


def _fetch(hours: int) -> dict[str, Any]:
    """真去打 ES（不缓存）。失败时返回带 error 的空结构，端点不 500。"""
    end_dt = datetime.now(UTC)
    start_dt = end_dt - timedelta(hours=hours)
    start_iso = start_dt.isoformat().replace("+00:00", "Z")
    end_iso = end_dt.isoformat().replace("+00:00", "Z")
    payload: dict[str, Any] = {
        "hours": hours,
        "since": start_iso,
        "until": end_iso,
        "traffic": {"points": [], "total_docs": 0, "total_bytes": 0, "avg_bytes_per_sec": 0.0},
        "protocols": {
            "total": 0,
            "other_docs": 0,
            "items": [],
            "excluded_docs": 0,
            "excluded_percent": 0.0,
        },
        "computed_at": end_dt.isoformat(),
        "cached": False,
        "error": "",
    }
    try:
        from app.ingestion import es_config
        from app.ingestion.es_client import get_es

        cfg = es_config.current()
        pattern = str(cfg.get("es.events_index") or settings.es_events_index)
        resp = get_es().search(index=pattern, body=build_query(hours, start=start_iso, end=end_iso))
    except Exception as exc:  # noqa: BLE001
        log.warning("24h 流量/协议聚合失败: %s", exc)
        payload["error"] = str(exc)[:200]
        return payload
    # ⚠️ 不要对 ES 的响应做类型判定：elastic_transport.ObjectApiResponse 的 MRO 是
    # `[ObjectApiResponse, ApiResponse, Generic, object]` —— **既不是 dict，也不是 Mapping**，
    # 只是鸭子类型地实现了 `.get` / `__getitem__`。这里曾经写 `isinstance(resp, dict)` 又改成
    # `isinstance(resp, Mapping)`，两次都把正常响应当成坏响应（实机报「ES 返回了非预期结构」、
    # 整张图空白）。正确做法：直接按鸭子类型用，把解析包进 try，异常才当错误。
    try:
        payload["traffic"] = shape_traffic(resp, hours=hours)
        payload["protocols"] = shape_protocols(resp)
    except Exception as exc:  # noqa: BLE001
        log.warning("解析 24h 流量/协议聚合结果失败: %s", exc)
        payload["error"] = f"解析 ES 聚合结果失败：{str(exc)[:160]}"
    return payload


@router.get("/overview")
def stats_overview(
    _: Annotated[User, Depends(get_current_user)],
    hours: int = DEFAULT_HOURS,
):
    """24 小时流量（字节量）+ 协议占比。结果进程内缓存 `status_agg_cache_seconds`。"""
    window = clamp_hours(hours)
    ttl = max(0.0, float(settings.status_agg_cache_seconds))
    key = str(window)
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(key)
        if ttl > 0 and hit is not None and now - hit[0] < ttl:
            return {**hit[1], "cached": True}
        payload = _fetch(window)
        # 聚合失败不写缓存：下一轮还能立刻重试（而不是把错误钉 5 分钟）
        if not payload.get("error"):
            _cache[key] = (now, payload)
        return payload

#: 近 N 分钟流量（心电图式按分钟打点）——为什么不用 24h/1h：1 小时的桶看不出"现在在不在传"，
#: 而且**未过完的那个小时**会让图上右端假性塌陷（实测被用户当成"流量掉了"）。
TRAFFIC_MINUTES_DEFAULT = 10
TRAFFIC_MINUTES_MAX = 120


def clamp_minutes(value: Any) -> int:
    try:
        minutes = int(value)
    except (TypeError, ValueError):
        return TRAFFIC_MINUTES_DEFAULT
    return max(1, min(minutes, TRAFFIC_MINUTES_MAX))


def build_minute_query(minutes: int, *, start: str, end: str) -> dict[str, Any]:
    """按 **1 秒** 出流量桶（只统计 conn —— HTTP 的 bytes 会重复计入）。

    为什么是每秒而不是每分钟（2026-10 用户口径）：曲线要**按每秒打点**画成心电图式，
    10 分钟 = 600 个点；仪表盘上只显示 **10 个时间段刻度**（整分钟），刻度由
    `shape_minute_traffic` 额外给出的 `minute_marks` 决定。
    """
    return {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": start, "lt": end}}},
        "aggs": {
            "traffic": {
                "filter": {"term": {"log_type.keyword": "conn"}},
                "aggs": {
                    "per_second": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "1s",
                            "min_doc_count": 0,
                            "extended_bounds": {"min": start, "max": end},
                        },
                        "aggs": {
                            "bytes_out": {"sum": {"field": "bytes_out"}},
                            "bytes_in": {"sum": {"field": "bytes_in"}},
                        },
                    }
                },
            }
        },
    }


def shape_minute_traffic(resp: Any, *, minutes: int, now: datetime) -> dict[str, Any]:
    """分钟桶 → 点（含"进行中的这一分钟"按时长折算，避免右端假性塌陷）。"""
    buckets = (((resp.get("aggregations") or {}).get("traffic") or {}).get("per_second") or {}).get(
        "buckets"
    ) or []
    points: list[dict[str, Any]] = []
    minute_marks: list[str] = []
    for bucket in buckets:
        if not isinstance(bucket, dict):
            continue
        bytes_out = _int_of(bucket.get("bytes_out", {}).get("value"))
        bytes_in = _int_of(bucket.get("bytes_in", {}).get("value"))
        total = bytes_out + bytes_in
        start_at = str(bucket.get("key_as_string") or "")
        # 进行中的那一分钟：只过了 x 秒 → 用 x 秒折算速率（否则看上去像流量骤降）
        # 每秒一桶：已经过完的秒就是 1 秒；**当前这一秒**是不完整的 → 标 partial 且不做放大折算
        # （对"1 秒"做按比例放大只会制造尖刺，反而更容易被误读成流量突增）
        partial = False
        elapsed = 1.0
        try:
            began = datetime.fromisoformat(start_at)  # py3.11+ 认 Z
            partial = (now - began).total_seconds() < 0.95
        except (TypeError, ValueError):
            partial = False  # 时间不合法就按"已过完"处理（只影响最后一点的高亮）
        # ISO 形如 2026-10-13T14:30:00.000Z：[17:19] 是**秒**位，整分钟才记一个刻度
        if start_at[17:19] == "00":
            minute_marks.append(start_at)
        points.append(
            {
                "ts": start_at,
                "docs": _int_of(bucket.get("doc_count")),
                "bytes_total": total,
                # 发送/接收分开给：仪表盘右上角要「实时发送 / 实时接收」分别显示（参考图口径）
                "bytes_out": bytes_out,
                "bytes_in": bytes_in,
                "bytes_per_sec": round(total / elapsed, 1),
                "partial": partial,
            }
        )
    # 仪表盘要求「X 轴正好 N 个刻度、每分钟一个」：窗口两端会各多出一个，只留最后 N 个
    minute_marks = minute_marks[-minutes:]
    total_bytes = sum(int(p["bytes_total"]) for p in points)
    return {
        "points": points,
        # 仪表盘上的 10 个时间段刻度（整分钟）；曲线本身是每秒一个点
        "minute_marks": minute_marks,
        "per_second": True,
        "minutes": minutes,
        "total_bytes": total_bytes,
        "avg_bytes_per_sec": round(total_bytes / max(1, minutes * 60), 1),
    }


@router.get("/traffic")
def stats_traffic(
    _: Annotated[User, Depends(get_current_user)],
    minutes: int = TRAFFIC_MINUTES_DEFAULT,
):
    """**近 N 分钟流量**（默认 10 分钟、**每秒一个点**）—— 给总览页的"心电图"用。

    曲线按秒打点（10 分钟 = 600 点）；仪表盘只显示 `minute_marks`（每整分钟一个）作为时间段刻度。
    当前这一秒不完整 → 标 `partial`（不做放大折算，避免制造尖刺）。
    口径仍是 **Zeek conn 的应用层字节**（不含链路层开销/重传/未跟踪流），不是网卡收包量。
    """
    from datetime import UTC, datetime as _dt, timedelta as _td

    want = clamp_minutes(minutes)
    end_dt = _dt.now(UTC)
    start_dt = end_dt - _td(minutes=want)
    start_iso = start_dt.isoformat().replace("+00:00", "Z")
    end_iso = end_dt.isoformat().replace("+00:00", "Z")
    out: dict[str, Any] = {
        "minutes": want,
        "since": start_iso,
        "until": end_iso,
        "points": [],
        "minute_marks": [],
        "per_second": True,
        "total_bytes": 0,
        "avg_bytes_per_sec": 0.0,
        "computed_at": end_dt.isoformat(),
        "note": "口径：Zeek conn 的应用层字节（orig+resp），不是网卡收包量",
    }
    try:
        from app.ingestion import es_config
        from app.ingestion.es_client import get_es

        cfg = es_config.current()
        pattern = str(cfg.get("es.events_index") or settings.es_events_index)
        resp = get_es().search(
            index=pattern, body=build_minute_query(want, start=start_iso, end=end_iso)
        )
        out.update(shape_minute_traffic(resp, minutes=want, now=end_dt))
    except Exception as exc:  # noqa: BLE001
        log.warning("近 %s 分钟流量聚合失败: %s", want, exc)
        out["error"] = str(exc)[:200]
    return out
