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
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends

from app.api.deps import get_current_user
from app.config import settings
from app.db.models import User
from app.ingestion.log_types import stats_protocol_log_types
from app.workers.log import get_logger

#: 等价于 3.11 的 `datetime.UTC`（本仓库 requires-python >=3.11）；用别名写法
#: 免得按旧语法解析的静态检查工具报「unknown import symbol」。
UTC = timezone.utc

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
            # 掉包（Zeek stats.log）：按**小时桶**汇总，供「24 小时掉包率」用。
            # 丢包是偶发的（实测 24h 里只有 7 次爆量），30 分钟窗口经常撞不到 0 —— 所以长期口径也要给。
            "drops": {
                "filter": {"term": {"log_type.keyword": "stats"}},
                "aggs": {
                    "per_hour": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": _INTERVAL,
                            "min_doc_count": 0,
                            "extended_bounds": {"min": start, "max": end},
                        },
                        "aggs": {
                            "pkts_dropped": {"sum": {"field": "pkts_dropped"}},
                            "pkts_proc": {"sum": {"field": "pkts_proc"}},
                        },
                    }
                },
            },
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
    # 掉包（Zeek stats.log 的每 5 分钟增量 → 可以求和）：
    # 丢包偶发，30 分钟窗口经常是 0，所以这里一并给「近 N 小时」的长期掉包率
    drop_buckets = (
        ((resp.get("aggregations") or {}).get("drops") or {}).get("per_hour") or {}
    ).get("buckets") or []
    dropped = sum(
        _int_of((b.get("pkts_dropped") or {}).get("value"))
        for b in drop_buckets
        if isinstance(b, dict)
    )
    proc = sum(
        _int_of((b.get("pkts_proc") or {}).get("value"))
        for b in drop_buckets
        if isinstance(b, dict)
    )
    return {
        "points": points,
        "total_docs": total_docs,
        "total_bytes": total_bytes,
        "avg_bytes_per_sec": round(total_bytes / max(1, hours * 3600), 1),
        # 近 N 小时丢包与掉包率（分母 = 丢包 + 处理）
        "pkts_dropped_total": dropped,
        "pkts_proc_total": proc,
        "day_drop_rate": round(dropped / (dropped + proc) * 100, 4) if (dropped + proc) else 0.0,
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


#: 「近期流量」窗口：默认近 30 分钟（用户口径「近期 = 近半小时」）。
#: 为什么不用 24h/1h：1 小时的桶看不出"现在在不在传"，而且**未过完的那个小时**会让图上右端
#: 假性塌陷（实测被用户当成"流量掉了"）。
TRAFFIC_MINUTES_DEFAULT = 30
TRAFFIC_MINUTES_MAX = 60
#: 打点粒度：每 20 秒一个点（30 分钟 = 90 点）。用户 2026-10 口径。
TRAFFIC_INTERVAL_SECONDS = 20
#: 分段：每 5 分钟一个"段"（仪表盘按 5 分钟分区，X 轴不画刻度线）。
TRAFFIC_SEGMENT_MINUTES = 5
#: 结果缓存（秒）：仪表盘 5 秒轮询一次，不缓存就会每 5 秒穿透一次 ES。
TRAFFIC_CACHE_SECONDS = 30

#: 进程内缓存：{窗口分钟数: (写入时刻, 结果)}
_traffic_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def clamp_minutes(value: Any) -> int:
    try:
        minutes = int(value)
    except (TypeError, ValueError):
        return TRAFFIC_MINUTES_DEFAULT
    return max(1, min(minutes, TRAFFIC_MINUTES_MAX))


def build_minute_query(minutes: int, *, start: str, end: str) -> dict[str, Any]:
    """按 **20 秒** 出流量桶（只统计 conn —— HTTP 的 bytes 会重复计入）。

    为什么是 20 秒（2026-10 用户口径）：仪表盘每条曲线 20 秒打一个点，近半小时 = 90 个点；
    点太密（1 秒）既看不清趋势、也让每次轮询都拖大响应；太疏（1 分钟）又看不出"现在在不在传"。
    """
    return {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": start, "lt": end}}},
        "aggs": {
            # 掉包（Zeek stats.log，每 5 分钟上报一条）：与流量桶用**同一套时间桶参数**，
            # 所以两串 buckets 的下标一一对应，shape 里按同一下标取值。
            # 注意：必须放在**分钟查询**里（曾经锚点先命中上面的 24 小时查询，加错了函数 → 全 0）。
            "drops": {
                "filter": {"term": {"log_type.keyword": "stats"}},
                "aggs": {
                    "per_interval": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": f"{TRAFFIC_INTERVAL_SECONDS}s",
                            "min_doc_count": 0,
                            "extended_bounds": {"min": start, "max": end},
                        },
                        "aggs": {
                            "pkts_dropped": {"sum": {"field": "pkts_dropped"}},
                            # 同区间处理包数：用来算掉包率（dropped / (proc + dropped)）
                            "pkts_proc": {"sum": {"field": "pkts_proc"}},
                        },
                    }
                },
            },
            "traffic": {
                "filter": {"term": {"log_type.keyword": "conn"}},
                "aggs": {
                    "per_interval": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": f"{TRAFFIC_INTERVAL_SECONDS}s",
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
        },
    }


def shape_minute_traffic(resp: Any, *, minutes: int, now: datetime) -> dict[str, Any]:
    """ES 响应 → 曲线点 + 5 分钟分段 + 当前/峰值。

    三个要点（对齐仪表盘观感，参考主机资源占用那种 Sparkline）：

    - **每 20 秒一个点**，最右那格是"进行中的 20 秒"→ 标 `partial`，速率按时长折算
      （不折算的话右端看着像流量骤降；但对不足 1 秒的窗口不放大，免得零流被放大成尖刺）；
    - **不给 X 轴刻度**：服务端只给 `segment_marks`（每 5 分钟的整点）让前端画清淡的分段，
      曲线本身连续滚动 —— 最老一格从左出、新一格从右进；
    - **`current` / `peak`** 服务端算好，前端直接显示成大数字（Sparkline 的常见排布）。
    """
    buckets = (
        ((resp.get("aggregations") or {}).get("traffic") or {}).get("per_interval") or {}
    ).get("buckets") or []

    # 掉包桶：与流量桶同粒度同边界 → 下标一一对应
    drop_buckets = (
        ((resp.get("aggregations") or {}).get("drops") or {}).get("per_interval") or {}
    ).get("buckets") or []
    points: list[dict[str, Any]] = []
    segment_marks: list[str] = []
    interval = float(TRAFFIC_INTERVAL_SECONDS)
    # Zeek 最近一次上报的丢包值（stats.log 每 5 分钟一条）
    last_report: int | None = None
    # 窗口累计（`pkts_dropped` 是每 5 分钟的**增量**，所以可以直接求和；
    # 实测一次爆 48,123 包后下一个区间回 0，确证不是累计计数器）
    total_dropped = 0
    total_proc = 0
    for idx, bucket in enumerate(buckets):
        if not isinstance(bucket, dict):
            continue
        bytes_out = _int_of(bucket.get("bytes_out", {}).get("value"))
        bytes_in = _int_of(bucket.get("bytes_in", {}).get("value"))
        total = bytes_out + bytes_in
        start_at = str(bucket.get("key_as_string") or "")
        partial = False
        elapsed = interval
        try:
            began = datetime.fromisoformat(start_at)  # py3.11+ 认 Z
            age = (now - began).total_seconds()
            if age < interval - 0.5:
                partial = True
                elapsed = max(1.0, age)  # 不足 1 秒按 1 秒算，避免把零星流量放大成尖刺
        except (TypeError, ValueError):
            partial = False
        # 5 分钟分段：整分钟且分钟数是 5 的倍数。ISO 形如 2026-10-13T14:30:00.000Z
        if len(start_at) >= 19 and start_at[17:19] == "00":
            minute_number = int(start_at[14:16]) if start_at[14:16].isdigit() else -1
            if minute_number >= 0 and minute_number % TRAFFIC_SEGMENT_MINUTES == 0:
                segment_marks.append(start_at)
        # 掉包：取同下标的桶（两串 histogram 同粒度同边界 → 下标一一对应）
        drop_bucket = drop_buckets[idx] if idx < len(drop_buckets) else {}
        pkts_dropped = _int_of((drop_bucket.get("pkts_dropped") or {}).get("value"))
        pkts_proc = _int_of((drop_bucket.get("pkts_proc") or {}).get("value"))
        if drop_bucket.get("doc_count"):
            last_report = pkts_dropped
        total_dropped += pkts_dropped
        total_proc += pkts_proc
        points.append(
            {
                "ts": start_at,
                "docs": _int_of(bucket.get("doc_count")),
                "bytes_total": total,
                "bytes_out": bytes_out,
                "bytes_in": bytes_in,
                # **每秒**口径（桶内总量 ÷ 桶实际秒数）：图上画的是这个。
                # 曾经直接画桶内总量、却按"/秒"标注 —— 20 秒的量被读成 1 秒，虚高 20 倍。
                "bytes_per_sec": round(total / elapsed, 1),
                "bytes_out_per_sec": round(bytes_out / elapsed, 1),
                "bytes_in_per_sec": round(bytes_in / elapsed, 1),
                "pkts_dropped": pkts_dropped,
                "pkts_proc": pkts_proc,
                "partial": partial,
            }
        )
    total_bytes = sum(int(point["bytes_total"]) for point in points)
    rates = [float(point["bytes_per_sec"]) for point in points]
    return {
        "points": points,
        # 每 5 分钟一个分段标记（前端画清淡分隔；X 轴不显示刻度文字）
        "segment_marks": segment_marks[-24:],
        "interval_seconds": TRAFFIC_INTERVAL_SECONDS,
        "segment_minutes": TRAFFIC_SEGMENT_MINUTES,
        "minutes": minutes,
        "total_bytes": total_bytes,
        "avg_bytes_per_sec": round(total_bytes / max(1, minutes * 60), 1),
        # 仪表盘右上角的两个大数字：当前（最近一格）与峰值
        "current_bytes_per_sec": rates[-1] if rates else 0.0,
        "peak_bytes_per_sec": max(rates) if rates else 0.0,
        "avg_recent_bytes_per_sec": round(sum(rates) / len(rates), 1) if rates else 0.0,
        # Zeek **最近一次上报**的丢包值（stats.log 每 5 分钟一条；不是窗口累加，避免把累积型计数器加成假总数）
        "pkts_dropped_latest": last_report or 0,
        # 窗口丢包总数与掉包率（分母 = 丢包 + 处理，都是同区间上报的增量）
        "pkts_dropped_total": total_dropped,
        "pkts_proc_total": total_proc,
        "drop_rate": round(total_dropped / (total_dropped + total_proc) * 100, 4)
        if (total_dropped + total_proc)
        else 0.0,
    }


@router.get("/traffic")
def stats_traffic(
    _: Annotated[User, Depends(get_current_user)],
    minutes: int = TRAFFIC_MINUTES_DEFAULT,
):
    """**近 N 分钟流量**（默认 30 分钟、**每 20 秒一个点**）——给总览页「近期流量」仪表盘用。

    曲线 20 秒打点（30 分钟 = 90 点）、每 5 分钟一个分段、**不给 X 轴刻度**（Sparkline 观感）。
    当前这一格不完整 → 标 `partial`（按时长折算速率，不做放大）。
    结果进程内缓存 `TRAFFIC_CACHE_SECONDS`（默认 30 秒）：仪表盘 5 秒轮询，不缓存会穿透 ES。
    口径：**Zeek conn 的应用层字节**（orig+resp），不是网卡收包量。
    """
    import time as _time

    want = clamp_minutes(minutes)
    key = str(want)
    now_ts = _time.monotonic()
    hit = _traffic_cache.get(key)
    if hit is not None and now_ts - hit[0] < TRAFFIC_CACHE_SECONDS:
        payload = dict(hit[1])
        payload["cached"] = True
        return payload

    end_dt = datetime.now(UTC)
    start_dt = end_dt - timedelta(minutes=want)
    start_iso = start_dt.isoformat().replace("+00:00", "Z")
    end_iso = end_dt.isoformat().replace("+00:00", "Z")
    out: dict[str, Any] = {
        "minutes": want,
        "since": start_iso,
        "until": end_iso,
        "points": [],
        "segment_marks": [],
        "interval_seconds": TRAFFIC_INTERVAL_SECONDS,
        "segment_minutes": TRAFFIC_SEGMENT_MINUTES,
        "total_bytes": 0,
        "avg_bytes_per_sec": 0.0,
        "current_bytes_per_sec": 0.0,
        "peak_bytes_per_sec": 0.0,
        "avg_recent_bytes_per_sec": 0.0,
        "cached": False,
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
    out["cached"] = False
    _traffic_cache[key] = (now_ts, dict(out))
    return out
