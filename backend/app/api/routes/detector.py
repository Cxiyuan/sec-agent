"""检测器运行状态：队列深度、投递速率、丢弃计数。

目的：让「事件被丢弃 / 未进入分析」可见（此前只写一行统计日志，无法查询、无告警）。
数据全部从 Redis 读，不依赖检测器进程存活。
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from app.agents import triage_policy
from app.api.deps import get_current_user
from app.config import settings
from app.db.models import User
from app.detector import health
from app.detector.analyzed import AnalyzedRegistry
from app.detector.runner import rate_bucket
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/detector", tags=["detector"])


@router.get("/coverage")
def detector_coverage(
    _: Annotated[User, Depends(get_current_user)],
    minutes: int = 60,
):
    """漏报兑底率：窗口内 ES 命中文档数 vs 已落库事件数（含丢弃计数）。

    语义：比率 <1 是正常的（策略跳过、聚合归并都会减少落库事件），看的是**趋势突变**
    （比率骤降 = 大批事件没进分析），所以同时返回容量性丢弃计数供对照。
    """
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import func, select

    from app.config import settings
    from app.db.base import SessionLocal
    from app.db.models import Event, EventGroup

    since = datetime.now(UTC) - timedelta(minutes=max(5, min(int(minutes or 60), 1440)))
    out: dict[str, Any] = {"minutes": minutes, "since": since.isoformat()}
    with SessionLocal() as db:
        out["pg_events"] = int(
            db.execute(select(func.count(Event.id)).where(Event.ts >= since)).scalar_one() or 0
        )
        out["groups"] = int(
            db.execute(
                select(func.count(EventGroup.id)).where(EventGroup.created_at >= since)
            ).scalar_one()
            or 0
        )
        out["excluded_groups"] = int(
            db.execute(
                select(func.count(EventGroup.id)).where(
                    EventGroup.created_at >= since, EventGroup.status == "excluded"
                )
            ).scalar_one()
            or 0
        )
    es_docs: int | None = None
    try:
        from app.ingestion import es_config
        from app.ingestion.es_client import get_es

        cfg = es_config.current()
        pattern = ",".join(
            [
                str(cfg.get("es.zeek_index") or settings.es_zeek_index),
                str(cfg.get("es.wazuh_index") or settings.es_wazuh_index),
            ]
        )
        resp = get_es().count(
            index=pattern,
            query={"range": {"@timestamp": {"gte": since.isoformat()}}},
        )
        es_docs = int(resp.get("count") or 0)
    except Exception as exc:  # noqa: BLE001
        out["es_error"] = str(exc)[:200]
    out["es_docs"] = es_docs
    if es_docs:
        ratio = float(out["pg_events"]) / float(es_docs)
        out["coverage_ratio"] = round(ratio, 3)
        out["warn"] = ratio < float(settings.detector_coverage_warn_ratio)
    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        out["dropped"] = client.hgetall(settings.detector_drop_key)
    except Exception as exc:  # noqa: BLE001
        out["dropped_error"] = str(exc)[:200]
    return out


@router.get("/rate")
def detector_rate(
    _: Annotated[User, Depends(get_current_user)],
    minutes: int = 10,
):
    """五段速率：入队 / 扫描 / 命中 / 投递 / 分析（哪一段窄，一眼可见）。

    健康形态：入队 ≈ 扫描 > 命中 > 投递 ≈ 分析。
    入队速率用守恒关系推算：入队 = 扫描 + 队列增长（无需生产者埋点）。
    """
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import func, select

    from app.config import settings
    from app.db.base import SessionLocal
    from app.db.models import EventGroup

    out: dict[str, Any] = {}
    snap: dict[str, Any] = {}
    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        raw = client.hgetall("shentong:detector:rates")
        snap = dict(raw) if isinstance(raw, dict) else {}
        out["queue_raw"] = int(client.llen(settings.detector_raw_queue) or 0)
        out["queue_digest"] = int(client.llen(settings.detector_digest_queue) or 0)
        out["agent_capacity_per_min"] = int(settings.detector_max_digests_per_minute)
    except Exception as exc:  # noqa: BLE001
        out["redis_error"] = str(exc)[:200]

    def _num(key: str) -> float:
        try:
            return float(snap.get(key) or 0)
        except (TypeError, ValueError):
            return 0.0

    window = max(1.0, _num("ts") and (datetime.now(UTC).timestamp() - _num("ts")) or 0.0)
    if window > 0 and snap:
        out["window_seconds"] = round(window, 1)
        out["scanned_per_sec"] = round(_num("scanned") / window, 1)
        out["hits_per_min"] = round(_num("hit") / window * 60.0, 1)
        out["digests_per_min"] = round(_num("digest") / window * 60.0, 1)
        out["delivered_per_min"] = round(_num("delivered") / window * 60.0, 1)
        out["raw_trimmed_total"] = int(_num("raw_trimmed"))
        out["limit_saturated"] = int(_num("limit_saturated"))
        out["requeued_total"] = int(_num("requeued"))
        # 入队速率（守恒）：扫描 + 裁剪 + 队列增长 ≈ 入队
        out["ingest_per_sec_est"] = out["scanned_per_sec"]
    since = datetime.now(UTC) - timedelta(minutes=max(1, min(int(minutes or 10), 1440)))
    with SessionLocal() as db:
        analyzed = int(
            db.execute(
                select(func.count(EventGroup.id)).where(EventGroup.created_at >= since)
            ).scalar_one()
            or 0
        )
    out["analyzed_per_min"] = round(analyzed / max(1, min(int(minutes or 10), 1440)), 2)
    out["note"] = "入队≈扫描>命中>投递≈分析 为健康；最小的一段即瓶颈"
    return out


@router.get("/stats")
def get_stats(_: Annotated[User, Depends(get_current_user)]):
    out: dict[str, Any] = {
        "enabled": settings.detector_enabled,
        "queue_raw": None,
        "queue_digest": None,
        "queue_processing": None,
        "delivered_this_minute": None,
        "rate_limit_per_minute": settings.detector_max_digests_per_minute,
        "queue_max": settings.detector_queue_max,
        "digest_max_age_seconds": settings.detector_digest_max_age_seconds,
        "dropped": {},
        "last_dropped_at": None,
        # 选主状态：谁在消费（另一个实例在待命热备）
        "leader": None,
        # 投递前去重（省重复 LLM 调用）
        "dedup": {
            "enabled": settings.dedup_enabled,
            "inflight_ttl_seconds": settings.dedup_inflight_ttl_seconds,
            "skipped_total": 0,
            "last_skipped_at": None,
            "inflight": 0,
            "done": 0,
        },
        # 投递了但分析失败（原来只有一行日志，看不出来是否在漏分析）
        "task_failed": {"failed_total": 0, "last_failed_at": None},
        # 误报治理：策略跳过的数量与最后时间（内网常规流量等）——降噪必须可见
        "policy": {"internal_routine": 0, "last_at": None},
    }
    try:
        import redis

        client: Any = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        out["queue_raw"] = int(client.llen(settings.detector_raw_queue))
        out["queue_digest"] = int(client.llen(settings.detector_digest_queue))
        out["queue_processing"] = int(client.llen(settings.detector_processing_queue))
        out["delivered_this_minute"] = int(client.get(rate_bucket()) or 0)
        dropped = client.hgetall(settings.detector_drop_key)
        raw_dropped = dropped if isinstance(dropped, dict) else {}
        out["dropped"] = {
            key: int(val)
            for key, val in raw_dropped.items()
            if key != "last_dropped_at" and str(val).isdigit()
        }
        out["last_dropped_at"] = raw_dropped.get("last_dropped_at")
        holder = client.get(settings.detector_leader_key)
        out["leader"] = {
            "holder": str(holder) if holder else None,
            "ttl_seconds": max(0, int(client.ttl(settings.detector_leader_key) or 0)),
        }
        dedup_raw = client.hgetall(settings.detector_dedup_key)
        dedup_stats = dedup_raw if isinstance(dedup_raw, dict) else {}
        out["dedup"].update(
            {
                "skipped_total": int(dedup_stats.get("skipped") or 0),
                "last_skipped_at": dedup_stats.get("last_skipped_at"),
            }
        )
        failed_raw = client.hgetall(settings.detector_task_failed_key)
        failed_stats = failed_raw if isinstance(failed_raw, dict) else {}
        out["task_failed"].update(
            {
                "failed_total": int(failed_stats.get("failed") or 0),
                "last_failed_at": failed_stats.get("last_failed_at"),
            }
        )
        policy_raw = client.hgetall(triage_policy.POLICY_STATS_KEY)
        policy_stats = policy_raw if isinstance(policy_raw, dict) else {}
        out["policy"] = {
            "internal_routine": int(policy_stats.get("internal_routine") or 0),
            "last_at": policy_stats.get("last_at"),
        }
        # Redis 体检：内存吃满会让整条分析链静默卡死（真实事故），必须一眼可见
        mem = health.redis_memory(client)
        out["redis"] = mem
        out["redis_warn"] = (
            bool(mem.get("max")) and mem.get("perc", 0) >= settings.redis_memory_warn_perc
        )
        try:
            out["handled_skipped"] = int(
                client.get(f"{settings.detector_handled_key}:skipped") or 0
            )
        except (TypeError, ValueError):
            out["handled_skipped"] = 0
        if settings.dedup_enabled:
            out["dedup"].update(AnalyzedRegistry().counts())
    except Exception as exc:  # noqa: BLE001
        log.warning("读取检测器状态失败: %s", exc)
        out["error"] = str(exc)[:200]
    return out
