"""检测器运行状态：队列深度、投递速率、丢弃计数。

目的：让「事件被丢弃 / 未进入分析」可见（此前只写一行统计日志，无法查询、无告警）。
数据全部从 Redis 读，不依赖检测器进程存活。
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from app.api.deps import get_current_user
from app.config import settings
from app.db.models import User
from app.detector.analyzed import AnalyzedRegistry
from app.detector.runner import rate_bucket
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/detector", tags=["detector"])


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
        if settings.dedup_enabled:
            out["dedup"].update(AnalyzedRegistry().counts())
    except Exception as exc:  # noqa: BLE001
        log.warning("读取检测器状态失败: %s", exc)
        out["error"] = str(exc)[:200]
    return out
