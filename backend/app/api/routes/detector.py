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
    except Exception as exc:  # noqa: BLE001
        log.warning("读取检测器状态失败: %s", exc)
        out["error"] = str(exc)[:200]
    return out
