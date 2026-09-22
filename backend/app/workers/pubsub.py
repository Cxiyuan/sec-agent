"""Redis 发布：分析结果推送给 WebSocket 广播。"""

from __future__ import annotations

import json
from typing import Any

import redis

from app.config import settings
from app.workers.log import get_logger

log = get_logger(__name__)


def publish(channel: str, message: dict[str, Any]) -> None:
    try:
        r = redis.Redis.from_url(settings.redis_url)
        r.publish(channel, json.dumps(message, ensure_ascii=False, default=str))
    except Exception as exc:  # noqa: BLE001
        # Redis 不可用时静默降级，不影响分析主流程
        log.debug("Redis 发布失败: %s", exc)
