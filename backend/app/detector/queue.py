"""Redis 可靠队列：LPUSH 入队 + BRPOPLPUSH 取出 + LREM 确认。

List 实现（Logstash 的 redis output 确定支持 list，不依赖 Streams）。
取出即进 processing 列表，处理成功才移除；启动时回灌残留，保证不丢。
"""

from __future__ import annotations

from typing import Any

import redis

from app.workers.log import get_logger

log = get_logger(__name__)


class ReliableQueue:
    """List 可靠队列（raw / processing 两个键）。"""

    def __init__(self, client: redis.Redis, raw_key: str, processing_key: str) -> None:
        self.r: Any = client
        self.raw = raw_key
        self.processing = processing_key

    def push(self, payload: str) -> None:
        self.r.lpush(self.raw, payload)

    def recover(self) -> int:
        """把 processing 里的残留回灌 raw（上次未确认的消息）。"""
        moved = 0
        while True:
            item = self.r.rpoplpush(self.processing, self.raw)
            if item is None:
                break
            moved += 1
        if moved:
            log.warning("回灌上次未确认的队列消息 %d 条", moved)
        return moved

    def consume(self, timeout: int = 5) -> str | None:
        """阻塞取出（取出即进 processing）。"""
        item = self.r.brpoplpush(self.raw, self.processing, timeout)
        return item if isinstance(item, str) else None

    def try_consume(self) -> str | None:
        """非阻塞取出（用于攒批时批量拉取）。"""
        item = self.r.rpoplpush(self.raw, self.processing)
        return item if isinstance(item, str) else None

    def ack(self, payload: str) -> None:
        self.r.lrem(self.processing, 1, payload)

    def depth(self) -> tuple[int, int]:
        """返回 (raw 待处理数, processing 在处理数)。"""
        return int(self.r.llen(self.raw)), int(self.r.llen(self.processing))
