"""已处理文档登记：检测器标记“这条日志我看到了”，供兜底任务补漏时跳过。

- 键：sha256(原始文档 JSON)，与归一化指纹无关（后者不含时间，粒度更粗）
- 存 Redis Set，带 TTL（需覆盖兜底最大回补时长，避免水位回补时误判）
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.workers.log import get_logger

log = get_logger(__name__)


def doc_hash(doc: dict[str, Any]) -> str:
    """原始文档内容哈希（补漏判定键）。"""
    try:
        blob = json.dumps(doc, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        blob = str(doc)
    return hashlib.sha256(blob.encode("utf-8", errors="replace")).hexdigest()[:32]


class HandledRegistry:
    """Redis Set：记录检测器已处理的文档哈希。"""

    def __init__(self, client: Any, key: str, ttl: int) -> None:
        self.r = client
        self.key = key
        self.ttl = ttl

    def mark_many(self, hashes: list[str]) -> None:
        if not hashes:
            return
        pipe = self.r.pipeline()
        for h in hashes:
            pipe.sadd(self.key, h)
        pipe.expire(self.key, self.ttl)
        pipe.execute()

    def is_handled(self, h: str) -> bool:
        return bool(self.r.sismember(self.key, h))

    def filter_unhandled(self, hashes: list[str]) -> list[bool]:
        """批量判定：返回与输入等长的布尔表（True=未处理过，需要兜底分析）。"""
        if not hashes:
            return []
        pipe = self.r.pipeline()
        for h in hashes:
            pipe.sismember(self.key, h)
        return [not bool(v) for v in pipe.execute()]
