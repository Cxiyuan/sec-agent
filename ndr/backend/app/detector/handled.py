"""已处理文档登记：检测器标记“这条日志我看到了”，供兜底补漏时跳过。

- 键：sha256(原始文档 JSON)，与归一化指纹无关（后者不含时间，粒度更粗）

**为什么按时间分桶 + 设置成员上限（这是一次真实事故的修复）**
原实现是「单个 Set + 每次写入刷新 TTL」，看起来有 TTL 就安全，实际上只要写入不断，
TTL 永远被刷新 → 集合无上限增长。线上实测该键涨到 **1677 万成员 / 1.4GB**，
把 Redis 撑到 maxmemory；`noeviction` 之下 Redis 拒绝一切写命令 → Celery 结果写不进去
→ 任务全部抛 OutOfMemoryError 崩溃 → 事件组永远停在 analyzing、4 小时 39 分没出报告，
而且**表面上没有任何告警**（只有 Celery 的 CRITICAL 日志）。
所以现在的设计是「三重有界」：
1. 按 `bucket_seconds` 分桶，桶自身的 TTL 到期就整桶消失（不会互相续命）；
2. 单桶成员硬上限 `max_members`，超限丢弃登记并计数/告警（**绝不静默**）；
3. 判定只看覆盖 TTL 的那几个桶，语义不变（旧桶过期后会重复分析；**投递前去重**已随第 5 期
   退役，现在兜底的是「摘要超龄丢弃」与智能体侧按事件组指纹吸收重复，代价可接受）。
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from app.config import settings
from app.workers.log import get_logger

log = get_logger(__name__)


def _as_int(value: Any, default: int) -> int:
    """安全转 int（值可能来自环境变量/后台配置，可能是脏字符串）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(str(value)))
        except (TypeError, ValueError):
            return default


def doc_hash(doc: dict[str, Any]) -> str:
    """原始文档内容哈希（补漏判定键）。"""
    try:
        blob = json.dumps(doc, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        blob = str(doc)
    return hashlib.sha256(blob.encode("utf-8", errors="replace")).hexdigest()[:32]


class HandledRegistry:
    """Redis：记录检测器已处理的文档哈希（分桶 + 有界）。

    ``ttl`` 决定“往前看多久”，``bucket_seconds`` 决定分桶粒度，``max_members`` 是单桶硬上限。
    旧签名（client, key, ttl）完全兼容。
    """

    def __init__(
        self,
        client: Any,
        key: str,
        ttl: int,
        bucket_seconds: int | None = None,
        max_members: int | None = None,
    ) -> None:
        self.r = client
        self.key = key
        self.ttl = max(60, _as_int(ttl, 7200))
        self.bucket = max(
            60,
            _as_int(
                bucket_seconds
                if bucket_seconds is not None
                else settings.detector_handled_bucket_seconds,
                600,
            ),
        )
        self.max_members = max(
            1000,
            _as_int(
                max_members if max_members is not None else settings.detector_handled_max_members,
                50000,
            ),
        )
        self.skipped = 0  # 超限被丢弃的登记数（可查，不静默）

    def _keys(self, now: float | None = None) -> list[str]:
        """需要查看的桶：当前桶 + 覆盖整个 TTL 的历史桶。"""
        ts = time.time() if now is None else now
        current = _as_int(ts, 0) // self.bucket
        span = max(1, self.ttl // self.bucket + 1)
        return [f"{self.key}:{current - i}" for i in range(span)]

    def mark_many(self, hashes: list[str], now: float | None = None) -> None:
        if not hashes:
            return
        ts = time.time() if now is None else now
        cur_key = self._keys(ts)[0]
        try:
            current_size = _as_int(self.r.scard(cur_key), 0)
            if len(hashes) + current_size > self.max_members:
                room = max(0, self.max_members - current_size)
                dropped = len(hashes) - room
                hashes = hashes[:room]
                if dropped > 0:
                    self.skipped += dropped
                    log.warning(
                        "已处理登记单桶达上限 %d，丢弃 %d 条登记（这些文档兜底时会重复分析）——"
                        "若频繁出现请下调流量或提高 detector_handled_max_members 上限",
                        self.max_members,
                        dropped,
                    )
            if not hashes:
                return
            pipe = self.r.pipeline()
            for h in hashes:
                pipe.sadd(cur_key, h)
            # 桶 TTL = 保留窗 + 一个桶（保证「往前看」的桶在 TTL 内都还在）
            pipe.expire(cur_key, self.ttl + self.bucket)
            pipe.execute()
        except Exception as exc:  # noqa: BLE001
            log.debug("写入已处理登记失败（不影响主流程）: %s", exc)

    def is_handled(self, h: str, now: float | None = None) -> bool:
        keys = self._keys(now)
        try:
            pipe = self.r.pipeline()
            for k in keys:
                pipe.sismember(k, h)
            return any(bool(v) for v in pipe.execute())
        except Exception as exc:  # noqa: BLE001
            log.debug("查询已处理登记失败（按未处理转发）: %s", exc)
            return False
