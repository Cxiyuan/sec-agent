"""频率规则的实时滑动窗口（Redis ZSET）。

原实现依赖「整个分析窗口的日志列表」做计数；实时链路是逐条到达的，
故改为按 (规则, 分组键) 维护滑动窗口：
- 命中条数：ZSET member=事件唯一标识，score=时间戳
- distinct 去重数：ZSET member=distinct 字段值，score=时间戳
达阈值且不在冷却期 → 触发一次（冷却防同一分组反复告警）。
"""

from __future__ import annotations

import time
from typing import Any

from app.rules.engine import count_key
from app.schemas import UnifiedLog
from app.workers.log import get_logger

log = get_logger(__name__)

_PREFIX = "shentong:freq"


class FreqWindow:
    """频率规则滑动窗口。"""

    def __init__(self, client: Any, window: int, cooldown: int) -> None:
        self.r = client
        self.window = max(1, _to_int(window, 300))
        self.cooldown = max(0, _to_int(cooldown, 0))

    def observe(self, rule: dict[str, Any], entry: UnifiedLog, now: float | None = None) -> bool:
        """记录一次命中；返回是否「触发」（达阈值且不在冷却期）。"""
        cond = rule.get("conditions") or {}
        name = str(rule.get("name") or "")
        if not name:
            return False

        keys = cond.get("key")
        if not isinstance(keys, list) or not keys:
            keys = ["src_ip"]
        group = count_key(entry, [str(k) for k in keys]) or "-"

        min_count = _to_int(cond.get("min_count"), 1)
        distinct_field = str(cond.get("distinct") or "")
        min_distinct = _to_int(cond.get("min_distinct"), 0)

        ts = time.time() if now is None else now
        # 每规则窗口（长窗规则如 6h 慢速横向用）：缺省沿用全局窗口
        window = max(1, _to_int(cond.get("window"), self.window))
        cutoff = ts - window
        # 冷却：同一分组在冷却期内只触发一次。
        # 缺省取 max(全局冷却, 本规则窗口) —— 长窗规则（例：6h 慢速横向）若沿用 300s 全局
        # 冷却，会在窗口内每 5 分钟重复出发一次（单主机 6h 最多 72 条摘要，实机已见）。
        # 规则可用 conditions.cooldown 显式覆盖（0 = 不冷却）。
        raw_cooldown = cond.get("cooldown")
        if raw_cooldown is None:
            cooldown = max(self.cooldown, window)
        else:
            cooldown = max(0, _to_int(raw_cooldown, self.cooldown))
        base = f"{_PREFIX}:{name}:{group}"
        cnt_key = f"{base}:cnt"
        ttl = window * 2 + 60

        pipe = self.r.pipeline()
        pipe.zremrangebyscore(cnt_key, "-inf", cutoff)
        pipe.zadd(cnt_key, {f"{entry.fingerprint()}:{ts:.3f}": ts})
        pipe.expire(cnt_key, ttl)
        dst_key = ""
        if distinct_field:
            dst_key = f"{base}:dst"
            pipe.zremrangebyscore(dst_key, "-inf", cutoff)
            pipe.expire(dst_key, ttl)
        pipe.execute()

        if distinct_field:
            value = str(getattr(entry, distinct_field, "") or "")
            if value:
                self.r.zadd(dst_key, {value: ts})

        count = _to_int(self.r.zcard(cnt_key), 0)
        if count < min_count:
            return False
        if distinct_field and min_distinct > 0 and _to_int(self.r.zcard(dst_key), 0) < min_distinct:
            return False

        # 冷却：同一分组在冷却期内只触发一次
        if cooldown <= 0:
            return True
        return bool(self.r.set(f"{base}:cool", "1", nx=True, ex=cooldown))


def _to_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
