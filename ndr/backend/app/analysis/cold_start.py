"""冷启动窗口：基线/画像从零学习的保护期。

为什么必须有它：ES/PG 重建（或环境首次上线）之后，数值基线与画像都从零开始学，
前 48 小时「第一次见」洪峰会把队列前部占满——**人人都新**等于真异常排不上。
窗口内做的事（都在调用方）：

- novelty / coverage / structure 的强度封顶在高强度档之下（真异常仍排得更前）；
- coverage / retest 低频轮询间隔按倍数放大（`cold_start_scale`）。

起点记在哪：Redis `SETNX` 一个时间戳（**持久**），第一次进分析机制时写。
重建 ES/PG 不影响它（Redis 也在那个卷里？在）——所以重建 Redis 后窗口会重新开始，
正好符合「基线重学」的语义。
"""

from __future__ import annotations

import time
from typing import Any

from app.analysis import params

#: 冷启动起点标记（持久键，不设 TTL）
COLD_START_KEY = "shentong:analysis:cold_start_ts"

#: 冷启动期间封顶只作用于这三类：它们正是"人人都新"的来源；
#: hit / shift 是真异常信号，不封顶，让它们保持更高优先级。
CAPPED_KINDS: frozenset[str] = frozenset({"novelty", "coverage", "structure"})


def started(client: Any) -> float | None:
    """读（或首次写入）冷启动起点。Redis 不可用返回 None（视为未启用，不挡检测）。"""
    if client is None:
        return None
    try:
        raw = client.get(COLD_START_KEY)
        if raw is None:
            client.setnx(COLD_START_KEY, time.time())
            raw = client.get(COLD_START_KEY)
        return float(raw)
    except Exception:  # noqa: BLE001 — Redis 抖动不能影响检测
        return None


def active(client: Any) -> bool:
    """是否仍在保护期。hours=0 永远 False。"""
    hours = params.cold_start_hours()
    if hours <= 0:
        return False
    start = started(client)
    if start is None:
        return False
    return (time.time() - start) < hours * 3600


def interval_scale(client: Any) -> float:
    """coverage/retest 低频轮询的间隔倍数（活动期放大）。"""
    return params.cold_start_scale() if active(client) else 1.0


def damped(strength: float, client: Any) -> float:
    """把冷启动类线索的强度封顶（低于高强度档；非活动期原样返回）。"""
    if not active(client):
        return strength
    cap = params.cold_start_strength_cap()
    return max(0.0, min(strength, cap))
