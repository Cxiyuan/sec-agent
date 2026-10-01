"""Redis 体检：把“内存吃满 → noeviction 拒写 → 全链路静默卡死”变成可见信号。

真实事故：`shentong:handled:docs` 集合涨到 1677 万成员 / 1.4GB，把 Redis 顶到 maxmemory，
`noeviction` 之下写命令全部被拒 → Celery 结果写不进去、任务崩溃、事件组永远停在 analyzing，
持续 4 小时 39 分没有任何告警。这个模块给检测器循环和后台接口提供同一份判据。
"""

from __future__ import annotations

from typing import Any

from app.workers.log import get_logger

log = get_logger(__name__)


def _num(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def redis_memory(client: Any) -> dict[str, Any]:
    """内存占用（used / maxmemory / 百分比）。maxmemory=0 表示不限，perc 记 0。"""
    try:
        info = client.info("memory")
        used = _num(info.get("used_memory"))
        limit = _num(info.get("maxmemory"))
        perc = (used / limit * 100.0) if limit > 0 else 0.0
        return {
            "used": int(used),
            "max": int(limit),
            "perc": round(perc, 1),
            "used_human": info.get("used_memory_human"),
            "policy": info.get("maxmemory_policy"),
        }
    except Exception as exc:  # noqa: BLE001
        return {"used": 0, "max": 0, "perc": 0.0, "error": str(exc)}


def describe(mem: dict[str, Any]) -> str:
    """一行可读描述（日志用）。"""
    from app.config import settings

    if not mem.get("max"):
        return "Redis 内存：不限（未设 maxmemory）"
    flag = " ⚠ 已达告警线" if mem.get("perc", 0) >= settings.redis_memory_warn_perc else ""
    return (
        f"Redis 内存 {mem.get('used_human')}/{mem.get('max', 0) / 1048576:.0f}M"
        f"（{mem.get('perc')}%，策略 {mem.get('policy')}）{flag}"
    )
