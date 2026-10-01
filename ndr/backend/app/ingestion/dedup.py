"""窗口指纹去重：同一时间窗口内重复日志合并。"""
from __future__ import annotations

from datetime import timedelta

from app.schemas import UnifiedLog


def dedup_logs(logs: list[UnifiedLog], window_minutes: int = 5) -> list[UnifiedLog]:
    """按 (窗口, 指纹) 去重。

    时间被压到 window_minutes 粒度分桶，同桶内同指纹只保留首条。
    """
    seen: set[tuple[str, str]] = set()
    out: list[UnifiedLog] = []
    for log in logs:
        bucket = log.ts.replace(second=0, microsecond=0)
        bucket -= timedelta(minutes=bucket.minute % window_minutes)
        key = (bucket.isoformat(), log.fingerprint())
        if key in seen:
            continue
        seen.add(key)
        out.append(log)
    return out
