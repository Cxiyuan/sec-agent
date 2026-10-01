"""MCP 最近调用记录：只给界面看，放在 Redis 的有界列表里。

为什么不落库：这是**运维可见性**数据，不是业务数据。写库要为它建表、做清理、还要担心
调查高峰期的写入压力；放 Redis 一个 `LPUSH` + `LTRIM` 就完了，上限固定、天然过期，
重启也不影响正确性（丢的是历史调用列表，不是结论）。
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import redis

from app.config import settings

log = logging.getLogger(__name__)


def _client() -> Any:
    return redis.Redis.from_url(settings.redis_url, decode_responses=True)


def _snippet(params: Any) -> str:
    """参数摘录：只留开头，够定位问题就行（也可能含敏感值，不进日志之外的地方）。"""
    if params in (None, {}, ""):
        return ""
    try:
        text = json.dumps(params, ensure_ascii=False)
    except (TypeError, ValueError):
        text = str(params)
    limit = max(0, settings.mcp_call_detail_chars)
    return text[:limit]


def record(
    *,
    tool: str,
    token_name: str,
    ok: bool,
    duration_ms: int,
    params: Any = None,
    error: str = "",
) -> None:
    """记一条调用。

    **绝不让记录失败影响工具调用本身**：这是个旁路，Redis 抖一下不该让智能体的调查挂掉。
    """
    if settings.mcp_call_keep <= 0:
        return
    item = {
        "ts": time.time(),
        "tool": tool,
        "token": token_name,
        "ok": bool(ok),
        "duration_ms": int(duration_ms),
        "detail": _snippet(params),
        "error": (error or "")[:300],
    }
    try:
        client = _client()
        client.lpush(settings.mcp_call_key, json.dumps(item, ensure_ascii=False))
        client.ltrim(settings.mcp_call_key, 0, settings.mcp_call_keep - 1)
    except Exception as exc:  # noqa: BLE001
        log.debug("MCP 调用记录写入失败（不影响本次调用）：%s", exc)


def recent(limit: int = 50) -> list[dict[str, Any]]:
    """最近调用，新的在前。Redis 不可用时返回空表而不是报错。"""
    limit = max(1, min(int(limit), settings.mcp_call_keep or 1))
    try:
        items = _client().lrange(settings.mcp_call_key, 0, limit - 1)
    except Exception as exc:  # noqa: BLE001
        log.debug("MCP 调用记录读取失败：%s", exc)
        return []
    out: list[dict[str, Any]] = []
    for raw in items:
        try:
            item = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if isinstance(item, dict):
            ts = item.get("ts")
            item["time"] = (
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ts))) if ts else ""
            )
            out.append(item)
    return out


def clear() -> None:
    try:
        _client().delete(settings.mcp_call_key)
    except Exception as exc:  # noqa: BLE001
        log.debug("MCP 调用记录清理失败：%s", exc)
