"""通用运行时配置：默认取环境变量，后台「系统配置」可覆盖（30 秒 TTL 缓存）。

用于让**后台可调**的参数（RAG 检索参数等）无需重启即生效。
（模型名见 models/registry.py，各自有专用解析器；事件取数走 NDR 的 MCP，见 investigation/mcp_client.py。）
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import select

from app.db.base import SessionLocal
from app.db.models import SystemConfig
from app.workers.log import get_logger

log = get_logger(__name__)

_CACHE_TTL_SECONDS = 30.0
_cache: dict[str, Any] | None = None
_cache_at: float = 0.0


def _load() -> dict[str, Any]:
    values: dict[str, Any] = {}
    try:
        with SessionLocal() as db:
            for row in db.scalars(select(SystemConfig)).all():
                value = (row.value or {}).get("value")
                if value not in (None, ""):
                    values[row.key] = value
    except Exception as exc:  # noqa: BLE001
        log.warning("读取运行时配置失败: %s", exc)
    return values


def _snapshot() -> dict[str, Any]:
    global _cache, _cache_at
    now = time.monotonic()
    if _cache is None or (now - _cache_at) > _CACHE_TTL_SECONDS:
        _cache = _load()
        _cache_at = now
    return _cache


def _coerce(value: Any, default: Any) -> Any:
    """按默认值类型转换（后台存的是 JSON，可能是字符串）。"""
    if value is None:
        return default
    if isinstance(default, bool):
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes", "on", "是")
        return bool(value)
    if isinstance(default, int):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default
    if isinstance(default, float):
        try:
            return float(value)
        except (TypeError, ValueError):
            return default
    return value


def get(key: str, default: Any) -> Any:
    """取运行时配置：DB 有值则按默认值类型转换后用，否则用 default。"""
    snapshot = _snapshot()
    if key not in snapshot:
        return default
    return _coerce(snapshot[key], default)


def invalidate() -> None:
    """配置更新后立即失效缓存。"""
    global _cache, _cache_at
    _cache = None
    _cache_at = 0.0
