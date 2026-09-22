"""模型解析：把角色解析成实际模型名。

角色：edge / flash / deep / embo_db / embo_query

默认值来自环境变量；后台「系统配置」里的 `model.<role>` 可运行时覆盖。
进程内 30 秒 TTL 缓存，避免每次调用查库；配置更新时调用 invalidate_model_cache()。
"""

from __future__ import annotations

import time

from sqlalchemy import select

from app.config import settings
from app.db.base import SessionLocal
from app.db.models import SystemConfig
from app.workers.log import get_logger

log = get_logger(__name__)

ROLES = ("edge", "flash", "deep", "embo_db", "embo_query")

_CACHE_TTL_SECONDS = 30.0
_cache: dict[str, str] | None = None
_cache_at: float = 0.0


def _defaults() -> dict[str, str]:
    return {
        "edge": settings.edge_model_name,
        "flash": settings.flash_model_name,
        "deep": settings.deep_model_name,
        "embo_db": settings.embo_db_model_name,
        "embo_query": settings.embo_query_model_name,
    }


def _load() -> dict[str, str]:
    """读取系统配置覆盖值，与默认值合并。"""
    values = _defaults()
    try:
        with SessionLocal() as db:
            rows = db.scalars(
                select(SystemConfig).where(
                    SystemConfig.key.in_([f"model.{r}" for r in ROLES])
                )
            ).all()
            for row in rows:
                role = row.key.removeprefix("model.")
                value = (row.value or {}).get("value")
                if value:
                    values[role] = str(value)
    except Exception as exc:  # noqa: BLE001
        log.warning("读取模型配置失败，使用环境变量默认值: %s", exc)
    return values


def _snapshot() -> dict[str, str]:
    global _cache, _cache_at
    now = time.monotonic()
    if _cache is None or (now - _cache_at) > _CACHE_TTL_SECONDS:
        _cache = _load()
        _cache_at = now
    return _cache


def resolve_model(role: str) -> str:
    """按角色取模型名；未知角色回退环境变量默认。"""
    snapshot = _snapshot()
    if role in snapshot:
        return snapshot[role]
    return _defaults().get(role, role)


def invalidate_model_cache() -> None:
    """配置更新后立即失效缓存。"""
    global _cache, _cache_at
    _cache = None
    _cache_at = 0.0


def current_models() -> dict[str, str]:
    """当前生效的模型名（用于展示/排障）。"""
    return dict(_snapshot())
