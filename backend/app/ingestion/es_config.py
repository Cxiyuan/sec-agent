"""ES 运行时配置：默认取环境变量，后台「系统配置」可覆盖（30 秒 TTL 缓存）。

配套 `get_es()` 使用，使后台改 ES 地址/认证后无需重启后端。
"""

from __future__ import annotations

import time

from sqlalchemy import select

from app.config import settings
from app.db.base import SessionLocal
from app.db.models import SystemConfig
from app.workers.log import get_logger

log = get_logger(__name__)

_CACHE_TTL_SECONDS = 30.0
_cache: dict[str, str] | None = None
_cache_at: float = 0.0

# 可被后台覆盖的键（与 api/routes/config.py 的 CONFIG_KEYS 对齐）
RUNTIME_KEYS = (
    "es.url",
    "es.username",
    "es.password",
    "es.zeek_index",
    "es.wazuh_index",
    "es.retention_days",
)


def defaults() -> dict[str, str]:
    return {
        "es.url": settings.es_url,
        "es.username": settings.es_user,
        "es.password": settings.es_password,
        "es.zeek_index": settings.es_zeek_index,
        "es.wazuh_index": settings.es_wazuh_index,
        "es.retention_days": str(settings.es_retention_days),
    }


def _load() -> dict[str, str]:
    values = defaults()
    try:
        with SessionLocal() as db:
            rows = db.scalars(
                select(SystemConfig).where(SystemConfig.key.in_(list(RUNTIME_KEYS)))
            ).all()
            for row in rows:
                value = (row.value or {}).get("value")
                if value not in (None, ""):
                    values[row.key] = str(value)
    except Exception as exc:  # noqa: BLE001
        log.warning("读取 ES 配置失败，使用环境变量默认值: %s", exc)
    return values


def current() -> dict[str, str]:
    """当前生效的 ES 配置（带 TTL 缓存）。"""
    global _cache, _cache_at
    now = time.monotonic()
    if _cache is None or (now - _cache_at) > _CACHE_TTL_SECONDS:
        _cache = _load()
        _cache_at = now
    return dict(_cache)


def invalidate() -> None:
    """配置更新后立即失效缓存。"""
    global _cache, _cache_at
    _cache = None
    _cache_at = 0.0


def retention_days() -> int:
    try:
        return int(current().get("es.retention_days") or settings.es_retention_days)
    except (TypeError, ValueError):
        return settings.es_retention_days


def auth_pair() -> tuple[str, str] | None:
    cfg = current()
    user = (cfg.get("es.username") or "").strip()
    if not user:
        return None
    return (user, cfg.get("es.password") or "")
