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

# 可被后台覆盖的键：这里是**唯一来源**，`api/routes/es_admin.py` 直接读它（那里原先复制
# 的一份 CONFIG_KEYS 已删）。加键只改这里。
RUNTIME_KEYS = (
    "es.url",
    "es.username",
    "es.password",
    "es.events_index",
    "es.retention_days",
)


def defaults() -> dict[str, str]:
    return {
        "es.url": settings.es_url,
        "es.username": settings.es_user,
        "es.password": settings.es_password,
        "es.events_index": settings.es_events_index,
        "es.retention_days": str(settings.es_retention_days),
    }


def _load() -> dict[str, str]:
    """读库里的覆盖值；没有覆盖的键用环境变量默认值。

    「DB 里没有这一行」与「DB 里显式置空」是两回事，这里靠存储形态区分：
      - 没有这一行        → 用环境变量默认值；
      - `{"value": "x"}`  → 覆盖成 x；
      - `{"value": null}` → **显式清空**（写侧用 JSON null 表示「用户就是要它为空」），
        此时**不**回落环境变量 —— 否则界面点了「清空密码」，`ES_PASSWORD` 又把它填回来，
        看起来像清空没生效（G 组报的就是这个）；
      - `{"value": ""}`   → 当作「没填」，回落环境变量（历史行为，库里可能还留着这种老行）。

    写侧约定（E 组 `api/routes/es_admin.py` 的 PUT）：清空某个键时写 `{"value": None}`，
    既不删行也不写空串。若写侧判断代价大于收益，就保持现状并记为已知限制。
    """
    values = defaults()
    try:
        with SessionLocal() as db:
            rows = db.scalars(
                select(SystemConfig).where(SystemConfig.key.in_(list(RUNTIME_KEYS)))
            ).all()
            for row in rows:
                data = row.value if isinstance(row.value, dict) else {}
                if "value" not in data:
                    continue
                value = data.get("value")
                if value is None:
                    values[row.key] = ""  # 显式清空：不回落到环境变量
                elif str(value) != "":
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
