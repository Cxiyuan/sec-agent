"""ES 运行时配置：连接信息只来自部署环境，策略项默认环境变量、后台可覆盖（30 秒 TTL 缓存）。

**连接信息（`es.url` / `es.username` / `es.password`）不可由用户配置**：Elasticsearch 随
NDR 一起部署，地址与凭据由部署环境给定（`.env` 的 `ES_*` → 后台的 `ST_ES_*`）。这几项永远
取 `settings.es_*`，本模块不读库、也没有写入口 —— 同一事实只允许一个来源，否则会出现
「界面写了一个地址、实际连的是另一个」而看不出来。

只有**策略项**（`es.events_index` / `es.retention_days`）允许在后台改：它们是「日志存哪族
索引、留多久」，不是「连到哪台机器」，改完 30 秒内生效（写侧会 `invalidate()` 立即失效）。
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
#
# 注意：**连接信息不在这个名单里**。`es.url` / `es.username` / `es.password` 曾经可覆盖
# （库里存 `SystemConfig` 行），现在只认部署环境；库里的历史行仍在，但不再被读，属遗留垃圾，
# 可以安全删除（服务器实测本来就没有这些行）。
RUNTIME_KEYS = (
    "es.events_index",
    "es.retention_days",
)


def defaults() -> dict[str, str]:
    """全部键的部署环境默认值（含不可覆盖的连接信息，供 `current()` 组装）。"""
    return {
        "es.url": settings.es_url,
        "es.username": settings.es_user,
        "es.password": settings.es_password,
        "es.events_index": settings.es_events_index,
        "es.retention_days": str(settings.es_retention_days),
    }


def _load() -> dict[str, str]:
    """读库里的覆盖值；没有覆盖的键用环境变量默认值。

    只有 `RUNTIME_KEYS`（索引族 + 保留天数）会被覆盖；连接信息三项永远来自环境变量。

    「DB 里没有这一行」与「DB 里显式置空」是两回事，这里靠存储形态区分：
      - 没有这一行        → 用环境变量默认值；
      - `{"value": "x"}`  → 覆盖成 x；
      - `{"value": null}` → **显式清空**（写侧用 JSON null 表示「用户就是要它为空」），
        此时**不**回落环境变量 —— 否则界面点了「清空」，环境变量又把它填回来，
        看起来像清空没生效（G 组报的就是这个）；
      - `{"value": ""}`   → 当作「没填」，回落环境变量（历史行为，库里可能还留着这种老行）。

    写侧约定（`api/routes/es_admin.py` 的 PUT）：清空某个键时写 `{"value": None}`，
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
