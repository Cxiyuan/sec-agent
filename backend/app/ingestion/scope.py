"""分析网段：读取启用中的网段组并合并成 CIDR 列表。"""

from __future__ import annotations

from sqlalchemy import select

from app.db.base import SessionLocal
from app.db.models import AnalysisScope
from app.workers.log import get_logger

log = get_logger(__name__)


def enabled_cidrs() -> list[str]:
    """所有启用网段组里的 IP/CIDR（去重保序）。出错时返回空（等价于不分析）。"""
    try:
        with SessionLocal() as db:
            rows = db.scalars(select(AnalysisScope).where(AnalysisScope.enabled.is_(True))).all()
    except Exception as exc:  # noqa: BLE001
        log.warning("读取分析网段失败: %s", exc)
        return []

    seen: set[str] = set()
    out: list[str] = []
    for row in rows:
        for item in row.cidrs or []:
            value = str(item).strip()
            if value and value not in seen:
                seen.add(value)
                out.append(value)
    return out


def scope_status() -> dict[str, int | bool]:
    """供前端首次向导判断：是否已配置、启用几套。"""
    try:
        with SessionLocal() as db:
            rows = db.scalars(select(AnalysisScope)).all()
    except Exception:  # noqa: BLE001
        return {"configured": False, "total": 0, "enabled_count": 0}
    total = len(rows)
    enabled = sum(1 for r in rows if r.enabled)
    return {"configured": total > 0, "total": total, "enabled_count": enabled}
