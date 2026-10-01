"""规则读写辅助（NDR 侧）。"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Rule


def get_enabled_rules(db: Session) -> list[dict[str, Any]]:
    """取启用中的规则（按 priority 升序），供检测器逐条匹配。"""
    rows = db.execute(select(Rule).where(Rule.enabled.is_(True)).order_by(Rule.priority)).scalars()
    return [
        {
            "name": r.name,
            "description": r.description,
            "conditions": r.conditions,
            "severity": r.severity,
            "source": r.source,
            "priority": r.priority,
        }
        for r in rows
    ]
