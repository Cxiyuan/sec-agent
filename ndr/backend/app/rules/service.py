"""规则读写辅助（NDR 侧）。"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Rule


def get_enabled_rules(db: Session) -> list[dict[str, Any]]:
    """取启用中的规则（按 priority 升序），供检测器逐条匹配。

    同优先级必须再加 `id` 作二级键：检测器是「首个命中即停」，而内置规则每次启动都会
    upsert 重写（行序会变）——只按 priority 排序时，同一请求命中多条同优先级规则时
    留下哪一条**不保证稳定**，摘要里的规则名会误导分析师（2026-10 规则评审 P2）。
    """
    rows = db.execute(
        select(Rule).where(Rule.enabled.is_(True)).order_by(Rule.priority, Rule.id)
    ).scalars()
    return [
        {
            "name": r.name,
            "description": r.description,
            "conditions": r.conditions,
            "severity": r.severity,
            "source": r.source,
            "priority": r.priority,
            # 规则适用范围（network/host）：检测器据此只在该侧事件上求值
            "scope": r.scope,
        }
        for r in rows
    ]
