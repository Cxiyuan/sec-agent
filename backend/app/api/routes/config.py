"""系统配置路由。"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.base import get_db
from app.db.models import SystemConfig, User

router = APIRouter(prefix="/api/config", tags=["config"])

# 可配置键及默认值（与 config.py settings 对应）
CONFIG_KEYS = {
    "escalate_score_threshold": 0.6,
    "report_min_severity": "medium",
    "hitl_enabled": False,
    "hitl_min_severity": "high",
    "analysis_interval_minutes": 5,
    "baseline_observe_days": 7,
}


class ConfigIn(BaseModel):
    value: Any


@router.get("")
def list_config(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    rows = db.execute(select(SystemConfig)).scalars().all()
    stored = {r.key: r.value.get("value") if r.value else None for r in rows}
    result = {}
    for key, default in CONFIG_KEYS.items():
        result[key] = stored.get(key, default)
    return {"items": result}


@router.put("/{key}")
def update_config(
    key: str,
    body: ConfigIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    if key not in CONFIG_KEYS:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="未知配置项")
    row = db.get(SystemConfig, key)
    if row is None:
        row = SystemConfig(key=key, value={})
        db.add(row)
    row.value = {"value": body.value}
    db.commit()
    return {"key": key, "value": body.value}
