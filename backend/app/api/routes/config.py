"""系统配置路由。"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.config import settings
from app.db.base import get_db
from app.db.models import SystemConfig, User
from app.models.registry import invalidate_model_cache

router = APIRouter(prefix="/api/config", tags=["config"])

# 可配置键及默认值。默认取环境变量；写入 DB 后 DB 值优先。
CONFIG_KEYS: dict[str, Any] = {
    # 模型名（角色分工，后台可运行时修改）
    "model.edge": settings.edge_model_name,
    "model.flash": settings.flash_model_name,
    "model.deep": settings.deep_model_name,
    "model.embo_db": settings.embo_db_model_name,
    "model.embo_query": settings.embo_query_model_name,
    # 升级与报告
    "escalate_score_threshold": settings.escalate_score_threshold,
    "report_min_severity": settings.report_min_severity,
    "hitl_enabled": settings.hitl_enabled,
    "hitl_min_severity": settings.hitl_min_severity,
    "analysis_interval_minutes": settings.analysis_interval_minutes,
    "baseline_observe_days": settings.baseline_observe_days,
    # RAG
    "rag_enabled": settings.rag_enabled,
    "rag_top_k": settings.rag_top_k,
}


class ConfigIn(BaseModel):
    value: Any


@router.get("")
def list_config(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    rows = db.scalars(select(SystemConfig)).all()
    stored = {r.key: (r.value or {}).get("value") for r in rows}
    return {"items": {key: stored.get(key, default) for key, default in CONFIG_KEYS.items()}}


@router.put("/{key}")
def update_config(
    key: str,
    body: ConfigIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    if key not in CONFIG_KEYS:
        raise HTTPException(status_code=404, detail="未知配置项")
    row = db.get(SystemConfig, key)
    if row is None:
        row = SystemConfig(key=key, value={})
        db.add(row)
    row.value = {"value": body.value}
    db.commit()
    # 模型名变更立即生效；其余配置由各节点读取时生效
    invalidate_model_cache()
    return {"key": key, "value": body.value}
