"""排除过滤管理：命中后事件仍落库，但跳过全部模型调用与报告生成。

为什么必须界面可管、可查：排除配置是最容易「配错就静默漏报」的一类开关。
所以保存时过三道校验（空条件 / 字段白名单 / 正则），运行期必须能回答
「到底排除了什么」（命中计数 + 最近样例）。
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.base import get_db
from app.db.models import ExclusionFilter, User
from app.ingestion import exclusion
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/exclusions", tags=["exclusions"])

OPERATORS = ["eq", "ne", "contains", "regex", "gt", "gte", "lt", "lte", "in", "exists"]


class ExclusionIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = ""
    conditions: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    priority: int = 100


def _dict(row: ExclusionFilter) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "conditions": row.conditions or {},
        "enabled": row.enabled,
        "priority": row.priority,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def _validate(payload: ExclusionIn) -> None:
    errors = exclusion.validate_conditions(payload.conditions)
    if errors:
        raise HTTPException(status_code=400, detail="；".join(errors))


def _get(db: Session, filter_id: str) -> ExclusionFilter:
    row = db.execute(
        select(ExclusionFilter).where(ExclusionFilter.id == filter_id)
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="排除过滤不存在")
    return row


def _check_name_free(db: Session, name: str, exclude_id: str | None = None) -> None:
    row = db.execute(
        select(ExclusionFilter).where(ExclusionFilter.name == name)
    ).scalar_one_or_none()
    if row is not None and row.id != exclude_id:
        raise HTTPException(status_code=409, detail="同名排除过滤已存在")


@router.get("")
def list_filters(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    rows = db.execute(select(ExclusionFilter).order_by(ExclusionFilter.priority)).scalars().all()
    return {"total": len(rows), "items": [_dict(r) for r in rows]}


@router.get("/fields")
def list_fields(_: Annotated[User, Depends(get_current_user)]):
    """条件可用字段与运算符（供界面条件编辑器）。"""
    return {
        "fields": sorted(exclusion.allowed_fields()),
        "rule_fields": list(exclusion.EXTRA_FIELDS),
        "operators": OPERATORS,
    }


@router.get("/stats")
def get_stats(_: Annotated[User, Depends(get_current_user)]):
    """命中统计与最近样例：用来回答「我配的排除到底排掉了什么」。"""
    return {**exclusion.get_stats(), "samples": exclusion.get_samples()}


@router.post("")
def create_filter(
    payload: ExclusionIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    _validate(payload)
    _check_name_free(db, payload.name)
    row = ExclusionFilter(
        name=payload.name,
        description=payload.description,
        conditions=payload.conditions,
        enabled=payload.enabled,
        priority=payload.priority,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    exclusion.invalidate_cache()
    log.info("新增排除过滤：%s（启用 %s）", row.name, row.enabled)
    return _dict(row)


@router.put("/{filter_id}")
def update_filter(
    filter_id: str,
    payload: ExclusionIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    row = _get(db, filter_id)
    _validate(payload)
    _check_name_free(db, payload.name, exclude_id=row.id)
    row.name = payload.name
    row.description = payload.description
    row.conditions = payload.conditions
    row.enabled = payload.enabled
    row.priority = payload.priority
    db.commit()
    db.refresh(row)
    exclusion.invalidate_cache()
    log.info("更新排除过滤：%s（启用 %s）", row.name, row.enabled)
    return _dict(row)


@router.delete("/{filter_id}")
def delete_filter(
    filter_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    row = _get(db, filter_id)
    name = row.name
    db.delete(row)
    db.commit()
    exclusion.invalidate_cache()
    log.info("删除排除过滤：%s", name)
    return {"ok": True}
