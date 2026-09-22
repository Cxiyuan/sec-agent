"""分析网段：CRUD + 状态（供首次设置向导拦截）。"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.api.validation import is_valid_ip_or_cidr
from app.db.base import get_db
from app.db.models import AnalysisScope, User
from app.ingestion.scope import scope_status

router = APIRouter(prefix="/api/analysis-scopes", tags=["analysis-scopes"])

MAX_CIDRS = 200


class ScopeIn(BaseModel):
    name: str
    description: str = ""
    cidrs: list[str] = Field(default_factory=list)
    enabled: bool = True


def _clean(cidrs: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for c in cidrs:
        value = (c or "").strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _validate(cidrs: list[str]) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    cleaned = _clean(cidrs)
    if not cleaned:
        errors.append({"field": "cidrs", "msg": "必须至少填写一个网段或 IP"})
    if len(cleaned) > MAX_CIDRS:
        errors.append({"field": "cidrs", "msg": f"最多 {MAX_CIDRS} 条"})
    for value in cleaned:
        if not is_valid_ip_or_cidr(value):
            errors.append({"field": "cidrs", "msg": f"非法 IP/CIDR：{value}"})
    return errors


def _scope_dict(s: AnalysisScope) -> dict[str, Any]:
    return {
        "id": s.id,
        "name": s.name,
        "description": s.description,
        "cidrs": s.cidrs or [],
        "enabled": s.enabled,
        "updated_at": s.updated_at.isoformat() if s.updated_at else None,
    }


@router.get("/status")
def get_status(_: Annotated[User, Depends(get_current_user)]):
    """供前端判断是否已配置分析网段（未配置 → 强制进向导）。"""
    return scope_status()


@router.get("")
def list_scopes(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    rows = db.scalars(select(AnalysisScope).order_by(AnalysisScope.created_at)).all()
    return {"items": [_scope_dict(s) for s in rows]}


@router.post("")
def create_scope(
    body: ScopeIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="名称不能为空")
    exists = db.scalars(select(AnalysisScope).where(AnalysisScope.name == name)).first()
    if exists is not None:
        return JSONResponse(
            status_code=409,
            content={"conflict": "duplicate_name", "detail": f"名称已存在：{name}"},
        )
    errors = _validate(body.cidrs)
    if errors:
        return JSONResponse(
            status_code=400,
            content={"conflict": "field_error", "detail": errors[0]["msg"], "field_errors": errors},
        )
    scope = AnalysisScope(
        name=name,
        description=body.description,
        cidrs=_clean(body.cidrs),
        enabled=body.enabled,
    )
    db.add(scope)
    db.commit()
    return _scope_dict(scope)


@router.put("/{scope_id}")
def update_scope(
    scope_id: str,
    body: ScopeIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    scope = db.get(AnalysisScope, scope_id)
    if scope is None:
        raise HTTPException(status_code=404, detail="网段组不存在")
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="名称不能为空")
    dup = db.scalars(
        select(AnalysisScope).where(AnalysisScope.name == name, AnalysisScope.id != scope_id)
    ).first()
    if dup is not None:
        return JSONResponse(
            status_code=409,
            content={"conflict": "duplicate_name", "detail": f"名称已存在：{name}"},
        )
    errors = _validate(body.cidrs)
    if errors:
        return JSONResponse(
            status_code=400,
            content={"conflict": "field_error", "detail": errors[0]["msg"], "field_errors": errors},
        )
    scope.name = name
    scope.description = body.description
    scope.cidrs = _clean(body.cidrs)
    scope.enabled = body.enabled
    db.commit()
    return _scope_dict(scope)


@router.delete("/{scope_id}")
def delete_scope(
    scope_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    scope = db.get(AnalysisScope, scope_id)
    if scope is None:
        raise HTTPException(status_code=404, detail="网段组不存在")
    db.delete(scope)
    db.commit()
    return {"ok": True}
