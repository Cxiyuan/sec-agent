"""规则 CRUD（后台界面配置）。"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.base import get_db
from app.db.models import Rule, User
from app.rules.engine import has_conditions, validate_rule_regexes

router = APIRouter(prefix="/api/rules", tags=["rules"])


class RuleIn(BaseModel):
    name: str
    description: str = ""
    conditions: dict[str, Any] = Field(default_factory=dict)
    severity: str = "medium"
    enabled: bool = True
    priority: int = 100


def _validate(body: RuleIn) -> list[dict[str, str]]:
    """保存前校验：条件非空 + 正则合法（非法正则会静默不生效）。"""
    errors: list[dict[str, str]] = []
    if not has_conditions({"conditions": body.conditions}):
        errors.append({"field": "conditions", "msg": "规则至少需要一个条件（空条件规则不生效）"})
    for msg in validate_rule_regexes({"conditions": body.conditions}):
        errors.append({"field": "conditions", "msg": msg})
    return errors


def _rule_dict(r: Rule) -> dict[str, Any]:
    return {
        "id": r.id,
        "name": r.name,
        "description": r.description,
        "conditions": r.conditions,
        "severity": r.severity,
        "source": r.source,
        "enabled": r.enabled,
        "priority": r.priority,
    }


@router.get("")
def list_rules(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    rows = db.execute(select(Rule).order_by(Rule.priority)).scalars().all()
    return {"items": [_rule_dict(r) for r in rows]}


@router.post("")
def create_rule(
    body: RuleIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    exists = db.execute(select(Rule).where(Rule.name == body.name)).scalar_one_or_none()
    if exists:
        raise HTTPException(status_code=409, detail="规则名已存在")
    errors = _validate(body)
    if errors:
        return JSONResponse(
            status_code=400,
            content={
                "conflict": "field_error",
                "detail": errors[0]["msg"],
                "field_errors": errors,
            },
        )
    rule = Rule(
        name=body.name,
        description=body.description,
        conditions=body.conditions,
        severity=body.severity,
        enabled=body.enabled,
        priority=body.priority,
        source="user",
    )
    db.add(rule)
    db.commit()
    return _rule_dict(rule)


@router.put("/{rule_id}")
def update_rule(
    rule_id: str,
    body: RuleIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    rule = db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="规则不存在")
    errors = _validate(body)
    if errors:
        return JSONResponse(
            status_code=400,
            content={
                "conflict": "field_error",
                "detail": errors[0]["msg"],
                "field_errors": errors,
            },
        )
    rule.name = body.name
    rule.description = body.description
    rule.conditions = body.conditions
    rule.severity = body.severity
    rule.enabled = body.enabled
    rule.priority = body.priority
    db.commit()
    return _rule_dict(rule)


@router.delete("/{rule_id}")
def delete_rule(
    rule_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    rule = db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="规则不存在")
    if rule.source == "builtin":
        raise HTTPException(status_code=400, detail="内置规则不可删除，可禁用")
    db.delete(rule)
    db.commit()
    return {"ok": True}
