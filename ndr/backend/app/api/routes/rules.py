"""规则 CRUD（后台界面配置）。"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
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


def _name_taken(db: Session, name: str, *, ignore_id: str | None = None) -> bool:
    """规则名是否已被占用（`ignore_id` = 改名时排除自己）。

    数据库上 `rules.name` 本来就是唯一约束，这里的检查只为给出 409 而不是让
    IntegrityError 冒成 500。
    """
    stmt = select(Rule.id).where(Rule.name == name)
    if ignore_id is not None:
        stmt = stmt.where(Rule.id != ignore_id)
    return db.execute(stmt).first() is not None


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
    if _name_taken(db, body.name):
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
    try:
        db.commit()
    except IntegrityError as exc:  # 并发下同名两条：唯一约束兜底
        db.rollback()
        raise HTTPException(status_code=409, detail="规则名已存在") from exc
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
    if body.name != rule.name:
        # 内置规则**不让改名**：`main.py` 的启动播种按 name 幂等 upsert，改名后它找不到
        # 原来那条，会在下次启动再插一条同名内置规则（两条重复的规则同时生效）；
        # 而删除接口本来就禁止删内置规则（`:134`），所以「改名」是绕过那条保护的口子。
        # 要加自己的判断请新建一条用户规则 —— 也就是把内置规则当模板。
        if rule.source == "builtin":
            raise HTTPException(
                status_code=400,
                detail="内置规则不可改名（改名会让下次启动再插一条同名内置规则）；请新建用户规则",
            )
        if _name_taken(db, body.name, ignore_id=rule.id):
            raise HTTPException(status_code=409, detail="规则名已存在")
    rule.name = body.name
    rule.description = body.description
    rule.conditions = body.conditions
    rule.severity = body.severity
    rule.enabled = body.enabled
    rule.priority = body.priority
    try:
        db.commit()
    except IntegrityError as exc:  # 并发改名到同一个名字：唯一约束兜底
        db.rollback()
        raise HTTPException(status_code=409, detail="规则名已存在") from exc
    out = _rule_dict(rule)
    if rule.source == "builtin":
        # 内置规则的描述/条件/严重度/优先级每次启动都会被代码里的定义覆盖（只有 enabled
        # 会保留），别让界面看起来「改成功了」。见 main.py `_seed()`。
        out["warning"] = (
            "这是内置规则：描述/条件/严重度/优先级会在下次启动时被内置定义覆盖"
            "（只有启用状态会保留）。需要长期生效请新建一条用户规则。"
        )
    return out


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
