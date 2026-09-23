"""安全分析技能 CRUD（后台配置）。"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.base import get_db
from app.db.models import Skill, User
from app.tools import TOOLS, tool_names

router = APIRouter(prefix="/api/skills", tags=["skills"])


class SkillIn(BaseModel):
    name: str
    description: str = ""
    sop: str = ""
    event_types: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    enabled: bool = True
    priority: int = 100


def _validate(body: SkillIn) -> list[dict[str, str]]:
    """保存前校验：名称/事件类型/SOP 非空，工具名必须存在。"""
    errors: list[dict[str, str]] = []
    if not body.name.strip():
        errors.append({"field": "name", "msg": "技能名不能为空"})
    if not body.event_types:
        errors.append({"field": "event_types", "msg": "至少声明一个事件类型（否则永远不会被路由命中）"})
    if not body.sop.strip():
        errors.append({"field": "sop", "msg": "SOP 正文不能为空"})
    known = set(tool_names())
    for t in body.tools:
        if t not in known:
            errors.append({"field": "tools", "msg": f"工具 {t} 不存在"})
    return errors


def _skill_dict(s: Skill) -> dict[str, Any]:
    return {
        "id": s.id,
        "name": s.name,
        "description": s.description,
        "sop": s.sop,
        "event_types": s.event_types or [],
        "tools": s.tools or [],
        "source": s.source,
        "enabled": s.enabled,
        "priority": s.priority,
    }


@router.get("")
def list_skills(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    rows = db.execute(select(Skill).order_by(Skill.priority)).scalars().all()
    return {
        "items": [_skill_dict(r) for r in rows],
        "tools": [
            {"name": name, "category": spec["category"], "description": spec["description"]}
            for name, spec in TOOLS.items()
        ],
    }


@router.post("")
def create_skill(
    body: SkillIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    exists = db.execute(select(Skill).where(Skill.name == body.name)).scalar_one_or_none()
    if exists:
        raise HTTPException(status_code=409, detail="技能名已存在")
    errors = _validate(body)
    if errors:
        return JSONResponse(
            status_code=400,
            content={"conflict": "field_error", "detail": errors[0]["msg"], "field_errors": errors},
        )
    skill = Skill(
        name=body.name.strip(),
        description=body.description,
        sop=body.sop,
        event_types=body.event_types,
        tools=body.tools,
        enabled=body.enabled,
        priority=body.priority,
        source="user",
    )
    db.add(skill)
    db.commit()
    return _skill_dict(skill)


@router.put("/{skill_id}")
def update_skill(
    skill_id: str,
    body: SkillIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    skill = db.get(Skill, skill_id)
    if skill is None:
        raise HTTPException(status_code=404, detail="技能不存在")
    errors = _validate(body)
    if errors:
        return JSONResponse(
            status_code=400,
            content={"conflict": "field_error", "detail": errors[0]["msg"], "field_errors": errors},
        )
    skill.name = body.name.strip()
    skill.description = body.description
    skill.sop = body.sop
    skill.event_types = body.event_types
    skill.tools = body.tools
    skill.enabled = body.enabled
    skill.priority = body.priority
    db.commit()
    return _skill_dict(skill)


@router.delete("/{skill_id}")
def delete_skill(
    skill_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    skill = db.get(Skill, skill_id)
    if skill is None:
        raise HTTPException(status_code=404, detail="技能不存在")
    if skill.source == "builtin":
        raise HTTPException(status_code=400, detail="内置技能不可删除，可禁用")
    db.delete(skill)
    db.commit()
    return {"ok": True}
