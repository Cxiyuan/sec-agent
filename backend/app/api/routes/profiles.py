"""账号 / 会话跨窗口画像：查询与清理。"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

from app.agents.profile import cleanup, list_profiles, top_anomalies
from app.api.deps import get_current_user
from app.db.models import User

router = APIRouter(prefix="/api/profiles", tags=["profiles"])


@router.get("")
def list_all(
    _: Annotated[User, Depends(get_current_user)],
    kind: str | None = None,
    min_risk: float = Query(0.0, ge=0.0, le=1.0),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """账号 / 会话画像列表（按风险分降序）。"""
    return list_profiles(kind=kind, min_risk=min_risk, limit=limit, offset=offset)


@router.get("/top")
def top(
    _: Annotated[User, Depends(get_current_user)],
    limit: int = Query(10, ge=1, le=50),
) -> dict[str, Any]:
    """驾驶舱用：高风险账号 / 会话 TOP。"""
    return top_anomalies(limit=limit)


@router.post("/cleanup")
def do_cleanup(_: Annotated[User, Depends(get_current_user)]):
    """清理长期无观测的画像。"""
    return cleanup()
