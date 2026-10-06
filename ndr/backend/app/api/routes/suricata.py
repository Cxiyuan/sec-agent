"""签名引擎（Suricata）规则集接口：状态 / 来源配置 / 检查更新 / 生效 / 清空。

规则是**检测口径**，所以分成两步：检查（拉 manifest + 下载 + 让容器跑 `suricata -T` 校验）
与生效（人工确认后切换）。定时任务只做检查、不生效。
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.base import get_db
from app.db.models import User
from app.suricata import rules as suricata_rules

router = APIRouter(prefix="/api/suricata", tags=["suricata"])


class SourceIn(BaseModel):
    """更新来源配置。``token`` 不传 = 保留原值，空串 = 清除。"""

    url: str | None = None
    token: str | None = None
    enabled: bool | None = None


def _fail(exc: suricata_rules.RulesError) -> HTTPException:
    return HTTPException(status_code=exc.status, detail=str(exc))


@router.get("/rules")
def get_rules(
    _: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """规则集状态：来源配置 + 生效版本/条数 + 待确认版本 + 最近检查 + 历史。"""
    return suricata_rules.status(db)


@router.put("/rules/source")
def put_source(
    body: SourceIn,
    _: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """保存更新地址 / 令牌 / 启用开关（令牌不回显）。"""
    try:
        cfg = suricata_rules.save_source_config(db, body.url, body.token, body.enabled)
    except suricata_rules.RulesError as exc:
        raise _fail(exc) from exc
    return {"source": cfg}


@router.post("/rules/check")
def post_check(
    _: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """检查更新：拉 manifest → 比哈希 → 有差异则下载并请求容器校验（不生效）。"""
    try:
        return suricata_rules.check_now(db)
    except suricata_rules.RulesError as exc:
        raise _fail(exc) from exc


@router.post("/rules/apply")
def post_apply(
    _: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """生效：只接受「已下载且校验通过」的待确认版本（前端应先弹确认框）。"""
    try:
        return suricata_rules.apply_pending(db)
    except suricata_rules.RulesError as exc:
        raise _fail(exc) from exc


@router.post("/rules/reset")
def post_reset(
    _: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """清空规则：回到空占位（签名引擎不再产生任何告警）。"""
    try:
        return suricata_rules.reset_rules(db)
    except suricata_rules.RulesError as exc:
        raise _fail(exc) from exc
