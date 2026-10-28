"""观察事实与外连白名单的接口。

- `/api/baseline/observations`：行为基线产出的事实（外连新目标 / 异地登录 / 爆破 / 404 / 计数偏离），
  **只有事实没有结论**；
- `/api/baseline/egress-allow`：外连白名单（自学习条目可编辑/删除，删除留墓碑永不再学）；
- `/api/baseline/egress`：某台资产已学到的外连目的地（排查"这台机器平时连谁"）。

界面上的「行为分析」页直接读这三组接口；智能体侧对应的 MCP 工具是 `list_observations`。
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.api.deps import get_current_user
from app.baseline import egress, observations
from app.db.models import User

router = APIRouter(prefix="/api/baseline", tags=["baseline-observations"])


@router.get("/observations")
def list_observations(
    _: Annotated[User, Depends(get_current_user)],
    kind: str = Query(default=""),
    subject: str = Query(default=""),
    minutes: int = Query(default=1440, ge=1, le=60 * 24 * 30),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """行为基线事实（按最近时间倒序）。`kind` 见 `app/baseline/observations.py`。"""
    return observations.list_observations(
        kind=kind.strip(), subject=subject.strip(), minutes=minutes, limit=limit, offset=offset
    )


@router.get("/observations/stats")
def observation_stats(
    _: Annotated[User, Depends(get_current_user)],
    minutes: int = Query(default=1440, ge=1, le=60 * 24 * 30),
) -> dict[str, Any]:
    """按事实类型汇总（界面顶部卡片用）。"""
    return observations.stats(minutes=minutes)


@router.get("/egress")
def list_egress(
    _: Annotated[User, Depends(get_current_user)],
    src_ip: str = Query(default=""),
    kind: str = Query(default=""),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    """某台资产（或全部）已学到的外连目的地。"""
    return {"items": egress.list_baseline(src_ip.strip(), kind=kind.strip(), limit=limit)}


@router.get("/egress-allow")
def list_egress_allow(
    _: Annotated[User, Depends(get_current_user)],
    kind: str = Query(default=""),
    scope: str = Query(default=""),
    include_tombstone: bool = Query(default=False),
) -> dict[str, Any]:
    """外连白名单（默认不含已删除的墓碑条目）。"""
    return {"items": egress.list_allow(kind=kind.strip(), scope=scope.strip(), include_tombstone=include_tombstone)}


class AllowBody(BaseModel):
    kind: str = Field(description="dst_ip / domain / port")
    value: str = Field(description="目标值（IP / 域名 / 端口）")
    scope: str = Field(default="global", description="global 或 asset")
    asset: str = Field(default="", description="scope=asset 时的资产 IP")
    enabled: bool = Field(default=True)
    note: str = Field(default="")


@router.post("/egress-allow")
def save_egress_allow(
    _: Annotated[User, Depends(get_current_user)], body: AllowBody
) -> JSONResponse:
    """新增/编辑白名单（记为手工条目；会覆盖同键的自学习条目）。"""
    result = egress.save_allow(body.model_dump())
    return JSONResponse(status_code=200 if result.get("ok") else 400, content=result)


@router.delete("/egress-allow/{entry_id}")
def delete_egress_allow(
    _: Annotated[User, Depends(get_current_user)], entry_id: str
) -> JSONResponse:
    """删除白名单。默认留**墓碑**：以后不会再自动学回来。"""
    done = egress.remove_allow(entry_id, tombstone=True)
    return JSONResponse(status_code=200 if done else 404, content={"ok": done})


@router.post("/egress-allow/{entry_id}/restore")
def restore_egress_allow(
    _: Annotated[User, Depends(get_current_user)], entry_id: str
) -> JSONResponse:
    """撤销墓碑（重新允许自学习）。"""
    done = egress.remove_tombstone(entry_id)
    return JSONResponse(status_code=200 if done else 404, content={"ok": done})
