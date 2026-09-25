"""事件组查询 + HITL 确认。"""

from __future__ import annotations

import asyncio
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.agents.runner import resume_graph
from app.api.deps import get_current_user
from app.db.base import get_db
from app.db.models import EventGroup, User

router = APIRouter(prefix="/api/events", tags=["events"])


def _group_dict(g: EventGroup, with_events: bool = False) -> dict[str, Any]:
    data = {
        "id": g.id,
        "fingerprint": g.fingerprint,
        "src_ips": g.src_ips,
        "dst_ips": g.dst_ips,
        "window_start": g.window_start.isoformat() if g.window_start else None,
        "window_end": g.window_end.isoformat() if g.window_end else None,
        "event_count": g.event_count,
        "triage_score": g.triage_score,
        "status": g.status,
        "severity": g.severity,
        "business_context": g.business_context,
        "lookback": g.lookback,
        "memory_hits": g.memory_hits,
        "attack_chain": g.attack_chain,
        "profile": g.profile,
        "anomaly": g.anomaly,
        "response_suggestions": g.response_suggestions,
        # 聚合规模（实时链路）：命中次数/规则分布/目标与端口/首末时间
        "aggregate": g.aggregate or {},
        # 被排除过滤命中：事件可见、可回溯，但不参与模型分析与报告
        "excluded": g.status == "excluded",
        "created_at": g.created_at.isoformat() if g.created_at else None,
    }
    if with_events:
        data["events"] = [
            {
                "id": e.id,
                "source_system": e.source_system,
                "ts": e.ts.isoformat() if e.ts else None,
                "event_type": e.event_type,
                "src_ip": e.src_ip,
                "dst_ip": e.dst_ip,
                "src_port": e.src_port,
                "dst_port": e.dst_port,
                "protocol": e.protocol,
                "severity": e.severity,
                "hit_rule": e.hit_rule,
                "edge_score": e.edge_score,
                "summary": e.summary,
                "excluded": e.excluded,
            }
            for e in g.events
        ]
    return data


@router.get("/groups")
def list_groups(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    status: str | None = None,
    severity: str | None = None,
    include_excluded: bool = False,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    count_q = select(func.count()).select_from(EventGroup)
    q = select(EventGroup).order_by(EventGroup.window_start.desc())
    if status:
        count_q = count_q.where(EventGroup.status == status)
        q = q.where(EventGroup.status == status)
    elif not include_excluded:
        # 默认不显示“已排除”组（噪声不刷屏）；要看就传 status=excluded 或 include_excluded=true
        count_q = count_q.where(EventGroup.status != "excluded")
        q = q.where(EventGroup.status != "excluded")
    if severity:
        count_q = count_q.where(EventGroup.severity == severity)
        q = q.where(EventGroup.severity == severity)
    total = db.scalar(count_q) or 0
    rows = db.scalars(q.limit(limit).offset(offset)).all()
    return {"total": total, "items": [_group_dict(g) for g in rows]}


@router.get("/groups/{group_id}")
def get_group(
    group_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    g = db.execute(
        select(EventGroup).where(EventGroup.id == group_id).options(selectinload(EventGroup.events))
    ).scalar_one_or_none()
    if g is None:
        raise HTTPException(status_code=404, detail="事件组不存在")
    return _group_dict(g, with_events=True)


class ConfirmRequest(BaseModel):
    action: str  # "confirm" | "dismiss"


@router.post("/groups/{group_id}/confirm")
async def confirm_group(
    group_id: str,
    req: ConfirmRequest,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    g = db.get(EventGroup, group_id)
    if g is None:
        raise HTTPException(status_code=404, detail="事件组不存在")
    if g.thread_id is None:
        raise HTTPException(status_code=400, detail="该事件组无待确认状态")

    decision = {"confirmations": {g.fingerprint: req.action}}
    await asyncio.to_thread(resume_graph, g.thread_id, decision)
    return {"ok": True, "action": req.action, "fingerprint": g.fingerprint}
