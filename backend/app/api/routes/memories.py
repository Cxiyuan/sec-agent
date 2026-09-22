"""分析记忆：查询与清理。"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.agents.memory import cleanup, list_memories
from app.api.deps import get_current_user
from app.config import settings
from app.db.base import get_db
from app.db.models import AnalysisMemory, User

router = APIRouter(prefix="/api/memories", tags=["memories"])


def _memory_dict(m: AnalysisMemory) -> dict[str, Any]:
    return {
        "id": m.id,
        "kind": m.kind,
        "fingerprint": m.fingerprint,
        "severity": m.severity,
        "summary": m.summary,
        "ips": m.ips or [],
        "asset_ids": m.asset_ids or [],
        "detail": m.detail or {},
        "window_start": m.window_start.isoformat() if m.window_start else None,
        "window_end": m.window_end.isoformat() if m.window_end else None,
        "created_at": m.created_at.isoformat() if m.created_at else None,
    }


@router.get("")
def list_all(
    _: Annotated[User, Depends(get_current_user)],
    kind: str | None = None,
    severity: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    return list_memories(kind=kind, severity=severity, limit=limit, offset=offset)


@router.get("/by-object")
def by_object(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    ip: str | None = None,
    asset_id: str | None = None,
    fingerprint: str | None = None,
    days: int = Query(0, ge=0, le=365),
    limit: int = Query(20, ge=1, le=200),
):
    """按 IP / 资产 / 指纹查历史记忆（供事件详情的历史比对展示）。"""
    stmt = select(AnalysisMemory).where(AnalysisMemory.kind == "group")
    conds = []
    if fingerprint:
        conds.append(AnalysisMemory.fingerprint == fingerprint)
    if ip:
        conds.append(AnalysisMemory.ips.op("?|")([ip]))
    if asset_id:
        conds.append(AnalysisMemory.asset_ids.op("?|")([asset_id]))
    if conds:
        stmt = stmt.where(or_(*conds))
    window = days or settings.memory_persistence_days
    stmt = stmt.where(AnalysisMemory.created_at >= datetime.now(UTC) - timedelta(days=window))
    rows = db.scalars(stmt.order_by(AnalysisMemory.created_at.desc()).limit(limit)).all()
    return {
        "total": len(rows),
        "window_days": window,
        "persistent": len(rows) >= settings.memory_persistence_threshold,
        "items": [_memory_dict(m) for m in rows],
    }


@router.get("/persistent")
def persistent(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    days: int = Query(0, ge=0, le=365),
    limit: int = Query(10, ge=1, le=50),
):
    """按 IP 聚合最近出现次数，返回“持续性威胁”TOP（供驾驶舱）。"""
    window = days or settings.memory_persistence_days
    since = datetime.now(UTC) - timedelta(days=window)
    rows = db.scalars(
        select(AnalysisMemory)
        .where(AnalysisMemory.kind == "group", AnalysisMemory.created_at >= since)
        .order_by(AnalysisMemory.created_at.desc())
        .limit(5000)
    ).all()
    counts: dict[str, dict[str, Any]] = {}
    for m in rows:
        ts = m.created_at.isoformat() if m.created_at else None
        for ip in m.ips or []:
            entry = counts.setdefault(
                str(ip),
                {"ip": str(ip), "count": 0, "last_seen": None, "severities": {}},
            )
            entry["count"] += 1
            if ts and (entry["last_seen"] is None or ts > str(entry["last_seen"])):
                entry["last_seen"] = ts
            if m.severity:
                sev = entry["severities"]
                sev[m.severity] = sev.get(m.severity, 0) + 1
    items = sorted(counts.values(), key=lambda x: -x["count"])[:limit]
    return {
        "window_days": window,
        "threshold": settings.memory_persistence_threshold,
        "items": items,
    }


@router.post("/cleanup")
def do_cleanup(_: Annotated[User, Depends(get_current_user)]):
    return cleanup()
