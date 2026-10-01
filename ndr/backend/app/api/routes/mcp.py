"""MCP 服务管理：令牌（生成 / 吊销）、最近调用、智能体写回的结论、暴露的工具清单。

令牌只在这里生成：**明文返回一次**，刷新界面也再拿不到（库里只有哈希），忘了就吊销重建。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.config import settings
from app.db.base import get_db
from app.db.models import ConclusionRecord, User
from app.investigation import tools as es_tools
from app.mcp import auth as token_auth, calls, ndr_tools

router = APIRouter(prefix="/api/mcp", tags=["mcp"])


class TokenIn(BaseModel):
    name: str = ""


class TokenStateIn(BaseModel):
    enabled: bool = True


def _service_status() -> dict[str, Any]:
    """探活 MCP 容器（连不上不影响界面其它部分，只如实说明）。"""
    base = settings.mcp_public_url.rstrip("/")
    out: dict[str, Any] = {
        "url": f"{base}{settings.mcp_path}",
        "health_url": f"{base}/health",
        "reachable": False,
    }
    try:
        resp = httpx.get(f"{base}/health", timeout=2.0)
        out["status_code"] = resp.status_code
        out["reachable"] = resp.status_code == 200
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)[:200]
    return out


def _purge_expired(db: Session) -> int:
    """顺手清掉过保留期的结论（不另起定时任务）。"""
    days = max(1, settings.mcp_conclusion_retention_days)
    cutoff = datetime.now(UTC) - timedelta(days=days)
    result = db.execute(delete(ConclusionRecord).where(ConclusionRecord.updated_at < cutoff))
    db.commit()
    # rowcount 没声明在 Result 泛型上，但删除语句返回的游标一定有它
    return int(getattr(result, "rowcount", 0) or 0)


@router.get("/status")
def get_status(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """总览：服务是否在、有多少令牌、调用与结论统计。"""
    purged = _purge_expired(db)
    total = db.execute(select(func.count()).select_from(ConclusionRecord)).scalar_one()
    tools = sorted(es_tools.TOOLS) + sorted(ndr_tools.TOOLS)
    recent = calls.recent(limit=200)
    return {
        "service": _service_status(),
        "token_prefix": settings.mcp_token_prefix,
        "tokens": {
            "total": len(token_auth.list_tokens()),
            "enabled": sum(1 for t in token_auth.list_tokens() if t.get("enabled")),
        },
        "calls": {
            "kept": len(recent),
            "errors": sum(1 for c in recent if not c.get("ok")),
            "last_at": recent[0].get("time", "") if recent else "",
        },
        "conclusions": {"total": int(total), "purged_expired": purged},
        "tools": {"count": len(tools), "names": tools},
    }


@router.get("/tools")
def get_tools(_: Annotated[User, Depends(get_current_user)]) -> dict[str, Any]:
    """暴露给智能体的工具清单（含参数说明），排查「智能体为什么说没有这个能力」时看它。"""
    items: list[dict[str, Any]] = []
    for name, spec in {**es_tools.TOOLS, **ndr_tools.TOOLS}.items():
        items.append(
            {"name": name, "desc": spec.get("desc", ""), "params": spec.get("params") or {}}
        )
    return {"tools": sorted(items, key=lambda x: x["name"]), "count": len(items)}


@router.get("/tokens")
def list_tokens(_: Annotated[User, Depends(get_current_user)]) -> dict[str, Any]:
    """令牌列表（只有前缀与用量，永远不回明文与哈希）。"""
    return {"tokens": token_auth.list_tokens()}


@router.post("/tokens")
def create_token(
    body: TokenIn,
    _: Annotated[User, Depends(get_current_user)],
) -> Any:
    """新建令牌：**明文只在这里返回一次**，请立刻填进智能体配置。"""
    token, token_id = token_auth.generate(body.name)
    return JSONResponse(
        {
            "id": token_id,
            "token": token,
            "note": "明文只显示这一次（库里只存哈希）。请立刻填入智能体配置；忘了就吊销重建。",
        }
    )


@router.post("/tokens/{token_id}/state")
def set_token_state(
    token_id: str,
    body: TokenStateIn,
    _: Annotated[User, Depends(get_current_user)],
) -> Any:
    """启用 / 吊销令牌（吊销立即生效，不需要重启任何服务）。"""
    if not token_auth.set_enabled(token_id, body.enabled):
        return JSONResponse({"error": "not_found", "detail": "令牌不存在"}, status_code=404)
    return {"ok": True, "enabled": body.enabled}


@router.delete("/tokens/{token_id}")
def delete_token(token_id: str, _: Annotated[User, Depends(get_current_user)]) -> Any:
    """删除令牌（仅用于建错了、从未用过的；已用过的请用吊销，保留调用追溯）。"""
    if not token_auth.delete_token(token_id):
        return JSONResponse({"error": "not_found", "detail": "令牌不存在"}, status_code=404)
    return {"ok": True}


@router.get("/calls")
def list_calls(
    _: Annotated[User, Depends(get_current_user)],
    limit: int = 50,
) -> dict[str, Any]:
    """最近的 MCP 调用（工具、令牌、耗时、成败、参数摘录）。"""
    return {"calls": calls.recent(limit=limit)}


@router.delete("/calls")
def clear_calls(_: Annotated[User, Depends(get_current_user)]) -> dict[str, Any]:
    calls.clear()
    return {"ok": True}


@router.get("/conclusions")
def list_conclusions(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    limit: int = 50,
) -> dict[str, Any]:
    """智能体写回的结论（最近更新在前）。"""
    purged = _purge_expired(db)
    rows = (
        db.execute(
            select(ConclusionRecord)
            .order_by(ConclusionRecord.updated_at.desc())
            .limit(max(1, min(limit, settings.mcp_max_rows)))
        )
        .scalars()
        .all()
    )
    return {
        "conclusions": [
            {
                "id": str(r.id),
                "event_id": r.event_id,
                "fingerprint": r.fingerprint,
                "thread_id": r.thread_id,
                "status": r.status,
                "severity": r.severity,
                "summary": r.summary,
                "detail": r.detail or {},
                "created_at": r.created_at.isoformat() if r.created_at else "",
                "updated_at": r.updated_at.isoformat() if r.updated_at else "",
            }
            for r in rows
        ],
        "purged_expired": purged,
    }
