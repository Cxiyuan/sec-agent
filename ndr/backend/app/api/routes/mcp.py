"""MCP 服务管理：令牌（生成 / 轮换 / 到期 / 吊销）、最近调用、智能体写回的结论、工具清单。

令牌只在这里生成：**明文返回一次**，刷新界面也再拿不到（库里只有哈希），忘了就轮换或吊销重建。

到期时间（`mcp_tokens.expires_at`，空 = 永不过期）由这里设置；**真正拒绝过期令牌的地方是
`app/mcp/auth.py` 的 `verify()`**（D 组），本文件只负责写库与展示。
"""

from __future__ import annotations

import secrets
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
from app.db.models import ConclusionRecord, McpToken, User
from app.investigation import tools as es_tools
from app.mcp import auth as token_auth, calls, ndr_tools

router = APIRouter(prefix="/api/mcp", tags=["mcp"])

#: 令牌有效期上限（天）。定成 10 年是「永久」的实用等价物，同时挡住误填的巨大数字。
MAX_TOKEN_DAYS = 3650


class TokenIn(BaseModel):
    name: str = ""
    #: 多少天后过期；不传 = 永不过期（与既有令牌语义一致）
    expires_in_days: int | None = None


class TokenExpiryIn(BaseModel):
    #: 新的有效期天数；显式传 null = 清除到期时间（永不过期）
    expires_in_days: int | None = None


class TokenStateIn(BaseModel):
    enabled: bool = True


def _bad_days(days: int | None) -> bool:
    return days is not None and not 1 <= days <= MAX_TOKEN_DAYS


def _expires_at(days: int) -> datetime:
    return datetime.now(UTC) + timedelta(days=days)


def _with_expiry(db: Session, tokens: list[dict[str, object]]) -> list[dict[str, object]]:
    """把 `expires_at` / `expired` 并进 `token_auth.list_tokens()` 的结果。

    D 组的 `list_tokens()` 不返回到期列（它只管生成/校验），这里补上，界面才画得出
    「还有几天过期」。查不到的（刚被别处删掉）按永不过期展示。
    """
    ids = [str(t.get("id") or "") for t in tokens]
    if not ids:
        return tokens
    rows = db.execute(select(McpToken.id, McpToken.expires_at).where(McpToken.id.in_(ids))).all()
    expiry: dict[str, datetime | None] = {str(rid): exp for rid, exp in rows}
    now = datetime.now(UTC)
    for item in tokens:
        exp = expiry.get(str(item.get("id") or ""))
        item["expires_at"] = exp.isoformat() if exp else ""
        item["expired"] = bool(exp is not None and exp <= now)
    return tokens


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
    # 令牌列表取一次：原来这里连调两次 list_tokens()（一次数总数、一次数启用），
    # 中间恰好吊销/新建就会自相矛盾。
    tokens = _with_expiry(db, token_auth.list_tokens())
    return {
        "service": _service_status(),
        "token_prefix": settings.mcp_token_prefix,
        "tokens": {
            "total": len(tokens),
            "enabled": sum(1 for t in tokens if t.get("enabled")),
            "expired": sum(1 for t in tokens if t.get("expired")),
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
def list_tokens(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """令牌列表（只有前缀、用量与到期时间，永远不回明文与哈希）。"""
    return {"tokens": _with_expiry(db, token_auth.list_tokens())}


@router.post("/tokens")
def create_token(
    body: TokenIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> Any:
    """新建令牌：**明文只在这里返回一次**，请立刻填进智能体配置。

    `expires_in_days` 可选：不传 = 永不过期（默认，与既有令牌一致）。
    """
    if _bad_days(body.expires_in_days):
        return JSONResponse(
            {"error": "bad_expires", "detail": f"expires_in_days 取值范围 1~{MAX_TOKEN_DAYS}"},
            status_code=400,
        )
    token, token_id = token_auth.generate(body.name)
    expires = _expires_at(body.expires_in_days) if body.expires_in_days else None
    if expires is not None:
        row = db.get(McpToken, token_id)
        if row is not None:
            row.expires_at = expires
            db.commit()
    return JSONResponse(
        {
            "id": token_id,
            "token": token,
            "expires_at": expires.isoformat() if expires else "",
            "note": "明文只显示这一次（库里只存哈希）。请立刻填入智能体配置；忘了就轮换。",
        }
    )


def _rotate_secret(db: Session, token_id: str) -> str | None:
    """原地换一个全新明文；返回 None 表示令牌不存在。

    复用 `app/mcp/auth.py` 的 `_hash`（那里是唯一的哈希实现，两处各写一遍 sha256 迟早漂移）。
    明文格式与 `token_auth.generate()` 保持一致：`{mcp_token_prefix}{token_urlsafe(32)}`。
    """
    row = db.get(McpToken, token_id)
    if row is None:
        return None
    token = f"{settings.mcp_token_prefix}{secrets.token_urlsafe(32)}"
    body = token[len(settings.mcp_token_prefix) :]
    row.token_hash = token_auth._hash(token)
    row.prefix = body[:8]
    db.commit()
    return token


@router.post("/tokens/{token_id}/rotate")
def rotate_token(
    token_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> Any:
    """原地轮换：同一令牌换一个全新明文，**旧明文立即失效**（verify() 每次查库）。

    名称、调用次数、启用状态与到期时间都保留 —— 换密钥不该丢掉它在界面上的历史。
    """
    token = _rotate_secret(db, token_id)
    if token is None:
        return JSONResponse({"error": "not_found", "detail": "令牌不存在"}, status_code=404)
    return JSONResponse(
        {
            "id": token_id,
            "token": token,
            "note": "明文只显示这一次；旧明文已立即失效，请同步更新智能体配置。",
        }
    )


@router.post("/tokens/{token_id}/expiry")
def set_token_expiry(
    token_id: str,
    body: TokenExpiryIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> Any:
    """设置或清除到期时间（`expires_in_days: null` = 永不过期）。

    只写库：拒绝过期令牌是 `app/mcp/auth.py` 的 `verify()` 的职责（D 组）。
    """
    if _bad_days(body.expires_in_days):
        return JSONResponse(
            {"error": "bad_expires", "detail": f"expires_in_days 取值范围 1~{MAX_TOKEN_DAYS}"},
            status_code=400,
        )
    row = db.get(McpToken, token_id)
    if row is None:
        return JSONResponse({"error": "not_found", "detail": "令牌不存在"}, status_code=404)
    expires = _expires_at(body.expires_in_days) if body.expires_in_days else None
    row.expires_at = expires
    db.commit()
    return {
        "ok": True,
        "expires_at": expires.isoformat() if expires else "",
    }


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
