"""认证路由：登录、登出、当前账号、改密。

令牌是**无状态 JWT**（见 `app/api/deps.py`）：服务端不保存会话，所以 `/logout` 只是让
前端丢弃本地令牌的显式语义；服务端唯一的失效手段是改 JWT 密钥（会让所有令牌一起失效）。
改密后旧令牌同样**仍然有效到过期**（默认 12 小时）——要立刻踢掉旧令牌得换 `ST_JWT_SECRET`，
这条限制写在这里而不是假装已经做到。
"""

from __future__ import annotations

import threading
import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import (
    create_token,
    get_current_user,
    hash_password,
    is_factory_password_hash,
    verify_password,
)
from app.config import FACTORY_ADMIN_PASSWORD, settings
from app.db.base import get_db
from app.db.models import User

router = APIRouter(prefix="/api/auth", tags=["auth"])

#: 新口令长度下限/上限（长度是唯一能强制、也最有性价比的口令策略）。
PASSWORD_MIN_CHARS = 8
PASSWORD_MAX_CHARS = 128

#: 登录失败限速：同一「来源 IP + 用户名」在窗口内失败这么多次就拒登一段时间。
#: 计数在**进程内**（当前部署是单进程 uvicorn；多 worker 时每个 worker 各算一份，
#: 挡住的仍然是最常见的脚本爆破）。目的只是防爆破，不做账号锁定 —— 锁定会被用来
#: 拿别人的用户名做拒绝服务。
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 60.0

_login_failures: dict[str, list[float]] = {}
_login_lock = threading.Lock()


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class PasswordIn(BaseModel):
    old_password: str
    new_password: str


def _client_key(request: Request, username: str) -> str:
    host = request.client.host if request.client else "unknown"
    return f"{host}|{username.strip().lower()}"


def _failure_times(key: str, now: float) -> list[float]:
    """窗口内还没过期的失败时刻（顺手丢掉过期项，字典不会无限长）。"""
    kept = [t for t in _login_failures.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
    if kept:
        _login_failures[key] = kept
    else:
        _login_failures.pop(key, None)
    return kept


def _login_blocked(key: str) -> int:
    """被限速时返回还要等几秒，否则 0。"""
    now = time.monotonic()
    with _login_lock:
        times = _failure_times(key, now)
        if len(times) < LOGIN_MAX_FAILURES:
            return 0
        return max(1, int(LOGIN_WINDOW_SECONDS - (now - min(times))) + 1)


def _record_login_failure(key: str) -> None:
    now = time.monotonic()
    with _login_lock:
        times = _failure_times(key, now)
        times.append(now)
        _login_failures[key] = times


def _clear_login_failures(key: str) -> None:
    with _login_lock:
        _login_failures.pop(key, None)


@router.post("/login", response_model=TokenResponse)
def login(
    request: Request,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[Session, Depends(get_db)],
):
    key = _client_key(request, form.username)
    wait = _login_blocked(key)
    if wait:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"登录失败次数过多，请 {wait} 秒后再试",
            headers={"Retry-After": str(wait)},
        )
    user = db.execute(select(User).where(User.username == form.username)).scalar_one_or_none()
    if user is None or not verify_password(form.password, user.password_hash):
        _record_login_failure(key)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户名或密码错误")
    _clear_login_failures(key)
    return TokenResponse(access_token=create_token(user.username))


@router.get("/me")
def me(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """当前账号状态。`default_password_in_use` 供界面提示「还在用出厂口令，请改密」。"""
    in_use = is_factory_password_hash(user.password_hash)
    return {
        "username": user.username,
        "role": user.role,
        "default_password_in_use": in_use,
        "password_min_chars": PASSWORD_MIN_CHARS,
        "note": (
            "默认管理员口令（出厂值）仍在使用，请立刻修改：POST /api/auth/change-password"
            if in_use
            else ""
        ),
    }


@router.post("/change-password")
def change_password(
    body: PasswordIn,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """改自己的口令：校验旧口令 + 新口令长度/不同，写库。

    **不要求**先改默认口令才让用系统（避免锁死现网），但默认口令在用时会由启动日志与
    `/api/auth/me` 一直提示。
    """
    if not verify_password(body.old_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="原密码不正确")
    new = body.new_password
    if len(new) < PASSWORD_MIN_CHARS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"新密码至少 {PASSWORD_MIN_CHARS} 个字符",
        )
    if len(new) > PASSWORD_MAX_CHARS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"新密码最多 {PASSWORD_MAX_CHARS} 个字符",
        )
    if new == body.old_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="新密码不能与原密码相同"
        )
    if new == FACTORY_ADMIN_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="新密码不能是出厂默认口令",
        )
    user.password_hash = hash_password(new)
    db.commit()
    return {
        "ok": True,
        "default_password_in_use": False,
        "note": (
            "已更新口令。令牌是无状态 JWT：已签发的旧令牌仍然有效到各自过期时间"
            f"（{int(settings.jwt_expire_minutes)} 分钟），要立刻全部失效请更换 ST_JWT_SECRET。"
        ),
    }


@router.post("/logout")
def logout(_: Annotated[User, Depends(get_current_user)]) -> dict[str, Any]:
    """登出（无状态令牌：服务端没有会话可销毁，语义 = 前端丢弃本地令牌）。"""
    return {
        "ok": True,
        "note": "令牌是无状态 JWT，服务端不保存会话；请前端删除本地令牌即完成登出。",
    }
