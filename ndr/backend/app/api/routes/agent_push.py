"""智能体推送配置与状态（第 5 期）：地址、令牌、开关、连通性自检、待重发队列。

界面在「系统配置」页：配好智能体的接收地址（``http://<agent>:8000/api/push/digests``）
与令牌（与智能体侧 ``ST_PUSH_TOKEN`` 一致），点「测试连接」确认通，再打开开关。
没配地址时检测器仍走旧的 Redis 队列交接（升级期不会两头都断）。

状态里的数字来自 Redis（检测器进程写、跨重启可查），不依赖检测器存活：
``sent`` 推成功 / ``queued`` 推送失败已落重发队列 / ``retried`` 重发成功 /
``retry_failed`` 重发失败 / ``queue_depth`` 还在等重发的批数。
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.config import settings
from app.db.base import get_db
from app.db.models import SystemConfig, User
from app.detector import push
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/agent-push", tags=["agent-push"])

HINT = (
    "推送成功与否由 HTTP 2xx 判定：失败的批落在 NDR 的持久重试队列里，检测循环每轮自动重发；"
    "智能体侧按「事件组指纹 + 时间桶」判重，同一攻击重复推送只累加计数、不会出第二份报告"
)


class PushConfigIn(BaseModel):
    """保存配置。``token`` 传 null = 不修改（传空字符串 = 清空）。"""

    url: str = ""
    token: str | None = None
    enabled: bool = True
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=120.0)
    max_per_push: int = Field(default=200, ge=1, le=5000)


class PushTestIn(BaseModel):
    url: str | None = None
    token: str | None = None


def _client() -> Any | None:
    try:
        import redis

        return redis.Redis.from_url(settings.redis_url, decode_responses=True)
    except Exception as exc:  # noqa: BLE001
        log.warning("连接 Redis 失败（推送状态不可读）: %s", exc)
        return None


def _public(cfg: dict[str, Any]) -> dict[str, Any]:
    token = str(cfg.get("token") or "")
    return {
        "url": str(cfg.get("url") or ""),
        "token_set": bool(token),
        "token_masked": push.mask_token(token),
        "enabled": bool(cfg.get("enabled")),
        "timeout_seconds": float(cfg.get("timeout_seconds") or 10.0),
        "max_per_push": int(cfg.get("max_per_push") or 200),
        "active": push.is_on(cfg),
        "ping_url": push.ping_url(str(cfg.get("url") or "")),
    }


def _env_public() -> dict[str, Any]:
    env = push.env_defaults()
    return {
        "url": env["url"],
        "enabled": bool(env["enabled"]),
        "token_set": bool(env["token"]),
    }


def _payload(db: Session) -> dict[str, Any]:
    cfg = push.load_config(db)
    client = _client()
    return {
        "config": _public(cfg),
        "status": push.status(client) if client is not None else {"error": "Redis 不可用"},
        "env": _env_public(),
        "hint": HINT,
    }


@router.get("")
def get_agent_push(
    _: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, Any]:
    return _payload(db)


@router.put("")
def put_agent_push(
    payload: PushConfigIn,
    _: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, Any]:
    row = db.get(SystemConfig, push.CONFIG_KEY)
    raw = (row.value or {}).get("value") if row is not None else None
    stored: dict[str, Any] = dict(raw) if isinstance(raw, dict) else {}
    stored["url"] = payload.url.strip()
    stored["enabled"] = bool(payload.enabled)
    stored["timeout_seconds"] = float(payload.timeout_seconds)
    stored["max_per_push"] = int(payload.max_per_push)
    if payload.token is not None:
        stored["token"] = payload.token
    # token 为 null 且库里从未存过 → 不写这个键，继续用环境变量里的默认令牌
    saved = push.save_config(db, stored)
    log.info(
        "智能体推送配置已保存：url=%s 令牌=%s 开关=%s 生效=%s",
        saved["url"] or "(空)",
        "已设置" if saved["token"] else "未设置",
        saved["enabled"],
        push.is_on(saved),
    )
    return _payload(db)


@router.post("/test")
def test_agent_push(
    payload: PushTestIn,
    _: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, Any]:
    cfg = push.load_config(db)
    if payload.token is not None:
        cfg["token"] = payload.token
    url = str(payload.url or cfg.get("url") or "").strip()
    if not url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="还没填智能体推送地址（形如 http://agent:8000/api/push/digests）",
        )
    ok, detail = push.ping(cfg, url)
    return {"ok": ok, "url": push.ping_url(url), "detail": detail}


@router.post("/retry")
def retry_agent_push(
    _: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, Any]:
    """手动触发一次重发（界面上「立即重发」按钮）。"""
    client = _client()
    if client is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Redis 不可用")
    result = push.retry_pending(client, {}, limit=20)
    return {"result": result, **_payload(db)}
