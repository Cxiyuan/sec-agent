"""MCP 令牌：生成、校验、吊销（库里只存哈希）。

明文**只在生成那一刻**返回一次，之后谁都拿不回来 —— 这是有意的取舍：库被读走也
换不出可用令牌。代价是忘了只能吊销重建，所以额外存了明文前 8 位（`prefix`）供
界面辨认到底是哪一个。
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select

from app.config import settings
from app.db.base import SessionLocal
from app.db.models import McpToken


@dataclass(frozen=True)
class TokenInfo:
    """校验通过后交给调用方的最小信息（不返回 ORM 对象，避免会话关闭后失效）。"""

    id: str
    name: str
    prefix: str


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate(name: str) -> tuple[str, str]:
    """建一个新令牌，返回 `(明文, id)`。明文只出现这一次。"""
    token = f"{settings.mcp_token_prefix}{secrets.token_urlsafe(32)}"
    body = token[len(settings.mcp_token_prefix) :]
    row = McpToken(name=(name or "").strip()[:128], token_hash=_hash(token), prefix=body[:8])
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        return token, str(row.id)


def verify(token: str) -> TokenInfo | None:
    """校验 Bearer 令牌，顺带累加调用计数与最近使用时间。

    **每次都查库、不缓存**：这样界面上一吊销就立刻调不通。单次调查的工具调用量很小
    （几十次），多一次按主键索引的查询不值得为它引入缓存失效的坑。
    """
    token = (token or "").strip()
    if not token:
        return None
    with SessionLocal() as db:
        row = db.execute(
            select(McpToken).where(McpToken.token_hash == _hash(token))
        ).scalar_one_or_none()
        if row is None or not row.enabled:
            return None
        info = TokenInfo(id=str(row.id), name=row.name, prefix=row.prefix)
        row.call_count += 1
        row.last_used_at = datetime.now(UTC)
        db.commit()
        return info


def list_tokens() -> list[dict[str, object]]:
    """界面用：列出全部令牌（永远不回哈希与明文）。"""
    with SessionLocal() as db:
        rows = db.execute(select(McpToken).order_by(McpToken.created_at.desc())).scalars().all()
        return [
            {
                "id": str(r.id),
                "name": r.name,
                "prefix": r.prefix,
                "enabled": bool(r.enabled),
                "call_count": int(r.call_count or 0),
                "last_used_at": r.last_used_at.isoformat() if r.last_used_at else "",
                "created_at": r.created_at.isoformat() if r.created_at else "",
            }
            for r in rows
        ]


def set_enabled(token_id: str, enabled: bool) -> bool:
    """启用 / 吊销。不删行 —— 调用记录还要能追溯到它。"""
    with SessionLocal() as db:
        row = db.get(McpToken, token_id)
        if row is None:
            return False
        row.enabled = bool(enabled)
        db.commit()
        return True


def delete_token(token_id: str) -> bool:
    """彻底删除（仅用于建错了、从未用过的令牌）。"""
    with SessionLocal() as db:
        row = db.get(McpToken, token_id)
        if row is None:
            return False
        db.delete(row)
        db.commit()
        return True
