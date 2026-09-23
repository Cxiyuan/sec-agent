"""本地计算工具：IOC 提取 / 编码解码 / 指纹 hash。无外部依赖、始终可用。"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any
from urllib.parse import unquote, unquote_plus

from app.tools.context import ToolContext

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE
)
_URL_RE = re.compile(r"https?://[^\s\"'<>()]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}\b", re.IGNORECASE)
# 恶意样本哈希常见三种长度：64=sha256 / 40=sha1 / 32=md5（只做提取，不参与生成）
_HASH_RES = [
    re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE),
    re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE),
    re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE),
]


def _dedup(items: list[str], limit: int = 50) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        k = x.lower()
        if k not in seen:
            seen.add(k)
            out.append(x)
            if len(out) >= limit:
                break
    return out


def _try_b64decode(s: str) -> str | None:
    """尝试 base64 解码为文本；非法输入或解码出非文本（非合法 UTF-8）返回 None。"""
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=False)
    except ValueError:
        return None
    try:
        txt = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None  # 解码出二进制/垃圾，不是我们要的文本 payload
    if not txt.strip():
        return None
    # 过滤控制字符（保留常见空白）
    if any(ord(c) < 32 and c not in "\n\t\r" for c in txt):
        return None
    return txt[:500]


def ioc_extract(ctx: ToolContext) -> dict[str, Any]:
    """从事件组文本提取 IOC（IP/域名/URL/邮箱/hash）。"""
    text = ctx.text or ""
    hashes: list[str] = []
    for pat in _HASH_RES:
        hashes.extend(pat.findall(text))
    return {
        "ips": _dedup(_IPV4_RE.findall(text)),
        "domains": _dedup(_DOMAIN_RE.findall(text)),
        "urls": _dedup(_URL_RE.findall(text)),
        "emails": _dedup(_EMAIL_RE.findall(text), 20),
        "hashes": _dedup(hashes),
    }


def url_decode(ctx: ToolContext) -> dict[str, Any]:
    """对 query/body 做 URL 与 base64 解码去混淆（攻击者常用编码绕过检测）。"""
    samples = (ctx.query_strings or []) + (ctx.bodies or [])
    decoded: list[str] = []
    for s in samples[:10]:
        if not s:
            continue
        for dec in (unquote, unquote_plus):
            d = dec(s)
            if d != s and d not in decoded:
                decoded.append(d[:500])
        b64 = _try_b64decode(s)
        if b64 and b64 not in decoded:
            decoded.append(b64)
    return {"decoded": decoded[:20]}


def hash_calc(ctx: ToolContext) -> dict[str, Any]:
    """对事件组文本计算内容指纹（供报告/跨窗口关联）。只用 SHA256。"""
    data = (ctx.text or "")[:10000].encode("utf-8", errors="replace")
    return {"sha256": hashlib.sha256(data).hexdigest()}
