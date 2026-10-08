"""拓扑节点别名：给 IP 起的显示名（运维在「拓扑发现」页点节点编辑）。

为什么单独存一份、而不是复用中继清单里的名字：别名是**纯展示层**的东西，任何出现在图上的
地址都能起名（客户端、源站、中继都行），跟"是不是中继"无关。它改起来要立即生效，也不能
让中继去重/代理头信任这些**安全语义**跟着受一点影响 —— 所以独立键、独立缓存、只读展示。

存储（`SystemConfig.topology.node_aliases`）：``{"aliases": {"<ip>": "<名字>"}}``
- 空名字 = 删除该别名（界面清空即还原成 IP）；
- 只接受合法 IP 作为键（图上的节点就是 IP，故不认域名）。

**fail-open**：读库失败按「没有别名」处理，绝不因为别名问题让拓扑页打不开 —— 别名只是好看，
显示名退化成 IP 即可，真实 IP 永远是准的。
"""

from __future__ import annotations

import ipaddress
import threading
import time
from typing import Any

from sqlalchemy.orm import Session

from app.db.base import SessionLocal
from app.db.models import SystemConfig
from app.workers.log import get_logger

log = get_logger(__name__)

#: SystemConfig 键名
KEY = "topology.node_aliases"
#: 别名缓存 TTL（秒）：拓扑页与其它页面都会问「这个 IP 叫什么」，缓存住免得每处都读库。
CACHE_TTL_SECONDS = 30.0
#: 名字长度上限（太长的名字会把图上的节点撑爆，也超出面板标题的合理范围）
MAX_NAME = 64

_lock = threading.Lock()
_cache: dict[str, Any] = {"at": 0.0, "aliases": {}}


def _clean(text: Any) -> str:
    return str(text or "").strip()


def _load() -> dict[str, str]:
    """真去读库（不缓存）。读不到按「没有别名」处理。"""
    try:
        with SessionLocal() as db:
            row = db.get(SystemConfig, KEY)
            payload = dict((row.value or {}) if row is not None else {})
    except Exception as exc:  # noqa: BLE001
        log.warning("读取拓扑别名失败（按「没有别名」处理）: %s", exc)
        payload = {}
    raw = payload.get("aliases")
    if not isinstance(raw, dict):
        raw = {}
    out: dict[str, str] = {}
    for ip, name in raw.items():
        value = _clean(name)
        if value:
            out[str(ip)] = value[:MAX_NAME]
    return out


def snapshot() -> dict[str, str]:
    """当前别名表（带 TTL 缓存）。"""
    now = time.monotonic()
    if now - float(_cache.get("at") or 0.0) > CACHE_TTL_SECONDS:
        fresh = _load()
        with _lock:
            _cache["aliases"] = fresh
            _cache["at"] = now
    return dict(_cache.get("aliases") or {})


def invalidate() -> None:
    """写入后立即失效缓存（下一次读取就重新读库）。"""
    with _lock:
        _cache["at"] = 0.0


def get(ip: Any) -> str:
    """这个 IP 的别名；没起过名字返回空串。"""
    return snapshot().get(_clean(ip), "")


def validate_name(name: Any) -> str:
    """校验名字；返回错误说明（空串 = 合法）。"""
    value = _clean(name)
    if len(value) > MAX_NAME:
        return f"名字不能超过 {MAX_NAME} 个字符"
    return ""


def validate_ip(ip: Any) -> str:
    """校验键是不是合法 IP；返回错误说明（空串 = 合法）。"""
    try:
        ipaddress.ip_address(_clean(ip))
    except ValueError:
        return f"不是合法 IP：{_clean(ip) or '(空)'}"
    return ""


def set_alias(db: Session, ip: str, name: str) -> dict[str, str]:
    """给一个 IP 起名（空名字 = 删除）。返回最新的完整别名表。"""
    key = _clean(ip)
    row = db.get(SystemConfig, KEY)
    if row is None:
        row = SystemConfig(key=KEY, value={})
        db.add(row)
    payload = dict(row.value or {})
    mapping = dict(payload.get("aliases") or {})
    value = _clean(name)[:MAX_NAME]
    if value:
        mapping[key] = value
    else:
        mapping.pop(key, None)
    payload["aliases"] = mapping
    row.value = payload
    db.commit()
    invalidate()
    return snapshot()


def describe() -> dict[str, Any]:
    """给界面用的一份快照（键就是别名表本身）。"""
    aliases = snapshot()
    return {"aliases": aliases, "count": len(aliases)}
