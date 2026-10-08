"""中继节点清单（反向代理 / WAF / 内网 DNS 转发器）：**只读 PG，没有就是不认任何中继**。

为什么只放 PG（用户 2026-10 定的口径）：这份清单同时决定两件事 ——
1. **信不信代理头**（直连对端在清单里才认 XFF，落到 `real_client_ip`）；
2. **哪些跳要按中继去重**（`hop=front/back`，见 `normalizer` 与检测器的中继配对层）。
它是随网络环境变化的**数据**，该由运维在「监控网段」页随改随生效，不固化在部署环境变量里，
也不设环境变量兜底。

**fail-closed**：PG 里没有这份清单 = **认定网络里没有中继** —— 不信任任何代理头
（`real_client_ip` 恒空）、所有事件 `hop=direct`、不做配对与去重。

存储（`SystemConfig.zeek.relay_nodes`）：``{"value": "<清单文本>", "roles": {...}, "detected_at": ...}``
- `value`：IP 或 CIDR，逗号/换行分隔，`#` 注释行；
- `roles` / `detected_at`：**由检测器自动推算后回写**（本模块只读，不写）。
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

#: SystemConfig 键名（界面「监控网段」页维护）
KEY = "zeek.relay_nodes"
#: 清单缓存 TTL：逐条事件都会问「这个对端是不是中继」，必须缓存；写入时立即失效。
CACHE_TTL_SECONDS = 30.0

#: 侧向设置（界面三选）：auto = 按实测内容自动判，front/back = 强制保留客户端侧/源站侧。
SIDE_AUTO = "auto"
SIDE_FRONT = "front"
SIDE_BACK = "back"
SIDES: tuple[str, ...] = (SIDE_AUTO, SIDE_FRONT, SIDE_BACK)

#: 角色手工覆盖（与 sides 并列存在同一个键里）：auto = 按证据自动判，其余为运维定死。
ROLE_AUTO = "auto"
ROLE_PROXY = "proxy"
ROLE_DNS = "dns"
ROLE_BOTH = "both"
ROLES: tuple[str, ...] = (ROLE_AUTO, ROLE_PROXY, ROLE_DNS, ROLE_BOTH)

#: 上下级拓扑单独一个键：与清单/角色分开存，便于独立回滚。
TOPOLOGY_KEY = "zeek.relay_topology"
#: 非法项的告警次数上限（清单是安全边界配置，写错要看得见，但不能刷爆日志）
_MAX_WARNINGS = 5

_Net = ipaddress.IPv4Network | ipaddress.IPv6Network

_lock = threading.Lock()
_cache: dict[str, Any] = {
    "at": 0.0,
    "text": "",
    "nets": (),
    "roles": {},
    "sides": {},
    "role_overrides": {},
    "detected_at": "",
}
_warnings = 0

#: 拓扑单独的缓存（它写得没角色那么勤，读得更少）
_topo_lock = threading.Lock()
_topo_cache: dict[str, Any] = {"at": 0.0, "data": {}}


def parse(text: str) -> tuple[_Net, ...]:
    """把清单文本解析成网段集合。非法项丢弃并限量告警（不静默、不整体失败）。"""
    global _warnings
    nets: list[_Net] = []
    for chunk in str(text or "").replace(",", "\n").splitlines():
        value = chunk.strip()
        if not value or value.startswith("#"):
            continue
        try:
            nets.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            if _warnings < _MAX_WARNINGS:
                _warnings += 1
                log.warning("中继清单里的项不是合法 IP/CIDR，已忽略：%s", value)
    return tuple(nets)


def _load() -> dict[str, Any]:
    """真去读库（不缓存）。读不到按「没有中继」处理，绝不让归一化挂掉。"""
    try:
        with SessionLocal() as db:
            row = db.get(SystemConfig, KEY)
            payload = dict((row.value or {}) if row is not None else {})
    except Exception as exc:  # noqa: BLE001
        log.warning("读取中继清单失败（按「没有中继」处理）: %s", exc)
        payload = {}
    text = str(payload.get("value") or "")
    roles = payload.get("roles") if isinstance(payload.get("roles"), dict) else {}
    sides = payload.get("sides") if isinstance(payload.get("sides"), dict) else {}
    overrides = (
        payload.get("role_overrides") if isinstance(payload.get("role_overrides"), dict) else {}
    )
    return {
        "text": text,
        "nets": parse(text),
        "roles": roles or {},
        "sides": sides or {},
        "role_overrides": overrides or {},
        "detected_at": str(payload.get("detected_at") or ""),
    }


def _snapshot() -> dict[str, Any]:
    now = time.monotonic()
    if now - float(_cache.get("at") or 0.0) > CACHE_TTL_SECONDS:
        fresh = _load()
        with _lock:
            _cache.update({**fresh, "at": now})
    return dict(_cache)


def invalidate() -> None:
    """清单写入后立即失效缓存（下一次读取就重新读库）。"""
    with _lock:
        _cache["at"] = 0.0


def raw_text() -> str:
    """清单原文（界面回显用）。"""
    return str(_snapshot().get("text") or "")


def networks() -> tuple[_Net, ...]:
    """清单解析后的网段集合（热路径用，带 30 秒缓存）。"""
    return tuple(_snapshot().get("nets") or ())


def roles() -> dict[str, Any]:
    """检测器自动推算的角色与证据计数（界面只读展示）。"""
    value = _snapshot().get("roles")
    return dict(value) if isinstance(value, dict) else {}


def sides() -> dict[str, str]:
    """运维为每台中继指定的「保留哪一侧」（`auto` / `front` / `back`）；键是清单里的地址。"""
    value = _snapshot().get("sides")
    return dict(value) if isinstance(value, dict) else {}


def side_override(ip: Any) -> str:
    """该中继的侧向设置：`auto`（默认，按实测内容自动判）/ `front` / `back`。"""
    return sides().get(str(ip or "").strip(), SIDE_AUTO)


def role_overrides() -> dict[str, str]:
    """运维为每台中继**手工指定**的角色（`auto` / `proxy` / `dns` / `both`）。"""
    value = _snapshot().get("role_overrides")
    return dict(value) if isinstance(value, dict) else {}


def role_override(ip: Any) -> str:
    """该中继的角色手工覆盖；`auto` = 按证据自动判（可清除）。"""
    return role_overrides().get(str(ip or "").strip(), ROLE_AUTO)


def detected_at() -> str:
    return str(_snapshot().get("detected_at") or "")


def configured() -> bool:
    """是否配了中继清单。False = 系统认定「网络里没有中继」（不认代理头、不做去重）。"""
    return bool(raw_text().strip())


def is_relay(ip: Any) -> bool:
    """这个地址是不是中继节点（直连对端可信 / 该跳需要按中继处理）。"""
    text = str(ip or "").strip()
    if not text:
        return False
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    return any(addr in net for net in networks())


# ---------- 写（界面维护 + 检测器回写角色） ----------


def validate(text: str) -> list[dict[str, str]]:
    """校验清单文本：每一项都必须是合法 IP 或 CIDR。返回字段错误清单（空 = 合法）。"""
    errors: list[dict[str, str]] = []
    for chunk in str(text or "").replace(",", "\n").splitlines():
        value = chunk.strip()
        if not value or value.startswith("#"):
            continue
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            errors.append({"field": "relay_nodes", "msg": f"不是合法 IP / CIDR：{value}"})
    return errors


def _payload(row: SystemConfig | None) -> dict[str, Any]:
    return dict((row.value or {}) if row is not None else {})


def save(db: Session, text: str) -> None:
    """保存清单文本（保留检测器回写的 roles / detected_at）。"""
    row = db.get(SystemConfig, KEY)
    if row is None:
        row = SystemConfig(key=KEY, value={})
        db.add(row)
    payload = _payload(row)
    payload["value"] = str(text or "")
    row.value = payload
    db.commit()
    invalidate()


def save_roles(db: Session, roles: dict[str, Any], *, detected_at_value: str) -> None:
    """检测器把自动推算的角色写回同一个键（**不覆盖** `value` 与 `sides`）。"""
    row = db.get(SystemConfig, KEY)
    if row is None:
        # 没有清单就没有推算对象；这里只建一个只带角色信息的行（value 为空）
        row = SystemConfig(key=KEY, value={})
        db.add(row)
    payload = _payload(row)
    payload["roles"] = roles
    payload["detected_at"] = detected_at_value
    row.value = payload
    db.commit()
    invalidate()


def validate_roles(mapping: dict[str, Any]) -> list[dict[str, str]]:
    """校验角色覆盖：键必须是清单内地址，值必须是 auto/proxy/dns/both。"""
    errors: list[dict[str, str]] = []
    for ip, role in dict(mapping or {}).items():
        if not is_relay(ip):
            errors.append({"field": "roles", "msg": f"{ip} 不在中继清单里"})
        if str(role) not in ROLES:
            errors.append({"field": "roles", "msg": f"{ip} 的取值只能是 auto/proxy/dns/both"})
    return errors


def save_role_overrides(db: Session, mapping: dict[str, Any]) -> None:
    """保存角色手工覆盖（**不覆盖**清单文本、检测器回写的 roles 与 sides）。"""
    row = db.get(SystemConfig, KEY)
    if row is None:
        row = SystemConfig(key=KEY, value={})
        db.add(row)
    payload = _payload(row)
    payload["role_overrides"] = {str(k): str(v) for k, v in dict(mapping or {}).items()}
    row.value = payload
    db.commit()
    invalidate()


# ---------- 上下级拓扑（单独键，检测器回写） ----------


def _load_topology() -> dict[str, Any]:
    try:
        with SessionLocal() as db:
            row = db.get(SystemConfig, TOPOLOGY_KEY)
            data = dict((row.value or {}) if row is not None else {})
    except Exception as exc:  # noqa: BLE001
        log.warning("读取中继拓扑失败（按空处理）: %s", exc)
        data = {}
    return data


def _topology_snapshot() -> dict[str, Any]:
    now = time.monotonic()
    if now - float(_topo_cache.get("at") or 0.0) > CACHE_TTL_SECONDS:
        fresh = _load_topology()
        with _topo_lock:
            _topo_cache["data"] = fresh
            _topo_cache["at"] = now
    return dict(_topo_cache.get("data") or {})


def invalidate_topology() -> None:
    with _topo_lock:
        _topo_cache["at"] = 0.0


def topology() -> dict[str, Any]:
    """中继上下级关系（检测器推算回写）：edges / levels / chains / 异常标记。"""
    return _topology_snapshot()


def save_topology(db: Session, data: dict[str, Any]) -> None:
    """写回拓扑（合并已在检测器里做完，这里只落库）。"""
    row = db.get(SystemConfig, TOPOLOGY_KEY)
    if row is None:
        row = SystemConfig(key=TOPOLOGY_KEY, value={})
        db.add(row)
    row.value = dict(data or {})
    db.commit()
    invalidate_topology()


def validate_sides(mapping: dict[str, Any]) -> list[dict[str, str]]:
    """校验侧向设置：键必须是清单内地址，值必须是 auto/front/back。"""
    errors: list[dict[str, str]] = []
    for ip, side in dict(mapping or {}).items():
        if not is_relay(ip):
            errors.append({"field": "sides", "msg": f"{ip} 不在中继清单里"})
        if str(side) not in SIDES:
            errors.append({"field": "sides", "msg": f"{ip} 的取值只能是 auto/front/back"})
    return errors


def save_sides(db: Session, mapping: dict[str, Any]) -> None:
    """保存侧向设置（**不覆盖**清单文本 `value` 与检测器回写的 `roles`）。"""
    row = db.get(SystemConfig, KEY)
    if row is None:
        row = SystemConfig(key=KEY, value={})
        db.add(row)
    payload = _payload(row)
    payload["sides"] = {str(k): str(v) for k, v in dict(mapping or {}).items()}
    row.value = payload
    db.commit()
    invalidate()


def apply_role_overrides(roles: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """把手工指定的角色叠加到检测器回写的角色上（**读时生效**）。

    为什么要读时叠加：角色是检测器按流量累计、每 `ST_RELAY_ROLE_DETECT_SECONDS`（默认 300 秒）
    回写一次 —— 运维在界面上指定完还要等一轮才能看到，体验很差。侧向本来就是读时生效的，
    角色也用同一口径。（侧向/清单的读取方有 30 秒缓存，所以最迟 30 秒生效。）
    """
    out = {str(ip): dict(info or {}) for ip, info in (roles or {}).items()}
    for ip, value in (overrides or {}).items():
        role = str(value or "")
        if role not in (ROLE_PROXY, ROLE_DNS, ROLE_BOTH) or ip not in out:
            continue
        out[ip]["roles"] = ["proxy", "dns"] if role == ROLE_BOTH else [role]
        out[ip]["role_source"] = "manual"
        out[ip]["role_reason"] = ""
    return out


def describe() -> dict[str, Any]:
    """给界面用的一份快照：清单原文、解析出的条目、角色推算结果、侧向设置、是否已配置。"""
    snap = _snapshot()
    nets = tuple(snap.get("nets") or ())
    return {
        "text": str(snap.get("text") or ""),
        "count": len(nets),
        # 单地址按纯 IP 展示（侧向设置的键就是它）；真正的网段条目按 CIDR 展示（侧向靠自动判）
        "nodes": [
            str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)
            for net in nets
        ],
        "configured": bool(str(snap.get("text") or "").strip()),
        "roles": apply_role_overrides(
            dict(snap.get("roles") or {}), dict(snap.get("role_overrides") or {})
        ),
        "sides": dict(snap.get("sides") or {}),
        "role_overrides": dict(snap.get("role_overrides") or {}),
        "topology": topology(),
        "detected_at": str(snap.get("detected_at") or ""),
    }
