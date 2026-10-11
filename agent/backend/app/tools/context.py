"""工具输入上下文：从事件组聚合出的字段，供各工具确定性消费。"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field

#: 监控网段缓存：规则热路径每条事件都要判，不能每次都去读库
_NETS_TTL_SECONDS = 30.0
_nets_lock = __import__("threading").Lock()
_nets_at = 0.0
_nets_cache: list[object] = []


@dataclass
class ToolContext:
    """从事件组聚合的输入。字段均为只读聚合结果，工具不得依赖具体事件结构。"""

    src_ips: list[str] = field(default_factory=list)
    dst_ips: list[str] = field(default_factory=list)
    external_ips: list[str] = field(default_factory=list)  # 公网 IP（供情报查询）
    text: str = ""  # 拼接的 summary/uri/body/query，供 IOC 提取
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    query_strings: list[str] = field(default_factory=list)
    bodies: list[str] = field(default_factory=list)
    scope_cidrs: list[str] = field(default_factory=list)


def is_public_ip(ip: str) -> bool:
    """是否公网 IP（排除私有/回环/链路本地/保留段）。"""
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return bool(addr.is_global)


def _monitored_networks() -> list[object]:
    """当前监控网段（带 30 秒缓存）。清单来源与 NDR 侧、采集器、检测器同源。"""
    global _nets_at, _nets_cache
    now = time.monotonic()
    with _nets_lock:
        if now - _nets_at < _NETS_TTL_SECONDS:
            return _nets_cache
    texts: list[str] = []
    try:
        # agent 栈的 scope 模块只暴露 enabled_cidrs（与 NDR 侧 monitored_nets 同一份配置）
        from app.ingestion.scope import enabled_cidrs

        texts = list(enabled_cidrs())
    except Exception as exc:  # noqa: BLE001 — 取不到就回落
        import logging

        logging.getLogger(__name__).debug("读监控网段失败，改用环境变量回落: %s", exc)
        texts = []
    if not texts:
        try:
            from app.config import settings

            raw = str(getattr(settings, "zeek_monitored_nets", "") or "")
            texts = [x.strip() for x in raw.replace(",", "\n").splitlines() if x.strip()]
        except Exception:  # noqa: BLE001
            texts = []
    nets: list[object] = []
    for text in texts:
        try:
            nets.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            continue
    with _nets_lock:
        _nets_at, _nets_cache = now, nets
    return nets


def is_internal_ip(ip: str) -> bool:
    """是否**属于我们监控的网段**（配了网段时以网段为准，否则回落到「非公网即内网」）。

    口径与 Zeek 的 `Site::local_nets`（`local_orig`/`local_resp`）、采集 BPF、检测器 scope
    同源。不能只看「非公网」：客户端私网段很宽（10/8、172.16/12），而监控网段只是其中一小段，
    实测有 13% 的侧判定分歧（详见 NDR 侧 `app/iputil.py` 文件头的对账表）。
    """
    value = str(ip or "").strip()
    if not value:
        return False
    nets = _monitored_networks()
    if not nets:
        return not is_public_ip(value)
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(addr in net for net in nets)  # type: ignore[operator]
