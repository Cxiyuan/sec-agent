"""局域网 IP 判定。"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

from app.config import settings

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@lru_cache
def _networks() -> tuple[IPNetwork, ...]:
    nets: list[IPNetwork] = []
    for cidr in settings.lan_cidrs.split(","):
        cidr = cidr.strip()
        if not cidr:
            continue
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return tuple(nets)


def is_lan_ip(ip: str | None) -> bool:
    """判断是否属于配置的局域网网段（默认 RFC1918）。"""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _networks())


def lan_networks() -> tuple[IPNetwork, ...]:
    """当前配置的局域网网段（供录入校验使用）。"""
    return _networks()
