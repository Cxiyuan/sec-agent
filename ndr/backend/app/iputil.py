"""契约辅助：内外网判定（与 agent 侧 app/tools/context.py 的 is_public_ip 保持一致）。"""

from __future__ import annotations

import ipaddress


def is_public_ip(ip: str) -> bool:
    """是否公网 IP（排除私有/回环/链路本地/保留段）。"""
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return bool(addr.is_global)
