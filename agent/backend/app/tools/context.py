"""工具输入上下文：从事件组聚合出的字段，供各工具确定性消费。"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field


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
