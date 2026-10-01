"""监控网段：向 NDR 的 MCP 问「现在抓的是哪些网段」。

网段是 NDR 的**抓包配置**（后台「Zeek 抓包」面板写入，同时生成 Zeek 的 bpf 过滤条件），
智能体侧不再自己维护一份：以前本地表里的默认私网段与真实抓包范围可以完全不同，
回溯就会按错误的网段筛日志。

取不到清单时返回**空列表**——NDR 的语义是「清单为空 = 不过滤（抓全部）」，
所以空 = 不限制，而不是「什么都不查」。
"""

from __future__ import annotations

import time

from app.investigation.mcp_client import call
from app.workers.log import get_logger

log = get_logger(__name__)

# 进程内缓存：一次调查/回溯会问好几次，而网段一天也改不了一次
_CACHE_TTL = 60.0
_cache: tuple[float, list[str]] = (0.0, [])


def enabled_cidrs() -> list[str]:
    """NDR 当前的监控网段清单（IP/CIDR）；取不到时为 []（= 不限制）。"""
    global _cache
    now = time.monotonic()
    if _cache[0] and now - _cache[0] < _CACHE_TTL:
        return list(_cache[1])

    resp = call("list_networks", {})
    nets = resp.get("networks")
    if not isinstance(nets, list):
        log.warning("向 NDR 取监控网段失败（按不限制处理）: %s", resp.get("error") or resp)
        return []

    seen: set[str] = set()
    out: list[str] = []
    for item in nets:
        value = str(item).strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    _cache = (now, out)
    return list(out)
