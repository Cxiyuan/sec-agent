"""契约辅助：内外网判定（与 agent 侧 app/tools/context.py 保持一致）。

两套口径，**不能混用**（2026-10 与 Zeek 原生日志对账后统一）：

- `is_public_ip(ip)`：是不是**公网地址**（RFC1918 / 回环 / 保留段之外）。用于「外联/情报」类判据。
- `is_internal_ip(ip)`：是不是**我们监控网段里的地址**。用于 `src_internal` / `dst_internal`
  这类「内外有别」判据（内网横向、内网服务枚举、内网利用探测…）。

为什么内网不能只看「非公网」（实测数据，地址已泛化）：客户端私网地址段很宽（10/8、172.16/12、
192.168/16），而监控网段往往只是其中一小段（现场是一个 /22 + 两个 /24）。拿 250 条 Zeek conn 与
Zeek 自带标记（`local_orig` / `local_resp`，由 `Site::local_nets` 算出，与采集 BPF、检测器 scope
过滤同源）对账，**64 次侧判定（约 13%）不一致**，全部是「我们把监控范围外的私网当成了内网」：

| 地址（举例） | 私有？ | 在监控网段内？ | 后果 |
|---|---|---|---|
| 监控网段内的主机 | 是 | 是 | 真内网 ✓ |
| `10.9.9.9`（另一个 10/8 子段） | 是 | **否** | 被当成「内网横向」→ 误报 |
| `172.16.5.5`（172.16/12 的别的子段） | 是 | **否** | 同上；按 `dst_internal` 写的降噪还会挡掉跨段流量 → 漏报 |
| `192.168.9.9` | 是 | **否** | 同上 |

网段清单来源与采集器/检测器严格同源：`app.ingestion.scope.monitored_nets()`
（`SystemConfig.zeek.monitored_nets`）；读不到时才回落到 `ST_ZEEK_MONITORED_NETS`。
**一条网段都没配**时回落到老行为「非公网即内网」（不凭空把地址判成外网）。
"""

from __future__ import annotations

import ipaddress
import threading
import time
from typing import Any

from app.workers.log import get_logger

log = get_logger(__name__)

#: 网段缓存：规则热路径每条事件都要判，不能每次都去读库
_CACHE_TTL_SECONDS = 30.0
_cache_lock = threading.Lock()
_cache_at: float = 0.0
_cache_nets: list[Any] = []
_cache_raw: tuple[str, ...] = ()


def is_public_ip(ip: str) -> bool:
    """是否公网 IP（排除私有/回环/链路本地/保留段）。"""
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return bool(addr.is_global)


def _net_texts() -> tuple[str, ...]:
    """当前监控网段清单（文本）。读库失败/未配置时返回空。"""
    try:
        from app.ingestion.scope import monitored_nets

        nets = tuple(monitored_nets())
        if nets:
            return nets
    except Exception as exc:  # noqa: BLE001 — 取不到就走回落口径，不影响判定主流程
        log.debug("读监控网段失败，改用环境变量回落: %s", exc)
    try:
        from app.config import settings

        raw = str(getattr(settings, "zeek_monitored_nets", "") or "")
        return tuple(x.strip() for x in raw.replace(",", "\n").splitlines() if x.strip())
    except Exception as exc:  # noqa: BLE001
        log.debug("读 ST_ZEEK_MONITORED_NETS 失败: %s", exc)
        return ()


def _networks() -> list[Any]:
    """解析后的监控网段（带 30 秒缓存；清单变化在 30 秒内生效）。"""
    global _cache_at, _cache_nets, _cache_raw
    now = time.monotonic()
    with _cache_lock:
        if now - _cache_at < _CACHE_TTL_SECONDS:
            return _cache_nets
    texts = _net_texts()
    nets: list[Any] = []
    for text in texts:
        try:
            nets.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            continue
    with _cache_lock:
        _cache_at, _cache_nets, _cache_raw = now, nets, texts
    return nets


def monitored_net_texts() -> tuple[str, ...]:
    """当前监控网段清单（给守卫测试与排查用）。"""
    _networks()
    return _cache_raw


def is_internal_ip(ip: str) -> bool:
    """是否**属于我们监控的网段**（配了网段时以网段为准，否则回落到「非公网即内网」）。"""
    value = str(ip or "").strip()
    if not value:
        return False
    nets = _networks()
    if not nets:
        return not is_public_ip(value)
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(addr in net for net in nets)
