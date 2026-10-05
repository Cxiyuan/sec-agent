"""中继角色自动推算 + 两侧「内容」统计：清单里的每个地址是「反向代理 / WAF」还是
「内网 DNS 转发器」，以及它的**哪一侧带明文请求内容**。

为什么要推算（用户 2026-10 的口径）：中继清单只有一份地址清单，但两类角色的去重方式不同 ——
反代靠代理头配前后跳，DNS 转发靠「客户端跳 vs 转发跳」配。让运维在界面再填一遍角色既重复
又容易漏，所以由系统**按实际流量自动判断**，只读展示在界面上供核对。

判定（只看当前清单内的地址，stateless 口径）：
- 该地址在 **http/ssl** 事件里出现（作 src 或 dst）→ `proxy` 证据 +1（WAF/反代处理的就是这两类）
- 该地址在 **dns** 事件里出现 → `dns` 证据 +1
- 其余类型（conn/files/…）不提供证据：conn 覆盖所有流量，判不出角色

**两侧内容统计（2026-10 实机实测新增）**：去重要问的头号问题是「该保留哪一侧」。
实测本环境的 WAF：客户端侧那一跳是 **TLS 且无 SNI**（44,623 条 ssl 里 SNI 0 条、http 只有 9 条），
而源站侧那一跳是**明文 HTTP**（28,557 行 http，带 Host/URI/请求体，XFF 里 438 个真实客户端）——
两侧内容比 9 : 28,557。所以判据必须看「哪一侧有内容」，不能看跳的名字。

位置：**检测器**（持锁实例逐条看到全部在范围事件），累计只走内存，不额外扫库；
每 `ST_RELAY_ROLE_DETECT_SECONDS`（默认 300s）把计数与时间写回 PG 同一个键（**不覆盖清单**）。
清单变更（指纹变化）时计数清零 —— 旧地址的残留证据没有意义。
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from app.config import settings
from app.db.base import SessionLocal
from app.ingestion import relay_nodes
from app.schemas import UnifiedLog
from app.workers.log import get_logger

log = get_logger(__name__)

#: 日志类型 → 角色证据。http/ssl 归「反代/WAF」；dns 归「内网 DNS 转发器」。
_ROLE_BY_LOG_TYPE: dict[str, str] = {
    "http": "proxy",
    "ssl": "proxy",
    "dns": "dns",
}
ROLE_LABELS: dict[str, str] = {"proxy": "反向代理", "dns": "DNS 转发"}

#: 算「内容」的日志类型：有请求语义的**明文**日志（规则/画像/资产真正要读的东西）。
#: **不含 ssl** —— 加密流量里读不到 Host/URI/body（无 SNI 的 ssl 只是一次握手）。
CONTENT_LOG_TYPES: frozenset[str] = frozenset({"http", "http2", "smtp", "dns"})

#: 侧向：保留客户端侧 / 源站侧
SIDE_FRONT = relay_nodes.SIDE_FRONT
SIDE_BACK = relay_nodes.SIDE_BACK


def auto_side(front: int, back: int) -> str:
    """按两侧的内容条数判该保留哪一侧（默认保留客户端侧 = 历史行为）。

    阈值刻意保守（`ST_RELAY_SIDE_MIN` / `ST_RELAY_SIDE_RATIO`）：数据要足够悬殊才翻，
    否则偶发的健康检查/扫描会把侧向带偏。
    """
    minimum = max(1, int(settings.relay_side_min))
    ratio = max(1, int(settings.relay_side_ratio))
    if back >= minimum and back >= ratio * max(1, front):
        return SIDE_BACK
    if front >= minimum and front >= ratio * max(1, back):
        return SIDE_FRONT
    return SIDE_FRONT


class RelayRoleDetector:
    """累计中继角色证据并周期回写 PG（进程内计数，单写者）。"""

    def __init__(self) -> None:
        self._counts: dict[str, dict[str, int]] = {}
        # 两侧的「内容」条数：{ip: {"front": n, "back": n}}；front = 该地址作目的地
        self._content: dict[str, dict[str, int]] = {}
        self._signature = ""
        self._last_flush = 0.0

    def observe(self, entry: UnifiedLog) -> None:
        """逐条事件累计证据（只对清单内的地址算）。"""
        log_type = str(entry.log_type or "")
        if log_type in CONTENT_LOG_TYPES:
            self._count_content(entry)
        role = _ROLE_BY_LOG_TYPE.get(log_type)
        if role is None:
            return
        for ip in (entry.src_ip, entry.dst_ip):
            if ip and relay_nodes.is_relay(ip):
                counts = self._counts.setdefault(str(ip), {})
                counts[role] = counts.get(role, 0) + 1

    def _count_content(self, entry: UnifiedLog) -> None:
        """记「哪一侧带明文请求内容」：目的地是中继 → 客户端侧；来源是中继 → 源站侧。"""
        for ip, side in ((entry.dst_ip, "front"), (entry.src_ip, "back")):
            if ip and relay_nodes.is_relay(ip):
                bucket = self._content.setdefault(str(ip), {"front": 0, "back": 0})
                bucket[side] = bucket.get(side, 0) + 1

    def side_of(self, ip: Any) -> str:
        """这台中继该保留哪一侧：运维设置优先，否则按实测内容自动判（默认客户端侧）。"""
        addr = str(ip or "").strip()
        override = relay_nodes.side_override(addr)
        if override in (SIDE_FRONT, SIDE_BACK):
            return override
        counts = self._content.get(addr) or {}
        return auto_side(int(counts.get("front") or 0), int(counts.get("back") or 0))

    def _reset_if_list_changed(self) -> None:
        signature = relay_nodes.raw_text().strip()
        if signature != self._signature:
            self._signature = signature
            self._counts = {}
            self._content = {}

    def snapshot(self) -> dict[str, Any]:
        """当前证据计数与侧向（要展示给界面看的那份结构）。"""
        out: dict[str, Any] = {}
        for ip, counts in sorted(self._counts.items()):
            content = self._content.get(ip) or {}
            override = relay_nodes.side_override(ip)
            out[ip] = {
                "proxy": int(counts.get("proxy", 0)),
                "dns": int(counts.get("dns", 0)),
                # 角色名由证据多的那类决定；两类都有就都给（同一个地址既做反代又做 DNS 很常见）
                "roles": [role for role in ("proxy", "dns") if int(counts.get(role, 0)) > 0],
                # 两侧的明文请求内容条数 + 当前生效的侧向（界面据此核对/覆盖）
                "front_content": int(content.get("front") or 0),
                "back_content": int(content.get("back") or 0),
                "side": self.side_of(ip),
                "side_source": "manual" if override in (SIDE_FRONT, SIDE_BACK) else "auto",
            }
        return out

    def maybe_flush(self) -> bool:
        """到点就把证据写回 PG（返回是否写了）。写失败只记警告，不影响检测主循环。"""
        self._reset_if_list_changed()
        interval = max(30, int(settings.relay_role_detect_seconds))
        now = time.monotonic()
        if now - self._last_flush < interval:
            return False
        self._last_flush = now
        if not relay_nodes.configured():
            return False  # 没有清单就没有推算对象
        try:
            with SessionLocal() as db:
                relay_nodes.save_roles(
                    db,
                    self.snapshot(),
                    detected_at_value=datetime.now(UTC).isoformat(),
                )
        except Exception as exc:  # noqa: BLE001
            log.warning("中继角色写回失败（下一轮重试）: %s", exc)
            return False
        return True
