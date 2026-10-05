"""中继角色自动推算：清单里的每个地址是「反向代理 / WAF」还是「内网 DNS 转发器」。

为什么要推算（用户 2026-10 的口径）：中继清单只有一份地址清单，但两类角色的去重方式不同 ——
反代靠代理头配前后跳，DNS 转发靠「客户端跳 vs 转发跳」配。让运维在界面再填一遍角色既重复
又容易漏，所以由系统**按实际流量自动判断**，只读展示在界面上供核对。

判定（只看当前清单内的地址，stateless 口径）：
- 该地址在 **http/ssl** 事件里出现（作 src 或 dst）→ `proxy` 证据 +1（WAF/反代处理的就是这两类）
- 该地址在 **dns** 事件里出现 → `dns` 证据 +1
- 其余类型（conn/files/…）不提供证据：conn 覆盖所有流量，判不出角色

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


class RelayRoleDetector:
    """累计中继角色证据并周期回写 PG（进程内计数，单写者）。"""

    def __init__(self) -> None:
        self._counts: dict[str, dict[str, int]] = {}
        self._signature = ""
        self._last_flush = 0.0

    def observe(self, entry: UnifiedLog) -> None:
        """逐条事件累计证据（只对清单内的地址算）。"""
        role = _ROLE_BY_LOG_TYPE.get(str(entry.log_type or ""))
        if role is None:
            return
        for ip in (entry.src_ip, entry.dst_ip):
            if ip and relay_nodes.is_relay(ip):
                counts = self._counts.setdefault(str(ip), {})
                counts[role] = counts.get(role, 0) + 1

    def _reset_if_list_changed(self) -> None:
        signature = relay_nodes.raw_text().strip()
        if signature != self._signature:
            self._signature = signature
            self._counts = {}

    def snapshot(self) -> dict[str, Any]:
        """当前证据计数（要展示给界面看的那份结构）。"""
        out: dict[str, Any] = {}
        for ip, counts in sorted(self._counts.items()):
            out[ip] = {
                "proxy": int(counts.get("proxy", 0)),
                "dns": int(counts.get("dns", 0)),
                # 角色名由证据多的那类决定；两类都有就都给（同一个地址既做反代又做 DNS 很常见）
                "roles": [role for role in ("proxy", "dns") if int(counts.get(role, 0)) > 0],
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
