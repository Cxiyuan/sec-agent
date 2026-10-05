"""中继去重：一次业务访问只让**一侧**进检测/画像/资产，且保留客户端侧证据。

## 为什么是「保留前跳、丢掉后跳」

中继（反代/WAF/内网 DNS 转发器）会让同一个请求在抓包点上出现**两条**：
- **前跳**（`hop=front`）：客户端 → 中继。`src_ip` 就是**真实客户端**，请求头/payload/TLS 指纹
  也都在它上面 → 检测证据最全；
- **后跳**（`hop=back`）：中继 → 真实目的。HTTP/SSL 这类带 XFF（`real_client_ip` 告诉我们
  真实客户端），DNS 这类连 XFF 都没有（`src` 就是内网 DNS）。

两条都进检测就会：① 同一个请求算两次；② 后跳的 `src` 是内网中继，于是"内网主机查询可疑域名"
这类告警会**归因到 DNS 服务器头上**。所以保留前跳、丢掉后跳。

## 为什么不按「配对」做

两条跳是**两条独立 TCP 连接**（uid 不同），配对只能靠 (客户端, host/SNI, 协议, 端口) + 时间窗，
而且**顺序不可依赖**（日志写入时刻由各事务完成时刻决定，后跳常常先落）。做真正的配对/合并
需要在热路径上"挂起前跳、等后跳、再补上源站"，改动面与失败模式都大得多。

这里改用**可见性守卫**（简单、与顺序无关、两端拓扑都不会丢数据）：

- 前跳：照常处理，并记下「这个中继的前跳是可见的」（`_front_seen[relay] = 时间`）；
- 后跳：若**最近 `visibility_seconds` 内见过该中继的前跳** → 判定为重复，丢掉（计数）；
- 后跳：若从没见过前跳（例如抓包点只在源站侧）→ **照常处理**（计数 `relay_back_only`），
  宁可多算一条也不丢这条业务访问。

已知取舍（如实记录）：这样一条摘要的 `dst_ips` 是中继（不是源站 IP），真实源站 IP 需要到
ES 里看同一次访问的后跳文档（`hop=back`）；被访问方基线按 **hostname** 建 key，所以资产归因不受影响。
"""

from __future__ import annotations

import time
from typing import Any

from app.config import settings
from app.schemas import UnifiedLog

#: 记住「该中继的前跳可见」的时长：比日志落盘抖动大得多，又短到能反映拓扑变化。
DEFAULT_VISIBILITY_SECONDS = 300


class RelayDedup:
    """按「前跳是否可见」丢弃中继后跳（进程内状态，检测器单写者）。"""

    def __init__(self, visibility_seconds: int | None = None) -> None:
        try:
            raw = (
                visibility_seconds
                if visibility_seconds is not None
                else settings.relay_visibility_seconds
            )
            seconds = int(raw)
        except (TypeError, ValueError):
            seconds = DEFAULT_VISIBILITY_SECONDS
        self.visibility = max(30, seconds)
        self._front_seen: dict[str, float] = {}
        self.counts: dict[str, int] = {
            "relay_front": 0,
            "relay_back_dropped": 0,
            "relay_back_kept": 0,
            "relay_internal_dropped": 0,
        }

    def _relay_of(self, entry: UnifiedLog) -> str:
        """这条跳涉及的中继地址：前跳看 dst，后跳看 src。"""
        if entry.hop == "front":
            return str(entry.dst_ip or "")
        return str(entry.src_ip or "")

    def _visible(self, relay: str, now: float) -> bool:
        seen = self._front_seen.get(relay)
        return seen is not None and now - seen <= self.visibility

    def decide(self, entry: UnifiedLog, now: float | None = None) -> str:
        """返回 ``"pass"``（交给下游）或 ``"drop"``（判定为重复/中继内部，不处理）。"""
        ts = time.monotonic() if now is None else now
        hop = str(entry.hop or "direct")
        if hop == "direct":
            return "pass"
        if hop == "relay_internal":
            # 中继之间/级联的内部跳：既不是客户端侧也不是真实目的，一律不处理
            self.counts["relay_internal_dropped"] += 1
            return "drop"
        relay = self._relay_of(entry)
        if hop == "front":
            self.counts["relay_front"] += 1
            if relay:
                self._front_seen[relay] = ts
                self._prune(ts)
            return "pass"
        # hop == "back"：前跳可见就当重复丢掉；否则保留（抓包点可能只在源站侧）
        if relay and self._visible(relay, ts):
            self.counts["relay_back_dropped"] += 1
            return "drop"
        self.counts["relay_back_kept"] += 1
        return "pass"

    def _prune(self, now: float) -> None:
        """清掉过期记录，避免为不再出现的中继长期占内存。"""
        if len(self._front_seen) <= 64:
            return
        for relay, seen in list(self._front_seen.items()):
            if now - seen > self.visibility:
                self._front_seen.pop(relay, None)

    def snapshot(self) -> dict[str, Any]:
        """给心跳/界面用的一份计数。"""
        return {
            **self.counts,
            "relay_front_visible": {k: round(v, 1) for k, v in self._front_seen.items()},
        }
