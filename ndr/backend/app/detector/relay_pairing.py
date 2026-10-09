"""中继去重：一次业务访问只让**一侧**进检测/画像/资产，且保留**有明文请求内容**的那一侧。

## 判据为什么从「跳的名字」改成「哪一侧有内容」（2026-10 实机实测）

原判据是「保留前跳（客户端 → 中继）、丢掉后跳（中继 → 真目的）」，理由是两句假设：
① 前跳的 `src_ip` 就是真实客户端；② 前跳的请求头/payload/TLS 指纹都在它上面。

**这两条在本环境的 WAF 上都不成立**（实测）：

| 跳 | 事实 |
|---|---|
| 199.214/215 → 199.203（客户端侧） | conn 45,183 / ssl 44,623（**SNI 0 条**）/ http **9** / weird 62,505；src 99.9% 是另一台代理 199.214，**不是客户端** |
| 199.203 → 196.112/125（源站侧） | **http 28,557 行 / 2,431 连接**、files 20,825、Host `www.example.com` 16,774、XFF 真实客户端 **438 个/15 分钟** |

两侧内容比 **9 : 28,557（1 : 3172）**：客户端侧是「TLS 无 SNI」的加密流，规则读不到
Host/URI/body；源站侧才是 WAF 解密后的明文请求。继续按「保前跳」就会丢掉唯一有证据的那跳
（84 条内置规则里 21 条依赖 `uri_path/method/status_code/user_agent/referer/content_type`）。

同时实测发现原判据的「前跳可见就丢后跳」是**按中继整体**记的、非常脆：只要 300 秒内有
**任何**未登记源碰过该中继（实测：`10.1.2.254` 的 ICMP 探活、`198.51.100.19` 的明文
HTTP），整段有内容的跳就被丢掉 —— 实测 `relay_back_dropped 29,403 / back_kept 24`，
即 99.9% 被误丢。

## 现在的判据（三条）

1. **按内容判侧向**：由 `relay_roles` 在**去重之前**累计每个中继两侧的明文内容条数
   （`http`/`http2`/`smtp`/`dns`；**不含 ssl**），按 `ST_RELAY_SIDE_MIN` /
   `ST_RELAY_SIDE_RATIO` 判该保留哪一侧；运维可在界面**手动覆盖**（auto/front/back）。
   统计在去重之前，所以「丢了哪一侧」不会让判据自己锁死。
2. **链的下游续跳丢掉**：本跳 `src` 不是中继，但代理头（`X-Real-IP` / `X-Forwarded-For`
   末尾 = 发送方自己观测到的对端）是清单内的中继 → 它是同一次访问的下游续传。
   **必须限定「src 不是中继」**：证据跳（中继 → 源站）的代理头里同样带着中继（它的上游，
   实测 XFF 末尾 1,669 条是 199.214），不限定就会把要保留的那条丢掉。
3. **中继之间的跳**（`relay_internal`）不再无条件丢：只有「发送方的内容侧就是源站侧」
   且本跳确实带明文内容时才留（本环境的 199.214 → 199.203 是 TLS 无内容 → 照旧丢）。

## 为什么仍然不做「配对」

两跳是**两条独立 TCP 连接**（uid 不同），配对只能靠 (客户端, host/SNI, 协议, 端口) + 时间窗，
而且顺序不可依赖。上面的判据全部是**单条事件可判**的（侧向是每中继的滚动统计、续跳看本跳的
代理头），不需要挂起等待，热路径开销只有 dict 查表。

已知取舍（如实记录）：
- 「续跳」判据依赖代理头；客户端理论上可以伪造 `X-Real-IP: <中继IP>` 让本跳被丢（被动监听的
  固有局限）。相比之下按 XFF 最左值判更弱（那是客户端可塞的位置），所以这里只认
  `X-Real-IP` 与 `X-Forwarded-For` **末尾**（发送方自己观测到的对端）。
- 侧向是每中继的统计：同一台中继两侧都有内容时，默认仍按客户端侧（与历史行为一致）。
"""

from __future__ import annotations

import ipaddress
import re
import time
from collections.abc import Callable
from typing import Any

from app.config import settings
from app.detector.relay_roles import CONTENT_LOG_TYPES, SIDE_BACK, SIDE_FRONT
from app.ingestion import relay_nodes
from app.schemas import UnifiedLog

#: 记住「该中继的前跳可见」的时长：比日志落盘抖动大得多，又短到能反映拓扑变化。
DEFAULT_VISIBILITY_SECONDS = 300

#: 「链的续跳」判定用的代理头字段（与 `ingestion/normalizer.py` 的 `_RAW_PROXY_HEADERS`
#: 对应：那边用它取真实客户端，这里只用来判断「这条跳是不是某个中继的下游续传」）。
_RAW_PROXY_HEADERS: tuple[str, ...] = (
    "x-real-ip",
    "x_real_ip",
    "x-forwarded-for",
    "x_forwarded_for",
)


def _ip_list(text: Any) -> list[str]:
    """从一段文本里取 IP（逗号/空格分隔，容忍 `1.2.3.4:80` 与 `[v6]:port` 写法）。"""
    out: list[str] = []
    for token in re.split(r"[,\s;]+", str(text or "")):
        token = token.strip().strip('"').strip("'")
        if not token:
            continue
        if token.startswith("[") and "]" in token:  # [v6]:port
            token = token[1 : token.index("]")]
        elif token.count(":") == 1:  # v4:port
            token = token.rsplit(":", 1)[0]
        try:
            out.append(str(ipaddress.ip_address(token)))
        except ValueError:
            continue
    return out


def chain_peer_ips(entry: UnifiedLog) -> set[str]:
    """代理头里「发送方自己观测到的对端 IP」：`X-Real-IP` 与 `X-Forwarded-For` **末尾**。

    这两个位置是**发送方追加/覆盖**写的（不是客户端可塞的位置），所以用它们判「上一跳是谁」
    比用 XFF 最左值可靠；正常反代链里两者一致（实测 298/298 一致）。
    """
    raw = getattr(entry, "raw", None)
    raw = raw if isinstance(raw, dict) else {}
    out: set[str] = set()
    items: list[str] = []
    proxied = raw.get("proxied")
    if isinstance(proxied, (list, tuple)):
        items.extend(str(item) for item in proxied)
    elif proxied:
        items.append(str(proxied))
    for item in items:
        name, sep, value = item.partition("->")
        if not sep:
            continue
        head = name.strip().lower()
        ips = _ip_list(value)
        if not ips:
            continue
        if "real-ip" in head or "real_ip" in head:
            out.add(ips[0])
        elif "forwarded" in head:
            out.add(ips[-1])
    # 没有 Zeek 的 proxied 包装时退回裸头
    for key in _RAW_PROXY_HEADERS:
        value = raw.get(key)
        if not value:
            continue
        ips = _ip_list(value if isinstance(value, str) else " ".join(str(v) for v in value))
        if not ips:
            continue
        out.add(ips[0] if "real" in key else ips[-1])
    return out


class RelayDedup:
    """按「哪一侧有明文请求内容」丢弃中继的另一侧（进程内状态，检测器单写者）。"""

    def __init__(
        self,
        visibility_seconds: int | None = None,
        side_of: Callable[[str], str] | None = None,
    ) -> None:
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
        # 侧向判定注入：`relay_roles.side_of`（实测内容 + 运维覆盖）；不注入时按历史行为保留客户端侧
        self._side_of: Callable[[str], str] = side_of or (lambda _ip: SIDE_FRONT)
        self._front_seen: dict[str, float] = {}
        self.counts: dict[str, int] = {
            "relay_front": 0,
            "relay_front_dropped": 0,
            "relay_back_dropped": 0,
            "relay_back_kept": 0,
            "relay_internal_dropped": 0,
            "relay_internal_kept": 0,
            "relay_chain_continuation_dropped": 0,
        }

    def _relay_of(self, entry: UnifiedLog) -> str:
        """这条跳涉及的中继地址：前跳看 dst，后跳/中继内部跳看 src。"""
        if entry.hop == "front":
            return str(entry.dst_ip or "")
        return str(entry.src_ip or "")

    def _visible(self, relay: str, now: float) -> bool:
        seen = self._front_seen.get(relay)
        return seen is not None and now - seen <= self.visibility

    def _side(self, relay: str) -> str:
        try:
            side = str(self._side_of(relay) or SIDE_FRONT)
        except Exception:  # noqa: BLE001 — 判据出问题也不能打断检测主循环
            return SIDE_FRONT
        return side if side in (SIDE_FRONT, SIDE_BACK) else SIDE_FRONT

    def _is_chain_continuation(self, entry: UnifiedLog) -> bool:
        """本跳 src 不是中继，但代理头说它是从某个中继转发过来的 → 同一次访问的下游续传。

        必须限定「src 不是中继」：证据跳（中继 → 源站）的代理头里同样带着中继（它的上游是
        下一台中继），不限定就会把要保留的那一条也丢掉。
        """
        src = str(entry.src_ip or "")
        if not src or relay_nodes.is_relay(src):
            return False
        return any(ip != src and relay_nodes.is_relay(ip) for ip in chain_peer_ips(entry))

    def decide(self, entry: UnifiedLog, now: float | None = None) -> str:
        """返回 ``"pass"``（交给下游）或 ``"drop"``（重复 / 无内容侧，不处理）。"""
        ts = time.monotonic() if now is None else now
        hop = str(entry.hop or "direct")

        # ① 链的下游续跳：先判（与侧向无关，且它一定是重复）
        if hop == "direct":
            if self._is_chain_continuation(entry):
                self.counts["relay_chain_continuation_dropped"] += 1
                return "drop"
            return "pass"

        relay = self._relay_of(entry)
        side = self._side(relay)

        if hop == "relay_internal":
            # 中继之间的跳：只有「发送方的内容侧就是源站侧」且本跳确实带明文内容时才留
            if side == SIDE_BACK and str(entry.log_type or "") in CONTENT_LOG_TYPES:
                self.counts["relay_internal_kept"] += 1
                return "pass"
            self.counts["relay_internal_dropped"] += 1
            return "drop"

        if hop == "front":
            self.counts["relay_front"] += 1
            if relay:
                self._front_seen[relay] = ts
                self._prune(ts)
            if side == SIDE_FRONT:
                return "pass"
            # 该中继的内容在源站侧 → 客户端侧这跳没有规则能读的东西，丢掉
            self.counts["relay_front_dropped"] += 1
            return "drop"

        # hop == "back"：内容在源站侧就保留；否则沿用「前跳可见才丢」的兜底
        # （抓包点可能只在源站侧，那种情况下没见过前跳，保留更安全）
        if side == SIDE_BACK or not (relay and self._visible(relay, ts)):
            self.counts["relay_back_kept"] += 1
            return "pass"
        self.counts["relay_back_dropped"] += 1
        return "drop"

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
