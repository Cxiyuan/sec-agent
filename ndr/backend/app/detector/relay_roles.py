"""中继角色自动推算 + 两侧「内容」统计 + **上下级链路拓扑**。

为什么要推算（用户 2026-10 的口径）：中继清单只有一份地址清单，但两类角色的去重方式不同 ——
反代靠代理头配前后跳，DNS 转发靠「客户端跳 vs 转发跳」配。让运维在界面再填一遍角色既重复
又容易漏，所以由系统**按实际流量自动判断**，只读展示在界面上供核对。

判定（只看当前清单内的地址，stateless 口径）：
- 该地址在 **http/ssl** 事件里出现（作 src 或 dst）→ `proxy` 证据 +1（WAF/反代处理的就是这两类）
- 该地址在 **dns** 事件里出现 → `dns` 证据 +1
- 其余类型（conn/files/…）不提供证据：conn 覆盖所有流量，判不出角色

**两侧内容统计**：去重要问的头号问题是「该保留哪一侧」。实测本环境的 WAF：客户端侧那一跳是
**TLS 且无 SNI**，而源站侧那一跳是**明文 HTTP**（带 Host/URI/请求体，XFF 里是真实客户端）——
所以判据必须看「哪一侧有内容」，不能看跳的名字。

**2026-10 可靠性改造（用户口径：1+2+3）**：
1. 回写从「整份覆盖」改「**合并**」：每地址带 `hits_total`（跨重启累计，用于角色判定）与
   `window_hits`（本进程观测数，用于展示活跃度），所以检测器重启或低流量期**不会再掉成「未判定」**；
2. 每地址带 `last_seen`（最近一次被观测到的业务时间）与 `reason`（未判定原因，分两种：
   从未观测到证据类流量 / 两侧均无明文内容），界面据此解释「为什么没判定」；
3. 角色与侧向都支持**运维手工指定**（`role_overrides` / 已存在的 `sides`），优先级：手工 > 证据 > 未判定。

**上下级拓扑**（同一回写节奏，两类独立证据，各自计数、各自标来源）：
- ① 直连观测边：`hop=relay_internal` 的事件（src/dst 都在清单里）→ 边 `src→dst` 的 `direct += 1`；
- ② 代理头边：对每条事件用 `chain_peer_ips()` 取「上一跳」（`X-Real-IP` / `XFF 末尾`，发送方自写、
  客户端塞不进去）→ 边 `上一跳→src` 的 `header += 1`。
两类证据都 ≥ `ST_RELAY_EDGE_MIN` 才标记为「已确认」（低于门槛的只展示、不参与链路推导）；
超过 `ST_RELAY_EDGE_STALE_SECONDS` 没再观测只标 `stale`，不删。拓扑按上游→下游排序给出
`levels`（无入边 = 0 = 最靠近真实客户端的入口）与 `chains`；检出环时打断最弱的边并记录
`cycle_broken`（界面明示，不静默）。

位置：**检测器**（持锁实例逐条看到全部在范围事件，且在去重之前 —— 所以被丢掉的那一跳也能
贡献角色与拓扑证据）。本模块只把结果写回 PG，不做任何 I/O 于热路径。
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
#: 注意：**光出现这些类型不够** —— 还得是它在「替别人转发」，见 `observe()`。
_ROLE_BY_LOG_TYPE: dict[str, str] = {
    "http": "proxy",
    "ssl": "proxy",
    "dns": "dns",
}
ROLE_LABELS: dict[str, str] = {"proxy": "反向代理", "dns": "DNS 转发"}

#: 中继链路上的跳（与 `ingestion/normalizer._relay_hop` 同口径）
HOP_RELAY_INTERNAL = "relay_internal"
HOP_BACK = "back"

#: 角色证据口径版本。改口径就 +1：旧累计值是按旧语义数的，混着用就永远纠正不过来。
#: v2（2026-10）：从「该地址出现在 http/ssl/dns 日志里」改成「该地址在替别人转发」——
#: v1 把中继**自己上网**算成反代（.186 用 apt 拉 Ubuntu 镜像 1,150 条 http/ssl）、
#: 把中继**自己查 DNS** 算成 DNS 转发（.203 查 time.example.com 158 条），界面因此显示
#: 「反向代理 / DNS 转发」两个角色，与运维认知不符。
ROLE_EVIDENCE_VERSION = 2

#: 角色判定失败原因（两个都直接展示在界面上，所以写成人话）
REASON_NEVER_SEEN = "从未观测到 http/ssl/dns 流量"
REASON_WEAK_EVIDENCE = "证据不足（转发流量太少或占比过低，判不出角色）"

#: 算「内容」的日志类型：有请求语义的**明文**日志（规则/画像/资产真正要读的东西）。
#: **不含 ssl** —— 加密流量里读不到 Host/URI/body（无 SNI 的 ssl 只是一次握手）。
CONTENT_LOG_TYPES: frozenset[str] = frozenset({"http", "http2", "smtp", "dns"})

#: 侧向：保留客户端侧 / 源站侧
SIDE_FRONT = relay_nodes.SIDE_FRONT
SIDE_BACK = relay_nodes.SIDE_BACK

#: 未判定原因（界面直接展示，所以写成人话）
REASON_NO_CONTENT = "两侧均无明文内容，按保守默认保留客户端侧"

#: 拓扑里最多保留多少条链（防病态数据把界面撑爆）
_MAX_CHAINS = 20


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


def _role_override_list(override: str, evidence: list[str]) -> list[str]:
    """手工覆盖 → 角色列表；`auto` = 用证据。"""
    if override == relay_nodes.ROLE_PROXY:
        return ["proxy"]
    if override == relay_nodes.ROLE_DNS:
        return ["dns"]
    if override == relay_nodes.ROLE_BOTH:
        return ["proxy", "dns"]
    return evidence


def decide_roles(totals: dict[str, int]) -> list[str]:
    """按「证据量 + 占比」决定展示哪些角色（把残留噪音挡在门外）。

    为什么要占比：累计值是跨重启的历史合计，少量噪音会永远挂着第二个角色 —— 实机：.186 是纯
    DNS 转发（dns 206 万），自己 apt 上网留下 64 条 http/ssl 就被标成「反向代理 / DNS 转发」；
    .203 是 nginx WAF（proxy 225 万），自己查过 66 次 DNS 就被标成「DNS 转发」。改口径后这类
    噪音不再计数，占比门槛再兜一层（比如 .203 经 .211 转发时留下的 152 条 dns 也不足以成角色）。
    """
    proxy = max(0, int(totals.get("proxy") or 0))
    dns = max(0, int(totals.get("dns") or 0))
    total = proxy + dns
    if total <= 0:
        return []
    minimum = max(1, int(settings.relay_role_min_hits))
    share = max(0.0, float(settings.relay_role_min_share))
    picked: list[str] = []
    for role, hits in (("proxy", proxy), ("dns", dns)):
        if hits >= minimum and hits >= share * total:
            picked.append(role)
    return picked


def _side_from_counts(override: str, front: int, back: int, previous: str) -> tuple[str, str]:
    """侧向 + 来源：手工优先；否则本轮内容足够多就按本轮判，不够就沿用上一次判定。

    沿用上一次是关键：检测器重启后本轮没有内容时，**不能**把已经判对的 `back` 退回默认值
    （实机踩过：.203 已判「保留源站侧」，重启后一度退回客户端侧）。
    """
    if override in (SIDE_FRONT, SIDE_BACK):
        return override, "manual"
    minimum = max(1, int(settings.relay_side_min))
    if max(front, back) >= minimum:
        return auto_side(front, back), "auto"
    if previous in (SIDE_FRONT, SIDE_BACK):
        return previous, "kept"
    return auto_side(front, back), "auto"


def derive_topology(
    edges: dict[str, dict[str, Any]],
    nodes: list[str],
    *,
    min_evidence: int,
    stale_seconds: int,
    now_ts: float,
    generated_at: str,
) -> dict[str, Any]:
    """把边证据整理成「上下级拓扑」：确认的边 + 层级 + 链 + 异常标记。

    - `edges` 键形如 ``"上游|下游"``，值 = ``{"direct": n, "header": n, "last_seen": iso}``；
    - 只保留**当前清单内**的两端（被移除的地址计入 `pruned`）；
    - `confirmed`：两类证据任一达到 `min_evidence`（链路推导只用确认的边，其余只展示）；
    - `stale`：超过 `stale_seconds` 没再观测（按 `last_seen` 的时间戳判）。
    """
    alive = set(nodes)
    pruned = 0
    kept: list[dict[str, Any]] = []
    for key, item in sorted(edges.items()):
        if "|" not in key:
            continue
        up, down = key.split("|", 1)
        if up not in alive or down not in alive or up == down:
            pruned += 1
            continue
        direct = int(item.get("direct") or 0)
        header = int(item.get("header") or 0)
        last_seen = str(item.get("last_seen") or "")
        age = now_ts - _parse_ts(last_seen, now_ts)
        kept.append(
            {
                "from": up,
                "to": down,
                "direct": direct,
                "header": header,
                "confirmed": max(direct, header) >= max(1, min_evidence),
                "stale": age > max(60, stale_seconds),
                "last_seen": last_seen,
            }
        )

    confirmed = [(e["from"], e["to"]) for e in kept if e["confirmed"]]
    levels, cycle_broken = _levels(confirmed, edges)

    # 链：从没有入边的节点一路走到叶子（同一路径只留一条）
    chains: list[list[str]] = []
    for start in sorted(n for n in alive if n in levels and n not in {d for _, d in confirmed}):
        stack: list[list[str]] = [[start]]
        while stack:
            path = stack.pop()
            tail = path[-1]
            downs = sorted(d for u, d in confirmed if u == tail and d not in path)
            if not downs:
                if len(path) > 1:
                    chains.append(path)
                continue
            for down in downs:
                stack.append([*path, down])
            if len(chains) > _MAX_CHAINS * 4:  # 病态数据保护
                break
    deduped = sorted({tuple(c) for c in chains})[:_MAX_CHAINS]
    return {
        "edges": kept,
        "levels": levels,
        "chains": [list(c) for c in deduped],
        "min_evidence": max(1, min_evidence),
        "pruned": pruned,
        "cycle_broken": cycle_broken,
        "generated_at": generated_at,
    }


def _parse_ts(value: str, default: float) -> float:
    try:
        return datetime.fromisoformat(value).timestamp()
    except (TypeError, ValueError):
        return default


def _levels(
    confirmed: list[tuple[str, str]], edges: dict[str, dict[str, Any]]
) -> tuple[dict[str, int], list[list[str]]]:
    """拓扑排序求层级（无入边 = 0）。有环就打断最弱的边，并记录被打断的边。"""
    broken: list[list[str]] = []
    pairs = list(confirmed)
    for _ in range(8):  # 最多打断 8 次（病态数据下不至于死循环）
        nodes = sorted({x for pair in pairs for x in pair})
        incoming: dict[str, set[str]] = {n: set() for n in nodes}
        for up, down in pairs:
            incoming[down].add(up)
        levels: dict[str, int] = {}
        pending = list(nodes)
        progress = True
        while pending and progress:
            progress = False
            for node in list(pending):
                ups = [u for u in incoming[node] if u in levels]
                if len(ups) != len(incoming[node]):
                    continue
                levels[node] = (max((levels[u] for u in ups), default=-1)) + 1
                pending.remove(node)
                progress = True
        if not pending:
            return levels, broken
        # 有环：打断「环内」证据最弱的边
        weakest = None
        weakest_score = None
        for up, down in pairs:
            if up in pending and down in pending:
                item = edges.get(f"{up}|{down}") or {}
                score = int(item.get("direct") or 0) + int(item.get("header") or 0)
                if weakest_score is None or score < weakest_score:
                    weakest, weakest_score = (up, down), score
        if weakest is None:
            break
        pairs.remove(weakest)
        broken.append([weakest[0], weakest[1]])
    return {}, broken


class RelayRoleDetector:
    """累计中继角色/内容/拓扑证据并周期回写 PG（进程内计数，单写者）。"""

    def __init__(self) -> None:
        self._counts: dict[str, dict[str, int]] = {}
        # 两侧的「内容」条数：{ip: {"front": n, "back": n}}；front = 该地址作目的地
        self._content: dict[str, dict[str, int]] = {}
        # 自上次回写以来的增量（用于与库内累计值合并，避免重启就丢历史判定）
        self._pending_roles: dict[str, dict[str, int]] = {}
        self._pending_content: dict[str, dict[str, int]] = {}
        self._pending_edges: dict[str, dict[str, Any]] = {}
        self._last_seen: dict[str, str] = {}
        self._signature = ""
        self._last_flush = 0.0

    def observe(self, entry: UnifiedLog) -> None:
        """逐条事件累计证据（只对清单内的地址算）。

        **只算「它在替别人转发」的证据**（2026-10 实机踩到并修正）：中继自己发起的流量不算。
        判据来自实机数据（见模块头）：

        - 它作**目的地**：有人来访问它的服务（http/ssl）或来问它 DNS（dns）—— 这是转发器本色；
        - 它作**源**：只有走转发链才算 ——
          ① 中继↔中继直连跳（`hop=relay_internal`）：它必定是转发链的一环。
             这条是唯一能认下 .214 的判据：它作源的 TLS 不带代理头（客户端直连它、首跳没人加 XFF），
             但 6 小时 153 万次 TLS 全打在中继 .203 上；
          ② `hop=back` **且带代理头**（`real_client_ip` 非空）：它替客户端去源站。自己上网的请求
             不会带代理头 —— .186 的 1,150 条 apt 流量正是这一条把它们挡掉的。
        """
        log_type = str(entry.log_type or "")
        if log_type in CONTENT_LOG_TYPES:
            self._count_content(entry)
        self._count_edge(entry)
        role = _ROLE_BY_LOG_TYPE.get(log_type)
        if role is None:
            return
        hop = str(getattr(entry, "hop", "") or "")
        src = str(entry.src_ip or "")
        dst = str(entry.dst_ip or "")
        seen_at = _iso(getattr(entry, "ts", None))
        addrs: list[str] = []
        if relay_nodes.is_relay(dst):
            addrs.append(dst)
        if relay_nodes.is_relay(src):
            # ① 中继↔中继直连跳，或 ② 带代理头地替客户端去源站（自己上网的请求没有代理头）
            forwards = hop == HOP_RELAY_INTERNAL or (
                hop == HOP_BACK and bool(getattr(entry, "real_client_ip", None))
            )
            if forwards:
                addrs.append(src)
        for addr in dict.fromkeys(addrs):
            counts = self._counts.setdefault(addr, {})
            counts[role] = counts.get(role, 0) + 1
            pending = self._pending_roles.setdefault(addr, {})
            pending[role] = pending.get(role, 0) + 1
            self._last_seen[addr] = max(self._last_seen.get(addr, ""), seen_at)

    def _count_content(self, entry: UnifiedLog) -> None:
        """记「哪一侧带明文请求内容」：目的地是中继 → 客户端侧；来源是中继 → 源站侧。"""
        seen_at = _iso(getattr(entry, "ts", None))
        for ip, side in ((entry.dst_ip, "front"), (entry.src_ip, "back")):
            if ip and relay_nodes.is_relay(ip):
                addr = str(ip)
                bucket = self._content.setdefault(addr, {"front": 0, "back": 0})
                bucket[side] = bucket.get(side, 0) + 1
                pending = self._pending_content.setdefault(addr, {"front": 0, "back": 0})
                pending[side] = pending.get(side, 0) + 1
                self._last_seen[addr] = max(self._last_seen.get(addr, ""), seen_at)

    def _count_edge(self, entry: UnifiedLog) -> None:
        """累计上下级边证据：① 中继↔中继直连跳 ② 代理头里的「上一跳」。"""
        src = str(entry.src_ip or "")
        dst = str(entry.dst_ip or "")
        seen_at = _iso(getattr(entry, "ts", None))
        # ① 直连观测：两端都在清单里（中继→中继），方向就是请求前进方向
        if src and dst and relay_nodes.is_relay(src) and relay_nodes.is_relay(dst) and src != dst:
            self._bump_edge(src, dst, "direct", seen_at)
        # ② 代理头：发送方自己追加的位置（X-Real-IP / XFF 末尾），指向「上一跳」
        # 延迟导入：relay_pairing 反向依赖本模块的常量（CONTENT_LOG_TYPES/SIDE_*），
        # 模块级导入会成环；函数内导入在首次调用后就是一次 sys.modules 查表，可忽略。
        if src:
            from app.detector.relay_pairing import chain_peer_ips

            for peer in chain_peer_ips(entry):
                other = str(peer or "").strip()
                if not other or other == src or not relay_nodes.is_relay(other):
                    continue
                self._bump_edge(other, src, "header", seen_at)

    def _bump_edge(self, up: str, down: str, kind: str, seen_at: str) -> None:
        item = self._pending_edges.setdefault(f"{up}|{down}", {"direct": 0, "header": 0})
        item[kind] = int(item.get(kind) or 0) + 1
        item["last_seen"] = max(str(item.get("last_seen") or ""), seen_at)

    def side_of(self, ip: Any) -> str:
        """这台中继该保留哪一侧：运维设置优先，否则按实测内容自动判（默认客户端侧）。"""
        addr = str(ip or "").strip()
        override = relay_nodes.side_override(addr)
        if override in (SIDE_FRONT, SIDE_BACK):
            return override
        counts = self._content.get(addr) or {}
        stored = relay_nodes.roles().get(addr) or {}
        previous = str(stored.get("side") or "")
        side, _ = _side_from_counts(
            override, int(counts.get("front") or 0), int(counts.get("back") or 0), previous
        )
        return side

    def _reset_if_list_changed(self) -> None:
        signature = relay_nodes.raw_text().strip()
        if signature != self._signature:
            self._signature = signature
            self._counts = {}
            self._content = {}
            self._pending_roles = {}
            self._pending_content = {}
            self._pending_edges = {}
            self._last_seen = {}

    def snapshot(self) -> dict[str, Any]:
        """当前证据 + 与库内累计值**合并**后的展示结构（界面与后续判定都用它）。"""
        stored = relay_nodes.roles()
        out: dict[str, Any] = {}
        for ip, counts in sorted(self._counts.items()):
            out[ip] = self._merge_one(ip, counts, stored.get(ip) or {})
        # 本轮没观测到、但库里有记录的地址：保留（重启/低流量不再掉成「未判定」）
        for ip, old in stored.items():
            if ip not in out and relay_nodes.is_relay(ip):
                out[ip] = dict(old)
        # 清单里**从未被观测过**的地址也要出现：界面要能显示「为什么未判定」，
        # 而不是给一个没有解释的空行（用户 2026-10 的明确要求）。
        for net in relay_nodes.networks():
            addr = str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)
            if addr in out or addr in stored:
                continue
            out[addr] = self._merge_one(
                addr,
                {},
                {
                    "hits_total": {"proxy": 0, "dns": 0},
                    "evidence_version": ROLE_EVIDENCE_VERSION,
                    "roles": [],
                    "role_reason": REASON_NEVER_SEEN,
                },
            )
        return out

    def _merge_one(
        self, ip: str, counts: dict[str, int], old: dict[str, Any] | None
    ) -> dict[str, Any]:
        stored = old if isinstance(old, dict) else {}
        pending = self._pending_roles.get(ip) or {}
        raw_totals = stored.get("hits_total")
        old_totals = raw_totals if isinstance(raw_totals, dict) else {}
        if int(stored.get("evidence_version") or 0) != ROLE_EVIDENCE_VERSION:
            # 口径换代：旧累计值语义不同，不能混用（否则错误角色永远纠正不过来）
            old_totals = {}
        totals = {
            role: int(old_totals.get(role) or 0) + int(pending.get(role) or 0)
            for role in ("proxy", "dns")
        }
        evidence = decide_roles(totals)

        content = self._content.get(ip) or {}
        pending_content = self._pending_content.get(ip) or {}
        old_front = int(stored.get("front_total") or 0)
        old_back = int(stored.get("back_total") or 0)
        front_total = old_front + int(pending_content.get("front") or 0)
        back_total = old_back + int(pending_content.get("back") or 0)

        override = relay_nodes.role_override(ip)
        roles = _role_override_list(override, evidence)
        side, side_source = _side_from_counts(
            relay_nodes.side_override(ip),
            int(content.get("front") or 0),
            int(content.get("back") or 0),
            str(stored.get("side") or ""),
        )
        # 原因分开给（界面各用各的）：
        #   角色：手工指定过就不算「未判定」；只在「从未观测到证据类流量」时解释；
        #   侧向：本轮内容不够、也没有历史判定与手工覆盖时，说明走的是保守默认。
        if override != relay_nodes.ROLE_AUTO:
            role_reason = ""
        elif not any(int(totals.get(r) or 0) for r in ("proxy", "dns")):
            role_reason = REASON_NEVER_SEEN
        elif not roles:
            role_reason = REASON_WEAK_EVIDENCE
        else:
            role_reason = ""
        enough_content = max(int(content.get("front") or 0), int(content.get("back") or 0)) >= max(
            1, int(settings.relay_side_min)
        )
        side_reason = (
            "" if (enough_content or side_source in ("manual", "kept")) else REASON_NO_CONTENT
        )
        return {
            "proxy": int(counts.get("proxy", 0)),
            "dns": int(counts.get("dns", 0)),
            # 证据口径版本：换代时旧累计值作废（见 ROLE_EVIDENCE_VERSION）
            "evidence_version": ROLE_EVIDENCE_VERSION,
            "hits_total": totals,
            "window_hits": int(sum(int(counts.get(r, 0)) for r in ("proxy", "dns"))),
            "roles": roles,
            "role_source": "manual" if override != relay_nodes.ROLE_AUTO else "auto",
            "front_content": int(content.get("front") or 0),
            "back_content": int(content.get("back") or 0),
            "front_total": front_total,
            "back_total": back_total,
            "side": side,
            "side_source": side_source,
            "last_seen": max(
                str(self._last_seen.get(ip) or ""), str(stored.get("last_seen") or "")
            ),
            "role_reason": role_reason,
            "side_reason": side_reason,
        }

    def _merged_edges(self) -> dict[str, dict[str, Any]]:
        """与库内拓扑合并边证据（累加计数、取最大 last_seen），再重算层级与链。"""
        stored = relay_nodes.topology().get("edges")
        merged: dict[str, dict[str, Any]] = {}
        for item in stored if isinstance(stored, list) else []:
            if not isinstance(item, dict):
                continue
            key = f"{item.get('from')}|{item.get('to')}"
            merged[key] = {
                "direct": int(item.get("direct") or 0),
                "header": int(item.get("header") or 0),
                "last_seen": str(item.get("last_seen") or ""),
            }
        for key, item in self._pending_edges.items():
            bucket = merged.setdefault(key, {"direct": 0, "header": 0, "last_seen": ""})
            bucket["direct"] = int(bucket.get("direct") or 0) + int(item.get("direct") or 0)
            bucket["header"] = int(bucket.get("header") or 0) + int(item.get("header") or 0)
            bucket["last_seen"] = max(
                str(bucket.get("last_seen") or ""), str(item.get("last_seen") or "")
            )
        return merged

    def derive_and_save_topology(self, db: Any, *, generated_at: str) -> None:
        merged = self._merged_edges()
        nodes = [
            str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)
            for net in relay_nodes.networks()
        ]
        data = derive_topology(
            merged,
            nodes,
            min_evidence=int(settings.relay_edge_min),
            stale_seconds=int(settings.relay_edge_stale_seconds),
            now_ts=time.time(),
            generated_at=generated_at,
        )
        relay_nodes.save_topology(db, data)
        self._pending_edges = {}

    def maybe_flush(self) -> bool:
        """到点就把证据（与库内累计值合并后）写回 PG。写失败只记警告，不影响检测主循环。"""
        self._reset_if_list_changed()
        interval = max(30, int(settings.relay_role_detect_seconds))
        now = time.monotonic()
        if now - self._last_flush < interval:
            return False
        self._last_flush = now
        if not relay_nodes.configured():
            return False  # 没有清单就没有推算对象
        generated_at = datetime.now(UTC).isoformat()
        try:
            with SessionLocal() as db:
                relay_nodes.save_roles(db, self.snapshot(), detected_at_value=generated_at)
                self.derive_and_save_topology(db, generated_at=generated_at)
        except Exception as exc:  # noqa: BLE001
            log.warning("中继角色/拓扑写回失败（下一轮重试）: %s", exc)
            return False
        self._pending_roles = {}
        self._pending_content = {}
        return True


def _iso(value: Any) -> str:
    if isinstance(value, datetime):
        return (value if value.tzinfo else value.replace(tzinfo=UTC)).isoformat()
    return ""
