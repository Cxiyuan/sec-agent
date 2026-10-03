"""兜底预筛：规则未命中时，用启发式挑出值得交 LLM 复筛的日志（防漏报）。

背景：规则是硬性入口，规则覆盖不到的行为会被直接丢弃 → 漏报。
本模块在规则之后加一层「启发式安全网」：对被规则漏掉的日志打分，
分数达标的候选（上限可配）交边缘模型复筛，通过者同样成为可疑事件。

注意：这是「显著降低漏报」，不等于「绝对不漏报」。绝对不漏报需全量交 LLM，
成本不可接受；上限与阈值均可配（ST_PREFILTER_*）。
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from app.agents import triage_policy
from app.config import settings
from app.ingestion.conn_states import is_established
from app.schemas import UnifiedLog
from app.workers.log import get_logger

log = get_logger(__name__)

# 已知高风险端口（后门/代理/矿池常用）
SUSPICIOUS_PORTS: set[int] = {
    4444,
    4445,
    5555,
    6666,
    6667,
    7777,
    9001,
    9050,
    1337,
    31337,
    12345,
    54321,
    1080,
}

# 常用端口（不在其中的外联端口更值得关注）
COMMON_PORTS: set[int] = {
    20,
    21,
    22,
    23,
    25,
    53,
    67,
    68,
    69,
    80,
    110,
    119,
    123,
    135,
    137,
    138,
    139,
    143,
    161,
    162,
    179,
    389,
    443,
    445,
    465,
    514,
    515,
    587,
    631,
    636,
    873,
    993,
    995,
    1433,
    1521,
    1723,
    2049,
    2082,
    2083,
    2181,
    2375,
    2379,
    3000,
    3128,
    3306,
    3389,
    4443,
    5000,
    5432,
    5601,
    5672,
    5900,
    5984,
    6000,
    6379,
    6443,
    7001,
    8000,
    8008,
    8080,
    8081,
    8088,
    8443,
    8888,
    9000,
    9090,
    9200,
    9300,
    9443,
    10000,
    11211,
    27017,
}


@dataclass
class Candidate:
    log: UnifiedLog
    score: float
    reasons: list[str] = field(default_factory=list)


def build_scope_networks(cidrs: list[str]) -> list[Any]:
    nets: list[Any] = []
    for c in cidrs or []:
        raw = (c or "").strip()
        if not raw:
            continue
        try:
            if "/" in raw:
                nets.append(ipaddress.ip_network(raw, strict=False))
            else:
                addr = ipaddress.ip_address(raw)
                nets.append(ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}", strict=False))
        except ValueError:
            continue
    return nets


def _in_networks(ip_value: Any, nets: list[Any]) -> bool:
    if not ip_value or not nets:
        return False
    try:
        addr = ipaddress.ip_address(str(ip_value))
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in nets)


def _looks_established(entry: UnifiedLog) -> bool:
    """是否像“正常建立过会话”：成功连接状态（或已建立类事件）且**双向都有字节**。

    为什么要单独判它：未建立/半开连接（S0/REJ）是扫描/探活的典型特征，而双向有字节
    的已建立会话基本是正常业务（内网尤其如此）—— 后者正是兜底预筛噪声的主来源。

    "握手完成过"只认 app/ingestion/conn_states.py 那张表（``is_established``），
    事件类型只是标签兜底：以前这里手写了第三份 conn_state 白名单，与 normalizer /
    triage_policy 各说各话（SH 明明没建立却被当成已建立），故统一收回表里。
    """
    success = is_established(entry.conn_state) or entry.event_type in triage_policy.SUCCESS_EVENT_TYPES
    return success and bool(entry.bytes_out) and bool(entry.bytes_in)


def score_log(
    entry: UnifiedLog,
    *,
    scope_nets: list[Any],
    known_asset_ips: set[str],
) -> Candidate | None:
    """启发式打分：**只对可疑特征加分、对正常特征扣分**，并守住召回底线。

    改动原因（实测）：原来「非常用端口 +0.3 / 外联 +0.2」对**内网到内网**的常规连接
    也生效，于是兜底预筛命中里 91% 是正常已建立连接，把模型预算全吃掉了。
    现在：非标端口只在**跨出受管网段**时算信号；已建立会话/常用端口/已录资产目标要扣分。
    召回底线：明确可疑信号（后门端口 / 超大数据外发 / 未覆盖的 Wazuh 高危）不受扣分影响。
    """
    score = 0.0
    reasons: list[str] = []
    strong = False  # 明确可疑：命中即入选，不被扣分抵消

    dst_external = bool(entry.dst_ip) and not _in_networks(entry.dst_ip, scope_nets)
    src_managed = bool(entry.src_ip) and _in_networks(entry.src_ip, scope_nets)
    crosses = dst_external or not src_managed  # 至少一端跨出受管网段

    # 1) 高风险端口（后门/代理/矿池）：基本没有正常用途
    if entry.dst_port in SUSPICIOUS_PORTS:
        score += 0.5
        strong = True
        reasons.append(f"高风险端口 {entry.dst_port}")

    # 2) 非常用端口：只在跨出受管网段时才算信号（内网内部的非标端口多为自建服务）
    if entry.dst_port and entry.dst_port not in COMMON_PORTS and crosses:
        if entry.event_type in ("conn_established", "generic") or entry.log_type == "conn":
            score += 0.3
            reasons.append(f"跨网段非常用端口 {entry.dst_port}")
        if dst_external:
            score += 0.2
            reasons.append("外联非受管网段")

    # 3) 数据外传量（超大外发在任何方向都值得看）
    if entry.bytes_out:
        if entry.bytes_out > settings.prefilter_bytes_out_alert:
            score += 0.6
            strong = True
            reasons.append(f"超大外发流量 {entry.bytes_out} 字节")
        elif entry.bytes_out > settings.prefilter_bytes_out_warn:
            score += 0.3
            reasons.append(f"较大外发流量 {entry.bytes_out} 字节")

    # 4) 异常长 query（DNS 隧道 / 注入 payload）
    if entry.query and len(entry.query) > settings.prefilter_query_len_warn:
        score += 0.3
        reasons.append(f"异常长请求/查询（{len(entry.query)} 字符）")

    # 5) HTTP 服务端错误：只在跨网段时算信号（内网应用报 5xx 属故障不属安全事件）
    if entry.status_code and entry.status_code >= 500 and crosses:
        score += 0.2
        reasons.append(f"HTTP {entry.status_code}")

    # 6) 目标不在已录资产中（首次出现的对象）
    if (
        entry.dst_ip
        and known_asset_ips
        and entry.dst_ip not in known_asset_ips
        and not dst_external
    ):
        score += 0.2
        reasons.append("目标不在已录资产中")

    # 7) Wazuh 中高级别但规则没命中（规则未覆盖的主机事件）
    if entry.source_system == "wazuh" and entry.severity in ("medium", "high", "critical"):
        score += 0.3
        if entry.severity in ("high", "critical"):
            strong = True
        reasons.append(f"未覆盖的 Wazuh {entry.severity} 事件")

    # ---- 正常特征扣分（本轮降噪的主要来源）----
    # 注意：“已建立会话”的扣分**只用于内网内部**：对外建立连接正是 C2/后门的典型形状，
    # 不能因为“建立了会话”就把它扣掉（否则真正的 C2 会被过滤掉）。
    if _looks_established(entry) and not dst_external:
        score -= settings.prefilter_penalty_established
        reasons.append("内网已建立会话（双向有字节）")
    if entry.dst_port in COMMON_PORTS:
        score -= settings.prefilter_penalty_common_port
        reasons.append(f"常用端口 {entry.dst_port}")
    if entry.dst_ip and known_asset_ips and entry.dst_ip in known_asset_ips and not dst_external:
        score -= settings.prefilter_penalty_known_asset
        reasons.append("目标为已录资产")

    score = max(0.0, round(score, 3))
    # 召回护栏：明确可疑不受扣分影响；其余必须过门槛
    if not strong and score < settings.prefilter_min_score:
        return None
    return Candidate(log=entry, score=score, reasons=reasons)


def prefilter(
    logs: list[UnifiedLog],
    *,
    scope_cidrs: list[str],
    known_asset_ips: set[str] | None = None,
) -> list[Candidate]:
    """对（已被规则漏掉的）日志打分，按分数降序返回候选（含上限截断）。"""
    if not settings.prefilter_enabled or not logs:
        return []
    scope_nets = build_scope_networks(scope_cidrs)
    assets = known_asset_ips or set()

    scored: list[Candidate] = []
    for entry in logs:
        cand = score_log(entry, scope_nets=scope_nets, known_asset_ips=assets)
        if cand is not None:
            scored.append(cand)

    scored.sort(key=lambda c: c.score, reverse=True)
    limit = settings.prefilter_max_candidates
    if len(scored) > limit:
        log.info("兜底预筛候选 %d 条，按上限截断为 %d", len(scored), limit)
        scored = scored[:limit]
    return scored


def known_asset_ip_set() -> set[str]:
    """已录资产的 IP 集合（含额外 IP），用于「首次出现」判定。"""
    try:
        from sqlalchemy import select

        from app.db.base import SessionLocal
        from app.db.models import Asset

        with SessionLocal() as db:
            rows = db.scalars(select(Asset)).all()
    except Exception as exc:  # noqa: BLE001
        log.warning("读取资产 IP 集合失败: %s", exc)
        return set()

    out: set[str] = set()
    for a in rows:
        if a.ip:
            out.add(str(a.ip))
        for extra in a.extra_ips or []:
            out.add(str(extra))
    return out
