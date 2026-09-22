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

from app.config import settings
from app.schemas import UnifiedLog
from app.workers.log import get_logger

log = get_logger(__name__)

# 已知高风险端口（后门/代理/矿池常用）
SUSPICIOUS_PORTS: set[int] = {
    4444, 4445, 5555, 6666, 6667, 7777, 9001, 9050, 1337, 31337, 12345, 54321, 1080,
}

# 常用端口（不在其中的外联端口更值得关注）
COMMON_PORTS: set[int] = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 137, 138, 139, 143, 161, 162,
    179, 389, 443, 445, 465, 514, 515, 587, 631, 636, 873, 993, 995, 1433, 1521, 1723, 2049,
    2082, 2083, 2181, 2375, 2379, 3000, 3128, 3306, 3389, 4443, 5000, 5432, 5601, 5672, 5900,
    5984, 6000, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9200,
    9300, 9443, 10000, 11211, 27017,
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


def score_log(
    entry: UnifiedLog,
    *,
    scope_nets: list[Any],
    known_asset_ips: set[str],
) -> Candidate | None:
    """启发式打分；低于阈值返回 None。"""
    score = 0.0
    reasons: list[str] = []

    # 1) 高风险端口
    if entry.dst_port in SUSPICIOUS_PORTS:
        score += 0.5
        reasons.append(f"高风险端口 {entry.dst_port}")

    # 2) 非常用端口的成功外联（疑似 C2/后门）
    external = bool(entry.dst_ip) and not _in_networks(entry.dst_ip, scope_nets)
    if entry.dst_port and entry.dst_port not in COMMON_PORTS:
        if entry.event_type in ("conn_established", "generic") or entry.log_type == "conn":
            score += 0.3
            reasons.append(f"非常用端口 {entry.dst_port} 连接")
        if external:
            score += 0.2
            reasons.append("外联非受管网段")

    # 3) 数据外传量
    if entry.bytes_out:
        if entry.bytes_out > settings.prefilter_bytes_out_alert:
            score += 0.6
            reasons.append(f"超大外发流量 {entry.bytes_out} 字节")
        elif entry.bytes_out > settings.prefilter_bytes_out_warn:
            score += 0.3
            reasons.append(f"较大外发流量 {entry.bytes_out} 字节")

    # 4) 异常长 query（DNS 隧道 / 注入 payload）
    if entry.query and len(entry.query) > settings.prefilter_query_len_warn:
        score += 0.3
        reasons.append(f"异常长请求/查询（{len(entry.query)} 字符）")

    # 5) HTTP 服务端错误
    if entry.status_code and entry.status_code >= 500:
        score += 0.2
        reasons.append(f"HTTP {entry.status_code}")

    # 6) 目的 IP 不在已录资产中（首次出现的对象）
    if entry.dst_ip and known_asset_ips and entry.dst_ip not in known_asset_ips and not external:
        score += 0.2
        reasons.append("目标不在已录资产中")

    # 7) Wazuh 中等级别但规则没命中（规则未覆盖的主机事件）
    if entry.source_system == "wazuh" and entry.severity in ("medium", "high", "critical"):
        score += 0.3
        reasons.append(f"未覆盖的 Wazuh {entry.severity} 事件")

    if score < settings.prefilter_min_score:
        return None
    return Candidate(log=entry, score=round(score, 3), reasons=reasons)


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
