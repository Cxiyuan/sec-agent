"""LangGraph 分析节点实现。"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.agents.persistence import (
    get_enabled_rules,
    save_business_context,
    save_groups,
    save_report,
    set_groups_pending,
    update_group_analysis,
)
from app.agents.state import AgentState
from app.config import settings
from app.db.base import SessionLocal
from app.db.models import SystemConfig
from app.ingestion.dedup import dedup_logs
from app.ingestion.es_client import fetch_window_logs
from app.ingestion.normalizer import normalize
from app.models import prompts
from app.models.llm import edge_invoke_json, flash_invoke_json, flash_invoke_text
from app.rag.context import build_business_context, context_text_for_group
from app.rules.engine import match_rule
from app.schemas import EventGroup, SuspiciousEvent, UnifiedLog
from app.workers.log import get_logger

log = get_logger(__name__)

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _now() -> datetime:
    return datetime.now(UTC)


def _config(db: Session, key: str, default: Any) -> Any:
    row = db.get(SystemConfig, key)
    if row and row.value is not None:
        return row.value.get("value", default)
    return default


def _safe_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# ---------- 节点 1：拉取 + 规范化 + 去重 ----------


def ingest_node(state: AgentState) -> dict[str, Any]:
    start = state.get("window_start") or (
        _now() - timedelta(minutes=settings.analysis_window_minutes)
    )
    end = state.get("window_end") or start + timedelta(minutes=settings.analysis_window_minutes)

    raw = fetch_window_logs(start, end)
    logs: list[UnifiedLog] = []
    for source, doc in raw:
        norm = normalize(source, doc)
        if norm is not None:
            logs.append(norm)
    logs = dedup_logs(logs, settings.analysis_window_minutes)
    log.info("窗口 %s ~ %s 拉取日志 %d 条，去重后 %d 条", start, end, len(raw), len(logs))
    return {"window_start": start, "window_end": end, "raw_logs": logs}


# ---------- 节点 2：研判降噪（四层漏斗） ----------


def triage_node(state: AgentState) -> dict[str, Any]:
    logs = state.get("raw_logs", [])
    with SessionLocal() as db:
        rules = get_enabled_rules(db)

    suspicious: list[SuspiciousEvent] = []
    for entry in logs:
        hit = None
        for rule in rules:  # 已按 priority 排序：用户规则 > 内置规则
            if match_rule(rule, entry):
                hit = rule
                break
        if hit is None:
            continue  # 未命中任何规则，视为正常流量

        # 边缘模型审查降噪
        user_prompt = prompts.TRIAGE_USER.format(
            event_type=entry.event_type,
            source_system=entry.source_system,
            src_ip=f"{entry.src_ip}:{entry.src_port}",
            dst_ip=f"{entry.dst_ip}:{entry.dst_port}",
            protocol=entry.protocol,
            hit_rule=hit["name"],
            summary=entry.summary,
            raw=json.dumps(entry.raw, ensure_ascii=False, default=str)[:1500],
        )
        try:
            result = edge_invoke_json(prompts.TRIAGE_SYSTEM, user_prompt)
        except Exception as exc:  # noqa: BLE001
            log.warning("边缘模型研判失败，默认视为可疑: %s", exc)
            result = {"is_suspicious": True, "score": 0.6, "reason": "边缘模型不可用"}

        score = _safe_float(result.get("score"), 0.5)
        is_suspicious = bool(result.get("is_suspicious", True))
        if is_suspicious:
            suspicious.append(
                SuspiciousEvent(
                    log=entry,
                    hit_rule=hit["name"],
                    rule_source=hit["source"],
                    edge_score=score,
                    edge_reason=str(result.get("reason", "")),
                )
            )
    log.info("研判降噪：%d 条日志 -> %d 条可疑事件", len(logs), len(suspicious))
    return {"suspicious_events": suspicious}


# ---------- 节点 3：多源关联（归组） ----------


def _group_fingerprint(ips: set[str], start: datetime) -> str:
    key = "|".join(sorted(ips)) + "|" + start.strftime("%Y%m%d%H%M")
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def correlate_node(state: AgentState) -> dict[str, Any]:
    events = state.get("suspicious_events", [])
    window_start = state.get("window_start") or _now()
    window_end = state.get("window_end") or window_start

    # 确定性归组：按 IP（源或目的）+ 时间窗口做 union-find
    parent: dict[int, int] = {i: i for i in range(len(events))}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    ip_to_idx: dict[str, list[int]] = {}
    for i, ev in enumerate(events):
        for ip in (ev.log.src_ip, ev.log.dst_ip):
            if ip:
                ip_to_idx.setdefault(ip, []).append(i)

    for idxs in ip_to_idx.values():
        for i in range(1, len(idxs)):
            union(idxs[0], idxs[i])

    buckets: dict[int, list[SuspiciousEvent]] = {}
    for i, ev in enumerate(events):
        buckets.setdefault(find(i), []).append(ev)

    groups: list[EventGroup] = []
    for bucket_events in buckets.values():
        src_ips = sorted({e.log.src_ip for e in bucket_events if e.log.src_ip})
        dst_ips = sorted({e.log.dst_ip for e in bucket_events if e.log.dst_ip})
        score = max((e.edge_score for e in bucket_events), default=0.0)
        fp = _group_fingerprint(set(src_ips) | set(dst_ips), window_start)
        groups.append(
            EventGroup(
                fingerprint=fp,
                src_ips=src_ips,
                dst_ips=dst_ips,
                window_start=window_start,
                window_end=window_end,
                events=bucket_events,
                triage_score=score,
                escalate=False,
            )
        )

    # 语义关联（补充）：对高分组之间用边缘模型判断是否同一次攻击（限流）
    groups = _semantic_merge(groups)

    # 升级判定（阈值打分）
    with SessionLocal() as db:
        threshold = _safe_float(
            _config(db, "escalate_score_threshold", settings.escalate_score_threshold),
            settings.escalate_score_threshold,
        )
    for g in groups:
        g.escalate = g.triage_score >= threshold

    # 持久化事件组，供后台/驾驶舱即时可见
    save_groups(groups, state.get("thread_id", ""))
    log.info(
        "关联归组：%d 个事件组，其中升级 %d 个", len(groups), sum(1 for g in groups if g.escalate)
    )
    return {"groups": groups}


def _semantic_merge(groups: list[EventGroup], max_calls: int = 20) -> list[EventGroup]:
    """边缘模型语义关联：高分且无共享 IP 的组，判断是否同一次攻击。"""
    if len(groups) < 2:
        return groups
    high = [g for g in groups if g.triage_score >= 0.5]
    merged = set()
    calls = 0
    for i in range(len(high)):
        for j in range(i + 1, len(high)):
            if calls >= max_calls:
                return groups
            a, b = high[i], high[j]
            if set(a.src_ips) & set(b.src_ips) or set(a.dst_ips) & set(b.dst_ips):
                continue
            calls += 1
            try:
                r = edge_invoke_json(
                    prompts.GROUP_SEMANTIC_SYSTEM,
                    prompts.GROUP_SEMANTIC_USER.format(
                        event_a=json.dumps(
                            [e.log.summary for e in a.events[:5]], ensure_ascii=False
                        ),
                        event_b=json.dumps(
                            [e.log.summary for e in b.events[:5]], ensure_ascii=False
                        ),
                    ),
                )
                if r.get("same_attack"):
                    merged.add(j)
                    a.events.extend(b.events)
                    a.src_ips = sorted(set(a.src_ips) | set(b.src_ips))
                    a.dst_ips = sorted(set(a.dst_ips) | set(b.dst_ips))
                    a.triage_score = max(a.triage_score, b.triage_score)
            except Exception as exc:  # noqa: BLE001
                log.warning("语义关联失败: %s", exc)
                continue
    if merged:
        groups = [g for idx, g in enumerate(groups) if idx not in merged]
    return groups


# ---------- 节点 3.5：资产背景富化（RAG） ----------


def asset_enrich_node(state: AgentState) -> dict[str, Any]:
    """对每个事件组的局域网 IP 做混合检索，生成业务背景。"""
    groups = state.get("groups", [])
    contexts: dict[str, dict[str, Any]] = {}
    for g in groups:
        query = " ".join(e.log.summary for e in g.events[:10] if e.log.summary)
        try:
            ctx = build_business_context(g.src_ips, g.dst_ips, query)
        except Exception as exc:  # noqa: BLE001
            log.warning("资产背景检索失败 %s: %s", g.fingerprint, exc)
            ctx = {"lan_ips": [], "assets": [], "knowledge": [], "text": ""}
        contexts[g.fingerprint] = ctx
        g.business_context = ctx
    if contexts:
        save_business_context(contexts)
        log.info("资产背景富化：%d 个事件组", len(contexts))
    return {"business_context": contexts}


# ---------- 节点 4：云端深度分析（子图，见 deep_analysis.py） ----------

# ---------- 节点 5：定级 ----------


def severity_node(state: AgentState) -> dict[str, Any]:
    groups = state.get("groups", [])
    analyses = state.get("analyses", {})
    for g in groups:
        rule_severity = "info"
        for ev in g.events:
            if (
                ev.log.severity in SEVERITY_RANK
                and SEVERITY_RANK[ev.log.severity] > SEVERITY_RANK[rule_severity]
            ):
                rule_severity = ev.log.severity
        chain = (analyses.get(g.fingerprint) or {}).get("attack_chain", {})
        profile = (analyses.get(g.fingerprint) or {}).get("profile", {})
        context_text = context_text_for_group(
            g, state.get("business_context", {}).get(g.fingerprint)
        )
        try:
            r = flash_invoke_json(
                prompts.SEVERITY_SYSTEM,
                prompts.SEVERITY_USER.format(
                    chain=json.dumps(chain, ensure_ascii=False, default=str),
                    profile=json.dumps(profile, ensure_ascii=False, default=str),
                    rule_severity=rule_severity,
                    business_context=context_text,
                ),
            )
            severity = r.get("severity", rule_severity)
        except Exception as exc:  # noqa: BLE001
            log.warning("云端定级失败，回退规则定级: %s", exc)
            severity = rule_severity
        if severity not in SEVERITY_RANK:
            severity = rule_severity
        update_group_analysis(g.fingerprint, severity=severity)
        g.severity = severity  # type: ignore[assignment]
    return {"groups": groups}


# ---------- HITL 节点 ----------


def hitl_node(state: AgentState) -> dict[str, Any]:
    from langgraph.types import interrupt

    with SessionLocal() as db:
        enabled = bool(_config(db, "hitl_enabled", settings.hitl_enabled))
        min_sev = str(_config(db, "hitl_min_severity", settings.hitl_min_severity))

    groups = state.get("groups", [])
    pending = [
        g
        for g in groups
        if (g.severity or "info") in SEVERITY_RANK
        and SEVERITY_RANK[g.severity or "info"] >= SEVERITY_RANK.get(min_sev, 3)
    ]

    if not enabled or not pending:
        return {}

    set_groups_pending([g.fingerprint for g in pending])
    decision = interrupt(
        {
            "message": "存在高危事件，等待人工确认",
            "pending": [
                {
                    "fingerprint": g.fingerprint,
                    "severity": g.severity,
                    "src_ips": g.src_ips,
                    "dst_ips": g.dst_ips,
                }
                for g in pending
            ],
        }
    )
    confirmations = decision.get("confirmations", {}) if isinstance(decision, dict) else {}
    return {"confirmations": confirmations}


# ---------- 节点 6：处置建议 ----------


def response_node(state: AgentState) -> dict[str, Any]:
    groups = state.get("groups", [])
    analyses = state.get("analyses", {})
    confirmations = state.get("confirmations", {})
    for g in groups:
        if confirmations.get(g.fingerprint) == "dismiss":
            update_group_analysis(g.fingerprint, status="dismissed")
            continue
        chain = (analyses.get(g.fingerprint) or {}).get("attack_chain", {})
        profile = (analyses.get(g.fingerprint) or {}).get("profile", {})
        context_text = context_text_for_group(
            g, state.get("business_context", {}).get(g.fingerprint)
        )
        try:
            r = flash_invoke_json(
                prompts.RESPONSE_SYSTEM,
                prompts.RESPONSE_USER.format(
                    severity=g.severity,
                    chain=json.dumps(chain, ensure_ascii=False, default=str),
                    profile=json.dumps(profile, ensure_ascii=False, default=str),
                    business_context=context_text,
                ),
            )
            suggestions = r.get("suggestions", [])
        except Exception as exc:  # noqa: BLE001
            log.warning("处置建议生成失败: %s", exc)
            suggestions = [
                {"category": "incident_response", "action": "人工复核", "detail": "模型不可用"}
            ]
        update_group_analysis(g.fingerprint, response_suggestions=suggestions)
    return {}


# ---------- 节点 7：报告输出 ----------


def _report_body(g: Any, analysis: dict[str, Any]) -> str:
    """用 flash 生成报告正文；失败返回空串（不阻断报告生成）。"""
    try:
        overview = {
            "src_ips": g.src_ips,
            "dst_ips": g.dst_ips,
            "severity": g.severity,
            "event_count": len(g.events),
            "window_start": g.window_start.isoformat() if g.window_start else None,
            "window_end": g.window_end.isoformat() if g.window_end else None,
        }
        return flash_invoke_text(
            prompts.REPORT_SYSTEM,
            prompts.REPORT_USER.format(
                overview=json.dumps(overview, ensure_ascii=False, default=str),
                chain=json.dumps(
                    analysis.get("attack_chain", {}), ensure_ascii=False, default=str
                ),
                profile=json.dumps(analysis.get("profile", {}), ensure_ascii=False, default=str),
                suggestions=json.dumps(
                    g.response_suggestions or [], ensure_ascii=False, default=str
                ),
            ),
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("报告正文生成失败（不影响报告输出）: %s", exc)
        return ""


def report_node(state: AgentState) -> dict[str, Any]:
    from app.reports.render import render_report

    groups = state.get("groups", [])
    analyses = state.get("analyses", {})
    confirmations = state.get("confirmations", {})
    with SessionLocal() as db:
        min_sev = str(_config(db, "report_min_severity", settings.report_min_severity))

    summary = {"total_groups": len(groups), "reports": 0}
    for g in groups:
        if confirmations.get(g.fingerprint) == "dismiss":
            continue
        sev = g.severity or "info"
        if SEVERITY_RANK.get(sev, 0) < SEVERITY_RANK.get(min_sev, 2):
            continue
        analysis = analyses.get(g.fingerprint) or {}
        body = _report_body(g, analysis)
        html, pdf_path = render_report(g, analysis, body)
        save_report(g.fingerprint, f"安全事件报告 - {sev}", sev, html, pdf_path)
        summary["reports"] += 1

    log.info("报告输出：%s", summary)
    return {"run_summary": summary}


# ---------- 条件路由 ----------


def escalate_route(state: AgentState) -> str:
    groups = state.get("groups", [])
    return "deep" if any(g.escalate for g in groups) else "skip"


def hitl_route(state: AgentState) -> str:
    from langgraph.types import interrupt  # noqa: F401  (仅占位说明)

    with SessionLocal() as db:
        enabled = bool(_config(db, "hitl_enabled", settings.hitl_enabled))
    if not enabled:
        return "pass"
    groups = state.get("groups", [])
    with SessionLocal() as db:
        min_sev = str(_config(db, "hitl_min_severity", settings.hitl_min_severity))
    for g in groups:
        sev = g.severity or "info"
        if SEVERITY_RANK.get(sev, 0) >= SEVERITY_RANK.get(min_sev, 3):
            return "confirm"
    return "pass"
