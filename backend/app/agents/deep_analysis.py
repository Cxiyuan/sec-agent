"""云端深度分析子图：异常检测、攻击链还原、攻击者画像 三个子节点。"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from langgraph.graph import END, START, StateGraph

from app.agents.memory import memory_text
from app.agents.nodes import skill_context_text
from app.agents.persistence import get_baseline, update_baseline
from app.agents.profile import profile_text
from app.agents.state import AgentState
from app.intel.threat_intel import enrich_profile
from app.models import prompts
from app.models.llm import deep_invoke_json, flash_invoke_json
from app.rag.context import context_text_for_group
from app.workers.log import get_logger

log = get_logger(__name__)

KILLCHAIN_STAGES = ["侦察", "入侵", "横向", "外泄"]


def _safe_int(value: Any) -> int | None:
    """安全转 int，非法值返回 None。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _escalating_groups(state: AgentState) -> list[Any]:
    return [g for g in state.get("groups", []) if g.escalate]


def _memory_blob(state: AgentState, fingerprint: str) -> str:
    return memory_text((state.get("memory") or {}).get(fingerprint) or {})


def _lookback_blob(state: AgentState, fingerprint: str) -> str:
    entry = (state.get("lookback") or {}).get(fingerprint) or {}
    return str(entry.get("summary") or "（无回溯）")


def _profile_blob(state: AgentState, fingerprint: str) -> str:
    info = ((state.get("profile") or {}).get("by_group") or {}).get(fingerprint)
    return profile_text(info)


# ---------- 4.1 异常检测（统计 + LLM） ----------


def _stat_features(g: Any) -> dict[str, float]:
    """按源 IP 统计网络侧特征。"""
    by_src: dict[str, Counter] = {}
    for ev in g.events:
        if not ev.log.src_ip:
            continue
        c = by_src.setdefault(ev.log.src_ip, Counter())
        c["conn_count"] += 1
        if ev.log.dst_port:
            c[f"dst_port:{ev.log.dst_port}"] += 1
        if ev.log.dst_ip:
            c[f"dst_ip:{ev.log.dst_ip}"] += 1

    features: dict[str, float] = {}
    for src, c in by_src.items():
        # Counter 值均为 int，无需 float() 包装（int 可直接赋给 float 字典）
        features[f"{src}:conn_count"] = c["conn_count"]
        features[f"{src}:distinct_dst_ports"] = sum(1 for k in c if k.startswith("dst_port:"))
        features[f"{src}:distinct_dst_ips"] = sum(1 for k in c if k.startswith("dst_ip:"))
    return features


def _detect_candidates(features: dict[str, float]) -> list[dict[str, Any]]:
    """统计基线比对：超过 2 个标准差即候选异常，并更新滚动基线。"""
    candidates = []
    for key, value in features.items():
        base = get_baseline(key)
        if base and base["std"] > 0 and value > base["mean"] + 2 * base["std"]:
            candidates.append(
                {"key": key, "value": value, "mean": base["mean"], "std": base["std"]}
            )
        update_baseline(key, value)
    return candidates


def anomaly_node(state: AgentState) -> dict[str, Any]:
    analyses = dict(state.get("analyses", {}))
    ctx_map = state.get("business_context", {})
    for g in _escalating_groups(state):
        features = _stat_features(g)
        candidates = _detect_candidates(features)
        findings: list[dict[str, Any]] = []
        context_text = context_text_for_group(g, ctx_map.get(g.fingerprint))
        for cand in candidates[:10]:  # 限制确认次数
            try:
                r = flash_invoke_json(
                    prompts.ANOMALY_CONFIRM_SYSTEM,
                    prompts.ANOMALY_CONFIRM_USER.format(
                        candidate=json.dumps(cand, ensure_ascii=False),
                        group_summary=json.dumps(
                            [e.log.summary for e in g.events[:10]], ensure_ascii=False
                        ),
                        business_context=context_text,
                        memory=_memory_blob(state, g.fingerprint),
                        lookback=_lookback_blob(state, g.fingerprint),
                        entity_profile=_profile_blob(state, g.fingerprint),
                        skill=skill_context_text(g, state.get("skill_context") or {}),
                    ),
                )
                if r.get("is_anomaly"):
                    findings.append(
                        {"candidate": cand, "kind": r.get("kind"), "reason": r.get("reason")}
                    )
            except Exception as exc:  # noqa: BLE001
                log.warning("异常检测确认失败: %s", exc)
        analyses.setdefault(g.fingerprint, {})["anomaly"] = {"findings": findings}
    return {"analyses": analyses}


# ---------- 4.2 攻击链还原（4 阶段，强制挂证据） ----------


def attack_chain_node(state: AgentState) -> dict[str, Any]:
    analyses = dict(state.get("analyses", {}))
    for g in _escalating_groups(state):
        timeline = [
            {
                "id": i,
                "type": ev.log.event_type,
                "src": f"{ev.log.src_ip}:{ev.log.src_port}",
                "dst": f"{ev.log.dst_ip}:{ev.log.dst_port}",
                "summary": ev.log.summary,
            }
            for i, ev in enumerate(g.events[:50])
        ]
        r: dict[str, Any] = {}
        context_text = context_text_for_group(
            g, state.get("business_context", {}).get(g.fingerprint)
        )
        try:
            r = deep_invoke_json(
                prompts.ATTACK_CHAIN_SYSTEM,
                prompts.ATTACK_CHAIN_USER.format(
                    timeline=json.dumps(timeline, ensure_ascii=False, default=str),
                    business_context=context_text,
                    memory=_memory_blob(state, g.fingerprint),
                    lookback=_lookback_blob(state, g.fingerprint),
                    entity_profile=_profile_blob(state, g.fingerprint),
                    skill=skill_context_text(g, state.get("skill_context") or {}),
                ),
            )
            stages = r.get("stages", [])
        except Exception as exc:  # noqa: BLE001
            log.warning("攻击链还原失败: %s", exc)
            stages = []

        # 强制挂证据：evidence_ids 必须映射回真实日志，否则丢弃该阶段
        id_to_ev = {i: ev for i, ev in enumerate(g.events)}
        valid_stages = []
        for st in stages:
            stage = st.get("stage", "")
            if stage not in KILLCHAIN_STAGES:
                continue
            evidence = []
            for eid in st.get("evidence_ids", []):
                eid_int = _safe_int(eid)
                ev = id_to_ev.get(eid_int) if eid_int is not None else None
                if ev is not None:
                    evidence.append(
                        {
                            "id": eid,
                            "type": ev.log.event_type,
                            "src": ev.log.src_ip,
                            "dst": ev.log.dst_ip,
                            "summary": ev.log.summary,
                        }
                    )
            if evidence:  # 无证据阶段不保留
                valid_stages.append(
                    {"stage": stage, "description": st.get("description", ""), "evidence": evidence}
                )

        analyses.setdefault(g.fingerprint, {})["attack_chain"] = {
            "stages": valid_stages,
            "confidence": r.get("confidence", 0.0),
            "summary": r.get("summary", ""),
        }
    return {"analyses": analyses}


# ---------- 4.3 攻击者画像（基础 + 行为，历史 + 情报） ----------


def profile_node(state: AgentState) -> dict[str, Any]:
    analyses = dict(state.get("analyses", {}))
    for g in _escalating_groups(state):
        intel = enrich_profile(g.src_ips)
        logs = [
            {
                "type": e.log.event_type,
                "src": e.log.src_ip,
                "dst": e.log.dst_ip,
                "summary": e.log.summary,
            }
            for e in g.events[:50]
        ]
        try:
            r = deep_invoke_json(
                prompts.PROFILE_SYSTEM,
                prompts.PROFILE_USER.format(
                    logs=json.dumps(logs, ensure_ascii=False, default=str),
                    history="{}",  # 历史行为可由 ES 历史查询补充，此处留空
                    intel=json.dumps(intel, ensure_ascii=False, default=str),
                    business_context=context_text_for_group(
                        g, state.get("business_context", {}).get(g.fingerprint)
                    ),
                    memory=_memory_blob(state, g.fingerprint),
                    lookback=_lookback_blob(state, g.fingerprint),
                    entity_profile=_profile_blob(state, g.fingerprint),
                    skill=skill_context_text(g, state.get("skill_context") or {}),
                ),
            )
            profile = {"basic": r.get("basic", {}), "behavior": r.get("behavior", {})}
        except Exception as exc:  # noqa: BLE001
            log.warning("攻击者画像失败: %s", exc)
            profile = {"basic": {"src_ips": g.src_ips}, "behavior": {}}
        analyses.setdefault(g.fingerprint, {})["profile"] = profile
    return {"analyses": analyses}


# ---------- 子图 ----------


def build_deep_analysis_subgraph() -> Any:
    sg = StateGraph(AgentState)
    sg.add_node("anomaly", anomaly_node)
    sg.add_node("attack_chain", attack_chain_node)
    sg.add_node("profile", profile_node)
    sg.add_edge(START, "anomaly")
    sg.add_edge("anomaly", "attack_chain")
    sg.add_edge("attack_chain", "profile")
    sg.add_edge("profile", END)
    return sg.compile()
