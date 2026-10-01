"""云端深度分析子图：异常检测、攻击链还原、攻击者画像 三个子节点。"""

from __future__ import annotations

import json
from typing import Any

from langgraph.graph import END, START, StateGraph

from app.agents.baseline_labels import candidates_of, text_of
from app.agents.concurrency import cloud_concurrency, parallel_map
from app.agents.memory import memory_text
from app.agents.nodes import skill_context_text
from app.agents.persistence import update_group_analysis
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
    """组级基线标签的文本（第 8 期起由 NDR 在摘要上打标，这里只渲染）。"""
    for g in state.get("groups", []):
        if g.fingerprint == fingerprint:
            return text_of((g.aggregate or {}).get("baseline"))
    return text_of(None)


# ---------- 4.1 异常检测（统计 + LLM） ----------


def anomaly_node(state: AgentState) -> dict[str, Any]:
    """异常确认：读 NDR 打好的 2σ 候选 → **并发**调云端确认 → 按组汇总。

    为什么并发：一个组最多 10 个候选，原先逐个等云端回话，一组就是 10 次串行等待。
    候选与基线（均值/标准差）都由 NDR 侧算好写在摘要里 —— 这里不再读日志、不再更新基线。
    """
    analyses = dict(state.get("analyses", {}))
    ctx_map = state.get("business_context", {})
    groups = _escalating_groups(state)
    pending: list[tuple[str, dict[str, Any], str]] = []  # (组指纹, 候选, 提示词)
    for g in groups:
        candidates = candidates_of((g.aggregate or {}).get("baseline"))
        group_summary = json.dumps([e.log.summary for e in g.events[:10]], ensure_ascii=False)
        memory_blob = _memory_blob(state, g.fingerprint)
        lookback_blob = _lookback_blob(state, g.fingerprint)
        profile_blob = _profile_blob(state, g.fingerprint)
        skill_blob = skill_context_text(g, state.get("skill_context") or {})
        context_text = context_text_for_group(g, ctx_map.get(g.fingerprint))
        for cand in candidates[:10]:  # 限制确认次数
            pending.append(
                (
                    g.fingerprint,
                    cand,
                    prompts.ANOMALY_CONFIRM_USER.format(
                        candidate=json.dumps(cand, ensure_ascii=False),
                        group_summary=group_summary,
                        business_context=context_text,
                        memory=memory_blob,
                        lookback=lookback_blob,
                        entity_profile=profile_blob,
                        skill=skill_blob,
                    ),
                )
            )

    def ask(item: tuple[str, dict[str, Any], str]) -> tuple[str, dict[str, Any] | None]:
        fingerprint, cand, user_prompt = item
        try:
            r = flash_invoke_json(prompts.ANOMALY_CONFIRM_SYSTEM, user_prompt)
        except Exception as exc:  # noqa: BLE001
            log.warning("异常检测确认失败: %s", exc)
            return fingerprint, None
        if not r.get("is_anomaly"):
            return fingerprint, None
        return fingerprint, {"candidate": cand, "kind": r.get("kind"), "reason": r.get("reason")}

    findings: dict[str, list[dict[str, Any]]] = {}
    for fingerprint, finding in parallel_map(
        ask, pending, "cloud-anomaly", workers=cloud_concurrency()
    ):
        if finding is not None:
            findings.setdefault(fingerprint, []).append(finding)
    # 与原来一致：每个升级组都写 anomaly 字段（无发现则为空列表）
    for g in groups:
        analyses.setdefault(g.fingerprint, {})["anomaly"] = {
            "findings": findings.get(g.fingerprint, [])
        }
    return {"analyses": analyses}


# ---------- 4.2 攻击链还原（4 阶段，强制挂证据） ----------


def attack_chain_node(state: AgentState) -> dict[str, Any]:
    """攻击链还原：并发调云端（deep）→ 再按原顺序强制挂证据。

    并发收益最大（deep 单次最慢），且组与组之间无依赖。
    """
    analyses = dict(state.get("analyses", {}))
    groups = _escalating_groups(state)
    pending: list[tuple[Any, str]] = []  # (组, 提示词)
    for g in groups:
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
        context_text = context_text_for_group(
            g, state.get("business_context", {}).get(g.fingerprint)
        )
        pending.append(
            (
                g,
                prompts.ATTACK_CHAIN_USER.format(
                    timeline=json.dumps(timeline, ensure_ascii=False, default=str),
                    business_context=context_text,
                    memory=_memory_blob(state, g.fingerprint),
                    lookback=_lookback_blob(state, g.fingerprint),
                    entity_profile=_profile_blob(state, g.fingerprint),
                    skill=skill_context_text(g, state.get("skill_context") or {}),
                ),
            )
        )

    def ask(item: tuple[Any, str]) -> dict[str, Any]:
        _g, user_prompt = item
        try:
            return deep_invoke_json(prompts.ATTACK_CHAIN_SYSTEM, user_prompt)
        except Exception as exc:  # noqa: BLE001
            log.warning("攻击链还原失败: %s", exc)
            return {}

    for (g, _prompt), r in zip(
        pending,
        parallel_map(ask, pending, "cloud-chain", workers=cloud_concurrency()),
        strict=False,
    ):
        raw_stages = r.get("stages")
        stages = raw_stages if isinstance(raw_stages, list) else []

        # 强制挂证据：evidence_ids 必须映射回真实日志，否则丢弃该阶段
        id_to_ev = {i: ev for i, ev in enumerate(g.events)}
        valid_stages = []
        for st in stages:
            if not isinstance(st, dict):
                continue
            stage = st.get("stage", "")
            if stage not in KILLCHAIN_STAGES:
                continue
            evidence = []
            raw_ids = st.get("evidence_ids")
            for eid in raw_ids if isinstance(raw_ids, list) else []:
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
    """攻击者画像：并发调云端（deep）；情报富化（enrich_profile）也在并发单元内。

    情报富化是外部 HTTP（免费源、带缓存），放在同一并发单元里能一并把等待时间压掉。
    """
    analyses = dict(state.get("analyses", {}))
    groups = _escalating_groups(state)
    pending: list[tuple[Any, str]] = []  # (组, 提示词)
    for g in groups:
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
        pending.append(
            (
                g,
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
        )

    def ask(item: tuple[Any, str]) -> dict[str, Any]:
        g, user_prompt = item
        try:
            r = deep_invoke_json(prompts.PROFILE_SYSTEM, user_prompt)
            return {"basic": r.get("basic", {}), "behavior": r.get("behavior", {})}
        except Exception as exc:  # noqa: BLE001
            log.warning("攻击者画像失败: %s", exc)
            return {"basic": {"src_ips": g.src_ips}, "behavior": {}}

    for (g, _prompt), profile in zip(
        pending,
        parallel_map(ask, pending, "cloud-profile", workers=cloud_concurrency()),
        strict=False,
    ):
        analyses.setdefault(g.fingerprint, {})["profile"] = profile
        # 把三种深度分析结果落库。
        # 为什么必须在这里写：图状态里的 analyses **不会自动进数据库**，而
        # update_group_analysis 虽然支持 attack_chain/profile/anomaly 三个参数，
        # 之前**没有任何调用点传它们** → 界面与报告里攻击链/画像永远是空的，
        # 等于花了两次 deep 调用的钱把结果丢掉（部署后实測：攻击链非空 = 0）。
        entry = analyses.get(g.fingerprint) or {}
        try:
            update_group_analysis(
                g.fingerprint,
                attack_chain=entry.get("attack_chain") or None,
                profile=profile,
                anomaly=entry.get("anomaly") or None,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("深度分析结果落库失败 %s: %s", g.fingerprint, exc)
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
