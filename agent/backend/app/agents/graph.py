"""LangGraph 图定义：单入口（实时链路）。

- 实时入口：状态里带 digests（检测器经 Redis 投递队列推送的聚合摘要）
  → realtime_triage → correlate → … → profile_update → END

注：原「兜底入口」（无 digests → ingest 主动拉 ES 水位窗口 → triage）随
「水位兜底全量重放」一起移除（commit d94276c）：单轮过完整图必被 1800s
硬超时，且检测器短窗聚合已覆盖实时检测，兜底入口无调用方。
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from app.agents.deep_analysis import build_deep_analysis_subgraph
from app.agents.nodes import (
    asset_enrich_node,
    correlate_node,
    escalate_route,
    hitl_node,
    hitl_route,
    lookback_node,
    memory_recall_node,
    memory_write_node,
    profile_recall_node,
    profile_update_node,
    realtime_triage_node,
    report_node,
    response_node,
    severity_node,
    skill_enrich_node,
)
from app.agents.state import AgentState


def _wire_tail(g: Any) -> None:
    """挂载「可疑事件已就绪」之后的公共链路（correlate → … → 画像更新）。"""
    g.add_node("correlate", correlate_node)
    g.add_node("asset_enrich", asset_enrich_node)
    g.add_node("memory_recall", memory_recall_node)
    g.add_node("profile_recall", profile_recall_node)
    g.add_node("skill_enrich", skill_enrich_node)
    g.add_node("lookback", lookback_node)
    g.add_node("deep_analysis", build_deep_analysis_subgraph())
    g.add_node("severity", severity_node)
    g.add_node("hitl", hitl_node)
    g.add_node("response", response_node)
    g.add_node("report", report_node)
    g.add_node("memory_write", memory_write_node)
    g.add_node("profile_update", profile_update_node)

    g.add_edge("correlate", "asset_enrich")
    g.add_edge("asset_enrich", "memory_recall")
    g.add_edge("memory_recall", "profile_recall")
    g.add_edge("profile_recall", "skill_enrich")
    # 技能路由后再升级判定：升级组先做回溯，再深度分析；否则直接定级
    g.add_conditional_edges(
        "skill_enrich", escalate_route, {"deep": "lookback", "skip": "severity"}
    )
    g.add_edge("lookback", "deep_analysis")
    g.add_edge("deep_analysis", "severity")
    # HITL：高危需人工确认
    g.add_conditional_edges("severity", hitl_route, {"confirm": "hitl", "pass": "response"})
    g.add_edge("hitl", "response")
    g.add_edge("response", "report")
    # 报告后写入分析记忆（对象级 + 轮次级）与画像基线，并清理过期数据
    g.add_edge("report", "memory_write")
    g.add_edge("memory_write", "profile_update")
    g.add_edge("profile_update", END)


def build_graph(checkpointer: Any = None) -> Any:
    g = StateGraph(AgentState)
    g.add_node("realtime_triage", realtime_triage_node)
    _wire_tail(g)
    g.add_edge(START, "realtime_triage")
    g.add_edge("realtime_triage", "correlate")
    return g.compile(checkpointer=checkpointer)
