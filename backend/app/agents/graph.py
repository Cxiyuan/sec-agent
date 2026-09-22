"""LangGraph 主图定义：主流水线 + 条件分支 + 深度分析子图 + HITL。"""

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
    ingest_node,
    report_node,
    response_node,
    severity_node,
    triage_node,
)
from app.agents.state import AgentState


def build_graph(checkpointer: Any = None) -> Any:
    g = StateGraph(AgentState)
    g.add_node("ingest", ingest_node)
    g.add_node("triage", triage_node)
    g.add_node("correlate", correlate_node)
    g.add_node("asset_enrich", asset_enrich_node)
    g.add_node("deep_analysis", build_deep_analysis_subgraph())
    g.add_node("severity", severity_node)
    g.add_node("hitl", hitl_node)
    g.add_node("response", response_node)
    g.add_node("report", report_node)

    g.add_edge(START, "ingest")
    g.add_edge("ingest", "triage")
    g.add_edge("triage", "correlate")
    g.add_edge("correlate", "asset_enrich")
    # 升级判定：有升级组走深度分析，否则跳过
    g.add_conditional_edges(
        "asset_enrich", escalate_route, {"deep": "deep_analysis", "skip": "severity"}
    )
    g.add_edge("deep_analysis", "severity")
    # HITL：高危需人工确认
    g.add_conditional_edges("severity", hitl_route, {"confirm": "hitl", "pass": "response"})
    g.add_edge("hitl", "response")
    g.add_edge("response", "report")
    g.add_edge("report", END)

    return g.compile(checkpointer=checkpointer)
