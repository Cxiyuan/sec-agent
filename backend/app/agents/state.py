"""LangGraph 图状态（TypedDict，字段可部分更新）。"""

from __future__ import annotations

from datetime import datetime
from typing import Any, TypedDict

from app.schemas import EventGroup, SuspiciousEvent, UnifiedLog


class AgentState(TypedDict, total=False):
    window_start: datetime
    window_end: datetime
    thread_id: str
    raw_logs: list[UnifiedLog]
    suspicious_events: list[SuspiciousEvent]
    groups: list[EventGroup]
    # fingerprint -> 业务背景 {lan_ips, assets, knowledge, text}
    business_context: dict[str, dict[str, Any]]
    # fingerprint -> 深度分析结果 {"anomaly":..., "attack_chain":..., "profile":...}
    analyses: dict[str, dict[str, Any]]
    # fingerprint -> "confirm" | "dismiss"
    confirmations: dict[str, str]
    run_summary: dict[str, Any]
