"""系统配置路由。"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.config import settings
from app.db.base import get_db
from app.db.models import SystemConfig, User
from app.models.registry import invalidate_model_cache
from app.runtime_config import invalidate as invalidate_runtime_config

router = APIRouter(prefix="/api/config", tags=["config"])

# 可配置键及默认值。默认取环境变量；写入 DB 后 DB 值优先。
# 注意：模型名已固化（MiniMax 国内版，见 registry），不在后台可改列表。
CONFIG_KEYS: dict[str, Any] = {
    # 升级与报告
    "escalate_score_threshold": settings.escalate_score_threshold,
    "report_min_severity": settings.report_min_severity,
    "hitl_enabled": settings.hitl_enabled,
    "hitl_min_severity": settings.hitl_min_severity,
    "baseline_observe_days": settings.baseline_observe_days,
    # RAG（经 runtime_config 即时生效）
    "rag_enabled": settings.rag_enabled,
    "rag_top_k": settings.rag_top_k,
    "rag_min_score": settings.rag_min_score,
    # 技能库与主动探测（经 runtime_config 即时生效）
    "skill_enabled": settings.skill_enabled,
    "intel_enabled": settings.intel_enabled,
    "active_scan_enabled": settings.active_scan_enabled,
    # 边缘模型思考模式（每场景独立开关，经 runtime_config 即时生效；IP 由 /api/edge 管理）
    "edge_thinking.semantic_merge": True,
    "edge_thinking.triage_complex": True,
    "edge_thinking.triage_simple": False,
    # 边缘模型批内并发度（经 runtime_config 即时生效）：上限 16 对齐服务器槽位；
    # 实测并发 8 → 23 次/分、串行仅 ~5，改大即提速（受服务器容量约束）
    "edge_review_concurrency": settings.edge_review_concurrency,
    # 自主取证调查（经 runtime_config 即时生效）
    "investigation_enabled": settings.investigation_enabled,
    "investigation_min_severity": settings.investigation_min_severity,
    "investigation_max_steps": settings.investigation_max_steps,
    "investigation_max_queries": settings.investigation_max_queries,
    "investigation_cooldown_minutes": settings.investigation_cooldown_minutes,
    "investigation_max_rounds_per_day": settings.investigation_max_rounds_per_day,
    # 云端模型并发峰值（经 runtime_config 即时生效）：节点里的"逐个事件组"已改并发，
    # 这是限流闸门——云端有 RPM/TPM 限制，改大要看着 429 调
    "cloud_max_concurrency": settings.cloud_max_concurrency,
    # 兜底预筛（防漏报）：规则未命中的日志经启发式打分后交边缘模型复筛
    # 可热调：实测 0.3 门槛会把大量正常连接（conn_established/generic）当可疑（占其命中 91%），
    # 故抬到 0.5 并开放后台可调
    "prefilter_min_score": settings.prefilter_min_score,
    "prefilter_enabled": settings.prefilter_enabled,
    "prefilter_max_candidates": settings.prefilter_max_candidates,
    # 误报治理策略（经 runtime_config 即时生效）：判据见 app/agents/triage_policy.py
    "policy_internal_routine_skip": settings.policy_internal_routine_skip,
    "policy_internal_routine_min_severity": settings.policy_internal_routine_min_severity,
    "policy_internal_routine_max_dst": settings.policy_internal_routine_max_dst,
    "policy_internal_routine_require_failed": settings.policy_internal_routine_require_failed,
    "severity_cap_internal": settings.severity_cap_internal,
    "severity_require_evidence_above": settings.severity_require_evidence_above,
    "severity_critical_requires_external": settings.severity_critical_requires_external,
    "escalate_require_rule_severity": settings.escalate_require_rule_severity,
    "escalate_allow_external": settings.escalate_allow_external,
    "prefilter_penalty_established": settings.prefilter_penalty_established,
    "prefilter_penalty_known_asset": settings.prefilter_penalty_known_asset,
    "prefilter_penalty_common_port": settings.prefilter_penalty_common_port,
    # 自主调查的模型调用上限（即时生效）：实测 6 会全撞限、产出为空，故抬到 10 并可后台调
    "investigation_max_llm_calls": settings.investigation_max_llm_calls,
}

# 说明：analysis_interval_minutes 不在后台可改列表 —— Celery Beat 调度在启动时读取，
# 改配置不会生效，只能改环境变量并重启 beat。


class ConfigIn(BaseModel):
    value: Any


@router.get("")
def list_config(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    rows = db.scalars(select(SystemConfig)).all()
    stored = {r.key: (r.value or {}).get("value") for r in rows}
    return {"items": {key: stored.get(key, default) for key, default in CONFIG_KEYS.items()}}


@router.put("/{key}")
def update_config(
    key: str,
    body: ConfigIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    if key not in CONFIG_KEYS:
        raise HTTPException(status_code=404, detail="未知配置项")
    row = db.get(SystemConfig, key)
    if row is None:
        row = SystemConfig(key=key, value={})
        db.add(row)
    row.value = {"value": body.value}
    db.commit()
    # 配置项均经 runtime_config 即时生效（模型名已固化，无需失效）
    invalidate_model_cache()
    invalidate_runtime_config()
    return {"key": key, "value": body.value}
