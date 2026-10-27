"""精准抑制接口：智能体给出可核验证据后自动生效，这里管登记、审计与撤销。

匹配口径是**结构化条件树**（复用规则引擎的 `{logic, rules:[{field, op, value}]}`），
字段白名单见 `suppression.ALLOWED_FIELDS`，至少 **2 个独立维度**（下限锁死）。
被抑制的现象：`mode=suppress` 时**不再生成命中事件**、不再派工、不再门铃；
`mode=record_only`（影响面过大 / 自动生效已关闭）时事件仍生成，只是不派工不推送。

原始数据（ES）**永不**被抑制影响：抑制错了也能用日志检索与原始证据事后重建。
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.base import get_db
from app.db.models import AnalysisSuppression, ExclusionFilter, User
from app.detector import suppression
from app.ingestion import exclusion
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/suppressions", tags=["suppressions"])

HINT = (
    "抑制条件用结构化条件树（field/op/value），至少两个独立维度："
    "只写一条签名或一条规则等于关掉一条检测规则，接口会拒绝。"
    "默认 14 天到期、可随时撤销；影响面过大（近 7 天命中/源数/网段数超阈值）会自动降级成"
    "「只不派工、事件仍生成」，不会静默掉一整类流量。"
)


class SuppressionIn(BaseModel):
    """新建/修改的字段。`match` 是条件树，字段清单见 `GET /api/suppressions/config`。"""

    name: str = Field(default="", max_length=128)
    #: `{"logic": "and", "rules": [{"field": "signature_id", "op": "eq", "value": "9110004"}, ...]}`
    match: dict[str, Any] = Field(default_factory=dict)
    reason_code: str = Field(default="", max_length=32)
    note: str = Field(default="", max_length=500)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    ttl_days: int | None = Field(default=None, ge=1, le=30)


class RevokeIn(BaseModel):
    reason: str = Field(default="", max_length=200)


class ConfigIn(BaseModel):
    """参数保存：只接受白名单键（`suppression.*`），校验不过返回 400 + `field_errors`。"""

    values: dict[str, Any] = Field(default_factory=dict)


class ConfigResetIn(BaseModel):
    keys: list[str] = Field(default_factory=list)


class PreviewIn(BaseModel):
    """试算请求：只给条件树，不落库。"""

    match: dict[str, Any] = Field(default_factory=dict)


class ToExclusionIn(BaseModel):
    """转人工排除规则的选项：默认生成**停用**草稿，人审后启用。"""

    enabled: bool = False


def _field_errors(errors: list[dict[str, str]]) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={
            "conflict": "field_error",
            "detail": errors[0]["msg"] if errors else "参数不合法",
            "field_errors": errors,
        },
    )


@router.get("")
def list_suppressions(
    _: Annotated[User, Depends(get_current_user)],
    q: str = "",
    enabled_only: bool = False,
    include_expired: bool = False,
    limit: int = 100,
    offset: int = 0,
):
    """抑制清单（按命中数降序：吞得多的最需要复核）。"""
    return suppression.list_items(
        q=q,
        enabled_only=enabled_only,
        include_expired=include_expired,
        limit=limit,
        offset=offset,
    )


@router.get("/stats")
def suppression_stats(_: Annotated[User, Depends(get_current_user)]):
    """总览：活跃/过期/已撤销、累计抑制量、两种 mode 分布、当前门槛与允许字段。"""
    return suppression.stats()


@router.get("/config")
def get_config(_: Annotated[User, Depends(get_current_user)]):
    """参数清单 + 当前生效值 + 理由码 + 允许的匹配字段（界面表单全靠它渲染）。"""
    return {
        "items": suppression.items(),
        "effective": suppression.effective(),
        "reason_codes": suppression.REASON_CODES,
        "allowed_fields": suppression.ALLOWED_FIELDS,
        "hint": HINT,
    }


@router.put("/config")
def save_config(
    payload: ConfigIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """保存参数（改完立刻生效：运行时配置缓存与抑制表缓存同时失效）。"""
    values = payload.values or {}
    if not values:
        return JSONResponse(
            status_code=400, content={"conflict": "field_error", "detail": "没有要保存的参数"}
        )
    errors = suppression.validate_config(values)
    if errors:
        return _field_errors(errors)
    written = suppression.save_config(db, values)
    log.info("抑制参数已更新：%d 项（%s）", written, ", ".join(sorted(values)))
    return {"written": written, "items": suppression.items(), "effective": suppression.effective()}


@router.post("/config/reset")
def reset_config(
    payload: ConfigResetIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """恢复默认（`keys` 为空 = 全部恢复）。"""
    removed = suppression.reset_config(db, payload.keys or None)
    return {"removed": removed, "items": suppression.items(), "effective": suppression.effective()}


@router.post("/preview")
def preview_impact(payload: PreviewIn, _: Annotated[User, Depends(get_current_user)]):
    """**新建前试算**：近 N 天同类命中量/源数/网段数，以及会被判成哪种 mode。

    用 POST 而不是 GET：条件树是嵌套结构，塞进查询串既难读也容易被截断。
    界面在提交前调它，就能先告诉运维"这个条件太宽，只会降级成只不派工"。
    """
    match = payload.match or {}
    errors = [e for e in suppression.validate_match(match) if e["field"] == "match"]
    if errors:
        return _field_errors(errors)
    trial = suppression.estimate_trial(match)
    return {
        "trial": trial,
        "mode": suppression.choose_mode(trial),
        "mode_label": (
            "完全不生成事件"
            if suppression.choose_mode(trial) == suppression.MODE_SUPPRESS
            else "只不派工（事件保留）"
        ),
        "thresholds": {
            "trial_days": suppression.trial_days(),
            "max_hits": suppression.trial_max_hits(),
            "max_srcs": suppression.trial_max_srcs(),
            "max_segments": suppression.trial_max_segments(),
            "min_match_dims": suppression.min_match_dims(),
        },
    }


@router.post("")
def create_suppression(
    body: SuppressionIn,
    user: Annotated[User, Depends(get_current_user)],
):
    """新建抑制条目（界面手工建与智能体回写走**同一套**校验与试算）。"""
    payload = body.model_dump()
    payload["origin"] = suppression.ORIGIN_UI
    errors = suppression.validate_item(payload)
    if errors:
        return _field_errors(errors)
    try:
        out = suppression.create_item(
            payload,
            created_by=getattr(user, "username", "") or "",
            origin=suppression.ORIGIN_UI,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return out


@router.put("/{item_id}")
def update_suppression(
    item_id: str,
    body: SuppressionIn,
    _: Annotated[User, Depends(get_current_user)],
):
    """修改条件/理由/有效期（改了 `match` 会**重新试算**并按结果调整 mode）。"""
    existing = suppression.get_item(item_id)
    if "error" in existing:
        raise HTTPException(status_code=404, detail=existing["error"])
    merged: dict[str, Any] = {
        "name": existing.get("name") or "",
        "match": existing.get("match") or {},
        "reason_code": existing.get("reason_code") or "",
        "evidence_refs": existing.get("evidence_refs") or [],
        **body.model_dump(exclude_defaults=True),
    }
    errors = suppression.validate_item(merged)
    if errors:
        return _field_errors(errors)
    out = suppression.update_item(item_id, merged)
    if "error" in out:
        raise HTTPException(status_code=404, detail=out["error"])
    if "field_errors" in out:
        return _field_errors(out["field_errors"])
    return out


@router.post("/{item_id}/revoke")
def revoke_suppression(
    item_id: str,
    body: RevokeIn,
    _: Annotated[User, Depends(get_current_user)],
):
    """撤销（立即失效、留原因与时间）。抑制是自动生效的，撤销就是它的兜底手段。"""
    out = suppression.set_enabled(item_id, enabled=False, reason=body.reason)
    if "error" in out:
        raise HTTPException(status_code=404, detail=out["error"])
    return out


@router.post("/{item_id}/restore")
def restore_suppression(
    item_id: str,
    _: Annotated[User, Depends(get_current_user)],
):
    """重新启用一条被撤销的抑制。"""
    out = suppression.set_enabled(item_id, enabled=True)
    if "error" in out:
        raise HTTPException(status_code=404, detail=out["error"])
    return out


@router.post("/{item_id}/to-exclusion")
def to_exclusion(
    item_id: str,
    _: Annotated[User, Depends(get_current_user)],
    body: ToExclusionIn | None = None,
    db: Annotated[Session, Depends(get_db)] = None,
):
    """反例学习：把一条抑制条目沉淀为「人工排除规则」草稿（**默认停用**）。

    为什么要单独一个入口（2026-10 规则评审）：抑制条目会过期、语义是"这类现象
    我交过结论"；排除规则的语义是"这类流量跳过模型与报告"——**更重**，必须人审。
    这里只做机械搬运（同一棵条件树），默认 `enabled=False`，界面确认后再启用。
    同名排除规则已存在时直接返回它（不重复建）。
    """
    item = db.get(AnalysisSuppression, item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="没有这条抑制条目")
    match = item.match or {}
    if not (isinstance(match, dict) and match.get("rules")):
        return JSONResponse(
            status_code=400,
            content={"conflict": "field_error", "detail": "这条抑制没有结构化条件（match.rules），无法转排除规则"},
        )
    errors = exclusion.validate_conditions(match)
    if errors:
        return _field_errors(errors)
    base_name = f"反例-{item.name or item_id[:8]}"[:120]
    row = db.execute(select(ExclusionFilter).where(ExclusionFilter.name == base_name)).scalar_one_or_none()
    created = False
    if row is None:
        row = ExclusionFilter(
            name=base_name,
            description=(
                f"由抑制条目「{item.name}」转写（反例学习）。条件与该抑制一致；"
                f"来源 {item.origin or 'agent'} · 证据 {len(item.evidence_refs or [])} 条 · "
                f"任务 {item.source_task_id or '—'}。启用前请复核影响面（GET /api/exclusions/stats）。"
            ),
            conditions=match,
            enabled=bool(body.enabled) if body is not None else False,
            priority=90,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        created = True
    return {
        "created": created,
        "enabled": row.enabled,
        "id": row.id,
        "name": row.name,
        "conditions": row.conditions,
    }
