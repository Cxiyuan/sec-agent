"""分析机制接口（派工队列 / 结论 / 覆盖率 / 预算参数）。

配套方案与决策记录见 `docs/ndr-analysis-mechanism.md`。

这里全部是**只读浏览 + 人工派工 + 参数读写**：真正"领活/交活"走 MCP
（`claim_tasks` / `complete_task` / `defer_task`），因为那是智能体的通道，
带令牌身份与配额；界面不该绕过配额去领任务。
"""

from __future__ import annotations

from typing import Annotated, Any

import redis
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.analysis import params, queue as tasks, subjects as inventory
from app.api.deps import get_current_user
from app.db.base import get_db
from app.db.models import User
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/analysis", tags=["analysis"])

HINT = (
    "NDR 不再把摘要推给智能体：这里生成的是**客观线索**（首见 / 自身基线偏离 / 盲区 / 规则命中），"
    "只含事实与客观强度，不含严重度与结论；判断权在智能体。"
    "预算、并发、租约、队列容量都在下方参数里调，改完 30 秒内生效。"
)


def _client() -> Any:
    from app.config import settings

    return redis.Redis.from_url(settings.redis_url, decode_responses=True)


class ManualTaskIn(BaseModel):
    """人工派工：运维"我就想看看这台"。走同一套去重与容量规则，不插队。"""

    subject: str = Field(default="", max_length=128)
    subject_kind: str = Field(default="ip", max_length=16)
    kind: str = Field(default="hit", max_length=16)
    note: str = Field(default="", max_length=500)
    strength: float = Field(default=0.6, ge=0.0, le=1.0)


class ConfigIn(BaseModel):
    values: dict[str, Any] = Field(default_factory=dict)


class ConfigResetIn(BaseModel):
    keys: list[str] = Field(default_factory=list)


@router.get("/tasks")
def list_tasks(
    _: Annotated[User, Depends(get_current_user)],
    state: str = "",
    kind: str = "",
    subject: str = "",
    q: str = "",
    limit: int = 50,
    offset: int = 0,
):
    """队列浏览（按客观强度降序）。`state` 留空 = 全部状态。"""
    return tasks.list_tasks(
        state=state, kind=kind, subject=subject, q=q, limit=limit, offset=offset
    )


@router.get("/tasks/{task_id}")
def task_detail(task_id: str, _: Annotated[User, Depends(get_current_user)]):
    """任务详情：含 `hint` 全量与该任务的历史结论（判断"是否重复分析过"）。"""
    out = tasks.task_detail(task_id)
    return out


@router.get("/results")
def list_results(
    _: Annotated[User, Depends(get_current_user)],
    task_id: str = "",
    subject: str = "",
    verdict: str = "",
    limit: int = 50,
    offset: int = 0,
):
    """智能体交回的结论清单（可按任务/对象/结论筛）。"""
    return inventory_results(
        task_id=task_id, subject=subject, verdict=verdict, limit=limit, offset=offset
    )


def inventory_results(
    *, task_id: str, subject: str, verdict: str, limit: int, offset: int
) -> dict[str, Any]:
    """`analysis_results` 的只读浏览（独立函数便于单测替身）。"""
    from sqlalchemy import func, select

    from app.db.base import SessionLocal
    from app.db.models import AnalysisResult

    cap = max(1, min(int(limit or 50), 200))
    start = max(0, int(offset or 0))
    conds: list[Any] = []
    if task_id:
        conds.append(AnalysisResult.task_id == task_id.strip())
    if subject:
        conds.append(AnalysisResult.subject == subject.strip())
    if verdict:
        conds.append(AnalysisResult.verdict == verdict.strip())
    try:
        with SessionLocal() as db:
            total = int(
                db.scalar(select(func.count()).select_from(AnalysisResult).where(*conds)) or 0
            )
            rows = db.scalars(
                select(AnalysisResult)
                .where(*conds)
                .order_by(AnalysisResult.created_at.desc())
                .limit(cap)
                .offset(start)
            ).all()
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读结论失败：{exc}", "items": [], "total": 0}
    return {
        "total": total,
        "returned": len(rows),
        "items": [
            {
                "id": str(r.id),
                "task_id": r.task_id,
                "kind": r.kind,
                "subject_kind": r.subject_kind,
                "subject": r.subject,
                "verdict": r.verdict,
                "confidence": r.confidence,
                "summary": r.summary,
                "findings": r.findings,
                "evidence_refs": list(r.evidence_refs or []),
                "tools_used": r.tools_used,
                "duration_ms": r.duration_ms,
                "claimed_by": r.claimed_by,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }


@router.get("/stats")
def analysis_stats(_: Annotated[User, Depends(get_current_user)]):
    """总览：各状态条数、按类型/结论分布、平均成本、计数器、当前预算。"""
    return tasks.stats(_client())


@router.get("/coverage")
def coverage(
    _: Annotated[User, Depends(get_current_user)],
    days: int = 7,
    kind: str = "",
    limit: int = 100,
):
    """覆盖率与盲区清单（这次改造的核心验收指标就出在这里）。"""
    return inventory.coverage(days=days, kind=kind, limit=limit)


@router.get("/inventory")
def inventory_map(
    _: Annotated[User, Depends(get_current_user)],
    limit: int = 100,
    kind: str = "",
):
    """对象清单（数据地图）：见过的资产/服务端口/对端/协议/签名。`kind` 留空=每类都取。"""
    return inventory.inventory(limit_per_kind=limit, kind=kind)


@router.post("/tasks")
def create_manual_task(
    payload: ManualTaskIn,
    user: Annotated[User, Depends(get_current_user)],
):
    """人工派工（与自动线索同一套去重、容量与配额，不插队）。"""
    if not payload.subject.strip():
        return JSONResponse(status_code=400, content={"detail": "要派工的对象（subject）不能为空"})
    return tasks.manual_task(
        _client(),
        subject_kind=payload.subject_kind,
        subject=payload.subject,
        note=f"{payload.note}（by {getattr(user, 'username', '') or 'ui'}）",
        kind=payload.kind,
        strength=payload.strength,
    )


@router.get("/config")
def get_config(_: Annotated[User, Depends(get_current_user)]):
    """参数清单（区间/单位/说明）+ 当前生效值。形状与 `/api/baseline/config` 一致。"""
    return {
        "items": params.items(),
        "effective": params.effective(),
        "kinds": list(params.KINDS),
        "verdicts": list(tasks.VERDICTS),
        "hint": HINT,
    }


@router.put("/config")
def save_config(
    payload: ConfigIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """保存参数（只认 `analysis.*` 白名单；校验失败回 400 + `field_errors`）。"""
    values = payload.values or {}
    if not values:
        return JSONResponse(
            status_code=400, content={"conflict": "field_error", "detail": "没有要保存的参数"}
        )
    errors = params.validate(values)
    if errors:
        return JSONResponse(
            status_code=400,
            content={
                "conflict": "field_error",
                "detail": errors[0]["msg"],
                "field_errors": errors,
            },
        )
    written = params.save(db, values)
    log.info("分析机制参数已更新：%d 项（%s）", written, ", ".join(sorted(values)))
    return {"written": written, "items": params.items(), "effective": params.effective()}


@router.post("/config/reset")
def reset_config(
    payload: ConfigResetIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """恢复默认（`keys` 为空 = 全部恢复）。"""
    removed = params.reset(db, payload.keys or None)
    return {"removed": removed, "items": params.items(), "effective": params.effective()}
