"""攻击者案件与自主调查接口。

两个 router：
- ``/api/cases``：案件列表/详情、发起与追问、合并/拆分、证据包与取证报告
- ``/api/investigation``：工具与字段目录（排错）、运行统计

注意：``/api/cases/stats`` 必须声明在 ``/api/cases/{case_id}`` **之前**，
否则 "stats" 会被当成案件 id 匹配（FastAPI 按声明顺序匹配）。
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.base import SessionLocal, get_db
from app.db.models import User
from app.investigation import (
    cases as case_service,
    export as export_service,
    service as investigation_service,
    tools as tools_service,
)

router = APIRouter(prefix="/api/cases", tags=["cases"])
tools_router = APIRouter(prefix="/api/investigation", tags=["investigation"])


def _require_case(case_id: str) -> dict[str, Any]:
    data = case_service.get_case(case_id)
    if data is None:
        raise HTTPException(status_code=404, detail="案件不存在")
    return data


@router.get("")
def list_cases(
    _: Annotated[User, Depends(get_current_user)],
    status: str | None = None,
    severity: str | None = None,
    keyword: str = "",
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    include_shelved: bool = False,
):
    return case_service.list_cases(
        status=status,
        severity=severity,
        keyword=keyword,
        limit=limit,
        offset=offset,
        include_shelved=include_shelved,
    )


@router.get("/stats")
def case_stats(_: Annotated[User, Depends(get_current_user)]):
    return case_service.stats()


# 注意：这两条必须声明在 /{case_id} 之前，否则 "rebuild" 会被当成案件 id
@router.post("/rebuild")
def rebuild_cases(
    _: Annotated[User, Depends(get_current_user)],
    dry_run: bool = True,
    limit: int = Query(0, ge=0, le=20000),
    hours: int = Query(0, ge=0, le=2160),
    dispatch_after: bool = False,
    rollback_run_id: str = "",
):
    """存量全量重建：dry_run=true 只算不写（先核对再执行），传 rollback_run_id 则回滚该批次。"""
    from app.investigation import rebuild as rebuild_service

    if rollback_run_id:
        return rebuild_service.rollback(rollback_run_id)
    bounded = limit or None
    window = hours or None
    if dry_run:
        return rebuild_service.dry_run(limit=bounded, hours=window)
    run_id = rebuild_service.new_run(dry=False, limit=bounded, hours=window)
    from app.workers.celery_app import celery_app

    celery_app.send_task(
        "analysis.rebuild_cases",
        args=[run_id],
        kwargs={"limit": bounded, "hours": window, "dispatch_after": dispatch_after},
    )
    return {"ok": True, "run_id": run_id, "queued": True}


@router.get("/rebuild/runs")
def rebuild_runs(
    _: Annotated[User, Depends(get_current_user)],
    limit: int = Query(20, ge=1, le=100),
):
    from sqlalchemy import select

    from app.db.models import RebuildRun

    with SessionLocal() as db:
        rows = db.scalars(
            select(RebuildRun).order_by(RebuildRun.started_at.desc()).limit(limit)
        ).all()
    return {
        "items": [
            {
                "id": row.id,
                "dry_run": row.dry_run,
                "status": row.status,
                "counts": row.counts or {},
                "started_at": row.started_at.isoformat() if row.started_at else None,
                "finished_at": row.finished_at.isoformat() if row.finished_at else None,
            }
            for row in rows
        ]
    }


@router.get("/{case_id}")
def get_case(case_id: str, _: Annotated[User, Depends(get_current_user)]):
    return _require_case(case_id)


@router.get("/{case_id}/rounds")
def list_rounds(
    case_id: str,
    _: Annotated[User, Depends(get_current_user)],
    limit: int = Query(50, ge=1, le=200),
):
    _require_case(case_id)
    return {"items": case_service.rounds(case_id, limit=limit)}


class InvestigateRequest(BaseModel):
    instruction: str = ""
    followup: bool = False


@router.post("/{case_id}/investigate")
def investigate(
    case_id: str,
    req: InvestigateRequest,
    _: Annotated[User, Depends(get_current_user)],
):
    """人工发起/追问一轮调查（进独立队列，不阻塞实时分析）。"""
    _require_case(case_id)
    kind = "followup" if req.followup else "manual"
    return investigation_service.dispatch(case_id, kind=kind, instruction=req.instruction.strip())


class FingerprintRequest(BaseModel):
    fingerprint: str


@router.post("/{case_id}/attach")
def attach_group(
    case_id: str,
    req: FingerprintRequest,
    _: Annotated[User, Depends(get_current_user)],
):
    _require_case(case_id)
    result = case_service.attach_group(case_id, req.fingerprint.strip())
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=str(result.get("error")))
    return result


@router.post("/{case_id}/detach")
def detach_group(
    case_id: str,
    req: FingerprintRequest,
    _: Annotated[User, Depends(get_current_user)],
):
    _require_case(case_id)
    result = case_service.detach_group(case_id, req.fingerprint.strip())
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=str(result.get("error")))
    return result


class MergeRequest(BaseModel):
    source_case_id: str


@router.post("/{case_id}/merge")
def merge_cases(
    case_id: str,
    req: MergeRequest,
    _: Annotated[User, Depends(get_current_user)],
):
    """把另一个案件并入本案件（人工纠正模型归集）。"""
    _require_case(case_id)
    result = case_service.merge_cases(case_id, req.source_case_id.strip())
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=str(result.get("error")))
    return result


@router.post("/{case_id}/close")
def close_case(case_id: str, _: Annotated[User, Depends(get_current_user)]):
    _require_case(case_id)
    return case_service.set_status(case_id, "closed")


@router.post("/{case_id}/reopen")
def reopen_case(case_id: str, _: Annotated[User, Depends(get_current_user)]):
    _require_case(case_id)
    return case_service.set_status(case_id, "open")


@router.get("/{case_id}/evidence")
def case_evidence(
    case_id: str,
    _: Annotated[User, Depends(get_current_user)],
    format: str = Query("json", pattern="^(json|zip)$"),
):
    """证据清单（json）或证据包（zip：manifest + evidence.jsonl + timeline.csv + iocs.csv）。"""
    case = _require_case(case_id)
    investigation = case.get("investigation") or {}
    if not investigation:
        raise HTTPException(status_code=400, detail="该案件还没有调查结果")
    if format == "zip":
        blob = export_service.build_evidence_zip(case, investigation)
        name = f"case_{case_id}_evidence.zip"
        return Response(
            content=blob,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{name}"'},
        )
    return export_service.evidence_list(investigation)


class ReportRequest(BaseModel):
    include_trail: bool = True


@router.post("/{case_id}/report")
def generate_report(
    case_id: str,
    _: Annotated[User, Depends(get_current_user)],
    req: ReportRequest | None = None,
):
    """生成/刷新取证报告（HTML + 尽力生成 PDF）。"""
    _require_case(case_id)
    include_trail = True if req is None else req.include_trail
    result = export_service.generate_report(case_id, include_trail=include_trail)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=str(result.get("error")))
    return result


@router.get("/{case_id}/report")
def get_report(case_id: str, _: Annotated[User, Depends(get_current_user)]):
    """查看最新取证报告：有 PDF 直接下发，没有则返回 HTML（与组报告同样的降级策略）。"""
    _require_case(case_id)
    latest = export_service.latest_report(case_id)
    if latest is None:
        raise HTTPException(status_code=404, detail="还没有生成取证报告（先 POST 生成）")
    if latest["has_pdf"] and latest["pdf_path"]:
        return FileResponse(
            str(latest["pdf_path"]),
            filename=f"{latest['title']}.pdf",
            media_type="application/pdf",
        )
    html = export_service.report_html(str(latest["id"]))
    if html is None:
        raise HTTPException(status_code=404, detail="报告内容缺失")
    return HTMLResponse(content=html)


def _safe_int(value: Any, default: int = 0) -> int:
    """安全转 int（Redis 返回值/外部输入可能是字符串或脏值）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@tools_router.get("/tools")
def list_tools(_: Annotated[User, Depends(get_current_user)]):
    """工具与字段目录（排错用：模型能查什么字段、有哪些工具）。"""
    return tools_service.spec_for_api()


@tools_router.get("/stats")
def investigation_stats(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """调查运行统计 + 队列积压（investigation 队列）。"""
    data = case_service.stats()
    queue_depth: int | None = None
    try:
        import redis

        from app.config import settings

        client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        queue_depth = _safe_int(client.llen("investigation"))
    except Exception as exc:  # noqa: BLE001
        data["queue_error"] = str(exc)[:200]
    data["queue_depth"] = queue_depth
    data["reports"] = _report_count(db)
    return data


def _report_count(db: Session) -> int:
    from sqlalchemy import func, select

    from app.db.models import CaseReport

    return _safe_int(db.scalar(select(func.count()).select_from(CaseReport)))
