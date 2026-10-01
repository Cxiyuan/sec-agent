"""报告查询与下载。"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.base import get_db
from app.db.models import Report, User

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("")
def list_reports(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    rows = db.execute(select(Report).order_by(Report.created_at.desc())).scalars().all()
    return {
        "items": [
            {
                "id": r.id,
                "group_id": r.group_id,
                "title": r.title,
                "severity": r.severity,
                "pdf_path": r.pdf_path,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]
    }


@router.get("/{report_id}/download")
def download_report(
    report_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    r = db.get(Report, report_id)
    if r is None:
        raise HTTPException(status_code=404, detail="报告不存在")
    if not r.pdf_path:
        raise HTTPException(status_code=404, detail="PDF 未生成（可能缺少系统渲染库）")
    return FileResponse(r.pdf_path, filename=f"{r.title}.pdf", media_type="application/pdf")
