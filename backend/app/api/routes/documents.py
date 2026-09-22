"""知识文档：上传 / 列表 / 删除 / 重新向量化。"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.base import get_db
from app.db.models import Document, User
from app.rag.indexer import clear_chunks
from app.rag.parser import extract_text
from app.rag.queue import enqueue_document_index

router = APIRouter(prefix="/api/documents", tags=["documents"])

ALLOWED_EXT = {".txt", ".md", ".markdown", ".log", ".csv", ".pdf", ".docx", ".xlsx"}
MAX_SIZE = 20 * 1024 * 1024  # 20MB


def _doc_dict(d: Document) -> dict[str, Any]:
    return {
        "id": d.id,
        "title": d.title,
        "filename": d.filename,
        "mime_type": d.mime_type,
        "size": d.size,
        "status": d.status,
        "uploaded_at": d.uploaded_at.isoformat() if d.uploaded_at else None,
    }


@router.get("")
def list_documents(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    rows = db.scalars(select(Document).order_by(Document.uploaded_at.desc())).all()
    return {"items": [_doc_dict(d) for d in rows]}


@router.post("")
async def upload_document(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    file: Annotated[UploadFile, File()],
):
    filename = file.filename or "document"
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(status_code=400, detail=f"不支持的格式：{ext}")
    data = await file.read()
    if len(data) > MAX_SIZE:
        raise HTTPException(status_code=400, detail="文件过大（>20MB）")
    try:
        text = extract_text(filename, data)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"文档解析失败：{exc}") from exc
    if not text.strip():
        raise HTTPException(status_code=400, detail="文档内容为空或无法解析")

    d = Document(
        title=Path(filename).stem,
        filename=filename,
        mime_type=file.content_type or "",
        size=len(data),
        content=text,
        status="pending",
    )
    db.add(d)
    db.commit()
    enqueue_document_index(d.id)
    return _doc_dict(d)


@router.delete("/{doc_id}")
def delete_document(
    doc_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    d = db.get(Document, doc_id)
    if d is None:
        raise HTTPException(status_code=404, detail="文档不存在")
    clear_chunks("document", doc_id)
    db.delete(d)
    db.commit()
    return {"ok": True}


@router.post("/{doc_id}/reindex")
def reindex_document(
    doc_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    d = db.get(Document, doc_id)
    if d is None:
        raise HTTPException(status_code=404, detail="文档不存在")
    d.status = "pending"
    db.commit()
    enqueue_document_index(doc_id)
    return {"ok": True, "status": "pending"}
