"""索引：分块 + 嵌入 + 写入 knowledge_chunks。"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.config import settings
from app.db.base import SessionLocal
from app.db.models import Asset, Document, KnowledgeChunk
from app.rag.embedder import embed_texts
from app.workers.log import get_logger

log = get_logger(__name__)


def split_text(text: str, size: int, overlap: int) -> list[str]:
    """按字符滑窗分块。"""
    text = (text or "").strip()
    if not text:
        return []
    if size <= 0:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        chunks.append(text[start : start + size])
        if start + size >= len(text):
            break
        start += max(1, size - overlap)
    return chunks


def asset_text(a: Asset) -> str:
    """资产 -> 可向量化的文本。"""
    parts = [f"资产名：{a.asset_name or a.hostname or a.ip}", f"主IP：{a.ip}"]
    if a.extra_ips:
        parts.append(f"其他IP：{', '.join(a.extra_ips)}")
    for label, val in [
        ("业务系统", a.business_system),
        ("负责人", a.owner),
        ("重要级别", a.importance),
        ("资产类型", a.asset_type),
        ("网络区域", a.network_zone),
        ("操作系统", a.os),
        ("开放服务", a.services),
        ("机房位置", a.location),
    ]:
        if val:
            parts.append(f"{label}：{val}")
    if a.tags:
        parts.append(f"标签：{', '.join(a.tags)}")
    if a.description:
        parts.append(f"业务描述：{a.description}")
    return "\n".join(parts)


def _replace_chunks(
    db: Session, source_type: str, source_id: str, chunks: list[str], meta: dict
) -> None:
    db.execute(
        delete(KnowledgeChunk).where(
            KnowledgeChunk.source_type == source_type, KnowledgeChunk.source_id == source_id
        )
    )
    if not chunks:
        db.flush()
        return
    vectors = embed_texts(chunks)
    for i, (chunk, vec) in enumerate(zip(chunks, vectors)):
        db.add(
            KnowledgeChunk(
                source_type=source_type,
                source_id=source_id,
                chunk_index=i,
                content=chunk,
                embedding=vec,
                meta=meta,
            )
        )
    db.flush()


def index_asset(asset_id: str) -> bool:
    """向量化单个资产。成功返回 True。"""
    with SessionLocal() as db:
        a = db.get(Asset, asset_id)
        if a is None:
            return False
        try:
            chunks = split_text(asset_text(a), settings.rag_chunk_size, settings.rag_chunk_overlap)
            _replace_chunks(db, "asset", asset_id, chunks, {"ip": a.ip, "asset_name": a.asset_name})
            a.embedding_status = "indexed"
            a.embedded_at = datetime.now(UTC)
            db.commit()
            return True
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            log.warning("资产向量化失败 %s: %s", asset_id, exc)
            a = db.get(Asset, asset_id)
            if a is not None:
                a.embedding_status = "failed"
                db.commit()
            return False


def index_document(doc_id: str, text: str) -> bool:
    """向量化文档正文。成功返回 True。"""
    with SessionLocal() as db:
        d = db.get(Document, doc_id)
        if d is None:
            return False
        try:
            chunks = split_text(text, settings.rag_chunk_size, settings.rag_chunk_overlap)
            _replace_chunks(
                db, "document", doc_id, chunks, {"title": d.title, "filename": d.filename}
            )
            d.status = "indexed"
            db.commit()
            return True
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            log.warning("文档向量化失败 %s: %s", doc_id, exc)
            d = db.get(Document, doc_id)
            if d is not None:
                d.status = "failed"
                db.commit()
            return False


def clear_chunks(source_type: str, source_id: str) -> None:
    with SessionLocal() as db:
        db.execute(
            delete(KnowledgeChunk).where(
                KnowledgeChunk.source_type == source_type, KnowledgeChunk.source_id == source_id
            )
        )
        db.commit()
