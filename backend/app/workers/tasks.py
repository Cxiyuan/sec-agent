"""分析任务：定时触发 LangGraph 管线。"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.agents.runner import get_graph
from app.config import settings
from app.workers.celery_app import celery_app
from app.workers.log import get_logger

log = get_logger(__name__)


@celery_app.task(name="analysis.run_window")
def run_analysis_window() -> dict:
    now = datetime.now(UTC)
    start = now - timedelta(minutes=settings.analysis_window_minutes)
    thread_id = str(uuid.uuid4())
    initial = {"window_start": start, "window_end": now, "thread_id": thread_id}

    graph = get_graph()
    config = {"configurable": {"thread_id": thread_id}}
    try:
        result = graph.invoke(initial, config)
        return {"thread_id": thread_id, "summary": result.get("run_summary", {})}
    except Exception:
        log.exception("分析任务失败")
        return {"thread_id": thread_id, "error": "分析任务失败"}


class IndexFailedError(Exception):
    """向量化失败，用于触发 Celery 重试。"""


@celery_app.task(
    name="rag.index_asset",
    autoretry_for=(IndexFailedError,),
    retry_backoff=True,
    max_retries=3,
)
def index_asset_task(asset_id: str) -> bool:
    """向量化单个资产。"""
    from app.rag.indexer import index_asset

    if not index_asset(asset_id):
        raise IndexFailedError(asset_id)
    return True


@celery_app.task(
    name="rag.index_document",
    autoretry_for=(IndexFailedError,),
    retry_backoff=True,
    max_retries=3,
)
def index_document_task(doc_id: str) -> bool:
    """向量化单个文档（正文已存库）。"""
    from app.db.base import SessionLocal
    from app.db.models import Document
    from app.rag.indexer import index_document

    with SessionLocal() as db:
        d = db.get(Document, doc_id)
        text = d.content if d is not None else ""
        db.expunge_all()
    if not text.strip():
        return False
    if not index_document(doc_id, text):
        raise IndexFailedError(doc_id)
    return True


@celery_app.task(
    name="rag.index_topology",
    autoretry_for=(IndexFailedError,),
    retry_backoff=True,
    max_retries=3,
)
def index_topology_task(topology_id: str) -> bool:
    """向量化一张拓扑图。"""
    from app.rag.indexer import index_topology

    if not index_topology(topology_id):
        raise IndexFailedError(topology_id)
    return True
