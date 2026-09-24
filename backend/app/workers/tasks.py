"""分析任务：实时摘要分析（事件驱动）+ 水位驱动的定时兜底。"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.agents.runner import get_graph
from app.config import settings
from app.workers.celery_app import celery_app
from app.workers.log import get_logger

log = get_logger(__name__)


@celery_app.task(name="analysis.analyze_digests")
def analyze_digests(digests: list[dict]) -> dict:
    """实时链路：分析检测器投递的一批聚合摘要（一次图运行处理一批）。"""
    if not digests:
        return {"summary": {"total_groups": 0, "reports": 0}, "digests": 0}
    now = datetime.now(UTC)
    thread_id = str(uuid.uuid4())
    initial = {
        "thread_id": thread_id,
        "digests": digests,
        "window_start": now,
        "window_end": now,
    }
    try:
        result = get_graph().invoke(initial, {"configurable": {"thread_id": thread_id}})
        return {"thread_id": thread_id, "digests": len(digests), "summary": result.get("run_summary", {})}
    except Exception:
        log.exception("实时分析任务失败")
        return {"thread_id": thread_id, "digests": len(digests), "error": "实时分析任务失败"}


def _read_watermark() -> datetime | None:
    """读取兜底水位（存 PostgreSQL，跨重启可靠）。"""
    from app.db.base import SessionLocal
    from app.db.models import SystemConfig

    try:
        with SessionLocal() as db:
            row = db.get(SystemConfig, settings.fallback_watermark_key)
        raw = (row.value or {}).get("value") if row is not None else None
    except Exception as exc:  # noqa: BLE001
        log.warning("读取兜底水位失败: %s", exc)
        return None
    if not raw:
        return None
    try:
        ts = datetime.fromisoformat(str(raw))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def _write_watermark(ts: datetime) -> None:
    from app.db.base import SessionLocal
    from app.db.models import SystemConfig

    try:
        with SessionLocal() as db:
            row = db.get(SystemConfig, settings.fallback_watermark_key)
            if row is None:
                row = SystemConfig(key=settings.fallback_watermark_key, value={})
                db.add(row)
            row.value = {"value": ts.isoformat()}
            db.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("写入兜底水位失败: %s", exc)


@celery_app.task(name="analysis.run_window")
def run_analysis_window() -> dict:
    """定时兜底：窗口 = [水位, now]，只补检测器没处理过的日志。

    为什么用水位而不是固定窗口：服务整体停机数小时后，固定窗口会让停机期间
    的漏报永远补不回来；水位驱动则恢复后一次性补齐（带最大回补上限）。
    """
    now = datetime.now(UTC)
    start = _read_watermark() or (now - timedelta(minutes=settings.analysis_window_minutes))
    max_backfill = timedelta(hours=settings.fallback_max_backfill_hours)
    if now - start > max_backfill:
        log.warning(
            "兜底窗口 %s 超过最大回补 %d 小时，已截断", start.isoformat(), settings.fallback_max_backfill_hours
        )
        start = now - max_backfill

    thread_id = str(uuid.uuid4())
    initial = {"window_start": start, "window_end": now, "thread_id": thread_id}
    try:
        result = get_graph().invoke(initial, {"configurable": {"thread_id": thread_id}})
    except Exception:
        log.exception("兜底分析任务失败（水位不前移，下轮重试同一窗口）")
        return {"thread_id": thread_id, "error": "兜底分析任务失败"}
    _write_watermark(now)
    return {"thread_id": thread_id, "summary": result.get("run_summary", {})}


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
