"""异步向量化入队（Celery 不可用时静默降级）。"""

from __future__ import annotations

from app.workers.celery_app import celery_app
from app.workers.log import get_logger

log = get_logger(__name__)


def enqueue_asset_index(asset_id: str) -> None:
    try:
        celery_app.send_task("rag.index_asset", args=[asset_id])
    except Exception as exc:  # noqa: BLE001
        log.warning("资产向量化入队失败 %s: %s", asset_id, exc)


def enqueue_document_index(doc_id: str) -> None:
    try:
        celery_app.send_task("rag.index_document", args=[doc_id])
    except Exception as exc:  # noqa: BLE001
        log.warning("文档向量化入队失败 %s: %s", doc_id, exc)
