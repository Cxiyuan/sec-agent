"""嵌入：调用 one-api 的 /v1/embeddings（OpenAI 兼容）。"""

from __future__ import annotations

import httpx

from app.config import settings
from app.workers.log import get_logger

log = get_logger(__name__)


def _base_url() -> str:
    return (settings.embedding_base_url or settings.cloud_model_base_url).rstrip("/")


def _api_key() -> str:
    return settings.embedding_api_key or settings.cloud_model_api_key or "not-needed"


def embed_texts(texts: list[str]) -> list[list[float]]:
    """批量嵌入。失败抛异常，由调用方兜底降级。"""
    if not texts:
        return []
    resp = httpx.post(
        f"{_base_url()}/embeddings",
        headers={"Authorization": f"Bearer {_api_key()}"},
        json={"model": settings.embedding_model_name, "input": texts},
        timeout=settings.embedding_timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    items = sorted(data.get("data", []), key=lambda x: x.get("index", 0))
    return [item["embedding"] for item in items]


def embed_text(text: str) -> list[float]:
    """单条嵌入，失败返回空列表。"""
    if not text.strip():
        return []
    try:
        result = embed_texts([text])
    except Exception as exc:  # noqa: BLE001
        log.warning("嵌入失败: %s", exc)
        return []
    return result[0] if result else []
