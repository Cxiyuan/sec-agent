"""嵌入：调用 one-api 的 /v1/embeddings（OpenAI 兼容）。

入库用 embo-db，查询用 embo-query（同维 1536，非对称检索）。
模型名由 app.models.registry 解析，支持后台运行时切换。
"""

from __future__ import annotations

import httpx

from app.config import settings
from app.models.registry import resolve_model
from app.workers.log import get_logger

log = get_logger(__name__)


def _base_url() -> str:
    return (settings.embedding_base_url or settings.cloud_model_base_url).rstrip("/")


def _api_key() -> str:
    return settings.embedding_api_key or settings.cloud_model_api_key or "not-needed"


def _embed(texts: list[str], model: str) -> list[list[float]]:
    if not texts:
        return []
    resp = httpx.post(
        f"{_base_url()}/embeddings",
        headers={"Authorization": f"Bearer {_api_key()}"},
        json={"model": model, "input": texts},
        timeout=settings.embedding_timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    items = sorted(data.get("data", []), key=lambda x: x.get("index", 0))
    vectors = [item["embedding"] for item in items]
    for vec in vectors:
        if len(vec) != settings.embedding_dim:
            log.warning(
                "嵌入维度不符：期望 %d，实际 %d（模型 %s）",
                settings.embedding_dim,
                len(vec),
                model,
            )
            break
    return vectors


def embed_for_index(texts: list[str]) -> list[list[float]]:
    """入库嵌入（embo-db）。失败抛异常，由调用方兜底。"""
    return _embed(texts, resolve_model("embo_db"))


def embed_for_query(text: str) -> list[float]:
    """查询嵌入（embo-query）。失败返回空列表，检索优雅降级。"""
    if not text.strip():
        return []
    try:
        result = _embed([text], resolve_model("embo_query"))
    except Exception as exc:  # noqa: BLE001
        log.warning("查询嵌入失败: %s", exc)
        return []
    return result[0] if result else []
