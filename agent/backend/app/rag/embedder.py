"""嵌入：调用 MiniMax embo-01（自有格式，非 OpenAI 兼容）。

- 端点：{base}/embeddings（base 与 api_key 见 app/cloud_config.py）
- 请求体：{"model": "embo-01", "texts": [...], "type": "db"|"query"}
- 响应体：{"vectors": [[...], ...]}
入库用 type=db（embo_db 角色），查询用 type=query（embo_query 角色），
同维度 1536、非对称检索。模型名由 app.models.registry 固化。
"""

from __future__ import annotations

import httpx

from app.cloud_config import cloud_api_key, cloud_base_url
from app.config import settings
from app.models.registry import resolve_model
from app.workers.log import get_logger

log = get_logger(__name__)


def _embed(texts: list[str], type_: str) -> list[list[float]]:
    """调 MiniMax /embeddings。type_ 为 db（入库）或 query（查询）。"""
    if not texts:
        return []
    resp = httpx.post(
        f"{cloud_base_url()}/embeddings",
        headers={"Authorization": f"Bearer {cloud_api_key()}"},
        json={
            "model": resolve_model("embo_db" if type_ == "db" else "embo_query"),
            "texts": texts,
            "type": type_,
        },
        timeout=settings.embedding_timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    vectors = data.get("vectors", []) if isinstance(data, dict) else []
    for vec in vectors:
        if len(vec) != settings.embedding_dim:
            log.warning(
                "嵌入维度不符：期望 %d，实际 %d（模型 embo-01）",
                settings.embedding_dim,
                len(vec),
            )
            break
    return vectors


def embed_for_index(texts: list[str]) -> list[list[float]]:
    """入库嵌入（type=db）。失败抛异常，由调用方兜底。"""
    return _embed(texts, "db")


def embed_for_query(text: str) -> list[float]:
    """查询嵌入（type=query）。失败返回空列表，检索优雅降级。"""
    if not text.strip():
        return []
    try:
        result = _embed([text], "query")
    except Exception as exc:  # noqa: BLE001
        log.warning("查询嵌入失败: %s", exc)
        return []
    return result[0] if result else []
