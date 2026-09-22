"""混合检索：局域网过滤 + IP 精确查询 + 向量语义检索。"""

from __future__ import annotations

from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.config import settings
from app.db.base import SessionLocal
from app.db.models import Asset, KnowledgeChunk
from app.rag.embedder import embed_for_query
from app.rag.lan import is_lan_ip
from app.workers.log import get_logger

log = get_logger(__name__)


def _asset_dict(a: Asset) -> dict[str, Any]:
    return {
        "id": a.id,
        "ip": a.ip,
        "extra_ips": a.extra_ips or [],
        "asset_name": a.asset_name,
        "hostname": a.hostname,
        "business_system": a.business_system,
        "owner": a.owner,
        "importance": a.importance,
        "asset_type": a.asset_type,
        "network_zone": a.network_zone,
        "os": a.os,
        "services": a.services,
        "tags": a.tags or [],
        "location": a.location,
        "description": a.description,
    }


def lookup_assets(db: Session, ips: list[str]) -> list[dict[str, Any]]:
    """IP 精确查询：主 IP 或额外 IP 命中。"""
    if not ips:
        return []
    conds: list[Any] = [Asset.ip.in_(ips)]
    for ip in ips:
        conds.append(Asset.extra_ips.contains([ip]))
    rows = db.scalars(select(Asset).where(or_(*conds))).all()
    return [_asset_dict(a) for a in rows]


def _cosine_sim(a: Any, b: Any) -> float:
    """Python 侧余弦相似度（top-K 数量小，开销可忽略）。"""
    if a is None or b is None:
        return 0.0
    av = list(a)
    bv = list(b)
    dot = sum(x * y for x, y in zip(av, bv))
    na = sum(x * x for x in av) ** 0.5
    nb = sum(y * y for y in bv) ** 0.5
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def vector_search(db: Session, query: str, k: int, min_score: float) -> list[dict[str, Any]]:
    """向量语义检索 knowledge_chunks（DB 排序走 HNSW，得分 Python 计算）。"""
    vec = embed_for_query(query)
    if not vec:
        return []
    distance = KnowledgeChunk.embedding.cosine_distance(vec)
    chunks = db.scalars(select(KnowledgeChunk).order_by(distance).limit(k)).all()
    results: list[dict[str, Any]] = []
    for chunk in chunks:
        score = _cosine_sim(vec, chunk.embedding)
        if score < min_score:
            continue
        results.append(
            {
                "source_type": chunk.source_type,
                "source_id": chunk.source_id,
                "content": chunk.content,
                "score": round(score, 4),
                "meta": chunk.meta or {},
            }
        )
    return results


def retrieve(src_ips: list[str], dst_ips: list[str], query_text: str) -> dict[str, Any]:
    """混合检索。返回 {lan_ips, assets, knowledge}。"""
    empty: dict[str, Any] = {"lan_ips": [], "assets": [], "knowledge": []}
    if not settings.rag_enabled:
        return empty

    # 仅查询局域网 IP
    lan_ips = sorted({ip for ip in (*src_ips, *dst_ips) if is_lan_ip(ip)})
    try:
        with SessionLocal() as db:
            assets = lookup_assets(db, lan_ips)
            query = query_text
            if assets:
                names = [str(a.get("asset_name") or a["ip"]) for a in assets]
                query = f"{query} {' '.join(names)}".strip()
            knowledge = vector_search(db, query, settings.rag_top_k, settings.rag_min_score)
    except Exception as exc:  # noqa: BLE001
        log.warning("混合检索失败: %s", exc)
        return {**empty, "lan_ips": lan_ips}

    # 去重：向量命中里排除已按 IP 精确命中的资产
    asset_ids = {a["id"] for a in assets}
    knowledge = [
        k for k in knowledge if not (k["source_type"] == "asset" and k["source_id"] in asset_ids)
    ]
    return {"lan_ips": lan_ips, "assets": assets, "knowledge": knowledge}
