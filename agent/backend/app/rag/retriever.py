"""混合检索：局域网过滤 + IP 精确查询 + 向量语义检索。"""

from __future__ import annotations

import ipaddress
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.config import settings
from app.db.base import SessionLocal
from app.db.models import Asset, KnowledgeChunk
from app.rag.embedder import embed_for_query
from app.rag.lan import is_lan_ip
from app.runtime_config import get as runtime_get
from app.topology.graph import subgraph_around
from app.topology.service import enabled_topologies
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
    """IP 精确查询（主 IP 或额外 IP）+ CIDR 网段包含。

    不再限制局域网，外部登记的资产也可按 IP 命中。
    """
    if not ips:
        return []
    found: dict[str, dict[str, Any]] = {}

    # 1. 精确匹配（主 IP + 额外 IP）
    conds: list[Any] = [Asset.ip.in_(ips)]
    for ip in ips:
        conds.append(Asset.extra_ips.contains([ip]))
    for a in db.scalars(select(Asset).where(or_(*conds))).all():
        found[a.id] = _asset_dict(a)

    # 2. CIDR 网段匹配：事件 IP 落在登记网段内即命中
    addrs: list[Any] = []
    for ip in ips:
        try:
            addrs.append(ipaddress.ip_address(ip))
        except ValueError:
            continue
    if addrs:
        for a in db.scalars(select(Asset).where(Asset.ip.contains("/"))).all():
            if a.id in found:
                continue
            if _asset_contains(a, addrs):
                found[a.id] = _asset_dict(a)

    return list(found.values())


def _asset_contains(a: Asset, addrs: list[Any]) -> bool:
    """资产登记的主 IP / 额外 IP 中是否有 CIDR 网段覆盖给定地址。"""
    for value in [a.ip, *(a.extra_ips or [])]:
        sval = str(value)
        if "/" not in sval:
            continue
        try:
            net = ipaddress.ip_network(sval, strict=False)
        except ValueError:
            continue
        for addr in addrs:
            if addr.version == net.version and addr in net:
                return True
    return False


def _cosine_sim(a: Any, b: Any) -> float:
    """Python 侧余弦相似度（top-K 数量小，开销可忽略）。

    维度必须一致：不一致说明索引由**旧 embedding** 生成。按口径**直接报错**（不静默跳过），
    由上层把错误透出并提示重建索引——静默截断会算出个假相似度，看起来“检索正常”实则全错。
    """
    if a is None or b is None:
        return 0.0
    av = list(a)
    bv = list(b)
    if len(av) != len(bv):
        raise ValueError(
            f"向量维度不一致（查询 {len(av)} 维 vs 索引 {len(bv)} 维）："
            "索引很可能由旧 embedding 生成，请重建知识库索引（rag.reindex_all）"
        )
    dot = sum(x * y for x, y in zip(av, bv, strict=True))
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


def topology_context(matched_asset_ids: set[str]) -> list[dict[str, Any]]:
    """按命中的资产找拓扑节点，取上下游局部子图（无命中/无拓扑返回空）。"""
    if not matched_asset_ids:
        return []
    try:
        tops = enabled_topologies()
    except Exception as exc:  # noqa: BLE001
        log.warning("拓扑检索失败: %s", exc)
        return []

    results: list[dict[str, Any]] = []
    for t in tops:
        graph = t["graph"]
        seeds = [
            str(n.get("id"))
            for n in graph.get("nodes", [])
            if matched_asset_ids & set((n.get("data") or {}).get("asset_ids") or [])
        ]
        if not seeds:
            continue
        sub = subgraph_around(graph, seeds, settings.topology_hops, settings.topology_max_nodes)
        if not sub["nodes"]:
            continue
        results.append({"topology_id": t["id"], "topology_name": t["name"], **sub})
    return results


def retrieve(src_ips: list[str], dst_ips: list[str], query_text: str) -> dict[str, Any]:
    """混合检索。返回 {lan_ips, assets, knowledge, topology}。"""
    empty: dict[str, Any] = {"lan_ips": [], "assets": [], "knowledge": [], "topology": []}
    if not runtime_get("rag_enabled", settings.rag_enabled):
        return empty

    # 仅查询局域网 IP
    lan_ips = sorted({ip for ip in (*src_ips, *dst_ips) if is_lan_ip(ip)})
    # 全部事件 IP 都参与精确/CIDR 匹配（外部登记资产也能命中）
    all_ips = sorted({ip for ip in (*src_ips, *dst_ips) if ip})
    if settings.rag_max_ips > 0:
        all_ips = all_ips[: settings.rag_max_ips]
    try:
        with SessionLocal() as db:
            assets = lookup_assets(db, all_ips)
            query = query_text
            if assets:
                names = [str(a.get("asset_name") or a["ip"]) for a in assets]
                query = f"{query} {' '.join(names)}".strip()
            knowledge = vector_search(
                db,
                query,
                int(runtime_get("rag_top_k", settings.rag_top_k)),
                float(runtime_get("rag_min_score", settings.rag_min_score)),
            )
    except Exception as exc:  # noqa: BLE001
        log.warning("资产/知识检索失败: %s", exc)
        return {**empty, "lan_ips": lan_ips}

    # 去重：向量命中里排除已按 IP 精确命中的资产
    asset_ids = {a["id"] for a in assets}
    knowledge = [
        k for k in knowledge if not (k["source_type"] == "asset" and k["source_id"] in asset_ids)
    ]
    return {
        "lan_ips": lan_ips,
        "assets": assets,
        "knowledge": knowledge,
        "topology": topology_context(asset_ids),
    }
