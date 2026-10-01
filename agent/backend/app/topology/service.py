"""拓扑服务：跨表操作（资产引用清理、节点类型播种、检索用节点汇总）。"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from app.db.base import SessionLocal
from app.db.models import Topology
from app.topology.builtin import BUILTIN_NODE_TYPES
from app.workers.log import get_logger
from app.workers.pubsub import publish

log = get_logger(__name__)


def seed_node_types() -> None:
    """幂等播种内置节点类型。"""
    from app.db.models import TopologyNodeType

    with SessionLocal() as db:
        existing = {nt.key for nt in db.scalars(select(TopologyNodeType)).all()}
        for spec in BUILTIN_NODE_TYPES:
            if spec["key"] in existing:
                continue
            db.add(TopologyNodeType(**spec, builtin=True))
        db.commit()


def detach_asset(asset_id: str) -> list[str]:
    """从所有拓扑节点中移除该资产引用，返回受影响的拓扑 id 列表。"""
    changed: list[str] = []
    with SessionLocal() as db:
        for t in db.scalars(select(Topology)).all():
            raw_graph = t.graph
            graph: dict[str, Any] = raw_graph if isinstance(raw_graph, dict) else {}
            raw_nodes = graph.get("nodes")
            nodes: list[Any] = raw_nodes if isinstance(raw_nodes, list) else []
            hit = False
            for node in nodes:
                if not isinstance(node, dict):
                    continue
                raw_data = node.get("data")
                data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
                raw_ids = data.get("asset_ids")
                ids: list[Any] = raw_ids if isinstance(raw_ids, list) else []
                if asset_id in ids:
                    data["asset_ids"] = [x for x in ids if x != asset_id]
                    hit = True
            if hit:
                t.graph = graph
                t.status = "pending"
                changed.append(t.id)
        db.commit()

    if changed:
        from app.rag.queue import enqueue_topology_index

        for tid in changed:
            enqueue_topology_index(tid)
        publish("shentong:events", {"type": "topology_changed", "count": len(changed)})
    return changed


def enabled_topologies() -> list[dict[str, Any]]:
    """所有启用中的拓扑（含图），供结构化检索使用。"""
    with SessionLocal() as db:
        rows = db.scalars(select(Topology).where(Topology.enabled.is_(True))).all()
        result: list[dict[str, Any]] = []
        for t in rows:
            raw = t.graph
            result.append(
                {
                    "id": t.id,
                    "name": t.name,
                    "graph": raw if isinstance(raw, dict) else {},
                }
            )
        return result
