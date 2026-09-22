"""网络拓扑：CRUD + 节点类型管理 + 重新向量化。"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.config import settings
from app.db.base import get_db
from app.db.models import Asset, Topology, TopologyNodeType, User
from app.rag.indexer import clear_chunks
from app.rag.queue import enqueue_topology_index
from app.topology.builtin import ICON_CANDIDATES
from app.topology.graph import normalize_graph, validate_graph

router = APIRouter(prefix="/api/topologies", tags=["topologies"])


class TopologyIn(BaseModel):
    name: str
    description: str = ""
    graph: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class NodeTypeIn(BaseModel):
    key: str = ""
    name: str
    icon: str = "Box"
    color: str = "#64748b"
    sort: int = 200


def _topology_dict(t: Topology, with_graph: bool = False) -> dict[str, Any]:
    data = {
        "id": t.id,
        "name": t.name,
        "description": t.description,
        "node_count": t.node_count,
        "edge_count": t.edge_count,
        "enabled": t.enabled,
        "status": t.status,
        "indexed_at": t.indexed_at.isoformat() if t.indexed_at else None,
        "updated_at": t.updated_at.isoformat() if t.updated_at else None,
    }
    if with_graph:
        data["graph"] = t.graph or {"nodes": [], "edges": []}
    return data


def _node_type_dict(nt: TopologyNodeType) -> dict[str, Any]:
    return {
        "key": nt.key,
        "name": nt.name,
        "icon": nt.icon,
        "color": nt.color,
        "builtin": nt.builtin,
        "sort": nt.sort,
    }


# ---------- 节点类型 ----------


@router.get("/node-types")
def list_node_types(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    rows = db.scalars(select(TopologyNodeType).order_by(TopologyNodeType.sort)).all()
    return {"items": [_node_type_dict(nt) for nt in rows], "icon_candidates": ICON_CANDIDATES}


@router.post("/node-types")
def create_node_type(
    body: NodeTypeIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="类型名称不能为空")
    key = (body.key or name).strip().lower().replace(" ", "_")
    if not key:
        raise HTTPException(status_code=400, detail="类型标识不能为空")
    if db.get(TopologyNodeType, key) is not None:
        return JSONResponse(
            status_code=409,
            content={"conflict": "duplicate_key", "detail": f"类型标识已存在：{key}"},
        )
    nt = TopologyNodeType(
        key=key, name=name, icon=body.icon or "Box", color=body.color or "#64748b",
        builtin=False, sort=body.sort,
    )
    db.add(nt)
    db.commit()
    return _node_type_dict(nt)


@router.put("/node-types/{key}")
def update_node_type(
    key: str,
    body: NodeTypeIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    nt = db.get(TopologyNodeType, key)
    if nt is None:
        raise HTTPException(status_code=404, detail="类型不存在")
    # 内置类型仅允许改名/图标/颜色，不允许改 key
    nt.name = body.name.strip() or nt.name
    nt.icon = body.icon or nt.icon
    nt.color = body.color or nt.color
    if not nt.builtin:
        nt.sort = body.sort
    db.commit()
    return _node_type_dict(nt)


@router.delete("/node-types/{key}")
def delete_node_type(
    key: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    nt = db.get(TopologyNodeType, key)
    if nt is None:
        raise HTTPException(status_code=404, detail="类型不存在")
    if nt.builtin:
        raise HTTPException(status_code=400, detail="内置类型不可删除")
    used = [
        t.name
        for t in db.scalars(select(Topology)).all()
        if any(
            ((n.get("data") or {}).get("node_type") == key)
            for n in (t.graph or {}).get("nodes", [])
        )
    ]
    if used:
        raise HTTPException(status_code=409, detail=f"该类型仍被拓扑使用：{'、'.join(used[:3])}")
    db.delete(nt)
    db.commit()
    return {"ok": True}


# ---------- 拓扑图 ----------


@router.get("")
def list_topologies(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    rows = db.scalars(select(Topology).order_by(Topology.updated_at.desc())).all()
    return {"items": [_topology_dict(t) for t in rows]}


@router.get("/{topology_id}")
def get_topology(
    topology_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    t = db.get(Topology, topology_id)
    if t is None:
        raise HTTPException(status_code=404, detail="拓扑不存在")
    return _topology_dict(t, with_graph=True)


def _prepare(db: Session, body: TopologyIn) -> tuple[dict[str, Any], JSONResponse | None]:
    """规范化 + 校验，返回 (graph, 错误响应或 None)。"""
    graph = normalize_graph(body.graph)
    node_types = {nt.key for nt in db.scalars(select(TopologyNodeType)).all()}
    asset_ids = {a.id for a in db.scalars(select(Asset)).all()}
    errors = validate_graph(
        graph,
        node_types=node_types,
        asset_ids=asset_ids,
        max_nodes=settings.topology_max_nodes_per_graph,
    )
    if errors:
        return graph, JSONResponse(
            status_code=400,
            content={
                "conflict": "field_error",
                "detail": errors[0],
                "field_errors": [{"field": "graph", "msg": e} for e in errors[:100]],
            },
        )
    return graph, None


@router.post("")
def create_topology(
    body: TopologyIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="拓扑名称不能为空")
    if db.scalars(select(Topology).where(Topology.name == name)).first() is not None:
        return JSONResponse(
            status_code=409,
            content={"conflict": "duplicate_name", "detail": f"拓扑名称已存在：{name}"},
        )
    graph, error = _prepare(db, body)
    if error is not None:
        return error

    t = Topology(
        name=name,
        description=body.description,
        graph=graph,
        node_count=len(graph["nodes"]),
        edge_count=len(graph["edges"]),
        enabled=body.enabled,
        status="pending",
    )
    db.add(t)
    db.commit()
    enqueue_topology_index(t.id)
    return _topology_dict(t, with_graph=True)


@router.put("/{topology_id}")
def update_topology(
    topology_id: str,
    body: TopologyIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    t = db.get(Topology, topology_id)
    if t is None:
        raise HTTPException(status_code=404, detail="拓扑不存在")

    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="拓扑名称不能为空")
    dup = db.scalars(select(Topology).where(Topology.name == name, Topology.id != topology_id)).first()
    if dup is not None:
        return JSONResponse(
            status_code=409,
            content={"conflict": "duplicate_name", "detail": f"拓扑名称已存在：{name}"},
        )
    graph, error = _prepare(db, body)
    if error is not None:
        return error

    t.name = name
    t.description = body.description
    t.graph = graph
    t.node_count = len(graph["nodes"])
    t.edge_count = len(graph["edges"])
    t.enabled = body.enabled
    t.status = "pending"
    db.commit()
    enqueue_topology_index(t.id)
    return _topology_dict(t, with_graph=True)


@router.delete("/{topology_id}")
def delete_topology(
    topology_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    t = db.get(Topology, topology_id)
    if t is None:
        raise HTTPException(status_code=404, detail="拓扑不存在")
    clear_chunks("topology", topology_id)
    db.delete(t)
    db.commit()
    return {"ok": True}


@router.post("/{topology_id}/reindex")
def reindex_topology(
    topology_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    t = db.get(Topology, topology_id)
    if t is None:
        raise HTTPException(status_code=404, detail="拓扑不存在")
    t.status = "pending"
    db.commit()
    enqueue_topology_index(topology_id)
    return {"ok": True, "status": "pending"}
