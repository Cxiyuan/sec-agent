"""拓扑图工具：结构规范化、校验、文本化。"""

from __future__ import annotations

from typing import Any


def field(obj: Any, key: str, default: str = "") -> str:
    """兼容 ORM 对象与字典的取值，统一返回去空字符串。"""
    val = obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)
    return str(val).strip() if val not in (None, "") else default


def asset_brief(asset: Any) -> str:
    """资产 -> 一行简短描述（用于拓扑切片与背景注入）。"""
    bits = [f"IP {field(asset, 'ip')}"]
    name = field(asset, "asset_name") or field(asset, "hostname")
    if name:
        bits.append(f"名称 {name}")
    for label, key in (
        ("业务系统", "business_system"),
        ("重要级别", "importance"),
        ("类型", "asset_type"),
        ("区域", "network_zone"),
    ):
        val = field(asset, key)
        if val:
            bits.append(f"{label} {val}")
    return "，".join(bits)


def _num(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _node_data(node: dict[str, Any]) -> dict[str, Any]:
    return _as_dict(node.get("data"))


def node_ids(graph: dict[str, Any]) -> list[str]:
    return [str(n.get("id") or "") for n in _as_list(graph.get("nodes")) if isinstance(n, dict)]


def normalize_graph(graph: Any) -> dict[str, Any]:
    """裁剪为只保留需要的字段，避免前端冗余数据入库。"""
    src = _as_dict(graph)
    nodes: list[dict[str, Any]] = []
    for raw in _as_list(src.get("nodes")):
        if not isinstance(raw, dict):
            continue
        data = _node_data(raw)
        pos = _as_dict(raw.get("position"))
        nodes.append(
            {
                "id": field(raw, "id"),
                "type": "topoNode",
                "position": {"x": _num(pos.get("x")), "y": _num(pos.get("y"))},
                "data": {
                    "label": field(data, "label"),
                    "node_type": field(data, "node_type"),
                    "asset_ids": [
                        str(a) for a in _as_list(data.get("asset_ids")) if str(a).strip()
                    ],
                    "zone": field(data, "zone"),
                    "note": field(data, "note"),
                },
            }
        )

    edges: list[dict[str, Any]] = []
    for raw in _as_list(src.get("edges")):
        if not isinstance(raw, dict):
            continue
        edges.append(
            {
                "id": field(raw, "id"),
                "source": field(raw, "source"),
                "target": field(raw, "target"),
                "label": field(raw, "label"),
                "type": "smoothstep",
            }
        )
    return {"nodes": nodes, "edges": edges}


def validate_graph(
    graph: dict[str, Any], *, node_types: set[str], asset_ids: set[str], max_nodes: int
) -> list[str]:
    """校验规范化后的图，返回错误说明列表（空 = 通过）。"""
    errors: list[str] = []
    nodes = [n for n in _as_list(graph.get("nodes")) if isinstance(n, dict)]
    edges = [e for e in _as_list(graph.get("edges")) if isinstance(e, dict)]

    if len(nodes) > max_nodes:
        errors.append(f"节点数 {len(nodes)} 超过上限 {max_nodes}")

    ids: set[str] = set()
    for i, n in enumerate(nodes, start=1):
        data = _node_data(n)
        nid = field(n, "id")
        label = field(data, "label") or nid or f"第{i}个节点"
        if not nid:
            errors.append(f"第{i}个节点缺少 id")
        elif nid in ids:
            errors.append(f"节点 id 重复：{nid}")
        ids.add(nid)

        ntype = field(data, "node_type")
        if not ntype:
            errors.append(f"节点「{label}」缺少类型")
        elif ntype not in node_types:
            errors.append(f"节点「{label}」的类型不存在：{ntype}")

        for aid in _as_list(data.get("asset_ids")):
            if str(aid) not in asset_ids:
                errors.append(f"节点「{label}」关联的资产不存在：{aid}")

    for i, e in enumerate(edges, start=1):
        if not field(e, "id"):
            errors.append(f"第{i}条连线缺少 id")
        if field(e, "source") not in ids:
            errors.append(f"第{i}条连线的起点节点不存在：{field(e, 'source')}")
        if field(e, "target") not in ids:
            errors.append(f"第{i}条连线的终点节点不存在：{field(e, 'target')}")

    return errors


def _adjacency(graph: dict[str, Any]) -> tuple[dict[str, set[str]], dict[tuple[str, str], str]]:
    """返回 (无向邻接表, 边标签[双向])。"""
    ids = set(node_ids(graph))
    adj: dict[str, set[str]] = {nid: set() for nid in ids}
    labels: dict[tuple[str, str], str] = {}
    for e in _as_list(graph.get("edges")):
        if not isinstance(e, dict):
            continue
        src, dst = field(e, "source"), field(e, "target")
        if src in ids and dst in ids and src != dst:
            adj[src].add(dst)
            adj[dst].add(src)
            label = field(e, "label")
            if label:
                labels[(src, dst)] = label
                labels[(dst, src)] = label
    return adj, labels


def build_chunks(
    name: str,
    description: str,
    graph: dict[str, Any],
    assets_by_id: dict[str, Any],
    type_names: dict[str, str],
) -> list[str]:
    """把拓扑渲染成多条用于向量化的文本切片（概览 + 每节点一条）。"""
    nodes = [n for n in _as_list(graph.get("nodes")) if isinstance(n, dict)]
    edges = _as_list(graph.get("edges"))
    adj, _ = _adjacency(graph)
    label_of: dict[str, str] = {}
    for n in nodes:
        data = _node_data(n)
        nid = field(n, "id")
        label_of[nid] = field(data, "label") or nid

    chunks: list[str] = []

    # 1) 概览
    zones: dict[str, list[str]] = {}
    for n in nodes:
        data = _node_data(n)
        zone = field(data, "zone") or "未分区"
        tname = type_names.get(field(data, "node_type"), field(data, "node_type"))
        zones.setdefault(zone, []).append(f"{field(data, 'label') or field(n, 'id')}（{tname}）")
    overview = [f"网络拓扑「{name}」"]
    if description:
        overview.append(f"说明：{description}")
    overview.append(f"共 {len(nodes)} 个设备、{len(edges)} 条连接")
    for zone, devices in zones.items():
        overview.append(f"{zone}：{'、'.join(devices)}")
    chunks.append("\n".join(overview))

    # 2) 每个节点一条
    for n in nodes:
        data = _node_data(n)
        nid = field(n, "id")
        tname = type_names.get(field(data, "node_type"), field(data, "node_type"))
        parts = [f"拓扑「{name}」中的设备：{field(data, 'label') or nid}（类型 {tname}）"]
        if field(data, "zone"):
            parts.append(f"网络区域：{field(data, 'zone')}")
        if field(data, "note"):
            parts.append(f"备注：{field(data, 'note')}")
        for aid in _as_list(data.get("asset_ids")):
            asset = assets_by_id.get(str(aid))
            if asset is not None:
                parts.append(f"关联资产：{asset_brief(asset)}")
        neighbours = [label_of.get(x, x) for x in sorted(adj.get(nid, set()))]
        if neighbours:
            parts.append(f"相邻设备：{'、'.join(neighbours)}")
        chunks.append("\n".join(parts))

    return chunks


def subgraph_around(
    graph: dict[str, Any], seed_node_ids: list[str], hops: int, max_nodes: int
) -> dict[str, Any]:
    """以种子节点为中心取上下游 hops 跳的子图。"""
    nodes: dict[str, dict[str, Any]] = {}
    for n in _as_list(graph.get("nodes")):
        if isinstance(n, dict) and field(n, "id"):
            nodes[field(n, "id")] = n
    adj, labels = _adjacency(graph)

    seeds = [nid for nid in seed_node_ids if nid in nodes]
    if not seeds:
        return {"hit_nodes": [], "nodes": [], "edges": []}

    visited: set[str] = set(seeds)
    frontier: set[str] = set(seeds)
    for _ in range(max(0, hops)):
        nxt: set[str] = set()
        for nid in frontier:
            nxt |= adj.get(nid, set())
        nxt -= visited
        if not nxt:
            break
        visited |= nxt
        frontier = nxt
        if len(visited) >= max_nodes:
            break

    selected = list(visited)[:max_nodes]
    sel = set(selected)
    edges = [
        {"source": src, "target": dst, "label": labels.get((src, dst), "")}
        for (src, dst) in labels
        if src in sel and dst in sel and src < dst
    ]
    return {
        "hit_nodes": seeds,
        "nodes": [nodes[nid] for nid in selected if nid in nodes],
        "edges": edges,
    }
