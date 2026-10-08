"""拓扑发现：两种视图的图数据（节点 + 有向边）。

**视图一「转发链路」**（默认，口径与「攻击链还原」页一致）：按**流量转发的逻辑**画图，
中继一定体现出来，多级串联也画成一条链。每一条事件的**有效端点**就是一条边：

    hop=direct        客户端 → 目的（源站）
    hop=front         客户端 → 中继
    hop=back/internal 中继   → 目的（源站）

于是一个中继既会作为 `front` 跳的目的、又会作为 `back` 跳的源，链路天然接了起来。
此外再把「监控网段」页推算出的**中继→中继**上下级边叠加上去（标 `inferred`，只推测不观测），
这样即使抓包点只在一侧、没直接抓到两级中继之间的流量，多级串联也能画出来。

**视图二「全量通信」**：ES 按 `src_ip → dst_ip` 聚合 TopN，图上节点多、边没有中继语义，
只用来「看看谁在跟谁说话」。超出 TopN 的部分截断并在界面上明说（不静默少画）。

节点一律用 **IP 作默认显示名**（不用 host 名，host 名不可靠且会跟别名混在一起）；运维起的
别名在展示层优先生效（见 `aliases` 模块），真实 IP 仍作为副标题/悬停保留。
"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from app.config import settings
from app.ingestion import relay_nodes
from app.workers.log import get_logger

log = get_logger(__name__)

#: 全量通信的聚合缓存（ES 上的 top-N 聚合在百万文档上不便宜，页面会来回切视图）
_full_cache: dict[str, Any] = {"at": 0.0, "hours": 0, "data": {}}
_full_lock = threading.Lock()

#: 「全量通信」里每个源节点最多保留多少条出边（太密就成毛线团了）
FULL_DEFAULT_EDGE_PER_NODE = 8


def _add_node(nodes: dict[str, dict[str, Any]], ip: str, events: int) -> None:
    node = nodes.get(ip)
    if node is None:
        nodes[ip] = {"id": ip, "events": int(events)}
    else:
        node["events"] = int(node.get("events") or 0) + int(events)


def _add_edge(
    edges: dict[tuple[str, str], dict[str, Any]],
    src: str,
    dst: str,
    *,
    events: int,
    kind: str,
    hop: str = "",
    **extra: Any,
) -> None:
    key = (src, dst)
    edge = edges.get(key)
    if edge is None:
        edge = {"source": src, "target": dst, "events": 0, "kind": kind, "hop": hop}
        edges[key] = edge
    edge["events"] = int(edge.get("events") or 0) + int(events)
    # 一条边既有观测又有推导时，按观测算（观测是硬证据，推导只是补全）
    if kind == "observed" and edge.get("kind") != "observed":
        edge["kind"] = "observed"
    for name, value in extra.items():
        if isinstance(value, bool):
            edge[name] = bool(edge.get(name)) or value
        elif isinstance(value, (int, float)):
            edge[name] = int(edge.get(name) or 0) + int(value)
        elif value not in (None, ""):
            edge[name] = value


def _classify(ip: str, sources: set[str], targets: set[str], relays: set[str]) -> str:
    """节点角色：中继 / 入口（客户端侧）/ 源站（目的侧）/ 两端都不是（unknown）。"""
    if ip in relays:
        return "relay"
    src, dst = ip in sources, ip in targets
    if src and not dst:
        return "client"
    if dst and not src:
        return "origin"
    if src and dst:
        return "transit"
    return "unknown"


def forward_graph(*, minutes: int, from_ts: str = "", to_ts: str = "") -> dict[str, Any]:
    """转发链路视图：只画**真正进了转发逻辑的事件**（通过中继去重的那一批）。"""
    from app.api.routes import chain as chain_route

    start, end = chain_route._window(minutes, from_ts, to_ts)
    docs, truncated = chain_route._fetch(start, end, settings.chain_max_events)
    topo_edges, levels = chain_route._edges()

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str], dict[str, Any]] = {}
    for doc in docs:
        if not chain_route._kept(doc):
            continue
        hop = str(doc.get("hop") or "direct")
        src = str(doc.get("src_ip") or "").strip()
        dst = str(doc.get("dst_ip") or "").strip()
        client = str(doc.get("real_client_ip") or "").strip()
        if hop == "direct" or hop == "front":
            a, b = (client or src), dst
        else:  # back / relay_internal：这一跳是「中继 → 源站」
            a, b = src, dst
        if not a or not b or a == b:
            continue
        _add_node(nodes, a, 1)
        _add_node(nodes, b, 1)
        _add_edge(edges, a, b, events=1, kind="observed", hop=hop)

    # 叠加推算出的中继→中继上下级边（只补「没直接抓到」的串联关系，已有观测就不重复画语义）
    broken: set[str] = set()
    topo = relay_nodes.topology()
    for pair in topo.get("cycle_broken") or []:
        if isinstance(pair, list) and len(pair) >= 2:
            broken.add(f"{pair[0]}|{pair[1]}")
    for edge in topo_edges:
        if not isinstance(edge, dict):
            continue
        src, dst = str(edge.get("from") or ""), str(edge.get("to") or "")
        if not src or not dst or f"{src}|{dst}" in broken:
            continue
        weight = int(edge.get("direct") or 0) + int(edge.get("header") or 0)
        _add_node(nodes, src, 0)
        _add_node(nodes, dst, 0)
        _add_edge(
            edges,
            src,
            dst,
            events=weight,
            kind="inferred",
            confirmed=bool(edge.get("confirmed")),
            direct=int(edge.get("direct") or 0),
            header=int(edge.get("header") or 0),
            stale=bool(edge.get("stale")),
        )

    relay_set = {ip for ip in nodes if relay_nodes.is_relay(ip)}
    relay_meta = relay_nodes.roles()
    sides = relay_nodes.sides()
    sources = {e["source"] for e in edges.values()}
    targets = {e["target"] for e in edges.values()}
    out_nodes: list[dict[str, Any]] = []
    for ip, node in nodes.items():
        info = dict(relay_meta.get(ip) or {})
        out_nodes.append(
            {
                "id": ip,
                "events": int(node.get("events") or 0),
                "kind": _classify(ip, sources, targets, relay_set),
                "roles": list(info.get("roles") or []),
                "role_source": str(info.get("role_source") or ""),
                "role_reason": str(info.get("role_reason") or ""),
                "side": str(sides.get(ip) or relay_nodes.SIDE_AUTO),
                "level": int(levels.get(ip, -1)) if ip in relay_set else -1,
            }
        )
    out_nodes.sort(key=lambda n: (-int(n["events"]), n["id"]))

    limit = max(1, int(settings.topology_node_limit))
    node_truncated = len(out_nodes) > limit
    kept = {n["id"] for n in out_nodes[:limit]}
    out_edges = [e for e in edges.values() if e["source"] in kept and e["target"] in kept]
    out_edges.sort(key=lambda e: (-int(e["events"]), e["source"], e["target"]))
    edge_limit = max(1, int(settings.topology_edge_limit))
    edge_truncated = len(out_edges) > edge_limit
    out_edges = out_edges[:edge_limit]
    return {
        "mode": "forward",
        "window": {"from": start.isoformat(), "to": end.isoformat()},
        "nodes": out_nodes[:limit],
        "edges": out_edges,
        "relays": {
            "configured": relay_nodes.configured(),
            "levels": levels,
        },
        "scanned": len(docs),
        "truncated": bool(truncated or node_truncated or edge_truncated),
        "note": _forward_note(
            truncated, node_truncated, edge_truncated, len(out_nodes), len(edges)
        ),
    }


def _forward_note(
    scan_truncated: bool,
    node_truncated: bool,
    edge_truncated: bool,
    node_count: int,
    edge_count: int,
) -> str:
    bits: list[str] = []
    if scan_truncated:
        bits.append("时间窗内事件太多，只扫描了上限内的最近事件")
    if node_truncated:
        bits.append(f"节点按事件数只保留前 {settings.topology_node_limit} 个（共 {node_count} 个）")
    if edge_truncated:
        bits.append(f"边按事件数只保留前 {settings.topology_edge_limit} 条（共 {edge_count} 条）")
    return "；".join(bits)


def build_full_query(
    *, start: str, end: str, node_limit: int, edge_per_node: int
) -> dict[str, Any]:
    """全量通信的 ES 聚合：`src_ip` terms → 每个源再出 `dst_ip` terms（纯函数，便于单测）。"""
    return {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": start, "lt": end}}},
        "aggs": {
            "src": {
                "terms": {
                    "field": "src_ip.keyword",
                    "size": max(1, node_limit),
                    "shard_size": max(2, node_limit * 2),
                },
                "aggs": {
                    "dst": {
                        "terms": {
                            "field": "dst_ip.keyword",
                            "size": max(1, edge_per_node),
                        }
                    }
                },
            }
        },
    }


def shape_full(resp: Any, *, node_limit: int) -> dict[str, Any]:
    """ES 响应 → 节点 + 边（边带事件数）。鸭子类型读响应，不做 isinstance 判定。"""
    aggs = resp.get("aggregations") or {}
    src = aggs.get("src") or {}
    buckets = src.get("buckets") or []
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str], dict[str, Any]] = {}
    for bucket in buckets:
        if not isinstance(bucket, dict):
            continue
        src_ip = str(bucket.get("key") or "").strip()
        if not src_ip:
            continue
        _add_node(nodes, src_ip, 0)
        for sub in (bucket.get("dst") or {}).get("buckets") or []:
            if not isinstance(sub, dict):
                continue
            dst_ip = str(sub.get("key") or "").strip()
            if not dst_ip or dst_ip == src_ip:
                continue
            count = int(sub.get("doc_count") or 0)
            _add_node(nodes, dst_ip, 0)
            _add_node(nodes, src_ip, count)
            _add_edge(edges, src_ip, dst_ip, events=count, kind="observed")
            # 目的节点的事件量按入边累计（源节点已在上面加过，这里只加目的侧）
            nodes[dst_ip]["events"] = int(nodes[dst_ip].get("events") or 0) + count
    other = int(src.get("sum_other_doc_count") or 0)
    node_list = [
        {"id": ip, "events": int(n["events"] or 0), "kind": "endpoint"} for ip, n in nodes.items()
    ]
    node_list.sort(key=lambda n: (-int(n["events"]), n["id"]))
    node_list = node_list[: max(1, node_limit)]
    kept = {n["id"] for n in node_list}
    edge_list = [e for e in edges.values() if e["source"] in kept and e["target"] in kept]
    edge_list.sort(key=lambda e: (-int(e["events"]), e["source"], e["target"]))
    return {
        "nodes": node_list,
        "edges": edge_list,
        "other_docs": other,
    }


def _fetch_full(hours: int, node_limit: int, edge_per_node: int) -> dict[str, Any]:
    end_dt = datetime.now(UTC)
    start_dt = end_dt - timedelta(hours=hours)
    start_iso = start_dt.isoformat().replace("+00:00", "Z")
    end_iso = end_dt.isoformat().replace("+00:00", "Z")
    payload: dict[str, Any] = {
        "mode": "full",
        "window": {"from": start_iso, "to": end_iso},
        "nodes": [],
        "edges": [],
        "truncated": False,
        "note": "",
        "computed_at": end_dt.isoformat(),
        "error": "",
    }
    try:
        from app.ingestion import es_config
        from app.ingestion.es_client import get_es

        cfg = es_config.current()
        pattern = str(cfg.get("es.events_index") or settings.es_events_index)
        resp = get_es().search(
            index=pattern,
            body=build_full_query(
                start=start_iso, end=end_iso, node_limit=node_limit, edge_per_node=edge_per_node
            ),
        )
        shaped = shape_full(resp, node_limit=node_limit)
    except Exception as exc:  # noqa: BLE001
        log.warning("全量通信聚合失败: %s", exc)
        payload["error"] = str(exc)[:200]
        return payload
    payload["nodes"] = shaped["nodes"]
    payload["edges"] = shaped["edges"]
    # 超出 TopN 的部分截断并明说（节点被砍 / 每个源的出边被砍都会体现在 sum_other_doc_count）
    payload["truncated"] = bool(shaped["other_docs"])
    if shaped["other_docs"]:
        payload["note"] = (
            f"源节点只保留事件最多的前 {node_limit} 个；"
            f"另有 {shaped['other_docs']} 条事件来自未画出的地址"
        )
    return payload


def full_graph(*, hours: int) -> dict[str, Any]:
    """全量通信视图：ES 按 `src_ip → dst_ip` 聚合 TopN（带进程内缓存）。"""
    window = max(1, int(hours))
    node_limit = max(1, int(settings.topology_node_limit))
    edge_per_node = max(1, int(settings.topology_full_edge_per_node))
    ttl = max(0.0, float(settings.topology_cache_seconds))
    now = time.monotonic()
    with _full_lock:
        hit = _full_cache.get("data") or {}
        if (
            ttl > 0
            and hit
            and int(_full_cache.get("hours") or 0) == window
            and now - float(_full_cache.get("at") or 0.0) < ttl
        ):
            return {**hit, "cached": True}
    payload = _fetch_full(window, node_limit, edge_per_node)
    if not payload.get("error"):
        with _full_lock:
            _full_cache.update({"at": now, "hours": window, "data": payload})
    return {**payload, "cached": False}
