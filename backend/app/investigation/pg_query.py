"""PostgreSQL 侧只读取证查询：资产、拓扑、画像、记忆、历史组、原始证据。

为什么要独立一层：组内取证直接查 PG（快、且 ``events.raw`` 已脱敏），
只有跨时段取证才必须走 ES（保留期 30 天）。工具层只管参数校验，取数逻辑都在这里。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db.base import SessionLocal
from app.db.models import Asset, EntityProfile, Event, EventGroup, Topology
from app.workers.log import get_logger

log = get_logger(__name__)

_MAX_ROWS = 200


def _now() -> datetime:
    return datetime.now(UTC)


def _safe_int(value: Any, default: int = 0) -> int:
    """安全转 int（接口/库里的值可能是字符串或脏值）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def assets_by_ips(ips: list[str]) -> list[dict[str, Any]]:
    """按 IP 取资产（含业务/重要性/网络区；extra_ips 一并匹配）。"""
    wanted = {str(ip) for ip in ips if ip}
    if not wanted:
        return []
    with SessionLocal() as db:
        rows = db.scalars(select(Asset)).all()
        extra_hits = [
            r for r in rows if r.ip not in wanted and wanted & {str(x) for x in (r.extra_ips or [])}
        ]
        primary = [r for r in rows if r.ip in wanted]
    out: list[dict[str, Any]] = []
    for r in [*primary, *extra_hits][:_MAX_ROWS]:
        out.append(
            {
                "ip": r.ip,
                "extra_ips": list(r.extra_ips or []),
                "hostname": r.hostname,
                "asset_name": r.asset_name,
                "business_system": r.business_system,
                "importance": r.importance,
                "asset_type": r.asset_type,
                "network_zone": r.network_zone,
                "os": r.os,
                "services": (r.services or "")[:300],
                "owner": r.owner,
                "is_external": r.is_external,
            }
        )
    return out


def topology_neighbors(ips: list[str], hops: int = 1) -> dict[str, Any]:
    """在已保存的拓扑图里找这些 IP 所在节点及其上下游（判断网络位置与横向路径）。"""
    wanted = {str(ip) for ip in ips if ip}
    if not wanted:
        return {"nodes": [], "edges": [], "note": "未提供 IP"}

    with SessionLocal() as db:
        asset_rows = db.scalars(select(Asset)).all()
        topo_rows = db.scalars(select(Topology).where(Topology.enabled.is_(True))).all()

    # 资产 id ↔ IP：拓扑节点里存的是 asset_ids
    id_by_ip: dict[str, str] = {r.ip: r.id for r in asset_rows if r.ip in wanted}
    tag_by_id = {r.id: r.ip for r in asset_rows}
    match_ids = set(id_by_ip.values())

    nodes_out: list[dict[str, Any]] = []
    edges_out: list[dict[str, Any]] = []
    for topo in topo_rows:
        graph = topo.graph or {}
        nodes = graph.get("nodes") or []
        edges = graph.get("edges") or []
        hit_ids: set[str] = set()
        for node in nodes:
            data = node.get("data") or {}
            asset_ids = {str(x) for x in (data.get("asset_ids") or [])}
            label = str(data.get("label") or "")
            if asset_ids & match_ids or any(ip in label for ip in wanted):
                hit_ids.add(str(node.get("id")))
        if not hit_ids:
            continue
        # 一跳邻接（够用于"从哪来、到哪去"）
        ring = set(hit_ids)
        for _ in range(max(1, min(int(hops or 1), 3))):
            for edge in edges:
                src, dst = str(edge.get("source")), str(edge.get("target"))
                if src in ring or dst in ring:
                    ring.add(src)
                    ring.add(dst)
        for node in nodes:
            nid = str(node.get("id"))
            if nid not in ring:
                continue
            data = node.get("data") or {}
            nodes_out.append(
                {
                    "topology": topo.name,
                    "node": nid,
                    "label": data.get("label"),
                    "node_type": data.get("node_type"),
                    "zone": data.get("zone"),
                    "note": str(data.get("note") or "")[:200],
                    "ips": [tag_by_id[i] for i in (data.get("asset_ids") or []) if i in tag_by_id][
                        :10
                    ],
                    "hit": nid in hit_ids,
                }
            )
        for edge in edges:
            if str(edge.get("source")) in ring and str(edge.get("target")) in ring:
                edges_out.append(
                    {
                        "topology": topo.name,
                        "source": edge.get("source"),
                        "target": edge.get("target"),
                        "label": edge.get("label"),
                    }
                )
    return {"nodes": nodes_out[:_MAX_ROWS], "edges": edges_out[:_MAX_ROWS]}


def entity_profiles(kind: str, keys: list[str]) -> list[dict[str, Any]]:
    """取账号/会话长期画像（UEBA 基线）：观测数、风险分、异常点、常用源 IP。"""
    wanted = [str(k) for k in keys if k]
    if not wanted:
        return []
    with SessionLocal() as db:
        rows = db.scalars(
            select(EntityProfile).where(
                EntityProfile.kind == kind, EntityProfile.entity_key.in_(wanted)
            )
        ).all()
    return [
        {
            "kind": r.kind,
            "key": r.entity_key,
            "display": r.entity_display,
            "obs_count": r.obs_count,
            "risk_score": r.risk_score,
            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            "src_ips": dict(list((r.src_ips or {}).items())[:10]),
            "paths": dict(list((r.paths or {}).items())[:10]),
            "user_agents": dict(list((r.user_agents or {}).items())[:10]),
            "hour_hist": r.hour_hist or {},
            "success_count": r.success_count,
            "fail_count": r.fail_count,
            "anomalies": (r.anomalies or [])[:10],
        }
        for r in rows
    ]


def memory_recall(ips: list[str], *, limit: int = 8) -> list[dict[str, Any]]:
    """召回与这些 IP 相关的历史分析记忆（跨窗口持续性）。"""
    from app.agents.memory import recall as recall_memory

    try:
        # 按 IP 召回（asset_ids/fingerprint 留空：案件层没有单一资产 id 与组指纹）
        info = recall_memory(sorted({str(ip) for ip in ips if ip}), [], "")
    except Exception as exc:  # noqa: BLE001
        log.warning("历史记忆召回失败: %s", exc)
        return []
    memories = list((info or {}).get("memories") or [])
    return memories[: max(1, limit)]


def group_history(ips: list[str], *, days: int = 30, limit: int = 20) -> list[dict[str, Any]]:
    """该攻击者/资产的历史事件组（跨时间桶）——还原路径的主线索。"""
    wanted = sorted({str(ip) for ip in ips if ip})
    if not wanted:
        return []
    since = _now() - timedelta(days=max(1, min(_safe_int(days, 30), 365)))
    with SessionLocal() as db:
        rows = db.scalars(
            select(EventGroup)
            .where(EventGroup.window_start >= since)
            .order_by(EventGroup.window_start.desc())
            .limit(500)
        ).all()
    out: list[dict[str, Any]] = []
    for r in rows:
        group_ips = {str(x) for x in (r.src_ips or [])} | {str(x) for x in (r.dst_ips or [])}
        if not (group_ips & set(wanted)):
            continue
        out.append(
            {
                "fingerprint": r.fingerprint,
                "window_start": r.window_start.isoformat() if r.window_start else None,
                "window_end": r.window_end.isoformat() if r.window_end else None,
                "src_ips": list(r.src_ips or [])[:10],
                "dst_ips": list(r.dst_ips or [])[:10],
                "event_count": r.event_count,
                "severity": r.severity,
                "status": r.status,
                "triage_score": r.triage_score,
                "aggregate": r.aggregate or {},
                "attack_chain_summary": str((r.attack_chain or {}).get("summary") or "")[:300],
            }
        )
        if len(out) >= limit:
            break
    return out


def event_by_id(event_id: str) -> dict[str, Any] | None:
    """按 ``ev:<uuid>`` 取原始事件（raw 在归一化时已脱敏）。"""
    key = str(event_id or "").removeprefix("ev:").strip()
    if not key:
        return None
    with SessionLocal() as db:
        row = db.get(Event, key)
    if row is None:
        return None
    return {
        "id": row.id,
        "ts": row.ts.isoformat() if row.ts else None,
        "source_system": row.source_system,
        "event_type": row.event_type,
        "src_ip": row.src_ip,
        "dst_ip": row.dst_ip,
        "src_port": row.src_port,
        "dst_port": row.dst_port,
        "protocol": row.protocol,
        "severity": row.severity,
        "hit_rule": row.hit_rule,
        "summary": row.summary,
        "raw": row.raw,
    }


def group_events(
    fingerprints: list[str], *, per_group: int = 30
) -> dict[str, list[dict[str, Any]]]:
    """取案件成员组的事件（组内取证的第一手材料）。"""
    fps = [str(f) for f in fingerprints if f]
    if not fps:
        return {}
    with SessionLocal() as db:
        rows = db.scalars(
            select(EventGroup)
            .where(EventGroup.fingerprint.in_(fps))
            .options(selectinload(EventGroup.events))
        ).all()
    out: dict[str, list[dict[str, Any]]] = {}
    for group in rows:
        events = sorted(group.events, key=lambda e: e.ts or _now())
        out[group.fingerprint] = [
            {
                "ref": f"ev:{e.id}",
                "ts": e.ts.isoformat() if e.ts else None,
                "event_type": e.event_type,
                "src": f"{e.src_ip}:{e.src_port}" if e.src_port else e.src_ip,
                "dst": f"{e.dst_ip}:{e.dst_port}" if e.dst_port else e.dst_ip,
                "protocol": e.protocol,
                "severity": e.severity,
                "hit_rule": e.hit_rule,
                "summary": str(e.summary or "")[:200],
            }
            for e in events[:per_group]
        ]
    return out


def count_events(fingerprints: list[str]) -> int:
    """成员组的事件总数（案件规模）。"""
    if not fingerprints:
        return 0
    with SessionLocal() as db:
        rows = db.scalars(
            select(EventGroup.fingerprint, EventGroup.event_count).where(
                EventGroup.fingerprint.in_([str(f) for f in fingerprints])
            )
        ).all()
    return sum(_safe_int(r[1]) for r in rows)
