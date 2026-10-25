"""资产中心：资产发现 / 资产分组 / 资产扫描 / 资产管理。

四块的职责（用户 2026-10 定的信息架构）：
- **发现**：从镜像流量里「看到」网段内的主机（ES 聚合 dst_ip，按流量排序），并标出**未纳管**的；
- **分组**：业务/责任维度的归类（`asset_groups`）；
- **扫描**：本部署**不主动发包**（生产网段发探测包风险高、需授权），改成"被动发现 + 端口暴露面"：
  同一份 ES 数据里看每台主机**被访问过哪些端口**，把没纳管的挑出来当待办；
- **管理**：台账（`asset_records`）的增删改查，可绑定分组。

为什么台账单独建表：`asset_stats` 是统计基线（每窗口滚动），台账是人工事实（责任人、级别），
两者生命周期与写入者都不同，混一张表以后必然要拆。
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.api.deps import get_current_user
from app.config import settings
from app.db.base import SessionLocal
from app.db.models import AssetGroup, AssetRecord, User
from app.ingestion import scope as scope_mod
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/assets", tags=["assets"])

CRITICALITY = ("core", "high", "normal", "test")

#: 端口 → 应用名（与可视化流量同一份口径，避免两处各写一套）
#: `shard_problem` 同样复用：ES 分片报错时会安静地返回 0 桶，必须显式说出来
from app.api.routes.traffic_views import app_of, shard_problem


def _es() -> Any:
    from app.ingestion.es_client import get_es

    return get_es()


def _nets() -> list[ipaddress._BaseNetwork]:
    out: list[ipaddress._BaseNetwork] = []
    for text in scope_mod.monitored_nets():
        try:
            out.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            continue
    return out


def _in(ip: str, nets: Iterable[ipaddress._BaseNetwork]) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return any(addr in net for net in nets if getattr(net, "version", 0) == addr.version)


# ---------- 分组 ----------


class GroupIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    color: str = ""
    note: str = ""


class GroupPatch(BaseModel):
    name: str | None = None
    color: str | None = None
    note: str | None = None


def _group_dict(row: AssetGroup, count: int = 0) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "color": row.color or "",
        "note": row.note or "",
        "assets": count,
        "created_at": row.created_at.isoformat() if row.created_at else "",
    }


@router.get("/groups")
def list_groups(_: Annotated[User, Depends(get_current_user)]) -> dict[str, Any]:
    with SessionLocal() as db:
        rows = db.scalars(select(AssetGroup).order_by(AssetGroup.name)).all()
        counts = dict(
            db.execute(
                select(AssetRecord.group_id, func.count()).group_by(AssetRecord.group_id)
            ).all()
        )
    return {"items": [_group_dict(r, int(counts.get(r.id, 0))) for r in rows]}


@router.post("/groups")
def create_group(payload: GroupIn, _: Annotated[User, Depends(get_current_user)]) -> dict[str, Any]:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="分组名不能为空")
    with SessionLocal() as db:
        exists = db.scalars(select(AssetGroup).where(AssetGroup.name == name)).first()
        if exists is not None:
            raise HTTPException(status_code=409, detail=f"分组「{name}」已存在")
        row = AssetGroup(name=name, color=payload.color or "", note=payload.note or "")
        db.add(row)
        db.commit()
        db.refresh(row)
        return _group_dict(row, 0)


@router.patch("/groups/{group_id}")
def update_group(
    group_id: str, payload: GroupPatch, _: Annotated[User, Depends(get_current_user)]
) -> dict[str, Any]:
    with SessionLocal() as db:
        row = db.get(AssetGroup, group_id)
        if row is None:
            raise HTTPException(status_code=404, detail="分组不存在")
        if payload.name is not None:
            name = payload.name.strip()
            if not name:
                raise HTTPException(status_code=400, detail="分组名不能为空")
            row.name = name
        if payload.color is not None:
            row.color = payload.color
        if payload.note is not None:
            row.note = payload.note
        db.commit()
        db.refresh(row)
        count = (
            db.scalar(
                select(func.count()).select_from(AssetRecord).where(AssetRecord.group_id == row.id)
            )
            or 0
        )
        return _group_dict(row, int(count))


@router.delete("/groups/{group_id}")
def delete_group(group_id: str, _: Annotated[User, Depends(get_current_user)]) -> dict[str, Any]:
    with SessionLocal() as db:
        row = db.get(AssetGroup, group_id)
        if row is None:
            raise HTTPException(status_code=404, detail="分组不存在")
        # 组删了资产不能跟着删：把成员的 group_id 清空（资产回到"未分组"）
        for asset in db.scalars(select(AssetRecord).where(AssetRecord.group_id == group_id)).all():
            asset.group_id = ""
        db.delete(row)
        db.commit()
    return {"deleted": group_id}


# ---------- 台账 ----------


class AssetIn(BaseModel):
    ip: str = Field(min_length=1, max_length=64)
    hostname: str = ""
    group_id: str = ""
    owner: str = ""
    criticality: str = "normal"
    tags: str = ""
    note: str = ""


class AssetPatch(BaseModel):
    hostname: str | None = None
    group_id: str | None = None
    owner: str | None = None
    criticality: str | None = None
    tags: str | None = None
    note: str | None = None


def _asset_dict(row: AssetRecord, groups: dict[str, str]) -> dict[str, Any]:
    return {
        "id": row.id,
        "ip": row.ip,
        "hostname": row.hostname or "",
        "group_id": row.group_id or "",
        "group_name": groups.get(row.group_id or "", ""),
        "owner": row.owner or "",
        "criticality": row.criticality or "normal",
        "tags": [t.strip() for t in (row.tags or "").split(",") if t.strip()],
        "note": row.note or "",
        "created_at": row.created_at.isoformat() if row.created_at else "",
        "updated_at": row.updated_at.isoformat() if row.updated_at else "",
    }


def _groups_map(db: Any) -> dict[str, str]:
    return {r.id: r.name for r in db.scalars(select(AssetGroup)).all()}


def records(
    *,
    q: str = "",
    group_id: str = "",
    criticality: str = "",
    limit: int = 200,
    offset: int = 0,
) -> dict[str, Any]:
    """台账查询（**无鉴权的版本**：界面路由与智能体工具共用一份实现）。"""
    cap = max(1, min(int(limit or 200), 1000))
    start = max(0, int(offset or 0))
    with SessionLocal() as db:
        conds = []
        if (q or "").strip():
            pat = f"%{q.strip()}%"
            conds.append(AssetRecord.ip.ilike(pat) | AssetRecord.hostname.ilike(pat))
        if (group_id or "").strip():
            conds.append(AssetRecord.group_id == group_id.strip())
        if (criticality or "").strip():
            conds.append(AssetRecord.criticality == criticality.strip())
        total = int(db.scalar(select(func.count()).select_from(AssetRecord).where(*conds)) or 0)
        rows = db.scalars(
            select(AssetRecord).where(*conds).order_by(AssetRecord.ip).limit(cap).offset(start)
        ).all()
        groups = _groups_map(db)
    return {"total": total, "items": [_asset_dict(r, groups) for r in rows]}


def records_by_ips(ips: list[str]) -> dict[str, Any]:
    """按 IP 精确取台账（智能体判"这台重不重要"的主用法）。

    返回里带 `known` / `unknown_ips`：**没进台账不等于不重要**，
    这个区分必须显式给出去，否则智能体会把"没登记"读成"无所谓"。
    """
    wanted = [str(x).strip()[:64] for x in (ips or []) if str(x).strip()][:200]
    if not wanted:
        return {"error": "要 ips（IP 清单）", "items": [], "known": 0, "unknown_ips": []}
    with SessionLocal() as db:
        rows = db.scalars(select(AssetRecord).where(AssetRecord.ip.in_(wanted))).all()
        groups = _groups_map(db)
    found = {str(r.ip): _asset_dict(r, groups) for r in rows}
    return {
        "items": [found[ip] for ip in wanted if ip in found],
        "known": len(found),
        "unknown_ips": [ip for ip in wanted if ip not in found],
        "note": "unknown_ips 是**没进资产台账**的地址（不代表不重要，只代表没登记）",
    }


@router.get("/records")
def list_records(
    _: Annotated[User, Depends(get_current_user)],
    q: str = "",
    group_id: str = "",
    criticality: str = "",
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    return records(q=q, group_id=group_id, criticality=criticality, limit=limit, offset=offset)


@router.post("/records")
def create_record(
    payload: AssetIn, _: Annotated[User, Depends(get_current_user)]
) -> dict[str, Any]:
    ip = payload.ip.strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="IP 格式不对") from exc
    criticality = payload.criticality if payload.criticality in CRITICALITY else "normal"
    with SessionLocal() as db:
        exists = db.scalars(select(AssetRecord).where(AssetRecord.ip == ip)).first()
        if exists is not None:
            raise HTTPException(status_code=409, detail=f"{ip} 已在台账里")
        row = AssetRecord(
            ip=ip,
            hostname=payload.hostname or "",
            group_id=payload.group_id or "",
            owner=payload.owner or "",
            criticality=criticality,
            tags=payload.tags or "",
            note=payload.note or "",
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        groups = _groups_map(db)
        return _asset_dict(row, groups)


@router.patch("/records/{record_id}")
def update_record(
    record_id: str, payload: AssetPatch, _: Annotated[User, Depends(get_current_user)]
) -> dict[str, Any]:
    with SessionLocal() as db:
        row = db.get(AssetRecord, record_id)
        if row is None:
            raise HTTPException(status_code=404, detail="资产不存在")
        if payload.hostname is not None:
            row.hostname = payload.hostname
        if payload.group_id is not None:
            row.group_id = payload.group_id
        if payload.owner is not None:
            row.owner = payload.owner
        if payload.criticality is not None and payload.criticality in CRITICALITY:
            row.criticality = payload.criticality
        if payload.tags is not None:
            row.tags = payload.tags
        if payload.note is not None:
            row.note = payload.note
        db.commit()
        db.refresh(row)
        return _asset_dict(row, _groups_map(db))


@router.delete("/records/{record_id}")
def delete_record(record_id: str, _: Annotated[User, Depends(get_current_user)]) -> dict[str, Any]:
    with SessionLocal() as db:
        row = db.get(AssetRecord, record_id)
        if row is None:
            raise HTTPException(status_code=404, detail="资产不存在")
        db.delete(row)
        db.commit()
    return {"deleted": record_id}


# ---------- 发现（被动：从镜像流量里看到的网段内主机） ----------


def _discovery_body(*, minutes: int, size: int) -> dict[str, Any]:
    return {
        "size": 0,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": f"now-{minutes}m"}}}],
                "must_not": [{"terms": {"log_type.keyword": ["analyzer", "stats", "metrics"]}}],
            }
        },
        "aggs": {
            # 以"被访问的资产"为主语（dst）：这是界面上看到的"网段内主机"
            "hosts": {
                "terms": {"field": "dst_ip.keyword", "size": size, "order": {"bytes_in": "desc"}},
                "aggs": {
                    "bytes_out": {"sum": {"field": "bytes_out"}},
                    "bytes_in": {"sum": {"field": "bytes_in"}},
                    # 不用脚本求和（缺 bytes_* 的文档会让整个分片报错、结果静默变 0）
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "first_seen": {"min": {"field": "@timestamp"}},
                    "hostname": {"terms": {"field": "hostname.keyword", "size": 1}},
                    "clients": {
                        "cardinality": {"field": "src_ip.keyword", "precision_threshold": 40000}
                    },
                    "ports": {
                        "terms": {"field": "dst_port", "size": 20, "order": {"bo": "desc"}},
                        "aggs": {
                            "bo": {"sum": {"field": "bytes_out"}},
                            "bi": {"sum": {"field": "bytes_in"}},
                        },
                    },
                },
            }
        },
    }


def _shape_hosts(
    resp: Any, *, nets: list[ipaddress._BaseNetwork], managed: set[str]
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for bucket in (((resp.get("aggregations") or {}).get("hosts") or {}).get("buckets")) or []:
        ip = str(bucket.get("key") or "")
        if not ip or (nets and not _in(ip, nets)):
            continue
        hosts = ((bucket.get("hostname") or {}).get("buckets")) or []
        ports = [
            {
                "port": pb.get("key"),
                "app": app_of(pb.get("key")),
                "bytes": int((pb.get("bo") or {}).get("value") or 0)
                + int((pb.get("bi") or {}).get("value") or 0),
            }
            for pb in (((bucket.get("ports") or {}).get("buckets")) or [])
        ]
        bytes_out = int((bucket.get("bytes_out") or {}).get("value") or 0)
        bytes_in = int((bucket.get("bytes_in") or {}).get("value") or 0)
        out.append(
            {
                "ip": ip,
                "hostname": str(hosts[0].get("key") or "") if hosts else "",
                "bytes_out": bytes_out,
                "bytes_in": bytes_in,
                "bytes_total": bytes_out + bytes_in,
                "conns": int(bucket.get("doc_count") or 0),
                "clients": int((bucket.get("clients") or {}).get("value") or 0),
                "ports": ports,
                "exposure": len(ports),
                "first_seen": (bucket.get("first_seen") or {}).get("value_as_string") or "",
                "last_seen": (bucket.get("last_seen") or {}).get("value_as_string") or "",
                "managed": ip in managed,
            }
        )
    return out


@router.get("/discover")
def discover(
    _: Annotated[User, Depends(get_current_user)],
    minutes: int = Query(default=1440, ge=5, le=60 * 24 * 30),
    limit: int = Query(default=200, ge=1, le=500),
) -> dict[str, Any]:
    """资产发现：网段内被访问过的主机（被动发现，不发探测包）。"""
    nets = _nets()
    try:
        resp = _es().search(
            index=settings.es_events_index,
            body=_discovery_body(minutes=minutes, size=min(500, max(limit * 2, 100))),
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("资产发现失败: %s", exc)
        return {"items": [], "error": f"ES 查询失败：{exc}", "minutes": minutes}
    with SessionLocal() as db:
        managed = set(db.scalars(select(AssetRecord.ip)).all())
    rows = _shape_hosts(resp, nets=nets, managed=managed)[:limit]
    return {
        "items": rows,
        "warning": shard_problem(resp),
        "managed": sum(1 for r in rows if r["managed"]),
        "unmanaged": sum(1 for r in rows if not r["managed"]),
        "minutes": minutes,
        "monitored_nets": [str(n) for n in nets],
        "note": "被动发现：只统计镜像流量里出现过的主机，不向网段发探测包。",
    }


@router.get("/scan")
def scan_view(
    _: Annotated[User, Depends(get_current_user)],
    minutes: int = Query(default=1440, ge=5, le=60 * 24 * 30),
    limit: int = Query(default=200, ge=1, le=500),
) -> dict[str, Any]:
    """资产扫描（被动模式）：主机暴露面 + 未纳管清单。

    明确不做主动扫描：对生产网段发包需要授权、也会影响业务；这里用**镜像流量里已发生的
    访问**推断暴露面（哪些端口被访问过、哪些主机还没纳管），风险为零、结论一样能用。
    """
    nets = _nets()
    try:
        resp = _es().search(
            index=settings.es_events_index,
            body=_discovery_body(minutes=minutes, size=min(500, max(limit * 2, 100))),
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("资产扫描聚合失败: %s", exc)
        return {"items": [], "error": f"ES 查询失败：{exc}"}
    with SessionLocal() as db:
        managed = set(db.scalars(select(AssetRecord.ip)).all())
    rows = _shape_hosts(resp, nets=nets, managed=managed)
    # 扫描视图只关心"有暴露面"的：按暴露端口数、流量排序，未纳管的排前面
    rows.sort(key=lambda r: (r["managed"], -r["exposure"], -r["bytes_total"]))
    port_hits: dict[str, int] = {}
    for row in rows:
        for port in row["ports"]:
            key = f"{port['app']}（{port['port']}）"
            port_hits[key] = port_hits.get(key, 0) + 1
    top_ports = sorted(port_hits.items(), key=lambda kv: -kv[1])[:15]
    return {
        "items": rows[:limit],
        "warning": shard_problem(resp),
        "top_ports": [{"label": k, "hosts": v} for k, v in top_ports],
        "unmanaged": [r["ip"] for r in rows if not r["managed"]][:limit],
        "minutes": minutes,
        "mode": "passive",
        "note": (
            "被动扫描：不发探测包，只根据镜像流量里已发生的访问推断暴露面。"
            "对生产网段的主动端口扫描需要单独授权，本系统不默认执行。"
        ),
    }
