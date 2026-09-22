"""资产管理：CRUD + CSV 导入 + 模板下载 + 重新向量化。"""

from __future__ import annotations

import csv
import io
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.base import get_db
from app.db.models import Asset, User
from app.rag.indexer import clear_chunks
from app.rag.queue import enqueue_asset_index as _reindex_async

router = APIRouter(prefix="/api/assets", tags=["assets"])

CSV_COLUMNS = [
    "ip",
    "extra_ips",
    "hostname",
    "asset_name",
    "business_system",
    "owner",
    "importance",
    "asset_type",
    "network_zone",
    "os",
    "services",
    "tags",
    "location",
    "description",
]


class AssetIn(BaseModel):
    ip: str
    extra_ips: list[str] = Field(default_factory=list)
    hostname: str = ""
    asset_name: str = ""
    business_system: str = ""
    owner: str = ""
    importance: str = "medium"
    asset_type: str = ""
    network_zone: str = ""
    os: str = ""
    services: str = ""
    tags: list[str] = Field(default_factory=list)
    location: str = ""
    description: str = ""


def _asset_dict(a: Asset) -> dict[str, Any]:
    return {
        "id": a.id,
        "ip": a.ip,
        "extra_ips": a.extra_ips or [],
        "hostname": a.hostname,
        "asset_name": a.asset_name,
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
        "embedding_status": a.embedding_status,
    }


def _apply(a: Asset, body: AssetIn) -> None:
    a.ip = body.ip.strip()
    a.extra_ips = [x.strip() for x in body.extra_ips if x.strip()]
    a.hostname = body.hostname
    a.asset_name = body.asset_name
    a.business_system = body.business_system
    a.owner = body.owner
    a.importance = body.importance
    a.asset_type = body.asset_type
    a.network_zone = body.network_zone
    a.os = body.os
    a.services = body.services
    a.tags = [x.strip() for x in body.tags if x.strip()]
    a.location = body.location
    a.description = body.description
    a.embedding_status = "pending"


@router.get("")
def list_assets(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    q: str | None = None,
    importance: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    conds = []
    if q:
        like = f"%{q}%"
        conds.append(
            or_(
                Asset.ip.ilike(like),
                Asset.asset_name.ilike(like),
                Asset.hostname.ilike(like),
                Asset.business_system.ilike(like),
                Asset.owner.ilike(like),
            )
        )
    if importance:
        conds.append(Asset.importance == importance)

    count_q = select(func.count()).select_from(Asset)
    q_stmt = select(Asset).order_by(Asset.ip)
    for c in conds:
        count_q = count_q.where(c)
        q_stmt = q_stmt.where(c)
    total = db.scalar(count_q) or 0
    rows = db.scalars(q_stmt.limit(limit).offset(offset)).all()
    return {"total": total, "items": [_asset_dict(a) for a in rows]}


@router.post("")
def create_asset(
    body: AssetIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    if not body.ip.strip():
        raise HTTPException(status_code=400, detail="IP 不能为空")
    exists = db.scalars(select(Asset).where(Asset.ip == body.ip.strip())).first()
    if exists:
        raise HTTPException(status_code=409, detail="该 IP 已存在")
    a = Asset()
    _apply(a, body)
    db.add(a)
    db.commit()
    _reindex_async(a.id)
    return _asset_dict(a)


@router.put("/{asset_id}")
def update_asset(
    asset_id: str,
    body: AssetIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    a = db.get(Asset, asset_id)
    if a is None:
        raise HTTPException(status_code=404, detail="资产不存在")
    conflict = db.scalars(
        select(Asset).where(Asset.ip == body.ip.strip(), Asset.id != asset_id)
    ).first()
    if conflict:
        raise HTTPException(status_code=409, detail="该 IP 已被其他资产占用")
    _apply(a, body)
    db.commit()
    _reindex_async(a.id)
    return _asset_dict(a)


@router.delete("/{asset_id}")
def delete_asset(
    asset_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    a = db.get(Asset, asset_id)
    if a is None:
        raise HTTPException(status_code=404, detail="资产不存在")
    clear_chunks("asset", asset_id)
    db.delete(a)
    db.commit()
    return {"ok": True}


@router.post("/{asset_id}/reindex")
def reindex_asset(
    asset_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    a = db.get(Asset, asset_id)
    if a is None:
        raise HTTPException(status_code=404, detail="资产不存在")
    a.embedding_status = "pending"
    db.commit()
    _reindex_async(asset_id)
    return {"ok": True, "status": "pending"}


def _csv_list(value: str) -> list[str]:
    return [x.strip() for x in (value or "").replace("|", ",").split(",") if x.strip()]


@router.post("/import")
async def import_csv(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    file: Annotated[UploadFile, File()],
):
    raw = await file.read()
    text = raw.decode("utf-8-sig", errors="ignore")
    reader = csv.DictReader(io.StringIO(text))
    created, updated, failed = 0, 0, 0
    errors: list[str] = []
    affected: list[str] = []

    for idx, row in enumerate(reader, start=2):
        ip = (row.get("ip") or "").strip()
        if not ip:
            failed += 1
            errors.append(f"第{idx}行：缺少 ip")
            continue
        a = db.scalars(select(Asset).where(Asset.ip == ip)).first()
        is_new = a is None
        if a is None:
            a = Asset(ip=ip)
            db.add(a)
            db.flush()
        a.extra_ips = _csv_list(row.get("extra_ips", ""))
        a.hostname = row.get("hostname") or ""
        a.asset_name = row.get("asset_name") or ""
        a.business_system = row.get("business_system") or ""
        a.owner = row.get("owner") or ""
        a.importance = (row.get("importance") or "medium").strip()
        a.asset_type = row.get("asset_type") or ""
        a.network_zone = row.get("network_zone") or ""
        a.os = row.get("os") or ""
        a.services = row.get("services") or ""
        a.tags = _csv_list(row.get("tags", ""))
        a.location = row.get("location") or ""
        a.description = row.get("description") or ""
        a.embedding_status = "pending"
        affected.append(a.id)
        if is_new:
            created += 1
        else:
            updated += 1

    db.commit()
    for aid in affected:  # 仅重算受影响资产
        _reindex_async(aid)
    return {"created": created, "updated": updated, "failed": failed, "errors": errors[:50]}


@router.get("/template")
def download_template(_: Annotated[User, Depends(get_current_user)]):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_COLUMNS)
    writer.writerow(
        [
            "192.168.1.10",
            "192.168.1.11|192.168.1.12",
            "db01",
            "核心数据库服务器",
            "订单系统",
            "张三",
            "critical",
            "服务器",
            "生产网",
            "CentOS 7.9",
            "3306,6379",
            "数据库|核心",
            "A机房",
            "承载订单交易主库，对外提供 3306 服务",
        ]
    )
    return StreamingResponse(
        io.BytesIO(buf.getvalue().encode("utf-8-sig")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=assets_template.csv"},
    )
