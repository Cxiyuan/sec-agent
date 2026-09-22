"""资产管理：CRUD + CSV 两阶段导入 + 模板下载 + 重新向量化。"""

from __future__ import annotations

import csv
import io
import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.api.validation import (
    MAX_ERRORS,
    FieldError,
    split_list,
    validate_asset,
)
from app.config import settings
from app.db.base import get_db
from app.db.models import Asset, User
from app.rag.indexer import clear_chunks
from app.rag.parser import decode_text
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
    "is_external",
]

EXTERNAL_TRUE = {"1", "true", "yes", "y", "是", "外部"}


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
    is_external: bool = False
    allow_ip_share: bool = False


# ---------- 序列化 ----------


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
        "is_external": a.is_external,
        "allow_ip_share": a.allow_ip_share,
        "embedding_status": a.embedding_status,
    }


def _brief(a: Asset) -> dict[str, Any]:
    """冲突/重复提示用的摘要。"""
    return {
        "id": a.id,
        "ip": a.ip,
        "asset_name": a.asset_name,
        "business_system": a.business_system,
        "importance": a.importance,
        "owner": a.owner,
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
    a.is_external = body.is_external
    a.allow_ip_share = body.allow_ip_share
    a.embedding_status = "pending"


# ---------- 冲突检查 ----------


def _all_ips(payload: dict[str, Any]) -> list[str]:
    ip = str(payload.get("ip") or "").strip()
    extras = split_list(payload.get("extra_ips"))
    return ([ip] if ip else []) + extras


def _load_index(db: Session) -> tuple[dict[str, Asset], dict[str, list[Asset]]]:
    """返回 (主 IP 索引, 任意 IP[主+额外] 索引)。"""
    by_ip: dict[str, Asset] = {}
    by_any: dict[str, list[Asset]] = {}
    for a in db.scalars(select(Asset)).all():
        by_ip[a.ip] = a
        by_any.setdefault(a.ip, []).append(a)
        for e in a.extra_ips or []:
            by_any.setdefault(str(e), []).append(a)
    return by_ip, by_any


def _holdings(by_any: dict[str, list[Asset]], ips: list[str], exclude_id: str | None) -> list[Asset]:
    seen: dict[str, Asset] = {}
    for ip in ips:
        for a in by_any.get(ip, []):
            if exclude_id and a.id == exclude_id:
                continue
            seen[a.id] = a
    return list(seen.values())


def _field_error_response(errors: list[FieldError]) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={
            "conflict": "field_error",
            "detail": errors[0].msg if errors else "校验失败",
            "field_errors": [e.as_dict() for e in errors],
        },
    )


def _duplicate_response(existing: Asset, hint: str) -> JSONResponse:
    return JSONResponse(
        status_code=409,
        content={
            "conflict": "duplicate_ip",
            "detail": "该 IP 已存在",
            "existing": _brief(existing),
            "hint": hint,
        },
    )


def _ip_conflict_response(holders: list[Asset], ips: list[str]) -> JSONResponse:
    return JSONResponse(
        status_code=409,
        content={
            "conflict": "ip_conflict",
            "detail": "该 IP 已被其它资产占用",
            "ips": ips,
            "holders": [_brief(h) for h in holders],
            "hint": "勾选『允许该 IP 归属多个资产』后可放行",
        },
    )


# ---------- 列表 / 单条写入 ----------


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
    payload = body.model_dump()
    errors = validate_asset(payload, is_external=body.is_external)
    if errors:
        return _field_error_response(errors)

    ip = body.ip.strip()
    by_ip, by_any = _load_index(db)
    if ip in by_ip:
        return _duplicate_response(by_ip[ip], "查看摘要后选择是否覆盖")

    if not body.allow_ip_share:
        holders = _holdings(by_any, _all_ips(payload), exclude_id=None)
        if holders:
            return _ip_conflict_response(holders, [h.ip for h in holders])

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

    payload = body.model_dump()
    errors = validate_asset(payload, is_external=body.is_external)
    if errors:
        return _field_error_response(errors)

    ip = body.ip.strip()
    by_ip, by_any = _load_index(db)
    dup = by_ip.get(ip)
    if dup is not None and dup.id != asset_id:
        return _duplicate_response(dup, "该 IP 已被其它资产使用，请更换或先处理冲突")

    if not body.allow_ip_share:
        holders = _holdings(by_any, _all_ips(payload), exclude_id=asset_id)
        if holders:
            return _ip_conflict_response(holders, [h.ip for h in holders])

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


# ---------- CSV 导入（两阶段） ----------


def _read_rows(file_bytes: bytes) -> list[dict[str, Any]]:
    """解码 + 表头校验 + 行数/体积校验，返回原始行列表。"""
    if len(file_bytes) > settings.asset_csv_max_mb * 1024 * 1024:
        raise HTTPException(
            status_code=400, detail=f"文件过大（>{settings.asset_csv_max_mb}MB）"
        )
    try:
        text = decode_text(file_bytes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    reader = csv.DictReader(io.StringIO(text))
    fieldnames = [f.strip() for f in (reader.fieldnames or [])]
    if "ip" not in fieldnames:
        raise HTTPException(status_code=400, detail="CSV 缺少必需的 ip 列（可下载模板参考）")

    rows = list(reader)
    if len(rows) > settings.asset_csv_max_rows:
        raise HTTPException(
            status_code=400, detail=f"超过最大行数 {settings.asset_csv_max_rows}"
        )
    return rows


def _row_payload(row: dict[str, Any]) -> dict[str, Any]:
    """CSV 行 -> 资产字段字典。"""
    def g(key: str) -> str:
        return str(row.get(key) or "").strip()

    return {
        "ip": g("ip"),
        "extra_ips": split_list(g("extra_ips")),
        "hostname": g("hostname"),
        "asset_name": g("asset_name"),
        "business_system": g("business_system"),
        "owner": g("owner"),
        "importance": g("importance") or "medium",
        "asset_type": g("asset_type"),
        "network_zone": g("network_zone"),
        "os": g("os"),
        "services": g("services"),
        "tags": split_list(g("tags")),
        "location": g("location"),
        "description": g("description"),
        "is_external": g("is_external").lower() in EXTERNAL_TRUE,
    }


def _analyse(
    db: Session, rows: list[dict[str, Any]], allow_external: bool
) -> dict[str, Any]:
    """校验全量行，返回预览报告（不写库）。"""
    errors: list[dict[str, Any]] = []
    duplicates: list[dict[str, Any]] = []
    ip_conflicts: list[dict[str, Any]] = []
    non_lan: list[dict[str, Any]] = []
    payloads: list[dict[str, Any]] = []
    new_count = 0
    truncated = False

    by_ip, by_any = _load_index(db)
    seen_ips: set[str] = set()

    for idx, row in enumerate(rows, start=2):
        payload = _row_payload(row)
        if allow_external:
            payload["is_external"] = True
        ip = payload["ip"]
        row_errors = validate_asset(payload, is_external=bool(payload["is_external"]))

        for e in row_errors:
            if len(errors) < MAX_ERRORS:
                errors.append({"row": idx, "ip": ip, "msg": f"{e.field}: {e.msg}"})
            else:
                truncated = True

        if not payload["is_external"]:
            from app.api.validation import in_lan_scope

            if ip and not in_lan_scope(ip):
                non_lan.append({"row": idx, "ip": ip})

        if row_errors:
            continue
        if ip in seen_ips:
            if len(errors) < MAX_ERRORS:
                errors.append({"row": idx, "ip": ip, "msg": "文件内主 IP 重复"})
            else:
                truncated = True
            continue
        seen_ips.add(ip)

        existing = by_ip.get(ip)
        if existing is not None:
            duplicates.append({"row": idx, "ip": ip, "existing": _brief(existing)})
        else:
            new_count += 1

        holders = _holdings(by_any, _all_ips(payload), exclude_id=existing.id if existing else None)
        if holders:
            ip_conflicts.append(
                {"row": idx, "ip": ip, "holders": [_brief(h) for h in holders]}
            )
        payloads.append({"row": idx, "payload": payload, "is_new": existing is None})

    return {
        "ok": not errors,
        "truncated": truncated,
        "total_rows": len(rows),
        "errors": errors,
        "new_count": new_count,
        "duplicates": duplicates,
        "ip_conflicts": ip_conflicts,
        "non_lan": non_lan,
        "_payloads": payloads,
    }


@router.post("/import/preview")
async def import_preview(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    file: Annotated[UploadFile, File()],
    allow_external: Annotated[bool, Form()] = False,
):
    raw = await file.read()
    report = _analyse(db, _read_rows(raw), allow_external=allow_external)
    report.pop("_payloads", None)
    return report


@router.post("/import")
async def import_csv(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    file: Annotated[UploadFile, File()],
    overwrite_ips: Annotated[str, Form()] = "[]",
    allow_ip_share: Annotated[bool, Form()] = False,
    allow_external: Annotated[bool, Form()] = False,
):
    try:
        overwrite = set(json.loads(overwrite_ips or "[]"))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="overwrite_ips 必须是 JSON 数组") from exc
    if not isinstance(overwrite, set):
        overwrite = set()

    raw = await file.read()
    report = _analyse(db, _read_rows(raw), allow_external=allow_external)

    if report["errors"]:  # 整批拒绝
        return JSONResponse(
            status_code=400,
            content={
                "conflict": "import_rejected",
                "detail": f"有 {len(report['errors'])} 处错误，整批未导入（请修正后重试）",
                "truncated": report["truncated"],
                "errors": report["errors"],
            },
        )

    by_ip, by_any = _load_index(db)
    if not allow_ip_share:
        unresolved = _holdings(
            by_any,
            [ip for p in report["_payloads"] for ip in _all_ips(p["payload"])],
            exclude_id=None,
        )
        # 排除掉本次会覆盖的同主 IP 资产
        overwrite_ids = {
            by_ip[p["payload"]["ip"]].id
            for p in report["_payloads"]
            if p["payload"]["ip"] in overwrite and p["payload"]["ip"] in by_ip
        }
        unresolved = [h for h in unresolved if h.id not in overwrite_ids]
        if unresolved:
            return _ip_conflict_response(unresolved, [h.ip for h in unresolved])

    created = updated = skipped = external = 0
    affected: list[str] = []
    for item in report["_payloads"]:
        payload = item["payload"]
        ip = payload["ip"]
        existing = by_ip.get(ip)
        body = AssetIn(**payload, allow_ip_share=allow_ip_share)
        if existing is not None:
            if ip not in overwrite:
                skipped += 1
                continue
            _apply(existing, body)
            affected.append(existing.id)
            updated += 1
        else:
            a = Asset()
            _apply(a, body)
            db.add(a)
            db.flush()
            affected.append(a.id)
            created += 1
        if payload.get("is_external"):
            external += 1

    db.commit()
    for aid in affected:
        _reindex_async(aid)
    return {"created": created, "updated": updated, "skipped": skipped, "external": external}


@router.get("/template")
def download_template(_: Annotated[User, Depends(get_current_user)]):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_COLUMNS)
    writer.writerow(
        [
            "192.168.1.10",
            "192.168.1.11|192.168.1.0/24",
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
            "承载订单交易主库，对外提供 3306 服务（IP 可填单机或 CIDR 网段）",
            "false",
        ]
    )
    return StreamingResponse(
        io.BytesIO(buf.getvalue().encode("utf-8-sig")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=assets_template.csv"},
    )
