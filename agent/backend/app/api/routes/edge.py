"""边缘模型（本地 llama-server）连接管理：IP 配置 + 连通性测试。

连接信息（api_key/模型名/端口/路径）已在 app/edge_config.py 固化，
此处只管理可变项 IP，并提供一键测试（调 /v1/models 验证 IP 可达 + key 正确）。
"""

from __future__ import annotations

import ipaddress
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.base import get_db
from app.db.models import SystemConfig, User
from app.edge_config import (
    EDGE_API_KEY,
    EDGE_MODEL_LABEL,
    EDGE_PORT,
    edge_base_url,
    edge_base_url_for,
    edge_current_ip,
)
from app.runtime_config import invalidate as invalidate_runtime_config

router = APIRouter(prefix="/api/edge", tags=["edge"])


class EdgeIpIn(BaseModel):
    ip: str


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address((ip or "").strip())
        return True
    except ValueError:
        return False


@router.get("")
def get_edge(_: Annotated[User, Depends(get_current_user)]):
    return {
        "ip": edge_current_ip(),
        "base_url": edge_base_url(),
        "model_label": EDGE_MODEL_LABEL,
        "port": EDGE_PORT,
        "api_key_set": bool(EDGE_API_KEY),
    }


@router.put("/ip")
def set_edge_ip(
    body: EdgeIpIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    ip = (body.ip or "").strip()
    if not _valid_ip(ip):
        return JSONResponse(
            status_code=400,
            content={"conflict": "field_error", "detail": "IP 格式非法"},
        )
    row = db.get(SystemConfig, "edge.model.ip")
    if row is None:
        row = SystemConfig(key="edge.model.ip", value={})
        db.add(row)
    row.value = {"value": ip}
    db.commit()
    invalidate_runtime_config()
    return {"ip": ip, "base_url": edge_base_url_for(ip)}


@router.post("/test")
def test_edge(body: EdgeIpIn, _: Annotated[User, Depends(get_current_user)]):
    ip = (body.ip or "").strip()
    if not _valid_ip(ip):
        return JSONResponse(
            status_code=400,
            content={"conflict": "field_error", "detail": "IP 格式非法"},
        )
    base = edge_base_url_for(ip)
    try:
        with httpx.Client(timeout=3.0, follow_redirects=True) as client:
            resp = client.get(f"{base}/models", headers={"Authorization": f"Bearer {EDGE_API_KEY}"})
    except httpx.HTTPError as exc:
        return {"ok": False, "status": "unreachable", "detail": f"不可达：{exc}", "base_url": base}

    if resp.status_code == 200:
        try:
            data = resp.json()
        except ValueError:
            data = {}
        models = data.get("data", []) if isinstance(data, dict) else []
        return {
            "ok": True,
            "status": "ok",
            "detail": "连接成功",
            "base_url": base,
            "models": [m.get("id") for m in models if isinstance(m, dict)][:10],
        }
    if resp.status_code == 401:
        return {
            "ok": False,
            "status": "auth_failed",
            "detail": "认证失败（api key 不匹配）",
            "base_url": base,
        }
    return {
        "ok": False,
        "status": f"http_{resp.status_code}",
        "detail": f"HTTP {resp.status_code}",
        "base_url": base,
    }
