"""Zeek 采集：网卡配置下发 / 网卡清单 / 状态。

后端只写**共享配置文件**（`/config/interface.conf`），Zeek 容器内的看门狗检测到变化后
在容器内重载 Zeek —— 后端不接触 docker socket，也不需要宿主权限。
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.config import settings
from app.db.base import get_db
from app.db.models import SystemConfig, User
from app.ingestion.scope import enabled_cidrs

router = APIRouter(prefix="/api/zeek", tags=["zeek"])

DEFAULT_CONF = {
    "interface": settings.zeek_interface,
    "bpf_filter": settings.zeek_bpf_filter,
    "local_nets": settings.zeek_local_nets,
}


class ZeekIfaceIn(BaseModel):
    interface: str
    bpf_filter: str = ""
    local_nets: str = ""  # 留空则自动取「分析网段」


def _read_conf() -> dict[str, str]:
    """读共享配置文件；不存在时返回默认值。"""
    values = dict(DEFAULT_CONF)
    path = settings.zeek_iface_conf
    if not os.path.exists(path):
        return values
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                if key in values:
                    values[key] = val.strip()
    except OSError:
        return dict(DEFAULT_CONF)
    return values


def _write_conf(interface: str, bpf: str, local_nets: str) -> str | None:
    """原子写（先临时文件再 rename），避免看门狗读到半截内容。

    成功返回 None；失败返回错误说明（由调用方转成 400）。
    """
    path = settings.zeek_iface_conf
    dirname = os.path.dirname(path) or "."
    tmp = f"{path}.tmp"
    body = (
        "# 由深瞳 Web 后台维护；本文件变化会被看门狗检测并重载 Zeek\n"
        f"interface={interface}\n"
        f"bpf_filter={bpf}\n"
        f"local_nets={local_nets}\n"
        f"# updated_at={datetime.now(UTC).isoformat()}\n"
    )
    try:
        os.makedirs(dirname, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(body)
        os.replace(tmp, path)
    except OSError as exc:
        return str(exc)
    return None


def _read_interfaces() -> list[dict[str, Any]]:
    """读 Zeek 容器写入的宿主网卡清单。"""
    path = settings.zeek_interfaces_json
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []


def _read_last_reload() -> str | None:
    path = os.path.join(settings.zeek_conf_dir, "last_reload")
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip() or None
    except OSError:
        return None


def _split_nets(value: str) -> list[str]:
    return [x.strip() for x in (value or "").split(",") if x.strip()]


def _effective_nets(configured: str) -> list[str]:
    """生效的 Site::local_nets：显式配置优先，否则取启用中的分析网段。"""
    explicit = _split_nets(configured)
    return explicit or enabled_cidrs()


@router.get("/interfaces")
def list_interfaces(_: Annotated[User, Depends(get_current_user)]):
    """Zeek 容器枚举出的宿主网卡清单（供后台下拉选择）。"""
    return {"items": _read_interfaces()}


@router.get("/status")
def get_status(_: Annotated[User, Depends(get_current_user)]):
    conf = _read_conf()
    return {
        "interface": conf.get("interface") or settings.zeek_interface,
        "bpf_filter": conf.get("bpf_filter", ""),
        "local_nets": conf.get("local_nets", ""),
        "effective_local_nets": _effective_nets(conf.get("local_nets", "")),
        "last_reload": _read_last_reload(),
        "config_path": settings.zeek_iface_conf,
        "detected": _read_interfaces(),
        # 镜像内硬编码（见 zeek/README.md）
        "rotation_hours": 24,
        "retention_days_local": 3,
    }


@router.put("/interface")
def set_interface(
    body: ZeekIfaceIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    iface = body.interface.strip()
    if not iface:
        return JSONResponse(
            status_code=400,
            content={"conflict": "field_error", "detail": "网卡名不能为空"},
        )
    if any(ch.isspace() for ch in iface):
        return JSONResponse(
            status_code=400,
            content={"conflict": "field_error", "detail": "网卡名不能包含空格"},
        )

    local_nets = body.local_nets.strip()
    if not local_nets:
        local_nets = ",".join(enabled_cidrs())

    write_error = _write_conf(iface, body.bpf_filter.strip(), local_nets)
    if write_error:
        return JSONResponse(
            status_code=400,
            content={
                "conflict": "write_failed",
                "detail": (
                    f"写入网卡配置失败：{write_error}"
                    "（请确认 /config 共享卷已挂载给后端与 Zeek）"
                ),
            },
        )

    # 同时落库（便于展示与追溯；文件才是 Zeek 实际读取的来源）
    for key, value in (
        ("zeek.interface", iface),
        ("zeek.bpf_filter", body.bpf_filter.strip()),
        ("zeek.local_nets", body.local_nets.strip()),
    ):
        row = db.get(SystemConfig, key)
        if row is None:
            row = SystemConfig(key=key, value={})
            db.add(row)
        row.value = {"value": value}
    db.commit()

    return {
        "ok": True,
        "interface": iface,
        "bpf_filter": body.bpf_filter.strip(),
        "local_nets": local_nets,
        "note": "已下发；Zeek 看门狗将在约 10 秒内重载（期间约 1~2 秒中断抓包）",
    }
