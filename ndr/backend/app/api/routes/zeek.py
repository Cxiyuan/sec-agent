"""Zeek 采集：监控网段 / 网卡配置下发、网卡清单、状态。

「监控网段」是一份多行清单（一行一条 CIDR/IP），由它生成 Zeek 的两个参数：

- `bpf_filter`：只抓这些网段（BPF 里 `net X` 本身即「源或目的落在 X」）；
- `local_nets`：Zeek 的 `Site::local_nets`（规则里的 src_internal / dst_internal 依赖它）。

后端只写**共享配置文件**（`/config/interface.conf`），Zeek 容器内的看门狗检测到变化后
在容器内重载 Zeek —— 后端不接触 docker socket，也不需要宿主权限。

清单同时落 SystemConfig：检测器（它不挂 /config 卷）读库里的那份，保证「抓什么就分析什么」。
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import runtime_config
from app.api.deps import get_current_user
from app.config import settings
from app.db.base import get_db
from app.db.models import SystemConfig, User
from app.ingestion.scope import (
    build_bpf,
    monitored_nets,
    nets_text,
    networks_status,
    parse_nets,
    validate_nets,
)

router = APIRouter(prefix="/api/zeek", tags=["zeek"])

#: interface.conf 里写哪些键（顺序即文件里的顺序）
CONF_KEYS = (
    "interface",
    "monitored_nets",
    "bpf_filter",
    "local_nets",
    "bpf_extra",
    "body_max_bytes",
    "resp_body_max_bytes",
)

#: 只有 interface / monitored_nets / bpf_extra / 两个上限是「输入」，另两个是由它们生成的输出
DEFAULT_CONF = {
    "interface": settings.zeek_interface,
    "monitored_nets": settings.zeek_monitored_nets,
    "bpf_filter": "",
    "local_nets": "",
    "bpf_extra": settings.zeek_bpf_extra,
    # 正文上限（字节）：Zeek 侧 shentong-limits.zeek 由这两个键渲染；后端 normalizer
    # 经 system_config 的 http.body_max_chars / http.resp_body_max_chars 用同一个数字截断
    "body_max_bytes": str(settings.http_body_max_chars),
    "resp_body_max_bytes": str(settings.http_resp_body_max_chars),
}

#: 正文上限可设范围（KB）：上限 1MB——Zeek 把正文留在内存里，放太大伤内存
LIMIT_KB_MIN = 1
LIMIT_KB_MAX = 1024


class ZeekIfaceIn(BaseModel):
    interface: str = ""  # 留空 = 保持当前网卡（首次向导只改网段时会用到）
    networks: str = ""  # 监控网段：一行一条（换行或逗号分隔）
    bpf_extra: str = ""  # 附加 BPF 条件（可选，如 not port 22）
    body_max_kb: int | None = None  # 请求正文上限（KB）；不传 = 沿用当前值
    resp_body_max_kb: int | None = None  # 响应正文上限（KB）；不传 = 沿用当前值


def _conf_bytes(conf: dict[str, str], key: str, default: int) -> int:
    """读 conf 里的字节数上限；缺失/非法时回落默认值。"""
    try:
        value = int(conf.get(key) or default)
    except (TypeError, ValueError):
        return default
    return value


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


def _write_conf(values: dict[str, str]) -> str | None:
    """原子写（先临时文件再 rename），避免看门狗读到半截内容。

    成功返回 None；失败返回错误说明（由调用方转成 400）。
    """
    path = settings.zeek_iface_conf
    dirname = os.path.dirname(path) or "."
    tmp = f"{path}.tmp"
    lines = [
        "# 由深瞳 Web 后台维护；本文件变化会被看门狗检测并重载采集器",
        f"# updated_at={datetime.now(UTC).isoformat()}",
    ]
    lines += [f"{key}={values.get(key, '')}" for key in CONF_KEYS]
    body = "\n".join(lines) + "\n"
    try:
        os.makedirs(dirname, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(body)
        os.replace(tmp, path)
    except OSError as exc:
        return str(exc)
    return None


def _conf_nets(conf: dict[str, str]) -> list[str]:
    """配置文件里的监控网段；文件里没有（如容器自建的空文件）则回落库里的那份。"""
    return parse_nets(conf.get("monitored_nets", "")) or monitored_nets()


def _put_config(db: Session, key: str, value: str) -> None:
    row = db.get(SystemConfig, key)
    if row is None:
        row = SystemConfig(key=key, value={})
        db.add(row)
    row.value = {"value": value}


#: 虚拟/环回网卡的名字模式（下拉里不该出现这些）。
#: 主判定是采集器容器写在 interfaces.json 里的 `physical`（sysfs 的
#: `/sys/class/net/<n>/device` 是否存在，只有 host 网络的采集器容器看得到宿主全部网卡）；
#: 这里做两道兑底：旧镜像还没写 `physical` 字段时，以及名字一看就是虚拟的口子。
_VIRTUAL_IFACE = re.compile(
    r"^(lo|docker\d*|br-[0-9a-f]+|veth\w+|virbr\d*|vmnet\d*|vboxnet\d*|tun\d*|tap\d*|"
    r"wg\d*|tailscale\d*|zt\w+|dummy\d*|ifb\d*|nflog|sit\d*|ip6tnl\d*|gre\d*|erspan\d*|"
    r"kube\w*|cni\d*|flannel\w*|cali\w*|cbr\d*|lxc\w*)$",
    re.IGNORECASE,
)


def _read_interfaces() -> list[dict[str, Any]]:
    """读采集器容器写入的宿主网卡清单，**只保留物理网卡**。

    界面上的「监听网卡」下拉由它渲染：docker0 / veth* / br-* / tun* 这类虚拟网卡
    不是抓包目标，列出来只会让人选错。
    """
    path = settings.zeek_interfaces_json
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    out: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        if not name or _VIRTUAL_IFACE.match(name):
            continue
        if "physical" in item and not item.get("physical"):
            continue
        out.append(item)
    return out


def _read_last_reload() -> str | None:
    path = os.path.join(settings.zeek_conf_dir, "last_reload")
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip() or None
    except OSError:
        return None


@router.get("/status")
def get_status(_: Annotated[User, Depends(get_current_user)]):
    conf = _read_conf()
    nets = _conf_nets(conf)
    bpf_extra = conf.get("bpf_extra", "")
    return {
        "interface": conf.get("interface") or settings.zeek_interface,
        "networks": nets,
        "bpf_extra": bpf_extra,
        "bpf_filter": build_bpf(nets, bpf_extra),
        "local_nets": ",".join(nets),
        "last_reload": _read_last_reload(),
        "config_path": settings.zeek_iface_conf,
        "detected": _read_interfaces(),
        # HTTP 正文上限（字节）：前端按 KB 展示；Zeek 侧与本服务的截断都以它为准
        "body_max_bytes": _conf_bytes(conf, "body_max_bytes", settings.http_body_max_chars),
        "resp_body_max_bytes": _conf_bytes(
            conf, "resp_body_max_bytes", settings.http_resp_body_max_chars
        ),
        # 镜像内硬编码（见 zeek/README.md）
        "rotation_hours": 24,
        "retention_days_local": 3,
    }


@router.get("/networks/status")
def get_networks_status(_: Annotated[User, Depends(get_current_user)]):
    """供前端判断是否已配置监控网段（未配置 → 强制进首次向导）。"""
    return networks_status()


@router.put("/interface")
def set_interface(
    body: ZeekIfaceIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    conf = _read_conf()
    iface = (body.interface or conf.get("interface") or settings.zeek_interface).strip()
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

    nets = parse_nets(body.networks)
    errors = validate_nets(nets)
    if errors:
        return JSONResponse(
            status_code=400,
            content={"conflict": "field_error", "detail": errors[0]["msg"], "field_errors": errors},
        )

    bpf_extra = body.bpf_extra.strip()

    # 正文上限：不传（None）= 沿用当前值；只接受 KB 整数，范围在这里兜住（entrypoint 只挡非数字）
    for label, kb in (
        ("请求正文上限", body.body_max_kb),
        ("响应正文上限", body.resp_body_max_kb),
    ):
        if kb is not None and not (LIMIT_KB_MIN <= kb <= LIMIT_KB_MAX):
            return JSONResponse(
                status_code=400,
                content={
                    "conflict": "field_error",
                    "detail": f"{label}需在 {LIMIT_KB_MIN}~{LIMIT_KB_MAX} KB 之间",
                    "field_errors": [
                        {"field": label, "msg": f"需在 {LIMIT_KB_MIN}~{LIMIT_KB_MAX} KB 之间"}
                    ],
                },
            )
    body_bytes = _conf_bytes(conf, "body_max_bytes", settings.http_body_max_chars)
    resp_bytes = _conf_bytes(conf, "resp_body_max_bytes", settings.http_resp_body_max_chars)
    if body.body_max_kb is not None:
        body_bytes = body.body_max_kb * 1024
    if body.resp_body_max_kb is not None:
        resp_bytes = body.resp_body_max_kb * 1024

    # 配置文件是 key=value 行格式，多行清单要压成逗号分隔（Zeek 侧按逗号切开渲染）
    nets_csv = ",".join(nets)
    values = {
        "interface": iface,
        "monitored_nets": nets_csv,
        "bpf_filter": build_bpf(nets, bpf_extra),
        "local_nets": nets_csv,
        "bpf_extra": bpf_extra,
        "body_max_bytes": str(body_bytes),
        "resp_body_max_bytes": str(resp_bytes),
    }

    write_error = _write_conf(values)
    if write_error:
        return JSONResponse(
            status_code=400,
            content={
                "conflict": "write_failed",
                "detail": (
                    f"写入网卡配置失败：{write_error}（请确认 /config 共享卷已挂载给后端与采集器）"
                ),
            },
        )

    # 同时落库：检测器不挂 /config 卷，它读这份；也便于展示与追溯
    for key, value in (
        ("zeek.interface", iface),
        ("zeek.monitored_nets", nets_text(nets)),
        ("zeek.bpf_filter", values["bpf_filter"]),
        ("zeek.local_nets", nets_csv),
        ("zeek.bpf_extra", bpf_extra),
        # 正文上限：normalizer 侧经 runtime_config 读这两个键（字符数，与 Zeek 侧字节数同值）
        ("http.body_max_chars", str(body_bytes)),
        ("http.resp_body_max_chars", str(resp_bytes)),
    ):
        _put_config(db, key, value)
    db.commit()
    # 本进程内的读取方（如内联规范化）立即用新值；normalizer 容器靠自己的 30 秒 TTL 过期
    runtime_config.invalidate()

    return {
        "ok": True,
        "interface": iface,
        "networks": nets,
        "bpf_extra": bpf_extra,
        "bpf_filter": values["bpf_filter"],
        "local_nets": nets_csv,
        "body_max_bytes": body_bytes,
        "resp_body_max_bytes": resp_bytes,
        "note": "已下发；采集器看门狗将在约 10 秒内自动重载（期间约 1~2 秒中断抓包）",
    }
