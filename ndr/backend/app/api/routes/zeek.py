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
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import runtime_config
from app.api.deps import get_current_user
from app.config import settings
from app.db.base import get_db
from app.db.models import SystemConfig, User
from app.ingestion import relay_nodes
from app.ingestion.scope import (
    build_bpf,
    monitored_nets,
    nets_text,
    networks_status,
    parse_nets,
    validate_nets,
)
from app.workers.log import get_logger

log = get_logger(__name__)

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
    # 这些端口在本环境是 TLS：不再按 HTTP 解析（见下面 tls_ports 的注释）
    "tls_ports",
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
    # 「按 TLS 解析的端口」（逗号分隔，空 = 不改 Zeek 默认端口表）。
    # 为什么要它（2026-10 实机实测）：Zeek 自带 HTTP 端口表含 8000/8008，而本环境这两个端口
    # 是 TLS → TLS 字节被当成 HTTP 行，刷出 5.2 万条 `bad_HTTP_request` /
    # `line_terminated_with_single_CR` 假协议异常。端口是**环境相关**的（本环境 8013 就是真
    # 明文 HTTP），所以做成部署配置而不是写死在产品代码里；空值 = 不做任何改动。
    "tls_ports": "",
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
    tls_ports: str | None = None  # 按 TLS 解析的端口（逗号/换行分隔）；不传 = 沿用当前值


def parse_tls_ports(text: Any) -> tuple[list[int], list[dict[str, str]]]:
    """解析「按 TLS 解析的端口」：返回 (端口列表, 错误列表)。容忍 `8000` 与 `8000/tcp` 两种写法。"""
    ports: list[int] = []
    errors: list[dict[str, str]] = []
    for chunk in str(text or "").replace(",", " ").split():
        token = chunk.strip()
        if not token or token.startswith("#"):
            continue
        value = token.split("/")[0].strip()
        if not value.isdigit():
            errors.append({"field": "tls_ports", "msg": f"不是合法端口：{token}"})
            continue
        port = int(value)
        if not 1 <= port <= 65535:
            errors.append({"field": "tls_ports", "msg": f"端口超出范围（1~65535）：{token}"})
            continue
        if port not in ports:
            ports.append(port)
    return ports, errors


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


def _read_suricata_status() -> dict[str, Any] | None:
    """签名引擎（Suricata）自己写在共享规则卷里的运行状态。

    文件是容器入口的 write_runtime 定期刷新的（存活/网卡/网段/规则文件与条数/引擎版本），
    见 ``ndr/suricata/entrypoint.sh``。读不到 = 没部署或根本没跑起来，界面按「未启用」显示。
    """
    path = os.path.join(settings.suricata_rules_dir, "runtime.json")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.loads(fh.read())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


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
        # 按 TLS 解析的端口（空 = 沿用 Zeek 默认 HTTP 端口表）
        "tls_ports": conf.get("tls_ports", ""),
        # 签名引擎（Suricata）：与网络采集器共用本页的网卡/网段配置，
        # 这里回它自己上报的状态（无 = 未部署/未运行）
        "suricata": _read_suricata_status(),
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

    # 按 TLS 解析的端口：不传 = 沿用当前值；只接受端口号（`8000` / `8000/tcp`）
    tls_ports = conf.get("tls_ports", "")
    if body.tls_ports is not None:
        parsed, port_errors = parse_tls_ports(body.tls_ports)
        if port_errors:
            return JSONResponse(
                status_code=400,
                content={
                    "conflict": "field_error",
                    "detail": port_errors[0]["msg"],
                    "field_errors": port_errors,
                },
            )
        tls_ports = ",".join(str(port) for port in parsed)

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
        "tls_ports": tls_ports,
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
        # 「按 TLS 解析的端口」也落库：检测器/归一化不挂 /config 卷，读这份更一致
        ("zeek.tls_ports", tls_ports),
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
        "tls_ports": tls_ports,
        "note": "已下发；采集器看门狗将在约 10 秒内自动重载（期间约 1~2 秒中断抓包）",
    }


# ---------- 中继节点清单（反代 / WAF / 内网 DNS 转发器） ----------
#
# 单独一个端点，**不挂在网段接口上**：改中继清单不需要动 Zeek 配置，
# 挂在一起会白白触发一次采集器重载（1~2 秒中断抓包）。


class RelayNodesIn(BaseModel):
    nodes: str = ""


class RelaySidesIn(BaseModel):
    #: {中继地址: "auto" | "front" | "back"}；`auto` = 按实测内容自动判
    sides: dict[str, str] = Field(default_factory=dict)


@router.get("/relay-nodes")
def get_relay_nodes(_: Annotated[User, Depends(get_current_user)]):
    """中继节点清单：**只读 PG**，界面「监控网段」页维护。

    PG 里没有 = 系统认定「网络里没有中继」：不信任任何代理头（`real_client_ip` 恒空）、
    所有事件 `hop=direct`、不做中继配对与去重。
    角色（反向代理 / 内网 DNS）由检测器自动推算后回写，这里只读展示（带证据计数）。
    """
    return relay_nodes.describe()


@router.put("/relay-nodes")
def set_relay_nodes(
    body: RelayNodesIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """保存中继清单（IP/CIDR、逗号/换行分隔、`#` 注释）。校验不过 400 + `field_errors`。

    这是**安全边界配置**：改它等于改「谁带来的 XFF 可信」与「哪些跳按中继去重」，
    所以每次变更都记一条日志。
    """
    errors = relay_nodes.validate(body.nodes)
    if errors:
        return JSONResponse(
            status_code=400,
            content={
                "conflict": "field_error",
                "detail": errors[0]["msg"],
                "field_errors": errors,
            },
        )
    relay_nodes.save(db, body.nodes)
    snapshot = relay_nodes.describe()
    log.info(
        "中继节点清单已更新：%d 项（configured=%s）", snapshot["count"], snapshot["configured"]
    )
    return snapshot


@router.put("/relay-nodes/sides")
def set_relay_sides(
    body: RelaySidesIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """设置每台中继「保留哪一侧」：`auto`（按实测内容自动判，默认）/ `front` / `back`。

    为什么要能手动覆盖（2026-10 实机实测）：WAF/反代这类中继，客户端侧可能是「TLS 无 SNI」的
    无内容流量，只有源站侧才有 Host/URI/请求体 —— 系统按两侧内容条数自动判（默认保留客户端侧），
    但拓扑特殊时运维需要能直接指定；改完约 30 秒内（读取方的缓存 TTL）生效。
    """
    errors = relay_nodes.validate_sides(body.sides)
    if errors:
        return JSONResponse(
            status_code=400,
            content={
                "conflict": "field_error",
                "detail": errors[0]["msg"],
                "field_errors": errors,
            },
        )
    relay_nodes.save_sides(db, body.sides)
    snapshot = relay_nodes.describe()
    log.info("中继侧向设置已更新：%s", snapshot["sides"])
    return snapshot


class RelayRolesIn(BaseModel):
    #: {中继地址: "auto" | "proxy" | "dns" | "both"}；`auto` = 按流量证据自动判（可清除手工指定）
    roles: dict[str, str] = Field(default_factory=dict)


@router.put("/relay-nodes/roles")
def set_relay_roles(
    body: RelayRolesIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """手工指定每台中继的角色：`auto`（按证据，默认）/ `proxy`（反向代理·WAF）/ `dns`（DNS 转发）/ `both`。

    为什么要能手工指定（2026-10 用户口径）：角色是**按实际流量**推算的 —— 只在
    http/ssl/dns 事件里出现过才能判出角色；只在 conn 层出现、或两侧都无明文内容的中继
    （实测 .214 只有 TLS 握手）永远判不出来。这种情形必须让运维能直接定死。
    优先级：**手工 > 证据 > 未判定（带原因）**；值改成 `auto` 即清除手工指定。
    """
    errors = relay_nodes.validate_roles(body.roles)
    if errors:
        return JSONResponse(
            status_code=400,
            content={
                "conflict": "field_error",
                "detail": errors[0]["msg"],
                "field_errors": errors,
            },
        )
    relay_nodes.save_role_overrides(db, body.roles)
    snapshot = relay_nodes.describe()
    log.info("中继角色手工指定已更新：%s", snapshot["role_overrides"])
    return snapshot
