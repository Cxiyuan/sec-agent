"""录入校验：资产字段、IP/CIDR、文档魔术字节。表单与 CSV 共用。"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.rag.lan import is_lan_ip, lan_networks

IMPORTANCE_VALUES = ("critical", "high", "medium", "low")

# 字段长度上限（与 DB 列宽对齐）
FIELD_LIMITS: dict[str, int] = {
    "ip": 64,
    "hostname": 128,
    "asset_name": 128,
    "business_system": 128,
    "owner": 64,
    "importance": 16,
    "asset_type": 64,
    "network_zone": 64,
    "os": 64,
    "location": 128,
    "services": 2000,
    "description": 2000,
}
LIST_MAX_ITEMS = 50
LIST_ITEM_MAX = 64

# 文档魔术字节（扩展名须与真实内容一致）
MAGIC: dict[str, bytes] = {
    ".pdf": b"%PDF-",
    ".docx": b"PK\x03\x04",
    ".xlsx": b"PK\x03\x04",
}
TEXT_EXT = {".txt", ".md", ".markdown", ".log", ".csv"}

MAX_ERRORS = 1000


@dataclass
class FieldError:
    field: str
    msg: str

    def as_dict(self) -> dict[str, str]:
        return {"field": self.field, "msg": self.msg}


def is_cidr(value: str) -> bool:
    return "/" in value.strip()


def is_valid_ip_or_cidr(value: str) -> bool:
    """合法单机 IP，或标准 CIDR 网段（主机位必须为 0，排除 /32、/128）。"""
    v = value.strip()
    if not v:
        return False
    try:
        if "/" in v:
            net = ipaddress.ip_network(v, strict=True)
            return net.prefixlen < net.max_prefixlen
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def split_list(value: Any) -> list[str]:
    """CSV 单元格或列表 -> 去空字符串列表（支持逗号与竖线分隔）。"""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = [str(x) for x in value]
    else:
        items = str(value).replace("|", ",").split(",")
    return [x.strip() for x in items if x.strip()]


def _cidr_touches_lan(cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=True)
    except ValueError:
        return True  # 非法网段已在别处报错
    return any(net.version == ln.version and net.overlaps(ln) for ln in lan_networks())


def in_lan_scope(value: str) -> bool:
    """IP 或 CIDR 是否落在局域网范围内。"""
    v = value.strip()
    if is_cidr(v):
        return _cidr_touches_lan(v)
    return is_lan_ip(v)


def validate_asset(payload: dict[str, Any], *, is_external: bool) -> list[FieldError]:
    """资产字段校验（表单与 CSV 共用同一套规则）。"""
    errors: list[FieldError] = []

    ip = str(payload.get("ip") or "").strip()
    if not ip:
        errors.append(FieldError("ip", "IP 不能为空"))
    elif len(ip) > FIELD_LIMITS["ip"]:
        errors.append(FieldError("ip", f"IP 超长（>{FIELD_LIMITS['ip']} 字符）"))
    elif not is_valid_ip_or_cidr(ip):
        errors.append(FieldError("ip", "不是合法的 IP 或 CIDR 网段（如 192.168.1.0/24）"))
    elif not in_lan_scope(ip) and not is_external:
        errors.append(
            FieldError("ip", "该 IP/网段不在局域网范围内，如需录入请开启『外部资产记录』")
        )

    if not any(
        str(payload.get(k) or "").strip() for k in ("asset_name", "business_system", "description")
    ):
        errors.append(FieldError("asset_name", "至少填写『资产名 / 业务系统 / 业务描述』之一"))

    extras = split_list(payload.get("extra_ips"))
    if len(extras) > LIST_MAX_ITEMS:
        errors.append(FieldError("extra_ips", f"额外 IP 最多 {LIST_MAX_ITEMS} 个"))
    seen: set[str] = {ip} if ip else set()
    for extra in extras:
        if not is_valid_ip_or_cidr(extra):
            errors.append(FieldError("extra_ips", f"非法 IP/CIDR：{extra}"))
        elif extra in seen:
            errors.append(FieldError("extra_ips", f"重复：{extra}"))
        elif not in_lan_scope(extra) and not is_external:
            errors.append(FieldError("extra_ips", f"不在局域网范围内：{extra}"))
        seen.add(extra)

    importance = str(payload.get("importance") or "medium").strip()
    if importance not in IMPORTANCE_VALUES:
        errors.append(
            FieldError("importance", f"必须是 {'/'.join(IMPORTANCE_VALUES)} 之一")
        )

    for field, limit in FIELD_LIMITS.items():
        if field == "ip":
            continue
        val = payload.get(field)
        if val is not None and len(str(val)) > limit:
            errors.append(FieldError(field, f"超长（>{limit} 字符）"))

    tags = split_list(payload.get("tags"))
    if len(tags) > LIST_MAX_ITEMS:
        errors.append(FieldError("tags", f"标签最多 {LIST_MAX_ITEMS} 个"))
    for tag in tags:
        if len(tag) > LIST_ITEM_MAX:
            errors.append(FieldError("tags", f"标签过长（>{LIST_ITEM_MAX} 字符）"))

    return errors


def check_document_magic(filename: str, data: bytes) -> str | None:
    """校验扩展名与真实内容是否一致；不一致返回说明，一致返回 None。"""
    ext = Path(filename).suffix.lower()
    magic = MAGIC.get(ext)
    if magic is not None and not data.startswith(magic):
        return f"文件内容与扩展名 {ext} 不符（可能已损坏或被改名）"
    if ext in TEXT_EXT and b"\x00" in data[:4096]:
        return "疑似二进制文件，无法按文本处理"
    return None
