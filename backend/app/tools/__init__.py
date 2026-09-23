"""脚本工具库：安全分析的确定性辅助工具（本地计算 / 免费情报 / 主动探测）。

工具统一签名 run(ctx: ToolContext) -> dict，由 execute() 按工具名调度；
主动探测受 settings.active_scan_enabled 开关约束。
"""

from __future__ import annotations

from typing import Any

from app.config import settings
from app.runtime_config import get as runtime_get
from app.tools.active import banner_grab, port_scan
from app.tools.context import ToolContext
from app.tools.intel import dns_resolve, geoip_lookup, rdap_lookup, threat_lookup
from app.tools.local import hash_calc, ioc_extract, url_decode
from app.workers.log import get_logger

log = get_logger(__name__)

TOOLS: dict[str, dict[str, Any]] = {
    "ioc_extract": {
        "category": "local",
        "run": ioc_extract,
        "description": "提取 IOC（IP/域名/URL/邮箱/hash）",
    },
    "url_decode": {
        "category": "local",
        "run": url_decode,
        "description": "URL/base64 解码去混淆",
    },
    "hash_calc": {
        "category": "local",
        "run": hash_calc,
        "description": "事件文本 SHA256 指纹",
    },
    "geoip_lookup": {
        "category": "intel",
        "run": geoip_lookup,
        "description": "IP 地理（ipwho.is/ip-api 免费）",
    },
    "rdap_lookup": {
        "category": "intel",
        "run": rdap_lookup,
        "description": "whois 注册信息（rdap.org 免费）",
    },
    "threat_lookup": {
        "category": "intel",
        "run": threat_lookup,
        "description": "恶意 IOC 信誉（abuse.ch 免费）",
    },
    "dns_resolve": {
        "category": "intel",
        "run": dns_resolve,
        "description": "域名解析",
    },
    "port_scan": {
        "category": "active",
        "run": port_scan,
        "description": "TCP 端口探测（默认关）",
    },
    "banner_grab": {
        "category": "active",
        "run": banner_grab,
        "description": "服务 banner 抓取（默认关）",
    },
}


def execute(tool_name: str, ctx: ToolContext) -> dict[str, Any]:
    """执行单个工具；未知工具 / 异常 / 主动探测未开均降级为结构化结果。"""
    spec = TOOLS.get(tool_name)
    if spec is None:
        return {"error": f"未知工具 {tool_name}"}
    if spec["category"] == "active" and not runtime_get("active_scan_enabled", settings.active_scan_enabled):
        return {"skipped": "主动探测未开启（active_scan_enabled=false）"}
    try:
        return spec["run"](ctx)
    except Exception as exc:  # noqa: BLE001
        log.warning("工具 %s 执行失败: %s", tool_name, exc)
        return {"error": str(exc)}


def tool_names() -> list[str]:
    return sorted(TOOLS)
