"""主动探测工具：TCP 端口探测 + 服务 banner 抓取。

安全边界：默认关闭（settings.active_scan_enabled=False）；只扫启用分析网段内的
内网目标 IP；限速超时；结果只作分析参考、不产生阻断动作。
"""

from __future__ import annotations

import socket
from typing import Any

from app.config import settings
from app.tools.context import ToolContext, is_public_ip


def _probe_ports() -> list[int]:
    ports: list[int] = []
    for p in (settings.active_scan_ports or "").split(","):
        p = p.strip()
        try:
            port = int(p)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            ports.append(port)
            if len(ports) >= settings.active_scan_max_ports:
                break
    return ports


def _internal_targets(ctx: ToolContext, limit: int) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for ip in ctx.dst_ips:
        if ip and ip not in seen and not is_public_ip(ip):
            seen.add(ip)
            out.append(ip)
            if len(out) >= limit:
                break
    return out


def _tcp_probe(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except OSError:
        return False


def port_scan(ctx: ToolContext) -> dict[str, Any]:
    """对事件组内网目标做 TCP 端口探测。"""
    targets = _internal_targets(ctx, limit=20)
    if not targets:
        return {"note": "无内网目标可扫"}
    ports = _probe_ports()
    results: dict[str, Any] = {}
    for host in targets:
        open_ports = [p for p in ports if _tcp_probe(host, p, settings.active_scan_timeout)]
        results[host] = {"open": open_ports}
    return {"results": results, "ports_scanned": len(ports)}


def _grab(host: str, port: int, timeout: float) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendall(b"\r\n")
            data = s.recv(256)
            return data.decode("utf-8", errors="replace").strip()[:200]
    except OSError:
        return ""


def banner_grab(ctx: ToolContext) -> dict[str, Any]:
    """对常见服务端口抓 banner（仅内网目标）。"""
    targets = _internal_targets(ctx, limit=10)
    if not targets:
        return {"note": "无内网目标可扫"}
    ports = [22, 21, 25, 80, 443, 3306, 6379, 8080]
    results: dict[str, Any] = {}
    for host in targets:
        for port in ports:
            banner = _grab(host, port, settings.active_scan_timeout)
            if banner:
                results.setdefault(host, {})[str(port)] = banner
    return {"results": results}
