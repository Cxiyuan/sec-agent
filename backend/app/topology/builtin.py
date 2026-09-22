"""内置拓扑节点类型（icon 为 lucide 图标名）。"""

from __future__ import annotations

BUILTIN_NODE_TYPES: list[dict] = [
    {"key": "firewall", "name": "防火墙", "icon": "Shield", "color": "#ef4444", "sort": 10},
    {"key": "switch", "name": "交换机", "icon": "Network", "color": "#3b82f6", "sort": 20},
    {"key": "router", "name": "路由器", "icon": "Router", "color": "#0ea5e9", "sort": 30},
    {"key": "log_audit", "name": "日志审计", "icon": "ScrollText", "color": "#a855f7", "sort": 40},
    {"key": "dns", "name": "DNS服务器", "icon": "Globe", "color": "#14b8a6", "sort": 50},
    {"key": "app_server", "name": "应用服务器", "icon": "Server", "color": "#22c55e", "sort": 60},
    {"key": "db_server", "name": "数据库服务器", "icon": "Database", "color": "#f59e0b", "sort": 70},
    {"key": "waf", "name": "Web应用防火墙", "icon": "ShieldCheck", "color": "#e11d48", "sort": 80},
    {"key": "vpn", "name": "VPN", "icon": "KeyRound", "color": "#8b5cf6", "sort": 90},
    {"key": "vuln_scan", "name": "漏洞扫描", "icon": "ScanLine", "color": "#f97316", "sort": 100},
    {"key": "internet", "name": "互联网", "icon": "Cloud", "color": "#64748b", "sort": 110},
    {"key": "endpoint", "name": "终端", "icon": "Monitor", "color": "#94a3b8", "sort": 120},
]

# 自定义类型可选图标（lucide 名称）
ICON_CANDIDATES: list[str] = [
    "Shield", "ShieldCheck", "ShieldAlert", "Network", "Router", "Globe", "Cloud",
    "Server", "Database", "HardDrive", "Cpu", "Boxes", "KeyRound", "Lock", "ScanLine",
    "Search", "Activity", "Bell", "Bug", "ScrollText", "FileSearch", "Monitor", "Wifi",
    "Cable", "Waypoints", "Share2", "Split", "Box", "Container", "Layers",
    "Smartphone", "Radio", "Terminal", "Camera", "Building2",
]
