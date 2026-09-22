"""内置安全事件规则（可作为初始化种子写入数据库）。"""

from __future__ import annotations

BUILTIN_RULES: list[dict] = [
    {
        "name": "内置-端口扫描",
        "description": "检测到端口扫描行为",
        "source": "builtin",
        "priority": 10,
        "severity": "medium",
        "conditions": {
            "logic": "and",
            "rules": [{"field": "event_type", "op": "eq", "value": "port_scan"}],
        },
    },
    {
        "name": "内置-扫描尝试连接",
        "description": "Zeek 记录的扫描尝试（S0/S1/S2/S3 状态）",
        "source": "builtin",
        "priority": 20,
        "severity": "low",
        "conditions": {
            "logic": "and",
            "rules": [{"field": "event_type", "op": "eq", "value": "scan_attempt"}],
        },
    },
    {
        "name": "内置-暴力破解",
        "description": "检测到暴力破解行为",
        "source": "builtin",
        "priority": 10,
        "severity": "high",
        "conditions": {
            "logic": "and",
            "rules": [{"field": "event_type", "op": "eq", "value": "brute_force"}],
        },
    },
    {
        "name": "内置-Wazuh高危告警",
        "description": "Wazuh 规则等级 >= 12 的高危主机事件",
        "source": "builtin",
        "priority": 10,
        "severity": "high",
        "conditions": {
            "logic": "and",
            "rules": [{"field": "event_type", "op": "eq", "value": "wazuh_high_alert"}],
        },
    },
    {
        "name": "内置-异常外联",
        "description": "内网主机连接非常用外部端口（疑似 C2 外联）",
        "source": "builtin",
        "priority": 30,
        "severity": "high",
        "conditions": {
            "logic": "and",
            "rules": [
                {
                    "field": "dst_port",
                    "op": "in",
                    "value": [4444, 5555, 6666, 7777, 8080, 8443, 31337],
                },
                {"field": "event_type", "op": "ne", "value": "scan_attempt"},
            ],
        },
    },
    {
        "name": "内置-常见敏感端口访问",
        "description": "访问常见敏感端口（22/3389/3306/6379 等）",
        "source": "builtin",
        "priority": 40,
        "severity": "low",
        "conditions": {
            "logic": "and",
            "rules": [
                {"field": "dst_port", "op": "in", "value": [22, 23, 3389, 3306, 5432, 6379, 27017]},
            ],
        },
    },
]
