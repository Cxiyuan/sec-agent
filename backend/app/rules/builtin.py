"""内置安全事件规则（启动时幂等 upsert 入库）。

规则结构（存 Postgres 的 conditions JSON 字段）
--------------------------------------------------
条件树（逐条匹配）：
    {"logic": "and"|"or", "rules": [{"field": ..., "op": ..., "value": ...}, ...]}
    操作符：eq / ne / in / contains / regex / gt / gte / lt / lte / exists

频率规则（窗口内聚合）：
    {"mode": "count", "key": ["src_ip", ...], "min_count": N,
     "logic": "and", "rules": [...]}

可用字段见 app/schemas.py 的 UnifiedLog（含 log_type / query / user_agent /
status_code / bytes_out / rule_id / rule_groups / mitre）。

优先级（priority 越小越先，命中即停）：5 最严重 → 40 可观测
"""

from __future__ import annotations

BUILTIN_RULES: list[dict] = [
    # ================= A. 勒索 / 僵尸网络 / 挖矿（最严重） =================
    {
        "name": "内置-勒索/僵尸网络域名",
        "description": "DNS/URL 命中勒索或僵尸网络相关关键字",
        "source": "builtin",
        "priority": 5,
        "severity": "critical",
        "conditions": {
            "logic": "and",
            "rules": [
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(ransom|lockbit|blacksuit|conti|emotet|trickbot|cobaltstrike|meterpreter|beacon)",
                }
            ],
        },
    },
    {
        "name": "内置-挖矿域名/矿池",
        "description": "命中矿池或挖矿相关域名/协议",
        "source": "builtin",
        "priority": 5,
        "severity": "high",
        "conditions": {
            "logic": "and",
            "rules": [
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(xmr|monero|minergate|nanopool|minexmr|coin-hive|cryptonight|stratum\\+tcp|2miners|f2pool)",
                }
            ],
        },
    },
    {
        "name": "内置-Wazuh恶意软件告警",
        "description": "Wazuh 恶意软件/勒索/病毒/木马类规则组",
        "source": "builtin",
        "priority": 5,
        "severity": "critical",
        "conditions": {
            "logic": "and",
            "rules": [{"field": "event_type", "op": "eq", "value": "wazuh_malware"}],
        },
    },
    # ================= B. Web 攻击 =================
    {
        "name": "内置-SQL注入特征",
        "description": "URL/请求命中 SQL 注入特征",
        "source": "builtin",
        "priority": 10,
        "severity": "high",
        "conditions": {
            "logic": "and",
            "rules": [
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(union\\s+select|or\\s+1\\s*=\\s*1|sleep\\(|benchmark\\(|waitfor\\s+delay|information_schema|into\\s+outfile)",
                }
            ],
        },
    },
    {
        "name": "内置-命令注入特征",
        "description": "URL/请求命中命令注入特征",
        "source": "builtin",
        "priority": 10,
        "severity": "high",
        "conditions": {
            "logic": "and",
            "rules": [
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(;\\s*(cat|ls|id|whoami|uname|curl|wget|nc)\\s)|/bin/(sh|bash)|cmd\\.exe|powershell\\s+-|\\|\\s*nc\\s",
                }
            ],
        },
    },
    {
        "name": "内置-路径穿越/敏感文件探测",
        "description": "路径穿越或探测敏感文件（.git/.env/备份/管理后台）",
        "source": "builtin",
        "priority": 10,
        "severity": "high",
        "conditions": {
            "logic": "and",
            "rules": [
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(\\.\\./|%2e%2e|/etc/(passwd|shadow)|/proc/self|win\\.ini|\\.git/|\\.env|wp-config|\\.ssh/|(backup|dump|db)\\.(sql|zip|tar|gz)|phpmyadmin|manager/html)",
                }
            ],
        },
    },
    {
        "name": "内置-Web攻击扫描器UA",
        "description": "User-Agent 命中已知攻击/扫描工具",
        "source": "builtin",
        "priority": 10,
        "severity": "high",
        "conditions": {
            "logic": "and",
            "rules": [
                {
                    "field": "user_agent",
                    "op": "regex",
                    "value": "(?i)(sqlmap|nikto|nmap|masscan|acunetix|nessus|w3af|dirb|gobuster|wfuzz|hydra|zgrab|nuclei)",
                }
            ],
        },
    },
    {
        "name": "内置-Web攻击（Wazuh规则组）",
        "description": "Wazuh web/attack 规则组命中",
        "source": "builtin",
        "priority": 10,
        "severity": "high",
        "conditions": {
            "logic": "and",
            "rules": [{"field": "event_type", "op": "eq", "value": "wazuh_web_attack"}],
        },
    },
    {
        "name": "内置-XSS/脚本注入特征",
        "description": "URL/请求命中 XSS 特征",
        "source": "builtin",
        "priority": 15,
        "severity": "medium",
        "conditions": {
            "logic": "and",
            "rules": [
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(<script|javascript:|onerror\\s*=|onload\\s*=|alert\\(|document\\.cookie)",
                }
            ],
        },
    },
    # ================= C. 认证 / 暴力破解 =================
    {
        "name": "内置-暴力破解",
        "description": "检测到暴力破解行为（notice/规则描述）",
        "source": "builtin",
        "priority": 10,
        "severity": "high",
        "conditions": {
            "logic": "and",
            "rules": [{"field": "event_type", "op": "eq", "value": "brute_force"}],
        },
    },
    {
        "name": "内置-高频认证失败",
        "description": "同一源 IP 在窗口内出现大量认证失败（≥10 次）",
        "source": "builtin",
        "priority": 12,
        "severity": "critical",
        "conditions": {
            "mode": "count",
            "key": ["src_ip"],
            "min_count": 10,
            "logic": "and",
            "rules": [{"field": "event_type", "op": "eq", "value": "brute_force"}],
        },
    },
    {
        "name": "内置-Wazuh登录失败",
        "description": "Wazuh 认证失败规则组",
        "source": "builtin",
        "priority": 20,
        "severity": "medium",
        "conditions": {
            "logic": "and",
            "rules": [
                {"field": "rule_groups", "op": "regex", "value": "(?i)authentication_fail"},
            ],
        },
    },
    # ================= D. 横向移动 =================
    {
        "name": "内置-横向移动高频连接",
        "description": "同一源 IP 对同一目标的高频管理端口连接（SMB/RDP/WinRM）",
        "source": "builtin",
        "priority": 22,
        "severity": "high",
        "conditions": {
            "mode": "count",
            "key": ["src_ip", "dst_ip"],
            "min_count": 10,
            "logic": "and",
            "rules": [
                {"field": "dst_port", "op": "in", "value": [445, 139, 135, 3389, 5985, 5986, 512, 513, 514]},
            ],
        },
    },
    {
        "name": "内置-横向移动管理端口",
        "description": "内网管理端口（SMB/WinRM/RDP/WMI）被访问",
        "source": "builtin",
        "priority": 30,
        "severity": "medium",
        "conditions": {
            "logic": "and",
            "rules": [
                {"field": "dst_port", "op": "in", "value": [445, 139, 135, 3389, 5985, 5986, 2049]},
                {"field": "event_type", "op": "ne", "value": "scan_attempt"},
            ],
        },
    },
    # ================= E. 外联 / C2 / 隧道 =================
    {
        "name": "内置-异常外联端口",
        "description": "连接非常用高风险端口（疑似 C2/后门）",
        "source": "builtin",
        "priority": 20,
        "severity": "high",
        "conditions": {
            "logic": "and",
            "rules": [
                {
                    "field": "dst_port",
                    "op": "in",
                    "value": [4444, 4445, 5555, 6666, 6667, 7777, 9001, 9050, 1337, 31337, 12345, 54321],
                },
                {"field": "event_type", "op": "ne", "value": "scan_attempt"},
            ],
        },
    },
    {
        "name": "内置-DNS隧道可疑长查询",
        "description": "DNS 查询名异常长（疑似数据外泄/隧道）",
        "source": "builtin",
        "priority": 20,
        "severity": "high",
        "conditions": {
            "logic": "and",
            "rules": [
                {"field": "log_type", "op": "eq", "value": "dns"},
                {"field": "query", "op": "regex", "value": "^[A-Za-z0-9_.-]{60,}$"},
            ],
        },
    },
    {
        "name": "内置-可疑域名（动态DNS/短域名）",
        "description": "命中动态DNS、短域名或匿名服务域名",
        "source": "builtin",
        "priority": 25,
        "severity": "medium",
        "conditions": {
            "logic": "and",
            "rules": [
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(\\.onion|\\.top$|\\.xyz$|\\.tk$|\\.pw$|dyn(dns)?\\.|no-ip\\.|ngrok\\.|pastebin\\.|transfer\\.sh)",
                }
            ],
        },
    },
    # ================= F. 数据外传 =================
    {
        "name": "内置-大流量外传",
        "description": "单连接外发流量 > 10MB",
        "source": "builtin",
        "priority": 25,
        "severity": "medium",
        "conditions": {
            "logic": "and",
            "rules": [{"field": "bytes_out", "op": "gt", "value": 10485760}],
        },
    },
    {
        "name": "内置-超大流量外传",
        "description": "单连接外发流量 > 100MB（疑似数据外泄）",
        "source": "builtin",
        "priority": 15,
        "severity": "high",
        "conditions": {
            "logic": "and",
            "rules": [{"field": "bytes_out", "op": "gt", "value": 104857600}],
        },
    },
    # ================= G. 扫描探测 =================
    {
        "name": "内置-端口扫描",
        "description": "检测到端口扫描行为",
        "source": "builtin",
        "priority": 20,
        "severity": "medium",
        "conditions": {
            "logic": "and",
            "rules": [{"field": "event_type", "op": "eq", "value": "port_scan"}],
        },
    },
    {
        "name": "内置-高频扫描连接",
        "description": "同一源 IP 在窗口内发起大量失败连接（≥30 次）",
        "source": "builtin",
        "priority": 24,
        "severity": "high",
        "conditions": {
            "mode": "count",
            "key": ["src_ip"],
            "min_count": 30,
            "logic": "and",
            "rules": [{"field": "event_type", "op": "in", "value": ["scan_attempt", "port_scan"]}],
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
        "name": "内置-Web目录爆破",
        "description": "同一源 IP 在窗口内产生大量 404/403（≥30 次）",
        "source": "builtin",
        "priority": 26,
        "severity": "medium",
        "conditions": {
            "mode": "count",
            "key": ["src_ip"],
            "min_count": 30,
            "logic": "and",
            "rules": [
                {"field": "log_type", "op": "eq", "value": "http"},
                {"field": "status_code", "op": "in", "value": [403, 404]},
            ],
        },
    },
    # ================= H. Wazuh 其他语义 =================
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
        "name": "内置-Wazuh文件完整性变更",
        "description": "Wazuh syscheck/系统变更类规则组",
        "source": "builtin",
        "priority": 30,
        "severity": "medium",
        "conditions": {
            "logic": "and",
            "rules": [{"field": "event_type", "op": "eq", "value": "wazuh_system_change"}],
        },
    },
    {
        "name": "内置-Wazuh漏洞告警",
        "description": "Wazuh 漏洞/CVE 类规则组",
        "source": "builtin",
        "priority": 30,
        "severity": "medium",
        "conditions": {
            "logic": "and",
            "rules": [{"field": "event_type", "op": "eq", "value": "wazuh_vulnerability"}],
        },
    },
    {
        "name": "内置-Wazuh网络告警",
        "description": "Wazuh 防火墙/IDS 类规则组",
        "source": "builtin",
        "priority": 28,
        "severity": "medium",
        "conditions": {
            "logic": "and",
            "rules": [{"field": "event_type", "op": "eq", "value": "wazuh_network_alert"}],
        },
    },
    {
        "name": "内置-Wazuh MITRE映射命中",
        "description": "Wazuh 规则带 MITRE ATT&CK 映射",
        "source": "builtin",
        "priority": 32,
        "severity": "medium",
        "conditions": {
            "logic": "and",
            "rules": [{"field": "mitre", "op": "exists"}],
        },
    },
    {
        "name": "内置-Wazuh策略违规",
        "description": "Wazuh audit/policy 类规则组",
        "source": "builtin",
        "priority": 34,
        "severity": "low",
        "conditions": {
            "logic": "and",
            "rules": [{"field": "event_type", "op": "eq", "value": "wazuh_policy_violation"}],
        },
    },
    # ================= I. 协议/内容异常（可观测） =================
    {
        "name": "内置-协议异常",
        "description": "Zeek weird/协议异常",
        "source": "builtin",
        "priority": 30,
        "severity": "medium",
        "conditions": {
            "logic": "and",
            "rules": [{"field": "event_type", "op": "eq", "value": "protocol_anomaly"}],
        },
    },
    {
        "name": "内置-TLS异常",
        "description": "TLS/证书异常告警",
        "source": "builtin",
        "priority": 30,
        "severity": "medium",
        "conditions": {
            "logic": "and",
            "rules": [{"field": "event_type", "op": "eq", "value": "tls_anomaly"}],
        },
    },
    {
        "name": "内置-SMTP滥用",
        "description": "SMTP 垃圾邮件/滥用行为",
        "source": "builtin",
        "priority": 30,
        "severity": "medium",
        "conditions": {
            "logic": "or",
            "rules": [
                {"field": "event_type", "op": "eq", "value": "smtp_abuse"},
                {"field": "log_type", "op": "eq", "value": "smtp"},
            ],
        },
    },
    {
        "name": "内置-常见敏感端口访问",
        "description": "访问常见敏感端口（22/23/3389/3306/6379 等）",
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
    {
        "name": "内置-文件传输可观测",
        "description": "Zeek files 日志（文件传输留痕）",
        "source": "builtin",
        "priority": 45,
        "severity": "low",
        "conditions": {
            "logic": "and",
            "rules": [{"field": "log_type", "op": "eq", "value": "files"}],
        },
    },
]
