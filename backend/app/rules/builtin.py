"""内置安全事件规则（启动时幂等 upsert 入库）。

规则结构（存 Postgres 的 conditions JSON 字段）
--------------------------------------------------
条件树（逐条匹配）：
    {"logic": "and"|"or", "rules": [{"field": ..., "op": ..., "value": ...}, ...]}
    操作符：eq / ne / in / contains / regex / gt / gte / lt / lte / exists
    支持 not 取反：{"not": {"field": ..., "op": ..., "value": ...}}
    规则级白名单：{"whitelist": [{...}]}（命中即该规则放过）

频率规则（窗口内聚合）：
    {"mode": "count", "key": ["src_ip"], "min_count": N,
     "distinct": "account", "min_distinct": 5, "logic": "and", "rules": [...]}

可用字段见 app/schemas.py 的 UnifiedLog。

优先级（priority 越小越先，命中即停）：5 最严重 → 60 可观测
"""

from __future__ import annotations

# 常用白名单（避免监控/健康检查误报）
_WHITELIST_HEALTH = [
    {"field": "uri_path", "op": "in", "value": ["/health", "/healthz", "/ping", "/metrics"]},
    {
        "field": "user_agent",
        "op": "regex",
        "value": "(?i)(kube-probe|prometheus|zabbix|nagios|uptime|healthcheck|ELB-HealthChecker)",
    },
]

BUILTIN_RULES: list[dict] = [
    # ================= A. 勒索 / 僵尸网络 / 挖矿 =================
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
    # ================= B. 注入 / 漏洞利用 =================
    {
        "name": "内置-SQL注入-基础特征",
        "description": "URL/参数命中 SQL 注入基础特征（联合查询/布尔/时间盲注）",
        "source": "builtin",
        "priority": 10,
        "severity": "high",
        "conditions": {
            "logic": "or",
            "rules": [
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(union\\s+(all\\s+)?select|or\\s+1\\s*=\\s*1|and\\s+1\\s*=\\s*1|sleep\\s*\\(|benchmark\\s*\\(|waitfor\\s+delay)",
                },
                {
                    "field": "body",
                    "op": "regex",
                    "value": "(?i)(union\\s+(all\\s+)?select|or\\s+1\\s*=\\s*1|sleep\\s*\\(|benchmark\\s*\\(|waitfor\\s+delay)",
                },
            ],
        },
    },
    {
        "name": "内置-SQL注入-元数据与文件读写",
        "description": "命中 information_schema / load_file / into outfile 等",
        "source": "builtin",
        "priority": 10,
        "severity": "high",
        "conditions": {
            "logic": "or",
            "rules": [
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(information_schema|into\\s+(out|dump)file|load_file\\s*\\(|xp_cmdshell|pg_sleep)",
                },
                {
                    "field": "body",
                    "op": "regex",
                    "value": "(?i)(information_schema|into\\s+(out|dump)file|load_file\\s*\\(|xp_cmdshell)",
                },
            ],
        },
    },
    {
        "name": "内置-NoSQL注入",
        "description": "命中 MongoDB 等 NoSQL 注入特征",
        "source": "builtin",
        "priority": 12,
        "severity": "high",
        "conditions": {
            "logic": "or",
            "rules": [
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(\\$ne|\\$gt|\\$regex|\\$where|\\$exists)",
                },
                {
                    "field": "body",
                    "op": "regex",
                    "value": "(?i)(\\$ne|\\$gt|\\$regex|\\$where|\\$exists)",
                },
            ],
        },
    },
    {
        "name": "内置-命令注入特征",
        "description": "命中命令注入特征（含编码绕过）",
        "source": "builtin",
        "priority": 10,
        "severity": "high",
        "conditions": {
            "logic": "or",
            "rules": [
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(;\\s*(cat|ls|id|whoami|uname|curl|wget|nc|bash|sh)\\s|/bin/(sh|bash)|cmd\\.exe|powershell\\s+-|\\|\\s*nc\\s|`[^`]+`)",
                },
                {
                    "field": "body",
                    "op": "regex",
                    "value": "(?i)(;\\s*(cat|ls|id|whoami|curl|wget|bash|sh)\\s)|/bin/(sh|bash)|cmd\\.exe|powershell\\s+-|\\$\\(",
                },
            ],
        },
    },
    {
        "name": "内置-路径穿越-编码变体",
        "description": "路径穿越（含 URL/双重编码与反斜杠变体）",
        "source": "builtin",
        "priority": 10,
        "severity": "high",
        "conditions": {
            "logic": "or",
            "rules": [
                {"field": "query", "op": "regex", "value": "(?i)(\\.\\./|\\.\\.\\\\)"},
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(%2e%2e%2f|%2e%2e/|%252e%252e|%c0%ae|\\.\\.%5c|%2e%2e%5c)",
                },
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(/etc/(passwd|shadow)|/proc/self|win\\.ini|boot\\.ini)",
                },
                {
                    "field": "body",
                    "op": "regex",
                    "value": "(?i)(\\.\\./|\\.\\.\\\\|/etc/(passwd|shadow))",
                },
            ],
        },
    },
    {
        "name": "内置-XSS/脚本注入特征",
        "description": "命中 XSS/HTML 注入特征",
        "source": "builtin",
        "priority": 15,
        "severity": "medium",
        "conditions": {
            "logic": "or",
            "rules": [
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(<script|</script|javascript:|onerror\\s*=|onload\\s*=|alert\\s*\\(|document\\.cookie|<img[^>]+src\\s*=)",
                },
                {
                    "field": "body",
                    "op": "regex",
                    "value": "(?i)(<script|javascript:|onerror\\s*=|document\\.cookie)",
                },
            ],
        },
    },
    {
        "name": "内置-模板注入SSTI",
        "description": "命中服务端模板注入（SSTI）表达式",
        "source": "builtin",
        "priority": 10,
        "severity": "high",
        "conditions": {
            "logic": "or",
            "rules": [
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(\\{\\{[^}]*\\}\\}|\\$\\{[^}]+\\}|#\\{[^}]+\\}|<%=[^%]+%>)",
                },
                {
                    "field": "body",
                    "op": "regex",
                    "value": "(\\{\\{[^}]*\\}\\}|\\$\\{[^}]+\\}|<%=[^%]+%>)",
                },
            ],
        },
    },
    {
        "name": "内置-表达式注入与JNDI(Log4Shell)",
        "description": "命中表达式注入 / Log4Shell JNDI 特征",
        "source": "builtin",
        "priority": 5,
        "severity": "critical",
        "conditions": {
            "logic": "or",
            "rules": [
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)\\$\\{(jndi|lower|upper|env|sys|java):",
                },
                {
                    "field": "body",
                    "op": "regex",
                    "value": "(?i)\\$\\{(jndi|lower|upper|env|sys|java):",
                },
                {"field": "user_agent", "op": "regex", "value": "(?i)\\$\\{jndi:"},
                {"field": "referer", "op": "regex", "value": "(?i)\\$\\{jndi:"},
                {"field": "query", "op": "regex", "value": "(?i)(ognl|spel|%24%7bjndi)"},
            ],
        },
    },
    {
        "name": "内置-XXE外部实体注入",
        "description": "命中 XXE 特征（DOCTYPE/ENTITY/SYSTEM）",
        "source": "builtin",
        "priority": 8,
        "severity": "high",
        "conditions": {
            "logic": "or",
            "rules": [
                {
                    "field": "body",
                    "op": "regex",
                    "value": "(?i)(<!DOCTYPE[^>]*\\[|<!ENTITY|SYSTEM\\s+[\"']file:|SYSTEM\\s+[\"']http)",
                },
                {"field": "query", "op": "regex", "value": "(?i)(<!DOCTYPE|<!ENTITY)"},
            ],
        },
    },
    {
        "name": "内置-反序列化特征",
        "description": "命中 Java/Python/PHP/.NET 反序列化 payload 特征",
        "source": "builtin",
        "priority": 8,
        "severity": "critical",
        "conditions": {
            "logic": "or",
            "rules": [
                {"field": "body", "op": "regex", "value": "(rO0AB|aced0005|AAEAAAD)"},
                {
                    "field": "body",
                    "op": "regex",
                    "value": '(?i)(__reduce__|c__builtin__|cos\\nsystem|pickle\\.loads|O:8:"|O:4:")',
                },
                {"field": "cookie", "op": "regex", "value": "(?i)rememberMe="},
                {
                    "field": "body",
                    "op": "regex",
                    "value": "(?i)(java\\.io\\.Serializable|ObjectInputStream|readObject)",
                },
            ],
        },
    },
    {
        "name": "内置-SSRF敏感参数与协议",
        "description": "命中 SSRF 特征（URL 参数 + 内网地址/危险协议）",
        "source": "builtin",
        "priority": 10,
        "severity": "high",
        "conditions": {
            "logic": "or",
            "rules": [
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(url|uri|link|src|dest|redirect|target|callback|image|fetch|proxy|next)=[^&]*(https?://|file://|gopher://|dict://|ftp://)",
                },
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(file://|gopher://|dict://|ldap://|tftp://)",
                },
                {"field": "query", "op": "contains", "value": "169.254.169.254"},
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(url|redirect|next|target)=[^&]*(127\\.0\\.0\\.1|localhost|0\\.0\\.0\\.0)",
                },
            ],
        },
    },
    {
        "name": "内置-文件包含/协议流",
        "description": "命中文件包含或协议流特征",
        "source": "builtin",
        "priority": 12,
        "severity": "high",
        "conditions": {
            "logic": "or",
            "rules": [
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(php://(input|filter|data)|data://|expect://|zip://|phar://)",
                },
                {
                    "field": "body",
                    "op": "regex",
                    "value": "(?i)(php://(input|filter)|data://|expect://)",
                },
            ],
        },
    },
    {
        "name": "内置-CRLF/响应头注入",
        "description": "命中 CRLF 注入或响应拆分特征",
        "source": "builtin",
        "priority": 15,
        "severity": "medium",
        "conditions": {
            "logic": "or",
            "rules": [
                {"field": "query", "op": "regex", "value": "(?i)(%0d%0a|%0a%0d|\\r\\n)"},
                {
                    "field": "body",
                    "op": "regex",
                    "value": "(?i)(%0d%0a|\\r\\n(set-cookie|location):)",
                },
            ],
        },
    },
    {
        "name": "内置-LDAP注入",
        "description": "命中 LDAP 注入特征",
        "source": "builtin",
        "priority": 15,
        "severity": "medium",
        "conditions": {
            "logic": "or",
            "rules": [
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(\\)\\(\\||\\(\\&|\\*\\)\\(|\\|\\(objectclass)",
                },
                {"field": "body", "op": "regex", "value": "(?i)(\\)\\(\\||\\|\\(objectclass)"},
            ],
        },
    },
    {
        "name": "内置-开放重定向探测",
        "description": "命中开放重定向探测（跳转参数指向外部地址）",
        "source": "builtin",
        "priority": 20,
        "severity": "medium",
        "conditions": {
            "logic": "and",
            "rules": [
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(redirect|url|next|return|continue|dest|goto|target)=",
                },
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(https?://|//[a-z0-9-]+\\.[a-z]{2,})",
                },
            ],
        },
    },
    {
        "name": "内置-Host头攻击",
        "description": "Host 头异常（含外部域名/内网地址/多值）",
        "source": "builtin",
        "priority": 15,
        "severity": "medium",
        "conditions": {
            "logic": "or",
            "rules": [
                {
                    "field": "hostname",
                    "op": "regex",
                    "value": "(?i)(localhost|127\\.0\\.0\\.1|169\\.254\\.169\\.254)",
                },
                {"field": "hostname", "op": "contains", "value": ","},
                {
                    "field": "hostname",
                    "op": "regex",
                    "value": "(?i)(burpcollaborator|interact\\.sh|oast\\.|canarytokens)",
                },
            ],
        },
    },
    {
        "name": "内置-危险HTTP方法",
        "description": "使用 PUT/DELETE/TRACE/OPTIONS 等危险或探测方法",
        "source": "builtin",
        "priority": 20,
        "severity": "medium",
        "conditions": {
            "logic": "and",
            "rules": [
                {"field": "log_type", "op": "eq", "value": "http"},
                {
                    "field": "method",
                    "op": "in",
                    "value": ["PUT", "DELETE", "TRACE", "TRACK", "PROPFIND", "OPTIONS"],
                },
            ],
            "whitelist": [
                {
                    "field": "user_agent",
                    "op": "regex",
                    "value": "(?i)(kube-probe|prometheus|healthcheck)",
                }
            ],
        },
    },
    {
        "name": "内置-WebShell上传",
        "description": "上传可执行脚本文件（疑似 WebShell）",
        "source": "builtin",
        "priority": 8,
        "severity": "critical",
        "conditions": {
            "logic": "and",
            "rules": [
                {"field": "method", "op": "in", "value": ["POST", "PUT"]},
                {
                    "field": "uri_path",
                    "op": "regex",
                    "value": "(?i)\\.(php|php[0-9]|phtml|jsp|jspx|asp|aspx|ashx|war|sh|pl|py)(\\?|$)",
                },
                {
                    "field": "status_code",
                    "op": "in",
                    "value": [200, 201, 202, 204, 302],
                },
            ],
        },
    },
    {
        "name": "内置-WebShell访问",
        "description": "访问常见 WebShell 路径",
        "source": "builtin",
        "priority": 10,
        "severity": "high",
        "conditions": {
            "logic": "or",
            "rules": [
                {
                    "field": "uri_path",
                    "op": "regex",
                    "value": "(?i)/(shell|cmd|webshell|c99|b374k|r57|antsword|behinder|godzilla)(\\.php|\\.jsp|\\.aspx|/|$)",
                },
                {"field": "uri_path", "op": "regex", "value": "(?i)/\\.(php|jsp|aspx)$"},
            ],
        },
    },
    {
        "name": "内置-恶意文件传输",
        "description": "Zeek files 中出现可执行/脚本类文件",
        "source": "builtin",
        "priority": 12,
        "severity": "high",
        "conditions": {
            "logic": "and",
            "rules": [
                {"field": "log_type", "op": "eq", "value": "files"},
                {
                    "field": "mime_type",
                    "op": "regex",
                    "value": "(?i)(x-dosexec|x-executable|x-sh|x-msdownload|java-archive|x-elf)",
                },
            ],
        },
    },
    {
        "name": "内置-弱TLS版本",
        "description": "使用 SSLv3/TLS1.0/TLS1.1 等弱协议版本",
        "source": "builtin",
        "priority": 25,
        "severity": "medium",
        "conditions": {
            "logic": "and",
            "rules": [
                {"field": "log_type", "op": "eq", "value": "ssl"},
                {
                    "field": "tls_version",
                    "op": "regex",
                    "value": "(?i)(SSLv3|TLSv1\\.0|TLSv1\\.1|TLSv10|TLSv11)",
                },
            ],
        },
    },
    {
        "name": "内置-自签或异常证书",
        "description": "证书签发者异常（自签/未知 CA）",
        "source": "builtin",
        "priority": 30,
        "severity": "low",
        "conditions": {
            "logic": "and",
            "rules": [
                {"field": "log_type", "op": "eq", "value": "ssl"},
                {
                    "field": "cert_issuer",
                    "op": "regex",
                    "value": "(?i)(self|unknown|localhost|test|openssl)",
                },
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
    # ================= C. 探测 / 漏洞挖掘 =================
    {
        "name": "内置-Web攻击扫描器UA",
        "description": "User-Agent 命中已知攻击/扫描/漏洞挖掘工具",
        "source": "builtin",
        "priority": 10,
        "severity": "high",
        "conditions": {
            "logic": "and",
            "rules": [
                {
                    "field": "user_agent",
                    "op": "regex",
                    "value": "(?i)(sqlmap|nikto|nmap|masscan|acunetix|nessus|w3af|dirb|gobuster|wfuzz|hydra|zgrab|nuclei|xray|goby|ffuf|feroxbuster|httpx|whatweb|jaeles|wpscan|dirsearch)",
                }
            ],
        },
    },
    {
        "name": "内置-JA3指纹命中",
        "description": (
            "TLS JA3 指纹命中已知工具清单（清单由系统配置 ST_JA3_BLOCKLIST 提供；"
            "清单为空时本规则自动禁用，避免对所有 TLS 会话误报）"
        ),
        "source": "builtin",
        "priority": 15,
        "severity": "medium",
        # value 由启动播种按 ST_JA3_BLOCKLIST 填充；空列表时 in 永不命中（安全默认）
        "conditions": {
            "logic": "and",
            "rules": [{"field": "ja3", "op": "in", "value": []}],
        },
    },
    {
        "name": "内置-敏感文件与源码泄露探测",
        "description": "探测 .git/.env/备份/配置等敏感文件",
        "source": "builtin",
        "priority": 12,
        "severity": "high",
        "conditions": {
            "logic": "or",
            "rules": [
                {
                    "field": "uri_path",
                    "op": "regex",
                    "value": "(?i)(/\\.git/|/\\.svn/|/\\.env|/\\.aws/|/\\.ssh/|/wp-config\\.php|/\\.DS_Store|/\\.htaccess)",
                },
                {
                    "field": "uri_path",
                    "op": "regex",
                    "value": "(?i)(backup|dump|www\\.zip|web\\.zip|backup\\.(sql|zip|tar|gz|rar|7z)|database\\.sql|db\\.sql)",
                },
                {
                    "field": "uri_path",
                    "op": "regex",
                    "value": "(?i)(/phpinfo\\.php|/info\\.php|/test\\.php|/server-status|/server-info)",
                },
                {
                    "field": "uri_path",
                    "op": "regex",
                    "value": "(?i)(/actuator|/swagger|/api-docs|/v2/api-docs|/graphql|/debug/|/console)",
                },
            ],
        },
    },
    {
        "name": "内置-未授权访问探测成功",
        "description": "直接访问管理/接口路径并返回 200（疑似未授权访问）",
        "source": "builtin",
        "priority": 15,
        "severity": "high",
        "conditions": {
            "logic": "and",
            "rules": [
                {"field": "status_code", "op": "eq", "value": 200},
                {
                    "field": "uri_path",
                    "op": "regex",
                    "value": "(?i)^/(admin|manager|manage|console|dashboard|api/v[0-9]+/(users|config|admin)|actuator)",
                },
                {"field": "auth_scheme", "op": "ne", "value": "basic"},
            ],
        },
    },
    {
        "name": "内置-云元数据访问",
        "description": "访问云元数据地址（SSRF 利用特征）",
        "source": "builtin",
        "priority": 5,
        "severity": "critical",
        "conditions": {
            "logic": "or",
            "rules": [
                {"field": "query", "op": "contains", "value": "169.254.169.254"},
                {"field": "body", "op": "contains", "value": "169.254.169.254"},
                {"field": "query", "op": "contains", "value": "metadata.google.internal"},
                {"field": "dst_ip", "op": "eq", "value": "169.254.169.254"},
            ],
        },
    },
    {
        "name": "内置-框架漏洞探测特征",
        "description": "命中 Shiro/Fastjson/Struts2/ThinkPHP 等常见框架漏洞探测",
        "source": "builtin",
        "priority": 10,
        "severity": "high",
        "conditions": {
            "logic": "or",
            "rules": [
                {"field": "cookie", "op": "regex", "value": "(?i)(rememberMe=|shiro)"},
                {
                    "field": "uri_path",
                    "op": "regex",
                    "value": "(?i)(\\.action$|\\.do$|/index\\.php\\?s=|/struts/)",
                },
                {"field": "body", "op": "regex", "value": "(?i)(@type.*com\\.sun|fastjson|jndi:)"},
                {
                    "field": "uri_path",
                    "op": "regex",
                    "value": "(?i)(/seeyon/|/weaver/|/e-mobile/|/mobile/plugin/)",
                },
            ],
        },
    },
    {
        "name": "内置-参数fuzzing超长载荷",
        "description": "单请求参数串异常长（自动化 fuzzing 特征）",
        "source": "builtin",
        "priority": 25,
        "severity": "medium",
        "conditions": {
            "logic": "or",
            "rules": [
                {"field": "query_string", "op": "regex", "value": "^.{600,}$"},
                {"field": "uri_path", "op": "regex", "value": "^.{400,}$"},
            ],
        },
    },
    {
        "name": "内置-目录/路径爆破",
        "description": "同源在窗口内产生大量 404/403（≥30 次）",
        "source": "builtin",
        "priority": 26,
        "severity": "high",
        "conditions": {
            "mode": "count",
            "key": ["src_ip"],
            "min_count": 30,
            "logic": "and",
            "rules": [
                {"field": "log_type", "op": "eq", "value": "http"},
                {"field": "status_code", "op": "in", "value": [403, 404]},
            ],
            "whitelist": _WHITELIST_HEALTH,
        },
    },
    {
        "name": "内置-多路径探测(漏洞挖掘)",
        "description": "同源访问大量不同路径（≥40 个 distinct 路径）",
        "source": "builtin",
        "priority": 24,
        "severity": "high",
        "conditions": {
            "mode": "count",
            "key": ["src_ip"],
            "min_count": 40,
            "distinct": "uri_path",
            "min_distinct": 40,
            "logic": "and",
            "rules": [{"field": "log_type", "op": "eq", "value": "http"}],
            "whitelist": _WHITELIST_HEALTH,
        },
    },
    {
        "name": "内置-暴力路径枚举(单路径高频)",
        "description": "同源对同一路径高频请求（≥60 次，疑似参数/账号枚举）",
        "source": "builtin",
        "priority": 26,
        "severity": "medium",
        "conditions": {
            "mode": "count",
            "key": ["src_ip", "uri_path"],
            "min_count": 60,
            "logic": "and",
            "rules": [{"field": "log_type", "op": "eq", "value": "http"}],
            "whitelist": _WHITELIST_HEALTH,
        },
    },
    {
        "name": "内置-服务端错误突变",
        "description": "同源在窗口内产生大量 5xx（≥20 次，疑似打挂或注入成功）",
        "source": "builtin",
        "priority": 22,
        "severity": "medium",
        "conditions": {
            "mode": "count",
            "key": ["src_ip"],
            "min_count": 20,
            "logic": "and",
            "rules": [
                {"field": "log_type", "op": "eq", "value": "http"},
                {"field": "status_code", "op": "gte", "value": 500},
            ],
        },
    },
    {
        "name": "内置-大面积目标探测",
        "description": "同源在窗口内访问大量不同目标（≥25 个 distinct dst_ip）",
        "source": "builtin",
        "priority": 24,
        "severity": "medium",
        "conditions": {
            "mode": "count",
            "key": ["src_ip"],
            "min_count": 25,
            "distinct": "dst_ip",
            "min_distinct": 25,
            "logic": "and",
            "rules": [{"field": "src_ip", "op": "exists"}],
        },
    },
    {
        "name": "内置-端口扫描",
        "description": "检测到端口扫描行为（notice）",
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
        "description": "同源在窗口内发起大量失败连接（≥30 次）",
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
    # ================= D. 凭证 / 会话 =================
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
        "name": "内置-Wazuh登录失败",
        "description": "Wazuh 认证失败规则组",
        "source": "builtin",
        "priority": 20,
        "severity": "medium",
        "conditions": {
            "logic": "and",
            "rules": [{"field": "rule_groups", "op": "regex", "value": "(?i)authentication_fail"}],
        },
    },
    {
        "name": "内置-高频认证失败",
        "description": "同源在窗口内出现大量认证失败（≥10 次）",
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
        "name": "内置-登录接口爆破",
        "description": "同源对登录接口高频 POST（≥15 次）",
        "source": "builtin",
        "priority": 12,
        "severity": "critical",
        "conditions": {
            "mode": "count",
            "key": ["src_ip"],
            "min_count": 15,
            "logic": "and",
            "rules": [
                {"field": "event_type", "op": "eq", "value": "http_login"},
                {"field": "method", "op": "in", "value": ["POST", "PUT"]},
            ],
            "whitelist": _WHITELIST_HEALTH,
        },
    },
    {
        "name": "内置-密码喷洒(同源多账号)",
        "description": "同源对 ≥5 个不同账号尝试登录（密码喷洒特征）",
        "source": "builtin",
        "priority": 8,
        "severity": "critical",
        "conditions": {
            "mode": "count",
            "key": ["src_ip"],
            "min_count": 5,
            "distinct": "account",
            "min_distinct": 5,
            "logic": "and",
            "rules": [
                {"field": "event_type", "op": "eq", "value": "http_login"},
                {"field": "account", "op": "exists"},
            ],
        },
    },
    {
        "name": "内置-撞库(同账号多源)",
        "description": "同一账号来自 ≥3 个不同源 IP 的登录（撞库/凭证填充特征）",
        "source": "builtin",
        "priority": 8,
        "severity": "critical",
        "conditions": {
            "mode": "count",
            "key": ["account"],
            "min_count": 3,
            "distinct": "src_ip",
            "min_distinct": 3,
            "logic": "and",
            "rules": [
                {"field": "event_type", "op": "in", "value": ["http_login", "brute_force"]},
                {"field": "account", "op": "exists"},
            ],
        },
    },
    {
        "name": "内置-HTTPBasic凭证暴力",
        "description": "同源对 HTTP Basic 认证高频请求（≥15 次）",
        "source": "builtin",
        "priority": 12,
        "severity": "high",
        "conditions": {
            "mode": "count",
            "key": ["src_ip"],
            "min_count": 15,
            "logic": "and",
            "rules": [
                {"field": "auth_scheme", "op": "eq", "value": "basic"},
                {"field": "status_code", "op": "in", "value": [401, 403]},
            ],
        },
    },
    {
        "name": "内置-会话跨IP复用",
        "description": "同一会话 cookie 出现在 ≥2 个不同源 IP（疑似会话劫持/凭证盗用）",
        "source": "builtin",
        "priority": 8,
        "severity": "critical",
        "conditions": {
            "mode": "count",
            "key": ["cookie"],
            "min_count": 2,
            "distinct": "src_ip",
            "min_distinct": 2,
            "logic": "and",
            "rules": [
                {"field": "cookie", "op": "exists"},
                {"field": "log_type", "op": "eq", "value": "http"},
            ],
        },
    },
    {
        "name": "内置-明文凭证传输(HTTP登录)",
        "description": "HTTP（非 TLS）端口上出现登录/凭证提交",
        "source": "builtin",
        "priority": 15,
        "severity": "high",
        "conditions": {
            "logic": "and",
            "rules": [
                {"field": "event_type", "op": "eq", "value": "http_login"},
                {"field": "dst_port", "op": "eq", "value": 80},
                {"field": "method", "op": "eq", "value": "POST"},
            ],
        },
    },
    {
        "name": "内置-默认口令尝试",
        "description": "请求体中出现常见默认口令组合",
        "source": "builtin",
        "priority": 15,
        "severity": "high",
        "conditions": {
            "logic": "or",
            "rules": [
                {
                    "field": "body",
                    "op": "regex",
                    "value": "(?i)(pass(word)?=(admin|123456|root|test|guest|admin123))",
                },
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(pass(word)?=(admin|123456|root|test|guest))",
                },
            ],
        },
    },
    {
        "name": "内置-Token/JWT异常使用",
        "description": "Bearer/JWT 令牌出现在 URL 参数或被用于高频请求",
        "source": "builtin",
        "priority": 20,
        "severity": "medium",
        "conditions": {
            "logic": "or",
            "rules": [
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)(token|jwt|access_token|id_token)=ey[A-Za-z0-9_-]{10,}",
                },
                {"field": "auth_scheme", "op": "in", "value": ["bearer", "jwt"]},
            ],
        },
    },
    {
        "name": "内置-密码重置接口滥用",
        "description": "同源对密码重置接口高频请求（≥10 次）",
        "source": "builtin",
        "priority": 15,
        "severity": "high",
        "conditions": {
            "mode": "count",
            "key": ["src_ip"],
            "min_count": 10,
            "logic": "and",
            "rules": [
                {
                    "field": "uri_path",
                    "op": "regex",
                    "value": "(?i)/(reset|forgot|password|passwd|recover|unlock)",
                },
            ],
        },
    },
    {
        "name": "内置-多账号同机登录",
        "description": "同一源 IP 使用 ≥8 个不同账号（共享终端或撞库）",
        "source": "builtin",
        "priority": 18,
        "severity": "medium",
        "conditions": {
            "mode": "count",
            "key": ["src_ip"],
            "min_count": 8,
            "distinct": "account",
            "min_distinct": 8,
            "logic": "and",
            "rules": [
                {"field": "account", "op": "exists"},
                {"field": "log_type", "op": "eq", "value": "wazuh"},
            ],
        },
    },
    {
        "name": "内置-Wazuh账号锁定",
        "description": "Wazuh 账号锁定/多次失败后锁定类规则",
        "source": "builtin",
        "priority": 12,
        "severity": "high",
        "conditions": {
            "logic": "and",
            "rules": [
                {
                    "field": "rule_groups",
                    "op": "regex",
                    "value": "(?i)(account_lock|locked|disabled)",
                },
            ],
        },
    },
    {
        "name": "内置-Wazuh提权告警",
        "description": "Wazuh 提权/特权操作类规则",
        "source": "builtin",
        "priority": 10,
        "severity": "high",
        "conditions": {
            "logic": "or",
            "rules": [
                {
                    "field": "rule_groups",
                    "op": "regex",
                    "value": "(?i)(privilege_escalation|sudo|su_)",
                },
                {
                    "field": "summary",
                    "op": "regex",
                    "value": "(?i)(privilege escalation|sudo:|su: )",
                },
            ],
        },
    },
    # ================= E. 横向移动 =================
    {
        "name": "内置-横向移动高频连接",
        "description": "同一源对同一目标的高频管理端口连接（SMB/RDP/WinRM ≥10）",
        "source": "builtin",
        "priority": 22,
        "severity": "high",
        "conditions": {
            "mode": "count",
            "key": ["src_ip", "dst_ip"],
            "min_count": 10,
            "logic": "and",
            "rules": [
                {
                    "field": "dst_port",
                    "op": "in",
                    "value": [445, 139, 135, 3389, 5985, 5986, 512, 513, 514],
                },
            ],
        },
    },
    {
        "name": "内置-横向移动多目标",
        "description": "同源对 ≥8 个不同目标的管理端口连接（横向扩散特征）",
        "source": "builtin",
        "priority": 18,
        "severity": "high",
        "conditions": {
            "mode": "count",
            "key": ["src_ip"],
            "min_count": 8,
            "distinct": "dst_ip",
            "min_distinct": 8,
            "logic": "and",
            "rules": [
                {"field": "dst_port", "op": "in", "value": [445, 139, 135, 3389, 5985, 5986]},
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
    # ================= F. 外联 / C2 / 隧道 =================
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
                    "value": [
                        4444,
                        4445,
                        5555,
                        6666,
                        6667,
                        7777,
                        9001,
                        9050,
                        1337,
                        31337,
                        12345,
                        54321,
                    ],
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
        "name": "内置-DNS-TXT隧道",
        "description": "DNS TXT 记录高频查询（隧道特征）",
        "source": "builtin",
        "priority": 20,
        "severity": "high",
        "conditions": {
            "mode": "count",
            "key": ["src_ip", "query"],
            "min_count": 10,
            "logic": "and",
            "rules": [
                {"field": "log_type", "op": "eq", "value": "dns"},
                {"field": "qtype", "op": "in", "value": ["16", "TXT"]},
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
    # ================= G. 数据外传 =================
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
    {
        "name": "内置-大规模数据下载",
        "description": "单连接下载 > 100MB（疑似数据窃取）",
        "source": "builtin",
        "priority": 20,
        "severity": "high",
        "conditions": {
            "logic": "and",
            "rules": [{"field": "bytes_in", "op": "gt", "value": 104857600}],
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
    # ================= I. 其他 Web / 协议异常 =================
    {
        "name": "内置-CSRF可疑来源",
        "description": "状态变更请求携带外部站点 Referer",
        "source": "builtin",
        "priority": 30,
        "severity": "low",
        "conditions": {
            "logic": "and",
            "rules": [
                {"field": "method", "op": "in", "value": ["POST", "PUT", "DELETE"]},
                {"field": "referer", "op": "regex", "value": "^https?://"},
                {
                    "field": "referer",
                    "op": "regex",
                    "value": "(?i)(evil|attacker|burpcollaborator|interact\\.sh)",
                },
            ],
        },
    },
    {
        "name": "内置-CORS配置错误探测",
        "description": "探测 CORS 配置（Origin 为可疑外部域）",
        "source": "builtin",
        "priority": 30,
        "severity": "low",
        "conditions": {
            "logic": "or",
            "rules": [
                {
                    "field": "query",
                    "op": "regex",
                    "value": "(?i)origin=(null|https?://(evil|attacker))",
                },
                {
                    "field": "body",
                    "op": "regex",
                    "value": "(?i)origin=(null|https?://(evil|attacker))",
                },
            ],
        },
    },
    {
        "name": "内置-上传类型不匹配",
        "description": "上传请求的 Content-Type 与文件名不符（疑似绕过）",
        "source": "builtin",
        "priority": 20,
        "severity": "medium",
        "conditions": {
            "logic": "and",
            "rules": [
                {"field": "event_type", "op": "eq", "value": "http_upload"},
                {"field": "content_type", "op": "regex", "value": "(?i)(image/|text/plain)"},
                {
                    "field": "uri_path",
                    "op": "regex",
                    "value": "(?i)\\.(php|jsp|aspx|sh|war)",
                },
            ],
        },
    },
    {
        "name": "内置-API高频调用",
        "description": "同源对 API 高频调用（≥200 次，疑似爬取或压测）",
        "source": "builtin",
        "priority": 34,
        "severity": "low",
        "conditions": {
            "mode": "count",
            "key": ["src_ip"],
            "min_count": 200,
            "logic": "and",
            "rules": [{"field": "uri_path", "op": "regex", "value": "(?i)^/(api|rest|graphql)"}],
            "whitelist": _WHITELIST_HEALTH,
        },
    },
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
