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

# 健康检查白名单的扩展：K8s actuator / 探针 / 指标接口被业务与编排常驻轮询，
# 归到「敏感文件探测」「未授权访问」这类规则里就是持续 FP（2026-10 规则评审 P1）。
_WHITELIST_PROBE = _WHITELIST_HEALTH + [
    {
        "field": "uri_path",
        "op": "regex",
        "value": "(?i)(/actuator/(health|info|readiness|liveness)"
        "|/healthz?$|/readyz$|/livez$|/metrics$|/health/)",
    },
]

#: 已**退役**的内置规则：名字从 `BUILTIN_RULES` 里拿掉了，但库里那行要保留并置停用。
#:
#: 为什么不删行：① 运维在规则页能看到「它为什么没了」；② 随时可以手动启用回去（回滚一条开关）。
#: 为什么退役「内置-扫描尝试连接」（2026-10 实机实测）：它的判据只有 `event_type=scan_attempt`
#: （conn_state S0 = 只发 SYN 无回应），**没有任何规模要求** → 一次失败 SYN 就告警。实测近 15 分钟
#: 9,165 条 S0 / 92 个源，其中不同目的端口最多的源只有 **3 个**（全是「服务没起/防火墙静默丢」
#: 的固定端口重试与「443→Google 0 回应」的出站被丢）→ 误报率 ≈ 100%，且吃掉 66~71 条摘要/5 分钟
#: （全部摘要的 55~79%），还会把频率规则饿死（见 detector/runner.py 的那段注释）。
#: 覆盖面由已有的扇出型规则接手：`内置-高频扫描连接`（30 分钟 ≥30 次且 ≥8 个不同端口）、
#: `内置-内网慢速服务枚举`（6h 内同源同目的 ≥25 个不同端口）、`内置-内网慢速横向`
#: （6h 内 ≥10 个不同内网目的）；新增的 `内置-快速端口扫描` 补齐「窄端口扫描（8~29 个端口）」
#: 这最后一个口子。
RETIRED_RULES: dict[str, str] = {
    "内置-扫描尝试连接": (
        "已停用：单次失败连接不再告警（实测误报率≈100%）。改由「内置-快速端口扫描」"
        "「内置-高频扫描连接」「内置-内网慢速服务枚举」「内置-内网慢速横向」按扇出判定。"
    ),
}

#: 要**直接删行**的内置规则（不是停用）。
#:
#: 为什么删而不是停用（2026-10 实机数据）：`内置-端口扫描` 的判据是 `event_type=port_scan`，
#: 而本部署采集面关掉了 Zeek 自带 notice（`shentong-policies.zeek`）→ 这个事件类型**不会由 Zeek 产生**；
#: 规则本身没有任何有效命中路径，留着只会是一个“看起来在防扫描”的死条。
DELETED_RULES: dict[str, str] = {
    "内置-端口扫描": "notice 型死规则（本部署不产生 port_scan；唯一来源是已被修正的日志源词匹配误判）",
    # 2026-10 用户口径：明文凭证传输是「配置事实」而不是攻击事件 —— 实测 2,848 条/12h 全是
    # 校园 App 的正常登录（status=200、579/644 个真实客户端），逐次告警只占额度。真要治理，
    # 应作为「站点该上 HTTPS」的配置类问题一次性处理，而不是当事件告警。
    "内置-明文凭证传输(HTTP登录)": "按用户口径删除：明文凭证属配置事实而非攻击事件（校园 App 正常登录逐次报）",
    # 2026-10 方案 A：与「多路径探测」同一行为双报（评审 recon.md:38），且门槛只有「次数」
    # 没有「不同路径」⇒ 正常用户连点 30 个 404（坏链/缺图）就会中（engine-semantics.md:189）。
    # 检测能力由「多路径探测」（≥50 个不同路径且失败）接手，故整条删除。
    "内置-目录/路径爆破": "与「多路径探测」重复且门槛过低（30 次 403/404、不限路径）：并入「多路径探测」",
    # 2026-10 用户口径：自签证书不需要检测。本环境实测 `cert_self_signed == true` 文档数 = 0
    # （一个自签都没有），且该规则判据只剩这一条布尔（issuer 分支上一步已按实机数据删除）——
    # 属“配置事实”而非攻击事件，故整条删除。
    "内置-自签或异常证书": "按用户口径删除：自签证书不需要检测（属配置事实非攻击事件）",
    # 2026-10 用户口径：只保留有攻击含义的 TLS 判据，放弃低价值的那条。
    # 实测（7 天）：event_type=tls_anomaly 共 59 条 ≈ 8 条/天，全部来自 weird.log，
    # 目标固定在同一个对外 TLS 服务（7 天 2,400+ 次成功会话里约 7% 异常收尾）；
    # 异常名是 SSL_excessive_alerts_in_record / ssl_early_application_data —— 它们说的是
    # 「客户端/中间盒与该服务的握手不顺」，属运维/健康信号，不是攻击事件，而这条规则
    # 是**裸单条匹配**（来一条报一条）。取代它的是两条有攻击含义的判据：
    # 「内置-TLS弱版本协商」「内置-TLS握手失败风暴」。
    "内置-TLS异常": "裸单条匹配，实测 8 条/天全是握手不顺的运维信号（非攻击事件）；由新的 TLS 两条判据取代",
    "内置-主机恶意软件告警": "主机监控线已随其日志源一起下线（本项目不再保留该日志源）",
    "内置-Web攻击（主机监控）": "主机监控线已随其日志源一起下线（本项目不再保留该日志源）",
    "内置-暴力破解": "主机监控线已随其日志源一起下线（本项目不再保留该日志源）",
    "内置-主机登录失败": "主机监控线已随其日志源一起下线（本项目不再保留该日志源）",
    "内置-高频认证失败": "主机监控线已随其日志源一起下线（本项目不再保留该日志源）",
    "内置-撞库(同账号多源)": "主机监控线已随其日志源一起下线（本项目不再保留该日志源）",
    "内置-多账号同机登录": "主机监控线已随其日志源一起下线（本项目不再保留该日志源）",
    "内置-主机账号锁定": "主机监控线已随其日志源一起下线（本项目不再保留该日志源）",
    "内置-主机提权告警": "主机监控线已随其日志源一起下线（本项目不再保留该日志源）",
    "内置-主机高危告警": "主机监控线已随其日志源一起下线（本项目不再保留该日志源）",
    "内置-主机文件完整性变更": "主机监控线已随其日志源一起下线（本项目不再保留该日志源）",
    "内置-主机漏洞告警": "主机监控线已随其日志源一起下线（本项目不再保留该日志源）",
    "内置-主机网络告警": "主机监控线已随其日志源一起下线（本项目不再保留该日志源）",
    "内置-主机MITRE映射命中": "主机监控线已随其日志源一起下线（本项目不再保留该日志源）",
    "内置-主机策略违规": "主机监控线已随其日志源一起下线（本项目不再保留该日志源）",
    # ----------------- 2026-10：与签名引擎（Suricata / ET Open）重叠的 48 条 -----------------
    # 这 48 条的判据全部落在「HTTP 的 hostname/uri/method/user_agent/cookie/请求体/响应体、
    # 文件属性、TLS 版本、DNS 查询名」这些字段上，而 Suricata 有**一一对应的规则关键字**
    # （http.host / http.uri / http.request_body / http.response_body / file.name / filemd5 /
    # tls.version / dns.query …），ET Open 里本来就有对应的现成签名，覆盖比自写 80 条广。
    # 检测器留下的价值在签名引擎结构上做不了的层：基线/画像/资产、中继链路还原、内外网方向、
    # 「按实体计不同值」（数据库的集合是二值，不会数“有几个不同的账号/端口/目的”）。
    # 保留的 32 条 = 15 条主机侧（+ 网络事件它看不到）+ 12 条计不同值 + 5 条部分重叠（3 条流量
    # 体积 + 协议异常 + TLS 异常）。配套改动：采集侧新增 Suricata 容器与归一化来源（两侧栈同步）。
    "内置-勒索/僵尸网络域名": "与签名引擎（Suricata / ET Open）重叠，已由 IOC 名单 签名覆盖",
    "内置-挖矿域名/矿池": "与签名引擎（Suricata / ET Open）重叠，已由 IOC 名单 签名覆盖",
    "内置-SQL注入-基础特征": "与签名引擎（Suricata / ET Open）重叠，已由 Web 攻击特征 签名覆盖",
    "内置-SQL注入-元数据与文件读写": "与签名引擎（Suricata / ET Open）重叠，已由 Web 攻击特征 签名覆盖",
    "内置-NoSQL注入": "与签名引擎（Suricata / ET Open）重叠，已由 Web 攻击特征 签名覆盖",
    "内置-命令注入特征": "与签名引擎（Suricata / ET Open）重叠，已由 Web 攻击特征 签名覆盖",
    "内置-路径穿越-编码变体": "与签名引擎（Suricata / ET Open）重叠，已由 Web 攻击特征 签名覆盖",
    "内置-XSS/脚本注入特征": "与签名引擎（Suricata / ET Open）重叠，已由 Web 攻击特征 签名覆盖",
    "内置-模板注入SSTI": "与签名引擎（Suricata / ET Open）重叠，已由 Web 攻击特征 签名覆盖",
    "内置-表达式注入与JNDI(Log4Shell)": "与签名引擎（Suricata / ET Open）重叠，已由 Web 攻击特征 签名覆盖",
    "内置-XXE外部实体注入": "与签名引擎（Suricata / ET Open）重叠，已由 Web 攻击特征 签名覆盖",
    "内置-反序列化特征": "与签名引擎（Suricata / ET Open）重叠，已由 Web 攻击特征 签名覆盖",
    "内置-SSRF敏感参数与协议": "与签名引擎（Suricata / ET Open）重叠，已由 Web 攻击特征 签名覆盖",
    "内置-文件包含/协议流": "与签名引擎（Suricata / ET Open）重叠，已由 Web 攻击特征 签名覆盖",
    "内置-CRLF/响应头注入": "与签名引擎（Suricata / ET Open）重叠，已由 Web 攻击特征 签名覆盖",
    "内置-LDAP注入": "与签名引擎（Suricata / ET Open）重叠，已由 Web 攻击特征 签名覆盖",
    "内置-开放重定向探测": "与签名引擎（Suricata / ET Open）重叠，已由 Web 攻击特征 签名覆盖",
    "内置-Host头攻击": "与签名引擎（Suricata / ET Open）重叠，已由 Web 攻击特征 签名覆盖",
    "内置-危险HTTP方法": "与签名引擎（Suricata / ET Open）重叠，已由 Web 攻击特征 签名覆盖",
    "内置-WebShell上传": "与签名引擎（Suricata / ET Open）重叠，已由 WebShell 特征 签名覆盖",
    "内置-WebShell访问": "与签名引擎（Suricata / ET Open）重叠，已由 WebShell 特征 签名覆盖",
    "内置-恶意文件传输": "与签名引擎（Suricata / ET Open）重叠，已由 文件哈希/类型 签名覆盖",
    "内置-弱TLS版本": "与签名引擎（Suricata / ET Open）重叠，已由 TLS 特征 签名覆盖",
    "内置-Web攻击扫描器UA": "与签名引擎（Suricata / ET Open）重叠，已由 Web 侦查与探测特征 签名覆盖",
    "内置-JA3指纹命中": "与签名引擎（Suricata / ET Open）重叠，已由 TLS 特征 签名覆盖",
    "内置-敏感文件与源码泄露探测": "与签名引擎（Suricata / ET Open）重叠，已由 Web 侦查与探测特征 签名覆盖",
    "内置-未授权访问探测成功": "与签名引擎（Suricata / ET Open）重叠，已由 Web 侦查与探测特征 签名覆盖",
    "内置-云元数据访问": "与签名引擎（Suricata / ET Open）重叠，已由签名覆盖",
    "内置-框架漏洞探测特征": "与签名引擎（Suricata / ET Open）重叠，已由 Web 侦查与探测特征 签名覆盖",
    "内置-参数fuzzing超长载荷": "与签名引擎（Suricata / ET Open）重叠，已由 Web 侦查与探测特征 签名覆盖",
    "内置-暴力路径枚举(单路径高频)": "与签名引擎（Suricata / ET Open）重叠，已由 Web 侦查与探测特征 签名覆盖",
    "内置-服务端错误突变": "与签名引擎（Suricata / ET Open）重叠，已由 Web 侦查与探测特征 签名覆盖",
    "内置-登录接口爆破": "与签名引擎（Suricata / ET Open）重叠，已由 认证类 HTTP 特征 签名覆盖",
    "内置-HTTPBasic凭证暴力": "与签名引擎（Suricata / ET Open）重叠，已由 认证类 HTTP 特征 签名覆盖",
    "内置-默认口令尝试": "与签名引擎（Suricata / ET Open）重叠，已由 认证类 HTTP 特征 签名覆盖",
    "内置-Token/JWT异常使用": "与签名引擎（Suricata / ET Open）重叠，已由 HTTP 频率/头特征 签名覆盖",
    "内置-密码重置接口滥用": "与签名引擎（Suricata / ET Open）重叠，已由 认证类 HTTP 特征 签名覆盖",
    "内置-横向移动高频连接": "与签名引擎（Suricata / ET Open）重叠，已由 连接与端口特征 签名覆盖",
    "内置-横向移动管理端口": "与签名引擎（Suricata / ET Open）重叠，已由 连接与端口特征 签名覆盖",
    "内置-异常外联端口": "与签名引擎（Suricata / ET Open）重叠，已由 连接与端口特征 签名覆盖",
    "内置-DNS隧道可疑长查询": "与签名引擎（Suricata / ET Open）重叠，已由 DNS 特征 签名覆盖",
    "内置-可疑域名（动态DNS/短域名）": "与签名引擎（Suricata / ET Open）重叠，已由 DNS 特征 签名覆盖",
    "内置-CSRF可疑来源": "与签名引擎（Suricata / ET Open）重叠，已由 HTTP 频率/头特征 签名覆盖",
    "内置-CORS配置错误探测": "与签名引擎（Suricata / ET Open）重叠，已由 HTTP 频率/头特征 签名覆盖",
    "内置-上传类型不匹配": "与签名引擎（Suricata / ET Open）重叠，已由 Web 侦查与探测特征 签名覆盖",
    "内置-API高频调用": "与签名引擎（Suricata / ET Open）重叠，已由 HTTP 频率/头特征 签名覆盖",
    "内置-常见敏感端口访问": "与签名引擎（Suricata / ET Open）重叠，已由 连接与端口特征 签名覆盖",
    "内置-Bearer令牌高频使用": "与签名引擎（Suricata / ET Open）重叠，已由 HTTP 频率/头特征 签名覆盖",
}


BUILTIN_RULES: list[dict] = [
    # ================= A. 勒索 / 僵尸网络 / 挖矿 =================
    # ================= B. 注入 / 漏洞利用 =================
    # ================= C. 探测 / 漏洞挖掘 =================
    {
        "name": "内置-多路径探测(漏洞挖掘)",
        "description": "同源在窗口内访问 ≥50 个不同路径且均为失败（401/403/404）",
        "source": "builtin",
        "priority": 24,
        "severity": "high",
        # 2026-10 实机数据（近 6h 按源 IP 的路径扇出）：
        # - 原条件把 **200** 也算进来 ⇒ 主要命中「正常浏览/爬虫」：≥50 个不同路径的源有 43 个，
        #   状态码收成 401/403/404 后只剩 **1** 个 —— 与规则自己那句注释「这里只看大量不同路径
        #   且失败」矛盾（注释写了、条件没写）；
        # - 原「内置-目录/路径爆破」（同源 ≥30 次 403/404，不限不同路径）与它是**同一行为双报**
        #   （2026-10 规则评审 recon.md 第 38 行已点出），而且门槛只有“次数”没有“不同路径” ⇒
        #   正常用户连点 30 个 404（坏链/缺图）就会中（engine-semantics.md:189 同一条结论）。
        #   那条已删除（见 DELETED_RULES），本规则接过它的检测能力并把口径收严。
        "conditions": {
            "mode": "count",
            "key": ["src_ip"],
            "min_count": 50,
            "distinct": "uri_path",
            "min_distinct": 50,
            "logic": "and",
            "rules": [
                {"field": "log_type", "op": "eq", "value": "http"},
                # 只看「不同路径且失败」：200 路径是正常浏览/爬虫的形态，不计入
                {"field": "status_code", "op": "in", "value": [401, 403, 404]},
            ],
            "whitelist": _WHITELIST_PROBE,
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
            "min_count": 40,
            "distinct": "dst_ip",
            "min_distinct": 40,
            "logic": "and",
            # `src_ip exists` 是恒真条件（评审 P0-3）：那等于「无条件按源计数」，
            # 监控/备份/代理/NAT 全部命中。改为只统计「未建立的连接」。
            "rules": [
                {
                    "field": "event_type",
                    "op": "in",
                    "value": ["scan_attempt", "rejected_connection"],
                },
            ],
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
            "distinct": "dst_port",
            "min_distinct": 8,
            "window": 1800,
            "logic": "and",
            # 只认 S0 会漏掉 REJ/RSTOS0/RSTRH 型扫描（conn_states 表）
            "rules": [
                {
                    "field": "event_type",
                    "op": "in",
                    "value": ["scan_attempt", "rejected_connection", "port_scan"],
                },
            ],
        },
    },
    {
        "name": "内置-快速端口扫描",
        "description": (
            "同源 5 分钟内 ≥10 次失败连接、且摸到 ≥8 个不同目的端口（窄端口扫描的典型形态）"
        ),
        "source": "builtin",
        "priority": 25,
        "severity": "medium",
        "conditions": {
            "mode": "count",
            "key": ["src_ip"],
            "window": 300,
            "min_count": 10,
            "distinct": "dst_port",
            "min_distinct": 8,
            "logic": "and",
            # 为什么是这两个事件类型（2026-10 实机实测）：`scan_attempt`（S0：只发 SYN 无回应）
            # 单靠自己既误报（防火墙静默丢/服务没起）又漏报 —— 经典 connect 扫描打「活主机的
            # 关闭端口」会收到 RST，Zeek 记的是 `rejected_connection`（REJ/RSTOS0/RSTRH）。
            # **不能**把已建立后的 RST（RSTO/RSTR）算进来：那是正常业务断连（conn_states 表）。
            "rules": [
                {"field": "log_type", "op": "eq", "value": "conn"},
                {
                    "field": "event_type",
                    "op": "in",
                    "value": ["scan_attempt", "rejected_connection"],
                },
            ],
        },
    },
    # ================= C2. 内网利用特征 =================
    {
        "name": "内置-内网漏洞利用探测",
        "description": (
            "同源 6 小时内对 ≥10 个不同内网目的发起带利用特征的请求"
            "（Shellshock/Log4Shell 类载荷头、Nacos/Solr/Tomcat 管理页等被批量利用的端点）"
        ),
        "source": "builtin",
        "priority": 6,
        "severity": "high",
        "conditions": {
            "mode": "count",
            "key": ["src_ip"],
            "window": 21600,
            "min_count": 10,
            "distinct": "dst_ip",
            "min_distinct": 10,
            "logic": "and",
            # 为什么要这条（2026-10 实机调研）：现有扫描类规则只数「不同端口/不同主机」
            # 而且只认未建立的连接；实测一台内网主机（10.1.2.66，后确认是授权漏扫设备）
            # 24h 内在 43 个内网目标上打了 2,905 个端口，UA 里带着 Shellshock 载荷、
            # 路径是 /nacos/v1/cs/ops/data/removal、/solr、/manager/html 这些**利用型端点**，
            # 但没有任何一条规则看「利用特征」。这条把两个维度合起来：**扇出（≥10 个内网目的）
            # ＋ 利用特征（载荷头或利用端点）**，避免单次探测就报。
            "rules": [
                {"field": "src_internal", "op": "eq", "value": True},
                {"field": "dst_internal", "op": "eq", "value": True},
                {
                    "logic": "or",
                    "rules": [
                        # Shellshock：UA / 头里带 `() { :; };` 形式的函数定义载荷
                        {"field": "user_agent", "op": "regex", "value": r"\(\s*\)\s*\{"},
                        # Log4Shell / JNDI 注入
                        {"field": "user_agent", "op": "regex", "value": r"\$\{jndi:"},
                        # 被批量利用的管理/未授权端点
                        {
                            "field": "uri_path",
                            "op": "regex",
                            "value": (
                                r"(?i)(?:/nacos/v1|/solr/|/manager/html|/actuator/(?:env|heapdump|gateway)"
                                r"|/druid/index\.html|/weblogic/|/struts/|\.\./)"
                            ),
                        },
                    ],
                },
            ],
        },
    },
    # ================= D. 凭证 / 会话 =================
    {
        "name": "内置-密码喷洒(同源多账号)",
        "description": "同源对 ≥5 个不同账号尝试登录（密码喷洒特征）",
        "source": "builtin",
        "priority": 8,
        "severity": "critical",
        "conditions": {
            "mode": "count",
            "key": ["src_ip", "dst_ip"],
            "min_count": 8,
            "window": 900,
            "distinct": "account",
            "min_distinct": 8,
            "logic": "and",
            "rules": [
                {"field": "event_type", "op": "eq", "value": "http_login"},
                {"field": "account", "op": "exists"},
            ],
        },
    },
    {
        "name": "内置-会话跨IP复用",
        "description": (
            "同一会话 id（按 ST_SESSION_COOKIE_NAMES 从 Cookie 头识别）出现在 ≥2 个不同源 IP"
            "（疑似会话劫持/凭证盗用）"
        ),
        "source": "builtin",
        "priority": 8,
        "severity": "critical",
        # 为什么键从 `cookie` 换成 `session_id`（2026-10 实机数据）：整条 Cookie 头里含有
        # **跨用户恒定**的值 —— `Path=/`（应用用 document.cookie 造出的常量 cookie）跨 2 个源 IP、
        # `EPORTAL_COOKIE_PASSWORD=` 空值模板跨 164 个源 IP ⇒ 24h 337 条 critical 摘要零真命中。
        # session_id 是「名字精确匹配 + 值非空」的会话值，这类常量 cookie 天然被排除。
        "conditions": {
            "mode": "count",
            "key": ["session_id"],
            "min_count": 2,
            "distinct": "src_ip",
            "min_distinct": 2,
            "logic": "and",
            "rules": [
                {"field": "session_id", "op": "exists"},
                {"field": "log_type", "op": "eq", "value": "http"},
            ],
        },
    },
    # ================= E. 横向移动 =================
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
            "window": 1800,
            "distinct": "dst_ip",
            "min_distinct": 8,
            "logic": "and",
            "rules": [
                {"field": "dst_port", "op": "in", "value": [445, 139, 135, 3389, 5985, 5986]},
                {"field": "conn_state", "op": "in", "value": ["SF", "S1", "S2", "S3"]},
            ],
        },
    },
    # ================= F. 外联 / C2 / 隧道 =================
    {
        "name": "内置-DNS-TXT隧道",
        "description": "DNS TXT 记录高频查询（隧道特征）",
        "source": "builtin",
        "priority": 20,
        "severity": "high",
        "conditions": {
            "mode": "count",
            # 原来 key 含 query（同一个名字重复 10 次）与隧道语义相反（评审 P1）：
            # TXT 隧道的特征是「同源查询大量**不同**的 TXT 名字」。
            "key": ["src_ip"],
            "min_count": 20,
            "window": 900,
            "distinct": "query",
            "min_distinct": 20,
            "logic": "and",
            "rules": [
                {"field": "log_type", "op": "eq", "value": "dns"},
                # qtype 优先存数字码，上游缺数字时才回落 qtype_name（评审 P1）
                {"field": "qtype", "op": "regex", "value": "(?i)^(16|txt)$"},
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
            "rules": [
                {"field": "bytes_out", "op": "gt", "value": 10485760},
                {"field": "src_internal", "op": "eq", "value": True},
                {"field": "dst_external", "op": "eq", "value": True},
            ],
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
            "rules": [
                {"field": "bytes_out", "op": "gt", "value": 104857600},
                {"field": "src_internal", "op": "eq", "value": True},
                {"field": "dst_external", "op": "eq", "value": True},
            ],
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
            "rules": [
                {"field": "bytes_in", "op": "gt", "value": 104857600},
                {"field": "src_external", "op": "eq", "value": True},
                {"field": "dst_internal", "op": "eq", "value": True},
            ],
        },
    },
    # ================= H. 主机监控其他语义 =================
    # ================= I. 其他 Web / 协议异常 =================
    {
        "name": "内置-协议异常",
        "description": "网络采集器：weird/协议异常（同源窗口内 ≥5 次；采集类异常已单列，见状态页「采集质量」灯）",
        "source": "builtin",
        "priority": 30,
        "severity": "medium",
        # 为什么加同源频次门槛（2026-10 实机实测）：摘要按「源 IP × 规则」分组，
        # 一次单发的怪象（DNS_unknown_opcode / bad_HTTP_request 各几条）也会各占一条摘要 ——
        # 实测残留的 ~52 个源每 5 分钟就吃 52~68 条额度（每个源只出 1 次）。
        # 同源 ≥5 次才算「成规模的协议异常」，单发留在 ES 里供回溯/MCP 查。
        "conditions": {
            "mode": "count",
            "key": ["src_ip"],
            "min_count": 5,
            "logic": "and",
            "rules": [{"field": "event_type", "op": "eq", "value": "protocol_anomaly"}],
        },
    },
    {
        "name": "内置-SMTP滥用",
        "description": "SMTP 垃圾邮件/滥用行为",
        "source": "builtin",
        "priority": 30,
        "severity": "medium",
        "conditions": {
            # 原 `OR log_type==smtp` 会把**每一封正常邮件**报 medium（评审 P1）；
            # 而 smtp_abuse 只由已关闭的 notice 流产出。改成「同源群发」的频率规则。
            "mode": "count",
            "key": ["src_ip"],
            "min_count": 50,
            "window": 1800,
            "distinct": "dst_ip",
            "min_distinct": 20,
            "logic": "and",
            "rules": [{"field": "log_type", "op": "eq", "value": "smtp"}],
        },
    },
    {
        "name": "内置-内网慢速横向",
        "description": "同一内网源在 6 小时内命中 ≥5 个不同内网目标（低慢小横向；短窗规则抓不到）",
        "source": "builtin",
        "priority": 27,
        "severity": "high",
        "conditions": {
            "mode": "count",
            "key": ["src_ip"],
            "window": 21600,
            "min_count": 10,
            "distinct": "dst_ip",
            "min_distinct": 10,
            "logic": "and",
            "rules": [
                {"field": "log_type", "op": "eq", "value": "conn"},
                {"field": "src_internal", "op": "eq", "value": True},
                {"field": "dst_internal", "op": "eq", "value": True},
                # 服务器回包/正常会话也会计入（评审 P1）：只看未建立的连接
                {
                    "field": "conn_state",
                    "op": "in",
                    "value": ["S0", "REJ", "SH", "SHR", "RSTOS0", "RSTRH", "OTH"],
                },
            ],
        },
    },
    {
        "name": "内置-内网慢速服务枚举",
        "description": "同一内网源在 6 小时内对同一目标摸 ≥10 个不同端口（慢速端口枚举）",
        "source": "builtin",
        "priority": 26,
        "severity": "medium",
        "conditions": {
            "mode": "count",
            "key": ["src_ip", "dst_ip"],
            "window": 21600,
            "min_count": 25,
            "distinct": "dst_port",
            "min_distinct": 25,
            "logic": "and",
            "rules": [
                {"field": "log_type", "op": "eq", "value": "conn"},
                {"field": "src_internal", "op": "eq", "value": True},
                {"field": "dst_internal", "op": "eq", "value": True},
                {
                    "field": "conn_state",
                    "op": "in",
                    "value": ["S0", "REJ", "SH", "SHR", "RSTOS0", "RSTRH", "OTH"],
                },
            ],
        },
    },
    # ================= J. 2026-10 规则评审补漏 =================
    {
        "name": "内置-单目标多端口深扫",
        "description": "同源对同一目标在窗口内试探 ≥20 个不同端口（单目标深扫）",
        "source": "builtin",
        "priority": 22,
        "severity": "high",
        "conditions": {
            "mode": "count",
            "key": ["src_ip", "dst_ip"],
            "min_count": 20,
            "window": 1800,
            "distinct": "dst_port",
            "min_distinct": 20,
            "logic": "and",
            "rules": [
                {
                    "field": "event_type",
                    "op": "in",
                    "value": ["scan_attempt", "rejected_connection"],
                },
            ],
        },
    },
    # ----------------- 签名引擎（Suricata）命中：按 EVE severity 分三档 -----------------
    # 判据只有「事件类型 + Suricata 自己的 alert.severity」（1=高 / 2=中 / 3=低）：
    # ET Open 有几万条规则，一刀切成「高危」会把 low 的探测类签名抬得过重，三档更可信。
    # 签名名 / SID / 类别 / community_id 都在归一化字段里，摘要样本中直接可见。
    {
        "name": "内置-签名命中(高危)",
        "description": "签名引擎命中：Suricata 高危签名（alert.severity=1）",
        "source": "builtin",
        "priority": 12,
        "severity": "high",
        "conditions": {
            "logic": "and",
            "rules": [
                {"field": "event_type", "op": "eq", "value": "signature_hit"},
                {"field": "signature_severity", "op": "eq", "value": 1},
            ],
        },
    },
    {
        "name": "内置-签名命中(中危)",
        "description": "签名引擎命中：Suricata 中危签名（alert.severity=2）",
        "source": "builtin",
        "priority": 35,
        "severity": "medium",
        "conditions": {
            "logic": "and",
            "rules": [
                {"field": "event_type", "op": "eq", "value": "signature_hit"},
                {"field": "signature_severity", "op": "eq", "value": 2},
            ],
        },
    },
    {
        "name": "内置-签名命中(低危)",
        "description": "签名引擎命中：Suricata 低危签名（alert.severity=3）",
        "source": "builtin",
        "priority": 60,
        "severity": "low",
        "conditions": {
            "logic": "and",
            "rules": [
                {"field": "event_type", "op": "eq", "value": "signature_hit"},
                {"field": "signature_severity", "op": "eq", "value": 3},
            ],
        },
    },
    # ----------------- TLS 攻击判据（2026-10 按实测重做） -----------------
    # 背景：原「内置-TLS异常」是裸单条匹配（来一条报一条），实测全是运维信号，已删除（见
    # DELETED_RULES 说明）。这里换成两条有攻击含义、且带同源同目标频次门槛的判据。
    # 阈值都是拿线上数据定的，不是拍脑袋：
    #   弱版本协商：6h 全量 ssl 采样里 SSLv3/TLSv10/TLSv11 共 20 条、集中在 1 对 (源,目的)
    #     —— 领先的那一对 18 次，其余对 ≤1 次 ⇒ 阈值取 5 次/6 小时：正好落在两者之间的空白区，
    #     既不会因为「偶发一次」误报，也不会配上过高的门槛变成永不触发的死规则（第一版就是
    #     这么写错的：10 次/小时，实测单对峰值才 3 次/小时）。
    #   握手失败：同期 established=false 168 条 / 31 对，领先的一对 105 次、其余 ≤10 次
    #     ⇒ 阈值取 30 次/6 小时：同样落在空白区，偶发失败不报、风暴才报。
    # 另：本来还想做「版本回退（客户端 offer 高于协商结果）」——实测该判据 0 条命中
    #   （这个环境里没有降级特征），做了一个永不触发的死规则没意义，因此不做。
    {
        "name": "内置-TLS弱版本协商",
        "description": "同源同目标持续协商出弱 TLS 版本（SSLv3/TLSv1.0/TLSv1.1）——疑似旧客户端或降级尝试",
        "source": "builtin",
        "priority": 29,
        "severity": "medium",
        "conditions": {
            "mode": "count",
            "key": ["src_ip", "dst_ip"],
            "min_count": 5,
            "window": 21600,
            "logic": "and",
            "rules": [
                {
                    "field": "tls_version",
                    "op": "in",
                    "value": ["SSLv2", "SSLv3", "TLSv10", "TLSv11"],
                },
            ],
        },
    },
    {
        "name": "内置-TLS握手失败风暴",
        "description": "同源同目标大量 TLS 握手未建立（可能是在探测/压制该 TLS 服务，或服务异常）",
        "source": "builtin",
        "priority": 21,
        "severity": "high",
        "conditions": {
            "mode": "count",
            "key": ["src_ip", "dst_ip"],
            "min_count": 30,
            "window": 21600,
            "logic": "and",
            "rules": [
                {"field": "log_type", "op": "eq", "value": "ssl"},
                {"field": "tls_established", "op": "eq", "value": False},
            ],
        },
    },
]
