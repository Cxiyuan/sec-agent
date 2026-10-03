"""内置安全分析技能：SOP（分析流程/方法）+ 关联脚本工具。

启动时幂等 upsert（见 main._seed）；用户可在后台增删改自定义技能。
每个 SOP 正文按统一结构编写：事件背景 / 判断要点 / 取证步骤 / 常见误报 / 处置建议。
"""

from __future__ import annotations

BUILTIN_SKILLS: list[dict] = [
    {
        "name": "暴力破解分析",
        "description": "SSH/RDP/Web 登录等多协议爆破的识别、溯源与处置",
        "event_types": ["brute_force", "ssh_activity", "http_login"],
        "tools": ["ioc_extract", "geoip_lookup"],
        "priority": 10,
        "sop": (
            "事件背景：攻击者对同一目标或跨目标反复尝试口令登录，特征是短时间高频认证失败。\n"
            "判断要点：\n"
            "1) 统计同一源 IP 在窗口内的失败次数与目标账号分布；成功一次即升级为「爆破成功」。\n"
            "2) 区分水平爆破（扫多个账号）与垂直爆破（对单个账号试多口令）。\n"
            "3) 结合 GeoIP：源 IP 地理位置与业务范围不符时可疑度显著上升。\n"
            "取证步骤：提取源 IP、目标账号、命中端口与协议、时间分布；核对目标资产重要性。\n"
            "常见误报：内部运维批量登录、监控探活、正常重试。\n"
            "处置建议：封禁源 IP、强制目标账号改密/启用 MFA、检查是否已有账号被成功爆破并横向移动。"
        ),
    },
    {
        "name": "端口扫描分析",
        "description": "内/外网端口扫描与探测行为的识别与溯源",
        "event_types": ["port_scan", "scan_attempt", "rejected_connection"],
        "tools": ["geoip_lookup", "port_scan"],
        "priority": 20,
        "sop": (
            "事件背景：攻击者枚举目标存活端口以发现攻击面，特征是短时间多目的端口、多目标、大量半开/拒绝连接。\n"
            "判断要点：\n"
            "1) 统计源 IP 在窗口内接触的目的 IP 数与目的端口数；覆盖面越广越像扫描。\n"
            "2) 区分水平扫描（扫网段）与垂直扫描（扫单主机多端口）。\n"
            "3) 结合 conn_state 判探测还是真实连接：S0/RSTOS0（只发 SYN、无任何回应）与 "
            "REJ/RSTRH 属**未建立**（探测/被拒）；SF/S1/S2/S3 与 RSTO/RSTR（握手已建立、"
            "之后才被断开）属**已建立**；SH/SHR 是「发过 SYN 就 FIN、从未收到 SYN-ACK」，"
            "同样**未建立**。口径唯一来源是 app/ingestion/conn_states.py 的表，别自己按字母猜。\n"
            "取证步骤：提取源 IP、扫描目标范围、端口集；必要时对源 IP 反向端口探测以确认其暴露面。\n"
            "常见误报：资产测绘、漏扫设备、监控系统巡检。\n"
            "处置建议：封禁扫描源、收敛目标暴露面、检查扫描后是否有针对开放端口的后续攻击。"
        ),
    },
    {
        "name": "Web 攻击分析",
        "description": "SQLi/XSS/RCE/SSRF/路径穿越等 Web 应用攻击的识别与取证",
        "event_types": ["web_attack", "wazuh_web_attack", "http_request"],
        "tools": ["url_decode", "ioc_extract"],
        "priority": 15,
        "sop": (
            "事件背景：攻击者通过 HTTP 请求注入恶意 payload，特征体现在 URI/query/body/cookie/header 中。\n"
            "判断要点：\n"
            "1) 先 URL/base64 解码 payload（攻击者常编码绕过 WAF），再识别攻击类型（SQLi/XSS/RCE/SSRF/路径穿越/文件包含）。\n"
            "2) 结合响应状态码：200 且带数据回显可能是注入成功，5xx 多为探针。\n"
            "3) 提取 payload 中的外联地址（回连 C2/外带数据）。\n"
            "取证步骤：解码请求体、定位注入点与 payload、提取 IOC、核对目标是否为关键业务。\n"
            "常见误报：正常表单含特殊字符、扫描器无害探针、URL 中合法编码。\n"
            "处置建议：封禁源 IP、修复注入点、审计该源是否已获取数据或拿下权限。"
        ),
    },
    {
        "name": "恶意软件/C2 外联分析",
        "description": "恶意软件、勒索、木马与 C2 外联行为的识别",
        "event_types": ["wazuh_malware", "conn_established", "tls_session", "file_transfer"],
        "tools": ["ioc_extract", "threat_lookup", "dns_resolve"],
        "priority": 10,
        "sop": (
            "事件背景：主机被植入恶意软件后回连 C2 或外发数据，特征是外联可疑 IP/域名、异常端口、可疑 TLS 指纹。\n"
            "判断要点：\n"
            "1) 提取外联目的 IP/域名/hash，用威胁情报（MalwareBazaar/ThreatFox）比对已知恶意 IOC。\n"
            "2) 关注非常用端口外联、心跳式周期连接、DGA 风格域名。\n"
            "3) 提取文件 hash（md5/sha1/sha256）送恶意样本库查询。\n"
            "取证步骤：提取 IOC、解析 C2 域名、查询恶意样本库、定位受感染主机与传播路径。\n"
            "常见误报：软件更新、云服务调用、正常 CDN 域名。\n"
            "处置建议：隔离主机、断网阻断 C2、清除恶意文件、全盘扫描并检查数据是否外泄。"
        ),
    },
    {
        "name": "横向移动分析",
        "description": "内网横向渗透（凭据重用/远程执行/共享访问）的识别",
        "event_types": ["wazuh_system_change", "ssh_activity", "conn_established"],
        "tools": ["geoip_lookup", "ioc_extract"],
        "priority": 15,
        "sop": (
            "事件背景：攻击者已进入内网后向其它主机蔓延，特征是单源跨多目标、系统配置变更、远程登录。\n"
            "判断要点：\n"
            "1) 统计源 IP 在窗口内触达的内网目标数量，跨越多台主机即疑似横向。\n"
            "2) 关注系统变更事件（服务安装/计划任务/账号创建）与远程执行特征。\n"
            "3) 结合资产重要性：是否已触及核心/数据库主机。\n"
            "取证步骤：提取横向路径（源→目标链）、核对被改动的系统项、关联资产拓扑。\n"
            "常见误报：运维批量变更、合规检查、IT 正常运维。\n"
            "处置建议：隔离受影响主机、吊销被重用凭据、追踪横向起点（初始失陷主机）。"
        ),
    },
    {
        "name": "数据外泄分析",
        "description": "敏感数据对外传输/泄露的识别与评估",
        "event_types": ["file_transfer", "http_upload", "conn_established"],
        "tools": ["ioc_extract", "dns_resolve"],
        "priority": 12,
        "sop": (
            "事件背景：内网数据被上传到外部，特征是外发大流量、文件传输到外部主机、DNS/HTTP 外带。\n"
            "判断要点：\n"
            "1) 关注外发字节量突增、上传到非常用外部目的、非工作时间外传。\n"
            "2) 识别外带通道：明文 HTTP POST、DNS 隧道、ICMP/加密通道。\n"
            "3) 提取外传目的 IP/域名与文件类型。\n"
            "取证步骤：提取外联 IOC、解析外传域名、估算外泄数据量、核对泄露数据敏感度。\n"
            "常见误报：正常云备份、CDN 上传、SaaS 同步。\n"
            "处置建议：阻断外联通道、评估泄露范围与合规影响、通知相关方并启动应急。"
        ),
    },
    {
        "name": "DNS 隧道分析",
        "description": "DNS 隧道/异常 DNS 查询的识别（数据外带与 C2 的隐蔽通道）",
        "event_types": ["dns_query", "dns_anomaly"],
        "tools": ["dns_resolve", "url_decode"],
        "priority": 12,
        "sop": (
            "事件背景：攻击者利用 DNS 协议隐蔽传输数据或回连 C2，特征是异常长/高熵域名、高频查询、异常 qtype。\n"
            "判断要点：\n"
            "1) 关注异常长域名、随机高熵子域、单一域名高频重复查询。\n"
            "2) 检查 TXT 记录回传、超长 label、罕见 qtype 组合。\n"
            "3) 解析域名看是否指向可疑/未注册/新注册域。\n"
            "取证步骤：提取查询域名、统计查询频率与子域熵值、解析域名的归属。\n"
            "常见误报：CDN 长域名、广告/分析域名、正常 DNS 轮询。\n"
            "处置建议：封锁隧道域名、审计内网 DNS 出口、排查发起隧道的主机。"
        ),
    },
    {
        "name": "凭证盗用分析",
        "description": "账号异常登录与凭证盗用（结合账号会话画像）的识别",
        "event_types": ["http_login", "brute_force"],
        "tools": ["ioc_extract", "geoip_lookup"],
        "priority": 10,
        "sop": (
            "事件背景：账号被窃取后异地/异常登录，特征是账号出现在新 IP、新 UA、非常用时段或会话跳变。\n"
            "判断要点：\n"
            "1) 结合账号会话画像：账号是否在新源 IP / 新 UA / 非常用时段出现。\n"
            "2) 关注单个账号短时间多 IP、单 IP 短时间多账号（撞库）。\n"
            "3) 提取源 IP 做 GeoIP，异地登录可疑度显著上升。\n"
            "取证步骤：提取账号与源 IP、对照历史画像基线、核对登录时间分布。\n"
            "常见误报：VPN/代理接入、用户出差、移动网络切换。\n"
            "处置建议：强制改密与 MFA、吊销异常会话、排查该账号已访问的敏感资源。"
        ),
    },
]
