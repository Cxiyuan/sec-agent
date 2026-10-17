"""契约 schema：统一日志结构（与 agent 侧保持一致）。"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]


class UnifiedLog(BaseModel):
    """Zeek / 签名引擎原始日志规范化后的统一结构。"""

    source_system: str  # "zeek" | "suricata"
    ts: datetime
    event_type: str  # 归一化事件类型：port_scan / brute_force / dns_query / ...
    log_type: str = (
        ""  # Zeek 日志类型：conn/dns/http/ssl/files/dhcp/x509/weird/notice…；签名引擎为 suricata
    )
    # 类型是否在采集白名单内（config 的 zeek_event/ops 清单）：名单外的流保留原名，
    # 只入库、不进检测/画像，靠 log_type.keyword 聚合巡检发现新流
    log_type_known: bool = True
    # 采集来源文件名（Filebeat 的 log.file.path 末段）：排查“这个字段是哪条流来的”
    source_file: str = ""
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    # 真实客户端 IP：代理头（X-Forwarded-For / Forwarded / Client-IP…）里的最左地址。
    # 只有 HTTP 日志且带了代理头才有值，其余为 NULL（不覆盖 src_ip＝TCP 对端）。
    real_client_ip: str | None = None
    # Zeek 连接状态（S0/REJ/SF…）：用于判定“是否真的建立了会话”（探活/扫描 vs 实际连接）
    conn_state: str = ""
    # Zeek weird.log 的异常名（如 possible_split_routing / bad_HTTP_request）。「协议异常」与
    # 「采集类异常」的区分完全靠它：采集类（镜像口丢包/非对称路由/网卡 offload 造成的协议怪象）
    # 由归一化标成 event_type=capture_anomaly，不再进「协议异常」规则，改由状态页的
    # 「采集质量」灯统计（见 normalizer._capture_weird）。
    weird_name: str = ""
    # Zeek 连接 UID：可把 http/ssl/dns/files 与**同一条** conn 对上（中继的前后跳是两条独立
    uid: str = ""
    # 签名引擎（Suricata）命中信息：只有 source_system="suricata" 的告警事件有值。
    # 「签名命中」三条内置规则按 signature_severity 分档（1=高 / 2=中 / 3=低，取自 EVE 的
    # alert.severity —— 那是 Suricata 自己的语义，与我们 Severity 不是一套）。
    signature: str = ""  # 签名名（EVE alert.signature）
    signature_id: str = ""  # SID（EVE alert.signature_id），可回查规则集
    signature_severity: int | None = None  # 1/2/3
    signature_category: str = ""  # 签名类别（EVE alert.category），研判提示
    # Community ID（社区流标识）：Zeek 的 conn.log 与 Suricata 的 alert 都会带，是**跨采集器**
    # 关联同一条流的键（比五元组稳：不受 NAT 与端口复用影响，加密流量也能对上）。
    community_id: str = ""
    # 中继链路位置（只读中继清单，见 ingestion/relay_nodes.py）：
    #   direct=不涉及中继；front=目的在中继清单（客户端→中继）；back=来源在中继清单
    #   （中继→真实目的）；relay_internal=两端都是中继（级联）。检测/画像/资产不处理 back 与
    #   relay_internal —— 它们与 front 是同一次业务访问的另一跳。
    hop: str = "direct"
    hostname: str | None = None
    user: str | None = None
    process: str | None = None
    command: str | None = None
    # 应用层字段（供规则做内容检测）
    query: str = ""  # DNS 查询名 / HTTP URI（完整）
    uri_path: str = ""  # HTTP 路径（去参数）
    query_string: str = ""  # HTTP 参数部分
    method: str = ""  # HTTP 方法
    body: str = ""  # 请求体（自动适配字段名 + 截断）
    resp_body: str = ""  # 响应体（自动适配字段名 + 截断）
    resp_body_len: int | None = None  # 整条响应体字节数（Zeek response_body_len，不受截断影响）
    # 请求/响应头全量文本（"头名: 值\n" 逐行）：Zeek 侧单头截 256 字节、同向总量 4KB 封顶
    req_headers: str = ""
    resp_headers: str = ""
    referer: str = ""
    cookie: str = (
        ""  # 截断；请求头值按既定口径原样保留（已接受的风险，见 docs/ndr-collect-plan.md）
    )
    # 会话 id：按 `ST_SESSION_COOKIE_NAMES` 从**未截断**的 Cookie 头里精确取名、取第一个非空值
    # （见 ingestion/session_cookie.py）。「会话跨IP复用」用它当键 —— 用整条 Cookie 头当键会把
    # 跨用户恒定的 cookie（`Path=/` 这类应用造的常量、空值模板）也算成同一会话，critical 级误报。
    session_id: str = ""
    auth_scheme: str = ""  # basic / bearer / jwt（只留方案名，凭证本体不在此字段）
    content_type: str = ""
    user_agent: str = ""
    status_code: int | None = None
    resp_mime: str = ""
    bytes_out: int | None = None  # 源→目的字节数（数据外传）
    bytes_in: int | None = None  # 目的→源字节数（数据窃取）

    # 账号来源（provenance）：proxy_auth=代理认证用户名（如 t14919610950627 这类终端 ID）
    # / http_form=登录表单或查询参数 / log_field=日志自带的 user 字段。
    # 界面据此标注，避免把代理认证的终端 ID 当成业务账号。
    account_source: str = ""

    # stats.log（Zeek 每 5 分钟上报一次）：套接字/内核丢包计数
    # → 「近期流量」图的掉包折线（值是**上报那一刻的原值**，本系统不做累积换算）
    pkts_dropped: int | None = None
    pkts_proc: int | None = None
    # TLS 指纹与证书（工具识别 / 弱 TLS）
    ja3: str = ""
    ja3s: str = ""
    # JA4 TLS 客户端指纹（BSD 子集的 ja4-zeek-scripts 产出）。
    # JA4S/JA4H/JA4L/JA4T/JA4SSH/JA4D 属 FoxIO License 1.1（非商业），本项目未收录 → 恒空。
    ja4: str = ""
    tls_version: str = ""
    cert_issuer: str = ""
    # 自签判定（normalizer 由 x509 的 certificate.issuer/subject 算出）：
    # 引擎没有「字段对字段」比较，自签只能在归一化层算好——否则规则无法表达。
    cert_self_signed: bool | None = None
    # TLS 握手是否真的建立（Zeek ssl.log 的 `established`）：「TLS 握手失败风暴」的判据。
    # 只在这种日志上有值，其余为 NULL。
    tls_established: bool | None = None
    # DNS / 文件
    qtype: str = ""
    filename: str = ""
    mime_type: str = ""
    # 文件（Zeek files.log）：哈希由 Zeek 的 FileHash 分析器算好落日志，这里原样搬运
    fuid: str = ""  # Zeek 文件 id，可与 http/dns/smtp 等日志里的 fuids 对上
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    file_source: str = ""  # 文件来源协议：HTTP / FTP / SMTP / SSL…
    file_is_orig: bool | None = None  # 方向：True=客户端上传，False=服务端下发
    # 明文文件提取（Zeek site/shentong-file-extract.zeek，批 4）：
    # extracted 是提取件落在 Zeek 容器 /extract 里的文件名（当前 = fuid），
    # extracted_size 是实际落盘字节数（被单文件上限截断时 < total_bytes），
    # extracted_cutoff=True 表示被上限截断（只留了前 N 字节）。
    extracted: str = ""
    extracted_size: int | None = None
    extracted_cutoff: bool | None = None
    # 账号（画像主键：user 字段优先，缺失时从请求体提取）
    account: str = ""
    severity: Severity = "info"
    summary: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)

    def fingerprint(self) -> str:
        """窗口指纹：时间窗口 + 关键字段，用于去重。"""
        key = (
            f"{self.source_system}|{self.event_type}|{self.src_ip}|{self.dst_ip}"
            f"|{self.src_port}|{self.dst_port}|{self.protocol}"
        )
        return hashlib.sha256(key.encode()).hexdigest()[:32]
