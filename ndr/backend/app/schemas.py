"""契约 schema：统一日志结构（与 agent 侧保持一致）。"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]


class UnifiedLog(BaseModel):
    """Zeek / Wazuh 原始日志规范化后的统一结构。"""

    source_system: str  # "zeek" | "wazuh"
    ts: datetime
    event_type: str  # 归一化事件类型：port_scan / brute_force / dns_query / ...
    log_type: str = (
        ""  # Zeek 日志类型：conn/dns/http/ssl/files/dhcp/x509/weird/notice…；Wazuh 为 wazuh
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
    cookie: str = ""  # 截断；请求头值按既定口径原样保留（已接受的风险，见 docs/ndr-collect-plan.md）
    auth_scheme: str = ""  # basic / bearer / jwt（只留方案名，凭证本体不在此字段）
    content_type: str = ""
    user_agent: str = ""
    status_code: int | None = None
    resp_mime: str = ""
    bytes_out: int | None = None  # 源→目的字节数（数据外传）
    bytes_in: int | None = None  # 目的→源字节数（数据窃取）
    # TLS 指纹与证书（工具识别 / 弱 TLS）
    ja3: str = ""
    ja3s: str = ""
    # JA4 TLS 客户端指纹（BSD 子集的 ja4-zeek-scripts 产出）。
    # JA4S/JA4H/JA4L/JA4T/JA4SSH/JA4D 属 FoxIO License 1.1（非商业），本项目未收录 → 恒空。
    ja4: str = ""
    tls_version: str = ""
    cert_issuer: str = ""
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
    # Wazuh 规则语义（保留原始规则信息，避免被压成通用类型）
    rule_id: str = ""
    rule_groups: str = ""  # 逗号连接
    mitre: str = ""  # 逗号连接（MITRE 技术号/战术）
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
