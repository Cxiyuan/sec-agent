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
        ""  # Zeek 日志类型：conn/dns/http/ssl/files/smtp/ssh/dhcp/notice；Wazuh 为 wazuh
    )
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
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
    referer: str = ""
    cookie: str = ""  # 截断；会话 id 只做哈希后入库
    auth_scheme: str = ""  # basic / bearer / jwt（不落库明文凭证）
    content_type: str = ""
    user_agent: str = ""
    status_code: int | None = None
    resp_mime: str = ""
    bytes_out: int | None = None  # 源→目的字节数（数据外传）
    bytes_in: int | None = None  # 目的→源字节数（数据窃取）
    # TLS 指纹与证书（工具识别 / 弱 TLS）
    ja3: str = ""
    ja3s: str = ""
    tls_version: str = ""
    cert_issuer: str = ""
    # DNS / 文件
    qtype: str = ""
    filename: str = ""
    mime_type: str = ""
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
