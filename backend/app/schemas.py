"""统一日志 schema 与 LangGraph 状态定义。"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
GroupStatus = Literal[
    "pending_confirmation", "analyzing", "analyzed", "confirmed", "dismissed", "report_generated"
]


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


class SuspiciousEvent(BaseModel):
    """降噪后留下的可疑事件。"""

    log: UnifiedLog
    hit_rule: str | None = None  # 命中的规则名
    rule_source: Literal["user", "builtin"] | None = None
    edge_score: float = 0.0  # 边缘模型打分（0~1）
    edge_reason: str = ""
    is_suspicious: bool = True


class EventGroup(BaseModel):
    """多源关联后的事件组（一次潜在攻击场景）。"""

    fingerprint: str
    src_ips: list[str] = Field(default_factory=list)
    dst_ips: list[str] = Field(default_factory=list)
    window_start: datetime
    window_end: datetime
    events: list[SuspiciousEvent] = Field(default_factory=list)
    triage_score: float = 0.0
    escalate: bool = False
    severity: Severity | None = None
    business_context: dict[str, Any] | None = None


class AttackStage(BaseModel):
    stage: str  # 侦察 / 入侵 / 横向 / 外泄
    description: str
    evidence: list[dict[str, Any]] = Field(default_factory=list)  # 挂载的日志证据


class AttackChain(BaseModel):
    stages: list[AttackStage] = Field(default_factory=list)
    confidence: float = 0.0
    summary: str = ""


class AttackerProfile(BaseModel):
    basic: dict[str, Any] = Field(default_factory=dict)
    behavior: dict[str, Any] = Field(default_factory=dict)


class AnomalyFindings(BaseModel):
    findings: list[dict[str, Any]] = Field(default_factory=list)


class ResponseSuggestion(BaseModel):
    category: Literal["block", "remediation", "incident_response"]
    action: str
    detail: str


class AgentState(BaseModel):
    """LangGraph 图状态。"""

    window_start: datetime | None = None
    window_end: datetime | None = None
    raw_logs: list[UnifiedLog] = Field(default_factory=list)
    suspicious_events: list[SuspiciousEvent] = Field(default_factory=list)
    groups: list[EventGroup] = Field(default_factory=list)
    # 深度分析结果（按组指纹存储）
    analyses: dict[str, dict[str, Any]] = Field(default_factory=dict)
    # 人工确认结果
    confirmations: dict[str, Literal["confirm", "dismiss"]] = Field(default_factory=dict)
    run_summary: dict[str, Any] = Field(default_factory=dict)
