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
    # 实时链路：该事件代表一个聚合摘要时的规模信息（次数/目标集/端口集/时间跨度）
    aggregate: dict[str, Any] = Field(default_factory=dict)
    # 被排除过滤命中：仍进事件组（可查、可回溯），但跳过全部模型调用与报告生成
    excluded: bool = False
    exclude_reason: str = ""


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
    # 汇总后的聚合规模（实时链路）：命中次数/目标数/端口数/首末时间
    aggregate: dict[str, Any] = Field(default_factory=dict)
    # 整组都是被排除的事件（独立成组，不跑模型与报告）
    excluded: bool = False
    # 排除/跳过的原因（排除过滤器命中，或误报治理判定为“内网常规流量”）
    exclude_reason: str = ""
    # 内外网方向（in→in / in→out / out→in / out→out / unknown）：定级约束与界面展示用
    direction: str = ""
    # 定级被约束的原因（如“内网方向封顶”），便于界面解释“为什么只有 medium”
    severity_cap_reason: str = ""


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
