"""PostgreSQL ORM 模型。"""

from __future__ import annotations

import uuid
from datetime import datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.config import settings
from app.db.base import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(32), default="admin")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    conditions: Mapped[dict] = mapped_column(JSON, default=dict)  # {logic, rules:[...]}
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    source: Mapped[str] = mapped_column(String(16), default="user")  # user | builtin
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)  # 越小越先
    # 内置规则在播种时按条件自动判定（见 rules/builtin.py::rule_scope），自定义规则由界面选择。
    scope: Mapped[str] = mapped_column(String(16), default="network")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class EventGroup(Base):
    __tablename__ = "event_groups"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    src_ips: Mapped[list] = mapped_column(JSON, default=list)
    dst_ips: Mapped[list] = mapped_column(JSON, default=list)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    triage_score: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(32), default="analyzed", index=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    thread_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    business_context: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    lookback: Mapped[dict | None] = mapped_column(JSONB, nullable=True)  # 回溯决策与历史行为摘要
    memory_hits: Mapped[dict | None] = mapped_column(JSONB, nullable=True)  # 召回的历史记忆摘要
    profile_hits: Mapped[dict | None] = mapped_column(JSONB, nullable=True)  # 账号/会话画像异常
    skill_hits: Mapped[dict | None] = mapped_column(JSONB, nullable=True)  # 命中的技能与工具结果
    aggregate: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )  # 聚合规模（实时链路：次数/目标集/端口集/首末时间）
    attack_chain: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # 误报治理：内外网方向（in→in / in→out / out→in / out→out / unknown）
    direction: Mapped[str] = mapped_column(String(16), default="")
    # 跳过原因（排除过滤器命中，或策略判定为「内网常规流量」）——必须可查，不静默
    exclude_reason: Mapped[str] = mapped_column(Text, default="")
    # 定级被约束的原因（如「内网方向封顶」）
    severity_cap_reason: Mapped[str] = mapped_column(Text, default="")
    # 所属攻击者案件（指针）：案件叙事不再覆盖本组的攻击链，只留指针 + 副本
    case_id: Mapped[str] = mapped_column(String(64), default="")
    # 案件视角副本（summary/path/rounds/superseded）——组详情可折叠查看，可追溯
    case_context: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    profile: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    anomaly: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    response_suggestions: Mapped[list | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    events: Mapped[list[Event]] = relationship(back_populates="group", cascade="all, delete-orphan")


class Event(Base):
    __tablename__ = "events"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    group_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("event_groups.id", ondelete="CASCADE"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    source_system: Mapped[str] = mapped_column(String(16))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    hit_rule: Mapped[str | None] = mapped_column(String(128), nullable=True)
    edge_score: Mapped[float] = mapped_column(Float, default=0.0)
    summary: Mapped[str] = mapped_column(Text, default="")
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    # 被排除过滤命中（仍落库可查，但不参与模型分析与报告）
    excluded: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    group: Mapped[EventGroup] = relationship(back_populates="events")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    group_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("event_groups.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str] = mapped_column(String(256))
    severity: Mapped[str] = mapped_column(String(16))
    html: Mapped[str] = mapped_column(Text, default="")
    pdf_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SystemConfig(Base):
    __tablename__ = "system_config"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Asset(Base):
    """局域网资产：提供 IP 的业务背景，供 RAG 注入分析。"""

    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    ip: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    extra_ips: Mapped[list] = mapped_column(JSONB, default=list)
    hostname: Mapped[str] = mapped_column(String(128), default="")
    asset_name: Mapped[str] = mapped_column(String(128), default="")
    business_system: Mapped[str] = mapped_column(String(128), default="", index=True)
    owner: Mapped[str] = mapped_column(String(64), default="")
    importance: Mapped[str] = mapped_column(
        String(16), default="medium"
    )  # critical/high/medium/low
    asset_type: Mapped[str] = mapped_column(String(64), default="")
    network_zone: Mapped[str] = mapped_column(String(64), default="")
    os: Mapped[str] = mapped_column(String(64), default="")
    services: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    location: Mapped[str] = mapped_column(String(128), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    is_external: Mapped[bool] = mapped_column(
        Boolean, default=False
    )  # 外部资产（非局域网，需显式开启）
    allow_ip_share: Mapped[bool] = mapped_column(
        Boolean, default=False
    )  # 允许该资产 IP 被多个资产共享
    embedding_status: Mapped[str] = mapped_column(
        String(16), default="pending"
    )  # pending/indexed/failed
    embedded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Document(Base):
    """知识文档（全局知识，不绑定具体 IP）。"""

    __tablename__ = "documents"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    title: Mapped[str] = mapped_column(String(256), default="")
    filename: Mapped[str] = mapped_column(String(256), default="")
    mime_type: Mapped[str] = mapped_column(String(128), default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    content: Mapped[str] = mapped_column(Text, default="")
    content_hash: Mapped[str] = mapped_column(String(64), default="", index=True)  # SHA-256 去重
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending/indexed/failed
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class KnowledgeChunk(Base):
    """统一向量库：资产描述与文档切片统一入库，一次向量检索覆盖两者。"""

    __tablename__ = "knowledge_chunks"
    __table_args__ = (
        Index(
            "ix_knowledge_chunks_embedding_hnsw",
            "embedding",
            postgresql_using="hnsw",
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
    )

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    source_type: Mapped[str] = mapped_column(String(16), index=True)  # asset | document | topology
    source_id: Mapped[str] = mapped_column(String(64), index=True)
    chunk_index: Mapped[int] = mapped_column(Integer, default=0)
    content: Mapped[str] = mapped_column(Text, default="")
    embedding: Mapped[list] = mapped_column(Vector(settings.embedding_dim))
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Topology(Base):
    """网络拓扑图（多张）：graph 存 React Flow 原生结构 {nodes, edges}。"""

    __tablename__ = "topologies"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    graph: Mapped[dict] = mapped_column(JSONB, default=dict)
    node_count: Mapped[int] = mapped_column(Integer, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending/indexed/failed
    indexed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class TopologyNodeType(Base):
    """拓扑节点类型（内置 + 自定义），icon 为 lucide 图标名。"""

    __tablename__ = "topology_node_types"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), default="")
    icon: Mapped[str] = mapped_column(String(64), default="Box")
    color: Mapped[str] = mapped_column(String(16), default="#64748b")
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    sort: Mapped[int] = mapped_column(Integer, default=100)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Skill(Base):
    """安全事件分析技能：SOP（分析流程/方法）+ 关联脚本工具，按事件类型路由。"""

    __tablename__ = "skills"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    sop: Mapped[str] = mapped_column(Text, default="")  # 分析 SOP 正文（注入提示词）
    event_types: Mapped[list] = mapped_column(JSONB, default=list)  # 路由用的事件类型
    tools: Mapped[list] = mapped_column(JSONB, default=list)  # 关联工具名
    source: Mapped[str] = mapped_column(String(16), default="user")  # builtin | user
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)  # 越小越先
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ExclusionFilter(Base):
    """用户自定义排除过滤：命中则事件仍落库，但跳过全部模型调用与报告生成。

    条件语法复用规则引擎（conditions 结构与规则一致），另支持命中规则的元数据字段
    （hit_rule / rule_source / rule_severity）。
    """

    __tablename__ = "exclusion_filters"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    conditions: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)  # 越小越先
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AnalysisMemory(Base):
    """分析记忆（两级）：kind=group 对象级 / kind=run 轮次级，用于历史比对与持续性统计。"""

    __tablename__ = "analysis_memories"
    __table_args__ = (
        Index("ix_analysis_memories_kind_fp", "kind", "fingerprint"),
        Index("ix_analysis_memories_ips", "ips", postgresql_using="gin"),
    )

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    kind: Mapped[str] = mapped_column(String(16), index=True)  # group | run
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ips: Mapped[list] = mapped_column(JSONB, default=list)
    asset_ids: Mapped[list] = mapped_column(JSONB, default=list)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class AttackerCase(Base):
    """攻击者案件：把跨时间桶的多个事件组归到同一攻击者的调查单元。

    为什么需要它：事件组指纹是「IP 集合 + 30 分钟桶」，同一攻击者跨时段的活动会
    分裂成多个组；只有把组聚合到案件，才能还原「完整路径」而不是碎片。
    """

    __tablename__ = "attacker_cases"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    # 主显示键（优先级：外部源 IP > 账号 > 域名 > hash > 内网源 IP）
    attacker_key: Mapped[str] = mapped_column(String(256), index=True)
    title: Mapped[str] = mapped_column(String(256), default="")
    # {ips, hosts, accounts, domains, hashes}：任一键命中即归并（多键并集）
    keys: Mapped[dict] = mapped_column(JSONB, default=dict)
    status: Mapped[str] = mapped_column(String(24), default="open", index=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    src_ips: Mapped[list] = mapped_column(JSONB, default=list)
    dst_ips: Mapped[list] = mapped_column(JSONB, default=list)
    group_fingerprints: Mapped[list] = mapped_column(JSONB, default=list)
    event_types: Mapped[list] = mapped_column(JSONB, default=list)
    group_count: Mapped[int] = mapped_column(Integer, default=0)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # 最新一轮调查结果（超集结构；逐轮完整留档见 CaseInvestigation）
    investigation: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # 冷却期内累积的新证据信号（新阶段/新 IOC/严重度上升）
    pending_signal: Mapped[dict] = mapped_column(JSONB, default=dict)
    # 归并依据（真正促成归并的键）+ 自动拆分原因 + 被哪个重建批次取代
    merge_basis: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    split_reason: Mapped[str] = mapped_column(Text, default="")
    superseded_by: Mapped[str] = mapped_column(String(64), default="")
    rounds_total: Mapped[int] = mapped_column(Integer, default=0)
    rounds_today: Mapped[int] = mapped_column(Integer, default=0)
    rounds_day: Mapped[str] = mapped_column(String(10), default="")  # 跨天重置用（YYYY-MM-DD）
    last_dispatched_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_allowed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")
    # 桥接情形（新组同时命中两个案件）时提示人工合并
    merge_suggestion: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class RebuildRun(Base):
    """存量重建批次：审计 + 回滚依据（一批次一次重建，可 dry-run）。"""

    __tablename__ = "rebuild_runs"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(24), default="running")
    counts: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    mapping: Mapped[dict | None] = mapped_column(JSONB, nullable=True)  # 旧案件 → 新建案件 id
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CaseInvestigation(Base):
    """案件调查轮次（每轮一行）：取证留档，含查询轨迹与预算消耗。"""

    __tablename__ = "case_investigations"
    __table_args__ = (Index("ix_case_investigations_case_round", "case_id", "round"),)

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    case_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("attacker_cases.id", ondelete="CASCADE"), index=True
    )
    round: Mapped[int] = mapped_column(Integer, default=1)
    kind: Mapped[str] = mapped_column(String(16), default="auto")  # auto|manual|followup
    instruction: Mapped[str] = mapped_column(Text, default="")  # 人工指令（追问）
    status: Mapped[str] = mapped_column(String(24), default="running", index=True)
    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    query_trail: Mapped[list] = mapped_column(JSONB, default=list)
    budget: Mapped[dict] = mapped_column(JSONB, default=dict)
    steps: Mapped[int] = mapped_column(Integer, default=0)
    llm_calls: Mapped[int] = mapped_column(Integer, default=0)
    tokens: Mapped[int] = mapped_column(Integer, default=0)
    elapsed_ms: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CaseReport(Base):
    """案件取证报告（与组级 reports 分开：案件不绑定单个事件组）。"""

    __tablename__ = "case_reports"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    case_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("attacker_cases.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str] = mapped_column(String(256), default="")
    severity: Mapped[str] = mapped_column(String(16), default="info")
    html: Mapped[str] = mapped_column(Text, default="")
    pdf_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
