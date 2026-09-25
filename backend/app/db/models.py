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


class BaselineStat(Base):
    """滚动基线统计（Welford 在线算法）：key 标识统计维度，如 src_ip:port_scan_count。"""

    __tablename__ = "baseline_stats"

    key: Mapped[str] = mapped_column(String(256), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0)
    mean: Mapped[float] = mapped_column(Float, default=0.0)
    m2: Mapped[float] = mapped_column(Float, default=0.0)  # 平方差累计，用于算标准差
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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


class AnalysisScope(Base):
    """分析网段（多套可启停）：只分析源/目的 IP 落在启用网段内的日志。"""

    __tablename__ = "analysis_scopes"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    cidrs: Mapped[list] = mapped_column(JSONB, default=list)  # 单 IP 或 CIDR 列表
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class EntityProfile(Base):
    """账号 / 会话跨窗口长期画像（UEBA 式统计基线）。

    entity_key：账号名原样；会话 id 为 SHA-256 哈希（**不落库明文 cookie**）。
    """

    __tablename__ = "entity_profiles"
    __table_args__ = (
        Index("ix_entity_profiles_kind_key", "kind", "entity_key", unique=True),
        Index("ix_entity_profiles_risk", "risk_score"),
        Index("ix_entity_profiles_last_seen", "last_seen"),
    )

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    kind: Mapped[str] = mapped_column(String(16), index=True)  # account | session
    entity_key: Mapped[str] = mapped_column(String(128))
    entity_display: Mapped[str] = mapped_column(String(160), default="")
    obs_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # 行为基线（频次分布）
    src_ips: Mapped[dict] = mapped_column(JSONB, default=dict)
    user_agents: Mapped[dict] = mapped_column(JSONB, default=dict)
    paths: Mapped[dict] = mapped_column(JSONB, default=dict)
    hour_hist: Mapped[dict] = mapped_column(JSONB, default=dict)
    success_count: Mapped[int] = mapped_column(Integer, default=0)
    fail_count: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    anomalies: Mapped[list] = mapped_column(JSONB, default=list)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


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


class AnalyzedFingerprint(Base):
    """已投递/已分析的事件指纹（投递前去重闸门）。

    两态：inflight（已投递、图还在跑）→ done（图正常跑完）。
    只有 done、或**未过期**的 inflight 才拦重复投递：否则任务失败的事件会被永久吞掉。
    指纹为**摘要级**（规则|源IP|时间桶）—— 检测器手里只有摘要，算不出事件/组级指纹。
    """

    __tablename__ = "analyzed_fingerprints"

    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    rule: Mapped[str] = mapped_column(String(128), default="")  # 便于排查与界面展示
    src_ip: Mapped[str] = mapped_column(String(64), default="")
    bucket_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="inflight", index=True)  # inflight|done
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    analyzed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    thread_id: Mapped[str | None] = mapped_column(String(64), nullable=True)


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
