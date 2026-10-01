"""PostgreSQL ORM 模型（NDR 侧：检测/规则/网段/排除/去重闸门）。"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

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


class SystemConfig(Base):
    __tablename__ = "system_config"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
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


class IngestFilter(Base):
    """入库前的降噪过滤：命中则**不投检测器**，但事件照常进 Elasticsearch。

    与排除过滤（`ExclusionFilter`）的区别在**作用点**：排除过滤在规则命中之后，决定
    「要不要跑模型」；这一张在归一化之后、规则之前，决定「要不要进检测器」——挡的是
    海量已知噪声（内网扫描器、监控探活、心跳域名），省下的是检测器之后的整条链路，
    而 ES 仍是全量事实源（命中事件在界面上照样查得到，只是不会形成告警）。

    条件作用域只有日志自身字段（此时还没有规则元数据），字段白名单见
    `app.ingestion.ingest_filter.allowed_fields()`。
    """

    __tablename__ = "ingest_filters"

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


class McpToken(Base):
    """智能体访问 MCP 服务的令牌。

    只存**哈希**：明文仅在生成时回显一次。这样即使库被读走也拿不到可用令牌；代价是
    忘了就只能吊销重建（所以额外存了 `prefix` 供界面辨认是哪一个）。

    吊销 = `enabled=False`，不删行——调用记录还要能追溯到它。
    """

    __tablename__ = "mcp_tokens"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), default="")
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    prefix: Mapped[str] = mapped_column(String(24), default="")  # 明文前 8 位，便于辨认
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    call_count: Mapped[int] = mapped_column(Integer, default=0)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ConclusionRecord(Base):
    """智能体通过 MCP 写回的调查结论（界面上看的镜像）。

    **不参与判重**：判重的权威在智能体侧（按指纹查 `EventGroup`）。这里只是一份审计与
    展示用的副本，所以允许被后一次写回覆盖（`dedup_key` 唯一）。
    保留期与判重窗口对齐（默认 7 天），过期行在列表接口里顺手清掉，不另起定时任务。
    """

    __tablename__ = "conclusion_records"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    # 事件ID 优先，没有就给指纹；它同时是「同一条事件只留一份结论」的幂等键
    dedup_key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    event_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), default="", index=True)
    thread_id: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(32), default="")  # 结论状态（真阳性/误报/待定…）
    severity: Mapped[str] = mapped_column(String(16), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class BaselineStat(Base):
    """滚动基线统计（Welford 在线算法）：key 标识统计维度，如 `{src_ip}:conn_count`。

    第 8 期从智能体侧迁来：基线是纯统计、不需要模型，而检测器本来就逐条看到归一化事件，
    放在数据产生侧算、算完随摘要打标给智能体，就不用智能体再自己学一遍。
    """

    __tablename__ = "baseline_stats"

    key: Mapped[str] = mapped_column(String(256), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0)
    mean: Mapped[float] = mapped_column(Float, default=0.0)
    m2: Mapped[float] = mapped_column(Float, default=0.0)  # 平方差累计，用于算标准差
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
