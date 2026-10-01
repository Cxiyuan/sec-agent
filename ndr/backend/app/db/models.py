"""PostgreSQL ORM 模型（NDR 侧：检测/规则/网段/排除/去重闸门）。"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
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
