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
    # 内置规则在播种时按条件自动判定（见 rules/builtin.py::rule_scope），自定义规则由界面选择；
    scope: Mapped[str] = mapped_column(String(16), default="network")
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

    `expires_at` 为空 = **永不过期**（既有令牌语义不变）；到期判定在
    `app/mcp/auth.py` 的 `verify()`（D 组），轮换与改到期时间在 `app/api/routes/mcp.py`。
    老库靠 `main.py` 的 `_MIGRATIONS` 补列（`ADD COLUMN IF NOT EXISTS`）。
    """

    __tablename__ = "mcp_tokens"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), default="")
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    prefix: Mapped[str] = mapped_column(String(24), default="")  # 明文前 8 位，便于辨认
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    call_count: Mapped[int] = mapped_column(Integer, default=0)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
    # first_seen / updated_at 都建索引：前者是「观测期是否已过」（快照里的预热计数）的过滤列，
    # 后者是保留期清理的过滤列 —— 两者以前都是全表扫描（2026-10 实机 QA：snapshot 每次轮询
    # 两条 COUNT(*)，seq_scan 已经跑到 1660）。
    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), index=True
    )


class AssetStat(Base):
    """被访问方（内网源站 / 内网 DNS）的行为基线：与 `baseline_stats` 同结构的 Welford 统计。

    为什么要单独一张表（没复用 `baseline_stats` 加前缀）：现有列表按「key 里最后一个冒号前…」
    推 IP 做分组，`asset:host:feature` 这类键会被解析成奇怪的 IP；单表互不干扰。
    key = `{资产标识}:{特征}`，资产标识优先 hostname（HTTP Host / SSL SNI），无则 `IP:端口`；
    特征：visits（**连接数**，一条 Zeek `uid` = 一次访问）/ requests（http/dns 请求数）/
    distinct_clients / distinct_client_ports / distinct_targets
    （HTTP 是不同 URI 数、DNS 是不同域名数）。
    """

    __tablename__ = "asset_stats"

    key: Mapped[str] = mapped_column(String(256), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0)
    mean: Mapped[float] = mapped_column(Float, default=0.0)
    m2: Mapped[float] = mapped_column(Float, default=0.0)
    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    #: 资产归属：internal（监控网段/内网 —— 我们自己的源站、DNS 转发器）/ external（公网目标，
    #: 含公共 DNS 解析器）。**异常判定只对 internal 判**（外部站点行为不由我们控制）。
    #: 口径 C（2026-10）：两块都保留，界面分组展示。
    scope: Mapped[str] = mapped_column(String(16), default="", index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), index=True
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
    #: 服务端 IP（被访问的监控资产）。为什么要单独记：界面展示的是「账号 + 关联服务端 IP」
    #: （会话展示名是 cookie 哈希，运维看不懂），原来只记了客户端源 IP。
    dst_ips: Mapped[dict] = mapped_column(JSONB, default=dict)
    user_agents: Mapped[dict] = mapped_column(JSONB, default=dict)
    paths: Mapped[dict] = mapped_column(JSONB, default=dict)
    hour_hist: Mapped[dict] = mapped_column(JSONB, default=dict)
    success_count: Mapped[int] = mapped_column(Integer, default=0)
    fail_count: Mapped[int] = mapped_column(Integer, default=0)
    #: 错误响应计数（status ≥ 400 且不是 401/403）。为什么要单独记：
    #: 成功只算 <400、失败只认 401/403，于是 404 风暴这类「探测/扫描」痕迹在画像里完全隐形
    #: （实测某账号 63,243 条 404，画像既不算成功也不算失败）。
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    #: 该画像被观测到**多少个窗口**（不是事件条数）。冷启动门槛按窗口算：
    #: 原来按事件条数（5 条日志）就放行，新实体刚出现就开始判异常，早期误报多。
    window_count: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    #: 似然比后验概率（0~1，见 `baseline/profile.py::posterior_of`）。为什么要单独一列：
    #: `risk_score` 是层级加和分，只要有强信号就顶到 1.0（实测 1,833 个过线会话里 TOP 全是 1.0），
    #: 排序等于没有优先级；后验概率保留大小差异，界面/MCP 排序用它。判据也随之切换
    #: （`profile.scoring=llr` 时看过后验阈值），见 `top_anomalies`。
    posterior: Mapped[float] = mapped_column(Float, default=0.0)
    #: 风险分/异常理由的**判定时间**（= 本轮落库时间）。为什么要单独一列：`updated_at`
    #: 每轮观测都会刷新，拿它当「风险时间」会让几小时前的陈旧风险看着像刚刚算出来的
    #: （2026-10 实机 QA 发现的问题）。本轮无异常时 risk_score 归零、本列置空。
    risk_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    anomalies: Mapped[list] = mapped_column(JSONB, default=list)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class HitEvent(Base):
    """命中事件：检测器交付侧的一次规则命中 —— **系统内唯一事件 ID 的载体**。

    为什么必须落 PG（2026-10 用户要求）：命中原来只活在 Redis 的「最近命中」流水里
    （重启即丢、没有稳定标识），而事件需要被长期引用与关联分析：忽略、加白名单、
    把 ID 交给智能体/人工追溯，都要求一个稳定唯一的 ID。所以每条命中在**摘要定型时**
    写一行，主键（UUID）就是那个 ID。

    `evidence` 存的是样例事件的**关键字段**（不是整份原始文档）：够界面展示与判断，
    又不把 PG 撑爆；完整原始文档仍在 ES（`uid` 可回查）。
    """

    __tablename__ = "hit_events"
    __table_args__ = (
        Index("ix_hit_events_created", "created_at"),
        Index("ix_hit_events_rule", "rule"),
        Index("ix_hit_events_ignored", "ignored"),
    )

    #: **系统唯一事件 ID**（关联分析的锚点）
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rule: Mapped[str] = mapped_column(String(200), default="")
    rule_severity: Mapped[str] = mapped_column(String(16), default="medium")
    rule_source: Mapped[str] = mapped_column(String(32), default="builtin")
    #: 事件来源类别（**不体现采集器名字**）：
    #: feature_match=特征匹配（签名引擎）/ behavior_analysis=行为分析（流量规则）/
    #: baseline_deviation=基线偏离（画像/数值基线）
    source_kind: Mapped[str] = mapped_column(String(24), default="behavior_analysis", index=True)
    #: 直连对端；中继链路上它是代理/WAF，真实请求方在 real_client_ips
    src_ip: Mapped[str] = mapped_column(String(64), default="")
    client: Mapped[str] = mapped_column(String(64), default="")
    client_source: Mapped[str] = mapped_column(String(16), default="")
    via: Mapped[str] = mapped_column(String(64), default="")
    proxied: Mapped[bool] = mapped_column(Boolean, default=False)
    count: Mapped[int] = mapped_column(Integer, default=0)
    #: 目的 **IP:端口 成对**列表（分开存 ips/ports 会让人看不出谁配谁）
    dst_pairs: Mapped[list] = mapped_column(JSONB, default=list)
    dst_ips: Mapped[list] = mapped_column(JSONB, default=list)
    dst_ports: Mapped[list] = mapped_column(JSONB, default=list)
    event_types: Mapped[list] = mapped_column(JSONB, default=list)
    conn_states: Mapped[list] = mapped_column(JSONB, default=list)
    log_types: Mapped[list] = mapped_column(JSONB, default=list)
    real_client_ips: Mapped[list] = mapped_column(JSONB, default=list)
    #: 样例事件的关键字段（时间/类型/URI/UA/状态码/账号…）
    evidence: Mapped[list] = mapped_column(JSONB, default=list)
    #: 已忽略：不再出现在默认列表里（行保留，可追溯、可撤回）
    ignored: Mapped[bool] = mapped_column(Boolean, default=False)
    ignored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ignored_reason: Mapped[str] = mapped_column(Text, default="")
    #: 由本条事件生成的白名单（排除过滤器）ID：留痕，便于「这条为什么不再报」
    whitelist_id: Mapped[str] = mapped_column(String(64), default="")


class AssetGroup(Base):
    """资产分组（资产中心 → 资产分组）：按业务/责任人给资产归类。

    为什么单独一张表（而不是写进 `asset_stats`）：后者是**统计基线**（Welford 均值/方差，
    每窗口滚动更新），台账是**人工维护的事实**（谁负责、重要级别、备注），两者生命周期不同。
    """

    __tablename__ = "asset_groups"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    color: Mapped[str] = mapped_column(String(16), default="")  # 界面上的色标（#1d4ed8 之类）
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AssetRecord(Base):
    """资产台账（资产中心 → 资产管理）：一台被纳管的主机。

    IP 是唯一键（监控网段内的资产以 IP 为准）；主机名/归属/责任人/重要级别/备注由人填，
    发现页看到"未纳管"的主机可以一键入库。**不存流量统计**（那是 asset_stats 的事）。
    """

    __tablename__ = "asset_records"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    ip: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    group_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    owner: Mapped[str] = mapped_column(String(128), default="")
    #: 重要级别：core 核心 / high 重要 / normal 一般 / test 测试
    criticality: Mapped[str] = mapped_column(String(16), default="normal")
    tags: Mapped[str] = mapped_column(String(255), default="")  # 逗号分隔
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
