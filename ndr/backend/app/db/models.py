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


class AnalysisSuppression(Base):
    """**精准抑制条目**：由智能体判定误报后回写，命中即不再派工、不再推送给智能体。

    为什么要单独一张表（而不是复用 `exclusion_filters`）：
    - 排除过滤是**人工**降噪配置，语义是「事件仍落库、只跳过模型」；
    - 这里是**智能体**给出的、带证据的、**会过期**的抑制，语义是「这类流量我已确认是
      误报，别再叫醒我」，必须单独记录「谁提的、凭哪条证据、什么时候失效、抑制了多少次」，
      否则运维无法复核、也无法一键撤销（这是全自动抑制唯一的兜底手段）。

    匹配口径（用户 2026-10 定）：**源 IP + 目的 IP:端口 + 协议 + payload** 四元精准匹配。
    为避免一条宽条件把整类攻击关掉，落库时强制**至少 2 个维度非空**（`min_match_dims`，
    下限锁 2，界面也不能调低）；payload 走正则，必须能编译且命中白名单。
    """

    __tablename__ = "analysis_suppressions"
    __table_args__ = (
        Index("ix_analysis_suppressions_enabled_expiry", "enabled", "expires_at"),
        Index("ix_analysis_suppressions_hits", "hits"),
    )

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    #: 精准匹配的四元（全部可选，但至少 2 个非空）
    #: 结构化匹配（**复用规则引擎的条件树**：`{logic, rules:[{field,op,value}]}`）。
    #: 为什么不用扁平列：匹配维度会变（端口段/URI 前缀/JA3/签名……），扁平列每加一个
    #: 就要改表 + 改求值；直接用 `evaluate_conditions` 则与排除过滤/规则同一种语法，
    #: 一份引擎、一套校验、一个求值顺序。
    match: Mapped[dict] = mapped_column(JSON, default=dict)

    #: 宽域保护降级用：影响面积过大时不静默，改为「仍生成事件、但不派工不推送」
    mode: Mapped[str] = mapped_column(String(16), default="suppress")  # suppress | record_only
    #: 申请时的**爆炸半径试算结果**（srcs / events / segments / dims），全量留库可审计
    trial: Mapped[dict] = mapped_column(JSON, default=dict)
    #: 提交时的记录来源（`{logic, rules:[{field,op,value}]}`）
    reason_code: Mapped[str] = mapped_column(String(32), default="")
    note: Mapped[str] = mapped_column(String(500), default="")
    #: 证据引用（`es:索引/文档id` / `ev:uuid`）：必须是提交令牌本会话真取回过的
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list)
    #: 取数工具种类数（证据多样性门槛：只看一段正文下结论不算数）
    evidence_tools: Mapped[int] = mapped_column(Integer, default=0)
    #: 智能体自报置信度（低于 `suppression_min_confidence` 不自动生效）
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    #: 是哪次任务给出的判定（无任务的人工抑制留空）
    source_task_id: Mapped[str] = mapped_column(String(64), default="")

    #: 来源：智能体令牌名，或界面操作者用户名
    created_by: Mapped[str] = mapped_column(String(64), default="")
    origin: Mapped[str] = mapped_column(String(16), default="agent")  # agent | ui

    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    hits: Mapped[int] = mapped_column(Integer, default=0)  # 被抑制次数（用户要求可查命中数）
    last_hit_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoke_reason: Mapped[str] = mapped_column(String(200), default="")
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


class AlertDisposition(Base):
    """告警处置标注（误报闭环，2026-10）。

    一行 = 「某实体的某条告警」被运维判成什么：
    - `verdict`: `false_positive`（误报，降权用）或 `confirm`（确认，仅记录）；
    - `signal`: 空 = 整条告警级别；填信号码（如 `new_src_ip`）= 只降权那一路证据。

    为什么要落到 PG 而不是内存：反馈的价值在于**跨重启累积**——将来做在线学习/校准
    都靠它；进程内计数一重启就没了，等于天天从零学。
    """

    __tablename__ = "alert_dispositions"
    __table_args__ = (
        Index("ix_alert_dispositions_entity", "kind", "entity_key"),
        Index("ix_alert_dispositions_created_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    kind: Mapped[str] = mapped_column(String(16), index=True)
    entity_key: Mapped[str] = mapped_column(String(128))
    signal: Mapped[str] = mapped_column(String(48), default="")
    verdict: Mapped[str] = mapped_column(String(16), default="false_positive")
    operator: Mapped[str] = mapped_column(String(64), default="")
    note: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


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
    #: 账号**上一次成功登录**的公网 IP 位置 `{country, province, city, label, ip, at}`。
    #: 只用于"地点变了"的事实（国家+省），局域网登录不写这一列（否则一次内网登录就废掉检测）。
    last_geo: Mapped[dict] = mapped_column(JSONB, default=dict)
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


class AnalysisTask(Base):
    """**客观线索队列**：NDR 只报"变了 / 第一次见 / 很久没看"，不报"这是攻击"。

    为什么要队列而不是推送（2026-10 改造，方案见 `docs/ndr-analysis-mechanism.md`）：
    原来是"规则命中 → 聚合摘要 → HTTP 推给智能体"，智能体退化成规则结果解释器，
    而且所有摘要都推、没有预算，实测 240 事件/秒时根本吃不消。现在改成
    **NDR 派工 + 智能体主动领取**：NDR 写这张表，只在有新线索时按一次"门铃"
    （不含任何数据），智能体按自己的预算 `claim_tasks` 领取并自主决定查什么。

    两条硬约束：
    - `dedupe_key` 唯一：同一现象在同一时间桶只有一条（否则队列会被同一件事刷满）；
    - `hint` 只放客观事实（均值/当前值/p 值/是否首见/涉及对象数/原始日志元数据），
      **不放严重度、不放结论** —— 判断权归智能体（D2）。
    """

    __tablename__ = "analysis_tasks"
    __table_args__ = (
        Index("ix_analysis_tasks_claim", "state", "priority", "created_at"),
        Index("ix_analysis_tasks_subject", "subject_kind", "subject"),
        Index("ix_analysis_tasks_lease", "lease_until"),
    )

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    #: 去重键：`kind|subject_kind:subject|feature|时间桶`
    dedupe_key: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    #: 线索类型：novelty 首见 / shift 自身基线偏离 / structure 结构特征 / coverage 盲区 / hit 规则命中 / hit_cluster 命中簇
    kind: Mapped[str] = mapped_column(String(16), index=True)
    #: 客观强度 0~1（`max(各分量)`，不求和 —— 求和会重演"三个弱信号≈一个强信号"）
    strength: Mapped[float] = mapped_column(Float, default=0.0)
    priority: Mapped[int] = mapped_column(Integer, default=0, index=True)
    subject_kind: Mapped[str] = mapped_column(String(16), default="ip")
    subject: Mapped[str] = mapped_column(String(128), default="")
    #: 建议分析的时间窗（智能体可以不听，但给了就有起点）
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    hint: Mapped[dict] = mapped_column(JSONB, default=dict)
    #: pending / claimed / done / deferred / stuck / expired
    state: Mapped[str] = mapped_column(String(12), default="pending", index=True)
    #: 租约：领取后到期未交回就自动回收（`attempts += 1`），避免任务被卡死的会话占住
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claimed_by: Mapped[str] = mapped_column(String(64), default="")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    #: 同族线索被合并的次数（队列满时不静默丢，改成合并计数）
    coalesced: Mapped[int] = mapped_column(Integer, default=0)
    #: 追问链（智能体可以自己往队列里追加活）
    parent_id: Mapped[str] = mapped_column(String(64), default="")
    depth: Mapped[int] = mapped_column(Integer, default=0)
    #: 结束原因（deferred/expired/stuck 的说明，界面直接显示）
    note: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AnalysisResult(Base):
    """智能体交回的结论（任务级）。与 `ConclusionRecord`（事件级）并存不冲突。

    为什么两张：事件级结论早就是界面"这条事件分析过没有"的数据源，语义不能动；
    任务级结论要带**成本**（`tools_used` / `duration_ms`）与 `verdict`，用来算预算是否合理、
    哪些现象反复被判误报（喂给精准抑制），这两件事事件级表装不下。
    """

    __tablename__ = "analysis_results"
    __table_args__ = (
        Index("ix_analysis_results_task", "task_id"),
        Index("ix_analysis_results_verdict_time", "verdict", "created_at"),
        Index("ix_analysis_results_subject", "subject_kind", "subject"),
        Index("ix_analysis_results_oldest", "digested_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(String(64), default="")
    kind: Mapped[str] = mapped_column(String(16), default="")
    subject_kind: Mapped[str] = mapped_column(String(16), default="")
    subject: Mapped[str] = mapped_column(String(128), default="")
    #: 结论词表见 `analysis/verdicts.py`（与事件结论 status 共用一份实现）
    verdict: Mapped[str] = mapped_column(String(24), default="", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    summary: Mapped[str] = mapped_column(Text, default="")
    findings: Mapped[dict] = mapped_column(JSONB, default=dict)
    evidence_refs: Mapped[list] = mapped_column(JSONB, default=list)
    #: 成本口径（预算调优的依据）：本任务用了多少次工具调用、跑了多久
    tools_used: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    #: **终态原因**：
    #: `concluded`=查清并下了结论 / `budget_exhausted`=预算耗尽 / `tool_error`=取数失败
    #: / `timeout`=会话超时 / `aborted`=被中断。
    #: 为什么要它：只看 verdict 时 `inconclusive` 分不清「没查到」和「超时了」，
    #: 没法评估智能体的活干得对不对（前者说明线索质量差，后者说明预算不够）。
    terminal_reason: Mapped[str] = mapped_column(String(24), default="")
    #: 被冷摘要聚合的时间：非空表示这行的明细已进 `analysis_digests`（**行本身永不删除**，
    #: 只是「概览视图」不再逐条列它，需要明细时用 `prior_findings(detail=true)` 拉回来）。
    digested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claimed_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class ObservedSubject(Base):
    """ "第一次见"与"覆盖率"的地基：NDR 见过的可分析对象登记表。

    为什么要落库而不是每次现算：
    - novelty 判定要长期记忆（Redis 单靠 TTL 会把"半年没见"当成新出现）；
    - 覆盖率是这次改造的验收指标（近 7 天有多少资产被分析过），必须能查；
    - 只增不减的表本项目吃过亏，所以带 `last_seen_at` 并按保留期清理。
    """

    __tablename__ = "observed_subjects"
    __table_args__ = (
        Index("ix_observed_subjects_kind_value", "kind", "value", unique=True),
        Index("ix_observed_subjects_last_seen", "last_seen_at"),
        Index("ix_observed_subjects_last_analyzed", "last_analyzed_at"),
    )

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    #: asset 内网资产 / service_port 资产:端口 / peer 外部对端 / protocol 协议 / signature 签名
    kind: Mapped[str] = mapped_column(String(24))
    value: Mapped[str] = mapped_column(String(160))
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    seen_count: Mapped[int] = mapped_column(Integer, default=0)
    #: 被分析次数与最近分析时间（覆盖率与 staleness 分量的数据源）
    analyzed_count: Mapped[int] = mapped_column(Integer, default=0)
    last_analyzed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AnalysisAnchor(Base):
    """**锚点**：把一条分析结论挂到具体资产上（多对多）。

    为什么需要（借鉴 artex 双图的 `exploration_anchors`）：
    结论原来只挂**单个 `subject`**，而现实里一条结论常常覆盖多个资产——
    “这台是反向代理”影响它后面的 20 台后端，“这个网段在做例行扫描”影响整段地址。
    没有锚点时：覆盖度只能回答“分析过没有”，无法回答“**对这台机器我们到底知道什么**”；
    有了锚点，两个方向都能查：从结论看它影响哪些资产，从资产反查它被哪些结论覆盖过。

    资源只由服务端归一化后写入（IP 统一走 `iputil`，域名转小写），
    智能体只提交原始值——**去重与归一不交给模型**。
    """

    __tablename__ = "analysis_anchors"
    __table_args__ = (
        Index("ix_analysis_anchors_asset", "asset_kind", "asset_value"),
        Index("ix_analysis_anchors_result", "result_id"),
    )

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    #: 被锚定的结论（`analysis_results.id`）
    result_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    task_id: Mapped[str] = mapped_column(String(64), default="")
    #: ip / host / domain / endpoint / service
    asset_kind: Mapped[str] = mapped_column(String(16), default="ip")
    asset_value: Mapped[str] = mapped_column(String(196), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AnalysisTrace(Base):
    """**过程轨迹**：智能体分析过程中发现的“值得别人知道的事实”（借鉴 artex 的 worker 间过程级检索）。

    为什么不只留最终结论：很多有价值的观察（“这 IP 是反代”“这条签名在 8080 上噪声很大”）
    出现在某次分析的**过程**里，却未必写进结论；下一个任务看不到就只能重复烧预算。

    **信任级别很重要**（写进 MCP instructions）：轨迹是“他人未经核实的观察”，
    只能当线索、**绝不能当抑制证据**（`submit_suppression` 的 `evidence_refs` 只收 `es:`/`ev:`）。
    """

    __tablename__ = "analysis_traces"
    __table_args__ = (
        Index("ix_analysis_traces_task", "task_id", "step_index"),
        Index("ix_analysis_traces_subject", "subject_kind", "subject", "created_at"),
    )

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    subject_kind: Mapped[str] = mapped_column(String(16), default="")
    subject: Mapped[str] = mapped_column(String(128), default="")
    step_index: Mapped[int] = mapped_column(Integer, default=0)
    #: 产生这条观察的取数工具名（只写工具名，不存工具参数以免带出正文）
    tool: Mapped[str] = mapped_column(String(48), default="")
    #: 一句话观察（≤500 字）；读者是下一个智能体，不是人，所以要求“可直接用”
    summary: Mapped[str] = mapped_column(Text, default="")
    #: 可选细节（≤2000 字）：关键字段、命中条件、反例。刻意**不存原始报文**，
    #: 否则轨迹表会变成第二份 ES（又大又不一致），原始证据永远用 `es:` 引用去取。
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AnalysisDigest(Base):
    """**冷摘要**：把已经“变冷”的历史结论按对象聚合成一行概览（借鉴 artex 的 cold-digest）。

    为什么需要：`prior_findings` / 覆盖率这类“概览视图”如果逐条吐原始结论，
    返回量会随历史线性膨胀，智能体上下文迟早被历史撑爆。摘要化后**概览恒定大小**，
    要看明细再 `detail=true` 下钻。

    红线：原始 `analysis_results` 行**永不删除**，这里只是另一份聚合视图。
    """

    __tablename__ = "analysis_digests"
    __table_args__ = (Index("ix_analysis_digests_subject", "subject_kind", "subject", unique=True),)

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    subject_kind: Mapped[str] = mapped_column(String(16), default="")
    subject: Mapped[str] = mapped_column(String(128), default="")
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: 被折叠的原始结论条数
    result_count: Mapped[int] = mapped_column(Integer, default=0)
    #: verdict → 条数（例如 {"false_positive": 5, "benign": 2}）
    verdict_mix: Mapped[dict] = mapped_column(JSONB, default=dict)
    #: 最近一次的结论（排序与“这台上次怎么看”的快速回答）
    last_verdict: Mapped[str] = mapped_column(String(24), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
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
    #: 告警簇 ID（`clustering.cluster_id`：归类 + 网段 + 小时）。一次扫描会命中几十个地址，
    #: 逐条看等于噪声，按簇看才知道"这是一件事"；簇是聚合出来的标识，粒度由 clustering 定义。
    cluster_id: Mapped[str] = mapped_column(String(24), default="", index=True)
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
    #: 流量方向（聚合定型时由 triage_policy.direction_of 算一次）：
    #: out→in / in→out / in→in / out→out / unknown。判定对象限定在「监控网段内/外」
    direction: Mapped[str] = mapped_column(String(16), default="")
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


class Observation(Base):
    """**观察事实**：行为基线发现"和平时不一样"的地方，只描述事实，不下结论。

    为什么单独一张表（不复用 `hit_events`）：命中事件是"某条规则判定了什么"，
    带规则名与严重度；而基线偏离只是一个客观变化（"这台机器第一次连这个 IP:443"）。
    判定权在智能体 —— 表里**没有 severity、没有 verdict**，只有事实、强度与时间。
    同一 `dedupe_key`（kind + subject + 维度）在一个冷却期内只留一行，累加次数。
    """

    __tablename__ = "observations"
    __table_args__ = (
        Index("ix_observations_dedupe", "dedupe_key", unique=True),
        Index("ix_observations_kind_last", "kind", "last_seen"),
        Index("ix_observations_subject", "subject"),
    )

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    #: egress_new / egress_rare / geo_jump / login_bruteforce / path_probe / conn_shift
    kind: Mapped[str] = mapped_column(String(32), default="", index=True)
    #: asset / account / session
    subject_kind: Mapped[str] = mapped_column(String(16), default="asset")
    subject: Mapped[str] = mapped_column(String(128), default="")
    #: 客观事实（改了哪一维、旧值/新值、基线值、观测值…），键名中文，界面可直接展示
    facts: Mapped[dict] = mapped_column(JSONB, default=dict)
    #: 客观强度（0~1，不是严重度）：只用于排序与预算，不表达"危不危险"
    strength: Mapped[float] = mapped_column(Float, default=0.0)
    count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    dedupe_key: Mapped[str] = mapped_column(String(200), default="")
    #: 最近一次被转成任务的时刻（D7，2026-10-29）：同一事实 6 小时内不重复派工，
    #: 否则最强的几条事实每 5 分钟重新占位，低强度事实永远轮不到
    last_enqueued_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class EgressBaseline(Base):
    """服务器主动外连的**目的地身份**基线（目的 IP / 域名 / 端口）。

    与数值基线（连接数/端口数）不同：这里关心的是"这台机器以前连过谁"。
    一台服务器第一次连某个 IP/域名/端口，通常就是新装的程序/更新/或者异常进程。
    """

    __tablename__ = "egress_baseline"
    __table_args__ = (
        Index("ix_egress_baseline_unique", "src_ip", "kind", "value", unique=True),
        Index("ix_egress_baseline_last", "last_seen"),
    )

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    src_ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    #: dst_ip / domain / port
    kind: Mapped[str] = mapped_column(String(16), default="")
    value: Mapped[str] = mapped_column(String(255), default="")
    count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class EgressAllow(Base):
    """外连白名单：自学习条目（可手工改/删）+ 手工条目。

    `tombstone=True` 表示"这条被人工删过，不要再自动学回来" ——
    没有墓碑的话删除毫无意义：下一窗口观察到同一个目标又会自动入表。
    """

    __tablename__ = "egress_allow"
    __table_args__ = (
        Index(
            "ix_egress_allow_unique", "kind", "value", "scope", "asset", unique=True
        ),
    )

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    #: dst_ip / domain / port
    kind: Mapped[str] = mapped_column(String(16), default="")
    value: Mapped[str] = mapped_column(String(255), default="")
    #: global（所有资产）/ asset（仅某台）
    scope: Mapped[str] = mapped_column(String(16), default="global")
    asset: Mapped[str] = mapped_column(String(64), default="")
    #: learned / manual
    source: Mapped[str] = mapped_column(String(16), default="manual")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    tombstone: Mapped[bool] = mapped_column(Boolean, default=False)
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    note: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
