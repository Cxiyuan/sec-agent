"""NDR 后端侧的 MCP 专用门面：MCP 只准依赖这一个文件，不许穿透到内部子系统。

`app/mcp/` 是独立的 MCP 服务进程，但它和 Web 后端共用同一个 `app` 包，导入没有任何物理
隔离。以前 `app/mcp/` 直接 import `app.db` / `app.ingestion` / `app.detector` /
`app.investigation` / `app.baseline` / `app.workers`，内部实现一改就要跟着改 MCP 层，
边界名存实亡（见 `docs/ndr-redesign.md` §8 第 5 条）。

这个模块就是那道边界：内部依赖全部收敛到这里，对外只暴露 MCP 真正需要的那几件能力。
**它只做转发与收敛，不含业务逻辑** —— 想改内部实现时只改调用点，`app/mcp/` 不用动。

边界由 `tests/py/test_mcp_boundary.py` 用 AST 静态守住：`app/mcp/` 下的任何文件都不许出现
`app.db` / `app.ingestion` / `app.detector` / `app.investigation` / `app.baseline` /
`app.rules` / `app.collector` / `app.api` / `app.workers` 这类内部导入，只能 import
`app.config`、`app.mcp.*` 与 `app.mcpapi` 本身。
"""

from __future__ import annotations

from typing import Any

from app import system_license
from app.analysis import (
    anchors as analysis_anchors,
    digests as _digests,
    params as analysis_params,
    queue as analysis_queue,
    subjects as analysis_subjects,
    traces as _traces,
    verdicts as _verdicts,
)
from app.api.routes.assets_center import (
    records as _asset_records,
    records_by_ips as _asset_records_by_ips,
)
from app.api.routes.files import (
    is_valid_fuid as _is_valid_fuid,
    lookup_extract as _lookup_extract,
    resolve_extract_path as _resolve_extract_path,
)
from app.api.routes.rules import all_rules as _all_rules
from app.baseline import (
    egress as _egress,
    observations as _observations,
    profile as _profile,
    stats as _stats,
)
from app.db.base import SessionLocal as session_factory
from app.db.models import (
    ConclusionRecord,
    ExclusionFilter,
    IngestFilter,
    McpToken,
    Rule,
)
from app.detector import health as _health, hits as _hits, suppression
from app.ingestion import (
    es_client as _es_client,
    es_config as _es_config,
    relay_nodes as _relay_nodes,
    scope as _scope,
)
from app.investigation import catalog, tools as es_tools
from app.investigation.tools import execute as _es_tool_execute
from app.workers.log import get_logger

__all__ = [
    "ConclusionRecord",
    "ExclusionFilter",
    "IngestFilter",
    "McpToken",
    "Rule",
    "analysis_anchor_kinds",
    "analysis_anchors",
    "analysis_digests",
    "analysis_get_trace",
    "analysis_log_step",
    "analysis_params",
    "analysis_queue",
    "analysis_search_traces",
    "analysis_status_values",
    "analysis_subjects",
    "analysis_task_state",
    "analysis_terminal_reasons",
    "analysis_verdict_values",
    "asset_context_by_ips",
    "asset_records",
    "build_networks",
    "catalog",
    "conclusion_value_aliases",
    "detector_health",
    "es_client",
    "es_config",
    "es_tools",
    "execute_es_tool",
    "get_hit_event",
    "get_logger",
    "hit_clusters",
    "hit_source_labels",
    "hit_stats",
    "in_scope",
    "is_valid_fuid",
    "list_analysis_results",
    "list_hit_events",
    "list_profiles",
    "lookup_extract",
    "monitored_nets",
    "networks_status",
    "record_profile_disposition",
    "relay_inventory",
    "resolve_extract_path",
    "rule_inventory",
    "session_factory",
    "stats_lookup",
    "suppression",
    "system_license",
    "top_anomalies",
]

# 下面所有转发都走「模块属性」而不是「导入期绑定的函数对象」：原 `app/mcp/` 里的懒导入
# 在调用时才取模块属性，测试的 monkeypatch 才能生效；门面必须保住同一份可替换性，否则
# 只是把依赖搬了个家、却静默改变了行为。

# ---------- ES 客户端与运行时配置 ----------


def es_client() -> Any:
    """取 ES 客户端（连接信息取自运行时配置，客户端按连接三要素缓存复用）。"""
    return _es_client.get_es()


def es_config() -> dict[str, str]:
    """当前生效的 ES 运行时配置（DB 覆盖 env，带 30 秒 TTL 缓存）。"""
    return _es_config.current()


# ---------- 网段与 scope ----------


def build_networks(cidrs: list[str]) -> list[Any]:
    """把 CIDR / 单 IP 字符串解析成 ip_network 列表（非法的丢弃，返回空表）。"""
    return _es_client.build_networks(cidrs)


def in_scope(ip_value: Any, nets: list[Any]) -> bool:
    """判断 IP 是否落在给定网段集合内（内网判定的唯一依据）。"""
    return _es_client.in_scope(ip_value, nets)


def monitored_nets() -> list[str]:
    """当前监控网段清单（去重保序；读库出错返回空表）。"""
    return _scope.monitored_nets()


def networks_status() -> dict[str, int | bool]:
    """网段配置状态：`{"configured": bool, "count": int}`。"""
    return _scope.networks_status()


# ---------- 字段目录 / 取证工具 / 基线 ----------
# `catalog` 与 `es_tools` 直接以模块形态转出：前者的字段路径解析、后者的工具注册表都
# 是 MCP 直接遍历的接口，包一层函数反而多一层无意义的转发。
#
# 例外是**调度入口**：MCP 层不直接调 `es_tools.execute(...)`，只经下面这个转发。
# 这样 MCP 侧只有一个取数调度点（以后加鉴权/限流/审计只改一处），也避免
# 「模块名 + execute」这个形状被静态扫描误当成 SQL 拼接端点（它实际是工具分派）。


def execute_es_tool(name: str, args: Any, ctx: Any) -> dict[str, Any]:
    """执行取数层的一个工具（唯一调度入口，内部仍是 `tools.execute` 的实现）。"""
    return _es_tool_execute(name, args, ctx)



def list_observations(
    *, kind: str = "", subject: str = "", minutes: int = 1440, limit: int = 50, offset: int = 0
) -> dict[str, Any]:
    """行为基线事实（外连新目标 / 异地登录 / 爆破 / 404 / 计数偏离）。"""
    return _observations.list_observations(
        kind=kind, subject=subject, minutes=minutes, limit=limit, offset=offset
    )



def egress_baseline(src_ip: str, *, kind: str = "", value: str = "", limit: int = 100) -> dict[str, Any]:
    """某台资产已经学到的主动外连目的地 + 白名单状态（判断"新目标"是否真的新）。"""
    rows = _egress.list_baseline(src_ip, kind=kind, limit=limit)
    allowed: dict[str, Any] = {"allowed": False, "scope": "", "source": "", "note": ""}
    if value:
        allowed = _egress.check_allow(src_ip, kind or "dst_ip", value)
    allowlist = [
        entry
        for entry in _egress.list_allow(limit=200)
        if entry["kind"] == (kind or entry["kind"])
        and entry["scope"] in ("global", "asset")
        and (entry["scope"] == "global" or entry["asset"] == src_ip)
    ]
    return {
        "src_ip": src_ip,
        "known_destinations": rows,
        "total": len(rows),
        "checked": {"kind": kind or "dst_ip", "value": value, **allowed} if value else None,
        "allowlist": allowlist,
        "note": (
            "数量很少（几~几十）说明这台机器平时外连很少，新目标更值得看；"
            "上百说明它是代理/更新服务器，单看「新目标」意义有限"
        ),
    }


def stats_lookup(ip: str = "", key: str = "", limit: int = 50) -> dict[str, Any]:
    """查数值基线：某源 IP 的长期均值 / 标准差 / 样本数与是否过观测期。"""
    return _stats.lookup(ip=ip, key=key, limit=limit)


def list_profiles(
    *,
    kind: str | None = None,
    keys: list[str] | None = None,
    min_risk: float = 0.0,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """查账号 / 会话画像（跨窗口长期基线），可按实体键指名或只看过阈值的异常。"""
    return _profile.list_profiles(
        kind=kind, keys=keys, min_risk=min_risk, limit=limit, offset=offset
    )


def top_anomalies(limit: int = 10) -> dict[str, Any]:
    """按风险分取 TOP 异常画像。"""
    return _profile.top_anomalies(limit)


# ---------- 检测器健康与日志 ----------


# ---------- 提取件（明文文件提取，采集面批 4） ----------
# 与 Web 下载路由（`GET /api/files/{fuid}`）共用同一份校验与取数口径：
# `is_valid_fuid` 验格式、`lookup_extract` 从 ES 找回「真的有提取件」的那条事件、
# `resolve_extract_path` 把 `extracted` 字段解析成提取目录内的绝对路径（防目录穿越与符号链接逃逸）。


def is_valid_fuid(fuid: str) -> bool:
    """fuid 格式是否合法（形如 `Fx8HnP1AbCdEfGhIjK`）。"""
    return _is_valid_fuid(fuid)


def lookup_extract(fuid: str) -> dict[str, Any] | None:
    """按 fuid 找回有提取件的那条事件；没有则回 None。"""
    return _lookup_extract(fuid)


def resolve_extract_path(extracted: str) -> Any:
    """把 ES 的 `extracted` 字段解析成提取目录内的绝对路径；非法/逃逸回 None。"""
    from app.config import settings as _settings

    return _resolve_extract_path(_settings.extract_dir, extracted)


def detector_health(client: Any) -> dict[str, Any]:
    """检测器依赖的 Redis 体检（内存占用 / 上限 / 淘汰策略）。

    传入调用方已有的 redis 客户端，与检测器读的是同一份口径；不在这里新建连接。
    """
    return _health.redis_memory(client)


# `get_logger` 直接以 import 形态转出（MCP 各模块用它建自己的 logger）。

# ---------- 命中事件与历史结论（G1：智能体要能看"有哪些事件、看过没有"） ----------


def list_hit_events(
    *,
    ip: str = "",
    q: str = "",
    rule: str = "",
    source_kind: str = "",
    cluster_id: str = "",
    severity: str = "",
    minutes: int = 0,
    include_ignored: bool = False,
    sort: str = "recent",
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """按对象/时间/来源查命中事件清单（与界面同一份口径：`source_kind` 三类来源）。"""
    return _hits.list_hits(
        ip=ip,
        q=q,
        rule=rule,
        source_kind=source_kind,
        cluster_id=cluster_id,
        severity=severity,
        minutes=minutes,
        include_ignored=include_ignored,
        sort=sort,
        limit=limit,
        offset=offset,
    )


def hit_source_labels() -> dict[str, str]:
    """三类来源的键与中文名（**唯一事实来源仍是 `detector.hits`**，这里只转发）。"""
    return dict(_hits.SOURCE_LABELS)


def get_hit_event(hit_id: str) -> dict[str, Any]:
    """单条命中事件详情（含证据与簇 ID）。"""
    return _hits.get_hit(str(hit_id or "").strip())


def list_analysis_results(
    *,
    subject: str = "",
    kind: str = "",
    verdict: str = "",
    limit: int = 20,
    detail: bool = False,
    via_asset: bool = False,
) -> dict[str, Any]:
    """某个对象的历史结论（开工前先查，避免重复分析白烧预算）。

    `detail=True` 连已折叠进摘要的原始判定一起给；`via_asset=True` 把锚到同一批资产的
    结论也带出来（一条"这台是反代"因此能作用到它后面的后端主机）。
    """
    return analysis_queue.recent_results(
        subject=subject,
        kind=kind,
        verdict=verdict,
        limit=limit,
        detail=detail,
        via_asset=via_asset,
    )


# ---------- 派工任务状态 / 过程轨迹（智能体闭环用） ----------


def analysis_task_state(task_id: str) -> dict[str, Any]:
    """单条任务的当前状态与结论（会话结束后用来判断"到底交回没有"）。"""
    return analysis_queue.task_detail(task_id)


def analysis_log_step(
    *, task_id: str, tool: str = "", summary: str = "", detail: str = ""
) -> dict[str, Any]:
    """记一条过程观察（别人以后能检索到，省掉重复取数）。"""
    return _traces.log_step(task_id=task_id, tool=tool, summary=summary, detail=detail)


def analysis_search_traces(
    *, q: str = "", exclude_task: str = "", subject: str = "", limit: int = 20
) -> dict[str, Any]:
    """在别的任务的过程记录里检索（自动排除自己这条；结果是"未经核实的观察"）。"""
    return _traces.search_traces(q=q, exclude_task=exclude_task, subject=subject, limit=limit)


def analysis_get_trace(*, task_id: str, limit: int = 20) -> dict[str, Any]:
    """取某个任务的全部过程步骤。"""
    return _traces.get_trace(task_id=task_id, limit=limit)


def analysis_digests(subject: str = "", subject_kind: str = "", limit: int = 20) -> list[dict[str, Any]]:
    """冷摘要（折叠后的历史概览，恒定大小）。"""
    return _digests.get_digests(subject=subject, subject_kind=subject_kind, limit=limit)


def analysis_anchor_kinds() -> tuple[str, ...]:
    """锚点允许的资产类型（智能体要按它填 `anchors[].kind`）。"""
    return analysis_anchors.ANCHOR_KINDS


def analysis_terminal_reasons() -> tuple[str, ...]:
    """终态原因取值（`complete_task` 的 `terminal_reason`）。"""
    return _verdicts.TERMINAL_REASONS


# ---------- 资产台账（M1：判严重度必须知道这台是什么、多重要、归谁管） ----------


def asset_records(
    *, q: str = "", criticality: str = "", group_id: str = "", limit: int = 100
) -> dict[str, Any]:
    """按关键字/级别筛资产台账。"""
    return _asset_records(q=q, group_id=group_id, criticality=criticality, limit=limit)


def asset_context_by_ips(ips: list[str]) -> dict[str, Any]:
    """按 IP 精确取台账上下文（含"没登记"的显式区分）。"""
    return _asset_records_by_ips(ips)


# ---------- 事件聚合与统计（M2 / M4） ----------


def hit_clusters(
    *,
    minutes: int = 1440,
    limit: int = 20,
    include_ignored: bool = False,
    source_kind: str = "",
) -> dict[str, Any]:
    """告警簇：同一归类 + 同一网段 + 同一小时折成一件事（含事件数、源数、最高级别）。"""
    return _hits.clusters(
        minutes=minutes, limit=limit, include_ignored=include_ignored, source_kind=source_kind
    )


def hit_stats(*, minutes: int = 1440) -> dict[str, Any]:
    """事件面统计：总量、按来源/级别分布、TOP 事件归类、趋势。"""
    return _hits.hits_stats(minutes=minutes)


# ---------- 规则清单（M5：智能体要能回答"NDR 现在到底在检测什么"） ----------


def rule_inventory() -> list[dict[str, Any]]:
    """全部检测规则（行为分析可编辑 + 特征匹配只读），与界面同一份口径。"""
    with session_factory() as db:
        return _all_rules(db)


# ---------- 中继清单（M6：判横向/外联前必须知道谁是反代、谁是源站） ----------


def relay_inventory() -> dict[str, Any]:
    """中继节点清单与推算出的角色/侧向（**复用界面同一份快照** `relay_nodes.describe()`）。

    为什么不给智能体 `text` 原文：那是运维维护的清单文本（含注释），对分析没用还吃上下文；
    真正需要的是「哪些地址是中继、被算成反代还是 DNS 转发、保留哪一侧」。
    """
    snap = dict(_relay_nodes.describe())
    snap.pop("text", None)
    return snap


# ---------- 画像级误报降权（M3） ----------


def record_profile_disposition(
    profile_ref: str,
    verdict: str,
    *,
    signal: str = "",
    note: str = "",
    operator: str = "",
) -> dict[str, Any]:
    """给画像告警打处置（误报→按时间窗降权；确认→仅留档）。"""
    return _profile.disposition_for(
        profile_ref, verdict, signal=signal, note=note, operator=operator
    )


# ---------- 统一词表（verdict / status 只有一份实现） ----------


def analysis_verdict_values() -> tuple[str, ...]:
    """任务判定允许的结论态（不含流程态）。"""
    return _verdicts.VERDICT_VALUES


def analysis_status_values() -> tuple[str, ...]:
    """事件结论允许的状态（结论态 + 流程态）。"""
    return _verdicts.STATUS_VALUES


def conclusion_value_aliases() -> dict[str, str]:
    """结论/判定的中文与简写别名表（**与 verdict 共用一份**，不再各写一套）。"""
    return dict(_verdicts.VALUE_ALIASES)
