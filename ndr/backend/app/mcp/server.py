"""MCP 服务：智能体分析事件时用这里的工具查询、调查、写回结论。

挂在 `python -m app.mcp.server`，由 compose 的 `ndr-mcp` 服务拉起。

两层工具：
- `app.investigation.tools` 的 10 个「查 ES」工具（取数层，NDR 是数据的看门人）；
- `app.mcp.ndr_tools` 的 33 个 NDR 自身状态/配置/基线/写回工具。

**每个 MCP 工具都写成显式形参的函数**，这不是风格问题：MCP 的 inputSchema 由函数签名
推导，用 `**kwargs` 接参数会被当成「一个必填参数 kwargs」，调用必然报 validation error。
参数名与智能体提示词里的一致（`source`/`filters`/`start`/`end`…），所以包装层只做
「丢掉没传的参数」这一件事，默认值语义完全由下层决定。
"""

from __future__ import annotations

import json
import time
from collections.abc import Collection
from contextvars import ContextVar
from typing import Any

import uvicorn
from mcp.server.mcpserver import MCPServer
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import settings
from app.mcp import auth as token_auth, calls, ndr_tools
from app.mcpapi import es_tools, execute_es_tool, get_logger, system_license

log = get_logger(__name__)

# 当前请求用的是哪个令牌（中间件写入，调用记录读它；工具上下文按 id 分会话）。
# 用 ContextVar 而不是传参：MCP 的调用链在 SDK 内部，没有地方能一路把身份带下去。
_current_token: ContextVar[str] = ContextVar("mcp_token_name", default="?")
_current_token_id: ContextVar[str] = ContextVar("mcp_token_id", default="")

_HTTP_UNAUTHORIZED = 401

# ---------- 工具上下文（按令牌会话复用） ----------
#
# 为什么必须复用：`ToolCtx.valid_refs`（「不能凭空引用证据」的白名单）与
# `ToolCtx.raw_evidence`（原始证据 20 条上限）都是 **跨调用累积** 才有意义的。
# 原实现每次工具调用都 `es_tools.ToolCtx()` 新建，于是：
#   - ref 白名单校验的 `if ctx.valid_refs and ...` 永远是空集 → 校验失效；
#   - 证据条数从 0 开始 → 上限永不生效；
#   - `describe_data` 的 case 字段永远是 null（后来直接删了那个死字段）。
# （2026-10 MCP QA）这里按令牌 id 缓存，带 TTL 与数量上限，避免无界增长。
_CTX_TTL_SECONDS = 6 * 3600.0
_CTX_MAX_SESSIONS = 64
#: 单个会话最多记多少条 ref；超出就清空重来（宁可让模型重查，也不无界吃内存）
_CTX_MAX_REFS = 20000
_ctx_cache: dict[str, tuple[float, Any]] = {}
#: 会话内"工具名 → 产生过的证据引用数"。证据多样性门槛（≥2 种取数工具）靠它判定：
#: 只看一段被投毒的正文就下结论，是这个机制最怕的投毒方式。
_usage: dict[str, tuple[float, dict[str, int]]] = {}


def _usage_for(token_id: str) -> dict[str, int]:
    """取该会话的工具使用计数（新会话返回空表）。"""
    entry = _usage.get(token_id)
    return dict(entry[1]) if entry else {}


def _note_usage(token_id: str, tool: str, added: int) -> None:
    """记一笔：这个工具本次新增了 `added` 条证据引用。"""
    if added <= 0:
        return
    now = time.time()
    for stale_key in [k for k, (ts, _) in _usage.items() if now - ts > 6 * 3600]:
        _usage.pop(stale_key, None)
    _, counts = _usage.get(token_id, (now, {}))
    counts[tool] = counts.get(tool, 0) + added
    _usage[token_id] = (now, counts)


def _ctx_for(token_id: str) -> Any:
    """取该令牌的工具上下文（同一个令牌的多次调用共享 refs / 证据计数）。"""
    now = time.time()
    for stale in [k for k, (ts, _) in _ctx_cache.items() if now - ts > _CTX_TTL_SECONDS]:
        _ctx_cache.pop(stale, None)
    entry = _ctx_cache.get(token_id)
    if entry is not None:
        _ctx_cache[token_id] = (now, entry[1])
        return entry[1]
    if len(_ctx_cache) >= _CTX_MAX_SESSIONS:
        oldest = min(_ctx_cache, key=lambda k: _ctx_cache[k][0])
        _ctx_cache.pop(oldest, None)
    ctx = es_tools.ToolCtx()
    _ctx_cache[token_id] = (now, ctx)
    return ctx


def _reset_ctx_cache() -> None:
    """清空会话上下文（测试用）。"""
    _ctx_cache.clear()


def _clean(**kwargs: Any) -> dict[str, Any]:
    """丢掉没传的参数。

    MCP 客户端总会把 schema 里的参数补成默认值（空串/0/False），直接透传下去会覆盖
    下层的默认值。这里把「看起来没传」的值滤掉，只留下真正给了的。
    """
    return {k: v for k, v in kwargs.items() if v not in (None, "", 0, False, {}, [])}


def _run(name: str, args: dict[str, Any], *, native: bool = False) -> str:
    """执行一个工具，记一笔调用，回 JSON 文本（模型只吃文本）。"""
    started = time.perf_counter()
    # 上下文按令牌会话复用，见 `_ctx_for` 的说明（ref 白名单与证据上限靠它才生效）
    ctx = _ctx_for(_current_token_id.get() or "anonymous")
    if native:
        result = ndr_tools.dispatch(name, args)
    else:
        result = execute_es_tool(name, args, ctx)
    # 在**唯一入口**登记本次结果里的证据引用：`fetch_window` 这类 native 工具同样会带
    # `ref`，不在这里登记的话，随后的 raw_evidence 会把它们当成「凭空引用」拒掉。
    # （取数层工具内部也会登记一次 —— set 幂等，保留是为了它们能脱离 MCP 层直接单测。）
    before = len(ctx.valid_refs)
    ctx.register_refs(result)
    _note_usage(_current_token_id.get() or "anonymous", name, len(ctx.valid_refs) - before)
    if len(ctx.valid_refs) > _CTX_MAX_REFS:
        ctx.valid_refs.clear()
    elapsed = int((time.perf_counter() - started) * 1000)
    calls.record(
        tool=name,
        token_name=_current_token.get(),
        ok="error" not in result,
        duration_ms=elapsed,
        params=args,
        error=str(result.get("error") or ""),
    )
    return json.dumps(result, ensure_ascii=False, default=str)


# ---------- 查 ES 的工具（取数层在 NDR） ----------


def describe_data() -> str:
    """可用数据源、真实时间范围、字段清单（先调它，避免编字段名）。"""
    return _run("describe_data", {})


def search_events(
    source: str = "",
    filters: dict[str, Any] | None = None,
    keyword: str = "",
    start: str = "",
    end: str = "",
    limit: int = 0,
    sort: str = "",
    with_body: bool = False,
) -> str:
    """定向检索事件（时间范围 + 字段过滤 + 关键词）。"""
    return _run(
        "search_events",
        _clean(
            source=source,
            filters=filters,
            keyword=keyword,
            start=start,
            end=end,
            limit=limit,
            sort=sort,
            with_body=with_body,
        ),
    )


def aggregate_events(
    field: str = "",
    source: str = "",
    filters: dict[str, Any] | None = None,
    start: str = "",
    end: str = "",
    size: int = 0,
) -> str:
    """按字段 top-N 聚合（找横向目标 / 外联目的地 / 端口分布）。"""
    return _run(
        "aggregate_events",
        _clean(field=field, source=source, filters=filters, start=start, end=end, size=size),
    )


def timeline(
    entity: str = "", start: str = "", end: str = "", limit: int = 0, source: str = ""
) -> str:
    """某个 IP 的完整时间线（源与目的两侧合并，按时间升序）。"""
    return _run("timeline", _clean(entity=entity, start=start, end=end, limit=limit, source=source))


def net_flows(ip: str = "", start: str = "", end: str = "", top: int = 0, source: str = "") -> str:
    """网络侧画像：该 IP 的目的地 / 端口 / 连接状态 / 协议分布。"""
    return _run("net_flows", _clean(ip=ip, start=start, end=end, top=top, source=source))


def dns_queries(
    domain: str = "",
    ip: str = "",
    start: str = "",
    end: str = "",
    limit: int = 0,
    source: str = "",
) -> str:
    """DNS 查询记录（隧道、DGA、C2 域名解析）。"""
    return _run(
        "dns_queries",
        _clean(domain=domain, ip=ip, start=start, end=end, limit=limit, source=source),
    )


def tls_fingerprints(
    ip: str = "", start: str = "", end: str = "", limit: int = 0, source: str = ""
) -> str:
    """TLS 会话与 JA3 / SNI 指纹（识别 C2）。"""
    return _run("tls_fingerprints", _clean(ip=ip, start=start, end=end, limit=limit, source=source))


def web_requests(
    ip: str = "",
    uri: str = "",
    status_code: str = "",
    include_body: bool = False,
    start: str = "",
    end: str = "",
    limit: int = 0,
    source: str = "",
) -> str:
    """HTTP 请求（方法 / UA / 状态码，可选请求正文）。"""
    return _run(
        "web_requests",
        _clean(
            ip=ip,
            uri=uri,
            status_code=status_code,
            include_body=include_body,
            start=start,
            end=end,
            limit=limit,
            source=source,
        ),
    )


def file_hashes(
    ip: str = "",
    hash: str = "",
    filename: str = "",
    start: str = "",
    end: str = "",
    limit: int = 0,
    source: str = "",
) -> str:
    """文件传输与哈希（落地文件、外泄文件）。"""
    return _run(
        "file_hashes",
        _clean(
            ip=ip, hash=hash, filename=filename, start=start, end=end, limit=limit, source=source
        ),
    )


def raw_evidence(ref: str = "") -> str:
    """取原始证据文档（ref 形如 `es:<索引>/<文档id>`）。"""
    return _run("raw_evidence", _clean(ref=ref))


# ---------- NDR 自身状态与写回 ----------


def get_event(event_id: str = "", fingerprint: str = "") -> str:
    """按事件ID / 指纹取这条事件被投递过什么、已有哪些结论。"""
    return _run("get_event", _clean(event_id=event_id, fingerprint=fingerprint), native=True)


def get_rule(name: str = "", rule_id: str = "") -> str:
    """取检测规则原文（判断摘要为什么被判可疑）。"""
    return _run("get_rule", _clean(name=name, rule_id=rule_id), native=True)


def detector_status() -> str:
    """检测器运行状态：队列积压、吞吐、丢弃/去重/失败计数、主从、Redis 内存。"""
    return _run("detector_status", {}, native=True)


def list_networks() -> str:
    """监控网段清单（判定内网的依据）。"""
    return _run("list_networks", {}, native=True)


def list_filters() -> str:
    """排除过滤清单（命中即跳过分析，别把「被排除」读成「无异常」）。"""
    return _run("list_filters", {}, native=True)


def fetch_window(
    start: str = "",
    end: str = "",
    nets: list[str] | None = None,
    ips: list[str] | None = None,
    limit: int = 0,
) -> str:
    """按时间窗整批取回事件条目（可限定网段/IP，含原文），用于回溯：自己跑规则看历史行为。"""
    return _run(
        "fetch_window",
        _clean(start=start, end=end, nets=nets, ips=ips, limit=limit),
        native=True,
    )


def record_conclusion(
    summary: str = "",
    event_id: str = "",
    fingerprint: str = "",
    status: str = "",
    severity: str = "",
    detail: dict[str, Any] | None = None,
    thread_id: str = "",
) -> str:
    """把调查结论写回 NDR（界面可见；同一事件只留一份）。

    `status` 可填：true_positive / false_positive / benign / suspicious / inconclusive /
    pending / done（默认 done）；`severity` 可填：info / low / medium / high / critical
    （默认 info）。中文别名（真阳性、误报、高危…）也认；填了不认识的值会报错并列出可选值。
    """
    return _run(
        "record_conclusion",
        _clean(
            summary=summary,
            event_id=event_id,
            fingerprint=fingerprint,
            status=status,
            severity=severity,
            detail=detail,
            thread_id=thread_id,
        ),
        native=True,
    )


def baseline_lookup(ip: str = "", key: str = "", limit: int = 0) -> str:
    """查数值基线：某个源 IP 的连接数/目的端口数/目的 IP 数的长期均值与标准差。"""
    return _run("baseline_lookup", _clean(ip=ip, key=key, limit=limit), native=True)


def entity_profile(
    kind: str = "",
    keys: list[str] | None = None,
    min_risk: float = 0.0,
    anomalies_only: bool = False,
    limit: int = 0,
) -> str:
    """查账号/会话画像（跨窗口长期基线）；`anomalies_only` 只看过阈值的异常。"""
    return _run(
        "entity_profile",
        _clean(kind=kind, keys=keys, min_risk=min_risk, anomalies_only=anomalies_only, limit=limit),
        native=True,
    )


def file_content(fuid: str = "", encoding: str = "", max_bytes: int = 0) -> str:
    """取提取件（Zeek 落盘的明文文件）的内容或元数据（有界）。"""
    return _run(
        "file_content",
        _clean(fuid=fuid, encoding=encoding, max_bytes=max_bytes),
        native=True,
    )


# ---------- 派工队列与数据地图 ----------


def _with_ctx(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """注入两样模型不该自己填的东西：令牌名、本会话真取回过的证据引用。

    - `_token`：任务要记"谁领的"（租约归属与审计）；
    - `_valid_refs`：只有本会话真取回过的 `es:/ev:` 引用才能作为抑制的证据，
      否则随便编几条引用就能换到一条永久抑制（这是全自动抑制的关键防线）。
    """
    ctx = _ctx_for(_current_token_id.get() or "anonymous")
    out = dict(args)
    out["_token"] = _current_token.get() or "?"
    if name in ("complete_task", "submit_suppression"):
        out["_valid_refs"] = sorted(ctx.valid_refs)
        out["_tool_usage"] = _usage_for(_current_token_id.get() or "anonymous")
    return out


def claim_tasks(
    limit: int = 0, kinds: str = "", min_strength: float = 0.0, wait_seconds: int = 0
) -> str:
    """领取待分析的客观线索（NDR 不限制领取额度或并发）。"""
    # 必须走 `_with_ctx` 注入 `_token`：领取要记"谁领的"（租约归属、任务审计），
    # 漏了它所有调用方会落到兜底名 `mcp` 上，无法区分是哪个智能体持有任务。
    return _run(
        "claim_tasks",
        _with_ctx(
            "claim_tasks",
            _clean(limit=limit, kinds=kinds, min_strength=min_strength, wait_seconds=wait_seconds),
        ),
        native=True,
    )


def complete_task(
    task_id: str = "",
    verdict: str = "",
    summary: str = "",
    confidence: float = 0.0,
    findings: dict[str, Any] | None = None,
    evidence_refs: list[str] | None = None,
    next_tasks: list[dict[str, Any]] | None = None,
    suppression: dict[str, Any] | None = None,
    anchors: list[dict[str, Any]] | None = None,
    terminal_reason: str = "",
    tools_used: int = 0,
    duration_ms: int = 0,
) -> str:
    """交回结论；可追加追问（受深度上限）、提交精准抑制（仅误报、证据须真取过）、锚定资产。

    `anchors` 决定这条结论**影响哪些资产**（如一条"这台是反向代理"要挂到它后面的后端）；
    `terminal_reason` 说明是怎么结束的（查清了 / 预算用尽 / 取数失败 / 超时 / 中断），
    否则 `inconclusive` 无法区分"查了没证据"和"根本没查完"。
    """
    return _run(
        "complete_task",
        _with_ctx(
            "complete_task",
            _clean(
                task_id=task_id,
                verdict=verdict,
                summary=summary,
                confidence=confidence,
                findings=findings,
                evidence_refs=evidence_refs,
                next_tasks=next_tasks,
                suppression=suppression,
                anchors=anchors,
                terminal_reason=terminal_reason,
                tools_used=tools_used,
                duration_ms=duration_ms,
            ),
        ),
        native=True,
    )


def defer_task(task_id: str = "", reason: str = "", retry_after_seconds: int = 0) -> str:
    """延后再领（数据没入齐或暂不深挖），释放租约。"""
    return _run(
        "defer_task",
        _with_ctx(
            "defer_task",
            _clean(task_id=task_id, reason=reason, retry_after_seconds=retry_after_seconds),
        ),
        native=True,
    )


def task_state(task_id: str = "") -> str:
    """查单条任务的状态与结论：会话结束前用它确认"到底交回没有"。"""
    return _run("task_state", _clean(task_id=task_id), native=True)


def log_step(task_id: str = "", tool: str = "", summary: str = "", detail: str = "") -> str:
    """记一条过程观察（别人以后能检索到，省掉重复取数）。"""
    return _run(
        "log_step",
        _clean(task_id=task_id, tool=tool, summary=summary, detail=detail),
        native=True,
    )


def search_traces(q: str = "", exclude_task: str = "", subject: str = "", limit: int = 0) -> str:
    """在别的任务的过程记录里检索（结果是"未经核实的观察"，只能当线索）。"""
    return _run(
        "search_traces",
        _with_ctx(
            "search_traces",
            _clean(q=q, exclude_task=exclude_task, subject=subject, limit=limit),
        ),
        native=True,
    )


def get_trace(task_id: str = "", limit: int = 0) -> str:
    """取某个任务的全部过程步骤。"""
    return _run("get_trace", _clean(task_id=task_id, limit=limit), native=True)


def task_stats(days: int = 0, kind: str = "", limit: int = 0) -> str:
    """队列与成本总览：积压、按类型/结论分布、平均成本、覆盖率、预算配置。"""
    return _run("task_stats", _clean(days=days, kind=kind, limit=limit), native=True)


def server_info() -> str:
    """本 NDR 的身份（授权ID）：项目组织绑定校验用（必须与智能体侧配置一致）。"""
    return _run("server_info", {}, native=True)


def asset_map(kind: str = "", limit: int = 0) -> str:
    """数据地图：见过的资产/服务端口/外部对端/协议/签名清单（自主挑目标用）。"""
    return _run("asset_map", _clean(kind=kind, limit=limit), native=True)


def coverage_report(days: int = 0, kind: str = "", limit: int = 0, by: str = "") -> str:
    """覆盖率与盲区：哪些对象从来没看过、哪些久未看。

    `by="asset"` 改走锚点口径：统计"近 N 天有多少资产被结论覆盖过"，
    而不是只统计对象自己有没有被分析过。
    """
    return _run(
        "coverage_report", _clean(days=days, kind=kind, limit=limit, by=by), native=True
    )


def submit_suppression(
    match: dict[str, Any] | None = None,
    reason_code: str = "",
    evidence_refs: list[str] | None = None,
    confidence: float = 0.0,
    name: str = "",
    note: str = "",
    ttl_days: int = 0,
    task_id: str = "",
) -> str:
    """申请自动抑制（证据够硬就不再派工、不再生成该类事件）。"""
    return _run(
        "submit_suppression",
        _with_ctx(
            "submit_suppression",
            _clean(
                match=match,
                reason_code=reason_code,
                evidence_refs=evidence_refs,
                confidence=confidence,
                name=name,
                note=note,
                ttl_days=ttl_days,
                task_id=task_id,
            ),
        ),
        native=True,
    )


# ---------- 事件、既往结论、抑制与主动登记 ----------


def search_hits(
    ip: str = "", source_kinds: str = "", cluster_id: str = "", minutes: int = 0, limit: int = 0
) -> str:
    """查命中事件清单（新架构下没有推送，事件靠这里自己捞；返回带告警簇）。"""
    return _run(
        "search_hits",
        _clean(
            ip=ip, source_kinds=source_kinds, cluster_id=cluster_id, minutes=minutes, limit=limit
        ),
        native=True,
    )


def get_event_detail(event_id: str = "") -> str:
    """取单条事件完整内容（含证据、三类来源、簇 ID 与已有结论）。"""
    return _run("get_event_detail", _clean(event_id=event_id), native=True)


def prior_findings(
    subject: str = "",
    kind: str = "",
    verdict: str = "",
    limit: int = 0,
    detail: bool = False,
    via_asset: bool = False,
) -> str:
    """查该对象的既往结论：开工前先问"看过没有"，避免重复分析白烧预算。

    `detail=true` 连已折叠进摘要的原始判定一起给；`via_asset=true` 把锚到同一批资产的
    结论也带出来（一条"这台是反代"因此能解释它后面那些后端的历史）。
    """
    return _run(
        "prior_findings",
        _clean(
            subject=subject,
            kind=kind,
            verdict=verdict,
            limit=limit,
            detail=detail,
            via_asset=via_asset,
        ),
        native=True,
    )


def list_suppressions(
    q: str = "", enabled_only: bool = False, include_expired: bool = False, limit: int = 0
) -> str:
    """看当前精准抑制（含命中数与到期时间）。"""
    return _run(
        "list_suppressions",
        _clean(q=q, enabled_only=enabled_only, include_expired=include_expired, limit=limit),
        native=True,
    )


def revoke_suppression(suppression_id: str = "", reason: str = "") -> str:
    """撤销一条精准抑制（必须写原因，放开也要留审计）。"""
    return _run(
        "revoke_suppression", _clean(suppression_id=suppression_id, reason=reason), native=True
    )


def add_task(
    subject: str = "",
    subject_kind: str = "",
    kind: str = "",
    note: str = "",
    strength: float = 0.0,
) -> str:
    """主动登记一条线索（外部情报或巡逻发现时用；同一套去重与容量，不插队）。"""
    return _run(
        "add_task",
        _clean(subject=subject, subject_kind=subject_kind, kind=kind, note=note, strength=strength),
        native=True,
    )


# ---------- 资产上下文、簇、规则与中继（M1-M6） ----------


def asset_context(ips: list[str] | None = None, q: str = "", criticality: str = "", limit: int = 0) -> str:
    """查资产台账上下文（主机名/重要级别/责任人/分组）：判严重度前先查它。"""
    return _run("asset_context", _clean(ips=ips, q=q, criticality=criticality, limit=limit), native=True)


def hit_clusters(minutes: int = 0, source_kind: str = "", limit: int = 0, include_ignored: bool = False) -> str:
    """按告警簇看事件：一次扫描的几十个地址折成一件事（含事件数、源数、最高级别）。"""
    return _run(
        "hit_clusters",
        _clean(minutes=minutes, source_kind=source_kind, limit=limit, include_ignored=include_ignored),
        native=True,
    )


def hit_stats(minutes: int = 0) -> str:
    """事件面统计：总量、按来源/级别分布、TOP 事件归类、趋势。"""
    return _run("hit_stats", _clean(minutes=minutes), native=True)


def list_observations(
    kind: str = "", subject: str = "", minutes: int = 1440, limit: int = 50, offset: int = 0
) -> str:
    """行为基线事实：外连新目标/罕见、账号异地登录、爆破、404、连接数偏离（只有事实，没有结论）。"""
    return _run(
        "list_observations",
        _clean(kind=kind, subject=subject, minutes=minutes, limit=limit, offset=offset),
        native=True,
    )


def list_rules(source_kind: str = "", limit: int = 0) -> str:
    """列出 NDR 现在在检测什么（防「没事件」被误读成「没攻击」）。"""
    return _run("list_rules", _clean(source_kind=source_kind, limit=limit), native=True)


def relay_nodes() -> str:
    """中继清单与角色（判横向/外联前必查：经过反代时 src_ip 是代理本身）。"""
    return _run("relay_nodes", {}, native=True)


def record_disposition(profile_id: str = "", verdict: str = "", signal: str = "", note: str = "") -> str:
    """画像级处置（误报→按时间窗降权该实体或某一路证据；确认→仅留档）。"""
    return _run(
        "record_disposition",
        _with_ctx(
            "record_disposition", _clean(profile_id=profile_id, verdict=verdict, signal=signal, note=note)
        ),
        native=True,
    )


_ES_TOOL_FUNCS = (
    describe_data,
    search_events,
    aggregate_events,
    timeline,
    net_flows,
    dns_queries,
    tls_fingerprints,
    web_requests,
    file_hashes,
    raw_evidence,
)
_NDR_TOOL_FUNCS = (
    get_event,
    get_rule,
    detector_status,
    list_networks,
    list_filters,
    fetch_window,
    record_conclusion,
    baseline_lookup,
    entity_profile,
    file_content,
    claim_tasks,
    complete_task,
    defer_task,
    task_state,
    log_step,
    search_traces,
    get_trace,
    task_stats,
    server_info,
    asset_map,
    coverage_report,
    search_hits,
    get_event_detail,
    prior_findings,
    list_suppressions,
    revoke_suppression,
    add_task,
    asset_context,
    hit_clusters,
    hit_stats,
    list_rules,
    list_observations,
    relay_nodes,
    record_disposition,
    submit_suppression,
)


#: **工具档位**：按能力收窄工具面。
#:
#: 为什么不是"延迟加载"（artex 那套 deferred 提示块）：dsh 是把 MCP 工具作为结构化
#: 工具定义下发的，不存在"提示词里铺一堆名字"的成本，所以那套机制在这里没有落点。
#: 真正对得上的是**同族能力**：只把当前身份用得上的工具暴露出来。这同时修掉一个安全缺口——
#: 原来任何持有令牌的调用方都能看到并调用 `submit_suppression`（等于能关掉一部分检测面）。
#:
#: `analyst` 是智能体分析闭环够用的最小集（24 个）；排查/运维/复现用 `/mcp/full`（全部）。
_TOOL_PROFILES: dict[str, tuple[str, ...]] = {
    "analyst": (
        # 取数（最小必要集：先看数据地图，再按需检索与聚合）
        "describe_data",
        "search_events",
        "aggregate_events",
        "raw_evidence",
        # 事件面与历史
        "search_hits",
        "get_event_detail",
        "prior_findings",
        # 规则面：命中线索的 hint 只有规则名，看不到规则的匹配条件就会把
        # 「这条规则在抓什么」误当成「这条流量做了什么」
        "get_rule",
        "list_rules",
        "hit_clusters",
        # 资产上下文与全局态势
        "asset_context",
        "asset_map",
        "coverage_report",
        # 方向判定：反代/DNS 转发不查清楚，代理访问会被误读成内网主动外联
        "relay_nodes",
        # 派工闭环
        "claim_tasks",
        "complete_task",
        "defer_task",
        "task_state",
        # 身份：项目组织绑定校验（授权ID 必须与智能体侧配置一致）
        "server_info",
        # 抑制（申请与查看；撤销留给人在界面或 full 档上做）
        "submit_suppression",
        "list_suppressions",
        # 底座：没有这两把"尺子"，agent 只能去 ES 自己算"正常长什么样"
        "baseline_lookup",
        "entity_profile",
        # 行为基线事实（外连新目标/异地登录/爆破/404）：事实在前，判断在后
        "list_observations",
    ),
}


#: 取证工具的用途。instructions 按档位拼接：**只提当前档位真实存在的工具**
#: （2026-10 MCP QA：说明里写了 analyst 档没有的 timeline / relay_nodes / log_step，
#: agent 照着调会 tool-not-found，白烧一轮预算还会把终态记成 tool_error）。
_EVIDENCE_NOTES: tuple[tuple[str, str], ...] = (
    ("search_events", "时间窗 + 字段过滤 + 关键词定向检索"),
    ("aggregate_events", "按字段 top-N 聚合（规模/频率/端口分布）"),
    ("timeline", "单个 IP 源与目的合并时间线"),
    ("net_flows", "某 IP 的目的地/端口/连接状态/协议画像"),
    ("dns_queries", "DNS 查询（隧道/DGA/C2 域名）"),
    ("tls_fingerprints", "TLS 会话与 JA3/SNI 指纹"),
    ("web_requests", "HTTP 请求（方法/UA/状态码）"),
    ("file_hashes", "文件传输与哈希"),
    ("raw_evidence", "原始文档（返回可引用的 es:/ev: ref）"),
)


def _instructions_for(allowed: Collection[str] | None) -> str:
    """按工具档位生成契约说明（`allowed=None` 表示 full 档）。"""

    def has(name: str) -> bool:
        return allowed is None or name in allowed

    parts: list[str] = [
        "深瞳 NDR 是数据的看门人：采集侧日志已归一化成统一字段，只能通过这里查。"
    ]
    if has("server_info"):
        parts.append(
            "server_info 给出本 NDR 的**授权ID**（项目组织身份）：智能体侧绑定的项目 ID "
            "必须与它一致；不一致说明这台 MCP 指错了 NDR，不要继续干活。"
        )
    if has("describe_data"):
        parts.append("先调 describe_data 拿字段清单、真实时间范围与各来源量级，再按需取证。")
    evidence = [f"{name}（{note}）" for name, note in _EVIDENCE_NOTES if has(name)]
    if evidence:
        parts.append("取证：" + "；".join(evidence) + "。")

    if has("claim_tasks"):
        claim_line = (
            "**分析任务靠自己领**（新架构不再把摘要推给你）：claim_tasks 领取客观线索"
            "（只含事实与客观强度，不含严重度与结论）；complete_task 交回结论"
            "（可 next_tasks 追问、可提精准抑制）；defer_task 延后；task_state 看状态。"
        )
        if has("task_stats"):
            claim_line += "task_stats 看队列/成本总览与覆盖率。"
        parts.append(claim_line)

    history: list[str] = []
    if has("prior_findings"):
        history.append(
            "prior_findings(subject) 问过看过没有、结论是什么"
            "（detail=true 下钻原始判定，via_asset=true 连锚到同一批资产的结论）"
        )
    if has("search_hits"):
        history.append(
            "search_hits(ip=...) 按对象捞事件"
            "（cluster_id 把一次扫描的几十个地址折成一件事）"
        )
    if has("hit_clusters"):
        history.append("hit_clusters 按簇看（一次扫描是一件事）")
    if has("hit_stats"):
        history.append("hit_stats 看整体分布与 TOP 归类")
    if has("get_event"):
        history.append("get_event 按事件 ID/指纹取已有的结论")
    if has("get_event_detail"):
        history.append("get_event_detail 看单条事件的完整细节")
    if history:
        parts.append("**开工前先查历史**：" + "；".join(history) + "。")

    rules: list[str] = []
    if has("get_rule"):
        rules.append("get_rule 取规则原文与匹配条件（看清这条规则到底在抓什么）")
    if has("list_rules"):
        rules.append("list_rules 知道 NDR 在检测什么（没事件不等于没攻击）")
    if rules:
        parts.append("规则：" + "；".join(rules) + "。")

    ctx: list[str] = []
    if has("asset_context"):
        ctx.append("asset_context 查台账（是什么机器、多重要、归谁管）——判轻重必须靠它")
    if has("relay_nodes"):
        ctx.append("relay_nodes 查反代/DNS 转发（否则会把代理访问误判成内网主动外联）")
    if has("baseline_lookup"):
        ctx.append("baseline_lookup 查数值基线（当前值 vs 长期均值与 σ、是否过了观测期）")
    if has("entity_profile"):
        ctx.append("entity_profile 查账号/会话画像（长期基线、风险分与异常理由）")
    if has("list_observations"):
        ctx.append(
            "list_observations 查行为基线事实（外连新目标/异地登录/爆破/404/连接数偏离）——"
            "这里只有事实与强度，没有结论与严重度，判不判由你自己定"
        )
    if has("asset_map"):
        ctx.append("asset_map 看对象清单（资产/服务端口/外部对端/协议/签名）")
    if has("coverage_report"):
        ctx.append("coverage_report 看覆盖率与盲区（「没看到」是不是因为没采）")
    if ctx:
        parts.append("上下文与坐标：" + "；".join(ctx) + "。")

    sup: list[str] = []
    if has("list_suppressions"):
        sup.append("list_suppressions 看哪些现象已被精准抑制（会挡派工）")
    if has("submit_suppression"):
        sup.append(
            "确认某类现象是误报且证据够硬时用 submit_suppression 申请自动抑制"
            "（服务端六道机械门槛：结构化匹配、≥2 维度、引用真实性、≥2 种工具、"
            "置信度、新现象保护期；影响面过大自动降级为只不派工）"
        )
        sup.append(
            "**抑制闭环不需要人放行**：被降级时返回里写明哪个维度超限与怎么收窄，"
            "按建议改窄条件后用同一个 name 重提（同名覆盖）就会真正生效；"
            "生效后这类现象不再派工、不再按门铃"
        )
    if has("revoke_suppression"):
        sup.append("判错了用 revoke_suppression 收回（必须写原因）")
    if sup:
        parts.append("抑制：" + "；".join(sup) + "。")

    misc: list[str] = []
    if has("log_step"):
        misc.append(
            "关键发现用 log_step 记一句（轨迹是他人未经核实的观察，只能当线索，"
            "绝不能当抑制证据）"
        )
    if has("search_traces"):
        misc.append("search_traces 看别人留下的轨迹（别重复取数）")
    if has("get_trace"):
        misc.append("get_trace 看单条轨迹的完整步骤")
    if has("add_task"):
        misc.append("巡逻或外部情报得到值得看的对象用 add_task 登记")
    if has("record_disposition"):
        misc.append("画像级误报用 record_disposition 降权（与事件流抑制分工不同）")
    if has("detector_status"):
        misc.append("detector_status 看检测器状态")
    if has("list_networks"):
        misc.append("list_networks 看监控网段")
    if has("list_filters"):
        misc.append("list_filters 看两道过滤闸门")
    if has("fetch_window"):
        misc.append("要整批拉一段时间窗自己筛（回溯）用 fetch_window")
    if has("file_content"):
        misc.append("事件里有 extracted/fuid 字段时用 file_content 取提取件内容（有界）")
    if has("record_conclusion"):
        misc.append("record_conclusion 把调查结论写回 NDR")
    if misc:
        parts.append("其它：" + "；".join(misc) + "。")

    if has("complete_task"):
        parts.append(
            "**交回前先 task_state 确认到底交回没有**（会话结束不等于任务完成）；"
            "complete_task 里用 anchors 说明这条结论影响哪些资产（如一条「这台是反代」"
            "要挂到它后面的后端），用 terminal_reason 说明是怎么结束的"
            "（concluded / budget_exhausted / tool_error / timeout / aborted）——"
            "否则 inconclusive 分不清「查了没证据」和「根本没查完」。"
        )

    writers = [
        name
        for name in ("record_conclusion", "complete_task", "add_task", "revoke_suppression")
        if has(name)
    ]
    if writers:
        parts.append(
            f"除 {'、'.join(writers)} 这几个写动作外全部只读；"
            "不提供任何主动探测或系统管理动作。精准抑制有护栏：至少 2 个匹配维度、"
            "证据引用必须是本会话真取回过的，影响面过大自动降级。"
        )
    else:
        parts.append("全部只读；不提供任何主动探测或系统管理动作。")
    return "\n".join(parts)


def build_server(profile: str = "full") -> MCPServer:
    """建 MCP 服务并注册工具（`profile` 决定工具面，见 `_TOOL_PROFILES`）。"""
    key = str(profile or "full").strip().lower()
    if key == "full":
        allowed: tuple[str, ...] | None = None  # 全量档：不裁剪
    elif key in _TOOL_PROFILES:
        allowed = _TOOL_PROFILES[key]
    else:
        # 档位名写错**必须报错**：悄悄退回全量等于把权限放开
        raise ValueError(
            f"未知工具档位：{profile!r}（可用：full、{'、'.join(_TOOL_PROFILES)}）"
        )
    server = MCPServer(
        name="shentong-ndr",
        title="深瞳 NDR",
        instructions=_instructions_for(allowed),
        version="0.1.0",
    )
    wanted = None if allowed is None else set(allowed)
    for fn in _ES_TOOL_FUNCS + _NDR_TOOL_FUNCS:
        name = fn.__name__
        if wanted is not None and name not in wanted:
            continue
        spec = es_tools.TOOLS.get(name) or ndr_tools.TOOLS.get(name) or {}
        server.add_tool(fn, name=name, description=_describe(name, spec))
    return server


def _describe(name: str, spec: dict[str, Any]) -> str:
    params = spec.get("params") or {}
    arg_text = "、".join(f"{k}（{v}）" for k, v in params.items()) or "无参数"
    return f"{spec.get('desc') or name}。参数：{arg_text}"


class BearerAuth:
    """纯 ASGI 的 Bearer 校验中间件。

    没用 SDK 自带的 `token_verifier`：那套是 OAuth 风格（要 issuer_url、resource_server_url），
    而我们只是「界面生成的静态令牌 + 随时吊销」，自己写一层更直接。
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path") or ""
        if path.rstrip("/") in ("/health", "/healthz"):
            # 容器健康检查：不带令牌（它只是探活，不碰数据）
            await JSONResponse({"status": "ok"})(scope, receive, send)
            return

        header = ""
        for key, value in scope.get("headers") or []:
            if key == b"authorization":
                header = value.decode("latin-1")
                break
        token = header[7:].strip() if header[:7].lower() == "bearer " else ""
        info = token_auth.verify(token) if token else None
        if info is None:
            await JSONResponse(
                {"error": "invalid_token", "detail": "令牌缺失、无效或已吊销"},
                status_code=_HTTP_UNAUTHORIZED,
                headers={"WWW-Authenticate": "Bearer"},
            )(scope, receive, send)
            return

        reset = _current_token.set(info.name or info.prefix or "?")
        reset_id = _current_token_id.set(info.id)
        try:
            await self.app(scope, receive, send)
        finally:
            _current_token_id.reset(reset_id)
            _current_token.reset(reset)


class ServerIdentityHeader:
    """给所有 MCP 响应加 `x-ndr-auth-id`：智能体逐次核对"这还是我绑定的那个项目吗"。

    为什么放在最外层：401/404 这类错误响应也要带 —— 令牌填错时运维正是需要知道
    "我连的是哪台 NDR"。响应头不参与鉴权（它只是身份声明）。
    """

    HEADER = b"x-ndr-auth-id"

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        value = system_license.auth_id().encode("ascii", "ignore")

        async def send_with_identity(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                if not any(key.lower() == self.HEADER for key, _ in headers):
                    headers.append((self.HEADER, value))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_identity)


class TieredMCP:
    """按路径前缀把请求分给不同**工具档位**的 FastMCP 应用，并同时跑两者的生命周期。

    为什么两个应用而不是"一个应用里按令牌过滤工具"：FastMCP 的工具表是**服务级**的，
    没有按连接/按令牌过滤的官方口子。两个应用共用同一份工具实现、同一层 Bearer 鉴权，
    比在网关里做字符串过滤可查、可测（`tests/py/test_mcp_profiles.py` 直接数工具数）。

    前缀匹配必须**最长优先**：`/mcp/full` 要先于 `/mcp` 命中，否则完整档永远进不去。
    """

    def __init__(self, tiers: list[tuple[str, ASGIApp]]) -> None:
        self.tiers = tiers

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(scope, receive, send)
            return
        if scope["type"] != "http":
            return
        path = scope.get("path") or ""
        for prefix, app in sorted(self.tiers, key=lambda kv: -len(kv[0])):
            if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
                inner = dict(scope)
                stripped = path[len(prefix) :] or "/"
                inner["path"] = stripped
                inner["root_path"] = (scope.get("root_path") or "") + prefix
                await app(inner, receive, send)
                return
        await JSONResponse({"error": "not_found"}, status_code=404)(scope, receive, send)

    async def _lifespan(self, scope: Scope, receive: Receive, send: Send) -> None:
        """两个档位都要启动（streamable-http 的会话管理器在 lifespan 里建）。"""
        from contextlib import AsyncExitStack

        async with AsyncExitStack() as stack:
            for _prefix, app in self.tiers:
                router = getattr(app, "router", None)
                lifespan = getattr(router, "lifespan_context", None)
                if lifespan is not None:
                    await stack.enter_async_context(lifespan(app))
            first = await receive()
            if first["type"] != "lifespan.startup":
                return
            await send({"type": "lifespan.startup.complete"})
            nxt = await receive()
            if nxt["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})


def build_app() -> ASGIApp:
    """MCP 的 ASGI 应用（最外层声明身份，其次校验令牌，再按档位分路径）。"""
    tiers: list[tuple[str, ASGIApp]] = [
        # 完整档先注册：前缀匹配最长优先，但列表顺序也保持"更具体在前"以免依赖排序
        (settings.mcp_full_path, _tier_app("full", "/")),
        (settings.mcp_path, _tier_app("analyst", "/")),
    ]
    return ServerIdentityHeader(BearerAuth(TieredMCP(tiers)))


def _tier_app(profile: str, path: str) -> ASGIApp:
    server = build_server(profile)
    return server.streamable_http_app(
        streamable_http_path=path,
        # 传 host 不是「监听地址」，而是关掉一份默认的 DNS-rebinding 白名单：不传它会
        # 按 127.0.0.1 限制 Host 头，容器之间用服务名互访（Host: ndr-mcp:8090）会被 421 拒掉。
        host=settings.mcp_host,
    )


def main() -> None:
    log.info(
        "MCP 服务启动：http://%s:%s%s（analyst 档 %d 个工具）/ %s（全量 %d 个），令牌前缀 %s",
        settings.mcp_host,
        settings.mcp_port,
        settings.mcp_path,
        len(_TOOL_PROFILES["analyst"]),
        settings.mcp_full_path,
        len(_ES_TOOL_FUNCS) + len(_NDR_TOOL_FUNCS),
        settings.mcp_token_prefix,
    )
    uvicorn.run(
        build_app(),
        host=settings.mcp_host,
        port=settings.mcp_port,
        log_level="info",
        access_log=False,
    )


if __name__ == "__main__":
    main()
