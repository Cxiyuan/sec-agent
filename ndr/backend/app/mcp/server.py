"""MCP 服务：智能体分析事件时用这里的工具查询、调查、写回结论。

挂在 `python -m app.mcp.server`，由 compose 的 `ndr-mcp` 服务拉起。

两层工具：
- `app.investigation.tools` 的 10 个「查 ES」工具（取数层，NDR 是数据的看门人）；
- `app.mcp.ndr_tools` 的 9 个 NDR 自身状态/配置/基线/写回工具。

**每个 MCP 工具都写成显式形参的函数**，这不是风格问题：MCP 的 inputSchema 由函数签名
推导，用 `**kwargs` 接参数会被当成「一个必填参数 kwargs」，调用必然报 validation error。
参数名与智能体提示词里的一致（`source`/`filters`/`start`/`end`…），所以包装层只做
「丢掉没传的参数」这一件事，默认值语义完全由下层决定。
"""

from __future__ import annotations

import json
import time
from contextvars import ContextVar
from typing import Any

import uvicorn
from mcp.server.mcpserver import MCPServer
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.config import settings
from app.mcp import auth as token_auth, calls, ndr_tools
from app.mcpapi import es_tools, get_logger

log = get_logger(__name__)

# 当前请求用的是哪个令牌（中间件写入，调用记录读取）。用 ContextVar 而不是传参：
# MCP 的调用链在 SDK 内部，没有地方能一路把身份带下去。
_current_token: ContextVar[str] = ContextVar("mcp_token_name", default="?")

_HTTP_UNAUTHORIZED = 401


def _clean(**kwargs: Any) -> dict[str, Any]:
    """丢掉没传的参数。

    MCP 客户端总会把 schema 里的参数补成默认值（空串/0/False），直接透传下去会覆盖
    下层的默认值。这里把「看起来没传」的值滤掉，只留下真正给了的。
    """
    return {k: v for k, v in kwargs.items() if v not in (None, "", 0, False, {}, [])}


def _run(name: str, args: dict[str, Any], *, native: bool = False) -> str:
    """执行一个工具，记一笔调用，回 JSON 文本（模型只吃文本）。"""
    started = time.perf_counter()
    if native:
        result = ndr_tools.execute(name, args)
    else:
        result = es_tools.execute(name, args, es_tools.ToolCtx())
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
)


def build_server() -> MCPServer:
    """建 MCP 服务并注册全部工具。"""
    server = MCPServer(
        name="shentong-ndr",
        title="深瞳 NDR",
        instructions=(
            "深瞳 NDR 的事件查询与调查接口。事件数据（Zeek 流量日志与 Wazuh 主机告警，"
            "已归一化成统一字段）只能通过这里查——本服务是数据的看门人。\n"
            "先调 describe_data 拿字段清单与真实时间范围，再按需 search_events /"
            " aggregate_events / timeline / net_flows / dns_queries / tls_fingerprints /"
            " web_requests / file_hashes 取证，raw_evidence 取原始文档。\n"
            "事件ID 与指纹来自推送载荷，可用 get_event 回查投递记录与已有结论；"
            "get_rule 取规则原文；detector_status / list_networks / list_filters 看 NDR 现状；"
            "要整批拉一段时间窗的条目自己筛（回溯）用 fetch_window。\n"
            "除 record_conclusion（写回结论）外全部只读，不提供任何管理动作。"
        ),
        version="0.1.0",
    )
    for fn in _ES_TOOL_FUNCS + _NDR_TOOL_FUNCS:
        name = fn.__name__
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
        try:
            await self.app(scope, receive, send)
        finally:
            _current_token.reset(reset)


def build_app() -> ASGIApp:
    """MCP 的 ASGI 应用（外面套一层令牌校验）。"""
    server = build_server()
    app = server.streamable_http_app(
        streamable_http_path=settings.mcp_path,
        # 传 host 不是「监听地址」，而是关掉一份默认的 DNS-rebinding 白名单：不传它会
        # 按 127.0.0.1 限制 Host 头，容器之间用服务名互访（Host: ndr-mcp:8090）会被 421 拒掉。
        host=settings.mcp_host,
    )
    return BearerAuth(app)


def main() -> None:
    log.info(
        "MCP 服务启动：http://%s:%s%s（工具 %d 个，令牌前缀 %s）",
        settings.mcp_host,
        settings.mcp_port,
        settings.mcp_path,
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
