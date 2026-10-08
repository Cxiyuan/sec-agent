"""调查工具集：全部**只读**，统一签名 ``run(params, ctx) -> dict``。

两条纪律：
1. **参数校验 fail-closed**：未知参数、缺必填、类型不符都返回结构化错误（连同允许值一起
   回给模型让它自我纠正），绝不"猜一个默认值"往下跑。
2. **只读**：主动探测（port_scan/banner_grab）不进工具箱——取证阶段不该改变目标状态。
   需要探测请走技能库的人工开关（``active_scan_enabled``）。

证据引用在工具返回值里累积：任何 ``es:<index>/<id>`` 与 ``ev:<uuid>`` 都会登记到
``ctx.valid_refs``，``record_finding`` 只接受登记过的引用（防模型编造）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.config import settings
from app.investigation import mcp_client, pg_query
from app.tools.context import ToolContext, is_public_ip
from app.workers.log import get_logger

log = get_logger(__name__)

MAX_LIST = 50
# 单次查询的条数上限（limit / size / top 一律裁到这里）。以前取自 agent 侧 catalog.max_docs()，
# 现在取数在 NDR 侧，本地只留一个兜底：不把过大的值转发出去，真正的裁剪也在 NDR 侧。
MAX_ROWS = 2000


@dataclass
class ToolCtx:
    """一次调查的运行时上下文（工具共享）。"""

    case: dict[str, Any] = field(default_factory=dict)
    scope_cidrs: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    gaps: list[dict[str, Any]] = field(default_factory=list)
    raw_evidence: list[dict[str, Any]] = field(default_factory=list)
    valid_refs: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)

    def register_refs(self, *payloads: Any) -> None:
        """登记本轮可引用的证据引用（递归找 ref 字段）。"""
        stack = list(payloads)
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                ref = node.get("ref")
                if isinstance(ref, str) and ref.startswith(("es:", "ev:")):
                    self.valid_refs.add(ref)
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)


# ---------- 参数校验 ----------


def _params(args: Any) -> dict[str, Any]:
    if args is None:
        return {}
    if not isinstance(args, dict):
        raise TypeError("参数必须是对象（JSON object）")
    return args


def _str_param(
    args: dict[str, Any], name: str, *, required: bool = False, default: str = ""
) -> str:
    value = args.get(name, default)
    if value in (None, ""):
        if required:
            raise ValueError(f"缺少必填参数 {name}")
        return default
    if not isinstance(value, (str, int, float)):
        raise TypeError(f"参数 {name} 需要字符串")
    return str(value).strip()


def _int_param(args: dict[str, Any], name: str, *, default: int, lo: int, hi: int) -> int:
    value = args.get(name, default)
    if value in (None, ""):
        return default
    try:
        num = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"参数 {name} 需要整数") from exc
    return max(lo, min(num, hi))


def _list_param(args: dict[str, Any], name: str, *, required: bool = False) -> list[str]:
    value = args.get(name)
    if value in (None, ""):
        if required:
            raise ValueError(f"缺少必填参数 {name}")
        return []
    if isinstance(value, (str, int, float)):
        items = [value]
    elif isinstance(value, list):
        items = value
    else:
        raise TypeError(f"参数 {name} 需要字符串或字符串数组")
    return [str(x).strip() for x in items[:MAX_LIST] if str(x).strip()]


def _filters_param(args: dict[str, Any]) -> dict[str, Any]:
    """过滤对象：字段名/算子的合法性由 NDR 侧逐字段校验（未知字段 fail-closed）。"""
    value = args.get("filters")
    if value in (None, ""):
        return {}
    if not isinstance(value, dict):
        raise TypeError('参数 filters 需要对象，如 {"src_ip": "1.2.3.4"}')
    return value


def _check_unknown(args: dict[str, Any], allowed: tuple[str, ...], tool: str) -> None:
    unknown = sorted(set(args) - set(allowed))
    if unknown:
        raise ValueError(f"工具 {tool} 不支持参数 {unknown}。可用参数：{', '.join(allowed)}")


def _opt_int(args: dict[str, Any], name: str, *, lo: int, hi: int) -> int | None:
    """给了才校验并裁剪；没给返回 None——真正的默认值在 NDR 侧，不在本地写死第二份。"""
    if args.get(name) in (None, ""):
        return None
    return _int_param(args, name, default=lo, lo=lo, hi=hi)


def _clean_params(**kwargs: Any) -> dict[str, Any]:
    """丢掉「没给」的参数（None / 空串 / 0 / False / 空容器）。

    NDR 侧同名工具对每个参数都有自己的默认值，塞空值等于把它的默认值覆盖成空，
    所以没给的一律不发。
    """
    empty = (None, "", 0, False, {}, [])
    return {key: value for key, value in kwargs.items() if value not in empty}


def _present_ips(ctx: ToolCtx) -> list[str]:
    keys = ctx.case.get("keys") or {}
    return sorted({*(keys.get("ip") or []), *(keys.get("host") or [])})


def _tool_context(ctx: ToolCtx) -> ToolContext:
    """把案件键转成既有工具（情报/IOC）需要的 ToolContext。"""
    ips = _present_ips(ctx)
    texts = [str(x) for x in (ctx.case.get("texts") or [])]
    return ToolContext(
        src_ips=ips,
        dst_ips=sorted({str(x) for x in (ctx.case.get("dst_ips") or [])}),
        external_ips=[ip for ip in ips if is_public_ip(ip)],
        text="\n".join(texts)[:20000],
        scope_cidrs=ctx.scope_cidrs,
    )


# ---------- 工具实现 ----------


def _describe_data(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    _check_unknown(args, (), "describe_data")
    # 数据源描述（时间范围/字段清单）来自 NDR 的 MCP 工具；案件已知事实与中文提示留在智能体侧，
    # 不能被 NDR 返回的那份覆盖（NDR 侧的 ToolCtx 是新建的空上下文，看不到案件）。
    described = mcp_client.call("describe_data", {})
    err = described.get("error")
    if err:
        # 拿不到数据源描述时保持原语义（报错交由 execute 统一捕获）
        raise ValueError(str(err))
    sources = described.get("sources")
    if not isinstance(sources, list):
        sources = []
    lookback = described.get("lookback_limit_days")
    return {
        "sources": sources,
        "case": {
            "attacker_key": ctx.case.get("attacker_key"),
            "keys": ctx.case.get("keys"),
            "src_ips": ctx.case.get("src_ips"),
            "dst_ips": ctx.case.get("dst_ips"),
            "severity": ctx.case.get("severity"),
            "first_seen": ctx.case.get("first_seen"),
            "last_seen": ctx.case.get("last_seen"),
            "group_count": ctx.case.get("group_count"),
        },
        # 透传 NDR 的值：它跟着**运行时保留期**走（后台改保留期不用重启），
        # 用本地静态配置覆盖会出现「实际能查 45 天、模型被告知只能查 7 天」。
        "lookback_limit_days": (
            lookback if isinstance(lookback, int) else settings.investigation_max_lookback_days
        ),
        "hint": "时间参数用 ISO 格式；字段用 fields 里的逻辑名；未知字段会被拒绝并回传可用清单。",
    }


def _search_events(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    allowed = ("source", "filters", "keyword", "start", "end", "limit", "sort", "with_body")
    _check_unknown(args, allowed, "search_events")
    # 参数在这里 fail-closed 校验，取数与跨来源合并交给 NDR 侧的同名 MCP 工具
    sort = _str_param(args, "sort")
    result = mcp_client.call(
        "search_events",
        _clean_params(
            source=_str_param(args, "source"),
            filters=_filters_param(args),
            keyword=_str_param(args, "keyword"),
            start=_str_param(args, "start"),
            end=_str_param(args, "end"),
            limit=_opt_int(args, "limit", lo=1, hi=MAX_ROWS),
            sort="asc" if sort == "asc" else ("desc" if sort else ""),
            with_body=bool(args.get("with_body")),
        ),
    )
    ctx.register_refs(result)
    return result


def _aggregate_events(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    allowed = ("source", "field", "filters", "start", "end", "size")
    _check_unknown(args, allowed, "aggregate_events")
    field = _str_param(args, "field", required=True)
    return mcp_client.call(
        "aggregate_events",
        _clean_params(
            field=field,
            source=_str_param(args, "source"),
            filters=_filters_param(args),
            start=_str_param(args, "start"),
            end=_str_param(args, "end"),
            size=_opt_int(args, "size", lo=1, hi=200),
        ),
    )


def _timeline(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    allowed = ("entity", "start", "end", "limit", "source")
    _check_unknown(args, allowed, "timeline")
    entity = _str_param(args, "entity", required=True)
    # 时间窗强约束、源+目的两侧合并去重都由 NDR 侧同名工具做
    # （窗口被裁时它会在 notes 里说明，原因与提示文案与改动前一致）。
    result = mcp_client.call(
        "timeline",
        _clean_params(
            entity=entity,
            source=_str_param(args, "source"),
            start=_str_param(args, "start"),
            end=_str_param(args, "end"),
            limit=_opt_int(args, "limit", lo=1, hi=MAX_ROWS),
        ),
    )
    ctx.register_refs(result)
    return result


def _net_flows(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    allowed = ("ip", "start", "end", "top", "source")
    _check_unknown(args, allowed, "net_flows")
    ip = _str_param(args, "ip", required=True)
    # 两侧（src/dst）× 五个聚合字段的画像由 NDR 侧同名工具算，返回结构（ip/by_source/notes）不变。
    return mcp_client.call(
        "net_flows",
        _clean_params(
            ip=ip,
            source=_str_param(args, "source"),
            start=_str_param(args, "start"),
            end=_str_param(args, "end"),
            top=_opt_int(args, "top", lo=1, hi=100),
        ),
    )


def _dns_queries(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    allowed = ("domain", "ip", "start", "end", "limit", "source")
    _check_unknown(args, allowed, "dns_queries")
    domain = _str_param(args, "domain")
    ip = _str_param(args, "ip")
    if not domain and not ip:
        raise ValueError("domain 与 ip 至少要给一个")
    # log_type=dns / domain→query contains / ip→src_ip 这几个过滤条件由 NDR 侧同名工具自建。
    result = mcp_client.call(
        "dns_queries",
        _clean_params(
            domain=domain,
            ip=ip,
            source=_str_param(args, "source"),
            start=_str_param(args, "start"),
            end=_str_param(args, "end"),
            limit=_opt_int(args, "limit", lo=1, hi=MAX_ROWS),
        ),
    )
    ctx.register_refs(result)
    return result


def _tls_fingerprints(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    allowed = ("ip", "start", "end", "limit", "source")
    _check_unknown(args, allowed, "tls_fingerprints")
    ip = _str_param(args, "ip", required=True)
    # 会话明细 + JA3/SNI top 由 NDR 侧同名工具一起算（返回 hits/notes/ja3_top/sni_top）。
    result = mcp_client.call(
        "tls_fingerprints",
        _clean_params(
            ip=ip,
            source=_str_param(args, "source"),
            start=_str_param(args, "start"),
            end=_str_param(args, "end"),
            limit=_opt_int(args, "limit", lo=1, hi=MAX_ROWS),
        ),
    )
    ctx.register_refs(result)
    return result


def _web_requests(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    allowed = ("ip", "uri", "status_code", "start", "end", "limit", "include_body", "source")
    _check_unknown(args, allowed, "web_requests")
    # log_type=http / ip→src_ip / uri→query contains / status_code 由 NDR 侧自建；
    # 不给 source 时 NDR 侧默认只查 zeek（与改动前的默认来源一致）。
    result = mcp_client.call(
        "web_requests",
        _clean_params(
            ip=_str_param(args, "ip"),
            uri=_str_param(args, "uri"),
            status_code=_str_param(args, "status_code"),
            include_body=bool(args.get("include_body")),
            source=_str_param(args, "source"),
            start=_str_param(args, "start"),
            end=_str_param(args, "end"),
            limit=_opt_int(args, "limit", lo=1, hi=MAX_ROWS),
        ),
    )
    ctx.register_refs(result)
    return result


def _file_hashes(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    allowed = ("ip", "hash", "filename", "start", "end", "limit", "source")
    _check_unknown(args, allowed, "file_hashes")
    # log_type=files / ip→src_ip / sha256 / filename contains 由 NDR 侧自建；
    # 不给 source 时 NDR 侧默认只查 zeek（与改动前的默认来源一致）。
    result = mcp_client.call(
        "file_hashes",
        _clean_params(
            ip=_str_param(args, "ip"),
            hash=_str_param(args, "hash"),
            filename=_str_param(args, "filename"),
            source=_str_param(args, "source"),
            start=_str_param(args, "start"),
            end=_str_param(args, "end"),
            limit=_opt_int(args, "limit", lo=1, hi=MAX_ROWS),
        ),
    )
    ctx.register_refs(result)
    return result


def _raw_evidence(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    allowed = ("ref",)
    _check_unknown(args, allowed, "raw_evidence")
    ref = _str_param(args, "ref", required=True)
    if not ref.startswith(("ev:", "es:")):
        raise ValueError("ref 必须是 ev:<事件id> 或 es:<索引>/<文档id>")
    if ctx.valid_refs and ref not in ctx.valid_refs:
        raise ValueError("该 ref 不在本轮已查到的证据里（不能凭空引用）。请先用查询工具拿到 ref。")
    limit = max(1, settings.investigation_raw_evidence_max)
    if len(ctx.raw_evidence) >= limit:
        return {"note": f"原始证据已达上限 {limit} 条", "fetched": len(ctx.raw_evidence)}
    if ref.startswith("ev:"):
        row = pg_query.event_by_id(ref)
        if row is None:
            raise ValueError(f"未找到事件 {ref}")
        item = {"ref": ref, "kind": "event", **row}
    else:
        index, _, doc_id = ref[3:].partition("/")
        if not index or not doc_id:
            raise ValueError("es: 引用格式应为 es:<索引>/<文档id>")
        # 原始文档由 NDR 侧去取（并已在那里脱敏），agent 不再自己连 ES、也不再本地 _sanitize_raw
        result = mcp_client.call("raw_evidence", {"ref": ref})
        if isinstance(result.get("error"), str):
            return result
        item = result.get("item")
        if not isinstance(item, dict):
            return {"error": f"读取原始证据失败：{ref}"}
    ctx.raw_evidence.append(item)
    return {"fetched": len(ctx.raw_evidence), "item": item}


def _asset_lookup(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    _check_unknown(args, ("ips",), "asset_lookup")
    ips = _list_param(args, "ips") or (ctx.case.get("dst_ips") or [])
    rows = pg_query.assets_by_ips([str(x) for x in ips])
    return {"requested": len(ips), "found": len(rows), "assets": rows}


def _topology_neighbors(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    _check_unknown(args, ("ips", "hops"), "topology_neighbors")
    ips = _list_param(args, "ips") or _present_ips(ctx)
    return pg_query.topology_neighbors(
        [str(x) for x in ips], hops=_int_param(args, "hops", default=1, lo=1, hi=3)
    )


def _entity_profile(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    """账号/会话长期画像：第 8 期起基线在 NDR 侧算，这里转发到 NDR 的 MCP 工具。"""
    _check_unknown(args, ("kind", "keys", "min_risk"), "entity_profile")
    kind = _str_param(args, "kind", default="account")
    if kind not in ("account", "session"):
        raise ValueError("kind 只能是 account / session")
    keys = _list_param(args, "keys") or (ctx.case.get("keys") or {}).get("acct") or []
    payload: dict[str, Any] = {"kind": kind}
    if keys:
        payload["keys"] = [str(x) for x in keys]
    min_risk = args.get("min_risk")
    if min_risk is not None:
        try:
            payload["min_risk"] = min(max(float(min_risk), 0.0), 1.0)
        except (TypeError, ValueError):
            raise ValueError("min_risk 需要 0~1 的小数") from None
    result = mcp_client.call("entity_profile", payload)
    if not isinstance(result, dict):
        return {"kind": kind, "result": result}
    return {"kind": kind, "requested": len(keys), **result}


def _get_rule(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    """取检测规则原文（规则条件/严重度/优先级）。

    为什么需要它：摘要只带规则名与严重度，不带条件——模型无法回答「这条为什么被判可疑」。
    NDR 是规则的唯一事实源（`get_rule` 是它的 MCP 工具），所以转发过去而不是用本地副本。
    """
    _check_unknown(args, ("name", "rule_id"), "get_rule")
    name = _str_param(args, "name")
    rule_id = _str_param(args, "rule_id")
    if not name and not rule_id:
        raise ValueError("name 与 rule_id 至少要给一个（摘要里带的是规则名）")
    payload: dict[str, Any] = {}
    if name:
        payload["name"] = name
    if rule_id:
        payload["rule_id"] = rule_id
    return mcp_client.call("get_rule", payload)


def _list_filters(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    """取 NDR 的两道过滤闸门（降噪过滤 + 排除过滤）。

    为什么必须能调到：这两类配置都会让「某条事件没有告警」。看不到它们，
    就只能把「被过滤掉」当成「本来就没事」—— 漏报的锅会扣错地方。
    """
    _check_unknown(args, (), "list_filters")
    return mcp_client.call("list_filters", {})


def _file_content(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    """取提取件内容（有界）或元数据；按 fuid（事件里的 extracted/fuid 字段）。

    文件提取与下载通道只在 NDR 侧（提取件落在 Zeek 容器目录），这里转发到 NDR 的
    `file_content`；要完整文件用返回里的 download 路径（需 NDR 登录）。
    """
    _check_unknown(args, ("fuid", "encoding", "max_bytes"), "file_content")
    payload: dict[str, Any] = {"fuid": _str_param(args, "fuid", required=True)}
    encoding = _str_param(args, "encoding")
    if encoding:
        payload["encoding"] = encoding
    max_bytes = _opt_int(args, "max_bytes", lo=1, hi=1048576)
    if max_bytes is not None:
        payload["max_bytes"] = max_bytes
    return mcp_client.call("file_content", payload)


def _memory_recall(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    _check_unknown(args, ("ips", "limit"), "memory_recall")
    ips = _list_param(args, "ips") or _present_ips(ctx)
    return {
        "ips": ips,
        "memories": pg_query.memory_recall(
            [str(x) for x in ips], limit=_int_param(args, "limit", default=8, lo=1, hi=20)
        ),
    }


def _group_history(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    _check_unknown(args, ("ips", "days"), "group_history")
    ips = _list_param(args, "ips") or _present_ips(ctx)
    return {
        "ips": ips,
        "groups": pg_query.group_history(
            [str(x) for x in ips], days=_int_param(args, "days", default=30, lo=1, hi=365)
        ),
    }


def _threat_intel(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    _check_unknown(args, ("indicator", "kind"), "threat_intel")
    indicator = _str_param(args, "indicator", required=True)
    kind = _str_param(args, "kind", default="auto")
    tool_ctx = _tool_context(ctx)
    if kind in ("auto", "ip"):
        tool_ctx.external_ips = [indicator]
    if kind in ("auto", "domain"):
        tool_ctx.domains = [indicator]
    from app.tools.intel import dns_resolve, geoip_lookup, rdap_lookup, threat_lookup

    if kind == "ip":
        return {
            "ip": indicator,
            "geo": geoip_lookup(tool_ctx),
            "rdap": rdap_lookup(tool_ctx),
            "reputation": threat_lookup(tool_ctx),
        }
    if kind == "domain":
        return {
            "domain": indicator,
            "dns": dns_resolve(tool_ctx),
            "rdap": rdap_lookup(tool_ctx),
            "reputation": threat_lookup(tool_ctx),
        }
    if kind == "hash":
        tool_ctx.text = indicator
        return {"hash": indicator, "reputation": threat_lookup(tool_ctx)}
    if kind == "url":
        tool_ctx.text = indicator
        return {"url": indicator, "reputation": threat_lookup(tool_ctx)}
    raise ValueError("kind 只能是 auto / ip / domain / hash / url")


def _record_finding(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    allowed = ("stage", "description", "evidence_refs", "assets", "time_start", "time_end")
    _check_unknown(args, allowed, "record_finding")
    stage = _str_param(args, "stage", required=True)
    from app.investigation.schema import STAGES

    if stage not in STAGES:
        raise ValueError(f"stage 必须是 {'/'.join(STAGES)} 之一")
    refs = _list_param(args, "evidence_refs", required=True)
    if not refs:
        raise ValueError("record_finding 必须带 evidence_refs（无证据的结论不保留）")
    invalid = [r for r in refs if r not in ctx.valid_refs]
    if invalid:
        if ctx.valid_refs:
            hint = f"只能用本轮查询结果里的 ref（例如 {sorted(ctx.valid_refs)[:5]}）"
        else:
            # 一条证据都还没有时给可执行的指引（否则模型会反复编 ref）
            hint = (
                "本轮还没有任何证据引用——请先用查询工具拿到 ref"
                "（search_events / timeline / net_flows / dns_queries / aggregate_events 等）"
            )
        raise ValueError(f"引用无效：{invalid}。{hint}；不能凭空引用。")
    ctx.findings.append(
        {
            "stage": stage,
            "description": _str_param(args, "description")[:600],
            "evidence_refs": refs[:20],
            "assets": _list_param(args, "assets")[:20],
            "time_start": _str_param(args, "time_start") or None,
            "time_end": _str_param(args, "time_end") or None,
        }
    )
    return {"ok": True, "recorded": len(ctx.findings), "stage": stage}


def _note_gap(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    _check_unknown(args, ("missing", "why", "next_action"), "note_gap")
    ctx.gaps.append(
        {
            "missing": _str_param(args, "missing", required=True)[:300],
            "why": _str_param(args, "why")[:300],
            "next_action": _str_param(args, "next_action")[:300],
        }
    )
    return {"ok": True, "gaps": len(ctx.gaps)}


TOOLS: dict[str, dict[str, Any]] = {
    "describe_data": {
        "run": _describe_data,
        "desc": "可用数据源、真实时间范围、字段清单与案件已知事实（先调它避免编字段）",
        "params": {},
    },
    "search_events": {
        "run": _search_events,
        "desc": "定向检索事件（时间范围 + 字段过滤 + 关键词）",
        "params": {
            "source": "zeek|suricata|both",
            "filters": "对象，字段用逻辑名",
            "keyword": "自由文本",
            "start": "ISO 时间",
            "end": "ISO 时间",
            "limit": "条数",
            "sort": "asc|desc",
            "with_body": "是否带 HTTP 正文",
        },
    },
    "aggregate_events": {
        "run": _aggregate_events,
        "desc": "按字段 top-N 聚合（找横向目标/外联目的地/端口分布）",
        "params": {
            "field": "可聚合字段（见 describe_data）",
            "source": "zeek|suricata|both",
            "filters": "对象",
            "start": "ISO",
            "end": "ISO",
            "size": "桶数",
        },
    },
    "timeline": {
        "run": _timeline,
        "desc": "某 IP 的完整时间线（源+目的两侧合并，按时间升序）",
        "params": {"entity": "IP", "start": "ISO", "end": "ISO", "limit": "条数"},
    },
    "net_flows": {
        "run": _net_flows,
        "desc": "网络侧画像：该 IP 的目的地/端口/连接状态/服务分布（看向哪打、从哪来）",
        "params": {"ip": "IP", "start": "ISO", "end": "ISO", "top": "桶数"},
    },
    "dns_queries": {
        "run": _dns_queries,
        "desc": "DNS 查询记录（隧道、DGA、C2 域名解析）",
        "params": {
            "domain": "域名（模糊）",
            "ip": "发起解析的主机",
            "start": "ISO",
            "end": "ISO",
            "limit": "条数",
        },
    },
    "tls_fingerprints": {
        "run": _tls_fingerprints,
        "desc": "TLS 会话与 JA3/SNI 指纹（识别 C2）",
        "params": {"ip": "IP", "start": "ISO", "end": "ISO", "limit": "条数"},
    },
    "web_requests": {
        "run": _web_requests,
        "desc": "HTTP 请求（含方法/UA/状态码；可选请求正文）",
        "params": {
            "ip": "源 IP",
            "uri": "URL 片段",
            "status_code": "状态码",
            "include_body": "是否带正文",
            "start": "ISO",
            "end": "ISO",
            "limit": "条数",
        },
    },
    "file_hashes": {
        "run": _file_hashes,
        "desc": "文件传输与哈希（落地文件、外泄文件）",
        "params": {
            "ip": "IP",
            "hash": "sha256",
            "filename": "文件名片段",
            "start": "ISO",
            "end": "ISO",
            "limit": "条数",
        },
    },
    "raw_evidence": {
        "run": _raw_evidence,
        "desc": "取原始证据文档（只能引用本轮已查到的 ref；用于证据包）",
        "params": {"ref": "ev:<id> 或 es:<index>/<id>"},
    },
    "asset_lookup": {
        "run": _asset_lookup,
        "desc": "资产与业务背景（重要性/网络区/所属系统）",
        "params": {"ips": "IP 数组"},
    },
    "topology_neighbors": {
        "run": _topology_neighbors,
        "desc": "网络拓扑上的位置与上下游（判断横向路径）",
        "params": {"ips": "IP 数组", "hops": "跳数 1-3"},
    },
    "entity_profile": {
        "run": _entity_profile,
        "desc": "账号/会话长期画像与异常点（基线在 NDR 侧算）",
        "params": {
            "kind": "account|session",
            "keys": "账号或会话键数组",
            "min_risk": "只返回风险不低于该值（0~1，可选）",
        },
    },
    "get_rule": {
        "run": _get_rule,
        "desc": "取检测规则原文（条件/严重度/优先级）——回答「这条摘要为什么被判可疑」",
        "params": {"name": "规则名（与摘要里的完全一致）", "rule_id": "规则 ID（可选）"},
    },
    "list_filters": {
        "run": _list_filters,
        "desc": "NDR 的两道过滤闸门（降噪过滤=不进检测器；排除过滤=跳过分析）",
        "params": {},
    },
    "file_content": {
        "run": _file_content,
        "desc": "取提取件（落地/外泄的文件）内容或元数据（有界）；fuid 来自事件的 extracted 字段",
        "params": {
            "fuid": "文件 id（事件的 extracted/fuid 字段）",
            "encoding": "text|base64（默认 base64）",
            "max_bytes": "最多读多少字节（默认 64KiB，上限 1MiB）",
        },
    },
    "memory_recall": {
        "run": _memory_recall,
        "desc": "历史分析记忆（同一对象以前的结论与持续性）",
        "params": {"ips": "IP 数组", "limit": "条数"},
    },
    "group_history": {
        "run": _group_history,
        "desc": "该 IP 的历史事件组与定级（跨时间桶，路径主线索）",
        "params": {"ips": "IP 数组", "days": "天数"},
    },
    "threat_intel": {
        "run": _threat_intel,
        "desc": "威胁情报（GeoIP/RDAP/DNS/恶意 IOC 信誉）",
        "params": {"indicator": "IP/域名/hash/URL", "kind": "auto|ip|domain|hash|url"},
    },
    "record_finding": {
        "run": _record_finding,
        "desc": "记录一个攻击阶段与它的证据引用（必须带 ref，否则被拒）",
        "params": {
            "stage": "侦察|入侵|立足|横向|外泄",
            "description": "说明",
            "evidence_refs": "ref 数组",
            "assets": "涉及资产 IP 数组",
        },
    },
    "note_gap": {
        "run": _note_gap,
        "desc": "记录无法验证的点与建议的下一步",
        "params": {"missing": "缺什么", "why": "为什么查不到", "next_action": "建议动作"},
    },
}


def tool_names() -> list[str]:
    return sorted(TOOLS)


def tool_catalog_text(*, max_chars: int = 2600) -> str:
    """给模型看的工具清单（紧凑文本）。"""
    lines: list[str] = []
    for name in sorted(TOOLS):
        spec = TOOLS[name]
        params = spec.get("params") or {}
        arg_text = ", ".join(f"{k}: {v}" for k, v in params.items()) or "无参数"
        lines.append(f"- {name}（{arg_text}）：{spec['desc']}")
    return "\n".join(lines)[:max_chars]


def execute(name: str, args: Any, ctx: ToolCtx) -> dict[str, Any]:
    """执行工具：参数/查询错误都转成结构化观察（不抛给循环，让模型自我纠正）。"""
    spec = TOOLS.get(name)
    if spec is None:
        return {"error": f"未知工具 {name}。可用工具：{', '.join(tool_names())}"}
    try:
        params = _params(args)
        result = spec["run"](params, ctx)
        ctx.register_refs(result)
        return result if isinstance(result, dict) else {"result": result}
    except ValueError as exc:
        return {"error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        log.warning("调查工具 %s 执行失败: %s", name, exc)
        return {"error": f"工具执行失败：{exc}"}


def spec_for_api() -> dict[str, Any]:
    """给排错接口用的工具/字段元信息。"""
    # 数据源描述走 NDR 的 MCP 工具；拿不到就回空 sources（这个接口只给排错页看清单）。
    described = mcp_client.call("describe_data", {})
    remote_sources = described.get("sources")
    if not isinstance(remote_sources, list):
        remote_sources = []
    return {
        "tools": {
            name: {"desc": TOOLS[name]["desc"], "params": TOOLS[name]["params"]}
            for name in tool_names()
        },
        "sources": [
            {
                "source": item["source"],
                "index": item["index"],
                "fields": item["fields"],
                "agg_fields": item["agg_fields"],
            }
            for item in remote_sources
            if isinstance(item, dict)
        ],
        "stages": list(__import__("app.investigation.schema", fromlist=["STAGES"]).STAGES),
    }
