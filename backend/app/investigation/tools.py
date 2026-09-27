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
from app.investigation import catalog, es_query, pg_query
from app.tools.context import ToolContext, is_public_ip
from app.workers.log import get_logger

log = get_logger(__name__)

SOURCES = ("zeek", "wazuh")
MAX_LIST = 50


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


def _filters_param(args: dict[str, Any], source: str) -> dict[str, Any]:
    """过滤对象：字段名/算子的合法性由 es_query 逐字段校验（未知字段 fail-closed）。"""
    _ = source
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


SOURCE_NAMES = ("zeek", "wazuh")


def _resolve_sources(args: dict[str, Any], default: tuple[str, ...] = SOURCES) -> list[str]:
    raw = _str_param(args, "source", default="")
    if not raw or raw == "both":
        return list(default)
    if raw not in SOURCES:
        raise ValueError("参数 source 只能是 zeek / wazuh / both")
    return [raw]


def _search_multi(
    sources: list[str],
    *,
    filters: dict[str, Any],
    keyword: str = "",
    start: Any = None,
    end: Any = None,
    limit: int = 200,
    sort: str = "desc",
    with_body: bool = False,
) -> dict[str, Any]:
    """跨来源检索：某个来源字段不存在/查询失败时记 note 跳过，不整体失败。"""
    hits: list[dict[str, Any]] = []
    per_source: dict[str, Any] = {}
    notes: list[str] = []
    for source in sources:
        try:
            result = es_query.search(
                source,
                filters=filters,
                keyword=keyword or None,
                start=start,
                end=end,
                limit=limit,
                sort=sort,
                with_body=with_body,
            )
        except es_query.QueryError as exc:
            notes.append(f"{source}: {exc}")
            continue
        per_source[source] = {
            "returned": result.get("returned"),
            "truncated": result.get("truncated"),
            "index": result.get("index"),
        }
        hits.extend(result.get("hits") or [])
    if sort == "asc":
        hits.sort(key=lambda h: str(h.get("ts") or ""))
    return {
        "returned": len(hits),
        "by_source": per_source,
        "notes": notes,
        "hits": hits[: max(1, limit)],
    }


def _agg_multi(
    sources: list[str],
    field: str,
    *,
    filters: dict[str, Any],
    start: Any = None,
    end: Any = None,
    size: int = 20,
) -> dict[str, Any]:
    out: dict[str, Any] = {"field": field, "by_source": {}, "notes": []}
    for source in sources:
        try:
            result = es_query.aggregate(
                source, field, filters=filters, start=start, end=end, size=size
            )
        except es_query.QueryError as exc:
            out["notes"].append(f"{source}: {exc}")
            continue
        out["by_source"][source] = {
            "doc_count": result.get("doc_count"),
            "buckets": result.get("buckets"),
        }
    return out


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
    sources = []
    for item in es_query.describe_sources():
        sources.append(
            {
                "source": item["source"],
                "index": item["index"],
                "earliest": (item.get("bounds") or {}).get("earliest"),
                "latest": (item.get("bounds") or {}).get("latest"),
                "fields": item.get("fields"),
                "agg_fields": item.get("agg_fields"),
                "bounds_error": (item.get("bounds") or {}).get("error"),
            }
        )
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
        "lookback_limit_days": settings.investigation_max_lookback_days,
        "hint": "时间参数用 ISO 格式；字段用 fields 里的逻辑名；未知字段会被拒绝并回传可用清单。",
    }


def _search_events(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    allowed = ("source", "filters", "keyword", "start", "end", "limit", "sort", "with_body")
    _check_unknown(args, allowed, "search_events")
    sources = _resolve_sources(args)
    filters = _filters_param(args, "both" if len(sources) > 1 else sources[0])
    result = _search_multi(
        sources,
        filters=filters,
        keyword=_str_param(args, "keyword"),
        start=args.get("start"),
        end=args.get("end"),
        limit=_int_param(args, "limit", default=200, lo=1, hi=catalog.max_docs()),
        sort="asc" if _str_param(args, "sort", default="desc") == "asc" else "desc",
        with_body=bool(args.get("with_body")),
    )
    ctx.register_refs(result)
    return result


def _aggregate_events(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    allowed = ("source", "field", "filters", "start", "end", "size")
    _check_unknown(args, allowed, "aggregate_events")
    field = _str_param(args, "field", required=True)
    sources = _resolve_sources(args)
    result = _agg_multi(
        sources,
        field,
        filters=_filters_param(args, "both" if len(sources) > 1 else sources[0]),
        start=args.get("start"),
        end=args.get("end"),
        size=_int_param(args, "size", default=20, lo=1, hi=200),
    )
    return result


def _timeline(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    allowed = ("entity", "start", "end", "limit", "source")
    _check_unknown(args, allowed, "timeline")
    entity = _str_param(args, "entity", required=True)
    limit = _int_param(args, "limit", default=100, lo=1, hi=catalog.max_docs())
    sources = _resolve_sources(args)
    # timeline 是“按实体拉全量时间线”，跨太久必然 ES 超时 → 窗口强约束（并在 notes 里说明）
    win_start, win_end, clipped = es_query.clamp_window(
        args.get("start"), args.get("end"), settings.investigation_timeline_max_hours
    )
    # 实体既可能是源也可能是目的：两边都查再合并去重
    merged: dict[str, Any] = {"entity": entity, "returned": 0, "hits": [], "notes": []}
    if clipped:
        merged["notes"].append(
            f"时间窗已限制为最近 {settings.investigation_timeline_max_hours} 小时"
            "（timeline 是全量查询，必须控制窗口否则会 ES 超时）"
        )
    seen: set[str] = set()
    for side in ("src_ip", "dst_ip"):
        part = _search_multi(
            sources,
            filters={side: entity},
            start=win_start,
            end=win_end,
            limit=limit,
            sort="asc",
        )
        merged["notes"].extend(part.get("notes") or [])
        for hit in part.get("hits") or []:
            ref = str(hit.get("ref") or "")
            if ref in seen:
                continue
            seen.add(ref)
            merged["hits"].append(hit)
    merged["hits"].sort(key=lambda h: str(h.get("ts") or ""))
    merged["hits"] = merged["hits"][:limit]
    merged["returned"] = len(merged["hits"])
    ctx.register_refs(merged)
    return merged


def _net_flows(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    allowed = ("ip", "start", "end", "top", "source")
    _check_unknown(args, allowed, "net_flows")
    ip = _str_param(args, "ip", required=True)
    top = _int_param(args, "top", default=15, lo=1, hi=100)
    sources = _resolve_sources(args)
    out: dict[str, Any] = {"ip": ip, "by_source": {}, "notes": []}
    for side in ("src_ip", "dst_ip"):
        for agg_field in ("dst_ip", "dst_port", "conn_state", "service", "proto"):
            part = _agg_multi(
                sources,
                agg_field,
                filters={side: ip},
                start=args.get("start"),
                end=args.get("end"),
                size=top,
            )
            out["notes"].extend(part.get("notes") or [])
            for source, payload in (part.get("by_source") or {}).items():
                out["by_source"].setdefault(source, {})[f"{side}→{agg_field}"] = {
                    "doc_count": payload.get("doc_count"),
                    "buckets": (payload.get("buckets") or [])[:top],
                }
    return out


def _dns_queries(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    allowed = ("domain", "ip", "start", "end", "limit", "source")
    _check_unknown(args, allowed, "dns_queries")
    domain = _str_param(args, "domain")
    ip = _str_param(args, "ip")
    if not domain and not ip:
        raise ValueError("domain 与 ip 至少要给一个")
    filters: dict[str, Any] = {"log_type": "dns"}
    if domain:
        filters["query"] = {"contains": domain}
    if ip:
        filters["src_ip"] = ip
    result = _search_multi(
        _resolve_sources(args),
        filters=filters,
        start=args.get("start"),
        end=args.get("end"),
        limit=_int_param(args, "limit", default=200, lo=1, hi=catalog.max_docs()),
        sort="asc",
    )
    ctx.register_refs(result)
    return result


def _tls_fingerprints(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    allowed = ("ip", "start", "end", "limit", "source")
    _check_unknown(args, allowed, "tls_fingerprints")
    ip = _str_param(args, "ip", required=True)
    result = _search_multi(
        _resolve_sources(args),
        filters={"log_type": "ssl", "src_ip": ip},
        start=args.get("start"),
        end=args.get("end"),
        limit=_int_param(args, "limit", default=100, lo=1, hi=catalog.max_docs()),
        sort="asc",
    )
    ja3 = _agg_multi(
        _resolve_sources(args),
        "ja3",
        filters={"log_type": "ssl", "src_ip": ip},
        start=args.get("start"),
        end=args.get("end"),
        size=20,
    )
    sni = _agg_multi(
        _resolve_sources(args),
        "server_name",
        filters={"log_type": "ssl", "src_ip": ip},
        start=args.get("start"),
        end=args.get("end"),
        size=20,
    )
    ctx.register_refs(result)
    return {
        "hits": result.get("hits"),
        "notes": result.get("notes"),
        "ja3_top": ja3.get("by_source"),
        "sni_top": sni.get("by_source"),
    }


def _web_requests(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    allowed = ("ip", "uri", "status_code", "start", "end", "limit", "include_body", "source")
    _check_unknown(args, allowed, "web_requests")
    filters: dict[str, Any] = {"log_type": "http"}
    ip = _str_param(args, "ip")
    uri = _str_param(args, "uri")
    status = _str_param(args, "status_code")
    if ip:
        filters["src_ip"] = ip
    if uri:
        filters["uri"] = {"contains": uri}
    if status:
        filters["status_code"] = status
    result = _search_multi(
        _resolve_sources(args, ("zeek",)),
        filters=filters,
        start=args.get("start"),
        end=args.get("end"),
        limit=_int_param(args, "limit", default=100, lo=1, hi=catalog.max_docs()),
        sort="asc",
        with_body=bool(args.get("include_body")),
    )
    ctx.register_refs(result)
    return result


def _file_hashes(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    allowed = ("ip", "hash", "filename", "start", "end", "limit", "source")
    _check_unknown(args, allowed, "file_hashes")
    filters: dict[str, Any] = {"log_type": "files"}
    ip = _str_param(args, "ip")
    hash_value = _str_param(args, "hash")
    filename = _str_param(args, "filename")
    if ip:
        filters["src_ip"] = ip
    if hash_value:
        filters["sha256"] = hash_value
    if filename:
        filters["filename"] = {"contains": filename}
    result = _search_multi(
        _resolve_sources(args, ("zeek",)),
        filters=filters,
        start=args.get("start"),
        end=args.get("end"),
        limit=_int_param(args, "limit", default=100, lo=1, hi=catalog.max_docs()),
        sort="asc",
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
        index_and_id = ref[3:]
        index, _, doc_id = index_and_id.partition("/")
        if not index or not doc_id:
            raise ValueError("es: 引用格式应为 es:<索引>/<文档id>")
        try:
            resp = es_query._es().get(
                index=index, id=doc_id, request_timeout=es_query.query_timeout()
            )
        except Exception as exc:
            raise ValueError(f"读取 ES 文档失败：{exc}") from exc
        source = resp.get("_source") or {}
        from app.ingestion.normalizer import _sanitize_raw

        item = {"ref": ref, "kind": "es_doc", "index": index, "raw": _sanitize_raw(source)}
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
    _check_unknown(args, ("kind", "keys"), "entity_profile")
    kind = _str_param(args, "kind", default="account")
    if kind not in ("account", "session"):
        raise ValueError("kind 只能是 account / session")
    keys = _list_param(args, "keys") or (ctx.case.get("keys") or {}).get("acct") or []
    rows = pg_query.entity_profiles(kind, [str(x) for x in keys])
    return {"kind": kind, "requested": len(keys), "found": len(rows), "profiles": rows}


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
            "source": "zeek|wazuh|both",
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
            "source": "zeek|wazuh|both",
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
        "desc": "账号/会话长期画像与异常点",
        "params": {"kind": "account|session", "keys": "账号或会话键数组"},
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
    except es_query.QueryError as exc:
        return {"error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        log.warning("调查工具 %s 执行失败: %s", name, exc)
        return {"error": f"工具执行失败：{exc}"}


def spec_for_api() -> dict[str, Any]:
    """给排错接口用的工具/字段元信息。"""
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
            for item in es_query.describe_sources()
        ],
        "stages": list(__import__("app.investigation.schema", fromlist=["STAGES"]).STAGES),
    }
