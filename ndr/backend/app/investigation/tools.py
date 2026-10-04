"""调查工具集（NDR 侧）：全部**只读**，统一签名 ``run(params, ctx) -> dict``。

两条纪律：
1. **参数校验 fail-closed**：未知参数、缺必填、类型不符都返回结构化错误（连同允许值一起
   回给模型让它自我纠正），绝不"猜一个默认值"往下跑。
2. **只读**：主动探测（port_scan/banner_grab）不进工具箱——取证阶段不该改变目标状态。

证据引用在工具返回值里累积：任何 ``es:<index>/<id>`` 与 ``ev:<uuid>`` 都会登记到
``ctx.valid_refs``，``_raw_evidence`` 取原始证据时会核对引用（防模型编造不存在的引用）。

与 agent 侧那版的差别：这里只留**走 ES 的 10 个工具**（取数层已搬到 NDR），
依赖智能体自身数据（案件库/资产/情报/记忆）的工具留在 agent 侧；
``source`` 参数保留原语义，但不再选索引，而是过滤统一字段 ``source_system``
（见 ``es_query.source_clause``）。工具在这里就是普通 Python 函数 + ``TOOLS`` 注册表，
不引入 MCP / FastAPI 依赖，后面挂 MCP 时直接遍历注册表即可。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.ingestion.es_config import current as es_config_current
from app.investigation import catalog, es_query
from app.workers.log import get_logger

log = get_logger(__name__)

SOURCES = catalog.SOURCES
# 单次调查最多留几份原始证据（防把整个索引塞进证据包）
RAW_EVIDENCE_MAX = 20


@dataclass
class ToolCtx:
    """一次调查的运行时上下文（工具共享）。

    只留**真的被读**的字段：``raw_evidence``（已取回的证据）与 ``valid_refs``
    （引用白名单）。NDR 侧没有 agent 侧的 ``record_finding`` / ``note_gap``
    （那是智能体自己的调查流程）；原来的 ``case`` 字段在 MCP 层永远是空的
    （``describe_data`` 不接受参数、拿不到案件），属于死字段，已删（2026-10 MCP QA）。
    """

    raw_evidence: list[dict[str, Any]] = field(default_factory=list)
    valid_refs: set[str] = field(default_factory=set)

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


def _filters_param(args: dict[str, Any]) -> dict[str, Any]:
    """过滤对象：字段名/算子的合法性由 es_query 逐字段校验（未知字段 fail-closed）。

    这里不再按来源分开校验：统一结构下各来源文档字段一致（某来源没有的只是值为空），
    字段清单只有一个，来源差异由 source_system 过滤表达。
    """
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


def _resolve_sources(args: dict[str, Any], default: tuple[str, ...] = SOURCES) -> list[str]:
    """``source`` 参数 → 要查的来源列表（both/缺省 = 两个都查）。"""
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
    """跨来源检索：某个来源查询失败时记 note 跳过，不整体失败。

    两个来源现在是同一族索引，逐个查只为让 ``by_source`` 的返回结构保持不变
    （模型与调用样例都按这个结构读），并且某个来源出错时不牵连另一个。
    """
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
        fetched = list(result.get("hits") or [])
        per_source[source] = {
            # returned 在合并截断之后按最终列表重算（见下）：以前这里是「本来源截断前
            # 取回条数」，与真实返回不一致，模型会以为 Wazuh 的命中都在 hits 里。
            "returned": 0,
            "fetched": len(fetched),
            "truncated": result.get("truncated"),
            "index": result.get("index"),
        }
        hits.extend(fetched)

    # 合并后统一按时间排序再截断。以前是「按来源 extend 完直接 hits[:limit]」：
    # 默认 desc 下排在后面的来源（wazuh）会被整段丢掉，而 by_source 还报着 returned=N
    # ——智能体因此永远看不到 Wazuh 证据（来源顺序 zeek→wazuh 是写死的）。
    hits.sort(key=lambda h: str(h.get("ts") or ""), reverse=sort != "asc")
    kept = hits[: max(1, limit)]
    for row in kept:
        name = str(row.get("source_system") or "")
        if name in per_source:
            per_source[name]["returned"] = int(per_source[name]["returned"]) + 1
    dropped = len(hits) - len(kept)
    if dropped > 0:
        notes.append(
            f"各来源合并后共 {len(hits)} 条，按时间保留 {len(kept)} 条（截掉 {dropped} 条）；"
            "by_source.returned 是最终返回条数，fetched 是该来源实际取回条数。"
        )
    return {
        "returned": len(kept),
        "fetched": len(hits),
        "truncated": dropped > 0,
        "by_source": per_source,
        "notes": notes,
        "hits": kept,
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
        "lookback_limit_days": es_query.max_lookback_days(),
        "hint": "时间参数用 ISO 格式；字段用 fields 里的统一字段名；未知字段会被拒绝并回传可用清单。",
    }


def _search_events(args: dict[str, Any], ctx: ToolCtx) -> dict[str, Any]:
    allowed = ("source", "filters", "keyword", "start", "end", "limit", "sort", "with_body")
    _check_unknown(args, allowed, "search_events")
    result = _search_multi(
        _resolve_sources(args),
        filters=_filters_param(args),
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
    result = _agg_multi(
        _resolve_sources(args),
        field,
        filters=_filters_param(args),
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
    max_hours = es_query.timeline_max_hours()
    win_start, win_end, clipped = es_query.clamp_window(
        args.get("start"), args.get("end"), max_hours
    )
    # 实体既可能是源也可能是目的：两边都查再合并去重
    merged: dict[str, Any] = {"entity": entity, "returned": 0, "hits": [], "notes": []}
    if clipped:
        merged["notes"].append(
            f"时间窗已限制为最近 {max_hours} 小时"
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
    # 原来的 "service" 与 "proto" 两个聚合维度归一化后合成一个 protocol 字段
    # （normalizer: ``protocol = doc.get("proto") or doc.get("service")``），所以只留后者。
    for side in ("src_ip", "dst_ip"):
        for agg_field in ("dst_ip", "dst_port", "conn_state", "protocol"):
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
    # SNI 归一化后落在 hostname（normalizer: ``hostname = host or server_name``），
    # 返回键仍是 sni_top，调用方不用改。
    sni = _agg_multi(
        _resolve_sources(args),
        "hostname",
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
        # 参数名仍是 uri（提示词/样例不变），落到统一字段 query：归一化把完整 URI 写进
        # query（normalizer: ``query = doc.get("query") or uri``），原文也在 raw.uri。
        filters["query"] = {"contains": uri}
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
        # 哈希有顶层统一字段（files.log 的 md5/sha1/sha256 归一到 `sha256`，见 catalog.FIELDS），
        # 所以这里按字段过滤；`raw` 里当然也留着一份原文，但取数不该依赖它。
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
    limit = max(1, RAW_EVIDENCE_MAX)
    if len(ctx.raw_evidence) >= limit:
        return {"note": f"原始证据已达上限 {limit} 条", "fetched": len(ctx.raw_evidence)}
    if ref.startswith("ev:"):
        # ``ev:`` 是智能体侧事件库（PostgreSQL）的引用，NDR 这侧没有那张表。
        # 不静默降级成空结果：明确让调用方换 es: 引用，事件详情走 NDR 的 get_event 工具。
        raise ValueError(
            "ev: 引用属于智能体侧的事件库，本服务的查询层只能取 es:<索引>/<文档id>"
            "（事件详情请用 get_event 工具）"
        )
    index_and_id = ref[3:]
    index, _, doc_id = index_and_id.partition("/")
    if not index or not doc_id:
        raise ValueError("es: 引用格式应为 es:<索引>/<文档id>")
    # 索引白名单：ref 里的索引是**调用方给的**，不校验等于让 MCP 令牌持有者读 ES 里
    # 任意索引的任意文档（只允许事件索引族）。旧实现靠 ctx.valid_refs 挡，而那个校验
    # 在 MCP 层每调用新建 ToolCtx 时是失效的（2026-10 MCP QA）。
    pattern = str(es_config_current().get("es.events_index") or "")
    prefix = pattern.split("*")[0] or "shentong-events-"
    if not index.startswith(prefix):
        raise ValueError(f"只允许读取事件索引族的文档（{prefix}*），收到：{index}")
    try:
        resp = es_query._es().get(index=index, id=doc_id, request_timeout=es_query.query_timeout())
    except Exception as exc:
        raise ValueError(f"读取 ES 文档失败：{exc}") from exc
    source = resp.get("_source") or {}
    from app.ingestion.normalizer import _sanitize_raw

    item = {"ref": ref, "kind": "es_doc", "index": index, "raw": _sanitize_raw(source)}
    ctx.raw_evidence.append(item)
    return {"fetched": len(ctx.raw_evidence), "item": item}


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
            "filters": "对象，字段用统一字段名",
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
        "params": {
            "entity": "IP",
            "start": "ISO",
            "end": "ISO",
            "limit": "条数",
            "source": "zeek|wazuh|both",
        },
    },
    "net_flows": {
        "run": _net_flows,
        "desc": "网络侧画像：该 IP 的目的地/端口/连接状态/协议分布（看向哪打、从哪来）",
        "params": {
            "ip": "IP",
            "start": "ISO",
            "end": "ISO",
            "top": "桶数",
            "source": "zeek|wazuh|both",
        },
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
            "source": "zeek|wazuh|both",
        },
    },
    "tls_fingerprints": {
        "run": _tls_fingerprints,
        "desc": "TLS 会话与 JA3/SNI 指纹（识别 C2）",
        "params": {
            "ip": "IP",
            "start": "ISO",
            "end": "ISO",
            "limit": "条数",
            "source": "zeek|wazuh|both",
        },
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
            "source": "zeek|wazuh|both",
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
            "source": "zeek|wazuh|both",
        },
    },
    "raw_evidence": {
        "run": _raw_evidence,
        "desc": "取原始证据文档（只能引用本轮已查到的 ref；用于证据包）",
        "params": {"ref": "es:<index>/<id>"},
    },
}


def tool_names() -> list[str]:
    return sorted(TOOLS)


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
