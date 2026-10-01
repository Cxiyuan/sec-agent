"""取证查询层：把「统一字段 + 条件」翻译成 ES 查询（**只读**，带硬上限与超时）。

三个必须守住的点：
1. **未知字段 fail-closed**：返回带可用字段清单的报错，让模型自我纠正，而不是静默空结果。
2. **按真实 mapping 类型选路径**：text 字段必须走 ``.keyword``（既能精确匹配也能聚合），
   keyword 字段拼 ``.keyword`` 会静默空——所以查类型而不是猜。
3. **有界**：单次查询文档数、超时、聚合桶数都有硬上限，绝不把 ES 打爆。

与 agent 侧那版的差别只有一个维度：**索引不再是「来源」的函数**。归一化前置之后
Zeek 与 Wazuh 都写进同一族索引（``settings.es_events_index`` = ``shentong-events-*``），
文档是扁平统一字段。来源仍然能区分——归一化把 ``source_system`` 写进了文档，
工具的 ``source`` 参数就转成这个字段的 term 过滤（见 ``source_clause``），
除此之外所有字段路径都只有一份（见 ``catalog.FIELDS``）。
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from app.config import settings
from app.investigation import catalog
from app.workers.log import get_logger

log = get_logger(__name__)

DEFAULT_WINDOW_HOURS = 24
MAX_TERM_VALUES = 50
AGG_SIZE_MAX = 200
# 这几个上限原来读 agent 侧的 ``investigation_*`` 配置（后台可调）。NDR 的 config.py
# 不在本次改造范围内，没有对应配置项，于是按原默认值固定成模块常量：要调就改这里。
QUERY_TIMEOUT_SECONDS = 45
TIMELINE_MAX_HOURS = 72
DEFAULT_LOOKBACK_DAYS = 30
TIMEOUT_HINTS = (
    "timeout",
    "timed out",
    "circuit_breaking_exception",
    "search_phase_execution_exception",
)


def query_timeout() -> str:
    """ES 单次查询超时。

    原来写死 20s，线上实测聚合/时间线经常超时，而失败只把裸异常丢给模型（它只会原地重试），
    所以这里给到 45s；仍是模块常量，不要在调用点另写超时值。
    """
    return f"{max(5, QUERY_TIMEOUT_SECONDS)}s"


# 模块内多处沿用短名（对 export/tools 等外部调用点暴露公开名 query_timeout）
_query_timeout = query_timeout


def _is_timeout(exc: Exception) -> bool:
    text = str(exc).lower()
    return any(hint in text for hint in TIMEOUT_HINTS)


def _narrow(start: Any, end: Any) -> tuple[Any, Any]:
    """把时间窗对半（超时降级重试用）；无法对半时原样返回。"""
    start_dt, end_dt = _to_dt(start), _to_dt(end)
    if start_dt is None or end_dt is None or end_dt <= start_dt:
        return start, end
    middle = start_dt + (end_dt - start_dt) / 2
    return middle.isoformat(), end_dt.isoformat()


def _with_degrade(
    run: Callable[[Any, Any], dict[str, Any]], start: Any, end: Any
) -> tuple[dict[str, Any], bool]:
    """执行查询；超时则把时间窗对半重试一次，返回 (响应, 是否降级)。

    为什么降级而不是直接报错：模型看不到 ES 内部细节，裸异常会让它原地重试同一查询；
    对半后大多数查询能成功，仍失败则抛出带“缩小窗口/加实体过滤”的可执行提示。
    """
    try:
        return run(start, end), False
    except Exception as exc:
        if not _is_timeout(exc):
            raise
        narrowed = _narrow(start, end)
        if narrowed == (start, end):
            raise
        log.warning("ES 查询超时，降级重试（时间窗对半）：%s ~ %s", start, end)
        return run(*narrowed), True


def clamp_window(start: Any, end: Any, max_hours: int) -> tuple[str, str, bool]:
    """把时间窗限制在 max_hours 内（超出则保留最近一段），返回 (start, end, 是否截断)。"""
    start_iso, end_iso = window(start, end)
    start_dt, end_dt = _to_dt(start_iso), _to_dt(end_iso)
    if start_dt is None or end_dt is None:
        return start_iso, end_iso, False
    limit = timedelta(hours=max(1, _safe_int(max_hours, TIMELINE_MAX_HOURS)))
    if end_dt - start_dt > limit:
        return (end_dt - limit).isoformat(), end_iso, True
    return start_iso, end_iso, False


def timeline_max_hours() -> int:
    """timeline 的时间窗上限（全量查询，必须封顶否则必然 ES 超时）。"""
    return max(1, TIMELINE_MAX_HOURS)


class QueryError(Exception):
    """查询参数非法（未知字段 / 不支持的算子 / 类型不符）。消息会原样回给模型。"""


def _safe_int(value: Any, default: int = 0) -> int:
    """安全转 int（工具参数来自模型，可能是字符串或脏值）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ---------- 基础 ----------


def index_pattern() -> str:
    """统一的 ES 索引模式。

    只有一族索引（``shentong-events-*``）：Zeek 与 Wazuh 的文档结构在入库前已经统一，
    所以不存在「按来源选索引」的逻辑，也别再拼 ``zeek-*`` / ``wazuh-alerts-*``。
    """
    return settings.es_events_index


def max_lookback_days() -> int:
    """能回溯多少天。

    原来读 agent 侧的 ``investigation_max_lookback_days``（默认 30）。NDR 侧没有这个
    配置项，但 ``es_retention_days``（默认 30，后台可改）就是**物理上限**：ES 里没留的
    数据谁也查不出来，所以直接拿它当回溯封顶，量级与原来一致。
    """
    return max(1, _safe_int(settings.es_retention_days, DEFAULT_LOOKBACK_DAYS))


def _es() -> Any:
    from app.ingestion.es_client import get_es

    return get_es()


def _to_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value.strip():
        try:
            # Python 3.11+ 的 fromisoformat 已直接支持结尾的 "Z"
            parsed = datetime.fromisoformat(value.strip())
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def window(start: Any = None, end: Any = None) -> tuple[str, str]:
    """把时间参数规范成 (start_iso, end_iso)；未给则默认最近 24 小时。

    下界受 ``max_lookback_days``（= ES 保留期）约束，防止模型要求"查三年"把 ES 拖垮。
    """
    hard_end = datetime.now(UTC)
    end_dt = _to_dt(end) or hard_end
    end_dt = min(end_dt, hard_end)
    start_dt = _to_dt(start) or (end_dt - timedelta(hours=DEFAULT_WINDOW_HOURS))
    floor = hard_end - timedelta(days=max_lookback_days())
    start_dt = max(start_dt, floor)
    if start_dt >= end_dt:
        start_dt = end_dt - timedelta(minutes=1)
    return start_dt.isoformat(), end_dt.isoformat()


def _coerce(name: str, value: Any) -> Any:
    kind = catalog.kind_of(name)
    if kind == "num":
        try:
            return int(value)
        except (TypeError, ValueError):
            try:
                return float(value)
            except (TypeError, ValueError) as exc:
                raise QueryError(f"字段 {name} 需要数字，收到 {value!r}") from exc
    if kind == "bool":
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in ("true", "1", "yes", "是"):
            return True
        if text in ("false", "0", "no", "否"):
            return False
        raise QueryError(f"字段 {name} 需要布尔值，收到 {value!r}")
    if kind in ("date",):
        dt = _to_dt(value)
        if dt is None:
            raise QueryError(f"字段 {name} 需要时间（ISO 格式），收到 {value!r}")
        return dt.isoformat()
    return str(value)


def _dual(paths: list[str], build: Any) -> dict[str, Any]:
    """同一字段在主路径与 ``.keyword`` 上都试（避免类型差异导致的静默空结果）。"""
    should = [build(p) for p in paths]
    if len(should) == 1:
        return should[0]
    return {"bool": {"should": should, "minimum_should_match": 1}}


def _text_paths(path: str) -> list[str]:
    """不依赖 mapping 也能用的文本匹配路径（主路径 + .keyword）。"""
    return [path, f"{path}.keyword"]


def build_clause(name: str, value: Any) -> dict[str, Any]:
    """单个字段条件 → ES 子句。未知字段/非法算子一律抛 QueryError。"""
    index = index_pattern()
    path = catalog.resolve(name)
    if not path:
        allowed = ", ".join(sorted(catalog.available_fields(index)))
        raise QueryError(f"未知字段：{name}。可用字段：{allowed}")
    fkind = catalog.kind_of(name)

    # 列表 → terms（多值 or）
    if isinstance(value, (list, tuple, set)):
        values = [_coerce(name, v) for v in list(value)[:MAX_TERM_VALUES]]
        if not values:
            raise QueryError(f"字段 {name} 的取值列表为空")
        terms = catalog.term_paths(index, path)
        if not terms:
            raise QueryError(f'字段 {name} 不支持精确匹配，请用 {{"contains": "…"}}')
        return {"terms": {terms[0]: values}}

    if isinstance(value, dict):
        ops = {k.lower() for k in value}
        # 文本算子只对文本/关键字/ip 有意义；数值字段上会静默空结果（正是要防的坑）
        if ("contains" in ops or "prefix" in ops) and fkind not in ("text", "keyword", "ip"):
            raise QueryError(
                f"字段 {name}（{fkind}）不支持 contains/prefix，请用精确值或范围（gte/lte）"
            )
        if "contains" in ops:
            needle = str(value.get("contains", "")).strip()
            if not needle:
                raise QueryError(f"字段 {name} 的 contains 不能为空")
            return _dual(
                _text_paths(path),
                lambda p: {"wildcard": {p: {"value": f"*{needle}*", "case_insensitive": True}}},
            )
        if "prefix" in ops:
            needle = str(value.get("prefix", "")).strip()
            if not needle:
                raise QueryError(f"字段 {name} 的 prefix 不能为空")
            return _dual(_text_paths(path), lambda p: {"prefix": {p: {"value": needle}}})
        if "exists" in ops:
            return (
                {"exists": {"field": path}}
                if value.get("exists")
                else {"bool": {"must_not": {"exists": {"field": path}}}}
            )
        if ops & {"gte", "lte", "gt", "lt"}:
            if fkind not in ("num", "date"):
                raise QueryError(f"字段 {name}（{fkind}）不支持范围查询，请用精确值或 contains")
            body = {
                op: _coerce(name, value[op]) for op in ("gte", "lte", "gt", "lt") if op in value
            }
            return {"range": {path: body}}
        if "ne" in ops:
            terms = catalog.term_paths(index, path) or [path]
            return {"bool": {"must_not": {"term": {terms[0]: _coerce(name, value["ne"])}}}}
        raise QueryError(
            f"字段 {name} 不支持的条件写法：{sorted(ops)}。"
            "可用：精确值 / contains / prefix / exists / gte·lte·gt·lt / ne"
        )

    terms = catalog.term_paths(index, path)
    if not terms:
        raise QueryError(f'字段 {name} 是文本字段，请用 {{"contains": "…"}} 而不能精确匹配')
    return {"term": {terms[0]: _coerce(name, value)}}


def source_clause(source: str) -> dict[str, Any]:
    """来源 → ``source_system`` 过滤（工具的 source=zeek/wazuh 就落在这里）。

    为什么不是切索引：文档结构统一之后只有一族索引，来源不再是索引维度；归一化把
    ``source_system`` 如实写进了文档（``normalize_zeek`` → "zeek"，``normalize_wazuh``
    → "wazuh"），所以「只看 Zeek」= 对 source_system 精确过滤。
    """
    if source not in catalog.SOURCES:
        raise QueryError(f"来源只能是 {' / '.join(catalog.SOURCES)}，收到 {source!r}")
    return build_clause("source_system", source)


def build_filters(filters: Any) -> list[dict[str, Any]]:
    if filters is None:
        return []
    if not isinstance(filters, dict):
        raise QueryError('filters 必须是对象，如 {"src_ip": "1.2.3.4"}')
    out: list[dict[str, Any]] = []
    for name, value in filters.items():
        if value is None or value == "":
            continue
        out.append(build_clause(str(name), value))
    return out


def _time_clause(start: Any, end: Any) -> tuple[dict[str, Any], str, str]:
    start_iso, end_iso = window(start, end)
    return {"range": {"@timestamp": {"gte": start_iso, "lte": end_iso}}}, start_iso, end_iso


def keyword_clause(keyword: str, fields: list[str] | None = None) -> dict[str, Any]:
    """自由文本检索：在若干文本字段上做 simple_query_string（保守、不会语法报错）。"""
    names = fields or [
        n for n in catalog.SUMMARY_FIELDS if catalog.kind_of(n) in ("text", "keyword")
    ]
    paths = [p for p in (catalog.resolve(n) for n in names) if p]
    # 原来这里写死的是三个来源专有路径 ("zeek.body", "data.command", "rule.description")。
    # 归一化后它们各归其位：zeek.body → body；data.command → command；
    # rule.description → summary（见 ingestion/normalizer.py: ``summary = rule.description or …``）。
    # body 不在 SUMMARY_FIELDS 里（体积大，默认不带回来），但关键词检索必须覆盖它，
    # 否则「正文里出现过这个域名」这类查询会静默查不到；command/summary 通常已在
    # SUMMARY_FIELDS 里，下面的去重保证不会重复。
    for extra in ("body", "command", "summary"):
        path = catalog.resolve(extra)
        if path and path not in paths:
            paths.append(path)
    return {
        "simple_query_string": {
            "query": keyword,
            "fields": paths,
            "default_operator": "and",
            "lenient": True,
            "analyze_wildcard": False,
        }
    }


# ---------- 检索 ----------


def _get_path(doc: dict[str, Any], path: str) -> Any:
    """取值（复用 es_client 的实现：兼容「点号扁平键」与嵌套对象）。"""
    from app.ingestion.es_client import _get_path as impl

    return impl(doc, path)


def summarize(src: dict[str, Any]) -> dict[str, Any]:
    """把原始文档压成紧凑摘要（只留关键字段，空值不出现）。"""
    out: dict[str, Any] = {}
    for name in catalog.SUMMARY_FIELDS:
        path = catalog.resolve(name)
        if not path:
            continue
        value = _get_path(src, path)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, str) and len(value) > 300:
            value = value[:300]
        out[name] = value
    return out


def search(
    source: str,
    *,
    filters: Any = None,
    keyword: str | None = None,
    start: Any = None,
    end: Any = None,
    limit: int | None = None,
    sort: str = "desc",
    with_body: bool = False,
) -> dict[str, Any]:
    """定向检索某个来源的事件；返回紧凑结果（含 ``ref`` 供证据引用）。"""
    index = index_pattern()
    time_clause, start_iso, end_iso = _time_clause(start, end)
    must: list[dict[str, Any]] = [time_clause, source_clause(source)]
    must.extend(build_filters(filters))
    if keyword:
        must.append(keyword_clause(str(keyword)))
    cap = catalog.max_docs()
    size = max(1, min(_safe_int(limit, 200), cap))

    def _run(s: Any, e: Any) -> dict[str, Any]:
        clause, _s_iso, _e_iso = _time_clause(s, e)
        conds: list[dict[str, Any]] = [clause, source_clause(source)]
        conds.extend(build_filters(filters))
        if keyword:
            conds.append(keyword_clause(str(keyword)))
        resp: dict[str, Any] = _es().search(
            index=index,
            query={"bool": {"filter": conds}},
            size=size,
            sort=[{"@timestamp": "desc" if sort != "asc" else "asc"}],
            track_total_hits=False,
            request_timeout=_query_timeout(),
        )
        return resp

    try:
        resp, degraded = _with_degrade(_run, start, end)
    except Exception as exc:
        raise QueryError(
            "ES 查询超时：已自动把时间窗对半重试仍失败。建议缩小时间范围（用 start/end 指定具体时段）、"
            "加实体过滤（ip / asset / event_type），或先 aggregate_events 看分布。"
            f"原始错误：{str(exc)[:200]}"
        ) from exc

    hits: list[dict[str, Any]] = []
    for hit in resp.get("hits", {}).get("hits", []):
        src = hit.get("_source") or {}
        row = {"ref": f"es:{hit.get('_index')}/{hit.get('_id')}", **summarize(src)}
        if with_body:
            body = _get_path(src, catalog.resolve("body") or "")
            if body:
                row["body"] = str(body)[:600]
        hits.append(row)
    return {
        "source": source,
        "index": index,
        "window": {"start": start_iso, "end": end_iso},
        "returned": len(hits),
        "truncated": len(hits) >= size,
        "degraded": degraded,
        "note": "因超时已把时间窗对半重试" if degraded else "",
        "hits": hits,
    }


def aggregate(
    source: str,
    field: str,
    *,
    filters: Any = None,
    start: Any = None,
    end: Any = None,
    size: int = 20,
) -> dict[str, Any]:
    """按字段做 top-N 聚合（找横向目标、外联目的地、端口分布等）。"""
    index = index_pattern()
    if field not in catalog.AGG_FIELDS:
        raise QueryError(
            f"字段 {field} 不支持聚合（高基数字段会爆分桶）。"
            f"可聚合：{', '.join(catalog.agg_fields(index))}"
        )
    path = catalog.resolve(field)
    if not path or field not in catalog.available_fields(index):
        raise QueryError(f"字段 {field} 在当前索引里不存在")
    _, start_iso, end_iso = _time_clause(start, end)
    agg_name = f"top_{field}"
    agg_spec: dict[str, Any] = {
        agg_name: {
            "terms": {
                "field": catalog.agg_path(index, path),
                "size": max(1, min(_safe_int(size, 20), AGG_SIZE_MAX)),
            }
        }
    }

    def _run_agg(s: Any, e: Any) -> dict[str, Any]:
        clause, s_iso, _e_iso = _time_clause(s, e)
        # 降级重试时不算总数（算总数也是超时主因之一，而桶里的 doc_count 已够用）
        resp: dict[str, Any] = _es().search(
            index=index,
            track_total_hits=s_iso == start_iso,
            request_timeout=_query_timeout(),
            size=0,
            query={"bool": {"filter": [clause, source_clause(source), *build_filters(filters)]}},
            aggs=agg_spec,
        )
        return resp

    try:
        resp, degraded = _with_degrade(_run_agg, start, end)
    except Exception as exc:
        raise QueryError(
            "ES 聚合超时：已把时间窗对半重试仍失败。建议缩小时间范围、加实体过滤，或换更低基数的字段。"
            f"原始错误：{str(exc)[:200]}"
        ) from exc
    buckets = (resp.get("aggregations") or {}).get(agg_name, {}).get("buckets", [])
    total = ((resp.get("hits") or {}).get("total") or {}).get("value")
    if isinstance(total, dict):
        total = total.get("value")
    return {
        "source": source,
        "field": field,
        "window": {"start": start_iso, "end": end_iso},
        "doc_count": total,
        "degraded": degraded,
        "buckets": [{"value": b.get("key"), "count": b.get("doc_count")} for b in buckets],
    }


def count(
    source: str,
    *,
    filters: Any = None,
    keyword: str | None = None,
    start: Any = None,
    end: Any = None,
) -> int:
    index = index_pattern()
    time_clause, _, _ = _time_clause(start, end)
    must: list[dict[str, Any]] = [time_clause, source_clause(source)]
    must.extend(build_filters(filters))
    if keyword:
        must.append(keyword_clause(str(keyword)))
    try:
        resp = _es().count(
            index=index, query={"bool": {"filter": must}}, request_timeout=_query_timeout()
        )
    except Exception as exc:
        raise QueryError(f"ES 计数失败：{exc}") from exc
    return _safe_int(resp.get("count"))


def time_bounds(source: str) -> dict[str, Any]:
    """索引内真实数据时间范围（让模型知道"能查到多久以前"，而不是瞎猜）。

    注意这里**不按来源过滤**：两个来源同族索引，物理边界就是同一个（``source_system``
    只是文档属性，不影响 ES 里最早/最晚那条）。所以 describe_data 里两条来源的时间范围
    本来就该一样——不一样才说明哪里错了。
    """
    _ = source
    index = index_pattern()
    body = {
        "size": 0,
        "aggs": {
            "min_ts": {"min": {"field": "@timestamp"}},
            "max_ts": {"max": {"field": "@timestamp"}},
        },
    }
    try:
        resp = _es().search(index=index, request_timeout=_query_timeout(), **body)
    except Exception as exc:  # noqa: BLE001
        return {"source": source, "index": index, "error": str(exc)[:200]}
    aggs = resp.get("aggregations") or {}
    return {
        "source": source,
        "index": index,
        "earliest": (aggs.get("min_ts") or {}).get("value_as_string"),
        "latest": (aggs.get("max_ts") or {}).get("value_as_string"),
    }


def describe_sources() -> list[dict[str, Any]]:
    """各来源的索引与字段目录（供 describe_data 工具与排错接口）。

    字段目录是**索引级**的（两个来源共用同一套统一字段），来源之间只有 source_system
    过滤不同，所以这两个条目的 fields/agg_fields 一样、index 也一样。
    """
    index = index_pattern()
    fields = sorted(catalog.available_fields(index))
    agg = catalog.agg_fields(index)
    return [
        {
            "source": source,
            "index": index,
            "bounds": time_bounds(source),
            "fields": fields,
            "agg_fields": agg,
        }
        for source in catalog.default_sources()
    ]
