"""取证查询层：把「逻辑字段 + 条件」翻译成 ES 查询（**只读**，带硬上限与超时）。

三个必须守住的点：
1. **未知字段 fail-closed**：返回带可用字段清单的报错，让模型自我纠正，而不是静默空结果。
2. **按真实 mapping 类型选路径**：text 字段必须走 ``.keyword``（既能精确匹配也能聚合），
   keyword 字段拼 ``.keyword`` 会静默空——所以查类型而不是猜。
3. **有界**：单次查询文档数、超时、聚合桶数都有硬上限，绝不把 ES 打爆。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from app.config import settings
from app.investigation import catalog
from app.workers.log import get_logger

log = get_logger(__name__)

DEFAULT_WINDOW_HOURS = 24
MAX_TERM_VALUES = 50
QUERY_TIMEOUT = "20s"
AGG_SIZE_MAX = 200


class QueryError(Exception):
    """查询参数非法（未知字段 / 不支持的算子 / 类型不符）。消息会原样回给模型。"""


def _safe_int(value: Any, default: int = 0) -> int:
    """安全转 int（工具参数来自模型，可能是字符串或脏值）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ---------- 基础 ----------


def index_pattern(kind: str) -> str:
    """数据来源 → ES 索引模式（连接与索引名由 es_config 统一解析）。"""
    from app.ingestion import es_config

    cfg = es_config.current()
    if kind == "zeek":
        return cfg.get("es.zeek_index") or settings.es_zeek_index
    return cfg.get("es.wazuh_index") or settings.es_wazuh_index


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

    上界受 ``investigation_max_lookback_days`` 约束（默认取 ES 保留期同量级），
    防止模型要求"查三年"把 ES 拖垮。
    """
    hard_end = datetime.now(UTC)
    end_dt = _to_dt(end) or hard_end
    end_dt = min(end_dt, hard_end)
    start_dt = _to_dt(start) or (end_dt - timedelta(hours=DEFAULT_WINDOW_HOURS))
    floor = hard_end - timedelta(days=max(1, settings.investigation_max_lookback_days))
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


def build_clause(kind: str, name: str, value: Any) -> dict[str, Any]:
    """单个字段条件 → ES 子句。未知字段/非法算子一律抛 QueryError。"""
    index = index_pattern(kind)
    paths = [_p for _p in [catalog.resolve(kind, name)] if _p]
    if not paths:
        allowed = ", ".join(sorted(catalog.available_fields(kind, index)))
        known = name in catalog.FIELDS
        why = "该字段在本来源不存在" if known else "未知字段"
        raise QueryError(f"{why}：{name}。可用字段：{allowed}")
    path = paths[0]
    fkind = catalog.kind_of(name)

    # 列表 → terms（多值 or）
    if isinstance(value, (list, tuple, set)):
        values = [_coerce(name, v) for v in list(value)[:MAX_TERM_VALUES]]
        if not values:
            raise QueryError(f"字段 {name} 的取值列表为空")
        terms = catalog.term_paths(index, path)
        if not terms:
            raise QueryError(f"字段 {name} 不支持精确匹配，请用 {{\"contains\": \"…\"}}")
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
            return {"exists": {"field": path}} if value.get("exists") else {"bool": {"must_not": {"exists": {"field": path}}}}
        if ops & {"gte", "lte", "gt", "lt"}:
            if fkind not in ("num", "date"):
                raise QueryError(f"字段 {name}（{fkind}）不支持范围查询，请用精确值或 contains")
            body = {op: _coerce(name, value[op]) for op in ("gte", "lte", "gt", "lt") if op in value}
            return {"range": {path: body}}
        if "ne" in ops:
            terms = catalog.term_paths(index, path) or [path]
            return {"bool": {"must_not": {"term": {terms[0]: _coerce(name, value["ne"])}}}}
        raise QueryError(
            f"字段 {name} 不支持的条件写法：{sorted(ops)}。可用：精确值 / contains / prefix / exists / gte·lte·gt·lt / ne"
        )

    terms = catalog.term_paths(index, path)
    if not terms:
        raise QueryError(f"字段 {name} 是文本字段，请用 {{\"contains\": \"…\"}} 而不能精确匹配")
    return {"term": {terms[0]: _coerce(name, value)}}


def build_filters(kind: str, filters: Any) -> list[dict[str, Any]]:
    if filters is None:
        return []
    if not isinstance(filters, dict):
        raise QueryError("filters 必须是对象，如 {\"src_ip\": \"1.2.3.4\"}")
    out: list[dict[str, Any]] = []
    for name, value in filters.items():
        if value is None or value == "":
            continue
        out.append(build_clause(kind, str(name), value))
    return out


def _time_clause(start: Any, end: Any) -> tuple[dict[str, Any], str, str]:
    start_iso, end_iso = window(start, end)
    return {"range": {"@timestamp": {"gte": start_iso, "lte": end_iso}}}, start_iso, end_iso


def keyword_clause(kind: str, keyword: str, fields: list[str] | None = None) -> dict[str, Any]:
    """自由文本检索：在若干文本字段上做 simple_query_string（保守、不会语法报错）。"""
    names = fields or [
        n
        for n in catalog.SUMMARY_FIELDS.get(kind, [])
        if catalog.kind_of(n) in ("text", "keyword")
    ]
    paths = [p for p in (catalog.resolve(kind, n) for n in names) if p]
    for extra in ("zeek.body", "data.command", "rule.description"):
        if extra not in paths:
            paths.append(extra)
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


def summarize(kind: str, src: dict[str, Any]) -> dict[str, Any]:
    """把原始文档压成紧凑摘要（只留关键字段，空值不出现）。"""
    out: dict[str, Any] = {}
    for name in catalog.SUMMARY_FIELDS.get(kind, []):
        path = catalog.resolve(kind, name)
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
    kind: str,
    *,
    filters: Any = None,
    keyword: str | None = None,
    start: Any = None,
    end: Any = None,
    limit: int | None = None,
    sort: str = "desc",
    with_body: bool = False,
) -> dict[str, Any]:
    """定向检索事件；返回紧凑结果（含 ``ref`` 供证据引用）。"""
    index = index_pattern(kind)
    time_clause, start_iso, end_iso = _time_clause(start, end)
    must: list[dict[str, Any]] = [time_clause, *build_filters(kind, filters)]
    if keyword:
        must.append(keyword_clause(kind, str(keyword)))
    cap = catalog.max_docs()
    size = max(1, min(_safe_int(limit, 200), cap))
    query = {"bool": {"filter": must}}
    try:
        resp = _es().search(
            index=index,
            query=query,
            size=size,
            sort=[{"@timestamp": "desc" if sort != "asc" else "asc"}],
            track_total_hits=False,
            request_timeout=QUERY_TIMEOUT,
        )
    except Exception as exc:
        raise QueryError(f"ES 查询失败：{exc}") from exc

    hits: list[dict[str, Any]] = []
    for hit in resp.get("hits", {}).get("hits", []):
        src = hit.get("_source") or {}
        row = {"ref": f"es:{hit.get('_index')}/{hit.get('_id')}", **summarize(kind, src)}
        if with_body:
            body = _get_path(src, catalog.resolve(kind, "body") or "")
            if body:
                row["body"] = str(body)[:600]
        hits.append(row)
    return {
        "source": kind,
        "index": index,
        "window": {"start": start_iso, "end": end_iso},
        "returned": len(hits),
        "truncated": len(hits) >= size,
        "hits": hits,
    }


def aggregate(
    kind: str,
    field: str,
    *,
    filters: Any = None,
    start: Any = None,
    end: Any = None,
    size: int = 20,
) -> dict[str, Any]:
    """按字段做 top-N 聚合（找横向目标、外联目的地、端口分布等）。"""
    index = index_pattern(kind)
    if field not in catalog.AGG_FIELDS:
        raise QueryError(
            f"字段 {field} 不支持聚合（高基数字段会爆分桶）。可聚合：{', '.join(catalog.agg_fields(kind, index))}"
        )
    path = catalog.resolve(kind, field)
    if not path or field not in catalog.available_fields(kind, index):
        raise QueryError(f"字段 {field} 在该来源不可用")
    time_clause, start_iso, end_iso = _time_clause(start, end)
    query = {"bool": {"filter": [time_clause, *build_filters(kind, filters)]}}
    agg_name = f"top_{field}"
    body = {
        "size": 0,
        "query": query,
        "aggs": {agg_name: {"terms": {"field": catalog.agg_path(index, path), "size": max(1, min(_safe_int(size, 20), AGG_SIZE_MAX))}}},
    }
    try:
        resp = _es().search(index=index, track_total_hits=True, request_timeout=QUERY_TIMEOUT, **body)
    except Exception as exc:
        raise QueryError(f"ES 聚合失败：{exc}") from exc
    buckets = (resp.get("aggregations") or {}).get(agg_name, {}).get("buckets", [])
    total = ((resp.get("hits") or {}).get("total") or {}).get("value")
    return {
        "source": kind,
        "field": field,
        "window": {"start": start_iso, "end": end_iso},
        "doc_count": total,
        "buckets": [{"value": b.get("key"), "count": b.get("doc_count")} for b in buckets],
    }


def count(kind: str, *, filters: Any = None, keyword: str | None = None, start: Any = None, end: Any = None) -> int:
    index = index_pattern(kind)
    time_clause, _, _ = _time_clause(start, end)
    must: list[dict[str, Any]] = [time_clause, *build_filters(kind, filters)]
    if keyword:
        must.append(keyword_clause(kind, str(keyword)))
    try:
        resp = _es().count(index=index, query={"bool": {"filter": must}}, request_timeout=QUERY_TIMEOUT)
    except Exception as exc:
        raise QueryError(f"ES 计数失败：{exc}") from exc
    return _safe_int(resp.get("count"))


def time_bounds(kind: str) -> dict[str, Any]:
    """索引内真实数据时间范围（让模型知道"能查到多久以前"，而不是瞎猜）。"""
    index = index_pattern(kind)
    body = {"size": 0, "aggs": {"min_ts": {"min": {"field": "@timestamp"}}, "max_ts": {"max": {"field": "@timestamp"}}}}
    try:
        resp = _es().search(index=index, request_timeout=QUERY_TIMEOUT, **body)
    except Exception as exc:  # noqa: BLE001
        return {"source": kind, "index": index, "error": str(exc)[:200]}
    aggs = resp.get("aggregations") or {}
    return {
        "source": kind,
        "index": index,
        "earliest": (aggs.get("min_ts") or {}).get("value_as_string"),
        "latest": (aggs.get("max_ts") or {}).get("value_as_string"),
    }


def describe_sources() -> list[dict[str, Any]]:
    """所有来源的索引与字段目录（供 describe_data 工具与排错接口）。"""
    out: list[dict[str, Any]] = []
    for kind in catalog.default_sources():
        index = index_pattern(kind)
        out.append(
            {
                "source": kind,
                "index": index,
                "bounds": time_bounds(kind),
                "fields": sorted(catalog.available_fields(kind, index)),
                "agg_fields": catalog.agg_fields(kind, index),
            }
        )
    return out
