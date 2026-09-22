"""Elasticsearch 客户端：按「分析网段」定向拉取窗口日志。

- IP 字段为 ip 类型 → 用 ES 侧 CIDR 条件过滤（term + CIDR）
- 否则/查询失败 → 退化为拉取后 Python 侧网段过滤（并在结果里记录说明）
- 无启用网段 → 不拉取任何日志
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from elasticsearch import Elasticsearch

from app.config import settings
from app.ingestion import es_config
from app.ingestion.es_schema import get_ip_fields, split_fields
from app.workers.log import get_logger

log = get_logger(__name__)

PAGE_SIZE = 1000


@dataclass
class FetchResult:
    """拉取结果 + 过滤方式说明（供 run_summary 记录）。"""

    logs: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    mode: str = "es_cidr"  # es_cidr | python | no_scope
    notes: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def total(self) -> int:
        return len(self.logs)


def get_es() -> Elasticsearch:
    """构造 ES 客户端（连接信息取自运行时配置：DB 覆盖 env）。"""
    cfg = es_config.current()
    return Elasticsearch(
        cfg.get("es.url") or settings.es_url,
        basic_auth=es_config.auth_pair(),
        verify_certs=settings.es_verify_certs,
        request_timeout=60,
    )


def to_network(value: str) -> Any:
    """单 IP 或 CIDR -> ip_network；非法返回 None。"""
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        if "/" in raw:
            return ipaddress.ip_network(raw, strict=False)
        addr = ipaddress.ip_address(raw)
        return ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}", strict=False)
    except ValueError:
        return None


def build_networks(cidrs: list[str]) -> list[Any]:
    nets = [n for n in (to_network(c) for c in cidrs) if n is not None]
    return nets


def in_scope(ip_value: Any, nets: list[Any]) -> bool:
    if not ip_value or not nets:
        return False
    try:
        addr = ipaddress.ip_address(str(ip_value))
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in nets)


def _get_path(doc: dict[str, Any], path: str) -> Any:
    """取值：支持点号扁平键与嵌套对象两种形态。"""
    if path in doc:
        return doc[path]
    node: Any = doc
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def doc_in_scope(doc: dict[str, Any], fields: dict[str, str], nets: list[Any]) -> bool:
    for f in split_fields(fields.get("src", "")) + split_fields(fields.get("dst", "")):
        if in_scope(_get_path(doc, f), nets):
            return True
    return False


def scope_clause(fields: dict[str, str], cidrs: list[str]) -> dict[str, Any] | None:
    """ES 侧网段条件；字段类型不是 ip 时返回 None（由 Python 侧兜底）。"""
    if fields.get("type") != "ip":
        return None
    should: list[dict[str, Any]] = []
    for cidr in cidrs:
        for name in split_fields(fields.get("src", "")):
            should.append({"term": {name: cidr}})
        for name in split_fields(fields.get("dst", "")):
            should.append({"term": {name: cidr}})
    if not should:
        return None
    return {"bool": {"should": should, "minimum_should_match": 1}}


def _scroll(
    es: Elasticsearch, index: str, query: dict[str, Any], limit: int
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if limit <= 0:
        return out
    resp = es.search(
        index=index, query=query, size=min(PAGE_SIZE, limit), sort=[{"@timestamp": "asc"}]
    )
    hits = resp["hits"]["hits"]
    scroll_id = resp.get("_scroll_id")
    try:
        while hits and len(out) < limit:
            for hit in hits:
                out.append(hit.get("_source") or {})
                if len(out) >= limit:
                    break
            if not scroll_id:
                break
            resp = es.scroll(scroll_id=scroll_id, scroll="1m")
            hits = resp["hits"]["hits"]
    finally:
        if scroll_id:
            try:
                es.clear_scroll(scroll_id=scroll_id)
            except Exception as exc:  # noqa: BLE001
                log.debug("清理 scroll 失败: %s", exc)
    return out


def fetch_window_logs(
    start: datetime,
    end: datetime,
    cidrs: list[str] | None = None,
    *,
    max_logs: int | None = None,
) -> FetchResult:
    """拉取 [start, end) 内、源或目的 IP 落在给定网段内的 Zeek/Wazuh 日志。"""
    result = FetchResult()
    if not cidrs:
        result.mode = "no_scope"
        result.notes.append("未配置启用中的分析网段，本轮不拉取任何日志")
        return result

    limit = settings.max_logs_per_window if max_logs is None else max_logs
    nets = build_networks(cidrs)
    if not nets:
        result.mode = "no_scope"
        result.notes.append("分析网段解析为空，本轮不拉取任何日志")
        return result

    es = get_es()
    cfg = es_config.current()
    zeek_index = cfg.get("es.zeek_index") or settings.es_zeek_index
    wazuh_index = cfg.get("es.wazuh_index") or settings.es_wazuh_index
    time_filter = {"range": {"@timestamp": {"gte": start.isoformat(), "lt": end.isoformat()}}}
    modes: set[str] = set()

    for index, source in ((zeek_index, "zeek"), (wazuh_index, "wazuh")):
        fields = get_ip_fields(index, source)
        clause = scope_clause(fields, cidrs)
        query = {"bool": {"filter": [time_filter] + ([clause] if clause else [])}}

        docs: list[dict[str, Any]] = []
        if clause is not None:
            try:
                docs = _scroll(es, index, query, limit)
                modes.add("es_cidr")
                result.logs.extend((source, d) for d in docs)
                continue
            except Exception as exc:  # noqa: BLE001
                log.warning("ES 侧网段查询失败（%s）：%s，退化为 Python 过滤", index, exc)
                result.notes.append(f"{source}: ES 侧网段查询失败，已退化 Python 过滤")

        # 退化：只按时间拉取，再在 Python 侧按网段筛
        try:
            docs = _scroll(es, index, {"bool": {"filter": [time_filter]}}, limit)
        except Exception as exc:  # noqa: BLE001
            log.warning("拉取索引 %s 失败: %s", index, exc)
            result.notes.append(f"{source}: 拉取失败 {exc}")
            continue
        modes.add("python")
        if fields.get("type") != "ip":
            result.notes.append(
                f"{source}: IP 字段类型为 {fields.get('type')}，使用 Python 侧网段过滤"
            )
        kept = [d for d in docs if doc_in_scope(d, fields, nets)]
        result.notes.append(f"{source}: 拉取 {len(docs)} 条，网段内保留 {kept} 条")
        result.logs.extend((source, d) for d in kept)

    if "python" in modes and "es_cidr" in modes:
        result.mode = "python"  # 混合时标记为存在退化
    elif modes:
        result.mode = min(modes)

    if len(result.logs) > limit:
        result.logs = result.logs[:limit]
        result.truncated = True
        result.notes.append(f"超过单窗口上限 {limit} 条，已截断")

    return result
