"""Elasticsearch 客户端：拉取窗口日志。"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from elasticsearch import Elasticsearch

from app.config import settings


def get_es() -> Elasticsearch:
    auth = (settings.es_user, settings.es_password) if settings.es_user else None
    return Elasticsearch(
        settings.es_url,
        basic_auth=auth,
        verify_certs=settings.es_verify_certs,
        request_timeout=60,
    )


def fetch_window_logs(start: datetime, end: datetime) -> list[tuple[str, dict[str, Any]]]:
    """拉取 [start, end) 窗口内 Zeek + Wazuh 全部日志。

    返回 [(source_system, doc), ...]，source_system 为 "zeek" / "wazuh"。
    """
    es = get_es()
    results: list[tuple[str, dict[str, Any]]] = []
    query = {
        "bool": {
            "filter": [
                {"range": {"@timestamp": {"gte": start.isoformat(), "lt": end.isoformat()}}}
            ]
        }
    }

    for index, source in ((settings.es_zeek_index, "zeek"), (settings.es_wazuh_index, "wazuh")):
        try:
            # 分页滚动拉取，避免单次响应过大
            resp = es.search(index=index, query=query, size=1000, sort=[{"@timestamp": "asc"}])
            hits = resp["hits"]["hits"]
            scroll_id = resp.get("_scroll_id")
            while hits:
                for h in hits:
                    doc = h.get("_source") or {}
                    if h.get("fields") or "_source" not in h:
                        doc = h.get("_source", {})
                    results.append((source, doc))
                if scroll_id:
                    resp = es.scroll(scroll_id=scroll_id, scroll="1m")
                    hits = resp["hits"]["hits"]
                else:
                    break
            if scroll_id:
                es.clear_scroll(scroll_id=scroll_id)
        except Exception as exc:  # noqa: BLE001
            # 单索引不可用时降级，不阻塞整体分析
            from app.workers.log import get_logger

            get_logger(__name__).warning("拉取索引 %s 失败: %s", index, exc)
            continue

    return results
