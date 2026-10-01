"""Elasticsearch 客户端 + 「监控网段」判定工具。

- `get_es()`：构造客户端（连接信息取自运行时配置：DB 覆盖 env）
- `build_networks` / `in_scope` / `doc_in_scope`：检测器的网段前置过滤用
  （原始文档按字段路径取值，已归一化文档直接用 `src_ip` / `dst_ip`）
"""

from __future__ import annotations

import ipaddress
from typing import Any

from elasticsearch import Elasticsearch

from app.config import settings
from app.ingestion import es_config
from app.ingestion.es_schema import split_fields
from app.workers.log import get_logger

log = get_logger(__name__)


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
    """取值：支持「点号扁平键」与「嵌套对象」两种形态。

    注意：嵌套形态下键名自身可能含点（Zeek 的 id.orig_h 就是这种，经 Filebeat
    命名空间后变成 zeek -> id.orig_h）。所以逐层下钻时必须**优先匹配最长的键名**，
    不能简单按点号切分——否则会把 id.orig_h 拆成 id / orig_h 而取不到值。
    """
    if path in doc:
        return doc[path]
    parts = path.split(".")
    node: Any = doc
    i = 0
    while i < len(parts):
        if not isinstance(node, dict):
            return None
        for j in range(len(parts), i, -1):  # 从最长的键名试起
            key = ".".join(parts[i:j])
            if key in node:
                node = node[key]
                i = j
                break
        else:
            return None
    return node


def doc_in_scope(doc: dict[str, Any], fields: dict[str, str], nets: list[Any]) -> bool:
    for f in split_fields(fields.get("src", "")) + split_fields(fields.get("dst", "")):
        if in_scope(_get_path(doc, f), nets):
            return True
    return False
