"""Elasticsearch 客户端 + 「监控网段」判定工具。

- `get_es()`：取 ES 客户端（连接信息取自运行时配置：DB 覆盖 env，按连接三要素缓存复用）
- `build_networks` / `in_scope`：检测器的网段前置过滤用
- `_get_path`：按字段路径取值（`app/investigation/es_query.py` 也在用它）

「原始文档按配置字段路径判断网段」的 `doc_in_scope()` 已删：归一化前置之后不再分来源，
检测器判网段用的是已归一化文档的 `src_ip` / `dst_ip`（`in_scope`）。
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Any

from elasticsearch import Elasticsearch

from app.config import settings
from app.ingestion import es_config
from app.workers.log import get_logger

log = get_logger(__name__)


@lru_cache(maxsize=8)
def _client(url: str, auth: tuple[str, str] | None, verify: bool) -> Elasticsearch:
    return Elasticsearch(url, basic_auth=auth, verify_certs=verify, request_timeout=60)


def get_es() -> Elasticsearch:
    """取 ES 客户端（连接信息取自运行时配置：DB 覆盖 env）。

    客户端按「连接三要素」缓存复用：改造前每次调用都新建一个，而它在热路径上（MCP 每个
    工具、检索、试运行都会调），每个请求一个新连接池、旧的也不 close，白付连接与 TLS 开销。
    后台改配置后 `es_config.invalidate()` 会让缓存键跟着变，不会用到旧连接；maxsize=8 只是
    防反复改配置时无限堆积。客户端本身线程安全（elasticsearch-py 自带连接池）。
    """
    cfg = es_config.current()
    return _client(
        str(cfg.get("es.url") or settings.es_url),
        es_config.auth_pair(),
        bool(settings.es_verify_certs),
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
