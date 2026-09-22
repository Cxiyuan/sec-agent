"""ES 索引 mapping 自检：识别 IP 字段名与类型，结果缓存到 Redis。"""

from __future__ import annotations

import json
from typing import Any

from app.config import settings
from app.workers.log import get_logger

log = get_logger(__name__)

CACHE_KEY = "shentong:es_ip_fields"
CACHE_TTL_SECONDS = 1800  # 30 分钟


def configured_fields(index_kind: str) -> dict[str, str]:
    """按来源取配置的源/目的 IP 字段（支持逗号分隔多个）。"""
    if index_kind == "zeek":
        return {"src": settings.es_zeek_src_fields, "dst": settings.es_zeek_dst_fields}
    return {"src": settings.es_wazuh_src_fields, "dst": settings.es_wazuh_dst_fields}


def split_fields(value: str) -> list[str]:
    return [x.strip() for x in (value or "").split(",") if x.strip()]


def _field_type(props: dict[str, Any], field: str) -> str | None:
    """取字段类型：先按字面量键（点号扁平键），再逐级下钻（ES 对象字段在 properties 下）。"""
    direct = props.get(field)
    if isinstance(direct, dict) and "type" in direct:
        return str(direct["type"])

    node: Any = props
    for part in field.split("."):
        if not isinstance(node, dict):
            return None
        nxt = node.get(part)
        if nxt is None:
            inner = node.get("properties")
            nxt = inner.get(part) if isinstance(inner, dict) else None
        if nxt is None:
            return None
        node = nxt
    if isinstance(node, dict) and "type" in node:
        return str(node["type"])
    return None


def probe(index: str, index_kind: str) -> dict[str, str]:
    """探测索引 mapping，返回 {src, dst, type}；type 为 ip/keyword/unknown。"""
    conf = configured_fields(index_kind)
    info: dict[str, str] = {"src": conf["src"], "dst": conf["dst"], "type": "unknown"}
    try:
        from app.ingestion.es_client import get_es

        raw = es_mapping(get_es(), index)
        for src_field in split_fields(conf["src"]):
            t = _field_type(raw, src_field)
            if t:
                info["type"] = t
                break
        if info["type"] == "unknown":
            for dst_field in split_fields(conf["dst"]):
                t = _field_type(raw, dst_field)
                if t:
                    info["type"] = t
                    break
    except Exception as exc:  # noqa: BLE001
        log.warning("探测 ES mapping 失败 %s: %s", index, exc)
    return info


def es_mapping(es: Any, index: str) -> dict[str, Any]:
    """取索引 mapping 的 properties（取第一个匹配索引）。"""
    raw = es.indices.get_mapping(index=index)
    for body in raw.values():
        props = (body.get("mappings") or {}).get("properties") or {}
        if isinstance(props, dict):
            return props
    return {}


def get_ip_fields(index: str, index_kind: str) -> dict[str, str]:
    """带 Redis 缓存的字段信息（探测失败时返回配置值 + type=unknown）。"""
    client = None
    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        cached = client.get(f"{CACHE_KEY}:{index_kind}")
        if cached:
            data = json.loads(cached)
            if isinstance(data, dict) and data.get("type"):
                return {k: str(v) for k, v in data.items()}
    except Exception:  # noqa: BLE001
        client = None

    info = probe(index, index_kind)
    if client is not None:
        try:
            client.setex(f"{CACHE_KEY}:{index_kind}", CACHE_TTL_SECONDS, json.dumps(info))
        except Exception as exc:  # noqa: BLE001
            log.debug("写入字段缓存失败: %s", exc)
    return info


def clear_cache() -> None:
    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        for kind in ("zeek", "wazuh"):
            client.delete(f"{CACHE_KEY}:{kind}")
    except Exception as exc:  # noqa: BLE001
        log.debug("清理字段缓存失败: %s", exc)
