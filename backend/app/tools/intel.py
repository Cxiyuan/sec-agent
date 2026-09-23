"""免费在线情报工具（无需 API key）+ 本地 DNS 解析。

服务与限制：
- GeoIP：ipwho.is（https 免费）优先，失败回退 ip-api.com（http 免费，45 次/分钟）
- RDAP：rdap.org（RFC 7482，免费）
- 恶意 IOC：abuse.ch 家族免费 API（MalwareBazaar 查 hash / ThreatFox 查 IP·域名·hash / URLhaus 查 URL）
全部带超时 + 短 TTL 缓存 + 优雅降级，免费额度有限故单组查询数设上限。
"""

from __future__ import annotations

import socket
import time
from typing import Any

import httpx

from app.config import settings
from app.runtime_config import get as runtime_get
from app.tools.context import ToolContext, is_public_ip
from app.workers.log import get_logger

log = get_logger(__name__)

_UA = {"User-Agent": "shentong-sec-agent/1.0"}
_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_MAX_CACHE = 2000


def _intel_on() -> bool:
    return bool(runtime_get("intel_enabled", settings.intel_enabled))


def _cached(key: str, fetch, ttl: int) -> dict[str, Any]:
    now = time.monotonic()
    hit = _cache.get(key)
    if hit and (now - hit[0]) < ttl:
        return hit[1]
    result = fetch()
    if len(_cache) > _MAX_CACHE:
        _cache.clear()
    _cache[key] = (now, result)
    return result


def _http_json(url: str) -> dict[str, Any]:
    with httpx.Client(timeout=settings.intel_timeout, follow_redirects=True) as client:
        resp = client.get(url, headers=_UA)
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, dict) else {"raw": data}


def _post_json(url: str, *, data: dict[str, Any] | None = None, json: dict[str, Any] | None = None) -> dict[str, Any]:
    with httpx.Client(timeout=settings.intel_timeout, follow_redirects=True) as client:
        resp = client.post(url, data=data, json=json, headers=_UA)
        resp.raise_for_status()
        payload = resp.json()
        return payload if isinstance(payload, dict) else {"raw": payload}


def _pick_public(ips: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for ip in ips:
        if ip and ip not in seen and is_public_ip(ip):
            seen.add(ip)
            out.append(ip)
    return out


# ---------- GeoIP ----------


def _geoip_try(base: str, ip: str) -> dict[str, Any] | None:
    """尝试单个免费 GeoIP 服务；失败/失败响应返回 None（由调用方回退）。"""
    try:
        data = _http_json(base + ip)
    except Exception:  # noqa: BLE001
        return None
    success = data.get("success")
    if (success is not None and not success) or data.get("status") == "fail":
        return None
    conn = data.get("connection") or {}
    return {
        "ip": data.get("ip") or ip,
        "country": data.get("country") or data.get("country_code"),
        "city": data.get("city"),
        "region": data.get("region"),
        "isp": conn.get("isp") or data.get("isp"),
        "org": conn.get("org") or data.get("org") or data.get("as"),
    }


def _geoip_single(ip: str) -> dict[str, Any]:
    # ipwho.is 优先（https 免费、无 key），失败回退 ip-api.com
    for base in ("https://ipwho.is/", "http://ip-api.com/json/"):
        result = _geoip_try(base, ip)
        if result:
            return result
    return {"ip": ip, "error": "免费 GeoIP 查询失败/限速"}


def geoip_lookup(ctx: ToolContext) -> dict[str, Any]:
    ips = _pick_public(ctx.external_ips or ctx.src_ips)
    if not ips:
        return {"results": {}, "note": "无公网 IP 可查"}
    if not _intel_on():
        return {"skipped": "情报查询未开启（intel_enabled=false）"}
    out: dict[str, Any] = {}
    for ip in ips[: settings.intel_max_queries_per_group]:
        out[ip] = _cached(f"geoip:{ip}", lambda ip=ip: _geoip_single(ip), settings.intel_cache_ttl)
    return {"results": out}


# ---------- RDAP（whois） ----------


def _rdap_single(path: str) -> dict[str, Any]:
    try:
        data = _http_json(f"https://rdap.org/{path}")
    except Exception:  # noqa: BLE001
        return {"error": "RDAP 查询失败/限速"}
    return {
        "name": data.get("name"),
        "handle": data.get("handle"),
        "country": data.get("country"),
        "status": data.get("status"),
        "entity_count": len(data.get("entities") or []),
    }


def rdap_lookup(ctx: ToolContext) -> dict[str, Any]:
    if not _intel_on():
        return {"skipped": "情报查询未开启（intel_enabled=false）"}
    ips = _pick_public(ctx.external_ips or [])
    domains = (ctx.domains or [])[:3]
    out: dict[str, Any] = {"ips": {}, "domains": {}}
    budget = settings.intel_max_queries_per_group
    for ip in ips[:5]:
        if budget <= 0:
            break
        out["ips"][ip] = _cached(f"rdap:ip:{ip}", lambda ip=ip: _rdap_single(f"ip/{ip}"), settings.intel_cache_ttl)
        budget -= 1
    for d in domains:
        if budget <= 0:
            break
        out["domains"][d] = _cached(f"rdap:domain:{d}", lambda d=d: _rdap_single(f"domain/{d}"), settings.intel_cache_ttl)
        budget -= 1
    return out


# ---------- 恶意 IOC 信誉（abuse.ch，免费无 key） ----------


def _malwarebazaar(hash_value: str) -> dict[str, Any]:
    try:
        data = _post_json("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": hash_value})
    except Exception:  # noqa: BLE001
        return {"known": None, "source": "MalwareBazaar", "error": "查询失败/限速"}
    if data.get("query_status") != "ok":
        return {"known": False, "source": "MalwareBazaar"}
    return {
        "known": True,
        "source": "MalwareBazaar",
        "signature": data.get("signature"),
        "tags": (data.get("tags") or [])[:20],
        "first_seen": data.get("first_seen"),
    }


def _threatfox(ioc: str) -> dict[str, Any]:
    try:
        data = _post_json(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ioc},
        )
    except Exception:  # noqa: BLE001
        return {"known": None, "source": "ThreatFox", "error": "查询失败/限速"}
    if data.get("query_status") != "ok":
        return {"known": False, "source": "ThreatFox"}
    matches = (data.get("data") or [])[:20]
    return {
        "known": True,
        "source": "ThreatFox",
        "count": len(matches),
        "matches": [
            {
                "ioc": m.get("ioc"),
                "type": m.get("threat_type"),
                "malware": m.get("malware_printable"),
            }
            for m in matches
        ],
    }


def _urlhaus(url: str) -> dict[str, Any]:
    try:
        data = _post_json("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url})
    except Exception:  # noqa: BLE001
        return {"known": None, "source": "URLhaus", "error": "查询失败/限速"}
    if data.get("query_status") != "ok":
        return {"known": False, "source": "URLhaus"}
    return {
        "known": True,
        "source": "URLhaus",
        "threat": data.get("threat"),
        "tags": (data.get("tags") or [])[:20],
        "url_status": data.get("url_status"),
    }


def threat_lookup(ctx: ToolContext) -> dict[str, Any]:
    if not _intel_on():
        return {"skipped": "情报查询未开启（intel_enabled=false）"}
    from app.tools.local import ioc_extract

    iocs = ioc_extract(ctx)
    results: dict[str, Any] = {"hashes": {}, "ips": {}, "domains": {}, "urls": {}}
    budget = settings.intel_max_queries_per_group

    for h in iocs["hashes"][:5]:
        if budget <= 0:
            break
        results["hashes"][h] = _cached(f"threat:hash:{h}", lambda h=h: _malwarebazaar(h), settings.intel_cache_ttl)
        budget -= 1
    for ip in _pick_public(ctx.external_ips or iocs["ips"])[:5]:
        if budget <= 0:
            break
        results["ips"][ip] = _cached(f"threat:ip:{ip}", lambda ip=ip: _threatfox(ip), settings.intel_cache_ttl)
        budget -= 1
    for d in iocs["domains"][:5]:
        if budget <= 0:
            break
        results["domains"][d] = _cached(f"threat:domain:{d}", lambda d=d: _threatfox(d), settings.intel_cache_ttl)
        budget -= 1
    for u in iocs["urls"][:5]:
        if budget <= 0:
            break
        results["urls"][u] = _cached(f"threat:url:{u}", lambda u=u: _urlhaus(u), settings.intel_cache_ttl)
        budget -= 1
    return results


# ---------- DNS 解析（本地） ----------


def dns_resolve(ctx: ToolContext) -> dict[str, Any]:
    domains = ctx.domains or []
    if not domains:
        from app.tools.local import ioc_extract

        domains = ioc_extract(ctx)["domains"][:10]
    out: dict[str, Any] = {}
    for d in domains[:10]:
        try:
            infos = socket.getaddrinfo(d, None)
            out[d] = {"a": sorted({i[4][0] for i in infos})[:8]}
        except OSError:
            out[d] = {"error": "解析失败"}
    return out
