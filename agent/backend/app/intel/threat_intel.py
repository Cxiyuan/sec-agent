"""外部威胁情报查询：IP 信誉、地理、已知恶意。"""
from __future__ import annotations

from typing import Any

import httpx

from app.config import settings


def lookup_ip(ip: str) -> dict[str, Any]:
    """查询单 IP 情报。无情报源时返回空字典。"""
    if not settings.intel_enabled or not settings.intel_api_url:
        return {}
    try:
        headers = {"Authorization": f"Bearer {settings.intel_api_key}"} if settings.intel_api_key else {}
        resp = httpx.get(
            settings.intel_api_url.rstrip("/") + f"/ip/{ip}",
            headers=headers,
            timeout=settings.intel_timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, dict) else {"raw": data}
    except Exception:  # noqa: BLE001
        return {}


def enrich_profile(src_ips: list[str]) -> dict[str, Any]:
    """批量查询画像所需情报，合并成 {ip: info}。"""
    result: dict[str, Any] = {}
    for ip in src_ips[:50]:  # 限制查询量
        info = lookup_ip(ip)
        if info:
            result[ip] = info
    return result
