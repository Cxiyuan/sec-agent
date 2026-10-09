"""最近命中（摘要）的可见性：Redis 里留一小段，界面「最近命中」卡片吃它。

为什么需要（2026-10 实机调研）：摘要的唯一出口是「推给智能体」，而现场没配推送地址 ——
检测器**报了什么、报了谁，界面上完全看不到**（只有 `undelivered` 计数一直在涨）。
规则覆盖调优（"这台扫描设备到底触发了哪些规则"）这类问题，必须有一个**不依赖外部推送**
的可见入口。本模块只读写 Redis，不做任何判断、不改变投递行为。

长度由 `ST_DETECTOR_RECENT_MAX` 控制（默认 200 条，最新在头部）。
"""

from __future__ import annotations

import json
from typing import Any

from app.config import settings
from app.workers.log import get_logger

log = get_logger(__name__)

#: Redis list：最新在头部（LPUSH），长度受 `detector_recent_max` 限制
RECENT_KEY = "shentong:detector:recent"

#: 每条记录里各列表字段最多留几个（界面展示用，控制体积）
_MAX_LIST = 5


def _top(value: Any, limit: int = _MAX_LIST) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value[:limit]]
    return []


def compact(digest: dict[str, Any]) -> dict[str, Any]:
    """摘要 → 界面用的小记录（只留展示要用的字段，丢掉样例文档）。"""
    return {
        "ts": str(digest.get("last_seen") or digest.get("first_seen") or ""),
        "first_seen": str(digest.get("first_seen") or ""),
        "rule": str(digest.get("rule") or ""),
        "severity": str(digest.get("rule_severity") or digest.get("severity") or "medium"),
        "source": str(digest.get("rule_source") or digest.get("source") or "builtin"),
        "src_ip": str(digest.get("src_ip") or ""),
        "count": int(digest.get("count") or 0),
        "dst_ips": _top(digest.get("dst_ips")),
        "dst_ports": _top(digest.get("dst_ports")),
        "event_types": _top(digest.get("event_types")),
        "conn_states": _top(digest.get("conn_states")),
        "real_client_ips": _top(digest.get("real_client_ips"), 3),
        "proxied": bool(digest.get("proxied")),
        "excluded": bool(digest.get("excluded")),
        "exclude_reason": str(digest.get("exclude_reason") or ""),
    }


def record(client: Any, digest: dict[str, Any]) -> None:
    """记一条最近命中（失败只记 debug：可见性是辅助能力，不能影响检测主循环）。"""
    try:
        limit = max(10, int(settings.detector_recent_max))
        pipe = client.pipeline()
        pipe.lpush(RECENT_KEY, json.dumps(compact(digest), ensure_ascii=False))
        pipe.ltrim(RECENT_KEY, 0, limit - 1)
        pipe.execute()
    except Exception as exc:  # noqa: BLE001
        log.debug("写最近命中失败: %s", exc)


def load(client: Any, limit: int = 50) -> list[dict[str, Any]]:
    """读最近的命中（最新在前）。Redis 不可用时返回空列表，不抛。"""
    cap = max(1, min(int(limit or 50), max(10, int(settings.detector_recent_max))))
    try:
        raw = client.lrange(RECENT_KEY, 0, cap - 1)
    except Exception as exc:  # noqa: BLE001
        log.debug("读最近命中失败: %s", exc)
        return []
    out: list[dict[str, Any]] = []
    for item in raw or []:
        try:
            data = json.loads(item)
        except (TypeError, ValueError):
            continue
        if isinstance(data, dict):
            out.append(data)
    return out
