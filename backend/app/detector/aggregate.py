"""短窗聚合：按 (源 IP, 规则) 在窗口内累计命中，窗口到期产出「聚合摘要」。

实时链路逐条到达，若不聚合会出现「同源扫描 1234 次 → 1234 次模型研判」的
容量爆炸；聚合后只投递一条摘要（含次数/目标集/端口集/样例）。
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import UTC, datetime
from typing import Any

from app.schemas import UnifiedLog
from app.workers.log import get_logger

log = get_logger(__name__)

_PREFIX = "shentong:agg"
_DUE_KEY = "shentong:agg:due"
_MAX_SAMPLES = 3
_MAX_SET = 50


def _agg_key(src_ip: str, rule: str) -> str:
    raw = f"{src_ip}|{rule}".encode()
    return f"{_PREFIX}:{hashlib.sha256(raw).hexdigest()[:20]}"


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).isoformat()


class Aggregator:
    """按 (源 IP, 规则) 聚合命中；到期产出摘要。"""

    def __init__(self, client: Any, window_seconds: int, max_keys: int) -> None:
        self.r = client
        self.window = max(1, _to_int(window_seconds, 60))
        self.max_keys = max(1, _to_int(max_keys, 5000))

    def add(
        self,
        *,
        src_ip: str,
        rule: str,
        severity: str,
        source: str,
        entry: UnifiedLog,
        raw_doc: dict[str, Any],
        log_source: str,
        now: float | None = None,
    ) -> None:
        """累计一次命中（含样例文档，供后续分析构造事件）。"""
        ts = time.time() if now is None else now
        key = _agg_key(src_ip, rule)
        state = self._load(key)
        if state is None:
            state = {
                "src_ip": src_ip,
                "rule": rule,
                "rule_severity": severity,
                "rule_source": source,
                "count": 0,
                "dst_ips": [],
                "dst_ports": [],
                "event_types": [],
                "samples": [],
                "first_seen": _iso(ts),
                "first_seen_ts": ts,
                "last_seen": _iso(ts),
            }
        state["count"] = _to_int(state.get("count", 0), 0) + 1
        state["last_seen"] = _iso(ts)
        _push_unique(state, "dst_ips", entry.dst_ip)
        _push_unique(state, "dst_ports", entry.dst_port)
        _push_unique(state, "event_types", entry.event_type)
        samples = state.setdefault("samples", [])
        if len(samples) < _MAX_SAMPLES:  # 保留最多 3 条原文作为分析样本
            samples.append({"source": log_source, "doc": raw_doc})

        current = _to_int(self.r.zcard(_DUE_KEY), 0)
        if current >= self.max_keys and not self.r.zscore(_DUE_KEY, key):
            log.warning("聚合态数量达上限 %d，本条直接丢弃聚合（降级）", self.max_keys)
            return

        ttl = self.window * 2 + 600
        self.r.set(key, json.dumps(state, ensure_ascii=False), ex=ttl)
        self.r.zadd(_DUE_KEY, {key: _to_float(state.get("first_seen_ts"), ts) + self.window})

    def pop_due(self, now: float | None = None) -> list[dict[str, Any]]:
        """取出已到期的聚合摘要（并清理聚合态）。"""
        ts = time.time() if now is None else now
        keys = self.r.zrangebyscore(_DUE_KEY, "-inf", ts, start=0, num=500)
        out: list[dict[str, Any]] = []
        for key in keys:
            raw = self.r.get(key)
            self.r.zrem(_DUE_KEY, key)
            self.r.delete(key)
            if not raw:
                continue
            try:
                state = json.loads(raw)
            except (TypeError, ValueError):
                continue
            state.pop("first_seen_ts", None)
            out.append(state)
        return out

    def _load(self, key: str) -> dict[str, Any] | None:
        raw = self.r.get(key)
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except (TypeError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def pending(self) -> int:
        return _to_int(self.r.zcard(_DUE_KEY), 0)


def _to_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _push_unique(state: dict[str, Any], field: str, value: Any) -> None:
    if value in (None, ""):
        return
    items = state.get(field)
    if not isinstance(items, list):
        items = []
        state[field] = items
    if value not in items and len(items) < _MAX_SET:
        items.append(value)
