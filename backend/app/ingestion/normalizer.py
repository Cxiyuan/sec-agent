"""日志规范化：把 Zeek / Wazuh 原始文档映射成统一 schema。"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.schemas import Severity, UnifiedLog


def _to_dt(v: Any) -> datetime:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=UTC)
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v, tz=UTC)
    if isinstance(v, str):
        try:
            # Python 3.11+ 的 fromisoformat 已直接支持结尾的 "Z"
            return datetime.fromisoformat(v)
        except ValueError:
            return datetime.now(UTC)
    return datetime.now(UTC)


def _guess_event_type(conn_state: str | None, note: str | None, rule_level: int | None) -> str:
    """根据连接状态 / Zeek notice / Wazuh 规则等级粗略映射事件类型。"""
    if note:
        n = note.lower()
        if "scan" in n:
            return "port_scan"
        if "bruteforc" in n or "brute" in n:
            return "brute_force"
        if "smtp" in n or "spam" in n:
            return "smtp_abuse"
        return n.split("::")[-1].replace(" ", "_")[:64]
    if conn_state:
        if conn_state in ("S0", "S1", "S2", "S3"):
            return "scan_attempt"
        if conn_state == "REJ":
            return "rejected_connection"
        if conn_state == "SH":
            return "connection_shutdown"
    if rule_level is not None and rule_level >= 12:
        return "wazuh_high_alert"
    return "generic"


def normalize_zeek(doc: dict[str, Any]) -> UnifiedLog:
    ts = _to_dt(doc.get("ts") or doc.get("@timestamp"))
    src_ip = doc.get("id.orig_h")
    dst_ip = doc.get("id.resp_h")
    conn_state = doc.get("conn_state")
    note = doc.get("note")
    return UnifiedLog(
        source_system="zeek",
        ts=ts,
        event_type=_guess_event_type(conn_state, note, None),
        src_ip=str(src_ip) if src_ip else None,
        dst_ip=str(dst_ip) if dst_ip else None,
        src_port=_to_int(doc.get("id.orig_p")),
        dst_port=_to_int(doc.get("id.resp_p")),
        protocol=doc.get("proto") or doc.get("service"),
        severity="info",
        summary=doc.get("note") or f"zeek conn {conn_state}",
        raw=doc,
    )


def normalize_wazuh(doc: dict[str, Any]) -> UnifiedLog:
    ts = _to_dt(doc.get("timestamp") or doc.get("@timestamp"))
    data = doc.get("data") or {}
    src_ip = data.get("srcip") or doc.get("srcip")
    dst_ip = data.get("dstip") or doc.get("dstip")
    rule = doc.get("rule") or {}
    level = rule.get("level") if isinstance(rule, dict) else None
    description = (rule.get("description") if isinstance(rule, dict) else None) or doc.get(
        "description"
    )
    severity = _map_wazuh_level(level)
    return UnifiedLog(
        source_system="wazuh",
        ts=ts,
        event_type=_guess_event_type(None, description, level),
        src_ip=str(src_ip) if src_ip else None,
        dst_ip=str(dst_ip) if dst_ip else None,
        src_port=_to_int(data.get("srcport")),
        dst_port=_to_int(data.get("dstport")),
        protocol=data.get("protocol"),
        hostname=doc.get("agent") or (doc.get("agent") or {}).get("name")
        if isinstance(doc.get("agent"), dict)
        else doc.get("agent"),
        user=data.get("user") or data.get("srcuser"),
        process=data.get("process"),
        command=data.get("command"),
        severity=severity,
        summary=description or f"wazuh rule level {level}",
        raw=doc,
    )


def _to_int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _map_wazuh_level(level: Any) -> Severity:
    try:
        level = int(level)
    except (TypeError, ValueError):
        return "info"
    if level >= 15:
        return "critical"
    if level >= 12:
        return "high"
    if level >= 8:
        return "medium"
    if level >= 4:
        return "low"
    return "info"


def normalize(source: str, doc: dict[str, Any]) -> UnifiedLog | None:
    """按来源系统分发规范化，无法识别时返回 None。"""
    try:
        if source == "zeek":
            return normalize_zeek(doc)
        if source == "wazuh":
            return normalize_wazuh(doc)
        return None
    except Exception:  # noqa: BLE001
        return None
