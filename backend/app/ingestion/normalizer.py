"""日志规范化：把 Zeek / Wazuh 原始文档映射成统一 schema。

设计要点：
- 尽量保留可被规则利用的字段（log_type / query / user_agent / bytes_out / Wazuh 规则语义）
- event_type 按日志类型细分，便于规则精准命中
- 未映射的字段整条保留在 raw，规则可用 contains/regex 粗略匹配
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.schemas import Severity, UnifiedLog

# Zeek 日志类型判别：按「特征字段」识别（ES 里各日志类型字段集不同）
_ZEEK_TYPE_HINTS: list[tuple[str, tuple[str, ...]]] = [
    ("dns", ("query", "qtype", "rcode")),
    ("http", ("uri", "method", "status_code", "user_agent")),
    ("ssl", ("server_name", "ja3", "ja3s", "cipher")),
    ("files", ("fuid", "mime_type", "filename", "md5", "sha1")),
    ("smtp", ("mailfrom", "rcptto", "subject", "helo")),
    ("ssh", ("auth_success", "client", "server", "auth_attempts")),
    ("dhcp", ("assigned_addr", "client_addr", "mac")),
    ("notice", ("note", "msg", "sub")),
    ("conn", ("conn_state", "orig_bytes", "resp_bytes")),
]


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


def _as_dict(value: Any) -> dict[str, Any]:
    """非 dict 统一成空 dict（显式返回类型便于类型检查）。"""
    return value if isinstance(value, dict) else {}


def _to_int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _to_str_list(v: Any) -> str:
    """list/str -> 逗号连接字符串（便于规则做 contains/regex）。"""
    if v is None:
        return ""
    if isinstance(v, (list, tuple, set)):
        return ",".join(str(x) for x in v if str(x).strip())
    return str(v)


def _zeek_log_type(doc: dict[str, Any]) -> str:
    for name, hints in _ZEEK_TYPE_HINTS:
        if any(h in doc for h in hints):
            return name
    return "conn"


def _zeek_event_type(log_type: str, note: str | None, conn_state: str | None) -> str:
    """按日志类型 + notice 细分事件类型。"""
    if note:
        n = note.lower()
        if "scan" in n:
            return "port_scan"
        if "bruteforc" in n or "brute" in n:
            return "brute_force"
        if "smtp" in n or "spam" in n:
            return "smtp_abuse"
        if "ssl" in n or "cert" in n:
            return "tls_anomaly"
        if "dns" in n:
            return "dns_anomaly"
        if "weird" in n:
            return "protocol_anomaly"
        return n.split("::")[-1].replace(" ", "_")[:64]

    if log_type == "dns":
        return "dns_query"
    if log_type == "http":
        return "http_request"
    if log_type == "ssl":
        return "tls_session"
    if log_type == "files":
        return "file_transfer"
    if log_type == "smtp":
        return "smtp_activity"
    if log_type == "ssh":
        return "ssh_activity"
    if log_type == "dhcp":
        return "dhcp_activity"
    if log_type == "notice":
        return "zeek_notice"

    if conn_state:
        if conn_state in ("S0", "S1", "S2", "S3"):
            return "scan_attempt"
        if conn_state == "REJ":
            return "rejected_connection"
        if conn_state == "SH":
            return "connection_shutdown"
        if conn_state == "SF":
            return "conn_established"
    return "generic"


def normalize_zeek(doc: dict[str, Any]) -> UnifiedLog:
    ts = _to_dt(doc.get("ts") or doc.get("@timestamp"))
    log_type = _zeek_log_type(doc)
    note = doc.get("note")
    conn_state = doc.get("conn_state")
    src_ip = doc.get("id.orig_h")
    dst_ip = doc.get("id.resp_h")

    # 应用层内容：DNS 查询名 或 HTTP URI
    query = str(doc.get("query") or doc.get("uri") or "")
    return UnifiedLog(
        source_system="zeek",
        ts=ts,
        event_type=_zeek_event_type(log_type, note, conn_state),
        log_type=log_type,
        src_ip=str(src_ip) if src_ip else None,
        dst_ip=str(dst_ip) if dst_ip else None,
        src_port=_to_int(doc.get("id.orig_p")),
        dst_port=_to_int(doc.get("id.resp_p")),
        protocol=doc.get("proto") or doc.get("service"),
        hostname=doc.get("host") or doc.get("server_name"),
        user=doc.get("user") or doc.get("uid_owner"),
        query=query,
        user_agent=str(doc.get("user_agent") or ""),
        status_code=_to_int(doc.get("status_code")),
        bytes_out=_to_int(doc.get("orig_bytes")),
        severity="info",
        summary=str(note or doc.get("msg") or f"zeek {log_type} {conn_state or ''}").strip(),
        raw=doc,
    )


def _wazuh_rule_info(doc: dict[str, Any]) -> tuple[str, str, str]:
    """返回 (rule_id, rule_groups, mitre)。"""
    rule = _as_dict(doc.get("rule"))
    rule_id = str(rule.get("id") or "")
    groups = _to_str_list(rule.get("groups") or rule.get("group"))
    mitre_raw = rule.get("mitre")
    mitre = ""
    if isinstance(mitre_raw, dict):
        mitre_dict = _as_dict(mitre_raw)
        parts = [
            _to_str_list(mitre_dict.get("id")),
            _to_str_list(mitre_dict.get("technique")),
        ]
        mitre = ",".join(p for p in parts if p)
    else:
        mitre = _to_str_list(mitre_raw)
    return rule_id, groups, mitre


def normalize_wazuh(doc: dict[str, Any]) -> UnifiedLog:
    ts = _to_dt(doc.get("timestamp") or doc.get("@timestamp"))
    data = _as_dict(doc.get("data"))
    src_ip = data.get("srcip") or doc.get("srcip")
    dst_ip = data.get("dstip") or doc.get("dstip")
    rule = _as_dict(doc.get("rule"))
    level = rule.get("level")
    description = rule.get("description") or doc.get("description")
    severity = _map_wazuh_level(level)
    rule_id, rule_groups, mitre = _wazuh_rule_info(doc)
    agent = doc.get("agent")
    hostname = agent.get("name") if isinstance(agent, dict) else doc.get("agent")

    return UnifiedLog(
        source_system="wazuh",
        ts=ts,
        event_type=_wazuh_event_type(level, rule_groups, description),
        log_type="wazuh",
        src_ip=str(src_ip) if src_ip else None,
        dst_ip=str(dst_ip) if dst_ip else None,
        src_port=_to_int(data.get("srcport")),
        dst_port=_to_int(data.get("dstport")),
        protocol=data.get("protocol"),
        hostname=str(hostname) if hostname else None,
        user=data.get("user") or data.get("srcuser") or data.get("dstuser"),
        process=data.get("process"),
        command=data.get("command"),
        query=str(data.get("url") or data.get("uri") or ""),
        user_agent=str(data.get("user_agent") or ""),
        status_code=_to_int(data.get("status") or data.get("id")),
        rule_id=rule_id,
        rule_groups=rule_groups,
        mitre=mitre,
        severity=severity,
        summary=str(description or f"wazuh rule level {level}"),
        raw=doc,
    )


def _wazuh_event_type(level: Any, rule_groups: str, description: Any) -> str:
    """结合规则组与等级细分，避免全部压成 wazuh_high_alert。"""
    groups = (rule_groups or "").lower()
    if any(k in groups for k in ("web", "attack", "web_scan")):
        return "wazuh_web_attack"
    if any(k in groups for k in ("authentication_failed", "authentication_failures", "sshd")):
        return "brute_force"
    if any(k in groups for k in ("malware", "ransomware", "virus", "rootcheck", "trojan")):
        return "wazuh_malware"
    if any(k in groups for k in ("syscheck", "ossec", "sysmon", "windows")):
        return "wazuh_system_change"
    if any(k in groups for k in ("vulnerability", "cve")):
        return "wazuh_vulnerability"
    if any(k in groups for k in ("firewall", "ids", "ips")):
        return "wazuh_network_alert"
    if any(k in groups for k in ("audit", "policy")):
        return "wazuh_policy_violation"

    text = str(description or "").lower()
    if "brute" in text or "failed password" in text:
        return "brute_force"
    if "scan" in text:
        return "port_scan"
    if "sql" in text or "injection" in text:
        return "web_attack"

    try:
        if int(level) >= 12:
            return "wazuh_high_alert"
    except (TypeError, ValueError):
        pass
    return "wazuh_alert"


def _map_wazuh_level(level: Any) -> Severity:
    try:
        value = int(level)
    except (TypeError, ValueError):
        return "info"
    if value >= 15:
        return "critical"
    if value >= 12:
        return "high"
    if value >= 8:
        return "medium"
    if value >= 4:
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
