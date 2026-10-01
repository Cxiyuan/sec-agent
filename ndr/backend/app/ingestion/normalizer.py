"""日志规范化：把 Zeek / Wazuh 原始文档映射成统一 schema。

设计要点：
- 尽量保留可被规则利用的字段（Web 深检：method/uri_path/query_string/body/
  referer/cookie/auth_scheme/ja3/tls/qtype/filename 等）
- event_type 按日志类型细分，便于规则精准命中
- **安全**：不落库明文口令/Token（仅保留 auth_scheme）；会话 cookie 由画像层哈希
- 请求体字段名不固定 → 按配置候选择优，并截断
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

from app.config import settings
from app.schemas import Severity, UnifiedLog
from app.workers.log import get_logger

log = get_logger(__name__)

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


# ---------- 配置驱动的缓存 ----------


@lru_cache
def _csv(value: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in (value or "").split(",") if x.strip())


@lru_cache
def _login_re() -> re.Pattern[str]:
    try:
        return re.compile(settings.web_login_path_regex)
    except re.error:
        return re.compile(r"(?i)/(login|signin|auth)")


def _clip(value: Any, limit: int) -> str:
    text = str(value or "")
    return text[:limit] if len(text) > limit else text


# ---------- 凭证脱敏（仅用于持久化的 raw；body 保留供检测且不落库） ----------

_SENSITIVE_KEYS = {
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "authorization",
    "auth",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "client_secret",
    "api_key",
    "apikey",
    "private_key",
}
_CRED_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|access_token|refresh_token|secret|api_key|apikey)\b\s*[=:]\s*([^&;,\s\"']+)"
)
_CRED_HINTS = ("password", "passwd", "pwd", "token", "secret", "api_key", "authorization")


def _mask_text(text: str) -> str:
    low = text.lower()
    if not any(hint in low for hint in _CRED_HINTS):
        return text
    return _CRED_RE.sub(lambda m: f"{m.group(1)}=***", text)


def _sanitize_raw(value: Any, depth: int = 0) -> Any:
    """递归脱敏原始文档中的凭证字段（**不落库明文口令/Token**）。"""
    if depth > 4:
        return value
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, val in value.items():
            if str(key).lower() in _SENSITIVE_KEYS:
                out[key] = "***"
            else:
                out[key] = _sanitize_raw(val, depth + 1)
        return out
    if isinstance(value, list):
        return [_sanitize_raw(item, depth + 1) for item in value]
    if isinstance(value, str):
        return _mask_text(value)
    return value


# ---------- 基础转换 ----------


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


def _str_or_none(value: Any) -> str | None:
    """只接受字符串（非字符串返回 None）。

    用于防御字段名冲突：Filebeat 元数据会往事件里塞对象（如 host.name），
    同名时会把 Zeek 的字符串字段顶掉，直接透传给 pydantic 会报错。
    """
    return value if isinstance(value, str) and value else None


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


def _first(doc: dict[str, Any], keys: tuple[str, ...]) -> Any:
    """按候选字段名取第一个有值的字段（用于请求体等多命名场景）。"""
    for key in keys:
        value = _get(doc, key)
        if value:
            return value
    return None


def _get(doc: dict[str, Any], path: str) -> Any:
    """按点号路径取值。

    兼容两种形态：
    - 扁平键：Zeek 的 JSON 输出默认就是这种（{"id.orig_h": "1.2.3.4"}）
    - 嵌套对象：部分上游 pipeline（如 Logstash json 过滤器 / Filebeat expand_keys）
      会把点号键展开成 {"id": {"orig_h": "1.2.3.4"}}
    只支持扁平会在这类环境下把 IP/端口读成空值。
    """
    if path in doc:
        return doc[path]
    node: Any = doc
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def _split_uri(uri: str) -> tuple[str, str]:
    """URI -> (路径, 参数串)。"""
    raw = uri or ""
    if "?" in raw:
        path, _, qs = raw.partition("?")
        return path, qs
    return raw, ""


def _auth_scheme(doc: dict[str, Any]) -> str:
    """识别认证方式；**只保留 scheme，不保留凭证本体**。"""
    header = _first(doc, ("authorization", "Authorization", "http.authorization", "auth_header"))
    if header:
        return str(header).split(" ")[0].strip().lower()[:16]
    if doc.get("username") and doc.get("password") is not None:
        return "basic"
    return ""


def _extract_account(path: str, body: str, query_string: str, user_field: Any) -> str:
    """账号提取：user 字段优先；否则仅在登录路径下从参数中提取。"""
    if user_field and str(user_field).strip():
        return str(user_field).strip()[:128]
    if not path or not _login_re().search(path):
        return ""
    haystack = f"{query_string}&{body}"
    for name in _csv(settings.account_form_fields):
        pattern = rf"(?:^|[&;,\s]){re.escape(name)}\s*[=:]\s*([^&;,\s\"']+)"
        match = re.search(pattern, haystack, re.IGNORECASE)
        if match:
            return match.group(1)[:128]
    return ""


def _zeek_log_type(doc: dict[str, Any]) -> str:
    for name, hints in _ZEEK_TYPE_HINTS:
        if any(h in doc for h in hints):
            return name
    return "conn"


def _http_event_type(method: str, path: str, content_type: str, status_code: int | None) -> str:
    """HTTP 请求细分：登录 / 上传 / 错误 / 普通请求。"""
    upper = method.upper()
    if upper == "POST" and path and _login_re().search(path):
        return "http_login"
    if upper in ("POST", "PUT") and (
        "multipart/form-data" in content_type.lower()
        or path.lower().endswith((".php", ".jsp", ".jspx", ".aspx", ".ashx", ".war"))
    ):
        return "http_upload"
    if status_code is not None and status_code >= 400:
        return "http_error"
    return "http_request"


def _http_fields(doc: dict[str, Any], log_type: str) -> dict[str, Any]:
    """抽取 HTTP/TLS/DNS/文件相关的扩展字段。"""
    body_value = _first(doc, _csv(settings.http_body_fields))
    uri = str(doc.get("uri") or "")
    path, qs = _split_uri(uri) if log_type == "http" else ("", "")
    content_type = str(doc.get("content_type") or doc.get("request_content_type") or "")
    resp_mime = _to_str_list(doc.get("resp_mime_types") or doc.get("response_content_type"))
    return {
        "method": str(doc.get("method") or "")[:16],
        "uri_path": path[:512],
        "query_string": qs[:1024],
        "body": _clip(body_value, settings.http_body_max_chars),
        "referer": str(doc.get("referrer") or doc.get("referer") or "")[:512],
        "cookie": _clip(doc.get("cookie"), settings.http_cookie_max_chars),
        "content_type": content_type[:128],
        "resp_mime": resp_mime[:128],
        "ja3": str(doc.get("ja3") or "")[:64],
        "ja3s": str(doc.get("ja3s") or "")[:64],
        "tls_version": str(doc.get("version") or doc.get("tls_version") or "")[:32],
        "cert_issuer": str(doc.get("cert_issuer") or doc.get("issuer") or "")[:256],
        "qtype": str(doc.get("qtype") or doc.get("qtype_name") or "")[:16],
        "filename": str(doc.get("filename") or "")[:256],
        "mime_type": str(doc.get("mime_type") or "")[:128],
        "bytes_in": _to_int(doc.get("resp_bytes") or doc.get("response_body_len")),
    }


# ---------- Zeek ----------


def normalize_zeek(doc: dict[str, Any]) -> UnifiedLog:
    # Filebeat 采集时会把 Zeek 字段收在 zeek.* 命名空间下（避免与其元数据
    # host/agent/ecs 撞名，否则 http.log 的 host 会被覆盖）；这里解包，
    # 同时兼容旧的扁平结构（其它采集管道/历史数据）。
    outer = doc
    nested = doc.get("zeek")
    if isinstance(nested, dict):
        doc = nested
    ts = _to_dt(doc.get("ts") or outer.get("@timestamp"))
    log_type = _zeek_log_type(doc)
    note = doc.get("note")
    conn_state = doc.get("conn_state")
    src_ip = _get(doc, "id.orig_h")
    dst_ip = _get(doc, "id.resp_h")

    uri = str(doc.get("uri") or "")
    query = str(doc.get("query") or uri or "")
    extra = _http_fields(doc, log_type)
    status_code = _to_int(doc.get("status_code"))
    event_type = (
        _http_event_type(
            str(extra["method"]), str(extra["uri_path"]), str(extra["content_type"]), status_code
        )
        if log_type == "http"
        else _zeek_event_type(log_type, note, conn_state)
    )

    return UnifiedLog(
        source_system="zeek",
        ts=ts,
        event_type=event_type,
        log_type=log_type,
        src_ip=str(src_ip) if src_ip else None,
        dst_ip=str(dst_ip) if dst_ip else None,
        src_port=_to_int(_get(doc, "id.orig_p")),
        dst_port=_to_int(_get(doc, "id.resp_p")),
        protocol=doc.get("proto") or doc.get("service"),
        conn_state=str(conn_state or ""),  # 留给策略层判“是否真建立会话”（归一化时已读取）
        hostname=_str_or_none(doc.get("host")) or _str_or_none(doc.get("server_name")),
        user=doc.get("user") or doc.get("uid_owner"),
        query=query,
        user_agent=str(doc.get("user_agent") or ""),
        status_code=status_code,
        bytes_out=_to_int(doc.get("orig_bytes")),
        auth_scheme=_auth_scheme(doc),
        account=_extract_account(
            str(extra["uri_path"]),
            str(extra["body"]),
            str(extra["query_string"]),
            doc.get("user") or doc.get("username"),
        ),
        severity="info",
        summary=str(note or doc.get("msg") or f"zeek {log_type} {conn_state or ''}").strip(),
        raw=_sanitize_raw(doc),
        **extra,
    )


# ---------- Wazuh ----------


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
    # alerts.json 的每一条都带 rule；archives.json（logall_json 的全量原始日志）没有 rule。
    # 两者必须区分开：告警走检测规则，原始日志只入库供查询/回溯（见 normalizer_service）。
    is_archive = not rule
    agent = doc.get("agent")
    hostname = agent.get("name") if isinstance(agent, dict) else doc.get("agent")

    url = str(data.get("url") or data.get("uri") or "")
    path, qs = _split_uri(url)
    body_value = _first({**data, **doc}, _csv(settings.http_body_fields))
    status_code = _to_int(data.get("status"))
    user_field = data.get("user") or data.get("srcuser") or data.get("dstuser")

    if is_archive:
        raw_text = str(doc.get("full_log") or "").replace("\n", " ").strip()
        summary = _clip(raw_text or str(doc.get("location") or ""), 200) or "wazuh 原始日志"
        event_type = "wazuh_log"  # 原始日志不套告警事件类型，规则不会误命中
        log_type = "wazuh_archive"
    else:
        summary = str(description or f"wazuh rule level {level}")
        event_type = _wazuh_event_type(level, rule_groups, description)
        log_type = "wazuh"

    return UnifiedLog(
        source_system="wazuh",
        ts=ts,
        event_type=event_type,
        log_type=log_type,
        src_ip=str(src_ip) if src_ip else None,
        dst_ip=str(dst_ip) if dst_ip else None,
        src_port=_to_int(data.get("srcport")),
        dst_port=_to_int(data.get("dstport")),
        protocol=data.get("protocol"),
        hostname=str(hostname) if hostname else None,
        user=user_field,
        process=data.get("process"),
        command=data.get("command"),
        query=url,
        uri_path=path[:512],
        query_string=qs[:1024],
        method=str(data.get("method") or "")[:16],
        body=_clip(body_value, settings.http_body_max_chars),
        referer=str(data.get("referer") or "")[:512],
        cookie=_clip(data.get("cookie"), settings.http_cookie_max_chars),
        auth_scheme=_auth_scheme({**data, **doc}),
        content_type=str(data.get("content_type") or "")[:128],
        user_agent=str(data.get("user_agent") or ""),
        status_code=status_code,
        rule_id=rule_id,
        rule_groups=rule_groups,
        mitre=mitre,
        account=_extract_account(path, str(body_value or ""), qs, user_field),
        severity=severity,
        summary=summary,
        raw=_sanitize_raw(doc),
    )


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


_normalize_failures = 0
_MAX_FAILURE_LOGS = 5

_SOURCES = ("zeek", "wazuh")


def source_of(doc: dict[str, Any]) -> str:
    """判定日志来源。

    优先看显式标记 source_system（Zeek 的 Filebeat 会带）；
    缺失时做兜底嗅探——否则一本 Zeek 文档会被当成 Wazuh 解析，
    导致 event_type 全错、规则静默不命中（隐性漏检）。
    """
    raw = str(doc.get("source_system") or "").strip().lower()
    if raw in _SOURCES:
        return raw
    if "log_type" in doc or isinstance(doc.get("zeek"), dict):
        return "zeek"
    return "wazuh"


def normalize(source: str, doc: dict[str, Any]) -> UnifiedLog | None:
    """按来源系统分发规范化，无法识别时返回 None。

    异常不静默吞掉：否则「字段类型不符」这类问题会让整批事件无声丢弃
    （曾因 Filebeat 元数据 host 覆盖 Zeek 的 host，导致 999 条全部归零且无报错）。
    为防刷屏，每个进程最多记录前面若干条。
    """
    global _normalize_failures
    try:
        if source == "zeek":
            return normalize_zeek(doc)
        if source == "wazuh":
            return normalize_wazuh(doc)
        return None
    except Exception as exc:  # noqa: BLE001
        if _normalize_failures < _MAX_FAILURE_LOGS:
            _normalize_failures += 1
            log.warning("归一化失败（%s，第 %d 次）：%s", source, _normalize_failures, exc)
        return None
