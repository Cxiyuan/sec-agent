"""日志规范化：把 Zeek / Wazuh 原始文档映射成统一 schema。

设计要点：
- 尽量保留可被规则利用的字段（Web 深检：method/uri_path/query_string/body/
  referer/cookie/auth_scheme/ja3/tls/qtype/filename 等）
- event_type 按日志类型细分，便于规则精准命中
- **凭证明文**：body/resp_body 与请求头值**按既定口径原样保留**（智能体要原文做攻击分析，
  见 docs/ndr-collect-plan.md「已接受的风险」）；只对持久化的 raw 做递归脱敏
- 请求体字段名不固定 → 按配置候选择优，并截断
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

from app.config import settings
from app.ingestion import conn_states, log_types
from app.runtime_config import get as runtime_get
from app.schemas import Severity, UnifiedLog
from app.workers.log import get_logger

log = get_logger(__name__)

# Zeek 日志类型判别：按「特征字段」识别（各日志类型字段集不同）。
# 只在 Filebeat **没给出** log_type 时兜底（历史扁平文档 / 人工重放 / 旧队列积压）。
# 顺序 = 特异性从高到低：判定用 any()，撞上一个字段就定案，所以专用流必须排在共用字段的流
# 前面。ja4ssh 只认 `kex`（ssh.log 没有这个字段）；ja4d 先认 `ja4d`，退一步才认通用的
# `hash`（老式扁平文档只有 hash）——但如果 ja4d 排在前面，JA4SSH 会被它用 hash 抢走，
# 所以 ja4ssh 必须在 ja4d 之前。
# ja4ssh/ja4d 的字段取自上游脚本，批 2 用真实样本校正；这两个日志因 FoxIO 许可证暂不进仓库，
# 实际不会出现，这里只保证历史扁平文档不会串型。
_ZEEK_TYPE_HINTS: list[tuple[str, tuple[str, ...]]] = [
    ("x509", ("certificate", "fingerprint", "basic_constraints", "host_cert", "client_cert")),
    ("notice", ("note", "msg", "sub")),
    ("files", ("fuid", "mime_type", "filename", "md5", "sha1", "sha256")),
    ("http", ("uri", "method", "status_code", "user_agent")),
    ("ssl", ("server_name", "ja3", "ja3s", "ja4", "cipher")),
    ("dns", ("query", "qtype", "rcode")),
    ("smtp", ("mailfrom", "rcptto", "subject", "helo")),
    ("dhcp", ("assigned_addr", "client_addr", "mac")),
    ("ja4ssh", ("kex",)),
    ("ja4d", ("ja4d", "hash")),
    ("ssh", ("auth_success", "auth_attempts", "client", "server")),
    ("stats", ("pkts_proc", "pkts_dropped", "events_proc", "pkt_lag")),
    ("ntp", ("stratum", "root_delay", "root_disp", "ref_id")),
    ("packet_filter", ("filter", "init", "success")),
    ("reporter", ("level", "message", "location")),
    ("weird", ("name", "peer", "addl")),
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


# ---------- HTTP 正文上限（后台可调，见 Web 后台「采集 → 网段与上限」） ----------
# Zeek 侧另有硬上限（shentong-limits.zeek 渲染自 interface.conf 的 body_max_bytes /
# resp_body_max_bytes）；这里再截一次是防「Zeek 已放宽但后端仍按旧值截断」时的口径不一致。
# 单位是字符（Zeek 侧是字节）：ASCII 正文两者一致，非 ASCII 时后端可能多截一点，不敏感。


def http_body_limit() -> int:
    """请求正文落库上限（字符）。"""
    try:
        return int(runtime_get("http.body_max_chars", settings.http_body_max_chars))
    except (TypeError, ValueError):
        return settings.http_body_max_chars


def http_resp_body_limit() -> int:
    """响应正文落库上限（字符）。"""
    try:
        return int(runtime_get("http.resp_body_max_chars", settings.http_resp_body_max_chars))
    except (TypeError, ValueError):
        return settings.http_resp_body_max_chars


# ---------- 凭证脱敏（仅用于持久化的 raw；body/请求头按既定口径原样落库） ----------

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
    """递归脱敏持久化 raw 里的凭证字段（按 key 名遮蔽，以及 `password=x` 形态的值）。

    只作用于 raw 这一份：body/resp_body 与请求头值按既定口径**原样落库**
    （已接受的风险，见 docs/ndr-collect-plan.md），不在这个函数里处理。
    """
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


def _raw_with_type(doc: dict[str, Any], log_type: str, source_file: str) -> dict[str, Any]:
    """持久化的 raw：解包后的内层原文 + 类型/来源文件名。

    补 log_type/source_file 是为了让 MCP 的 raw_evidence 自解释（拿到原文就知道是哪条流、
    哪个文件来的），ES 侧也能按 raw.log_type 统计每条流实际进来多少。
    """
    raw = _sanitize_raw(doc)
    merged = dict(raw) if isinstance(raw, dict) else {"value": raw}
    merged["log_type"] = log_type
    if source_file:
        merged["source_file"] = source_file
    return merged


# ---------- 基础转换 ----------

#: 坏时间戳的可见化：解析失败以前是**静默**回退成 `now()`，坏时间戳会无声变成「现在」，
#: 时间线与频率滑窗跟着一起错。前 `_MAX_TS_WARNINGS` 条打 warning（防刷屏），计数一直累加。
_MAX_TS_WARNINGS = 5
_bad_ts_count = 0


def _note_bad_ts(value: Any) -> None:
    """坏时间戳告警（限流）：原文照旧留在 raw 里，这里只补一条线索。"""
    global _bad_ts_count
    _bad_ts_count += 1
    if _bad_ts_count <= _MAX_TS_WARNINGS:
        detail = value if isinstance(value, str) else str(value)
        log.warning(
            "时间戳无法解析（第 %d 次，后续同类不再重复告警），已按当前时间入库：%s",
            _bad_ts_count,
            detail[:64],
        )


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
            _note_bad_ts(v)
            return datetime.now(UTC)
    _note_bad_ts(v)
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


def _text_or_none(value: Any) -> str | None:
    """把「可能是对象」的字段收敛成可读字符串（用于 Wazuh 的 process/user/command/protocol）。

    Wazuh 的 syscollector / FIM 解码器会把 ``data.process``、``data.user`` 这类字段给成**对象**
    （如 ``{"name": "svchost.exe", "pid": "676", ...}``），直接透传给 ``UnifiedLog`` 的 ``str``
    字段会被 pydantic 拒掉，**整条记录进死信队列**：2026-10-03 实机开 archives（全量原始日志）
    后 373 条 ``normalize_failed`` 全是这一类。

    与 ``_str_or_none`` 的区别：那个用于「同名对象顶掉字符串，宁缺勿滥」的 Zeek 字段；
    这里面对的是**原始日志本身的内容**，丢字段可以、丢整条记录不行，所以对象优先取可读的
    名字类字段，取不到再退化成紧凑 JSON。
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value or None
    if isinstance(value, dict):
        for key in ("name", "command", "path", "cmd", "id"):
            inner = value.get(key)
            if isinstance(inner, str) and inner:
                return inner
        return json.dumps(value, ensure_ascii=False, sort_keys=True)[:256] or None
    if isinstance(value, (list, tuple)):
        return ", ".join(str(x) for x in value)[:256] or None
    return str(value)


def _to_int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _to_bool(v: Any) -> bool | None:
    """Zeek 的布尔值可能是 JSON 布尔，也可能是 "T"/"F" 字符串（旧扁平文档）。"""
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        text = v.strip().lower()
        if text in ("t", "true", "yes", "1"):
            return True
        if text in ("f", "false", "no", "0"):
            return False
        return None
    if isinstance(v, int):
        return bool(v)
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


_AUTH_HEADER_RE = re.compile(r"(?im)^[ \t]*authorization[ \t]*:[ \t]*([^\r\n]+)")


def _auth_from_headers(headers: Any) -> str:
    """从 Zeek 收集的原始头文本里取 Authorization 值。

    `zeek/site/shentong-httpheaders.zeek` 把请求头拼成 `Name: value\\n` 的多行字符串塞进
    `req_headers`；Zeek 的 http.log **没有**顶层 authorization 字段，所以不解析这里的话
    `auth_scheme` 永远是空的，内置「Token/JWT 异常使用」的第二条分支（auth_scheme in
    [bearer, jwt]）永不命中。
    """
    match = _AUTH_HEADER_RE.search(str(headers or ""))
    return match.group(1) if match else ""


def _auth_scheme(doc: dict[str, Any]) -> str:
    """识别认证方式；**只保留 scheme，不保留凭证本体**。"""
    header = _first(doc, ("authorization", "Authorization", "http.authorization", "auth_header"))
    if not header:
        header = _auth_from_headers(doc.get("req_headers"))
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


def _source_file(outer: dict[str, Any]) -> str:
    """采集来源文件名（Filebeat 的 log.file.path 末段）。"""
    path = str(_get(outer, "log.file.path") or outer.get("source_file") or "")
    return path.rsplit("/", 1)[-1][:128]


def _zeek_log_type(doc: dict[str, Any], outer: dict[str, Any]) -> tuple[str, bool]:
    """判定 (log_type, 是否在采集白名单内)。

    优先级：Filebeat 的文件名类型（最确定）→ 特征字段猜（兜底历史/重放文档）→ unknown。
    白名单外的类型保留原始名字但 known=False（只入库、不进检测，可聚合巡检发现新流）。
    """
    explicit = log_types.canonical_log_type(outer.get("log_type") or doc.get("log_type") or "")
    if explicit:
        return explicit, log_types.is_known(explicit)
    for name, hints in _ZEEK_TYPE_HINTS:
        if any(h in doc for h in hints):
            return name, log_types.is_known(name)
    return log_types.UNKNOWN, False


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


# ---------- 代理头 → 真实客户端 IP ----------
#
# Zeek 把「能表明请求经过代理」的请求头收进 HTTP::Info$proxied（默认清单见
# base/protocols/http/main.zeek 的 option proxy_headers），元素形如
# "X-FORWARDED-FOR -> 198.51.100.77, 203.0.113.9"。XFF 是客户端自报、可伪造，
# 因此只落成独立字段 real_client_ip，**不覆盖** src_ip（TCP 对端）。
_XFF_HEADERS = ("X-FORWARDED-FOR", "X-FORWARDED-FROM", "FORWARDED", "CLIENT-IP")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _first_ip(text: Any) -> str:
    """从代理头值里取第一个合法 IP（XFF 形如 "客户端, 代理1, 代理2"）。"""
    for part in str(text or "").replace(";", ",").split(","):
        candidate = part.strip().strip('"')
        if "=" in candidate:  # RFC 7239: for=1.2.3.4;proto=https
            candidate = candidate.split("=", 1)[1].strip().strip('"')
        if candidate.startswith("[") and "]" in candidate:  # [2001:db8::1]:4711
            candidate = candidate[1 : candidate.index("]")]
        if _is_ip(candidate):
            return candidate
        host, sep, _port = candidate.partition(":")
        if sep and _is_ip(host):  # 1.2.3.4:5678
            return host
    return ""


def _real_client_ip(doc: dict[str, Any]) -> str | None:
    """解析代理头里的真实客户端 IP；没有就返回 None（落库为 NULL）。"""
    raw = doc.get("proxied")
    if not raw:
        raw = _first(doc, ("x-forwarded-for", "X-Forwarded-For", "x_forwarded_for"))
    values = raw if isinstance(raw, (list, tuple)) else [raw]
    for item in values:
        text = str(item or "")
        name, sep, value = text.partition("->")
        if sep:
            # Zeek 的 proxied 是 "头名 -> 头值"；不认识的头（如 VIA）跳过
            if name.strip() and name.strip().upper() not in _XFF_HEADERS:
                continue
            found = _first_ip(value)
        else:
            # 上游直接给的裸代理头值（没有头名）
            found = _first_ip(text)
        if found:
            return found
    return None


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
        "body": _clip(body_value, http_body_limit()),
        "resp_body": _clip(
            _first(doc, _csv(settings.http_resp_body_fields)), http_resp_body_limit()
        ),
        "resp_body_len": _to_int(doc.get("response_body_len")),
        "req_headers": str(doc.get("req_headers") or "")[:8192],
        "resp_headers": str(doc.get("resp_headers") or "")[:8192],
        "real_client_ip": _real_client_ip(doc),
        "referer": str(doc.get("referrer") or doc.get("referer") or "")[:512],
        "cookie": _clip(doc.get("cookie"), settings.http_cookie_max_chars),
        "content_type": content_type[:128],
        "resp_mime": resp_mime[:128],
        "ja3": str(doc.get("ja3") or "")[:64],
        "ja3s": str(doc.get("ja3s") or "")[:64],
        "ja4": str(doc.get("ja4") or "")[:64],
        "tls_version": str(doc.get("version") or doc.get("tls_version") or "")[:32],
        "cert_issuer": str(doc.get("cert_issuer") or doc.get("issuer") or "")[:256],
        # qtype 存的是 **Zeek 原始值**：dns.log 里 `qtype` 是数字码（1=A、28=AAAA、16=TXT…），
        # `qtype_name` 才是人类可读名。对外口径（规则/检索/前端）统一按数字码：
        # C 组规则只用 "16"、D 组 catalog 按数字码写描述、G 组前端按数字码显示；
        # 只有上游**没给**数字码时才回落到 qtype_name。
        "qtype": str(doc.get("qtype") or doc.get("qtype_name") or "")[:16],
        "filename": str(doc.get("filename") or "")[:256],
        "mime_type": str(doc.get("mime_type") or "")[:128],
        "fuid": str(doc.get("fuid") or "")[:64],
        "md5": str(doc.get("md5") or "")[:64],
        "sha1": str(doc.get("sha1") or "")[:64],
        "sha256": str(doc.get("sha256") or "")[:64],
        "file_source": str(doc.get("source") or "")[:32],
        "file_is_orig": _to_bool(doc.get("is_orig")),
        # 明文文件提取（批 4）：文件名 / 实际落盘字节数 / 是否被上限截断
        "extracted": str(doc.get("extracted") or "")[:128],
        "extracted_size": _to_int(doc.get("extracted_size")),
        "extracted_cutoff": _to_bool(doc.get("extracted_cutoff")),
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
    log_type, log_type_known = _zeek_log_type(doc, outer)
    source_file = _source_file(outer)
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
        log_type_known=log_type_known,
        source_file=source_file,
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
        auth_scheme=_auth_scheme({**doc, "req_headers": extra.get("req_headers")}),
        account=_extract_account(
            str(extra["uri_path"]),
            str(extra["body"]),
            str(extra["query_string"]),
            doc.get("user") or doc.get("username"),
        ),
        severity="info",
        summary=str(note or doc.get("msg") or f"zeek {log_type} {conn_state or ''}").strip(),
        raw=_raw_with_type(doc, log_type, source_file),
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
    source_file = _source_file(doc)  # Filebeat 带来的原始文件（alerts.json / archives.json）

    url = str(data.get("url") or data.get("uri") or "")
    path, qs = _split_uri(url)
    body_value = _first({**data, **doc}, _csv(settings.http_body_fields))
    status_code = _to_int(data.get("status"))
    # 见 `_text_or_none`：syscollector/FIM 的 data.user 可能是对象，透传会把整条原始日志打成死信。
    user_field = _text_or_none(data.get("user") or data.get("srcuser") or data.get("dstuser"))

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
        protocol=_text_or_none(data.get("protocol")),
        hostname=str(hostname) if hostname else None,
        user=user_field,
        process=_text_or_none(data.get("process")),
        command=_text_or_none(data.get("command")),
        query=url,
        uri_path=path[:512],
        query_string=qs[:1024],
        method=str(data.get("method") or "")[:16],
        body=_clip(body_value, http_body_limit()),
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
        # 与 Zeek 侧同一个口径（`normalize_zeek` 的 raw）：raw 里带 log_type/source_file，
        # MCP 的 raw_evidence 拿到原文就知道是哪条流、哪个文件来的；Wazuh 的告警与归档
        # （archives.json）共用这张表，更需要 raw 自解释。
        raw=_raw_with_type(doc, log_type, source_file),
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
        # conn_state 的语义（标签 + 是否算「握手真的完成过」）统一维护在
        # app/ingestion/conn_states.py 的一张表里，这里只查表、不再手写 if 链：
        # 以前手写导致 RSTO/RSTR 被兜底成 generic、SH（没建立）被当成「已建立」，
        # 事件类型与分诊口径静默打架（那两个坑见该模块 docstring）。
        # 表外状态由 conn_states 记一次限流警告，不静默吞掉。
        mapped = conn_states.event_type_of(conn_state)
        if mapped:
            return mapped
    return conn_states.GENERIC_EVENT_TYPE


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
