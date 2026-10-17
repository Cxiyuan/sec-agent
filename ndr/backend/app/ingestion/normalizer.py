"""日志规范化：把 Zeek / 签名引擎原始文档映射成统一 schema。

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
from app.ingestion import conn_states, log_types, relay_nodes
from app.ingestion.session_cookie import session_id_from_cookie
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
    # raw 快照里也有原始头文本（含 Basic 凭证）→ 同样打码，别在这里漏掉
    merged = _redact_raw(dict(raw)) if isinstance(raw, dict) else {"value": raw}
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
#: 逐行 `Name: value` 的头文本（Zeek 的 req_headers/resp_headers 是这个形态）
_HEADER_LINE_RE = re.compile(r"(?im)^[ \t]*([A-Za-z0-9_-]+)[ \t]*:[ \t]*([^\r\n]*)")


def _header_value(headers: Any, *names: str) -> str:
    """从 Zeek 收集的原始头文本里取某个头的值（`Name: value\\n` 逐行）。

    Zeek 的 http.log **没有** cookie / content-type 这些列，头值只在 `req_headers` 里
    （见 `zeek/site/shentong-httpheaders.zeek`）。不解析这里的话：
    - `cookie` 恒空 → 内置「会话跨IP复用」（critical 级会话劫持）与「反序列化 rememberMe」
      分支永不触发；
    - `content_type` 恒空 → `http_upload` / 「上传类型不匹配」永不触发。
    （均见 2026-10 内置规则质量评审 P0-2 / P0-5。）
    """
    wanted = {n.lower() for n in names}
    for match in _HEADER_LINE_RE.finditer(str(headers or "")):
        if match.group(1).lower() in wanted:
            return match.group(2).strip()
    return ""


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


#: 落库前必须打码的头（保留头名、值换成 ***）。
#: 为什么：实机踩到校园出口代理在每个请求都带
#: `PROXY-AUTHORIZATION: Basic <base64(用户名:密码)>`，原样落库 = **明文密码进 ES 和界面**。
#: 注意：只对"要存进 ES 的头文本"打码；归一化**解析**（cookie / content-type / 认证方式）
#: 一律用未打码的原始文本，否则会话类判据会被打码打断。
_SECRET_HEADER_RE = re.compile(
    r"(?im)^("
    r"[ \t]*(?:(?:proxy-)?authorization|x-auth-token|x-api-key|token|password"
    r"|set-cookie|cookie)[ \t]*:[ \t]*"
    r").*$"
)

#: raw 里这些键的值同样要处理（raw 是原文快照，不处理等于绕过了上面的打码）
_RAW_SECRET_KEYS = frozenset(
    {
        "req_headers",
        "resp_headers",
        "authorization",
        "proxy-authorization",
        "x-auth-token",
        "x-api-key",
        "password",
    }
)


def _redact_headers(text: str) -> str:
    """头文本里的凭证值打码（`Name: value` → `Name: ***`）。"""
    if not text:
        return ""
    return _SECRET_HEADER_RE.sub(r"\1***", text)


def _redact_raw(raw: dict[str, Any]) -> dict[str, Any]:
    """raw 快照里的凭证同样打码（头文本走 _redact_headers，其余敏感键整值置 ***）。"""
    if not isinstance(raw, dict):
        return raw
    out = dict(raw)
    for key, value in list(out.items()):
        lowered = str(key).strip().lower()
        if lowered not in _RAW_SECRET_KEYS:
            continue
        if not isinstance(value, str):
            continue
        out[key] = _redact_headers(value) if "header" in lowered else "***"
    return out


#: 明显不是"人用的账号"的值（实机踩到的两类垃圾，见 _plausible_account）
_ACCOUNT_URL_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_ACCOUNT_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,}$")


def _plausible_account(value: str) -> bool:
    """账号值像不像真的账号（挡掉把 URL 编码中文、哈希、超长串当账号的情况）。

    实机见到的反例：`2601126116-%E5%90%84%E4%BD%8D%E5%90%8C%E5%AD%A6…`（把编码后的中文当账号）、
    `a5df6a72…`（64 位哈希被 128 截断）。这类值进画像只会污染列表。
    """
    text = value.strip()
    if not text or len(text) > 64:
        return False
    if _ACCOUNT_URL_ENCODED_RE.search(text):
        return False
    return not _ACCOUNT_HASH_RE.match(text)


def _extract_account(path: str, body: str, query_string: str, user_field: Any) -> str:
    """账号提取：user 字段优先；否则仅在登录路径下从参数中提取。"""
    if user_field and str(user_field).strip():
        value = str(user_field).strip()[:128]
        return value if _plausible_account(value) else ""
    if not path or not _login_re().search(path):
        return ""
    haystack = f"{query_string}&{body}"
    for name in _csv(settings.account_form_fields):
        pattern = rf"(?:^|[&;,\s]){re.escape(name)}\s*[=:]\s*([^&;,\s\"']+)"
        match = re.search(pattern, haystack, re.IGNORECASE)
        if match:
            value = match.group(1)[:128]
            return value if _plausible_account(value) else ""
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
# 因此只落成独立字段 real_client_ip、**不覆盖** src_ip（TCP 对端），并且**只有直连对端
# 本身是可信代理时才认**（见 _is_trusted_proxy / ST_ZEEK_TRUSTED_PROXIES）。
_XFF_HEADERS = ("X-FORWARDED-FOR", "X-FORWARDED-FROM", "FORWARDED", "CLIENT-IP", "X-REAL-IP")
#: 没有 Zeek 的 proxied 包装时退一步直接找的裸请求头（X-Real-IP 是单值头，主流反代都带）
_RAW_PROXY_HEADERS = (
    "x-forwarded-for",
    "X-Forwarded-For",
    "x_forwarded_for",
    "x-real-ip",
    "X-Real-IP",
)

_untrusted_proxy_warnings = 0
_MAX_UNTRUSTED_PROXY_WARNINGS = 5


def _trusted_proxy_nets() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """中继节点清单（反代/WAF/内网 DNS 转发器）：**只读 PG**，没有就是不认任何中继。

    解析、缓存与非法项告警全在 `app/ingestion/relay_nodes.py`（30 秒 TTL）。
    PG 里没这份清单 = 认定网络里没有中继 ⇒ 不信任任何代理头、`hop` 全 `direct`。
    """
    return list(relay_nodes.networks())


def _is_trusted_proxy(peer_ip: Any) -> bool:
    """直连对端是否在中继清单里；清单为空 / 对端未知 ⇒ False（fail-closed）。"""
    return relay_nodes.is_relay(peer_ip)


def _relay_hop(src_ip: Any, dst_ip: Any) -> str:
    """这一跳在中继链路上的位置（stateless，只读中继清单，**不看 XFF**）。

    - `front`：目的在中继清单里 →「客户端 → 中继」这一跳（带客户端原始请求/指纹）
    - `back` ：来源在中继清单里 →「中继 → 真实目的」这一跳（HTTP/SSL 这类才有 XFF）
    - `relay_internal`：两端都是中继（级联/中继之间），检测与基线一律不处理
    - `direct`：与中继无关
    """
    src_relay = relay_nodes.is_relay(src_ip)
    dst_relay = relay_nodes.is_relay(dst_ip)
    if src_relay and dst_relay:
        return "relay_internal"
    if dst_relay:
        return "front"
    if src_relay:
        return "back"
    return "direct"


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


def _real_client_ip(doc: dict[str, Any], peer_ip: Any = None) -> str | None:
    """解析代理头里的真实客户端 IP；没有（或来源不可信）就返回 None（落库为 NULL）。

    `peer_ip` 是**直连对端**（Zeek 的 `id.orig_h`）：只有它本身在**中继节点清单**里
    （界面「监控网段」页维护、存 PG，见 `ingestion/relay_nodes.py`）时才认这些头，
    否则任何人加一个 `X-Forwarded-For` 就能把客户端地址洗成任意值（规则/画像/检索全被带
    偏）。**清单为空 = 一律不认**（fail-closed）。
    """
    global _untrusted_proxy_warnings
    raw = doc.get("proxied")
    if not raw:
        raw = _first(doc, _RAW_PROXY_HEADERS)
    if not raw:
        return None
    if not _is_trusted_proxy(peer_ip):
        if _untrusted_proxy_warnings < _MAX_UNTRUSTED_PROXY_WARNINGS:
            _untrusted_proxy_warnings += 1
            # 区分两种情形（运维看日志要能直接分清是「没配」还是「配了但漏了这台」）
            if relay_nodes.configured():
                log.warning(
                    "代理头未被信任：直连对端 %s 不在「中继节点清单」里，real_client_ip 置空"
                    "（头值：%s）—— 若它确实是反向代理/WAF/内网 DNS，请到界面「监控网段」页加入清单",
                    peer_ip or "未知",
                    raw,
                )
            else:
                log.warning(
                    "代理头未被信任：中继节点清单**为空**（界面「监控网段」页未配置），"
                    "real_client_ip 一律置空（头值：%s）—— 网络里有反代/WAF/内网 DNS 时请先配置清单",
                    raw,
                )
        return None
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


def _cert_info(doc: dict[str, Any]) -> tuple[str, bool]:
    """返回 (签发者, 是否自签)。

    Zeek x509.log 把签发者/主体嵌套在 `certificate.issuer` / `certificate.subject` 下，
    只从顶层取 `issuer` 会**恒空** —— 内置「自签或异常证书」规则因此永不触发
    （2026-10 内置规则质量评审 P1）。这里同时算出 `cert_self_signed`（subject == issuer），
    给规则一个语义确定、无需比对两个字段的判据。
    """
    cert = doc.get("certificate")
    cert = cert if isinstance(cert, dict) else {}
    issuer = str(doc.get("cert_issuer") or doc.get("issuer") or cert.get("issuer") or "")[:256]
    subject = str(doc.get("cert_subject") or cert.get("subject") or "")[:256]
    self_signed = bool(issuer.strip()) and issuer.strip() == subject.strip()
    return issuer, self_signed


def _http_fields(doc: dict[str, Any], log_type: str, peer_ip: Any = None) -> dict[str, Any]:
    """抽取 HTTP/TLS/DNS/文件相关的扩展字段；peer_ip 见 `_real_client_ip`。"""
    body_value = _first(doc, _csv(settings.http_body_fields))
    uri = str(doc.get("uri") or "")
    path, qs = _split_uri(uri) if log_type == "http" else ("", "")
    req_headers_raw = str(doc.get("req_headers") or "")[:8192]
    # 解析用未打码原文（cookie/content-type/认证方式都要真值），落库用打码版本
    req_headers = _redact_headers(req_headers_raw)
    content_type = str(
        doc.get("content_type")
        or doc.get("request_content_type")
        or _header_value(req_headers_raw, "content-type")
    )
    cookie = _clip(
        doc.get("cookie") or _header_value(req_headers_raw, "cookie"),
        settings.http_cookie_max_chars,
    )
    # 会话 id 从**未截断**的 Cookie 头里取：长 Cookie 头会把会话 cookie 截掉 ⇒ 会话判据漏报。
    # 只认名单内的名字（精确匹配）且值非空 —— 见 ingestion/session_cookie.py 的说明。
    raw_cookie = str(doc.get("cookie") or _header_value(req_headers_raw, "cookie"))
    session_id = session_id_from_cookie(raw_cookie, settings.session_cookie_names)
    cert_issuer, cert_self_signed = _cert_info(doc)
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
        "req_headers": req_headers,
        "resp_headers": _redact_headers(str(doc.get("resp_headers") or "")[:8192]),
        "real_client_ip": _real_client_ip(doc, peer_ip),
        "referer": str(doc.get("referrer") or doc.get("referer") or "")[:512],
        "cookie": cookie,
        "session_id": session_id,
        "content_type": content_type[:128],
        "resp_mime": resp_mime[:128],
        "ja3": str(doc.get("ja3") or "")[:64],
        "ja3s": str(doc.get("ja3s") or "")[:64],
        "ja4": str(doc.get("ja4") or "")[:64],
        "tls_version": str(doc.get("version") or doc.get("tls_version") or "")[:32],
        # 握手是否真的建立（Zeek ssl.log 的 established）：TLS 握手失败风暴的判据
        "tls_established": _to_bool(doc.get("established")),
        "cert_issuer": cert_issuer,
        "cert_self_signed": cert_self_signed,
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

_filebeat_parse_warnings = 0
_MAX_FILEBEAT_PARSE_WARNINGS = 5


def _filebeat_parse_error(doc: dict[str, Any]) -> dict[str, Any] | None:
    """取 Filebeat 的 ndjson 解析失败标记（没有则 None）。

    Filebeat 的 filestream 开了 `parsers: [ndjson, add_error_key: true]`：解析失败时把错误
    挂在解析目标下（Zeek 线目标是 `zeek`，即 `zeek.error`；其它管道多在根 `error`），形如
    `{"type": "json", "message": "Error decoding JSON: invalid character 'h' ..."}`。
    """
    for holder in (doc, doc.get("zeek"), doc.get("suricata")):
        if not isinstance(holder, dict):
            continue
        err = holder.get("error")
        if isinstance(err, dict) and str(err.get("type") or "") == "json":
            return err
    return None


def _unwrap_filebeat_parse_error(doc: dict[str, Any], source: str) -> dict[str, Any] | None:
    """Filebeat 把日志行切碎时：用顶层 `message` 里原样保留的那一行抢救。

    2026-10-03 实机取证：Zeek 日志轮转/容器重建的窗口里 Filebeat 会把某一**行从中间切开**
    交给 ndjson 解析器，产出「一个业务字段都没有」的事件：
    `{"zeek": {"error": {...}}, "message": "<原始那一行>", ...}`（解析成功时**没有**顶层
    `message`）。旧行为是把它归一化成一条只有时间戳与 log_type 的空壳文档写进事件索引
    （实测 2026-10-03 的 shentong-events 里有 3 条），既污染检索又丢掉原文。这里用 Filebeat
    没丢的原始行再解一次：解出来就照常入库（两边 JSON 容忍度略有差异，少数行确实能救回）；
    解不出来返回 None，上层按归一化失败计数并投 `shentong:events:dead` 死信 —— 运维能看到
    原文，而不是拿到空壳。
    """
    global _filebeat_parse_warnings
    err = _filebeat_parse_error(doc)
    if err is None:
        return doc
    salvaged: Any = None
    message = doc.get("message")
    if isinstance(message, str) and message.strip():
        try:
            salvaged = json.loads(message)
        except ValueError:
            salvaged = None
    if not isinstance(salvaged, dict):
        if _filebeat_parse_warnings < _MAX_FILEBEAT_PARSE_WARNINGS:
            _filebeat_parse_warnings += 1
            log.warning(
                "Filebeat JSON 解析失败（%s），原始行无法复原，整条丢弃并投死信：%s",
                source,
                err.get("message") or err,
            )
        return None
    return salvaged


def normalize_zeek(doc: dict[str, Any]) -> UnifiedLog | None:
    # Filebeat 的 ndjson 解析失败事件先抢救/丢弃（见 _unwrap_filebeat_parse_error）：
    # 绝不落「只有 @timestamp + log_type」的空壳文档。
    unwrapped = _unwrap_filebeat_parse_error(doc, "zeek")
    if unwrapped is None:
        return None
    doc = unwrapped
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
    extra = _http_fields(doc, log_type, src_ip)
    status_code = _to_int(doc.get("status_code"))
    # weird.log 的异常名（只在这种日志上有）：决定 event_type 是协议异常还是**采集类异常**
    weird_name = str(doc.get("name") or "") if log_type == "weird" else ""
    event_type = (
        _http_event_type(
            str(extra["method"]), str(extra["uri_path"]), str(extra["content_type"]), status_code
        )
        if log_type == "http"
        else _zeek_event_type(log_type, note, conn_state, weird_name)
    )

    # 账号 + **来源**：代理认证的用户名（校园出口代理的终端 ID）与登录表单里的账号
    # 在界面上会长得一样（如 t14919610950627），标出来运维才知道那是什么。
    account = _extract_account(
        str(extra["uri_path"]),
        str(extra["body"]),
        str(extra["query_string"]),
        doc.get("user") or doc.get("username"),
    )
    account_source = ""
    if account:
        if re.search(
            r"(?im)^[ \t]*proxy-authorization[ \t]*:", str(extra.get("req_headers") or "")
        ):
            account_source = "proxy_auth"
        elif doc.get("user") or doc.get("username"):
            account_source = "log_field"
        else:
            account_source = "http_form"

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
        # stats.log 的丢包计数（只在这种日志上有）→ 近期流量图的掉包折线
        pkts_dropped=_to_int(doc.get("pkts_dropped")) if log_type == "stats" else None,
        pkts_proc=_to_int(doc.get("pkts_proc")) if log_type == "stats" else None,
        # Zeek weird.log 的异常名（其它日志恒空）：「协议异常」与「采集类异常」靠它区分
        weird_name=weird_name,
        # Zeek 连接 UID（同一跳内 http/ssl/dns/files ↔ conn 关联；中继前后跳是两条连接）
        uid=str(doc.get("uid") or ""),
        # Community ID（Zeek 的 community-id-logging 脚本在 conn.log 上产出）：
        # 与签名引擎（Suricata）告警里的同名字段可以对齐到同一条流。
        community_id=str(doc.get("community_id") or ""),
        # 中继链路位置（只读中继清单，stateless；见 relay_nodes.py）
        hop=_relay_hop(src_ip, dst_ip),
        hostname=_str_or_none(doc.get("host")) or _str_or_none(doc.get("server_name")),
        user=doc.get("user") or doc.get("uid_owner"),
        query=query,
        user_agent=str(doc.get("user_agent") or ""),
        status_code=status_code,
        bytes_out=_to_int(doc.get("orig_bytes")),
        # 认证方式要读**原始**头文本：extra 里的 req_headers 已打码（`AUTHORIZATION: ***`），
        # 拿打码文本来判会得到 `***` 这种假值（见 tests/py/test_rules_routing.py）
        auth_scheme=_auth_scheme(doc),
        account=account,
        account_source=account_source,
        severity="info",
        summary=str(note or doc.get("msg") or f"zeek {log_type} {conn_state or ''}").strip(),
        raw=_raw_with_type(doc, log_type, source_file),
        **extra,
    )


# ---------- Suricata（签名引擎） ----------

#: EVE 里体积大又没有检索价值的原始载荷字段：`packet` 是整包十六进制、`payload` 是本包载荷的
#  base64。两者内容与 `payload_printable`（可读形式）重复，落库只会把 raw 撑大，所以在写 raw
#  之前去掉；`payload_printable` 保留，智能体能直接看到命中的原文。
_EVE_RAW_DROP = ("packet", "payload")

#: EVE 的时间戳是 `2026-10-04T10:00:00.123456+0800` 这种**无冒号**时区写法，`fromisoformat`
#  在部分 Python 版本上直接拒收；而解析失败会静默回退成 now()，时间线跟着一起错。这里先补
#  冒号再交给 `_to_dt`。
_EVE_TZ_RE = re.compile(r"([+-]\d{2})(\d{2})$")


#: Suricata 自己的告警级别 → 我们的事件级 severity（1=高 / 2=中 / 3=低）。
#  这只是**事件**上的展示值；摘要级别由三条内置「签名命中」规则定（见 rules/builtin.py）。
_EVE_SEVERITY: dict[int, Severity] = {1: "high", 2: "medium", 3: "low"}


def _eve_ts(value: Any) -> Any:
    if isinstance(value, str):
        return _EVE_TZ_RE.sub(r"\1:\2", value.strip())
    return value


def _eve_http_doc(doc: dict[str, Any]) -> dict[str, Any]:
    """把 EVE 的 http/dns/tls/fileinfo 块映射成 `_http_fields` 认得的（Zeek 口径）字段名。

    映射而不是另写一份：URI 拆分、Cookie 截断、会话 id 取名这些口径在两条采集线上必须是同一
    套代码，否则同一件事会出两种结果。
    """
    http = _as_dict(doc.get("http"))
    dns = _as_dict(doc.get("dns"))
    tls = _as_dict(doc.get("tls"))
    fileinfo = _as_dict(doc.get("fileinfo"))
    out: dict[str, Any] = {}
    if http:
        out.update(
            {
                "host": http.get("hostname"),
                "uri": http.get("url"),
                "method": http.get("http_method"),
                "user_agent": http.get("http_user_agent"),
                "referrer": http.get("http_refer"),
                "status_code": http.get("status"),
                "content_type": http.get("http_content_type"),
                "response_body_len": http.get("length"),
                "req_headers": http.get("request_headers") or http.get("req_headers"),
                "cookie": http.get("http_cookie") or http.get("cookie"),
            }
        )
    if dns:
        out["query"] = dns.get("rrname")
        # 口径同 Zeek：优先数字码（dns.log 的 qtype），只在没有数字码时用名字
        out["qtype"] = (
            _as_dict(dns.get("rrtype")).get("code") or dns.get("rrtype") or dns.get("qtype")
        )
        out["qtype_name"] = dns.get("rrtype")
    if tls:
        out["server_name"] = tls.get("sni")
        out["version"] = tls.get("version")
        ja3 = _as_dict(tls.get("ja3")).get("hash") or tls.get("fingerprint")
        if ja3:
            out["ja3"] = ja3
    if fileinfo:
        out["filename"] = fileinfo.get("filename")
        out["md5"] = fileinfo.get("md5")
        out["sha1"] = fileinfo.get("sha1")
        out["sha256"] = fileinfo.get("sha256")
    return out


def _raw_suricata(doc: dict[str, Any], source_file: str) -> dict[str, Any]:
    """持久化的 raw：去掉原始载荷大字段后再套统一的 raw 规则。"""
    trimmed = {k: v for k, v in doc.items() if k not in _EVE_RAW_DROP}
    return _raw_with_type(trimmed, "suricata", source_file)


def normalize_suricata(doc: dict[str, Any]) -> UnifiedLog | None:
    """Suricata EVE 告警 → 统一结构（只处理 alert）。

    与 Zeek 线的差别：
    - `event_type` 恒为 `signature_hit`：它是「签名命中」这件事本身，不是某种协议日志；
    - 告警元数据（签名名/SID/类别/severity）进独立字段，摘要样本里直接可见；
    - `community_id` 与 Zeek 的 conn.log 同源 → 这是两边日志关联同一条流的键；
    - **不映射字节数**：流量体积类规则由 Zeek 的 conn 记录负责，两边都算会重复计数。
    """
    unwrapped = _unwrap_filebeat_parse_error(doc, "suricata")
    if unwrapped is None:
        return None
    outer = unwrapped
    nested = outer.get("suricata")
    inner = nested if isinstance(nested, dict) else outer
    alert = _as_dict(inner.get("alert"))
    if not alert:
        # 不是告警（配置漂移 / 人工重放）：不猜成某种事件，交给上层计失败数
        return None
    ts = _to_dt(_eve_ts(inner.get("timestamp")) or outer.get("@timestamp"))
    source_file = _source_file(outer)
    src_ip = inner.get("src_ip")
    dst_ip = inner.get("dest_ip")
    http = _as_dict(inner.get("http"))
    # 有 http 块才按 http 拆 URI（与 Zeek 的 log_type=“http” 行为对齐）
    extra = _http_fields(_eve_http_doc(inner), "http" if http else "suricata", src_ip)
    # 体积类规则只认 Zeek 的 conn 记录（见 docstring）
    extra["bytes_in"] = None
    sig_sev = _to_int(alert.get("severity"))
    signature = str(alert.get("signature") or "")
    signature_id = str(alert.get("signature_id") or "")
    return UnifiedLog(
        source_system="suricata",
        ts=ts,
        event_type="signature_hit",
        log_type="suricata",
        log_type_known=True,
        source_file=source_file,
        src_ip=str(src_ip) if src_ip else None,
        dst_ip=str(dst_ip) if dst_ip else None,
        src_port=_to_int(inner.get("src_port")),
        dst_port=_to_int(inner.get("dest_port")),
        protocol=_str_or_none(inner.get("proto")),
        # 位置照实算（中继清单只读）：它决定界面/智能体看到的是哪一跳。
        # 注意：签名命中**不做中继去重**（见 detector/runner.py）——告警来自另一个引擎，
        # 同一跳上重复上报本来就是两件事，丢掉反而丢证据。
        hop=_relay_hop(src_ip, dst_ip),
        hostname=_str_or_none(http.get("hostname"))
        or _str_or_none(_as_dict(inner.get("tls")).get("sni"))
        or _str_or_none(_as_dict(inner.get("dns")).get("rrname")),
        query=str(http.get("url") or _as_dict(inner.get("dns")).get("rrname") or ""),
        # UA 不在 `_http_fields` 的返回里（Zeek 侧也是单独赋值），这里显式搬过来
        user_agent=str(http.get("http_user_agent") or ""),
        # 响应码同理（Zeek 侧也是单独赋值）
        status_code=_to_int(http.get("status")),
        signature=signature,
        signature_id=signature_id,
        signature_severity=sig_sev,
        signature_category=str(alert.get("category") or ""),
        community_id=str(inner.get("community_id") or ""),
        # 事件级 severity 跟着 Suricata 自己的分档走（摘要级别由三条内置规则定，见 rules/builtin.py）
        severity=_EVE_SEVERITY.get(sig_sev or 0, "info"),
        summary=f"签名命中：{signature}（SID {signature_id}）".strip(),
        raw=_raw_suricata(inner, source_file),
        **extra,
    )


@lru_cache(maxsize=4)
def _capture_weird_names(raw: str) -> frozenset[str]:
    """把 `ST_ZEEK_CAPTURE_WEIRD_NAMES` 解析成小写集合（按文本缓存，逐条事件都会问）。"""
    return frozenset(part.strip().lower() for part in str(raw or "").split(",") if part.strip())


def _capture_weird(name: str) -> bool:
    """这条 weird 是「采集侧异常」还是「协议异常」？

    为什么单列一类（2026-10 实机实测）：`possible_split_routing` / `data_before_established` /
    `truncated_tcp_payload` 这类是**镜像口丢包 / 非对称路由 / 网卡 offload** 的痕迹，不是攻击信号，
    但它们占全部 weird 的 ~87%；一刀切命中「协议异常」会让一个 5 分钟窗口产出 75~84 条摘要
    （约占全部摘要一半），把真该看的挤掉。所以归成 `capture_anomaly`：**数据一条不丢**，
    只是不再当告警 —— 改由状态页的「采集质量」灯统计（丢包=漏检，还是得看得见）。
    """
    text = str(name or "").strip().lower()
    if not text:
        return False
    return text in _capture_weird_names(settings.zeek_capture_weird_names)


def _zeek_event_type(
    log_type: str, note: str | None, conn_state: str | None, weird_name: str | None = None
) -> str:
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

    if log_type == "weird":
        # 采集面已关掉 Zeek 自带 notice（shentong-policies.zeek 的 disable_stream），
        # protocol_anomaly / tls_anomaly 只能从 weird.log 的名字里出；否则内置
        # 「协议异常」「TLS异常」两规则在本部署永不触发（2026-10 规则评审 P0-5）。
        name = str(weird_name or "").lower()
        if _capture_weird(name):
            # 采集侧异常：不是攻击信号，而是「镜像口丢包/非对称路由/网卡 offload」的痕迹
            return "capture_anomaly"
        if any(k in name for k in ("ssl", "tls", "cert")):
            return "tls_anomaly"
        return "protocol_anomaly"

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


_SOURCES = ("zeek", "suricata")


def source_of(doc: dict[str, Any]) -> str:
    """判定日志来源。

    优先看显式标记 source_system（Zeek / Suricata 的 Filebeat 会带）；
    缺失时做兜底嗅探——否则一本 Zeek 文档会被当成别的来源解析，
    导致 event_type 全错、规则静默不命中（隐性漏检）。
    """
    raw = str(doc.get("source_system") or "").strip().lower()
    if raw in _SOURCES:
        return raw
    # Suricata 的 EVE 告警自带 alert 块与 flow_id（Zeek 没有），可以安全嗅探
    if isinstance(doc.get("suricata"), dict) or (
        isinstance(doc.get("alert"), dict) and "flow_id" in doc
    ):
        return "suricata"
    if "log_type" in doc or isinstance(doc.get("zeek"), dict):
        return "zeek"
    return "zeek"


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
        # Filebeat 解析失败的整行也要走同一道闸（抢救或丢弃），Zeek 与签名引擎一视同仁
        unwrapped = _unwrap_filebeat_parse_error(doc, source)
        if unwrapped is None:
            return None
        doc = unwrapped
        if source == "zeek":
            return normalize_zeek(doc)
        if source == "suricata":
            return normalize_suricata(doc)
        return None
    except Exception as exc:  # noqa: BLE001
        if _normalize_failures < _MAX_FAILURE_LOGS:
            _normalize_failures += 1
            log.warning("归一化失败（%s，第 %d 次）：%s", source, _normalize_failures, exc)
        return None
