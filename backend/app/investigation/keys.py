"""攻击者案件键抽取：从事件组抽出可归并的确定性键。

键类型（任一交集即可归并到同一案件）：
- ``ip``     公网源 IP —— 外部攻击者最稳定的标识
- ``host``   内网源 IP —— 内部跳板/被控主机
- ``acct``   账号 —— 登录类事件里的用户名（跨 IP 追同一操作者）
- ``domain`` / ``hash`` IOC —— 攻击者换 IP 时的关键连接线索

为什么用确定性键而不是直接让模型判断：归并结果会决定"哪些证据一起看"，
必须可解释、可复现；模型只在"无键交集但相似"时做边界裁定（见 cases.py）。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from app.config import settings
from app.tools.context import ToolContext, is_public_ip
from app.tools.local import ioc_extract
from app.workers.log import get_logger

log = get_logger(__name__)

# 主键优先级（越小越优先）：决定案件标题与 attacker_key 显示
KEY_PRIORITY: dict[str, int] = {"ip": 0, "acct": 1, "domain": 2, "hash": 3, "host": 4}
KEY_TYPES: tuple[str, ...] = ("ip", "acct", "domain", "hash", "host")

# 强键 / 弱键：只有强键能单独促成自动归并。
# 为什么：原来“任一单键交集即归并”，于是一个脏域名键（vnd.ms）或一个内网主机键
# 就能把几十个无关事件组粘成一个巨案（线上实测 149 组的案件）。
STRONG_KEYS: tuple[str, ...] = ("ip", "acct", "hash")
WEAK_KEYS: tuple[str, ...] = ("host", "domain")
_MAX_PER_TYPE = 20
_MAX_KEY_LEN = 200

# 账号字段候选（Zeek/Wazuh/Web 表单各家叫法不同）
_ACCOUNT_KEYS = {
    "username",
    "user",
    "user_name",
    "account",
    "uname",
    "userid",
    "user_id",
    "login",
    "srcuser",
    "dstuser",
    "uid_owner",
    "client_user",
}
# 明显不是人名的值（避免把设备名/服务名当账号）
_NOT_ACCOUNT = re.compile(r"(?i)^(system|local service|network service|anonymous|n/?a|-|root\$?)$")
_SAFE_ACCOUNT = re.compile(r"^[\w.@\\$-]{1,64}$")

# 形似域名但不是域名（文件扩展名）：IOC 正则会把 "a.php"/"b.js" 当域名，
# 若不加过滤会多出一堆无意义的键，可能把两个不相关的事件组误归成一个案件。
_FAKE_TLD = re.compile(
    r"(?i)\.(php|phtml|asp|aspx|jsp|jspx|htm|html|js|css|json|xml|txt|log|conf|ini|bak|sql|pdf|"
    r"png|jpe?g|gif|svg|ico|zip|rar|7z|tar|gz|exe|dll|so|bin|sh|py|rb|go|java|war|jar|cgi|pl)$"
)


def _walk_accounts(node: Any, out: set[str], depth: int = 0) -> None:
    """递归找账号字段（原始文档结构不固定，只能按字段名嗅探）。"""
    if depth > 4:
        return
    if isinstance(node, dict):
        for key, val in node.items():
            if str(key).lower() in _ACCOUNT_KEYS and isinstance(val, (str, int)):
                name = str(val).strip()
                if (
                    name
                    and not _NOT_ACCOUNT.match(name)
                    and _SAFE_ACCOUNT.match(name)
                    and len(name) > 1
                ):
                    out.add(name[:_MAX_KEY_LEN])
            else:
                _walk_accounts(val, out, depth + 1)
    elif isinstance(node, list):
        for item in node[:50]:
            _walk_accounts(item, out, depth + 1)


def _url_hosts(text: str) -> list[str]:
    """从 URL 里取主机名（作为域名键的一部分）。"""
    out: list[str] = []
    for match in re.finditer(r"https?://[^\s\"'<>()]+", text or "", re.IGNORECASE):
        try:
            host = urlparse(match.group(0)).hostname
        except ValueError:
            host = None
        if host:
            out.append(host.lower())
    return out


# ---- 域名抽取：只认「域名语义字段」，绝不让 MIME/文件名/任意文本混进来 ----
#
# 真实事故：`application/vnd.ms-cab-compressed` 里的 vnd.ms 被当成“攻击者域名”，
# 而域名键比主机键优先级高 → 案件被命名成 domain:vnd.ms，再把几十个无关组粘成巨案。
_DOMAIN_FIELD_KEYS = {
    "query",
    "host",
    "hostname",
    "host_name",
    "server_name",
    "referrer",
    "referer",
    "uri",
    "url",
    "request_uri",
    "domain",
    "domains",
}
_NEVER_DOMAIN_FIELDS = {
    "mime_type",
    "content_type",
    "content-type",
    "filename",
    "file_name",
    "fuid",
    "mime",
    "sub_type",
    "subtype",
}
# MIME 片段/类型前缀：以这些开头的“域名”一律丢弃
_MIME_PREFIX = re.compile(
    r"(?i)^(vnd|x-|ms-|octet|application|text|image|audio|video|font|multipart|message)"
)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_DOMAIN_SHAPE = re.compile(
    r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$", re.IGNORECASE
)


@dataclass
class _JunkStats:
    """被拒的域名候选统计（可见性：键污染不能静默）。"""

    refused: int = 0
    last: str = ""
    samples: list[str] = field(default_factory=list)

    def snapshot(self) -> dict[str, Any]:
        return {"refused": self.refused, "last": self.last, "samples": list(self.samples)}


KEY_JUNK_REJECTED = _JunkStats()


def _domain_candidates(text: str) -> list[str]:
    """从一个字段值里取候选域名（可能是 URL、Host 头或 DNS 查询名）。"""
    out: list[str] = []
    for chunk in re.split(r"[\s,;]+", str(text or "")):
        candidate = chunk.strip().strip("[]()<>\"'")
        if not candidate:
            continue
        if "://" in candidate:
            try:
                host = urlparse(candidate).hostname
            except ValueError:
                host = None
            if host:
                out.append(host.lower())
            continue
        host = candidate.split("/")[0].split("@")[-1]
        if _DOMAIN_SHAPE.match(host):
            out.append(host.lower())
    return out


def _walk_domain_fields(node: Any, out: set[str], depth: int = 0) -> None:
    """结构化遍历：只从域名语义字段取候选（值可为字符串或列表）。"""
    if depth > 5:
        return
    if isinstance(node, dict):
        for key, val in node.items():
            kname = str(key).lower()
            if kname in _NEVER_DOMAIN_FIELDS:
                continue
            if kname in _DOMAIN_FIELD_KEYS:
                for item in val if isinstance(val, list) else [val]:
                    out.update(_domain_candidates(str(item or "")))
            else:
                _walk_domain_fields(val, out, depth + 1)
    elif isinstance(node, list):
        for item in node[:50]:
            _walk_domain_fields(item, out, depth + 1)


def _is_plausible_domain(value: str) -> bool:
    """形状与语义上都像域名。"""
    domain = (value or "").strip().lower()
    if not domain or len(domain) > 253:
        return False
    if _IPV4_RE.match(domain) or ":" in domain:  # IP（含 v6）不是域名
        return False
    if "://" in domain or "/" in domain or domain.startswith("."):
        return False
    if _FAKE_TLD.search(domain):  # a.php / b.js 这类文件名
        return False
    if _MIME_PREFIX.match(domain.split(".", 1)[0]):  # vnd.ms / x-foo / octet-stream
        return False
    return bool(_DOMAIN_SHAPE.match(domain))


def _filter_domains(candidates: list[str], trusted: set[str]) -> tuple[list[str], list[str]]:
    """只留真域名：形状合法 **且** 出现在域名语义字段里（trusted）。

    为什么必须有 trusted 这一关：IOC 正则会把 `application/vnd.ms-cab-compressed`
    里的 vnd.ms 当成域名（形状完全合法），只有要求“它在 DNS/HTTP/URL 字段里真出现过”
    才能拦住这类污染。丢掉的都回传，供计数与日志（不静默）。
    """
    kept: list[str] = []
    rejected: list[str] = []
    for value in candidates:
        domain = str(value or "").strip().lower()
        if not _is_plausible_domain(domain) or domain not in trusted:
            rejected.append(domain)
            continue
        kept.append(domain)
    return kept, rejected


def _clean_domains(values: list[str]) -> list[str]:
    """过滤掉形似域名的文件名（a.php 这类），只留真域名。"""
    return [d for d in values if d and not _FAKE_TLD.search(d)]


def _dedup(values: list[str], limit: int = _MAX_PER_TYPE) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        key = str(value).strip()[:_MAX_KEY_LEN]
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(key)
        if len(out) >= limit:
            break
    return out


def extract_keys(
    *,
    src_ips: list[str] | None = None,
    dst_ips: list[str] | None = None,
    texts: list[str] | None = None,
    raws: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """抽取案件键，返回 ``{ip, host, acct, domain, hash, truncated}``（均去重）。

    只用源 IP 判"攻击者"：目的 IP 是被打的目标，混进键里会把"同一批被打的机器"
    误当成"同一攻击者"。
    """
    ips: list[str] = []
    hosts: list[str] = []
    for ip in src_ips or []:
        value = str(ip or "").strip()
        if not value:
            continue
        (ips if is_public_ip(value) else hosts).append(value)

    accounts: set[str] = set()
    text_parts: list[str] = list(texts or [])
    structured_domains: set[str] = set()
    for raw in raws or []:
        _walk_accounts(raw, accounts)
        _walk_domain_fields(raw, structured_domains)
        try:
            text_parts.append(json.dumps(raw, ensure_ascii=False, default=str)[:4000])
        except (TypeError, ValueError):
            continue

    iocs = ioc_extract(ToolContext(text="\n".join(text_parts)[:20000]))
    if settings.key_require_domain_field:
        # trusted 来源：结构化字段 + texts 里显式 URL 的 host（两者都是“域名语义”位置）
        trusted = set(structured_domains) | set(_url_hosts("\n".join(texts or [])))
        candidates = [*iocs["domains"], *_url_hosts("\n".join(text_parts)), *sorted(trusted)]
        domain_values, rejected = _filter_domains(candidates, trusted)
    else:
        # 兼容开关：关闭“必须来自域名字段”时回到旧行为（只做形状过滤）
        domain_values = _clean_domains(
            [*iocs["domains"], *_url_hosts("\n".join(text_parts)), *sorted(structured_domains)]
        )
        rejected = []
    domains = _dedup(domain_values)
    if rejected:
        sample_text = ", ".join(sorted({r for r in rejected if r})[:5])
        KEY_JUNK_REJECTED.refused += len(rejected)
        KEY_JUNK_REJECTED.last = sample_text
        KEY_JUNK_REJECTED.samples = sorted(
            {*KEY_JUNK_REJECTED.samples, *(r for r in rejected if r)}
        )[:10]
        log.info("键提取：丢弃 %d 个非域名候选（如 %s）", len(rejected), sample_text)
    return {
        "ip": _dedup(ips),
        "host": _dedup(hosts),
        "acct": _dedup(sorted(accounts)),
        "domain": domains,
        "hash": _dedup(iocs["hashes"]),
        "truncated": {
            "host": len(hosts) > _MAX_PER_TYPE,
            "domain": len(domain_values) > _MAX_PER_TYPE,
            "acct": len(accounts) > _MAX_PER_TYPE,
        },
    }


def key_set(keys: dict[str, Any] | None) -> set[str]:
    """把键字典摊平成 ``{"ip:1.2.3.4", ...}``，用于交集判断。"""
    out: set[str] = set()
    for kind in KEY_TYPES:
        for value in (keys or {}).get(kind) or []:
            out.add(f"{kind}:{value}")
    return out


def overlap(a: dict[str, Any] | None, b: dict[str, Any] | None) -> set[str]:
    return key_set(a) & key_set(b)


def strong_overlap(a: dict[str, Any] | None, b: dict[str, Any] | None) -> set[str]:
    """只算强键（ip/acct/hash）的交集 —— 自动归并的硬门槛。"""
    wanted = {f"{kind}:{value}" for kind in STRONG_KEYS for value in (a or {}).get(kind) or []}
    return wanted & key_set(b)


def weak_overlap(a: dict[str, Any] | None, b: dict[str, Any] | None) -> set[str]:
    """只算弱键（host/domain）的交集。"""
    wanted = {f"{kind}:{value}" for kind in WEAK_KEYS for value in (a or {}).get(kind) or []}
    return wanted & key_set(b)


def actor_of(keys: dict[str, Any] | None) -> str:
    """该组的“攻击源”标识：公网 IP 优先，其次内网主机。用于超限自动拆分。"""
    for kind in ("ip", "host"):
        for value in (keys or {}).get(kind) or []:
            return f"{kind}:{value}"
    return "unknown"


def primary_key(keys: dict[str, Any] | None) -> str:
    """按优先级选出主键（案件标题与 attacker_key）。无任何键时返回 ``unknown``。"""
    best: tuple[int, str] | None = None
    for kind in KEY_TYPES:
        for value in (keys or {}).get(kind) or []:
            candidate = (KEY_PRIORITY[kind], f"{kind}:{value}")
            if best is None or candidate[0] < best[0]:
                best = candidate
    return best[1] if best else "unknown"


def merge_keys(*items: dict[str, Any] | None) -> dict[str, list[str]]:
    """多组键求并集（案件吸收新组时用）。"""
    out: dict[str, list[str]] = {}
    for kind in KEY_TYPES:
        values: list[str] = []
        for item in items:
            values.extend((item or {}).get(kind) or [])
        out[kind] = _dedup(values)
    return out


def compact(keys: dict[str, Any] | None) -> dict[str, list[str]]:
    """去掉空列表与非列表值（如 truncated 标记），便于落库与界面展示。"""
    return {k: list(v) for k, v in (keys or {}).items() if isinstance(v, list) and v}
