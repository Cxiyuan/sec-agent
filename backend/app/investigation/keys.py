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
from typing import Any
from urllib.parse import urlparse

from app.tools.context import ToolContext, is_public_ip
from app.tools.local import ioc_extract

# 主键优先级（越小越优先）：决定案件标题与 attacker_key 显示
KEY_PRIORITY: dict[str, int] = {"ip": 0, "acct": 1, "domain": 2, "hash": 3, "host": 4}
KEY_TYPES: tuple[str, ...] = ("ip", "acct", "domain", "hash", "host")
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
) -> dict[str, list[str]]:
    """抽取案件键，返回 ``{ip, host, acct, domain, hash}``（均为去重后的列表）。

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
    for raw in raws or []:
        _walk_accounts(raw, accounts)
        try:
            text_parts.append(json.dumps(raw, ensure_ascii=False, default=str)[:4000])
        except (TypeError, ValueError):
            continue

    iocs = ioc_extract(ToolContext(text="\n".join(text_parts)[:20000]))
    domains = _dedup(_clean_domains([*iocs["domains"], *_url_hosts("\n".join(text_parts))]))
    return {
        "ip": _dedup(ips),
        "host": _dedup(hosts),
        "acct": _dedup(sorted(accounts)),
        "domain": domains,
        "hash": _dedup(iocs["hashes"]),
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
    """去掉空列表，便于落库与界面展示。"""
    return {k: list(v) for k, v in (keys or {}).items() if v}
