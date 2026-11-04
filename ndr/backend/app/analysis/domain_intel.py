"""域名归属/用途的离线情报：给智能体判断 DNS 隧道类告警一个客观坐标。

为什么必须做在 NDR 侧：智能体没有外网 WHOIS/RDAP 工具，看到
``<32hex>.v.smtcdns.com`` 时只能凭“随机子域”猜；而腾讯 CDN、华为云 CDN、
Amazon 设备遥测等合法服务同样使用长随机子域。把已知厂商后缀固化成
**可查询的事实**，比在提示词里让模型“注意 CDN”可靠。

边界：这里只提供归属与用途提示，**不替智能体下结论**。已知 CDN 域名也可能
被滥用；真正的隧道仍要看 qtype（TXT/NULL）、查询频次、回包和载荷。
"""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from functools import lru_cache
from typing import Any
from urllib.parse import urlsplit

#: 已知的多级公共后缀（够当前现网用；RDAP/PSL 完整表不引入运行时依赖）。
_MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset(
    {
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "edu.cn",
        "co.uk",
        "org.uk",
        "ac.uk",
        "co.jp",
        "com.au",
        "net.au",
        "com.hk",
        "com.tw",
        "com.sg",
        "com.br",
        "co.kr",
    }
)

#: 已知厂商后缀 → 归属/用途。按后缀长度倒序匹配，避免 `com` 抢先。
_KNOWN_PROVIDERS: dict[str, dict[str, str]] = {
    "smtcdns.com": {
        "provider": "腾讯",
        "category": "CDN 调度",
        "reason": "腾讯自有 CDN 调度域，客户端 SDK 会生成 <随机>.<服务>.v.smtcdns.com",
    },
    "tfogc.com": {
        "provider": "腾讯",
        "category": "遥测/追踪",
        "reason": "WHOIS/ICP 归属腾讯，rdt 子域用于客户端遥测/归因，常见 32 位哈希标签",
    },
    "cdnhwc8.com": {
        "provider": "华为云",
        "category": "CDN 调度",
        "reason": "华为云 CDN 边缘调度域，长随机标签是正常分发主机名",
    },
    "cdnhwc8.cn": {
        "provider": "华为云",
        "category": "CDN 调度",
        "reason": "华为云 CDN 边缘调度域，长随机标签是正常分发主机名",
    },
    "a2z.com": {
        "provider": "Amazon",
        "category": "设备遥测",
        "reason": "Amazon 设备/应用遥测域（minerva 等），长哈希子域是设备标识",
    },
    "windowsupdate.com": {
        "provider": "Microsoft",
        "category": "系统更新",
        "reason": "Windows Update 分发域，长主机名常见于 CDN 边缘",
    },
    "microsoft.com": {
        "provider": "Microsoft",
        "category": "系统更新/遥测",
        "reason": "Microsoft 更新、遥测与 CDN 服务域",
    },
    "msftconnecttest.com": {
        "provider": "Microsoft",
        "category": "网络探测",
        "reason": "Windows 网络连通性探测域",
    },
    "qq.com": {
        "provider": "腾讯",
        "category": "业务/遥测",
        "reason": "腾讯业务与客户端遥测域",
    },
    "gtimg.cn": {
        "provider": "腾讯",
        "category": "CDN/图片",
        "reason": "腾讯图片/CDN 域",
    },
    "qpic.cn": {
        "provider": "腾讯",
        "category": "CDN/图片",
        "reason": "腾讯图片 CDN 域",
    },
    "myqcloud.com": {
        "provider": "腾讯云",
        "category": "对象存储/CDN",
        "reason": "腾讯云 COS/CDN 域",
    },
    "360.cn": {
        "provider": "360",
        "category": "终端业务/遥测",
        "reason": "360 安全终端业务与遥测域",
    },
    "qhimg.com": {
        "provider": "360",
        "category": "CDN/图片",
        "reason": "360 图片 CDN 域",
    },
    "douyincdn.com": {
        "provider": "字节跳动",
        "category": "CDN",
        "reason": "抖音/字节 CDN 域",
    },
    "bytefcdn.com": {
        "provider": "字节跳动",
        "category": "CDN",
        "reason": "字节跳动 CDN 域",
    },
    "easytier.cn": {
        "provider": "EasyTier",
        "category": "P2P 组网",
        "reason": "EasyTier overlay VPN 的 STUN/引导域；是否授权要看资产台账与业务归属",
    },
}

_REVERSE_SUFFIXES = ("ip6.arpa", "in-addr.arpa")


def normalize_domain(value: Any) -> str:
    """把 URL / 带端口 / 末尾点的输入归一成小写域名。"""
    text = str(value or "").strip().strip("\"'")
    if not text:
        return ""
    if "://" in text:
        try:
            text = str(urlsplit(text).hostname or "")
        except ValueError:
            return ""
    else:
        text = text.split("/", 1)[0]
    text = text.strip().strip(".").lower()
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        if port.isdigit():
            text = host
    return text


def registrable_domain(domain: str) -> str:
    """取可注册主域（无 PSL 依赖的常用后缀版本）。"""
    labels = [part for part in normalize_domain(domain).split(".") if part]
    if len(labels) <= 2:
        return ".".join(labels)
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return last_two


def _matched_suffix(domain: str) -> str:
    for suffix in sorted(_KNOWN_PROVIDERS, key=len, reverse=True):
        if domain == suffix or domain.endswith("." + suffix):
            return suffix
    return ""


def _vcard_value(entity: dict[str, Any], key: str) -> str:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return ""
    for item in vcard[1]:
        if not isinstance(item, list) or len(item) < 4 or str(item[0]).lower() != key:
            continue
        value = item[3]
        if isinstance(value, list):
            value = " ".join(str(x) for x in value)
        return str(value or "").strip()
    return ""


def _rdap_entity_name(entities: Any) -> str:
    if not isinstance(entities, list):
        return ""
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        for key in ("fn", "org"):
            value = _vcard_value(entity, key)
            if value:
                return value
        nested = _rdap_entity_name(entity.get("entities"))
        if nested:
            return nested
    return ""


@lru_cache(maxsize=512)
def _rdap_lookup(domain: str) -> dict[str, Any]:
    """RDAP 查询注册人（失败返回空对象；不把失败当“未知=恶意”）。"""
    if os.getenv("NDR_DOMAIN_RDAP", "1").strip().lower() in ("0", "false", "off", "no"):
        return {}
    url = "https://rdap.org/domain/" + urllib.parse.quote(domain, safe="")
    request = urllib.request.Request(url, headers={"User-Agent": "shentong-ndr/domain-intel"})
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            payload = json.loads(response.read(2_000_000).decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 — 外部网络不可用/超时不影响本判定
        return {}
    if not isinstance(payload, dict):
        return {}
    return {
        "registrant": _rdap_entity_name(payload.get("entities")),
        "handle": str(payload.get("handle") or ""),
        "rdap_url": url,
    }


def lookup_domain(value: Any, *, allow_network: bool = True) -> dict[str, Any]:
    """返回一个域名/URL 的归属、用途和 DNS 隧道判读提示。"""
    domain = normalize_domain(value)
    if not domain:
        return {"error": "要 qname 或 domain（例如 abc.v.smtcdns.com）"}
    if not any(ch.isalpha() for ch in domain):
        return {
            "input": str(value),
            "domain": domain,
            "known": False,
            "category": "IP/非域名",
            "guidance": "这是 IP 或非域名输入；域名归属查询需要主机名。",
        }
    if domain == "arpa" or domain.endswith(".arpa"):
        reverse = next((s for s in _REVERSE_SUFFIXES if domain == s or domain.endswith("." + s)), "")
        if reverse:
            return {
                "input": str(value),
                "domain": domain,
                "registrable_domain": reverse,
                "known": True,
                "provider": "DNS 反向解析",
                "category": "PTR 反查",
                "benign_for_long_random_subdomain": True,
                "reason": f"{reverse} 是标准反向 DNS 后缀；多段单字符标签通常是 IPv6/IPv4 PTR 编码",
                "guidance": "PTR 反查不是 DNS 隧道；仅凭长标签/单字符标签不能判 true_positive。",
            }
    reg = registrable_domain(domain)
    suffix = _matched_suffix(domain)
    if suffix:
        info = dict(_KNOWN_PROVIDERS[suffix])
        return {
            "input": str(value),
            "domain": domain,
            "registrable_domain": reg,
            "matched_suffix": suffix,
            "known": True,
            **info,
            "benign_for_long_random_subdomain": True,
            "guidance": (
                "该后缀是已知厂商基础设施，长随机子域本身不是隧道证据。"
                "仍需看 qtype 是否 TXT/NULL、单主机频次是否异常、是否有回包/载荷；"
                "若只有 A/AAAA/HTTPS 且频次与基线相当，倾向 false_positive/benign。"
            ),
        }
    rdap = _rdap_lookup(reg) if allow_network else {}
    if rdap.get("registrant"):
        return {
            "input": str(value),
            "domain": domain,
            "registrable_domain": reg,
            "known": True,
            "provider": str(rdap.get("registrant")),
            "category": "RDAP 注册信息",
            "registrant": str(rdap.get("registrant")),
            "rdap_url": str(rdap.get("rdap_url") or ""),
            # 注册人已知 ≠ 用途良性：CDN/云厂商子域仍可能被滥用，不能仅凭 owner 判 benign。
            "benign_for_long_random_subdomain": False,
            "guidance": (
                "RDAP 已返回注册人，但注册人只说明归属、不说明用途。"
                "仍需看 qtype（TXT/NULL）、单主机频次、回包/载荷；"
                "若注册人是已知 CDN/遥测厂商再结合域名用途库判断。"
            ),
        }
    return {
        "input": str(value),
        "domain": domain,
        "registrable_domain": reg,
        "known": False,
        "benign_for_long_random_subdomain": False,
        "guidance": (
            "未知域名（RDAP 未返回可用注册人）。32 位十六进制子域只能当线索："
            "单次查询先判 suspicious；要判 true_positive，至少要有 TXT/NULL 等隧道类型、"
            "单主机高频持续、异常回包/载荷或外部情报佐证。"
        ),
    }
