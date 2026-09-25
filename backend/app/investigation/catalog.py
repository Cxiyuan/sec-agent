"""取证查询的字段目录：逻辑字段 → 各来源真实 ES 字段路径 + 类型。

**为什么必须白名单（fail-closed）**：模型极易编字段名（``scr_ip``/``source.ip``）。
拼错时 ES 只返回空结果，模型会据此误判「没有证据」——静默错误比报错危险得多。
因此未知字段一律报错并回传可用字段清单，让模型自我纠正。

字段路径依据（与代码逐一对齐，勿凭记忆改）：
- Zeek：Filebeat 的 ``ndjson.target: zeek`` 把字段收进 ``zeek.*`` 命名空间，
  ``log_type`` 由 script 处理器写在**顶层**（见 ``zeek/filebeat.yml``）；
  ``body`` 是 ``shentong-httpbody.zeek`` 给 http 加的自定义字段。
- Wazuh：``data.*`` / ``rule.*`` / ``agent.*``（见 ``normalizer.normalize_wazuh``）。
- 时间字段统一 ``@timestamp``。

运行期还会用 ES mapping 求交集（``available_fields``），字段名漂移时以真实 mapping 为准。
"""

from __future__ import annotations

import time
from typing import Any

from app.config import settings
from app.workers.log import get_logger

log = get_logger(__name__)

SOURCE_KINDS = ("zeek", "wazuh")

# 字段种类决定允许的查询动作（见 es_query.build_clause）
# term/keyword 类：精确匹配 + contains；num/date：范围 + 精确；ip：精确/CIDR + 范围
FIELDS: dict[str, dict[str, Any]] = {
    # ---------- 通用 ----------
    "ts": {"zeek": "@timestamp", "wazuh": "@timestamp", "kind": "date", "desc": "事件时间"},
    "src_ip": {
        "zeek": "zeek.id.orig_h",
        "wazuh": "data.srcip",
        "kind": "ip",
        "desc": "源地址",
    },
    "dst_ip": {
        "zeek": "zeek.id.resp_h",
        "wazuh": "data.dstip",
        "kind": "ip",
        "desc": "目的地址",
    },
    "src_port": {"zeek": "zeek.id.orig_p", "wazuh": "data.srcport", "kind": "num", "desc": "源端口"},
    "dst_port": {
        "zeek": "zeek.id.resp_p",
        "wazuh": "data.dstport",
        "kind": "num",
        "desc": "目的端口",
    },
    "proto": {"zeek": "zeek.proto", "wazuh": "data.protocol", "kind": "keyword", "desc": "协议"},
    "source_system": {"zeek": "source_system", "wazuh": "source_system", "kind": "keyword", "desc": "来源系统"},
    "log_type": {"zeek": "log_type", "wazuh": None, "kind": "keyword", "desc": "Zeek 日志类型 conn/http/dns/ssl/files/ssh/smtp/notice"},
    # ---------- 连接/流量 ----------
    "conn_state": {"zeek": "zeek.conn_state", "wazuh": None, "kind": "keyword", "desc": "连接状态 S0/SF/REJ…"},
    "service": {"zeek": "zeek.service", "wazuh": None, "kind": "keyword", "desc": "应用层协议识别（http/dns/ssl…）"},
    "duration": {"zeek": "zeek.duration", "wazuh": None, "kind": "num", "desc": "连接时长（秒）"},
    "bytes_out": {"zeek": "zeek.orig_bytes", "wazuh": None, "kind": "num", "desc": "上行字节（外泄看这个）"},
    "bytes_in": {"zeek": "zeek.resp_bytes", "wazuh": None, "kind": "num", "desc": "下行字节"},
    # ---------- HTTP ----------
    "method": {"zeek": "zeek.method", "wazuh": "data.method", "kind": "keyword", "desc": "HTTP 方法"},
    "host": {"zeek": "zeek.host", "wazuh": None, "kind": "keyword", "desc": "HTTP Host 头/域名"},
    "uri": {"zeek": "zeek.uri", "wazuh": "data.url", "kind": "text", "desc": "请求 URL（含路径与参数）"},
    "user_agent": {"zeek": "zeek.user_agent", "wazuh": "data.user_agent", "kind": "text", "desc": "User-Agent"},
    "status_code": {"zeek": "zeek.status_code", "wazuh": "data.status", "kind": "num", "desc": "HTTP 状态码"},
    "referrer": {"zeek": "zeek.referrer", "wazuh": "data.referer", "kind": "text", "desc": "Referer"},
    "body": {"zeek": "zeek.body", "wazuh": "data.request_body", "kind": "text", "desc": "请求正文（可能为空，体积大慎查）"},
    # ---------- TLS ----------
    "ja3": {"zeek": "zeek.ja3", "wazuh": None, "kind": "keyword", "desc": "TLS 客户端指纹"},
    "ja3s": {"zeek": "zeek.ja3s", "wazuh": None, "kind": "keyword", "desc": "TLS 服务端指纹"},
    "server_name": {"zeek": "zeek.server_name", "wazuh": None, "kind": "keyword", "desc": "TLS SNI"},
    "tls_version": {"zeek": "zeek.version", "wazuh": None, "kind": "keyword", "desc": "TLS 版本"},
    "cert_issuer": {"zeek": "zeek.issuer", "wazuh": None, "kind": "text", "desc": "证书签发者"},
    # ---------- DNS ----------
    "query": {"zeek": "zeek.query", "wazuh": None, "kind": "text", "desc": "DNS 查询名 / 通用查询串"},
    "qtype": {"zeek": "zeek.qtype_name", "wazuh": None, "kind": "keyword", "desc": "查询类型 A/AAAA/TXT…"},
    "rcode": {"zeek": "zeek.rcode_name", "wazuh": None, "kind": "keyword", "desc": "DNS 响应码"},
    "answers": {"zeek": "zeek.answers", "wazuh": None, "kind": "text", "desc": "DNS 应答（列表）"},
    # ---------- 文件 ----------
    "filename": {"zeek": "zeek.filename", "wazuh": None, "kind": "text", "desc": "文件名"},
    "mime_type": {"zeek": "zeek.mime_type", "wazuh": None, "kind": "keyword", "desc": "文件类型"},
    "fuid": {"zeek": "zeek.fuid", "wazuh": None, "kind": "keyword", "desc": "Zeek 文件唯一 id"},
    "md5": {"zeek": "zeek.md5", "wazuh": None, "kind": "keyword", "desc": "文件 MD5"},
    "sha1": {"zeek": "zeek.sha1", "wazuh": None, "kind": "keyword", "desc": "文件 SHA1"},
    "sha256": {"zeek": "zeek.sha256", "wazuh": None, "kind": "keyword", "desc": "文件 SHA256"},
    # ---------- SSH / 账号 ----------
    "user": {"zeek": "zeek.user", "wazuh": "data.user", "kind": "keyword", "desc": "账号"},
    "auth_success": {"zeek": "zeek.auth_success", "wazuh": None, "kind": "bool", "desc": "SSH 登录是否成功"},
    "auth_attempts": {"zeek": "zeek.auth_attempts", "wazuh": None, "kind": "num", "desc": "SSH 尝试次数"},
    "client": {"zeek": "zeek.client", "wazuh": None, "kind": "text", "desc": "SSH 客户端版本串"},
    # ---------- Zeek 告警 ----------
    "note": {"zeek": "zeek.note", "wazuh": None, "kind": "keyword", "desc": "Zeek notice 类型"},
    "msg": {"zeek": "zeek.msg", "wazuh": None, "kind": "text", "desc": "Zeek notice 说明"},
    # ---------- Wazuh ----------
    "rule_id": {"zeek": None, "wazuh": "rule.id", "kind": "keyword", "desc": "Wazuh 规则 id"},
    "rule_level": {"zeek": None, "wazuh": "rule.level", "kind": "num", "desc": "Wazuh 告警级别 0-15"},
    "rule_groups": {"zeek": None, "wazuh": "rule.groups", "kind": "text", "desc": "Wazuh 规则组"},
    "rule_desc": {"zeek": None, "wazuh": "rule.description", "kind": "text", "desc": "Wazuh 规则描述"},
    "mitre": {"zeek": None, "wazuh": "rule.mitre.id", "kind": "text", "desc": "MITRE 技术编号"},
    "agent_name": {"zeek": None, "wazuh": "agent.name", "kind": "keyword", "desc": "Wazuh 被采集主机名"},
    "process": {"zeek": None, "wazuh": "data.process", "kind": "text", "desc": "进程名（命令执行证据）"},
    "command": {"zeek": None, "wazuh": "data.command", "kind": "text", "desc": "命令行"},
    "wazuh_url": {"zeek": None, "wazuh": "data.url", "kind": "text", "desc": "Wazuh 记录的 URL"},
}

# 各来源"摘要观察"里默认带回来的字段（控体积）
SUMMARY_FIELDS: dict[str, list[str]] = {
    "zeek": [
        "ts",
        "log_type",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "proto",
        "conn_state",
        "service",
        "method",
        "host",
        "uri",
        "user_agent",
        "status_code",
        "query",
        "qtype",
        "answers",
        "ja3",
        "server_name",
        "filename",
        "mime_type",
        "md5",
        "sha256",
        "bytes_out",
        "bytes_in",
        "user",
        "auth_success",
        "note",
        "msg",
    ],
    "wazuh": [
        "ts",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "proto",
        "rule_id",
        "rule_level",
        "rule_groups",
        "rule_desc",
        "mitre",
        "agent_name",
        "process",
        "command",
        "wazuh_url",
        "user",
    ],
}

# 允许聚合的字段（terms 聚合只对低基数维度有意义；对 uri/body 聚合会爆分桶）
AGG_FIELDS: tuple[str, ...] = (
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "proto",
    "log_type",
    "conn_state",
    "service",
    "method",
    "host",
    "status_code",
    "user_agent",
    "query",
    "qtype",
    "rcode",
    "ja3",
    "ja3s",
    "server_name",
    "filename",
    "mime_type",
    "md5",
    "sha256",
    "user",
    "note",
    "agent_name",
    "process",
    "rule_id",
    "rule_groups",
)

_mapping_cache: dict[str, tuple[float, dict[str, str]]] = {}
_MAPPING_TTL = 1800.0


def field_names() -> list[str]:
    return sorted(FIELDS)


def spec(name: str) -> dict[str, Any] | None:
    return FIELDS.get(name)


def resolve(kind: str, name: str) -> str | None:
    """逻辑字段 → 该来源的真实 ES 字段路径（不存在返回 None）。"""
    item = FIELDS.get(name)
    if not item:
        return None
    path = item.get(kind)
    return str(path) if path else None


def kind_of(name: str) -> str:
    item = FIELDS.get(name) or {}
    return str(item.get("kind") or "keyword")


def mapping_types(index: str) -> dict[str, str]:
    """取索引 mapping 的 ``{字段全名: ES 类型}``（30 分钟内存缓存，失败返回空 dict=不做过滤）。

    为什么要类型：
    - ``text`` 字段不能直接聚合（会报 fielddata 错误）也不能 term 精确匹配，必须走 ``.keyword``；
    - ``keyword`` 字段没有 ``.keyword`` 子字段，拼上去会静默返回空结果。
    只有拿到真实类型才能选对路径，避免「静默空结果」误导模型。
    """
    now = time.monotonic()
    hit = _mapping_cache.get(index)
    if hit and (now - hit[0]) < _MAPPING_TTL:
        return hit[1]
    types: dict[str, str] = {}
    try:
        from app.ingestion.es_client import get_es
        from app.ingestion.es_schema import es_mapping

        props = es_mapping(get_es(), index)

        def walk(node: Any, prefix: str, depth: int = 0) -> None:
            if depth > 6 or not isinstance(node, dict):
                return
            for key, val in node.items():
                full = f"{prefix}.{key}" if prefix else str(key)
                if isinstance(val, dict) and "type" not in val:
                    inner = val.get("properties")
                    if isinstance(inner, dict):
                        walk(inner, full, depth + 1)
                    else:
                        walk(val, full, depth + 1)
                else:
                    types[full] = str((val or {}).get("type") or "") if isinstance(val, dict) else ""

        walk(props, "")
    except Exception as exc:  # noqa: BLE001
        log.debug("读取 ES mapping 失败（本次不做字段过滤）: %s", exc)
        types = {}
    _mapping_cache[index] = (now, types)
    return types


def es_type(index: str, path: str) -> str | None:
    """取某个真实字段路径的 ES 类型（拿不到 mapping 时返回 None=按未知处理）。"""
    types = mapping_types(index)
    if not types:
        return None
    if path in types:
        return types[path]
    # 带子字段（如 zeek.uri.keyword）→ 取主字段类型
    if path.endswith(".keyword") and path[: -len(".keyword")] in types:
        return types[path[: -len(".keyword")]]
    return None


def term_paths(index: str, path: str) -> list[str]:
    """精确匹配该走的路径（text 字段必须走 .keyword，否则 ES 不匹配）。"""
    etype = es_type(index, path)
    if etype == "text":
        types = mapping_types(index)
        return [f"{path}.keyword"] if f"{path}.keyword" in types else []
    return [path]


def agg_path(index: str, path: str) -> str:
    """聚合该走的路径（text 不可聚合 → 用 .keyword）。"""
    etype = es_type(index, path)
    if etype == "text":
        types = mapping_types(index)
        if f"{path}.keyword" in types:
            return f"{path}.keyword"
    return path


def available_fields(kind: str, index: str) -> dict[str, str]:
    """该来源真实可查的字段（目录 ∩ mapping）。mapping 拿不到时返回整个目录（不误伤）。"""
    present = mapping_types(index)
    out: dict[str, str] = {}
    for name in FIELDS:
        path = resolve(kind, name)
        if not path:
            continue
        if present and path not in present:
            continue
        out[name] = path
    return out


def catalog_text(kind: str, index: str, *, max_chars: int = 2600) -> str:
    """给模型看的字段清单（紧凑文本，超长截断）。"""
    fields = available_fields(kind, index)
    lines = [f"【{kind}】索引 {index}"]
    for name in sorted(fields):
        item = FIELDS[name]
        lines.append(f"- {name}({item['kind']}): {item['desc']}")
    text = "\n".join(lines)
    return text[:max_chars]


def agg_fields(kind: str, index: str) -> list[str]:
    present = available_fields(kind, index)
    return [f for f in AGG_FIELDS if f in present]


def default_sources() -> tuple[str, ...]:
    """本次调查涉及的数据来源（两个索引默认都查）。"""
    return SOURCE_KINDS


def max_docs() -> int:
    return max(1, min(settings.investigation_max_docs_per_query, 5000))
