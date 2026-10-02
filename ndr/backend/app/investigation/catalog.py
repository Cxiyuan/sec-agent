"""取证查询的字段目录：统一字段名 → 真实 ES 字段路径 + 类型 + 中文说明。

**为什么必须白名单（fail-closed）**：模型极易编字段名（``scr_ip``/``source.ip``）。
拼错时 ES 只返回空结果，模型会据此误判「没有证据」——静默错误比报错危险得多。
因此未知字段一律报错并回传可用字段清单，让模型自我纠正。

字段路径依据（与代码逐一对齐，勿凭记忆改）：
- 归一化前置之后 ES 里**只有一族索引**（``settings.es_events_index`` = ``shentong-events-*``）：
  Zeek 与 Wazuh 的原始文档在入库前就被拍平成同一套**扁平统一字段**，字段名 =
  ``ndr/backend/app/schemas.py`` 里 ``class UnifiedLog`` 的字段名（``src_ip`` / ``dst_ip`` /
  ``log_type`` / ``summary`` …）。所以这里没有「来源 → 字段路径」的双列映射，
  也不存在「按来源选索引」的逻辑。
- 来源仍然要能区分：归一化把 ``source_system``（``zeek`` / ``wazuh``）写进了文档，
  工具的 ``source`` 参数就靠这个字段过滤（见 ``es_query.source_clause``）。
- 原始文档没丢：``UnifiedLog.raw`` 把归一化前的整份文档带进 ES 的 ``raw`` 对象，
  归一化**没有单列**的东西只能在这里翻（例如 Zeek files 日志的 ``raw.sha256``）。
  ``raw`` 本身是对象、不能直接 term/聚合，所以不进目录；要原样取证走 raw_evidence 工具。
- 时间字段统一 ``@timestamp``：Logstash 的 date 过滤器把统一字段 ``ts`` 搬过去
  （见 ``ndr/backend/app/collector/template.py``），``ts`` 原值也还在文档里。

运行期还会用 ES mapping 求交集（``available_fields``），字段名漂移时以真实 mapping 为准。
"""

from __future__ import annotations

import time
from typing import Any

from app.workers.log import get_logger

log = get_logger(__name__)

# 来源仍然是一个查询维度（source_system 字段的取值），但不再是索引维度：两者落同一族索引。
SOURCES = ("zeek", "wazuh")

# 字段种类决定允许的查询动作（见 es_query.build_clause）
# term/keyword 类：精确匹配 + contains；num/date：范围 + 精确；ip：精确/CIDR + 范围
FIELDS: dict[str, dict[str, Any]] = {
    # ---------- 通用 ----------
    "ts": {
        "path": "@timestamp",
        "kind": "date",
        "desc": "事件时间（Logstash 把统一字段 ts 搬到 @timestamp，排序/范围都走它）",
    },
    "source_system": {
        "path": "source_system",
        "kind": "keyword",
        "desc": "来源系统 zeek/wazuh（来源不再是索引维度，只能用这个字段区分）",
    },
    "event_type": {
        "path": "event_type",
        "kind": "keyword",
        "desc": "归一化事件类型（port_scan/brute_force/dns_query/http_login…）",
    },
    "log_type": {
        "path": "log_type",
        "kind": "keyword",
        "desc": "日志类型：Zeek 的 conn/http/dns/ssl/files/ssh/smtp/notice/dhcp；Wazuh 固定 wazuh",
    },
    "src_ip": {"path": "src_ip", "kind": "ip", "desc": "源地址"},
    "dst_ip": {"path": "dst_ip", "kind": "ip", "desc": "目的地址"},
    "src_port": {"path": "src_port", "kind": "num", "desc": "源端口"},
    "dst_port": {"path": "dst_port", "kind": "num", "desc": "目的端口"},
    "protocol": {
        "path": "protocol",
        "kind": "keyword",
        "desc": "协议（Zeek 的 proto，缺失时归一化回落到 service）",
    },
    "conn_state": {
        "path": "conn_state",
        "kind": "keyword",
        "desc": "连接状态 S0/SF/REJ…（仅 Zeek conn 日志有）",
    },
    "hostname": {
        "path": "hostname",
        "kind": "keyword",
        "desc": "主机名/域名：Zeek 的 HTTP Host 或 TLS SNI；Wazuh 的被采集主机名",
    },
    "user": {
        "path": "user",
        "kind": "keyword",
        "desc": "账号（Zeek 的 user / Wazuh 的 data.user）",
    },
    "account": {
        "path": "account",
        "kind": "keyword",
        "desc": "被操作或登录的账号（归一化从 user、请求体、参数里提取）",
    },
    "process": {
        "path": "process",
        "kind": "text",
        "desc": "进程名（命令执行证据，主要来自 Wazuh）",
    },
    "command": {"path": "command", "kind": "text", "desc": "命令行"},
    "severity": {
        "path": "severity",
        "kind": "keyword",
        "desc": "归一化告警级别 critical/high/medium/low/info（Wazuh rule.level 映射而来）",
    },
    "summary": {
        "path": "summary",
        "kind": "text",
        "desc": "一句话摘要（Zeek 的 note/msg；Wazuh 的 rule.description）",
    },
    "rule_id": {"path": "rule_id", "kind": "keyword", "desc": "Wazuh 规则 id"},
    "rule_groups": {"path": "rule_groups", "kind": "text", "desc": "Wazuh 规则组"},
    "mitre": {"path": "mitre", "kind": "text", "desc": "MITRE 技术编号"},
    # ---------- HTTP ----------
    "method": {"path": "method", "kind": "keyword", "desc": "HTTP 方法"},
    "query": {
        "path": "query",
        "kind": "text",
        "desc": "DNS 查询名 / HTTP 完整 URI（归一化把 uri 并进这里，原文仍在 raw.uri）",
    },
    "uri_path": {"path": "uri_path", "kind": "text", "desc": "URI 路径（不含查询串）"},
    "query_string": {"path": "query_string", "kind": "text", "desc": "URI 查询串（? 之后的部分）"},
    "user_agent": {"path": "user_agent", "kind": "text", "desc": "User-Agent"},
    "status_code": {"path": "status_code", "kind": "num", "desc": "HTTP 状态码"},
    "referer": {
        "path": "referer",
        "kind": "text",
        "desc": "Referer（原始日志里 referrer/referer 两种拼写，统一字段是 referer）",
    },
    "body": {
        "path": "body",
        "kind": "text",
        "desc": "请求正文（可能为空，体积大慎查）",
    },
    "cookie": {"path": "cookie", "kind": "text", "desc": "Cookie 头"},
    "auth_scheme": {
        "path": "auth_scheme",
        "kind": "keyword",
        "desc": "认证方式 Basic/Bearer…（登录爆破看这个）",
    },
    "content_type": {"path": "content_type", "kind": "keyword", "desc": "请求 Content-Type"},
    "resp_mime": {"path": "resp_mime", "kind": "keyword", "desc": "响应 MIME 类型"},
    "resp_body": {
        "path": "resp_body",
        "kind": "text",
        "desc": "响应正文（Zeek resp_body 截断后入库，可能为空；完整字节数看 resp_body_len）",
    },
    "resp_body_len": {
        "path": "resp_body_len",
        "kind": "num",
        "desc": "整条响应体的字节数（Zeek response_body_len，不受采集截断影响）",
    },
    "real_client_ip": {
        "path": "real_client_ip",
        "kind": "ip",
        "desc": "真实客户端 IP：代理头（X-Forwarded-For/Forwarded/Client-IP）解析出的最左地址；"
        "没带代理头时为 NULL（src_ip 仍是 TCP 对端，二者可能不同）",
    },
    # ---------- TLS ----------
    "ja3": {"path": "ja3", "kind": "keyword", "desc": "TLS 客户端指纹"},
    "ja3s": {"path": "ja3s", "kind": "keyword", "desc": "TLS 服务端指纹"},
    "tls_version": {"path": "tls_version", "kind": "keyword", "desc": "TLS 版本"},
    "cert_issuer": {"path": "cert_issuer", "kind": "text", "desc": "证书签发者"},
    # ---------- DNS ----------
    "qtype": {"path": "qtype", "kind": "keyword", "desc": "查询类型 A/AAAA/TXT…"},
    # ---------- 文件 ----------
    "filename": {"path": "filename", "kind": "text", "desc": "文件名"},
    "mime_type": {"path": "mime_type", "kind": "keyword", "desc": "文件类型"},
    "sha256": {
        "path": "raw.sha256",
        "kind": "keyword",
        "desc": "文件 SHA256：归一化没单列哈希字段，只在原样保留的 raw 里（Zeek files → raw.sha256）",
    },
    # ---------- 流量 ----------
    "bytes_out": {
        "path": "bytes_out",
        "kind": "num",
        "desc": "上行字节（外泄看这个；Zeek orig_bytes）",
    },
    "bytes_in": {"path": "bytes_in", "kind": "num", "desc": "下行字节（Zeek resp_bytes）"},
}

# "摘要观察"里默认带回来的字段（控体积）。原本按来源分两列，字段统一后只有一份。
# 顺序就是输出顺序：``ts`` 必须在里面（timeline / search 按它排序去重）。
SUMMARY_FIELDS: list[str] = [
    "ts",
    "log_type",
    "event_type",
    "source_system",
    "src_ip",
    "real_client_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "conn_state",
    "hostname",
    "method",
    "query",
    "uri_path",
    "query_string",
    "user_agent",
    "status_code",
    "referer",
    "qtype",
    "ja3",
    "ja3s",
    "tls_version",
    "cert_issuer",
    "filename",
    "mime_type",
    "sha256",
    "bytes_out",
    "bytes_in",
    "user",
    "account",
    "severity",
    "rule_id",
    "rule_groups",
    "mitre",
    "summary",
    "process",
    "command",
]

# 允许聚合的字段（terms 聚合只对低基数维度有意义；对 uri/body 聚合会爆分桶）
AGG_FIELDS: tuple[str, ...] = (
    "src_ip",
    "real_client_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "log_type",
    "event_type",
    "conn_state",
    "hostname",
    "method",
    "status_code",
    "user_agent",
    "query",
    "qtype",
    "ja3",
    "ja3s",
    "tls_version",
    "filename",
    "mime_type",
    "sha256",
    "user",
    "account",
    "severity",
    "rule_id",
    "rule_groups",
    "process",
    "source_system",
)

_mapping_cache: dict[str, tuple[float, dict[str, str]]] = {}
_MAPPING_TTL = 1800.0


def field_names() -> list[str]:
    return sorted(FIELDS)


def spec(name: str) -> dict[str, Any] | None:
    return FIELDS.get(name)


def resolve(name: str) -> str | None:
    """统一字段名 → 它在 ES 里的真实路径（不在目录里返回 None）。"""
    item = FIELDS.get(name)
    if not item:
        return None
    path = item.get("path")
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

    **必须合并所有匹配索引的 mapping**：``shentong-events-*`` 是按日期滚动的多索引，
    只看第一个（可能只有当天那一个索引，甚至刚 rollover 的空索引）会把字段白名单缩成个位数，
    模型就会被告知"这些字段不可查"（agent 侧部署时真实踩到：60 个字段只剩 3 个）。
    """
    now = time.monotonic()
    hit = _mapping_cache.get(index)
    if hit and (now - hit[0]) < _MAPPING_TTL:
        return hit[1]
    types: dict[str, str] = {}
    try:
        from app.ingestion.es_client import get_es

        raw = get_es().indices.get_mapping(index=index)
        for body in (raw or {}).values():
            props = (body.get("mappings") or {}).get("properties") or {}
            if isinstance(props, dict):
                _collect_types(props, types)
    except Exception as exc:  # noqa: BLE001
        log.debug("读取 ES mapping 失败（本次不做字段过滤）: %s", exc)
        types = {}
    _mapping_cache[index] = (now, types)
    return types


def _collect_types(
    props: dict[str, Any], out: dict[str, str], prefix: str = "", depth: int = 0
) -> None:
    """递归展开 properties，把「**完整路径** → 类型」写进 out（含 text 字段的 .keyword 子字段）。

    注意必须累积父路径前缀：嵌套对象的字段名是 ``raw`` → ``id`` → ``orig_h``，
    真正的查询路径是 ``raw.id.orig_h``；只收集叶子名会让白名单对不上（静默缩水）。
    """
    if depth > 6:
        return
    for key, val in props.items():
        if not isinstance(val, dict):
            continue
        full = f"{prefix}.{key}" if prefix else str(key)
        inner = val.get("properties")
        if isinstance(inner, dict):
            _collect_types(inner, out, full, depth + 1)
        else:
            out[full] = str(val.get("type") or "")
        subs = val.get("fields")
        if isinstance(subs, dict):
            for sub, sub_spec in subs.items():
                sub_item = sub_spec if isinstance(sub_spec, dict) else {}
                out[f"{full}.{sub}"] = str(sub_item.get("type") or "")


def es_type(index: str, path: str) -> str | None:
    """取某个真实字段路径的 ES 类型（拿不到 mapping 时返回 None=按未知处理）。"""
    types = mapping_types(index)
    if not types:
        return None
    if path in types:
        return types[path]
    # 带子字段（如 raw.sha256.keyword）→ 取主字段类型
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


def available_fields(index: str) -> dict[str, str]:
    """本索引真实可查的字段（目录 ∩ mapping）。mapping 拿不到时返回整个目录（不误伤）。

    注意粒度是**索引**而不是来源：统一结构下所有来源的文档字段一致（Zeek 日志没有
    ``rule_id`` 只是值为空，不是字段不存在），所以不再按来源裁剪字段。
    """
    present = mapping_types(index)
    out: dict[str, str] = {}
    for name in FIELDS:
        path = resolve(name)
        if not path:
            continue
        if present and path not in present:
            continue
        out[name] = path
    return out


def catalog_text(index: str, *, max_chars: int = 2600) -> str:
    """给模型看的字段清单（紧凑文本，超长截断）。"""
    fields = available_fields(index)
    lines = [f"【NDR 统一事件】索引 {index}"]
    for name in sorted(fields):
        item = FIELDS[name]
        lines.append(f"- {name}({item['kind']}): {item['desc']}")
    text = "\n".join(lines)
    return text[:max_chars]


def agg_fields(index: str) -> list[str]:
    present = available_fields(index)
    return [f for f in AGG_FIELDS if f in present]


def default_sources() -> tuple[str, ...]:
    """本次调查默认涉及的数据来源（同族索引，靠 source_system 过滤）。"""
    return SOURCES


def max_docs() -> int:
    """单次查询最多取多少文档（硬上限，绝不把 ES 打爆）。

    为什么写死在模块里：NDR 的 ``config.py`` 不在本次改造范围内，agent 侧那个
    ``investigation_max_docs_per_query`` 在这里没有对应配置项，就先按原默认值（2000）封顶。
    """
    return 2000
