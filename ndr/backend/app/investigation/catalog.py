"""取证查询的字段目录：统一字段名 → 真实 ES 字段路径 + 类型 + 中文说明。

**为什么必须白名单（fail-closed）**：模型极易编字段名（``scr_ip``/``source.ip``）。
拼错时 ES 只返回空结果，模型会据此误判「没有证据」——静默错误比报错危险得多。
因此未知字段一律报错并回传可用字段清单，让模型自我纠正。

字段路径依据（与代码逐一对齐，勿凭记忆改）：
- 归一化前置之后 ES 里**只有一族索引**（``settings.es_events_index`` = ``shentong-events-*``）：
  ``ndr/backend/app/schemas.py`` 里 ``class UnifiedLog`` 的字段名（``src_ip`` / ``dst_ip`` /
  ``log_type`` / ``summary`` …）。所以这里没有「来源 → 字段路径」的双列映射，
  也不存在「按来源选索引」的逻辑。
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
SOURCES = ("zeek", "suricata")

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
        "desc": "来源系统 zeek/suricata（来源不再是索引维度，只能用这个字段区分）",
    },
    "event_type": {
        "path": "event_type",
        "kind": "keyword",
        "desc": "归一化事件类型（port_scan/brute_force/dns_query/http_login…）",
    },
    "log_type": {
        "path": "log_type",
        "kind": "keyword",
        "desc": "日志类型：Zeek 的 conn/http/dns/ssl/files/ssh/smtp/notice/dhcp；签名引擎固定 suricata",
    },
    "log_type_known": {
        "path": "log_type_known",
        "kind": "bool",
        "desc": "该类型是否在采集白名单内：false = 白名单外的流，只入 ES、不进检测与画像",
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
    "weird_name": {
        "path": "weird_name",
        "kind": "keyword",
        "desc": (
            "Zeek weird.log 的异常名（如 bad_HTTP_request / possible_split_routing）；仅 weird 日志有。"
            "采集类异常（镜像口丢包/非对称路由/offload）会被归一化标成 capture_anomaly"
        ),
    },
    "session_id": {
        "path": "session_id",
        "kind": "keyword",
        "desc": (
            "会话 id（按 ST_SESSION_COOKIE_NAMES 从 Cookie 头精确取名、取第一个非空值）；"
            "「会话跨IP复用」的判据用它，不用整条 Cookie 头"
        ),
    },
    "community_id": {
        "path": "community_id",
        "kind": "keyword",
        "desc": (
            "Community ID（CIS 社区流标识）：Zeek conn.log 与签名引擎告警上同值，"
            "用来把两个采集器对同一条流的事实对上（不受 NAT/端口复用影响）"
        ),
    },
    "signature": {
        "path": "signature",
        "kind": "keyword",
        "desc": "签名名（Suricata alert.signature）；只有 source_system=suricata 的告警有值",
    },
    "signature_id": {
        "path": "signature_id",
        "kind": "keyword",
        "desc": "签名 SID（Suricata alert.signature_id），可回查规则集出处",
    },
    "signature_severity": {
        "path": "signature_severity",
        "kind": "num",
        "desc": "签名的严重度 1/2/3（Suricata 自己的 alert.severity；摘要级别按它分三档）",
    },
    "signature_category": {
        "path": "signature_category",
        "kind": "keyword",
        "desc": "签名类别（Suricata alert.category，如 Attempted Administrator Privilege Gain）",
    },
    "hostname": {
        "path": "hostname",
        "kind": "keyword",
        "desc": "主机名/域名：Zeek 的 HTTP Host 或 TLS SNI",
    },
    "user": {
        "path": "user",
        "kind": "keyword",
        "desc": "账号（Zeek 的 user / 请求体提取）",
    },
    "account": {
        "path": "account",
        "kind": "keyword",
        "desc": "被操作或登录的账号（归一化从 user、请求体、参数里提取）",
    },
    "process": {
        "path": "process",
        "kind": "text",
        "desc": "进程名（命令执行证据）",
    },
    "command": {"path": "command", "kind": "text", "desc": "命令行"},
    "severity": {
        "path": "severity",
        "kind": "keyword",
    },
    "summary": {
        "path": "summary",
        "kind": "text",
    },
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
    "req_headers": {
        "path": "req_headers",
        "kind": "text",
        "desc": "请求头全量文本（每行一头「名: 值」；单头 256 字节、同向总量 4KB 封顶）",
    },
    "resp_headers": {
        "path": "resp_headers",
        "kind": "text",
        "desc": "响应头全量文本（同 req_headers 的截断口径）",
    },
    "real_client_ip": {
        "path": "real_client_ip",
        "kind": "ip",
        "desc": "真实客户端 IP：代理头（X-Forwarded-For/Forwarded/Client-IP）解析出的最左地址；"
        "只有直连对端在中继清单里才认（清单在界面「监控网段」页维护，存 PG），否则为 NULL"
        "（src_ip 仍是 TCP 对端，二者可能不同）",
    },
    "uid": {
        "path": "uid",
        "kind": "keyword",
        "desc": "Zeek 连接 UID：可把 http/ssl/dns/files 与**同一条** conn 对上（拿字节/连接状态/时长）；",
    },
    "hop": {
        "path": "hop",
        "kind": "keyword",
        "desc": "中继链路位置：direct=不涉及中继；front=目的在中继清单（客户端→中继）；"
        "back=来源在中继清单（中继→真实目的）；relay_internal=两端都是中继。"
        "检测/画像/资产只处理 front 与 direct",
    },
    # ---------- TLS ----------
    "ja3": {"path": "ja3", "kind": "keyword", "desc": "TLS 客户端指纹"},
    "ja3s": {"path": "ja3s", "kind": "keyword", "desc": "TLS 服务端指纹"},
    "ja4": {
        "path": "ja4",
        "kind": "keyword",
        "desc": "JA4 TLS 客户端指纹（BSD 子集脚本产出；JA4S/JA4H 等 JA4+ 因许可证未收录，恒空）",
    },
    "tls_version": {"path": "tls_version", "kind": "keyword", "desc": "TLS 版本"},
    "tls_established": {
        "path": "tls_established",
        "kind": "bool",
        "desc": "TLS 握手是否真的建立（Zeek ssl.log 的 established）；「TLS 握手失败风暴」的判据",
    },
    "cert_issuer": {"path": "cert_issuer", "kind": "text", "desc": "证书签发者"},
    "cert_self_signed": {
        "path": "cert_self_signed",
        "kind": "bool",
        "desc": "自签证书（归一化层比较 certificate.subject == certificate.issuer；引擎无法比字段，只能在这里算）",
    },
    # ---------- DNS ----------
    # 存的是 Zeek dns.log 的原始数字码，不是类型名（实机聚合出来的就是 1/28/16/32）。
    # 别按“值是 A/AAAA/TXT”去写过滤条件——那样永远查不到。
    "qtype": {
        "path": "qtype",
        "kind": "keyword",
        "desc": "DNS 查询类型的数字码：1=A、28=AAAA、16=TXT、32=SRV…（Zeek 原值，不是类型名）",
    },
    # ---------- 文件 ----------
    "filename": {"path": "filename", "kind": "text", "desc": "文件名"},
    "mime_type": {"path": "mime_type", "kind": "keyword", "desc": "文件类型"},
    "fuid": {
        "path": "fuid",
        "kind": "keyword",
        "desc": "Zeek 文件 id：可与 http/dns/smtp 等日志里的 fuids 对上，串起“哪个连接传了它”",
    },
    "md5": {
        "path": "md5",
        "kind": "keyword",
        "desc": "文件 MD5（Zeek FileHash 分析器算好落 files.log）",
    },
    "sha1": {"path": "sha1", "kind": "keyword", "desc": "文件 SHA1"},
    "sha256": {"path": "sha256", "kind": "keyword", "desc": "文件 SHA256"},
    "file_source": {
        "path": "file_source",
        "kind": "keyword",
        "desc": "文件来源协议：HTTP / FTP / SMTP / SSL…（Zeek files.log 的 source）",
    },
    "file_is_orig": {
        "path": "file_is_orig",
        "kind": "bool",
        "desc": "文件方向：true=客户端上传，false=服务端下发（ES 里是 boolean 类型）",
    },
    "extracted": {
        "path": "extracted",
        "kind": "keyword",
        "desc": "提取件在 Zeek 容器 /extract 里的文件名（当前 = fuid）；下载走 GET /api/files/{fuid}",
    },
    "extracted_size": {
        "path": "extracted_size",
        "kind": "num",
        "desc": "提取件实际落盘字节数（被单文件上限截断时小于 total_bytes）",
    },
    "extracted_cutoff": {
        "path": "extracted_cutoff",
        "kind": "keyword",
        "desc": "提取件是否被单文件上限截断（true=只留了前 N 字节）",
    },
    # ---------- 流量 ----------
    "bytes_out": {
        "path": "bytes_out",
        "kind": "num",
        "desc": "上行字节（外泄看这个；Zeek orig_bytes）",
    },
    "bytes_in": {"path": "bytes_in", "kind": "num", "desc": "下行字节（Zeek resp_bytes）"},
    # Zeek stats.log（每 5 分钟上报一条）的抓包丢包/收包计数：仪表盘掉包折线的数据源
    "pkts_dropped": {
        "path": "pkts_dropped",
        "kind": "num",
        "desc": "Zeek 上报的丢包数（stats.log，每 5 分钟一条；原值，非累加）",
    },
    "pkts_proc": {"path": "pkts_proc", "kind": "num", "desc": "Zeek 已处理包数（stats.log）"},
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
    "weird_name",
    "community_id",
    "signature",
    "signature_id",
    "signature_severity",
    "signature_category",
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
    "ja4",
    "tls_version",
    "tls_established",
    "cert_issuer",
    "filename",
    "mime_type",
    "fuid",
    "file_source",
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
    "weird_name",
    "signature",
    "signature_id",
    "signature_category",
    "hostname",
    "method",
    "status_code",
    "user_agent",
    "query",
    "qtype",
    "ja3",
    "ja3s",
    "ja4",
    "tls_version",
    "filename",
    "mime_type",
    "fuid",
    "md5",
    "sha1",
    "sha256",
    "file_source",
    "file_is_orig",
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
