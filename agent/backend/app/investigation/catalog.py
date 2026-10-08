"""智能体侧字段目录：只用来渲染给模型看的「字段目录」提示词文本。

字段路径（ES 的 ``zeek.*`` / ``data.*``）、mapping 探测、term/agg 路径选择、
「哪些字段在本索引真实可用」（NDR 的 ``describe_data`` 工具返回）都由 NDR 侧负责；
这里只是一份「逻辑字段名 → 类型 + 中文说明」的展示目录，不查 ES、不做任何查询构造。

**为什么仍然要白名单（fail-closed）**：模型极易编字段名（``scr_ip``/``source.ip``）。
拼错时查询只返回空结果，模型会据此误判「没有证据」——静默错误比报错危险得多。
因此未知字段一律忽略，并回传可用字段清单，让模型自我纠正。

权威来源：``ndr/backend/app/investigation/catalog.py``（字段名 / kind / desc 逐字一致，
仅去掉 ES 路径信息）。改字段请先改 NDR 侧，再同步这里。
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

# 默认数据来源（NDR 侧靠 source_system 字段过滤，不再是索引维度）。
SOURCES = ("zeek", "suricata")

# 单次查询条数上限（与 NDR 侧一致）。
MAX_DOCS = 2000

# 字段种类决定允许的查询动作（由 NDR 侧执行）：
# term/keyword 类：精确匹配 + contains；num/date：范围 + 精确；ip：精确/CIDR + 范围。
FIELDS: dict[str, dict[str, Any]] = {
    # ---------- 通用 ----------
    "ts": {
        "kind": "date",
        "desc": "事件时间（Logstash 把统一字段 ts 搬到 @timestamp，排序/范围都走它）",
    },
    "source_system": {
        "kind": "keyword",
        "desc": "来源系统 zeek/suricata（来源不再是索引维度，只能用这个字段区分）",
    },
    "event_type": {
        "kind": "keyword",
        "desc": "归一化事件类型（port_scan/brute_force/dns_query/http_login…）",
    },
    "log_type": {
        "kind": "keyword",
        "desc": "日志类型：Zeek 的 conn/http/dns/ssl/files/ssh/smtp/notice/dhcp；签名引擎固定 suricata",
    },
    "src_ip": {
        "kind": "ip",
        "desc": "源地址",
    },
    "dst_ip": {
        "kind": "ip",
        "desc": "目的地址",
    },
    "src_port": {
        "kind": "num",
        "desc": "源端口",
    },
    "dst_port": {
        "kind": "num",
        "desc": "目的端口",
    },
    "protocol": {
        "kind": "keyword",
        "desc": "协议（Zeek 的 proto，缺失时归一化回落到 service）",
    },
    "conn_state": {
        "kind": "keyword",
        "desc": "连接状态 S0/SF/REJ…（仅 Zeek conn 日志有）",
    },
    "hostname": {
        "kind": "keyword",
        "desc": "主机名/域名：Zeek 的 HTTP Host 或 TLS SNI",
    },
    "user": {
        "kind": "keyword",
        "desc": "账号（Zeek 的 user / 请求体提取）",
    },
    "account": {
        "kind": "keyword",
        "desc": "被操作或登录的账号（归一化从 user、请求体、参数里提取）",
    },
    "process": {
        "kind": "text",
        "desc": "进程名（命令执行证据）",
    },
    "command": {
        "kind": "text",
        "desc": "命令行",
    },
    "severity": {
        "kind": "keyword",
    },
    "summary": {
        "kind": "text",
    },
    "rule_id": {
        "kind": "keyword",
    },
    "rule_groups": {
        "kind": "text",
    },
    "mitre": {
        "kind": "text",
        "desc": "MITRE 技术编号",
    },
    # ---------- HTTP ----------
    "method": {
        "kind": "keyword",
        "desc": "HTTP 方法",
    },
    "query": {
        "kind": "text",
        "desc": "DNS 查询名 / HTTP 完整 URI（归一化把 uri 并进这里，原文仍在 raw.uri）",
    },
    "uri_path": {
        "kind": "text",
        "desc": "URI 路径（不含查询串）",
    },
    "query_string": {
        "kind": "text",
        "desc": "URI 查询串（? 之后的部分）",
    },
    "user_agent": {
        "kind": "text",
        "desc": "User-Agent",
    },
    "status_code": {
        "kind": "num",
        "desc": "HTTP 状态码",
    },
    "referer": {
        "kind": "text",
        "desc": "Referer（原始日志里 referrer/referer 两种拼写，统一字段是 referer）",
    },
    "body": {
        "kind": "text",
        "desc": "请求正文（可能为空，体积大慎查）",
    },
    "cookie": {
        "kind": "text",
        "desc": "Cookie 头",
    },
    "auth_scheme": {
        "kind": "keyword",
        "desc": "认证方式 Basic/Bearer…（登录爆破看这个）",
    },
    "content_type": {
        "kind": "keyword",
        "desc": "请求 Content-Type",
    },
    "resp_mime": {
        "kind": "keyword",
        "desc": "响应 MIME 类型",
    },
    "resp_body": {
        "kind": "text",
        "desc": "响应正文（Zeek resp_body 截断后入库，可能为空；完整字节数看 resp_body_len）",
    },
    "resp_body_len": {
        "kind": "num",
        "desc": "整条响应体的字节数（Zeek response_body_len，不受采集截断影响）",
    },
    "req_headers": {
        "kind": "text",
        "desc": "请求头全量文本（每行一头「名: 值」；单头 256 字节、同向总量 4KB 封顶）",
    },
    "resp_headers": {
        "kind": "text",
        "desc": "响应头全量文本（同 req_headers 的截断口径）",
    },
    "real_client_ip": {
        "kind": "ip",
        "desc": "真实客户端 IP：代理头（X-Forwarded-For/Forwarded/Client-IP）解析出的最左地址；"
        "没带代理头时为 NULL（src_ip 仍是 TCP 对端，二者可能不同）",
    },
    # ---------- TLS ----------
    "ja3": {
        "kind": "keyword",
        "desc": "TLS 客户端指纹",
    },
    "ja3s": {
        "kind": "keyword",
        "desc": "TLS 服务端指纹",
    },
    "ja4": {
        "kind": "keyword",
        "desc": "JA4 TLS 客户端指纹（BSD 子集脚本产出；JA4S/JA4H 等 JA4+ 因许可证未收录，恒空）",
    },
    "tls_version": {
        "kind": "keyword",
        "desc": "TLS 版本",
    },
    "cert_issuer": {
        "kind": "text",
        "desc": "证书签发者",
    },
    # ---------- DNS ----------
    "qtype": {
        "kind": "keyword",
        "desc": "查询类型 A/AAAA/TXT…",
    },
    # ---------- 文件 ----------
    "filename": {
        "kind": "text",
        "desc": "文件名",
    },
    "mime_type": {
        "kind": "keyword",
        "desc": "文件类型",
    },
    "fuid": {
        "kind": "keyword",
        "desc": "Zeek 文件 id：可与 http/dns/smtp 等日志里的 fuids 对上，串起“哪个连接传了它”",
    },
    "md5": {
        "kind": "keyword",
        "desc": "文件 MD5（Zeek FileHash 分析器算好落 files.log）",
    },
    "sha1": {
        "kind": "keyword",
        "desc": "文件 SHA1",
    },
    "sha256": {
        "kind": "keyword",
        "desc": "文件 SHA256",
    },
    "file_source": {
        "kind": "keyword",
        "desc": "文件来源协议：HTTP / FTP / SMTP / SSL…（Zeek files.log 的 source）",
    },
    "file_is_orig": {
        "kind": "keyword",
        "desc": "文件方向：true=客户端上传，false=服务端下发",
    },
    "extracted": {
        "kind": "keyword",
        "desc": "提取件在 Zeek 容器 /extract 里的文件名（当前 = fuid）；下载走 NDR 后端 GET /api/files/{fuid}",
    },
    "extracted_size": {
        "kind": "num",
        "desc": "提取件实际落盘字节数（被单文件上限截断时小于 total_bytes）",
    },
    "extracted_cutoff": {
        "kind": "keyword",
        "desc": "提取件是否被单文件上限截断（true=只留了前 N 字节）",
    },
    # ---------- 流量 ----------
    "bytes_out": {
        "kind": "num",
        "desc": "上行字节（外泄看这个；Zeek orig_bytes）",
    },
    "bytes_in": {
        "kind": "num",
        "desc": "下行字节（Zeek resp_bytes）",
    },
}

# "摘要观察"里默认带回来的字段（控体积，顺序就是输出顺序）。
# 顺序就是输出顺序：``ts`` 必须在里面（timeline / search 按它排序去重）。
SUMMARY_FIELDS: tuple[str, ...] = (
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
    "ja4",
    "tls_version",
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
)

# 允许聚合的字段（terms 聚合只对低基数维度有意义；对 uri/body 聚合会爆分桶）。
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


def field_names() -> list[str]:
    """返回排序后的全部字段名。"""
    return sorted(FIELDS)


def default_sources() -> tuple[str, ...]:
    """本次调查默认涉及的数据来源（NDR 侧靠 source_system 字段区分）。"""
    return SOURCES


def max_docs() -> int:
    """单次查询条数上限，与 NDR 侧一致。"""
    return MAX_DOCS


def catalog_text(
    index: str,
    fields: Sequence[str] | None = None,
    *,
    max_chars: int = 2600,
) -> str:
    """渲染给模型看的字段目录提示词。

    - ``fields=None``：渲染全部字段；给了就只渲染其中存在于 ``FIELDS`` 的名字
      （保持 ``FIELDS`` 的定义顺序，未知名字忽略；空列表 = 没有可用字段）。
    - 末尾按 ``max_chars`` 简单切片截断。
    """
    wanted = None if fields is None else set(fields)
    names = [n for n in FIELDS if wanted is None or n in wanted]
    lines = [f"【NDR 统一事件】索引 {index}，来源 {' / '.join(SOURCES)}"]
    for name in names:
        item = FIELDS[name]
        lines.append(f"- {name}（{item['kind']}）：{item['desc']}")
    return "\n".join(lines)[:max_chars]
