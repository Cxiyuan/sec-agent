"""Logstash 采集管道模板：由后台参数渲染，写入共享卷供 Logstash 热重载。

管道语义（与改造前一致）：
  beats(:5044) → 补 source_system → ES（历史，按 log_type 分索引）+ Redis List（旁路队列）
"""

from __future__ import annotations

from typing import Any

DEFAULT_ES_HOST = "http://elasticsearch:9200"
DEFAULT_ZEEK_INDEX = "zeek-%{[log_type]}-%{+yyyy.MM.dd}"
DEFAULT_WAZUH_INDEX = "wazuh-alerts-%{+yyyy.MM.dd}"
DEFAULT_REDIS_HOST = "redis"
DEFAULT_REDIS_PORT = 6379
DEFAULT_REDIS_DB = 0
DEFAULT_REDIS_KEY = "shentong:events:raw"

HEADER = """# 深瞳 · 采集侧双写管道（由 Web 后台维护，请勿手工编辑服务器文件）
#
#   Zeek(Filebeat)/Wazuh → Logstash(:{port}) ─┬→ Elasticsearch（历史与界面）
#                                            └→ Redis List（旁路队列，供检测器实时消费）
#
# 本文件由后台「系统配置 → Logstash 采集」生成/保存；保存后 Logstash 会自动重载（约 10s）。
# 模板与参数逻辑见 backend/app/collector/template.py。
"""


def default_params(es_host: str | None = None, redis_url: str | None = None) -> dict[str, Any]:
    """默认参数：ES/Redis 地址默认与后端一致（同 compose 网络）。"""
    host = es_host or DEFAULT_ES_HOST
    rhost, rport, rdb = DEFAULT_REDIS_HOST, DEFAULT_REDIS_PORT, DEFAULT_REDIS_DB
    if redis_url:
        parsed = _parse_redis_url(redis_url)
        if parsed:
            rhost, rport, rdb = parsed
    return {
        "es_enabled": True,
        "es_host": host,
        "zeek_index": DEFAULT_ZEEK_INDEX,
        "wazuh_index": DEFAULT_WAZUH_INDEX,
        "redis_enabled": True,
        "redis_host": rhost,
        "redis_port": rport,
        "redis_db": rdb,
        "redis_key": DEFAULT_REDIS_KEY,
    }


def render(params: dict[str, Any], beats_port: int = 5044) -> str:
    """按参数渲染完整管道文本。"""
    p = {**default_params(), **params}
    parts: list[str] = [HEADER.format(port=beats_port)]
    parts.append(
        f"""input {{
  beats {{
    port => {beats_port}
  }}
}}

filter {{
  # 统一来源标记：Zeek 的 Filebeat 已带 source_system=zeek
  if ![source_system] or [source_system] == "" {{
    mutate {{ add_field => {{ "source_system" => "wazuh" }} }}
  }}
}}

output {{"""
    )
    if p.get("es_enabled", True):
        es_host = str(p.get("es_host") or DEFAULT_ES_HOST)
        zeek_index = str(p.get("zeek_index") or DEFAULT_ZEEK_INDEX)
        wazuh_index = str(p.get("wazuh_index") or DEFAULT_WAZUH_INDEX)
        parts.append(
            f"""  # 1) Elasticsearch：历史归档 + 界面/回溯查询
  if [log_type] {{
    elasticsearch {{
      hosts => ["{es_host}"]
      index => "{zeek_index}"
      manage_template => false
      ilm_enabled => false
    }}
  }} else {{
    elasticsearch {{
      hosts => ["{es_host}"]
      index => "{wazuh_index}"
      manage_template => false
      ilm_enabled => false
    }}
  }}"""
        )
    else:
        parts.append("  # 1) Elasticsearch 输出：已停用（仅保留旁路队列）")

    if p.get("redis_enabled", True):
        parts.append(
            f"""  # 2) Redis 旁路队列：检测器实时消费（List；检测器用 BRPOPLPUSH 可靠取出）
  redis {{
    host => "{p.get("redis_host") or DEFAULT_REDIS_HOST}"
    port => {int(p.get("redis_port") or DEFAULT_REDIS_PORT)}
    db => {int(p.get("redis_db") or 0)}
    data_type => "list"
    key => "{p.get("redis_key") or DEFAULT_REDIS_KEY}"
  }}"""
        )
    else:
        parts.append("  # 2) Redis 旁路队列：已停用（只存历史、不做实时检测）")

    parts.append("}")
    return "\n".join(parts) + "\n"


def validate_pipeline(text: str, max_chars: int) -> list[str]:
    """静态校验（保存前）。返回问题列表，空列表表示通过。

    说明：后端没有 logstash 二进制，无法做真配置测试；因此只做静态检查，
    并配「保存前备份 + 一键回滚」兜底（详见路由实现）。
    """
    problems: list[str] = []
    body = text.strip()
    if not body:
        return ["管道内容不能为空"]
    if len(text) > max_chars:
        problems.append(f"内容过长：{len(text)} 字符（上限 {max_chars}）")
    if "input" not in body or "{" not in body:
        problems.append("缺少 input 段")
    if "output" not in body:
        problems.append("缺少 output 段")
    if not _braces_balanced(body):
        problems.append("花括号不配平（注意字符串/注释内的括号已忽略）")
    if not problems:
        problems.extend(_check_outputs(body))
    return problems


def _check_outputs(body: str) -> list[str]:
    """至少保留一个输出，否则管道无意义（Logstash 也会报错）。"""
    has_es = "elasticsearch" in body
    has_redis = "redis" in body
    if not has_es and not has_redis:
        return ["必须至少启用一个输出（Elasticsearch 或 Redis 旁路）"]
    return []


def _braces_balanced(text: str) -> bool:
    """引号与注释感知的花括号配平检查。"""
    depth = 0
    quote = ""
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "#":
            nxt = text.find("\n", i)
            i = len(text) if nxt < 0 else nxt
            continue
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return False
        i += 1
    return depth == 0 and not quote


def _parse_redis_url(url: str) -> tuple[str, int, int] | None:
    """从 redis://host:port/db 解析出 (host, port, db)。"""
    raw = (url or "").strip()
    if "://" not in raw:
        return None
    rest = raw.split("://", 1)[1]
    netloc, _, path = rest.partition("/")
    host, _, port_s = netloc.partition(":")
    if not host:
        return None
    try:
        port = int(port_s) if port_s else DEFAULT_REDIS_PORT
    except ValueError:
        port = DEFAULT_REDIS_PORT
    try:
        db = int(path) if path else DEFAULT_REDIS_DB
    except ValueError:
        db = DEFAULT_REDIS_DB
    return host, port, db
