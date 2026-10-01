"""Logstash 采集管道模板：由后台参数渲染，写入共享卷供 Logstash 热重载。

管道语义（归一化前置之后）：
  归一化服务 --HTTP POST(JSON)--> Logstash http(:8080) → ES 统一索引 shentong-events-<日期>

注意：**原始日志不再经过 Logstash**。Zeek/Wazuh 的 Filebeat 直接把原始文档写进
Redis List（`shentong:events:collect`），由归一化服务取出、拍平后再 POST 到这里。
所以本管道没有「按 log_type 分索引」的分流，只有一族索引。
"""

from __future__ import annotations

from typing import Any

DEFAULT_ES_HOST = "http://elasticsearch:9200"
DEFAULT_EVENTS_INDEX = "shentong-events-%{+yyyy.MM.dd}"
DEFAULT_HTTP_PORT = 8080

HEADER = """# 深瞳 · 采集侧入库管道（由 Web 后台维护，请勿手工编辑服务器文件）
#
#   归一化服务 --POST(JSON)--> Logstash http(:{port}) → Elasticsearch 统一索引
#
# Zeek 与 Wazuh 落同一族索引：原始文档在进 ES 之前已被拍平成统一结构（src_ip/dst_ip/...）。
# 因此这里既没有 filter 分流，也没有第二个输出。
#
# 本文件由后台「系统配置 → Logstash 采集」生成/保存；保存后 Logstash 会自动重载（约 10s）。
# 模板与参数逻辑见 ndr/backend/app/collector/template.py。
"""


def default_params(es_host: str | None = None) -> dict[str, Any]:
    """默认参数：ES 地址默认与后端一致（同 compose 网络）。"""
    return {
        "es_enabled": True,
        "es_host": es_host or DEFAULT_ES_HOST,
        "events_index": DEFAULT_EVENTS_INDEX,
    }


def render(params: dict[str, Any], http_port: int = DEFAULT_HTTP_PORT) -> str:
    """按参数渲染完整管道文本。"""
    p = {**default_params(), **params}
    parts: list[str] = [HEADER.format(port=http_port)]
    parts.append(
        f"""input {{
  # 归一化服务批量 POST（NDJSON，一行一条）。http 输入默认「一个请求 = 一个事件」，
  # 所以必须用 json_lines 编解码器才能把一批拆成多条事件。
  http {{
    port => {http_port}
    codec => "json_lines"
    additional_codecs => {{ "application/json" => "json_lines" }}
    # 请求头/对端地址默认会写成 host、headers 两个字段并入库，挪进 @metadata 丢掉
    remote_host_target_field => "[@metadata][http][remote_host]"
    request_headers_target_field => "[@metadata][http][headers]"
  }}
}}

filter {{
  # 归一化服务已把字段拍平，这里只把**事件时间**搬到 @timestamp。
  # 不搬的话索引会按入库日期滚动，跨天补投/重放的数据会进错索引。
  if [ts] {{
    date {{
      match => ["ts", "ISO8601"]
      target => "@timestamp"
      timezone => "UTC"
    }}
  }}
}}

output {{"""
    )
    if p.get("es_enabled", True):
        es_host = str(p.get("es_host") or DEFAULT_ES_HOST)
        index = str(p.get("events_index") or DEFAULT_EVENTS_INDEX)
        parts.append(
            f"""  # 无条件入库（红线：不做任何 drop / 条件跳过）
  elasticsearch {{
    hosts => ["{es_host}"]
    index => "{index}"
    manage_template => false
    ilm_enabled => false
  }}"""
        )
    else:
        parts.append("  # Elasticsearch 输出：已停用（此时管道不产生任何输出）")

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
    """必须保留 ES 输出，否则归一化后的日志无处可落（Logstash 也会报错）。"""
    if "elasticsearch" not in body:
        return ["必须启用 Elasticsearch 输出（归一化后的日志只有这一个去处）"]
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
