"""Filebeat 把日志行切碎时的归一化口径（2026-10-03 实机取证的回归测试）。

背景：Zeek 日志轮转 / 容器重建的窗口里，Filebeat 的 ``ndjson`` 解析器会把某一**行从中间
切开**，产出「一个业务字段都没有」的事件（字段名逐字来自实机探针）::

    {"zeek": {"error": {"type": "json", "message": "Error decoding JSON: invalid character 'h' ..."}},
     "message": "h{\\"ts\\":1791050001.0,\\"uid\\":\\"PROBEBAD\\"}", ...}

解析成功的事件**没有**顶层 ``message``，业务字段全在 ``zeek`` 下。旧行为把它归一化成只有
``@timestamp`` + ``log_type`` 的空壳文档写进事件索引（2026-10-03 的 ``shentong-events-*``
里实测 3 条，污染检索且丢掉原文）。现在的口径：先用 ``message`` 里原样保留的那一行抢救，
抢救不到返回 ``None`` —— 上层按归一化失败计数并投 ``shentong:events:dead`` 死信，
**绝不落空壳文档**。

两侧都跑（``--stack=ndr`` / ``--stack=agent``）。
"""

from __future__ import annotations

import json

from app.ingestion import normalizer

#: 实机探针里 Zeek conn.log 的那一行（截取关键字段）
CONN_LINE = {
    "ts": 1791050000.0,
    "uid": "PROBEGOOD",
    "id.orig_h": "198.51.100.9",
    "id.orig_p": 44444,
    "id.resp_h": "203.0.113.9",
    "id.resp_p": 80,
    "proto": "tcp",
    "duration": 0.1,
    "orig_bytes": 10,
    "resp_bytes": 20,
    "conn_state": "SF",
}

#: Filebeat 对 "h{...}" 这种半行给出的报错（逐字来自实机）
JSON_ERROR = {
    "type": "json",
    "message": "Error decoding JSON: invalid character 'h' looking for beginning of value",
}


def shell(message: str, log_type: str = "conn") -> dict:
    """Filebeat 解析失败事件的形态（字段名逐字来自实机探针）。"""
    return {
        "@timestamp": "2026-10-03T00:00:13.006Z",
        "@metadata": {"beat": "filebeat", "version": "8.15.3"},
        "source_system": "zeek",
        "log_type": log_type,
        "log": {"file": {"path": f"/logs/{log_type}.log"}, "offset": 123456},
        "message": message,
        "zeek": {"error": dict(JSON_ERROR)},
    }


def test_half_line_is_not_indexed_as_shell_document() -> None:
    """轮转窗口里的半行：不能变成只有时间戳 + log_type 的空壳文档。"""
    doc = shell('h{"ts":1791050001.0,"uid":"PROBEBAD"}')
    assert normalizer.normalize_zeek(dict(doc)) is None
    assert normalizer.normalize("zeek", dict(doc)) is None


def test_bare_number_line_is_dropped() -> None:
    """实机里混进 ssl.log 的裸数字行（Filebeat 报 unmarshal number）。"""
    doc = shell("17", log_type="ssl")
    doc["zeek"]["error"]["message"] = (
        "json: cannot unmarshal number into Go value of type map[string]interface {}"
    )
    assert normalizer.normalize("zeek", dict(doc)) is None


def test_valid_line_kept_in_message_is_recovered() -> None:
    """Filebeat 解析失败但原文仍是完整 JSON 对象时，用它入库，不丢事件。"""
    doc = shell(json.dumps(CONN_LINE))
    entry = normalizer.normalize("zeek", dict(doc))
    assert entry is not None
    assert entry.raw["uid"] == "PROBEGOOD"
    assert entry.src_ip == "198.51.100.9"
    assert entry.log_type == "conn"
    assert "error" not in entry.raw  # 抢救回来的事件不带 Filebeat 的 error 壳


def test_parse_error_without_original_line_is_dropped() -> None:
    doc = shell("")
    doc.pop("message")
    assert normalizer.normalize("zeek", dict(doc)) is None


def test_top_level_error_key_is_also_detected() -> None:
    """别的采集管道把 error 挂在根上（不是 ``zeek.*``）时同样拦住。"""
    doc = {
        "@timestamp": "2026-10-03T00:00:13.006Z",
        "log_type": "ssl",
        "error": dict(JSON_ERROR),
        "message": "17",
    }
    assert normalizer.normalize("zeek", doc) is None


def test_healthy_document_is_untouched() -> None:
    """正常事件（解析成功：没有 error、没有顶层 message）照旧。"""
    doc = {
        "@timestamp": "2026-10-03T00:00:13.006Z",
        "source_system": "zeek",
        "log_type": "conn",
        "zeek": dict(CONN_LINE),
    }
    entry = normalizer.normalize("zeek", doc)
    assert entry is not None
    assert entry.raw["uid"] == "PROBEGOOD"
    assert entry.src_ip == "198.51.100.9"
