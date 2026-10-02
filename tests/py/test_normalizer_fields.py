"""归一化字段契约：类型判定、raw 自解释字段、XFF 与响应体。

样本见 ``samples.py``（字段名取自实机 ``/logs/*.log``）。这些断言是
NDR ↔ 智能体两侧契约的"真源"：两侧的 normalizer 只差 ``source_of()``，
其余必须逐字一致（由 ``test_stack_consistency.py`` 用子进程实测）。
"""

from __future__ import annotations

import pytest
import samples
from app.config import settings
from app.ingestion import log_types
from app.ingestion.normalizer import normalize_zeek


@pytest.mark.parametrize("name", sorted(samples.DOCS))
def test_log_type_and_known_flag(name: str) -> None:
    want_type, want_known, want_cls = samples.EXPECT[name]
    entry = normalize_zeek(samples.DOCS[name])
    assert entry is not None
    assert entry.log_type == want_type
    assert entry.log_type_known is want_known
    assert log_types.classify_entry(entry) == want_cls
    assert log_types.is_detectable(entry) is (want_cls == "event")


@pytest.mark.parametrize("name", sorted(samples.DOCS))
def test_raw_is_self_describing(name: str) -> None:
    """raw 里必须带类型与来源文件名 —— MCP 的 raw_evidence 靠它自解释。"""
    doc = samples.DOCS[name]
    entry = normalize_zeek(doc)
    assert entry is not None
    assert entry.raw["log_type"] == entry.log_type
    path = ((doc.get("log") or {}).get("file") or {}).get("path", "")
    if path:
        assert entry.source_file == path.rsplit("/", 1)[-1]
        assert entry.raw["source_file"] == entry.source_file


def test_raw_keeps_inner_document() -> None:
    """raw 是解包后的内层原文（不是 Filebeat 的信封）。"""
    entry = normalize_zeek(samples.DOCS["conn"])
    assert entry is not None
    assert entry.raw["id.orig_h"] == samples.CONN["id.orig_h"]
    assert entry.raw["conn_state"] == "SF"
    assert "zeek" not in entry.raw


def test_raw_masks_credential_keys() -> None:
    """raw 里按 key 名遮蔽凭证（内层文档自己带 password 字段的情况）。"""
    doc = samples.envelope({**samples.HTTP, "password": "s3cret"}, "http", "/logs/http.log")
    entry = normalize_zeek(doc)
    assert entry is not None
    assert entry.raw["password"] == "***"


def test_flat_document_is_guessed() -> None:
    """没有 log_type 的旧文档/人工重放：靠特征字段猜，不兜底成 conn。"""
    entry = normalize_zeek(samples.DOCS["flat_x509"])
    assert entry is not None
    assert entry.log_type == "x509"
    assert entry.log_type_known is True
    assert entry.source_file == ""


def test_http_xff_and_resp_body() -> None:
    entry = normalize_zeek(samples.DOCS["http"])
    assert entry is not None
    # 代理头最左地址进 real_client_ip；src_ip 仍是 TCP 对端
    assert entry.real_client_ip == "198.51.100.77"
    assert entry.src_ip == "172.16.196.77"
    assert entry.resp_body == '{"detail":"unauthorized"}'
    assert entry.resp_body_len == 80
    assert entry.bytes_in == 80
    # 既定口径（用户已确认接受风险）：body 明文保留
    assert "Zq7ProbePwd9" in entry.body


def test_http_without_xff_is_null() -> None:
    doc = samples.envelope({k: v for k, v in samples.HTTP.items() if k != "proxied"}, "http", "/logs/http.log")
    entry = normalize_zeek(doc)
    assert entry is not None
    assert entry.real_client_ip is None


def test_resp_body_truncated() -> None:
    doc = samples.envelope({**samples.HTTP, "resp_body": "x" * 5000}, "http", "/logs/http.log")
    entry = normalize_zeek(doc)
    assert entry is not None
    assert len(entry.resp_body) == settings.http_resp_body_max_chars
    # 字节数是 Zeek 记的完整长度，不受截断影响
    assert entry.resp_body_len == 80


def test_unknown_type_keeps_name() -> None:
    """名单外的流保留原名 + known=False：能聚合巡检，不是静默丢。"""
    entry = normalize_zeek(samples.DOCS["unknown_stream"])
    assert entry is not None
    assert entry.log_type == "ja3sfp"
    assert entry.log_type_known is False
    assert entry.raw["source_file"] == "ja3sfp.log"
