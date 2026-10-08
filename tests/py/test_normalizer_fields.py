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
from app.ingestion.normalizer import normalize, normalize_wazuh, normalize_zeek
from app.ingestion.session_cookie import session_id_from_cookie
from app.schemas import UnifiedLog


def _entry(doc: dict) -> UnifiedLog | None:
    """按来源分发归一化（Zeek / 签名引擎各自的分支；口径见 samples.doc_source）。"""
    return normalize(samples.doc_source(doc), doc)


@pytest.fixture(autouse=True)
def _trusted_probe_peer(set_relays) -> None:
    """``samples.HTTP`` 的 TCP 对端是探针机 —— 真实部署里这个地址就是反向代理。

    2026-10 起代理头只在**直连对端在中继清单里**时才算 ``real_client_ip``，
    而清单现在**只读 PG**（不再有 `ST_ZEEK_TRUSTED_PROXIES`）；本文件其余样本不带
    ``proxied``，不受影响。
    """
    set_relays("192.0.2.0/24")


@pytest.mark.parametrize("name", sorted(samples.DOCS))
def test_log_type_and_known_flag(name: str) -> None:
    want_type, want_known, want_cls = samples.EXPECT[name]
    entry = _entry(samples.DOCS[name])
    assert entry is not None
    assert entry.log_type == want_type
    assert entry.log_type_known is want_known
    assert log_types.classify_entry(entry) == want_cls
    assert log_types.is_detectable(entry) is (want_cls == "event")


@pytest.mark.parametrize("name", sorted(samples.DOCS))
def test_raw_is_self_describing(name: str) -> None:
    """raw 里必须带类型与来源文件名 —— MCP 的 raw_evidence 靠它自解释。"""
    doc = samples.DOCS[name]
    entry = _entry(doc)
    assert entry is not None
    assert entry.raw["log_type"] == entry.log_type
    path = ((doc.get("log") or {}).get("file") or {}).get("path", "")
    if path:
        assert entry.source_file == path.rsplit("/", 1)[-1]
        assert entry.raw["source_file"] == entry.source_file


def test_ssl_established_mapped() -> None:
    """TLS 握手是否建立要落成字段：规则靠它判「TLS 握手失败风暴」。"""
    entry = normalize_zeek(samples.DOCS["ssl"])
    assert entry is not None and entry.tls_established is True
    failed = normalize_zeek({**samples.SSL, "established": False})
    assert failed is not None and failed.tls_established is False


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
    assert entry.src_ip == "192.0.2.77"
    assert entry.resp_body == '{"detail":"unauthorized"}'
    assert entry.resp_body_len == 80
    assert entry.bytes_in == 80
    # 既定口径（用户已确认接受风险）：body 明文保留
    assert "Zq7ProbePwd9" in entry.body


def test_http_without_xff_is_null() -> None:
    doc = samples.envelope(
        {k: v for k, v in samples.HTTP.items() if k != "proxied"}, "http", "/logs/http.log"
    )
    entry = normalize_zeek(doc)
    assert entry is not None
    assert entry.real_client_ip is None


def test_resp_body_truncated() -> None:
    doc = samples.envelope(
        {**samples.HTTP, "resp_body": "x" * (settings.http_resp_body_max_chars + 100)},
        "http",
        "/logs/http.log",
    )
    entry = normalize_zeek(doc)
    assert entry is not None
    assert len(entry.resp_body) == settings.http_resp_body_max_chars
    # 字节数是 Zeek 记的完整长度，不受截断影响
    assert entry.resp_body_len == 80


def test_http_headers_captured() -> None:
    """批 3：请求/响应头全量文本逐字搬运（Zeek 侧已截断，后端再按 8192 字符兜底）。"""
    entry = normalize_zeek(samples.DOCS["http"])
    assert entry is not None
    assert "AUTHORIZATION: Basic cHJvYmU6WnE3UHJvYmVQd2Q5" in entry.req_headers
    assert entry.req_headers.endswith("X-LONG: " + "A" * 256 + "\n")
    assert entry.resp_headers.startswith("CONTENT-TYPE: application/json\n")
    # 非 HTTP 流不串味
    ssl_entry = normalize_zeek(samples.DOCS["ssl"])
    assert ssl_entry is not None
    assert ssl_entry.req_headers == ""
    assert ssl_entry.resp_headers == ""


def test_http_limits_follow_settings() -> None:
    """两侧共用的运行时上限函数：无 system_config 行时回落到 settings 默认值。"""
    from app.ingestion.normalizer import http_body_limit, http_resp_body_limit

    assert http_body_limit() == settings.http_body_max_chars == 16384
    assert http_resp_body_limit() == settings.http_resp_body_max_chars == 65536


def test_tls_fingerprints() -> None:
    """SSL 流：ja3/ja3s 逐字搬运，ja4 是本批新增的 BSD 指纹（JA4+ 其余未收录）。"""
    entry = normalize_zeek(samples.DOCS["ssl"])
    assert entry is not None
    assert entry.ja3 == samples.SSL["ja3"]
    assert entry.ja3s == samples.SSL["ja3s"]
    assert entry.ja4 == "t13d301200_1d37bd780c83_ecd0401ec68b"
    assert entry.tls_version == "TLSv12"
    # 非 SSL 流不串味
    http_entry = normalize_zeek(samples.DOCS["http"])
    assert http_entry is not None
    assert http_entry.ja4 == ""


def test_files_metadata() -> None:
    """files 流：哈希/方向/来源协议进统一字段（批 2 前只有 raw 里翻得到）。"""
    entry = normalize_zeek(samples.DOCS["files"])
    assert entry is not None
    assert entry.fuid == "Fabc123"
    assert entry.md5 == samples.FILES["md5"]
    assert entry.sha1 == samples.FILES["sha1"]
    assert entry.sha256 == samples.FILES["sha256"]
    assert entry.file_source == "HTTP"
    assert entry.file_is_orig is False
    assert entry.filename == "report.pdf"


def test_file_is_orig_accepts_zeek_bool_strings() -> None:
    """旧扁平文档里布尔可能是 "T"/"F" 字符串，别当成 True 一律收下。"""
    for raw, want in (("T", True), ("F", False), (True, True), (False, False)):
        doc = samples.envelope({**samples.FILES, "is_orig": raw}, "files", "/logs/files.log")
        entry = normalize_zeek(doc)
        assert entry is not None
        assert entry.file_is_orig is want


def test_unknown_type_keeps_name() -> None:
    """名单外的流保留原名 + known=False：能聚合巡检，不是静默丢。"""
    entry = normalize_zeek(samples.DOCS["unknown_stream"])
    assert entry is not None
    assert entry.log_type == "ja3sfp"
    assert entry.log_type_known is False
    assert entry.raw["source_file"] == "ja3sfp.log"


def test_flat_ja4_streams_are_split() -> None:
    """平铺（没有 log_type）的 JA4+ 文档：ja4ssh 靠 kex 认、ja4d 靠 hash 认。

    顺序敏感：ja4d 若排在前面会用通用的 hash 把 JA4SSH 抢走，所以这里把两种流都钉住。
    """
    ssh_entry = normalize_zeek(dict(samples.JA4SSH))
    assert ssh_entry is not None
    assert ssh_entry.log_type == "ja4ssh"

    d_entry = normalize_zeek(dict(samples.JA4D))
    assert d_entry is not None
    assert d_entry.log_type == "ja4d"


@pytest.mark.parametrize(
    ("conn_state", "want"),
    [
        ("S0", "scan_attempt"),
        ("S1", "conn_established"),
        ("S2", "conn_established"),
        ("S3", "conn_established"),
        ("SF", "conn_established"),
        ("REJ", "rejected_connection"),
        ("SH", "connection_shutdown"),
    ],
)
def test_conn_state_event_type(conn_state: str, want: str) -> None:
    """conn_state → event_type：只有 S0（SYN 无回应）算扫描。

    S1/S2/S3 是握手已建立，与 triage_policy.SUCCESS_CONN_STATES 口径一致；改造前它们
    被判成 scan_attempt，导致带 ``event_type ne scan_attempt`` 的内置规则永不命中。
    """
    doc = samples.envelope({**samples.CONN, "conn_state": conn_state}, "conn", "/logs/conn.log")
    entry = normalize_zeek(doc)
    assert entry is not None
    assert entry.event_type == want


def test_dns_qtype_keeps_zeek_numeric_code() -> None:
    """qtype 存 Zeek 原始数字码（1=A、28=AAAA、16=TXT）。

    对外口径统一按数字码：C 组规则只用 "16"、D 组 catalog 与 G 组前端都按数字码，
    所以这里钉住「不许悄悄改成人类可读名」。
    """
    entry = normalize_zeek(samples.DOCS["dns"])
    assert entry is not None
    assert entry.qtype == "1"


def test_wazuh_raw_is_self_describing() -> None:
    """Wazuh 侧 raw 与 Zeek 同口径：带 log_type/source_file。

    告警（alerts.json）与归档（archives.json）共用同一张表，raw 自解释尤其重要。
    """
    doc = {
        "@timestamp": "2026-10-02T08:39:33.000Z",
        "rule": {"level": 10, "description": "sshd brute force"},
        "data": {"srcip": "203.0.113.9", "dstip": "192.0.2.77"},
        "log": {"file": {"path": "/var/ossec/logs/alerts/alerts.json"}},
    }
    entry = normalize_wazuh(doc)
    assert entry is not None
    assert entry.log_type == "wazuh"
    assert entry.raw["log_type"] == "wazuh"
    assert entry.raw["source_file"] == "alerts.json"


def test_wazuh_compliance_title_is_not_port_scan() -> None:
    """合规/基线告警标题里的 "scanning" 不能当成端口扫描（2026-10 实机数据发现）。

    库里 8 条 `event_type=port_scan` 全是 Wazuh 的 CIS 基准合规项 —— 原实现用
    `"scan" in description` 词匹配，把 "Ensure 'Turn on e-mail scanning' is set to Enabled"、
    "Scan removable drives"、"script scanning" 这类标题误标成端口扫描。
    """
    compliance = (
        "CIS Benchmark: Ensure 'Turn on e-mail scanning' is set to Enabled",
        "CIS Benchmark: Ensure 'Scan removable drives' is set to Enabled",
        "Ensure 'Turn on script scanning' is set to Enabled",
        "Ensure 'Scan all downloaded files and attachments' is set to Enabled",
    )
    for title in compliance:
        doc = {
            "@timestamp": "2026-10-02T08:39:33.000Z",
            "rule": {"level": 5, "description": title},
            "data": {"srcip": "203.0.113.9", "dstip": "192.0.2.77"},
            "log": {"file": {"path": "/var/ossec/logs/alerts/alerts.json"}},
        }
        entry = normalize_wazuh(doc)
        assert entry is not None
        assert entry.event_type != "port_scan", title
    # 真正的扫描描述仍要认（否则又把真告警改哑了）
    doc = {
        "@timestamp": "2026-10-02T08:39:33.000Z",
        "rule": {"level": 10, "description": "Port scan detected from 203.0.113.9"},
        "data": {"srcip": "203.0.113.9", "dstip": "192.0.2.77"},
        "log": {"file": {"path": "/var/ossec/logs/alerts/alerts.json"}},
    }
    entry = normalize_wazuh(doc)
    assert entry is not None and entry.event_type == "port_scan"


@pytest.mark.parametrize(
    ("cookie", "want"),
    [
        ("JSESSIONID=abc; lang=zh-CN", "abc"),
        ("lang=zh-CN; jsessionid=ABC123", "ABC123"),  # 名字大小写不敏感
        ('ASP.NET_SessionId="quoted value"', "quoted value"),  # 带引号去引号
        # 实测误报源（2026-10）：应用自己造的常量 cookie / 空值模板 / 不在名单里的名字
        ("Path=/; Path=/", ""),
        ("EPORTAL_COOKIE_PASSWORD=; EPORTAL_COOKIE_USERNAME=x", ""),
        ("XSESSION=abc", ""),  # 名字必须**精确**匹配，不能子串
        ("", ""),
    ],
)
def test_session_id_from_cookie(cookie: str, want: str) -> None:
    """会话 id 只能按名单**精确**取名且值非空 —— 否则常量 cookie 会让「会话跨IP复用」误报。"""
    assert session_id_from_cookie(cookie, settings.session_cookie_names) == want


def test_session_id_extracted_before_cookie_truncation() -> None:
    """会话 id 从**未截断**的 Cookie 头里取：长 Cookie 头不能把会话 cookie 截掉（否则漏报）。"""
    filler = "; ".join(f"k{i}=v" for i in range(settings.http_cookie_max_chars // 4))
    doc = {
        "@timestamp": "2026-10-02T05:00:00.000Z",
        "log_type": "http",
        "source_system": "zeek",
        "id.orig_h": "203.0.113.9",
        "id.resp_h": "192.0.2.77",
        "id.resp_p": 80,
        "method": "GET",
        "uri": "/x",
        "req_headers": f"COOKIE: {filler}; JSESSIONID=sess123\n",
    }
    entry = normalize_zeek(doc)
    assert entry is not None
    assert len(entry.cookie) <= settings.http_cookie_max_chars  # 字段本身照旧截断
    assert entry.session_id == "sess123"  # 但会话 id 从原始头里取到了


def test_wazuh_syscollector_archive_keeps_process_as_text() -> None:
    """syscollector/FIM 原始日志的 ``data.process`` 是对象，不能因为类型不符丢掉整条记录。

    2026-10-03 实机开 archives（全量原始日志）后：正常入库 148 条，另有 **373 条进死信**
    （``reason=normalize_failed``），pydantic 原话是
    ``process: Input should be a valid string [input_value={'name': 'svchost.exe', ...}]``。
    原始日志只入库供回溯，丢一个字段可以、丢整条记录不行，所以对象要收敛成可读字符串。
    """
    doc = {
        "@timestamp": "2026-10-03T10:24:40.639Z",
        "id": "1791022749.12345",
        "decoder": {"name": "syscollector"},
        "location": "syscheck",
        "agent": {"id": "003", "name": "WIN-MSRG5PALH14", "ip": "172.16.199.63"},
        "data": {
            "checksum": "c3adc15179a17226edad8129036fc5d8ffe81dec",
            "cmd": "C:\\Windows\\System32\\svchost.exe",
            "name": "svchost.exe",
            "pid": "676",
            "process": {"name": "svchost.exe", "pid": "676", "ppid": "596"},
            "user": {"name": "SYSTEM"},
        },
        "full_log": '{"data":{"checksum":"c3adc15179a17226edad8129036fc5d8ffe81dec","operation":"MODIFIED"}}',
    }
    entry = normalize_wazuh(doc)
    assert entry.log_type == "wazuh_archive"
    assert entry.event_type == "wazuh_log"
    assert entry.process == "svchost.exe"
    assert entry.user == "SYSTEM"
    assert entry.account == "SYSTEM"


def test_wazuh_object_fields_fall_back_to_compact_json() -> None:
    """对象里没有名字类字段时退化成紧凑 JSON，列表则按逗号拼接——都不许抛异常。"""
    doc = {
        "@timestamp": "2026-10-03T10:24:41.000Z",
        "decoder": {"name": "syscollector"},
        "data": {
            "process": {"pid": 1, "state": "R"},
            "user": ["alice", "bob"],
            "command": 42,
            "protocol": None,
        },
    }
    entry = normalize_wazuh(doc)
    assert entry.process == '{"pid": 1, "state": "R"}'
    assert entry.user == "alice, bob"
    assert entry.command == "42"
    assert entry.protocol is None
