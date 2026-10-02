"""Zeek 归一化样本集（字段名取自实机 ``/logs/*.log`` 的真实结构）。

``envelope()`` 造的是 Filebeat 实际发出的形态：``zeek`` 子对象（ndjson ``target: zeek``）
＋根上的 ``log_type`` / ``source_system`` / ``log.file.path``。
``flat()`` 造的是**没有信封**的形态：升级前压在队列里的旧文档、人工重放数据 ——
这类文档没有 ``log_type``，归一化只能靠特征字段猜（这条路径必须一直测到）。
"""

from __future__ import annotations

from typing import Any

TS = 1790912698.490834

# 各流的真实字段（值做了无害化，字段名保持原样）
CONN = {
    "ts": TS,
    "uid": "C1a2b3c4d5e6f7g8h9",
    "id.orig_h": "172.16.196.77",
    "id.orig_p": 37358,
    "id.resp_h": "172.16.196.80",
    "id.resp_p": 443,
    "proto": "tcp",
    "service": "ssl",
    "duration": 0.512,
    "orig_bytes": 1024,
    "resp_bytes": 4096,
    "conn_state": "SF",
    "history": "ShADadfF",
    "orig_pkts": 12,
    "resp_pkts": 10,
}

DNS = {
    "ts": TS,
    "uid": "Cdns0001",
    "id.orig_h": "172.16.196.77",
    "id.orig_p": 51000,
    "id.resp_h": "172.16.196.1",
    "id.resp_p": 53,
    "proto": "udp",
    "trans_id": 4242,
    "rtt": 0.002,
    "query": "example.internal",
    "qclass": 1,
    "qclass_name": "C_INTERNET",
    "qtype": 1,
    "qtype_name": "A",
    "rcode": 0,
    "rcode_name": "NOERROR",
    "answers": ["10.0.0.10"],
}

HTTP = {
    "ts": TS,
    "uid": "Chttp0001",
    "id.orig_h": "172.16.196.77",
    "id.orig_p": 37358,
    "id.resp_h": "172.16.196.80",
    "id.resp_p": 8081,
    "trans_depth": 1,
    "method": "POST",
    "host": "172.16.196.80:8081",
    "uri": "/__xffprobe?q=1",
    "version": "1.1",
    "user_agent": "curl/8.5.0",
    "request_body_len": 15,
    "response_body_len": 80,
    "status_code": 401,
    "status_msg": "Unauthorized",
    "tags": [],
    "proxied": ["X-FORWARDED-FOR -> 198.51.100.77, 203.0.113.9"],
    "body": '{"user":"probe","password":"Zq7ProbePwd9"}',
    "resp_body": '{"detail":"unauthorized"}',
}

SSL = {
    "ts": TS,
    "uid": "Cssl0001",
    "id.orig_h": "172.16.196.77",
    "id.orig_p": 37360,
    "id.resp_h": "172.16.196.80",
    "id.resp_p": 443,
    "version": "TLSv12",
    "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "server_name": "example.internal",
    "ja3": "10894b8a9d67451b0cf4b49f237ba189",
    "ja3s": "a0e9f5d64349fb13191bc781f81f42e1",
    "resumed": False,
}

FILES = {
    "ts": TS,
    "fuid": "Fabc123",
    "uid": "Chttp0001",
    "id.orig_h": "172.16.196.77",
    "id.resp_h": "172.16.196.80",
    "source": "HTTP",
    "depth": 0,
    "analyzers": ["MD5", "SHA1", "SHA256"],
    "mime_type": "application/octet-stream",
    "filename": "report.pdf",
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "seen_bytes": 20480,
    "total_bytes": 20480,
}

DHCP = {
    "ts": TS,
    "uids": ["Cdhcp0001"],
    "client_addr": "0.0.0.0",
    "server_addr": "172.16.196.1",
    "mac": "00:11:22:33:44:55",
    "assigned_addr": "172.16.196.90",
    "lease_time": 3600.0,
    "msg_types": ["REQUEST", "ACK"],
    "host_name": "workstation-01",
}

X509 = {
    "ts": TS,
    "id": "Fabc123",
    "certificate": {
        "subject": "CN=example.internal",
        "issuer": "CN=Internal CA",
        "serial": "0A1B2C3D",
        "not_valid_before": 1767225600.0,
        "not_valid_after": 1798761600.0,
        "key_type": "rsa",
        "key_length": 2048,
        "sig_alg": "sha256WithRSAEncryption",
    },
    "basic_constraints": {"ca": False},
    "san": {"dns": ["example.internal"]},
    "fingerprint": "abcdef0123456789",
}

WEIRD = {
    "ts": TS,
    "uid": "Cweird001",
    "id.orig_h": "172.16.196.77",
    "id.resp_h": "172.16.196.80",
    "name": "line_terminated_with_single_CR",
    "notice": False,
    "peer": "originator",
    "source": "HTTP",
    "addl": "data ends with CR",
}

NTP = {
    "ts": TS,
    "uid": "Cntp0001",
    "id.orig_h": "172.16.196.77",
    "id.resp_h": "172.16.196.1",
    "version": 4,
    "mode": 3,
    "stratum": 2,
    "poll": 6,
    "precision": -23,
    "root_delay": 0.001,
    "root_disp": 0.002,
    "ref_id": "10.0.0.1",
    "num_exts": 0,
}

PACKET_FILTER = {
    "ts": TS,
    "node": "ndr-sensor",
    "filter": "net 172.16.196.0/24",
    "init": True,
    "success": True,
}

REPORTER = {
    "ts": TS,
    "level": "Reporter::WARNING",
    "message": "I'm a warning",
    "location": "",
    "connection": "",
}

STATS = {
    "ts": TS,
    "peer": "zeek",
    "pkts_proc": 100000,
    "pkts_dropped": 3,
    "pkts_link": 100003,
    "pkts_filtered": 12,
    "bytes_recv": 12345678,
    "events_proc": 4321,
    "events_queued": 0,
    "pkt_lag": 0.001,
    "active_tcp_conns": 42,
    "files": 7,
    "dns_requests": 9,
}

SMTP = {
    "ts": TS,
    "uid": "Csmtp0001",
    "id.orig_h": "172.16.196.77",
    "id.resp_h": "172.16.196.80",
    "helo": "workstation-01",
    "mailfrom": "a@example.internal",
    "rcptto": ["b@example.internal"],
    "subject": "hello",
    "date": "Thu, 2 Oct 2026 05:00:00 +0000",
    "server": "smtp.example.internal",
}

SSH = {
    "ts": TS,
    "uid": "Cssh0001",
    "id.orig_h": "172.16.196.77",
    "id.resp_h": "172.16.196.80",
    "auth_success": False,
    "auth_attempts": 3,
    "direction": "INBOUND",
    "client": "SSH-2.0-OpenSSH_9.6",
    "server": "SSH-2.0-OpenSSH_9.3",
}

# JA4+ 包的流：字段名按上游脚本推断，批 2 用真实样本校正（这里只保证类型判定）
JA4SSH = {
    "ts": TS,
    "uid": "Cja4sh001",
    "id.orig_h": "172.16.196.77",
    "id.resp_h": "172.16.196.80",
    "direction": "C",
    "hash": "c1a2b3c4d5e6_c1a2b3c4d5e6",
    "kex": "curve25519-sha256",
}

JA4D = {
    "ts": TS,
    "uid": "Cja4d001",
    "id.orig_h": "172.16.196.77",
    "id.resp_h": "172.16.196.80",
    "hash": "q13d0312h3_55b375c5d22d_9c4f8cad6b31",
}

# 名单外的"新流"（上 JA4+ 包会带出的流；本次不是全量启用，用来测 unknown 路径）
UNKNOWN_STREAM = {
    "ts": TS,
    "uid": "Cja3fp001",
    "id.orig_h": "172.16.196.77",
    "id.resp_h": "172.16.196.80",
    "ja3": "10894b8a9d67451b0cf4b49f237ba189",
    "ja3s": "a0e9f5d64349fb13191bc781f81f42e1",
    "dummy_field_only_this_stream_has": 1,
}


def envelope(
    fields: dict[str, Any],
    log_type: str,
    path: str,
    source_system: str = "zeek",
) -> dict[str, Any]:
    """Filebeat 发出的形态（``zeek`` 子对象 + 根上的类型/来源/文件路径）。"""
    return {
        "@timestamp": "2026-10-02T05:00:00.000Z",
        "log_type": log_type,
        "source_system": source_system,
        "log": {"file": {"path": path}},
        "zeek": dict(fields),
        "host": {"name": "ndr-sensor"},
        "agent": {"type": "filebeat", "version": "8.15.3"},
    }


# 名字 → 待归一化的原始文档
DOCS: dict[str, dict[str, Any]] = {
    "conn": envelope(CONN, "conn", "/logs/conn.log"),
    "conn_rotated": envelope(CONN, "conn", "/logs/conn.2026-10-01.log"),
    "dns": envelope(DNS, "dns", "/logs/dns.log"),
    "http": envelope(HTTP, "http", "/logs/http.log"),
    "ssl": envelope(SSL, "ssl", "/logs/ssl.log"),
    "files": envelope(FILES, "files", "/logs/files.log"),
    "dhcp": envelope(DHCP, "dhcp", "/logs/dhcp.log"),
    "x509": envelope(X509, "x509", "/logs/x509.log"),
    "weird": envelope(WEIRD, "weird", "/logs/weird.log"),
    "ntp": envelope(NTP, "ntp", "/logs/ntp.log"),
    "packet_filter": envelope(PACKET_FILTER, "packet_filter", "/logs/packet_filter.log"),
    "reporter": envelope(REPORTER, "reporter", "/logs/reporter.log"),
    "stats": envelope(STATS, "stats", "/logs/stats.log"),
    "smtp": envelope(SMTP, "smtp", "/logs/smtp.log"),
    "ssh": envelope(SSH, "ssh", "/logs/ssh.log"),
    "ja4ssh": envelope(JA4SSH, "ja4ssh", "/logs/ja4ssh.log"),
    "ja4d": envelope(JA4D, "ja4d", "/logs/ja4d.log"),
    "unknown_stream": envelope(UNKNOWN_STREAM, "ja3sfp", "/logs/ja3sfp.log"),
    # 没有 log_type 的旧文档：只能靠特征字段猜
    "flat_http": dict(HTTP),
    "flat_x509": dict(X509),
    "flat_files": dict(FILES),
    "flat_conn": dict(CONN),
    # 子目录布局（历史部署）也要能取到文件名
    "conn_in_subdir": envelope(CONN, "conn", "/logs/2026-10-01/conn.log"),
}

# 期望的 (log_type, 是否在名单内, 分类)
EXPECT: dict[str, tuple[str, bool, str]] = {
    "conn": ("conn", True, "event"),
    "conn_rotated": ("conn", True, "event"),
    "dns": ("dns", True, "event"),
    "http": ("http", True, "event"),
    "ssl": ("ssl", True, "event"),
    "files": ("files", True, "event"),
    "dhcp": ("dhcp", True, "event"),
    "x509": ("x509", True, "event"),
    "weird": ("weird", True, "event"),
    "ntp": ("ntp", True, "ops"),
    "packet_filter": ("packet_filter", True, "ops"),
    "reporter": ("reporter", True, "ops"),
    "stats": ("stats", True, "ops"),
    "smtp": ("smtp", True, "event"),
    "ssh": ("ssh", True, "event"),
    "ja4ssh": ("ja4ssh", True, "ops"),
    "ja4d": ("ja4d", True, "ops"),
    "unknown_stream": ("ja3sfp", False, "unknown"),
    "flat_http": ("http", True, "event"),
    "flat_x509": ("x509", True, "event"),
    "flat_files": ("files", True, "event"),
    "flat_conn": ("conn", True, "event"),
    "conn_in_subdir": ("conn", True, "event"),
}

# 只跟 zeek 线有关：一致性比较用（Wazuh 走另一套 normalize_wazuh）
ZEEK_NAMES = tuple(DOCS)
