"""XFF（真实客户端 IP）与响应体的归一化回归测试。

来源：实机探针 —— 服务器 192.0.2.77 向 192.0.2.80:8081 发 ``POST /__xffprobe``，
带 ``X-Forwarded-For: 198.51.100.77, 203.0.113.9``，Zeek 把代理头记进 ``HTTP::Info$proxied``。
这条数据以前只活在 raw 里，现在进 ``real_client_ip`` 参与画像/规则/检索；2026-10 起这只在
**直连对端本身是可信代理**时成立（``ST_ZEEK_TRUSTED_PROXIES``，见
``test_untrusted_peer_drops_proxy_headers``），否则头里的地址一律不认。

两侧都跑（``--stack=ndr`` / ``--stack=agent``）。
"""

from __future__ import annotations

import pytest
from app import schemas
from app.config import settings
from app.ingestion import normalizer
from app.rules import engine

# 实机探针原文（服务器 192.0.2.77 发向 192.0.2.80:8081 的那条）
PROBE = {
    "ts": 1790912698.490834,
    "uid": "Cy2rDP36QlAdi9ru79",
    "id.orig_h": "192.0.2.77",
    "id.orig_p": 37358,
    "id.resp_h": "192.0.2.80",
    "id.resp_p": 8081,
    "trans_depth": 1,
    "method": "POST",
    "host": "192.0.2.80:8081",
    "uri": "/__xffprobe",
    "version": "1.1",
    "user_agent": "curl/8.5.0",
    "request_body_len": 15,
    "response_body_len": 80,
    "status_code": 401,
    "status_msg": "Unauthorized",
    "tags": [],
    "proxied": ["X-FORWARDED-FOR -> 198.51.100.77, 203.0.113.9"],
    "resp_body": '{"detail":"unauthorized"}',
}

#: 探针的直连对端 —— 真实部署里这个地址就是反向代理自己
TRUSTED_PEER = "192.0.2.77"


@pytest.fixture(autouse=True)
def _trusted_probe_peer(set_relays) -> None:
    """本文件测的是「直连对端是中继（可信代理）」时的解析口径（不可信的情形单独测）。"""
    set_relays("192.0.2.0/24")


PROXY_CASES: list[tuple[str, dict, str | None]] = [
    ("proxied 逗号列表取最左", {"proxied": ["X-FORWARDED-FOR -> 198.51.100.77, 203.0.113.9"]}, "198.51.100.77"),
    ("RFC7239 for=", {"proxied": ["FORWARDED -> for=10.1.2.3;proto=https"]}, "10.1.2.3"),
    ("RFC7239 IPv6 带端口", {"proxied": ['FORWARDED -> for="[2001:db8::1]:4711";proto=https']}, "2001:db8::1"),
    ("CLIENT-IP", {"proxied": ["CLIENT-IP -> 10.0.0.9"]}, "10.0.0.9"),
    ("IPv4 带端口", {"proxied": ["X-FORWARDED-FOR -> 10.0.0.5:8080"]}, "10.0.0.5"),
    ("VIA 不是客户端地址", {"proxied": ["VIA -> 1.1 nginx"]}, None),
    ("非法值", {"proxied": ["X-FORWARDED-FOR -> not-an-ip"]}, None),
    ("单值", {"proxied": ["X-FORWARDED-FOR -> 198.51.100.77"]}, "198.51.100.77"),
    ("裸头字段", {"x-forwarded-for": "203.0.113.7"}, "203.0.113.7"),
    ("裸头字段取最左", {"x-forwarded-for": "203.0.113.7, 10.0.0.1"}, "203.0.113.7"),
    ("X-Real-IP 进 proxy_headers（站点脚本补的）", {"proxied": ["X-REAL-IP -> 198.51.100.77"]}, "198.51.100.77"),
    ("裸 X-Real-IP 单值头", {"x-real-ip": "203.0.113.9"}, "203.0.113.9"),
    ("裸 X-Real-IP 带端口", {"x-real-ip": "203.0.113.9:443"}, "203.0.113.9"),
    ("空集合", {"proxied": []}, None),
    ("没有代理头", {}, None),
]


@pytest.mark.parametrize(("tag", "doc", "want"), PROXY_CASES, ids=[c[0] for c in PROXY_CASES])
def test_real_client_ip(tag: str, doc: dict, want: str | None) -> None:
    assert normalizer._real_client_ip(doc, TRUSTED_PEER) == want


def test_untrusted_peer_drops_proxy_headers(set_relays) -> None:
    """对端不在中继清单里 ⇒ 代理头一律不认（fail-closed，防伪造）。"""
    assert normalizer._real_client_ip({"proxied": PROBE["proxied"]}, TRUSTED_PEER) == "198.51.100.77"
    for peer in ("10.9.9.9", "172.16.197.1", None, "", "not-an-ip"):
        assert normalizer._real_client_ip({"proxied": PROBE["proxied"]}, peer) is None
    # 清单为空 = 谁都不信（连正确的对端也不信）——PG 里没配就是「网络里没有中继」
    set_relays("")
    assert normalizer._real_client_ip({"proxied": PROBE["proxied"]}, TRUSTED_PEER) is None


def test_trusted_proxies_accepts_host_cidr_and_list(set_relays) -> None:
    doc = {"proxied": PROBE["proxied"]}
    for cfg, peer, want in (
        ("192.0.2.77", "192.0.2.77", "198.51.100.77"),  # 单个代理写自己的 IP
        ("192.0.2.77/32", "192.0.2.77", "198.51.100.77"),
        ("192.0.2.0/24", "192.0.2.77", "198.51.100.77"),  # 代理是一个网段
        ("10.0.0.0/8, 192.0.2.77", "192.0.2.77", "198.51.100.77"),  # 多项/逗号分隔
        ("# 注释行\n192.0.2.77", "192.0.2.77", "198.51.100.77"),
        ("192.0.2.0/24", "172.16.197.77", None),
        ("not-a-cidr", "192.0.2.77", None),  # 非法项被忽略 ⇒ 等于没配
    ):
        set_relays(cfg)
        assert normalizer._real_client_ip(doc, peer) == want, (cfg, peer)


def test_probe_end_to_end() -> None:
    log = normalizer.normalize_zeek(dict(PROBE))
    assert log is not None
    assert log.log_type == "http"
    assert log.real_client_ip == "198.51.100.77"
    assert log.src_ip == "192.0.2.77"  # TCP 对端不被覆盖
    assert log.resp_body == '{"detail":"unauthorized"}'
    assert log.resp_body_len == 80
    assert log.bytes_in == 80
    assert log.event_type == "http_error"


def test_plain_traffic_has_no_real_client_ip() -> None:
    plain = {k: v for k, v in PROBE.items() if k not in ("proxied", "resp_body")}
    log = normalizer.normalize_zeek(plain)
    assert log is not None
    assert log.real_client_ip is None  # 无代理头 → NULL（归一化对空字段统一用 NULL）
    assert log.resp_body == ""
    assert log.resp_body_len == 80  # 字节数仍来自 Zeek 的 response_body_len


def test_resp_body_truncation() -> None:
    # 批 3 起响应体上限是 64KB（后台可调），按 settings 造一个必然超限的输入
    limit = settings.http_resp_body_max_chars
    log = normalizer.normalize_zeek(dict(PROBE, resp_body="x" * (limit + 100)))
    assert log is not None
    assert len(log.resp_body) == limit


def test_rule_matches_real_client_ip() -> None:
    log = normalizer.normalize_zeek(dict(PROBE))
    assert log is not None
    rule = {
        "id": "unit-xff",
        "name": "unit xff",
        "log_type": "http",
        "severity": "low",
        "conditions": {"rules": [{"field": "real_client_ip", "op": "eq", "value": "198.51.100.77"}]},
    }
    assert engine.match_rule(rule, log) is True
    other = {
        **rule,
        "conditions": {"rules": [{"field": "real_client_ip", "op": "eq", "value": "10.9.9.9"}]},
    }
    assert engine.match_rule(other, log) is False
    # 无代理头（NULL）时不该命中
    plain = {k: v for k, v in PROBE.items() if k != "proxied"}
    plain_log = normalizer.normalize_zeek(plain)
    assert plain_log is not None
    assert engine.match_rule(rule, plain_log) is False
    # 规则要能被挂到 http 上，否则永远不会被评估
    index = engine.build_rule_index([rule])
    assert rule in engine.rules_for_log_type(index, "http")


def test_profile_uses_real_client_ip(stack: str) -> None:
    """画像统计真实客户端（画像只在 NDR 侧）。"""
    if stack != "ndr":
        pytest.skip("画像已迁到 NDR，智能体侧无此模块")
    from app.baseline import profile

    entry = schemas.UnifiedLog(
        source_system="zeek",
        ts=PROBE["ts"],
        log_type="http",
        event_type="http_request",
        src_ip="192.0.2.77",
        real_client_ip="198.51.100.77",
        user="alice",
    )
    buckets: dict = {}
    profile.observe_entry(buckets, entry)
    src_ips = buckets[f"{profile.ACCOUNT}|alice"]["src_ips"]
    assert "198.51.100.77" in src_ips
    assert "192.0.2.77" not in src_ips

    buckets2: dict = {}
    entry2 = schemas.UnifiedLog(
        source_system="zeek",
        ts=PROBE["ts"],
        log_type="http",
        event_type="http_request",
        src_ip="192.0.2.77",
        real_client_ip=None,
        user="bob",
    )
    profile.observe_entry(buckets2, entry2)
    assert "192.0.2.77" in buckets2[f"{profile.ACCOUNT}|bob"]["src_ips"]  # 无代理头回落 src_ip
