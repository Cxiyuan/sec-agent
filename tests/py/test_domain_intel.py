"""域名归属情报（domain_intel）：DNS 隧道类告警的客观坐标。

钉住三类最容易误判的合法长随机子域：
- 腾讯 CDN/遥测（smtcdns.com / tfogc.com）
- 华为云 CDN（cdnhwc8.com）
- Amazon 设备遥测（a2z.com）
以及 ip6.arpa / in-addr.arpa PTR 反查。
"""

from __future__ import annotations

from app.analysis import domain_intel


def test_tencent_cdn_and_telemetry_are_known() -> None:
    cdn = domain_intel.lookup_domain(
        "aafd8cefac83e7667d4b1020157fd6db.v.smtcdns.com"
    )
    assert cdn["known"] is True
    assert cdn["provider"] == "腾讯"
    assert cdn["registrable_domain"] == "smtcdns.com"
    assert cdn["benign_for_long_random_subdomain"] is True

    telemetry = domain_intel.lookup_domain("32849170ffb36267323742377076e244.rdt.tfogc.com")
    assert telemetry["known"] is True
    assert telemetry["provider"] == "腾讯"
    assert telemetry["registrable_domain"] == "tfogc.com"


def test_huawei_cdn_and_amazon_device_are_known() -> None:
    huawei = domain_intel.lookup_domain("b.hon.cc.cdnhwc8.com")
    assert huawei["known"] is True
    assert huawei["provider"] == "华为云"

    amazon = domain_intel.lookup_domain(
        "6e5351d7ad9e61e3eb9b7bb3b36ab3a0a41f44960fd9fe3157824a833d65bf7."
        "us-east-1.prod.service.minerva.devices.a2z.com"
    )
    assert amazon["known"] is True
    assert amazon["provider"] == "Amazon"
    assert amazon["registrable_domain"] == "a2z.com"


def test_ptr_reverse_dns_is_not_a_tunnel() -> None:
    out = domain_intel.lookup_domain(
        "a.b.c.d.e.f.a.b.c.d.e.f.a.b.c.d.e.f.a.b.c.d.e.f."
        "a.b.c.d.e.f.a.b.c.d.e.f.a.b.c.d.e.f.ip6.arpa"
    )
    assert out["category"] == "PTR 反查"
    assert out["benign_for_long_random_subdomain"] is True
    assert "PTR" in out["guidance"]

    v4 = domain_intel.lookup_domain("10.1.2.3.in-addr.arpa")
    assert v4["category"] == "PTR 反查"


def test_unknown_domain_stays_suspicious_guidance() -> None:
    out = domain_intel.lookup_domain("deadbeefdeadbeefdeadbeefdeadbeef.evil.example")
    assert out["known"] is False
    assert out["benign_for_long_random_subdomain"] is False
    assert "suspicious" in out["guidance"]


def test_input_normalization() -> None:
    assert domain_intel.normalize_domain("https://Foo.Example.COM./path?q=1") == "foo.example.com"
    assert domain_intel.registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert domain_intel.lookup_domain("")["error"]

