"""行为基线改造（2026-10）：外连目的地、账号地理、FTP 采集、事实模型。

这些是**口径**测试：代码跑通不代表口径对。每一条断言都对应一个明确的用户决定：
- 外连只看"目的地身份"（IP/域名/端口），入口流量不建基线；
- 地理只比**国家 + 省**，失败登录记录但不更新基准，局域网登录不参与；
- 白名单删除留墓碑（否则下一窗口又学回来）；
- 事实只给智能体，不带严重度；
- Suricata 必须真的读到界面配的网卡（日志走 stderr、看门狗是函数、渲染有哨兵）。
"""

from __future__ import annotations

import importlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _ndr(request: pytest.FixtureRequest, name: str) -> Any:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("只在 NDR 侧")
    return importlib.import_module(name)


def test_geo_compares_country_and_province_only(request: pytest.FixtureRequest) -> None:
    geoip = _ndr(request, "app.geoip")
    sichuan = {"country": "CN", "province": "四川", "city": "成都"}
    guangdong = {"country": "CN", "province": "广东", "city": "深圳"}
    chengdu2 = {"country": "CN", "province": "四川", "city": "绵阳"}
    assert not geoip.same_place(sichuan, guangdong), "跨省必须算地点变了"
    assert geoip.same_place(sichuan, chengdu2), "同省不同市不算（城市级会误报）"
    # 局域网登录不参与比较
    assert geoip.same_place(sichuan, {"lan": True})
    assert geoip.same_place({"lan": True}, guangdong)
    # 缺国家/省时按"相同"处理（宁可不报，也不凭空造事实）
    assert geoip.same_place({"country": "CN"}, {"country": "CN", "province": "广东"})


def test_egress_values_are_normalized(request: pytest.FixtureRequest) -> None:
    egress = _ndr(request, "app.baseline.egress")
    assert egress._normalize("domain", "Example.COM.") == "example.com"
    assert egress._normalize("domain", "1.2.3.4:443") == "", "IP:端口 不是域名"
    assert egress._normalize("port", "443") == "443"
    assert egress._normalize("port", "abc") == ""
    assert egress._normalize("dst_ip", " 1.2.3.4 ") == "1.2.3.4"


def test_sampler_collects_only_active_egress_and_404(request: pytest.FixtureRequest) -> None:
    sampler_mod = _ndr(request, "app.baseline.sampler")
    sampler = sampler_mod.WindowSampler(window_seconds=300)
    # 内网服务器 → 公网：算主动外连（dst/域名/端口）
    sampler.observe(SimpleNamespace(
        src_ip="10.1.2.3", dst_ip="104.16.0.1", dst_port=8443, hostname="c2.example",
        event_type="conn_established", status_code=None,
    ), now=1000.0)
    # 内网 HTTP 404：算路径探测的原料
    sampler.observe(SimpleNamespace(
        src_ip="10.1.2.3", dst_ip="10.1.2.4", dst_port=80, hostname="",
        event_type="http_request", status_code=404,
    ), now=1001.0)
    # 公网客户端 → 内网：不建基线（外网源直接跳过）
    sampler.observe(SimpleNamespace(
        src_ip="1.1.1.1", dst_ip="10.1.2.4", dst_port=80, hostname="",
        event_type="http_request", status_code=200,
    ), now=1002.0)
    samples = sampler.pop_ready(now=1400.0)
    by_ip = {row["src_ip"]: row for row in samples}
    # 公网来源也在样本里（只为了数 404），但标了 skip_baseline
    assert set(by_ip) == {"10.1.2.3", "1.1.1.1"}
    assert by_ip["1.1.1.1"]["skip_baseline"] is True
    assert by_ip["1.1.1.1"]["requests"] == 1 and by_ip["1.1.1.1"]["egress_dsts"] == []
    row = by_ip["10.1.2.3"]
    assert row["egress_dsts"] == ["104.16.0.1"]
    assert row["egress_domains"] == ["c2.example"]
    assert row["egress_ports"] == ["8443"]
    assert row["requests"] == 1 and row["errors_404"] == 1


def test_ftp_login_is_normalized(request: pytest.FixtureRequest) -> None:
    normalizer = _ndr(request, "app.ingestion.normalizer")
    base = {
        "ts": 1793173082.0,
        "uid": "C1",
        "id.orig_h": "104.16.0.1",
        "id.orig_p": 40000,
        "id.resp_h": "10.1.2.3",
        "id.resp_p": 21,
        "user": "alice",
        "command": "USER",
        "arg": "alice",
        "reply_code": 230,
        "reply_msg": "Login successful",
    }
    entry = normalizer.normalize_zeek(dict(base))
    assert entry is not None
    assert entry.log_type == "ftp"
    assert entry.event_type == "ftp_login"
    assert entry.user == "alice"
    assert entry.status_code == 200, "230 = 登录成功，映射成 200 让账号画像能算成功"

    failed = normalizer.normalize_zeek({**base, "command": "PASS", "reply_code": 530, "reply_msg": "Login incorrect"})
    assert failed is not None and failed.status_code == 401

    activity = normalizer.normalize_zeek({**base, "command": "RETR", "arg": "a.txt", "reply_code": 150})
    assert activity is not None and activity.event_type == "ftp_activity"


def test_observation_kinds_are_fact_only(request: pytest.FixtureRequest) -> None:
    obs = _ndr(request, "app.baseline.observations")
    assert set(obs.KIND_LABELS) == {
        "egress_new", "egress_rare", "geo_jump", "login_bruteforce", "path_probe", "conn_shift",
    }
    # 事实表本身没有 severity / verdict 这类结论字段（模型定义里就不该有）
    from app.db.models import Observation

    columns = set(Observation.__table__.columns.keys())
    assert "severity" not in columns and "verdict" not in columns
    assert "strength" in columns and "facts" in columns


def test_new_routes_are_registered(request: pytest.FixtureRequest) -> None:
    main = _ndr(request, "app.main")
    paths = set(main.app.openapi()["paths"])
    assert {
        "/api/baseline/observations",
        "/api/baseline/observations/stats",
        "/api/baseline/egress",
        "/api/baseline/egress-allow",
        "/api/baseline/egress-allow/{entry_id}",
        "/api/baseline/egress-allow/{entry_id}/restore",
    } <= paths


def test_noisy_rules_removed_from_seed(request: pytest.FixtureRequest) -> None:
    builtin = _ndr(request, "app.rules.builtin")
    assert "协议异常" in builtin.DELETED_RULES
    assert "会话跨IP复用" in builtin.DELETED_RULES
    # 规则命中不再默认派工（只作为事实/证据）
    params = _ndr(request, "app.analysis.params")
    kinds = params.candidate_kinds()
    assert "hit" not in kinds and "shift" not in kinds
    assert "observation" in kinds


def test_suricata_reads_ui_interface() -> None:
    """Suricata 的三个坑：日志写 stdout 污染 sed、看门狗用了函数外的 local、空配置静默跑。"""
    script = (ROOT / "ndr" / "suricata" / "entrypoint.sh").read_text(encoding="utf-8")
    assert 'log() { echo "[suricata-entry] $*" >&2; }' in script, "日志必须走 stderr，否则被 $(...) 捕获"
    assert "watchdog_loop() {" in script, "看门狗要写成函数（local 只能用在函数里）"
    assert "watchdog_loop &" in script
    assert 'grep -qE "%(IFACE|HOME_NET|HTTP_PORTS|RULE_DIR|RULE_FILES)%"' in script, "渲染后要有占位符哨兵"
    assert "配置文件不可用" in script, "空/半截配置不允许启动 Suricata"
    assert "--af-packet=\"$iface\"" in script
    assert 'conf_get interface' in script
