"""中继链路三件套：清单（relay_nodes）、角色推算（relay_roles）、去重（relay_pairing）。

只跑 NDR 栈。它们共同实现用户 2026-10 的口径：

1. **清单只读 PG、没有就是不认任何中继**（无 env、无兜底）；
2. **角色由系统按实际流量自动推定**（http/ssl → 反代/WAF；dns → 内网 DNS 转发器）并回写 PG；
3. **一次业务访问只让一侧进检测**：保留前跳（客户端侧，证据最全），丢掉后跳
   （否则同一请求算两次，而且后跳的 src 是内网中继，告警会被归因到代理/DNS 头上）；
   若从未见过该中继的前跳（抓包点只在源站侧），后跳照常处理 —— 宁可多算也不丢数据。
"""

from __future__ import annotations

import importlib
from types import ModuleType, SimpleNamespace
from typing import Any, Self

import pytest


@pytest.fixture(scope="module")
def relay(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("中继链路只在 NDR 侧")
    return importlib.import_module("app.ingestion.relay_nodes")


@pytest.fixture(scope="module")
def roles_mod(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("中继角色推算只在 NDR 侧")
    return importlib.import_module("app.detector.relay_roles")


@pytest.fixture(scope="module")
def dedup_mod(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("中继去重只在 NDR 侧")
    return importlib.import_module("app.detector.relay_pairing")


class _Row:
    def __init__(self, key: str, value: dict[str, Any]) -> None:
        self.key = key
        self.value = value


class _Session:
    """够 relay_nodes 读写用的小号 Session（库里只有一行配置）。"""

    def __init__(self, rows: dict[str, _Row] | None = None) -> None:
        self.rows = rows if rows is not None else {}
        self.commits = 0

    def get(self, _model: Any, key: str) -> _Row | None:
        return self.rows.get(key)

    def add(self, row: _Row) -> None:
        self.rows[row.key] = row

    def commit(self) -> None:
        self.commits += 1

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool:
        return False


def _entry(**kw: Any) -> SimpleNamespace:
    """够待测函数用的事件（只带它们读的字段）。"""
    base: dict[str, Any] = {
        "log_type": "http",
        "src_ip": None,
        "dst_ip": None,
        "hop": "direct",
        "real_client_ip": None,
        # 代理头原始文档（链续跳判据读它；默认空 = 没有代理头）
        "raw": {},
    }
    base.update(kw)
    return SimpleNamespace(**base)


# ---------- 清单：解析 / 校验 / 读写 ----------


def test_parse_accepts_ip_cidr_comment_and_commas(relay: ModuleType) -> None:
    nets = relay.parse("192.0.2.77\n# 注释\n10.0.0.0/8, 2001:db8::/32\n\n坏的项")
    assert [str(n) for n in nets] == ["192.0.2.77/32", "10.0.0.0/8", "2001:db8::/32"]


def test_validate_reports_bad_items(relay: ModuleType) -> None:
    assert relay.validate("") == []
    assert relay.validate("192.0.2.77, # 注释") == []
    errors = relay.validate("192.0.2.77\nnot-a-cidr")
    assert errors and errors[0]["field"] == "relay_nodes" and "not-a-cidr" in errors[0]["msg"]


def test_is_relay_follows_list(relay: ModuleType, set_relays) -> None:
    set_relays("192.0.2.0/24")
    assert relay.is_relay("192.0.2.77") is True
    assert relay.is_relay("172.16.1.1") is False
    assert relay.is_relay(None) is False
    assert relay.is_relay("not-an-ip") is False
    # 清单为空 = 认定网络里没有中继（fail-closed）
    set_relays("")
    assert relay.is_relay("192.0.2.77") is False


def test_load_reads_pg_only_and_caches(relay: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """只读 PG：库存什么就是什么；invalidate() 之后能看到新值（30 秒 TTL 的失效点）。"""
    session = _Session({relay.KEY: _Row(relay.KEY, {"value": "192.0.2.9"})})
    monkeypatch.setattr(relay, "SessionLocal", lambda: session)
    relay.invalidate()
    assert relay.is_relay("192.0.2.9") is True
    assert relay.configured() is True
    # 库里改了但没 invalidate：仍按缓存（30 秒 TTL 内不重读）
    session.rows[relay.KEY].value = {"value": "10.9.9.9"}
    assert relay.is_relay("192.0.2.9") is True
    relay.invalidate()
    assert relay.is_relay("192.0.2.9") is False
    assert relay.is_relay("10.9.9.9") is True


def test_load_without_row_means_no_relay(
    relay: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(relay, "SessionLocal", lambda: _Session())
    relay.invalidate()
    assert relay.configured() is False
    assert relay.networks() == ()
    assert relay.describe()["count"] == 0


def test_save_keeps_detected_roles(relay: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """改清单不能把检测器推算的角色抹掉，反之写角色也不能改清单文本。"""
    session = _Session(
        {relay.KEY: _Row(relay.KEY, {"value": "10.0.0.1", "roles": {"10.0.0.1": {"proxy": 3}}})}
    )
    monkeypatch.setattr(relay, "SessionLocal", lambda: session)
    relay.save(session, "10.0.0.1,10.0.0.2")  # type: ignore[arg-type]
    assert session.rows[relay.KEY].value["value"] == "10.0.0.1,10.0.0.2"
    assert session.rows[relay.KEY].value["roles"] == {"10.0.0.1": {"proxy": 3}}

    relay.save_roles(session, {"10.0.0.2": {"dns": 7}}, detected_at_value="2026-10-05T00:00:00Z")  # type: ignore[arg-type]
    assert session.rows[relay.KEY].value["value"] == "10.0.0.1,10.0.0.2"
    assert session.rows[relay.KEY].value["roles"] == {"10.0.0.2": {"dns": 7}}
    assert session.rows[relay.KEY].value["detected_at"] == "2026-10-05T00:00:00Z"


def test_describe_reports_roles_and_configured(
    relay: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = _Session(
        {
            relay.KEY: _Row(
                relay.KEY,
                {"value": "10.0.0.9", "roles": {"10.0.0.9": {"proxy": 5}}, "detected_at": "t"},
            )
        }
    )
    monkeypatch.setattr(relay, "SessionLocal", lambda: session)
    relay.invalidate()
    info = relay.describe()
    assert info["configured"] is True and info["count"] == 1
    assert info["roles"] == {"10.0.0.9": {"proxy": 5}}
    assert info["detected_at"] == "t"


# ---------- 角色推算 ----------


def _np(roles_mod: ModuleType, **kw: Any) -> Any:
    """造一条证据够量的角色事件（默认阈值 200，所以批量观察）。"""
    return kw


def test_roles_only_count_traffic_it_forwards(roles_mod: ModuleType, set_relays) -> None:
    """角色证据 = **它在替别人转发**，不是「它出现过这种日志」。

    实机踩到（2026-10）：.186 是纯 DNS 转发器，却因为自己用 apt 拉 Ubuntu 镜像（1,150 条
    http/ssl、全 hop=back、无代理头）被标成「反向代理 / DNS 转发」；.203 是 nginx WAF，
    因为自己查过 DNS（经 .211 转发 158 条）被标成「DNS 转发」。
    """
    set_relays("192.0.2.0/24")
    det = roles_mod.RelayRoleDetector()
    # ① 有人来访问它的服务（它作目的地）→ 算反代
    det.observe(_entry(log_type="ssl", dst_ip="192.0.2.77", hop="front"))
    # ② 中继↔中继直连跳 → 算（唯一能认下「客户端直连、首跳无代理头」那类中继的判据）
    det.observe(
        _entry(log_type="http", src_ip="192.0.2.77", dst_ip="192.0.2.88", hop="relay_internal")
    )
    # ③ 它替客户端去源站（带代理头）→ 算
    det.observe(
        _entry(
            log_type="http",
            src_ip="192.0.2.77",
            dst_ip="10.1.1.1",
            hop="back",
            real_client_ip="203.0.113.7",
        )
    )
    # ④ 它自己上网（hop=back、没有代理头）→ **不算**
    det.observe(_entry(log_type="http", src_ip="192.0.2.77", dst_ip="91.189.91.83", hop="back"))
    # ⑤ 它自己直连上网（hop=direct）→ **不算**
    det.observe(_entry(log_type="ssl", src_ip="192.0.2.77", dst_ip="1.2.3.4", hop="direct"))
    # ⑥ 有人来问它 DNS → 算 DNS 转发
    det.observe(_entry(log_type="dns", dst_ip="192.0.2.77", dst_port=53, hop="front"))
    # ⑦ 它自己发 DNS 查询（hop=direct → 不算；哪怕走中继跳也过不了占比门槛）
    det.observe(_entry(log_type="dns", src_ip="192.0.2.77", dst_ip="8.8.8.8", hop="direct"))
    # ⑧ conn 覆盖所有流量、判不出角色
    det.observe(_entry(log_type="conn", src_ip="192.0.2.77"))
    # ⑨ 不在清单里
    det.observe(
        _entry(log_type="http", src_ip="172.16.1.1", hop="back", real_client_ip="203.0.113.9")
    )
    snap = det.snapshot()["192.0.2.77"]
    assert (snap["proxy"], snap["dns"]) == (3, 1), "只算它替别人转发的流量"
    assert snap["roles"] == [], "证据太少（不足 200 条）→ 宁可不判，也不给一个错的角色"
    assert snap["role_reason"] == roles_mod.REASON_WEAK_EVIDENCE
    assert "172.16.1.1" not in det.snapshot()


def test_roles_need_share_and_volume(roles_mod: ModuleType, set_relays) -> None:
    """角色要「有量 + 占得住」：186 的 64 条反代噪音 vs 206 万 DNS 转发，不能同时成立。"""
    set_relays("192.0.2.0/24")
    det = roles_mod.RelayRoleDetector()
    for _ in range(300):
        det.observe(_entry(log_type="dns", dst_ip="192.0.2.77", dst_port=53, hop="front"))
    for _ in range(60):  # 确有反代证据（有人访问它的 443），但量太少
        det.observe(_entry(log_type="ssl", dst_ip="192.0.2.77", dst_port=443, hop="front"))
    snap = det.snapshot()["192.0.2.77"]
    assert snap["roles"] == ["dns"], "量小的那类不该跟着展示（60 < 200）"
    assert snap["hits_total"] == {"proxy": 60, "dns": 300}

    # 量够（250 > 200）但占比过低（250/3250 = 7.7% < 10%）→ 仍只认 DNS
    set_relays("192.0.2.0/24")
    det2 = roles_mod.RelayRoleDetector()
    for _ in range(3000):
        det2.observe(_entry(log_type="dns", dst_ip="192.0.2.99", dst_port=53, hop="front"))
    for _ in range(250):
        det2.observe(_entry(log_type="ssl", dst_ip="192.0.2.99", dst_port=443, hop="front"))
    det2._reset_if_list_changed()
    assert det2.snapshot()["192.0.2.99"]["roles"] == ["dns"]


def test_roles_drop_stale_totals_from_old_evidence_version(
    roles_mod: ModuleType, set_relays
) -> None:
    """口径换代（evidence_version）后，旧累计值不许参与判定 —— 否则错误角色永远纠正不过来。"""
    set_relays("192.0.2.0/24")
    det = roles_mod.RelayRoleDetector()
    det._counts["192.0.2.77"] = {"dns": 3000}
    det._pending_roles["192.0.2.77"] = {"dns": 3000}
    old = {
        "hits_total": {"proxy": 1500, "dns": 3000},  # 旧口径：自己上网也被算成反代
        "roles": ["proxy", "dns"],
        "evidence_version": 1,
        "side": "front",
    }
    merged = det._merge_one("192.0.2.77", det._counts["192.0.2.77"], old)
    assert merged["hits_total"] == {"proxy": 0, "dns": 3000}, "旧口径的反代累计值必须作废"
    assert merged["roles"] == ["dns"]
    assert merged["evidence_version"] == roles_mod.ROLE_EVIDENCE_VERSION

    # 同版本才继续累加（重启不掉历史）
    fresh = dict(old, evidence_version=roles_mod.ROLE_EVIDENCE_VERSION)
    merged2 = det._merge_one("192.0.2.77", det._counts["192.0.2.77"], fresh)
    assert merged2["hits_total"] == {"proxy": 1500, "dns": 6000}


def test_roles_reset_when_list_changes(
    roles_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """换清单 → 旧地址的残留证据清零（清单变了，同一地址的角色结论不再适用）。

    注意：`_reset_if_list_changed()` 比的是 `raw_text()`（清单原文），所以要打补丁的是它，
    而不是 `networks()`（那是判定用的解析结果）。
    """
    monkeypatch.setattr(roles_mod.relay_nodes, "raw_text", lambda: "192.0.2.0/24")
    monkeypatch.setattr(roles_mod.relay_nodes, "is_relay", lambda ip: str(ip) == "192.0.2.77")
    det = roles_mod.RelayRoleDetector()
    det.observe(_entry(log_type="dns", dst_ip="192.0.2.77", hop="front"))
    assert det.snapshot()
    monkeypatch.setattr(roles_mod.relay_nodes, "raw_text", lambda: "10.0.0.0/8")
    det._reset_if_list_changed()
    assert det.snapshot() == {}


def test_roles_flush_skips_when_not_configured(
    roles_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(roles_mod.relay_nodes, "configured", lambda: False)
    det = roles_mod.RelayRoleDetector()
    det._last_flush = -1e9  # 到点了，但没有清单 → 不写库
    assert det.maybe_flush() is False


# ---------- 去重（保留前跳、丢掉后跳） ----------


def test_dedup_passes_direct_and_drops_relay_internal(dedup_mod: ModuleType) -> None:
    dedup = dedup_mod.RelayDedup(visibility_seconds=60)
    assert dedup.decide(_entry(hop="direct")) == "pass"
    assert (
        dedup.decide(_entry(hop="relay_internal", src_ip="10.0.0.1", dst_ip="10.0.0.2")) == "drop"
    )
    assert dedup.counts["relay_internal_dropped"] == 1


def test_dedup_drops_back_only_when_front_visible(dedup_mod: ModuleType) -> None:
    dedup = dedup_mod.RelayDedup(visibility_seconds=60)
    back = _entry(hop="back", src_ip="192.0.2.77", dst_ip="172.16.196.112")
    # 从没见过该中继的前跳（抓包点只在源站侧）→ 后跳照常处理，不丢数据
    assert dedup.decide(back, now=0.0) == "pass"
    assert dedup.counts["relay_back_kept"] == 1
    # 见到前跳之后 → 同一中继的后跳判为重复
    front = _entry(hop="front", src_ip="202.120.8.186", dst_ip="192.0.2.77")
    assert dedup.decide(front, now=10.0) == "pass"
    assert dedup.counts["relay_front"] == 1
    assert dedup.decide(back, now=11.0) == "drop"
    assert dedup.counts["relay_back_dropped"] == 1


def test_dedup_visibility_expires(dedup_mod: ModuleType) -> None:
    dedup = dedup_mod.RelayDedup(visibility_seconds=30)
    dedup.decide(_entry(hop="front", src_ip="202.120.8.186", dst_ip="192.0.2.77"), now=0.0)
    back = _entry(hop="back", src_ip="192.0.2.77", dst_ip="172.16.196.112")
    # 超出可见期：不再认定为重复（拓扑变化的兜底）
    assert dedup.decide(back, now=100.0) == "pass"


def test_dedup_front_records_each_relay(dedup_mod: ModuleType) -> None:
    dedup = dedup_mod.RelayDedup(visibility_seconds=60)
    dedup.decide(_entry(hop="front", src_ip="a", dst_ip="10.0.0.53"), now=5.0)
    assert dedup.snapshot()["relay_front_visible"] == {"10.0.0.53": 5.0}


def test_dedup_minimum_visibility(dedup_mod: ModuleType) -> None:
    """窗口下限 30 秒：配了 0 或负数也不能关掉守卫（否则每次拓扑抖动都会漏丢）。"""
    assert dedup_mod.RelayDedup(visibility_seconds=0).visibility == 30
    assert dedup_mod.RelayDedup(visibility_seconds=-5).visibility == 30


# ---------- 两侧内容统计与侧向判定（2026-10 实机实测新增）----------


def test_auto_side_by_content(roles_mod: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """按「哪一侧有内容」判侧向：悬殊才翻，默认保留客户端侧（= 历史行为）。

    本条环境的实测值就是 9 : 28,557（WAF 客户端侧是 TLS 无 SNI，源站侧才是明文 HTTP）。
    """
    monkeypatch.setattr(roles_mod.settings, "relay_side_min", 50)
    monkeypatch.setattr(roles_mod.settings, "relay_side_ratio", 10)
    assert roles_mod.auto_side(9, 28557) == "back"
    assert roles_mod.auto_side(5000, 10) == "front"
    assert roles_mod.auto_side(10, 10) == "front"
    assert roles_mod.auto_side(0, 0) == "front"
    # 边界：49 条不翻；50 条且刚好 10 倍才翻；6 : 50 不够 10 倍也不翻
    assert roles_mod.auto_side(0, 49) == "front"
    assert roles_mod.auto_side(5, 50) == "back"
    assert roles_mod.auto_side(6, 50) == "front"


def test_roles_counts_content_per_side(roles_mod: ModuleType, set_relays: Any) -> None:
    """内容统计：目的地是中继 → 客户端侧；来源是中继 → 源站侧；**ssl 不算内容**。"""
    set_relays("192.0.2.77")
    det = roles_mod.RelayRoleDetector()
    det.observe(_entry(log_type="http", dst_ip="192.0.2.77"))
    det.observe(_entry(log_type="dns", dst_ip="192.0.2.77"))
    det.observe(_entry(log_type="http", src_ip="192.0.2.77"))
    det.observe(_entry(log_type="ssl", dst_ip="192.0.2.77", raw={}))
    snap = det.snapshot()["192.0.2.77"]
    assert snap["front_content"] == 2
    assert snap["back_content"] == 1
    assert snap["side"] == "front" and snap["side_source"] == "auto"


def test_side_of_uses_manual_override(
    roles_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """运维手动指定的侧向优先于自动判定。"""
    monkeypatch.setattr(roles_mod.relay_nodes, "side_override", lambda _ip: "back")
    det = roles_mod.RelayRoleDetector()
    assert det.side_of("192.0.2.77") == "back"


def test_roles_content_reset_when_list_changes(
    roles_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """换清单 → 内容统计也归零（跟角色证据同一套复位逻辑）。"""
    monkeypatch.setattr(roles_mod.relay_nodes, "raw_text", lambda: "192.0.2.0/24")
    monkeypatch.setattr(roles_mod.relay_nodes, "is_relay", lambda ip: str(ip) == "192.0.2.77")
    det = roles_mod.RelayRoleDetector()
    det.observe(_entry(log_type="http", dst_ip="192.0.2.77"))
    assert det.snapshot()["192.0.2.77"]["front_content"] == 1
    monkeypatch.setattr(roles_mod.relay_nodes, "raw_text", lambda: "10.0.0.0/8")
    det._reset_if_list_changed()
    assert det.snapshot() == {}


def test_dedup_side_back_keeps_content_side(dedup_mod: ModuleType, set_relays: Any) -> None:
    """侧向 = 源站侧（本环境 WAF 的实际形态）：丢客户端侧跳、保留源站侧跳。

    同时覆盖「relay_internal 不再无条件丢」：源站侧有内容时，中继之间带明文的那条也要留。
    """
    set_relays("192.0.2.77")
    dedup = dedup_mod.RelayDedup(visibility_seconds=60, side_of=lambda _ip: "back")
    front = _entry(hop="front", src_ip="202.120.8.186", dst_ip="192.0.2.77", log_type="ssl")
    assert dedup.decide(front) == "drop"
    assert dedup.counts["relay_front_dropped"] == 1
    back = _entry(hop="back", src_ip="192.0.2.77", dst_ip="172.16.196.112", log_type="http")
    assert dedup.decide(back) == "pass"
    assert dedup.counts["relay_back_kept"] == 1
    inner_tls = _entry(
        hop="relay_internal", src_ip="192.0.2.77", dst_ip="192.0.2.78", log_type="ssl"
    )
    inner_http = _entry(
        hop="relay_internal", src_ip="192.0.2.77", dst_ip="192.0.2.78", log_type="http"
    )
    assert dedup.decide(inner_tls) == "drop"
    assert dedup.decide(inner_http) == "pass"
    assert dedup.counts["relay_internal_kept"] == 1


def test_dedup_side_front_keeps_today_behaviour(dedup_mod: ModuleType, set_relays: Any) -> None:
    """侧向 = 客户端侧（默认/明文反代/DNS 转发器）：与历史行为一致。"""
    set_relays("10.0.0.53")
    dedup = dedup_mod.RelayDedup(visibility_seconds=60, side_of=lambda _ip: "front")
    front = _entry(hop="front", src_ip="192.0.2.9", dst_ip="10.0.0.53", log_type="dns")
    assert dedup.decide(front) == "pass"
    back = _entry(hop="back", src_ip="10.0.0.53", dst_ip="223.5.5.5", log_type="dns")
    assert dedup.decide(back) == "drop"  # 前跳可见 → 后跳去重
    assert dedup.counts["relay_back_dropped"] == 1


def test_dedup_side_judgement_failure_falls_back_to_front(
    dedup_mod: ModuleType, set_relays: Any
) -> None:
    """侧向判据出异常时不能打断检测主循环 —— 回退到「保留客户端侧」。"""
    set_relays("192.0.2.77")

    def boom(_ip: str) -> str:
        raise RuntimeError("side judge down")

    dedup = dedup_mod.RelayDedup(visibility_seconds=60, side_of=boom)
    front = _entry(hop="front", src_ip="202.120.8.186", dst_ip="192.0.2.77")
    assert dedup.decide(front) == "pass"


def test_chain_peer_ips_reads_sender_side_values(dedup_mod: ModuleType) -> None:
    """只认「发送方自己写的」位置：X-Real-IP 与 XFF **末尾**（XFF 最左是客户端可塞的位置）。"""
    entry = _entry(
        raw={
            "proxied": [
                "X-FORWARDED-FOR -> 1.1.1.1, 2.2.2.2, 3.3.3.3",
                "X-REAL-IP -> 9.9.9.9:8080",
            ]
        }
    )
    assert dedup_mod.chain_peer_ips(entry) == {"3.3.3.3", "9.9.9.9"}
    # 没有 Zeek 的 proxied 包装时退回裸头
    entry2 = _entry(raw={"x-forwarded-for": "1.1.1.1, 2.2.2.2", "x-real-ip": "3.3.3.3"})
    assert dedup_mod.chain_peer_ips(entry2) == {"2.2.2.2", "3.3.3.3"}


def test_dedup_drops_chain_continuation(dedup_mod: ModuleType, set_relays: Any) -> None:
    """链的下游续跳：src 不是中继、但代理头说上一跳是清单内中继 → 丢掉（同一次访问已记）。"""
    set_relays("172.16.199.203")
    dedup = dedup_mod.RelayDedup(visibility_seconds=60, side_of=lambda _ip: "back")
    chain = {
        "proxied": [
            "X-FORWARDED-FOR -> 101.133.144.79, 172.16.199.203",
            "X-REAL-IP -> 172.16.199.203",
        ]
    }
    cont = _entry(
        hop="direct",
        src_ip="172.16.196.112",
        dst_ip="172.16.196.111",
        log_type="http",
        raw=chain,
    )
    assert dedup.decide(cont) == "drop"
    assert dedup.counts["relay_chain_continuation_dropped"] == 1
    # 证据跳（src 就是中继）不在续跳判据范围内 —— 它的代理头里同样带着中继
    keep = _entry(
        hop="back", src_ip="172.16.199.203", dst_ip="172.16.196.112", log_type="http", raw=chain
    )
    assert dedup.decide(keep) == "pass"
    assert dedup.counts["relay_chain_continuation_dropped"] == 1
    # 链里没有中继 → 不是续跳
    plain = _entry(
        hop="direct",
        src_ip="172.16.196.112",
        dst_ip="172.16.196.111",
        log_type="http",
        raw={"proxied": ["X-REAL-IP -> 203.0.113.9"]},
    )
    assert dedup.decide(plain) == "pass"


def test_validate_sides_rejects_unknown_address_and_bad_value(
    relay: ModuleType, set_relays: Any
) -> None:
    set_relays("192.0.2.77")
    assert relay.validate_sides({"192.0.2.77": "back"}) == []
    errors = relay.validate_sides({"203.0.113.5": "back", "192.0.2.77": "sideways"})
    assert len(errors) == 2


def test_sides_round_trip_in_describe(relay: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """侧向设置随清单一起读回（界面据此回显下拉框）——只读快照即可。"""
    monkeypatch.setattr(
        relay,
        "_snapshot",
        lambda: {
            "text": "192.0.2.77",
            "nets": relay.parse("192.0.2.77"),
            "roles": {"192.0.2.77": {"roles": ["proxy"]}},
            "sides": {"192.0.2.77": "back"},
            "detected_at": "2026-10-05T00:00:00+00:00",
        },
    )
    out = relay.describe()
    assert out["sides"] == {"192.0.2.77": "back"}
    assert out["nodes"] == ["192.0.2.77"]
    assert relay.side_override("192.0.2.77") == "back"
    assert relay.side_override("198.51.100.1") == "auto"
