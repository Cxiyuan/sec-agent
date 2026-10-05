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


def test_roles_count_evidence_by_log_type(roles_mod: ModuleType, set_relays) -> None:
    set_relays("192.0.2.0/24")
    det = roles_mod.RelayRoleDetector()
    det.observe(_entry(log_type="http", src_ip="192.0.2.77"))
    det.observe(_entry(log_type="ssl", dst_ip="192.0.2.77"))
    det.observe(_entry(log_type="dns", dst_ip="192.0.2.77"))
    det.observe(_entry(log_type="conn", src_ip="192.0.2.77"))  # 覆盖所有流量、判不出角色
    det.observe(_entry(log_type="http", src_ip="172.16.1.1"))  # 不在清单里
    snap = det.snapshot()
    assert snap["192.0.2.77"] == {"proxy": 2, "dns": 1, "roles": ["proxy", "dns"]}
    assert "172.16.1.1" not in snap


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
    det.observe(_entry(log_type="http", src_ip="192.0.2.77"))
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
