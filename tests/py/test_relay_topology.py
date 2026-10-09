"""中继上下级拓扑 + 角色/侧向的「合并式回写」+ 攻击链还原（用户 2026-10 口径）。

这一层的价值全在**可靠性**上：角色不能因为检测器重启就掉成「未判定」、拓扑不能用猜的。
所以测试盯死三件事：合并语义（不覆盖历史、不重复计数）、两类证据与门槛、以及链路还原里
「哪一段是直连观测、哪一段只是拓扑推导」的标注。
"""

from __future__ import annotations

import importlib
import time
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest


@pytest.fixture(scope="module")
def roles_mod(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("中继拓扑只在 NDR 侧")
    return importlib.import_module("app.detector.relay_roles")


@pytest.fixture(scope="module")
def relay(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("中继清单只在 NDR 侧")
    return importlib.import_module("app.ingestion.relay_nodes")


@pytest.fixture(scope="module")
def chain_mod(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("攻击链还原只在 NDR 侧")
    return importlib.import_module("app.api.routes.chain")


A = "10.1.2.11"
B = "10.1.2.10"
ORIGIN = "10.1.2.23"


def _net(ip: str) -> Any:
    import ipaddress

    return ipaddress.ip_network(ip)


@pytest.fixture
def stub_relays(monkeypatch: pytest.MonkeyPatch, relay: ModuleType) -> dict[str, Any]:
    """把清单/角色/拓扑都换成内存桩：本文件只测推算与还原逻辑，不碰 PG。"""
    state: dict[str, Any] = {"roles": {}, "topology": {}, "overrides": {}, "sides": {}}
    monkeypatch.setattr(relay, "networks", lambda: (_net(A), _net(B)))
    monkeypatch.setattr(relay, "is_relay", lambda ip: str(ip) in (A, B))
    monkeypatch.setattr(relay, "raw_text", lambda: f"{A}\n{B}\n")
    monkeypatch.setattr(relay, "configured", lambda: True)
    monkeypatch.setattr(relay, "roles", lambda: dict(state["roles"]))
    monkeypatch.setattr(relay, "topology", lambda: dict(state["topology"]))
    monkeypatch.setattr(relay, "role_override", lambda ip: state["overrides"].get(str(ip), "auto"))
    monkeypatch.setattr(relay, "side_override", lambda ip: state["sides"].get(str(ip), "auto"))
    monkeypatch.setattr(
        relay, "save_roles", lambda db, roles, detected_at_value: state.update(roles=roles)
    )
    monkeypatch.setattr(relay, "save_topology", lambda db, data: state.update(topology=data))
    return state


def _entry(**kw: Any) -> Any:
    base = {"log_type": "ssl", "src_ip": A, "dst_ip": B, "raw": {}, "ts": None, "hop": "direct"}
    base.update(kw)
    return SimpleNamespace(**base)


# ---------- 拓扑：层级 / 链 / 门槛 / stale / 环 ----------


def test_topology_levels_and_chains(roles_mod: ModuleType) -> None:
    now = time.time()
    iso = roles_mod.datetime.fromtimestamp(now, roles_mod.UTC).isoformat()
    data = roles_mod.derive_topology(
        {f"{A}|{B}": {"direct": 12, "header": 0, "last_seen": iso}},
        [A, B],
        min_evidence=5,
        stale_seconds=86400,
        now_ts=now,
        generated_at=iso,
    )
    assert data["levels"] == {A: 0, B: 1}
    assert data["chains"] == [[A, B]]
    assert data["edges"][0]["confirmed"] is True
    assert data["pruned"] == 0


def test_topology_below_threshold_not_confirmed(roles_mod: ModuleType) -> None:
    now = time.time()
    iso = roles_mod.datetime.fromtimestamp(now, roles_mod.UTC).isoformat()
    data = roles_mod.derive_topology(
        {f"{A}|{B}": {"direct": 2, "header": 1, "last_seen": iso}},
        [A, B],
        min_evidence=5,
        stale_seconds=86400,
        now_ts=now,
        generated_at=iso,
    )
    assert data["edges"][0]["confirmed"] is False
    assert data["levels"] == {}  # 未确认的边不参与链路推导
    assert data["chains"] == []


def test_topology_prunes_removed_and_marks_stale(roles_mod: ModuleType) -> None:
    now = time.time()
    old = roles_mod.datetime.fromtimestamp(now - 3 * 86400, roles_mod.UTC).isoformat()
    data = roles_mod.derive_topology(
        {
            f"{A}|{B}": {"direct": 9, "header": 0, "last_seen": old},
            f"{B}|10.0.0.9": {"direct": 9, "header": 0, "last_seen": old},
        },
        [A, B],
        min_evidence=5,
        stale_seconds=86400,
        now_ts=now,
        generated_at=old,
    )
    assert data["pruned"] == 1  # 10.0.0.9 不在清单里
    assert len(data["edges"]) == 1
    assert data["edges"][0]["stale"] is True  # 三天没再观测：只标 stale，不删


def test_topology_breaks_cycle(roles_mod: ModuleType) -> None:
    now = time.time()
    iso = roles_mod.datetime.fromtimestamp(now, roles_mod.UTC).isoformat()
    data = roles_mod.derive_topology(
        {
            f"{A}|{B}": {"direct": 9, "header": 0, "last_seen": iso},
            f"{B}|{A}": {"direct": 9, "header": 0, "last_seen": iso},
        },
        [A, B],
        min_evidence=5,
        stale_seconds=86400,
        now_ts=now,
        generated_at=iso,
    )
    assert data["cycle_broken"], "环必须被显式记录，不能静默"


# ---------- 角色/侧向：合并式回写 ----------


def test_merge_keeps_history_and_does_not_double_count(
    roles_mod: ModuleType, stub_relays: dict[str, Any]
) -> None:
    """库里已有历史累计：本轮只加增量，且角色不会因为这一轮没流量而丢。"""
    stub_relays["roles"] = {
        B: {
            "hits_total": {"proxy": 500, "dns": 0},
            "evidence_version": roles_mod.ROLE_EVIDENCE_VERSION,
            "roles": ["proxy"],
            "side": "back",
            "side_source": "auto",
            "front_total": 0,
            "back_total": 40,
            "last_seen": "2026-10-01T00:00:00+00:00",
        }
    }
    det = roles_mod.RelayRoleDetector()
    det._reset_if_list_changed()
    det.observe(_entry(log_type="ssl", src_ip="9.9.9.9", dst_ip=B))
    snap = det.snapshot()
    assert snap[B]["hits_total"]["proxy"] == 501  # 历史 500 + 本轮 1（有人来访问它的 443）
    assert snap[B]["roles"] == ["proxy"]
    assert snap[B]["side"] == "back"  # 本轮没内容 → 沿用已判对的侧向（不退回默认）
    # 再把增量清零（模拟一次写回），重复快照不应重复计数
    det._pending_roles = {}
    assert det.snapshot()[B]["hits_total"]["proxy"] == 500


def test_reason_for_never_seen_node(roles_mod: ModuleType, stub_relays: dict[str, Any]) -> None:
    """清单里有、但从未被观测过：必须给出「为什么未判定」。"""
    det = roles_mod.RelayRoleDetector()
    snap = det.snapshot()
    assert set(snap) == {A, B}
    assert snap[A]["roles"] == []
    assert snap[A]["role_reason"] == roles_mod.REASON_NEVER_SEEN


def test_reason_for_no_content(roles_mod: ModuleType, stub_relays: dict[str, Any]) -> None:
    """有握手证据但两侧都无明文内容（实测 .214 的情形）。"""
    det = roles_mod.RelayRoleDetector()
    det._reset_if_list_changed()
    for _ in range(roles_mod.settings.relay_role_min_hits):
        det.observe(_entry(log_type="ssl", src_ip="8.8.8.8", dst_ip=A, dst_port=443))
    snap = det.snapshot()
    assert snap[A]["roles"] == ["proxy"], "有人来访问它的 443（握手证据）"
    assert snap[A]["side_reason"] == roles_mod.REASON_NO_CONTENT


def test_manual_role_override_wins(roles_mod: ModuleType, stub_relays: dict[str, Any]) -> None:
    stub_relays["overrides"] = {A: "dns"}
    det = roles_mod.RelayRoleDetector()
    det._reset_if_list_changed()
    det.observe(_entry(log_type="ssl", src_ip="8.8.8.8", dst_ip=A))
    snap = det.snapshot()
    assert snap[A]["roles"] == ["dns"]
    assert snap[A]["role_source"] == "manual"
    assert snap[A]["role_reason"] == ""  # 手工指定过就不再是「未判定」


def test_edges_from_direct_and_header(roles_mod: ModuleType, stub_relays: dict[str, Any]) -> None:
    """两类证据各自累计：① 中继→中继直连跳 ② 代理头里的上一跳。"""
    det = roles_mod.RelayRoleDetector()
    det._reset_if_list_changed()
    det.observe(_entry(log_type="http", src_ip=A, dst_ip=B, hop="relay_internal"))
    det.observe(
        _entry(
            log_type="http",
            src_ip=B,
            dst_ip=ORIGIN,
            hop="back",
            raw={"proxied": [f"X-Real-IP -> {A}"]},
        )
    )
    edges = det._merged_edges()
    assert edges[f"{A}|{B}"]["direct"] == 1
    assert edges[f"{A}|{B}"]["header"] == 1


# ---------- 攻击链还原 ----------


def test_kept_matches_relay_dedup(chain_mod: ModuleType, stub_relays: dict[str, Any]) -> None:
    """只有通过中继去重的事件才进链路（与检测器看到的一致）。"""
    stub_relays["sides"] = {B: "back"}
    assert chain_mod._kept({"hop": "direct"}) is True
    assert chain_mod._kept({"hop": "back", "src_ip": B}) is True
    assert chain_mod._kept({"hop": "front", "dst_ip": B}) is False  # 内容在源站侧 → 客户端跳被丢


def test_chain_of_fills_relay_path_from_topology(
    chain_mod: ModuleType, stub_relays: dict[str, Any]
) -> None:
    """保留的那一跳 + 拓扑 → 完整链路（含推导出来的中间中继）。"""
    stub_relays["topology"] = {
        "edges": [
            {"from": A, "to": B, "direct": 30, "header": 2, "confirmed": True, "stale": False}
        ],
        "levels": {A: 0, B: 1},
    }
    chain = chain_mod._chain_of(
        {
            "hop": "back",
            "src_ip": B,
            "dst_ip": ORIGIN,
            "real_client_ip": "8.8.8.8",
            "hostname": "app.example.com",
            "log_type": "http",
            "event_type": "http_request",
        },
        stub_relays["topology"]["edges"],
    )
    assert chain is not None
    assert chain["client"] == "8.8.8.8"
    assert chain["origin"] == "app.example.com"
    assert chain["relay_path"] == [A, B]  # 中间那跳由拓扑补上
    assert chain["relay_evidence"][0]["direct"] == 30


def test_chain_of_without_relay_is_two_hops(
    stub_relays: dict[str, Any], chain_mod: ModuleType
) -> None:
    """没有中继/跳板时就是「真实请求IP → 源站IP」。"""
    chain = chain_mod._chain_of(
        {"hop": "direct", "src_ip": "8.8.8.8", "dst_ip": ORIGIN, "log_type": "http"},
        [],
    )
    assert chain is not None
    assert chain["relay_path"] == []
    assert chain["client"] == "8.8.8.8"
    assert chain["origin"] == ORIGIN


def test_build_groups_and_marks_suspicious(
    chain_mod: ModuleType, stub_relays: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    docs = [
        {
            "ts": "2026-10-09T02:00:00+00:00",
            "hop": "back",
            "src_ip": B,
            "dst_ip": ORIGIN,
            "real_client_ip": "8.8.8.8",
            "hostname": "app.example.com",
            "log_type": "http",
            "event_type": "http_upload",
            "status_code": 200,
            "filename": "shell.jsp",
            "uri_path": "/a",
        },
        {
            "ts": "2026-10-09T02:00:01+00:00",
            "hop": "back",
            "src_ip": B,
            "dst_ip": ORIGIN,
            "real_client_ip": "8.8.8.8",
            "hostname": "app.example.com",
            "log_type": "http",
            "event_type": "http_request",
            "status_code": 200,
            "uri_path": "/b",
        },
    ]
    monkeypatch.setattr(chain_mod, "_fetch", lambda s, e, size: (docs, False))
    data = chain_mod._build(
        chain_mod.datetime.now(chain_mod.UTC),
        chain_mod.datetime.now(chain_mod.UTC),
        ip="",
        host="",
        suspicious_only=True,
    )
    assert len(data["chains"]) == 1
    chain = data["chains"][0]
    assert chain["client"] == "8.8.8.8"
    assert chain["suspicious"] is True
    assert chain["facts"]["events"] == 1  # 只看可疑：普通 http_request 被过滤掉
    assert "shell.jsp" in chain["facts"]["filenames"]


def test_dispatch_requires_push_config(
    chain_mod: ModuleType, stub_relays: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """没配推送地址时给出明确提示（而不是静默失败）。"""
    monkeypatch.setattr(
        chain_mod,
        "_fetch",
        lambda s, e, size: (
            [
                {
                    "hop": "back",
                    "src_ip": B,
                    "dst_ip": ORIGIN,
                    "real_client_ip": "8.8.8.8",
                    "hostname": "app.example.com",
                    "log_type": "http",
                    "event_type": "http_upload",
                    "filename": "x.jsp",
                }
            ],
            False,
        ),
    )
    monkeypatch.setattr(chain_mod.digest_push, "load_config", lambda db: {"url": "", "token": ""})
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as excinfo:
        chain_mod.dispatch_chain(
            chain_mod.DispatchIn(client="8.8.8.8", origin="app.example.com", minutes=30),
            db=None,
            _=None,
        )
    assert excinfo.value.status_code == 400
    assert "智能体对接" in str(excinfo.value.detail)


def test_dispatch_builds_chain_digest(
    chain_mod: ModuleType, stub_relays: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    stub_relays["topology"] = {
        "edges": [{"from": A, "to": B, "direct": 30, "header": 2, "confirmed": True}],
        "levels": {A: 0, B: 1},
    }
    monkeypatch.setattr(
        chain_mod,
        "_fetch",
        lambda s, e, size: (
            [
                {
                    "ts": "2026-10-09T02:00:00+00:00",
                    "hop": "back",
                    "src_ip": B,
                    "dst_ip": ORIGIN,
                    "real_client_ip": "8.8.8.8",
                    "hostname": "app.example.com",
                    "log_type": "suricata",
                    "event_type": "signature_hit",
                    "signature": "ET WEB_SERVER SQL Injection",
                    "signature_id": "2010935",
                }
            ],
            False,
        ),
    )
    monkeypatch.setattr(
        chain_mod.digest_push,
        "load_config",
        lambda db: {"url": "http://agent/digests", "token": "t"},
    )
    sent: dict[str, Any] = {}

    def fake_push(cfg: dict[str, Any], digests: list[dict[str, Any]]) -> tuple[bool, str]:
        sent["cfg"] = cfg
        sent["digest"] = digests[0]
        return True, ""

    monkeypatch.setattr(chain_mod.digest_push, "push_batch", fake_push)
    out = chain_mod.dispatch_chain(
        chain_mod.DispatchIn(client="8.8.8.8", origin="app.example.com", minutes=30),
        db=None,
        _=None,
    )
    assert out["delivered"] is True
    digest = sent["digest"]
    assert digest["src_ip"] == "8.8.8.8"
    assert digest["dst_ips"] == ["app.example.com"]
    assert digest["aggregate"]["chain"]["relay_path"] == [A, B]
    assert digest["samples"], "样本要带给智能体，否则它看不到证据"


# ---------- 实测暴露的两个缺陷：各留一条守卫 ----------


def test_apply_role_overrides_is_read_time(relay: ModuleType) -> None:
    """手工指定角色要**读时生效**（检测器回写是 5 分钟一轮，不能让人等）。"""
    roles = {A: {"roles": ["proxy"], "role_source": "auto", "role_reason": ""}}
    out = relay.apply_role_overrides(roles, {A: "dns"})
    assert out[A]["roles"] == ["dns"]
    assert out[A]["role_source"] == "manual"
    assert out[A]["role_reason"] == ""
    # auto / 非法值不动它；未在清单里的地址也不会凭空出现
    assert relay.apply_role_overrides(roles, {A: "auto"})[A]["roles"] == ["proxy"]
    assert relay.apply_role_overrides(roles, {A: "whatever"})[A]["roles"] == ["proxy"]
    assert relay.apply_role_overrides(roles, {"10.0.0.9": "dns"}).get("10.0.0.9") is None
    assert relay.apply_role_overrides(roles, {A: "both"})[A]["roles"] == ["proxy", "dns"]


def test_chain_ignores_cycle_broken_edge(
    chain_mod: ModuleType, stub_relays: dict[str, Any]
) -> None:
    """链路推导必须排除被环打断的边，否则会出现重复中继（实机踩到 [.214,.203,.214]）。"""
    stub_relays["topology"] = {
        "edges": [
            {"from": A, "to": B, "direct": 7683, "header": 332, "confirmed": True},
            {"from": B, "to": A, "direct": 16, "header": 0, "confirmed": True},
        ],
        "levels": {A: 0, B: 1},
        "cycle_broken": [[B, A]],  # 弱边（16 次）被判断开
    }
    edges, _ = chain_mod._edges()
    assert [e["to"] for e in edges] == [B]  # 只剩 A→B
    chain = chain_mod._chain_of(
        {
            "hop": "back",
            "src_ip": B,
            "dst_ip": ORIGIN,
            "real_client_ip": "8.8.8.8",
            "hostname": "app.example.com",
            "log_type": "http",
        },
        edges,
    )
    assert chain is not None
    assert chain["relay_path"] == [A, B]  # 不再出现重复的 A


def test_save_role_overrides_prunes_auto(relay: ModuleType) -> None:
    """保存手工指定时剪掉 auto（界面会把每台都提交一遍，留着就是一堆空条目）。"""

    class _Row:
        def __init__(self, key: str, value: dict[str, Any]) -> None:
            self.key = key
            self.value = value

    class _DB:
        def __init__(self) -> None:
            self.rows: dict[str, Any] = {}

        def get(self, _model: Any, key: str) -> Any:
            return self.rows.get(key)

        def add(self, row: Any) -> None:
            self.rows[row.key] = row

        def commit(self) -> None:
            return None

    db = _DB()
    relay.save_role_overrides(db, {A: "auto", B: "dns"})
    # 断言写进库里的载荷（不读缓存：缓存走真 DB，测试里只看这次写入）
    assert db.rows[relay.KEY].value["role_overrides"] == {B: "dns"}
