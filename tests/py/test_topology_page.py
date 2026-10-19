"""拓扑发现页（/admin/topology）：转发链路/全量通信两个视图 + 节点别名。

用户 2026-10 口径：
- 节点默认显示名**必须是 IP**（别名只叠加显示，host 名不作节点名）；
- 以**流量转发的逻辑**为计算标准：有中继就要在图上体现（客户端 → 中继 → 中继 → 源站）；
- 别名是展示层数据、**全局生效**，改完立即生效且不影响任何检测语义。

拓扑图的实现刻意复用攻击链页的 `_window/_fetch/_kept/_edges`，所以这里除了断言图本身，
还断言**两页口径一致**（同一批事件、同一批中继边）——它们一旦漂移，运维会看到两张不一致的图。
"""

from __future__ import annotations

import importlib
from pathlib import Path
from types import ModuleType
from typing import Any, Self

import pytest

ROOT = Path(__file__).resolve().parents[2]
A = "10.1.2.11"
B = "10.1.2.10"
ORIGIN = "10.1.2.23"
CLIENT = "8.8.8.8"


@pytest.fixture(scope="module")
def topo(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("拓扑发现只在 NDR 侧")
    return importlib.import_module("app.topology.graph")


@pytest.fixture(scope="module")
def aliases(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("节点别名只在 NDR 侧")
    return importlib.import_module("app.topology.aliases")


@pytest.fixture(scope="module")
def route(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("拓扑接口只在 NDR 侧")
    return importlib.import_module("app.api.routes.topology")


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """把链路口径依赖（事件 / 中继清单 / 中继拓扑）全换成内存桩。"""
    chain_route = importlib.import_module("app.api.routes.chain")
    relay = importlib.import_module("app.ingestion.relay_nodes")

    state: dict[str, Any] = {
        "docs": [],
        "topology": {"edges": [], "levels": {}},
        "roles": {},
        "sides": {},
    }
    monkeypatch.setattr(chain_route, "_fetch", lambda s, e, size: (list(state["docs"]), False))
    monkeypatch.setattr(
        chain_route,
        "_edges",
        lambda: (list(state["topology"]["edges"]), dict(state["topology"]["levels"])),
    )
    monkeypatch.setattr(relay, "topology", lambda: dict(state["topology"]))
    monkeypatch.setattr(relay, "roles", lambda: dict(state["roles"]))
    monkeypatch.setattr(relay, "sides", lambda: dict(state["sides"]))
    monkeypatch.setattr(relay, "configured", lambda: True)
    monkeypatch.setattr(relay, "is_relay", lambda ip: str(ip) in (A, B))
    return state


def _doc(**kw: Any) -> dict[str, Any]:
    base = {
        "hop": "back",
        "src_ip": B,
        "dst_ip": ORIGIN,
        "real_client_ip": CLIENT,
        "log_type": "http",
        "event_type": "http_request",
    }
    base.update(kw)
    return base


# ---------- 转发链路视图 ----------


def test_forward_uses_same_kept_events_as_chain(topo: ModuleType, stub: dict[str, Any]) -> None:
    """保留的那一跳 → 边是「真实请求IP → 源站」；被丢掉的那一跳不进图。"""
    stub["sides"] = {B: "back"}
    stub["docs"] = [
        _doc(),  # hop=back 且内容在源站侧 → 保留
        _doc(hop="front", src_ip=CLIENT, dst_ip=B, real_client_ip=""),  # 客户端侧被去重丢掉
    ]
    data = topo.forward_graph(minutes=30)
    pairs = {(e["source"], e["target"]) for e in data["edges"]}
    # hop=back 这一跳的真实两端就是「中继 → 源站」（客户端在中继的另一侧，由 front 跳体现）
    assert (B, ORIGIN) in pairs, "保留的那一跳要画出来（中继 → 源站）"
    assert (CLIENT, B) not in pairs, "被中继去重丢掉的那一跳不该出现在转发视图里"
    assert data["mode"] == "forward"


def test_forward_adds_inferred_relay_chain(topo: ModuleType, stub: dict[str, Any]) -> None:
    """多级串联：中继→中继的边由上下级拓扑补出来，并标成 inferred（不是实测）。"""
    stub["sides"] = {B: "back"}
    stub["docs"] = [_doc()]
    stub["topology"] = {
        "edges": [
            {"from": A, "to": B, "direct": 7683, "header": 332, "confirmed": True, "stale": False}
        ],
        "levels": {A: 0, B: 1},
    }
    data = topo.forward_graph(minutes=30)
    inferred = [e for e in data["edges"] if e["kind"] == "inferred"]
    assert inferred, "中继之间的串联关系必须补进图里（否则看不出多级转发）"
    edge = inferred[0]
    assert (edge["source"], edge["target"]) == (A, B)
    assert edge["direct"] == 7683 and edge["header"] == 332
    kinds = {n["id"]: n["kind"] for n in data["nodes"]}
    assert kinds[A] == "relay" and kinds[B] == "relay"
    assert kinds[ORIGIN] == "origin"


def test_forward_respects_cycle_broken(topo: ModuleType, stub: dict[str, Any]) -> None:
    """拓扑里被判环打断的边不能出现在图上（否则链路会出现重复中继）。"""
    stub["sides"] = {B: "back"}
    stub["docs"] = [_doc()]
    stub["topology"] = {
        "edges": [
            {"from": A, "to": B, "direct": 7683, "header": 332, "confirmed": True},
            {"from": B, "to": A, "direct": 16, "header": 0, "confirmed": True},
        ],
        "levels": {A: 0, B: 1},
        "cycle_broken": [[B, A]],
    }
    data = topo.forward_graph(minutes=30)
    pairs = {(e["source"], e["target"]) for e in data["edges"]}
    assert (B, A) not in pairs


def test_forward_truncation_is_stated(
    topo: ModuleType, stub: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """超出节点上限要截断并**明说**（不许静默少画）。"""
    from app.config import settings

    stub["sides"] = {B: "back"}
    stub["docs"] = [
        _doc(src_ip=B, dst_ip=f"10.0.0.{i}", real_client_ip=CLIENT) for i in range(1, 30)
    ]
    monkeypatch.setattr(settings, "topology_node_limit", 5)
    data = topo.forward_graph(minutes=30)
    assert data["truncated"] is True
    assert data["note"], "截断必须带说明"
    assert len(data["nodes"]) <= 5


# ---------- 全量通信视图 ----------


def test_full_query_shape(topo: ModuleType) -> None:
    """全量视图查的是 ES 聚合（不拉文档），且带节点数上限与每节点出边上限。"""
    body = topo.build_full_query(
        start="2026-10-09T00:00:00Z", end="2026-10-09T01:00:00Z", node_limit=50, edge_per_node=4
    )
    assert body.get("size") == 0, "聚合查询不该拉文档"
    terms = ((body.get("aggs") or {}).get("src") or {}).get("terms") or {}
    assert terms.get("field") == "src_ip.keyword"
    assert terms.get("size") == 50, "源节点按上限截断"


def test_full_shaping_keeps_top_edges(topo: ModuleType) -> None:
    """把 ES 聚合结果整形：节点按事件数排序截断，边只留两端都在图里的。"""
    resp = {
        "aggregations": {
            "src": {
                "buckets": [
                    {
                        "key": B,
                        "doc_count": 100,
                        "dst": {
                            "buckets": [
                                {"key": ORIGIN, "doc_count": 60},
                                {"key": "10.0.0.9", "doc_count": 40},
                            ]
                        },
                    },
                    {"key": A, "doc_count": 50, "dst": {"buckets": [{"key": B, "doc_count": 50}]}},
                ]
            }
        }
    }
    shaped = topo.shape_full(resp, node_limit=10)
    # 节点包含所有出现过的 IP（源 + 目的），中继只是其中两个
    assert {A, B, ORIGIN, "10.0.0.9"} <= {n["id"] for n in shaped["nodes"]}
    pairs = {(e["source"], e["target"]) for e in shaped["edges"]}
    assert pairs == {(B, ORIGIN), (B, "10.0.0.9"), (A, B)}
    assert all(n["kind"] == "endpoint" for n in shaped["nodes"]), "全量视图的节点是普通端点"


def test_alias_validation_is_strict(aliases: ModuleType) -> None:
    assert aliases.validate_ip("10.1.2.10") == ""
    assert aliases.validate_ip("not-an-ip"), "非法 IP 必须报错"
    assert aliases.validate_name("核心WAF") == ""
    assert aliases.validate_name("") == "", "空名 = 删除别名，合法"
    assert aliases.validate_name("x" * 65), "超过 64 字必须报错"


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

    # 实现里用 `with SessionLocal() as db:` —— 假库也要支持上下文协议
    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


def test_set_alias_and_clear(aliases: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    # set_alias 返回的是 snapshot()（走缓存 + SessionLocal），把 SessionLocal 换成同一个假库
    db = _DB()
    monkeypatch.setattr(aliases, "SessionLocal", lambda: db)
    out = aliases.set_alias(db, B, "  核心WAF  ")
    assert out == {B: "核心WAF"}, "名称要去首尾空白"
    out = aliases.set_alias(db, B, "")  # 空名 = 删除
    assert out == {}, "空名要真的删掉别名（回到显示 IP）"


def test_alias_is_display_only(aliases: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """别名只影响展示层：写入后能读回来，不改任何检测语义（无副作用）。"""
    db = _DB()
    monkeypatch.setattr(aliases, "SessionLocal", lambda: db)
    aliases.set_alias(db, A, "WAF-入口")
    assert aliases.describe()["aliases"][A] == "WAF-入口"
    assert aliases.get(A) == "WAF-入口"
    assert aliases.get("10.0.0.1") == ""


# ---------- 接口 ----------


def test_route_rejects_unknown_mode(route: ModuleType) -> None:
    resp = route.get_topology(_=None, mode="whatever")  # type: ignore[arg-type]
    assert getattr(resp, "status_code", 200) == 400


def test_route_aliases_rejects_bad_ip(route: ModuleType) -> None:
    resp = route.set_alias(route.AliasIn(ip="999.1.1.1", name="x"), db=_DB(), _=None)  # type: ignore[arg-type]
    assert getattr(resp, "status_code", 200) == 400


def test_panel_parent_matches_levels_source() -> None:
    """中继清单的「上一跳」必须与「链路层级」同源（实机踩到：显示 L0 却写着上一跳 xxx）。

    层级（levels）是**排除被环打断的边**之后算出来的；上一跳如果直接读原始边列表，
    就会把被打断的反向弱边捡回来 —— 214 曾因此被显示成「L0 上一跳 203」（真实主干是
    214→203 的 163 万次，反向只有 614 次）。
    """
    panel = (ROOT / "ndr" / "frontend" / "components" / "relay-nodes-panel.tsx").read_text(
        encoding="utf-8"
    )
    assert "cycle_broken" in panel, "上一跳必须排除被判环打断的边"
    assert "brokenEdges" in panel
    assert "入口（无上级）" not in panel, "层级 0 只是「清单内没有上级」，不能直接叫入口"
    assert "最上游" in panel


def test_entry_probe_uses_plain_ips(topo: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """入口证据必须用**纯 IP** 查（清单里是网段对象，str() 会变成 1.2.3.4/32 匹配不到文档）。"""
    import ipaddress

    relay = importlib.import_module("app.ingestion.relay_nodes")
    es_client = importlib.import_module("app.ingestion.es_client")
    monkeypatch.setattr(relay, "networks", lambda: (ipaddress.ip_network(f"{A}/32"),))

    captured: dict[str, Any] = {}

    class _ES:
        def search(self, **kwargs: Any) -> dict[str, Any]:
            captured.update(kwargs)
            return {
                "aggregations": {
                    "relays": {
                        "buckets": [
                            {
                                "key": A,
                                "doc_count": 614,
                                "src": {"buckets": [{"key": "8.8.8.8", "doc_count": 12}]},
                            }
                        ]
                    }
                }
            }

    monkeypatch.setattr(es_client, "get_es", lambda: _ES())
    # es_config.current() 会去读库（测试环境没有 PG）：直接给一份索引名
    monkeypatch.setattr(
        importlib.import_module("app.ingestion.es_config"),
        "current",
        lambda: {"es.events_index": "shentong-events-*"},
    )
    out = topo.entry_probe(24)
    terms = ((captured.get("query") or {}).get("bool", {}).get("filter") or [])[-1].get(
        "terms"
    ) or {}
    assert terms.get("dst_ip.keyword") == [A], f"入口证据必须查纯 IP，实际 {terms}"
    assert out[A]["inbound"] == 614
    assert out[A]["entry_state"] == "entry", "有公网来源（8.8.8.8）就该判成入口"


def test_relays_survive_node_limit(
    topo: ModuleType, stub: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """中继是结构骨架：即使事件数很低（inferred 边带进来的）也不能被节点上限裁掉。"""
    from app.config import settings

    stub["sides"] = {B: "back"}
    stub["docs"] = [
        _doc(src_ip=B, dst_ip=f"10.0.0.{i}", real_client_ip=CLIENT) for i in range(1, 40)
    ]
    stub["topology"] = {
        "edges": [{"from": A, "to": B, "direct": 9, "header": 0, "confirmed": True}],
        "levels": {A: 0, B: 1},
    }
    monkeypatch.setattr(settings, "topology_node_limit", 3)
    data = topo.forward_graph(minutes=30)
    ids = {n["id"] for n in data["nodes"]}
    assert {A, B} <= ids, f"中继不能被裁掉（实际 {sorted(ids)}）"


# 2026-10 前端改版（提交 555fb81）删掉了独立的拓扑页（`/admin/topology` 与 `/topology`），
# 图与链路信息并入「可视化流量」的抽屉里，因此原来守那张页面的用例一并移除；
# 本文件其余用例守的是后端拓扑图算法（转发链路还原、全量视图塑形、别名校验），仍然有效。
