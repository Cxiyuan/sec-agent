"""被访问方（内网源站 / 内网 DNS）基线：`ndr/backend/app/baseline/asset.py`。

只跑 NDR 栈。它要回答的是用户 2026-10 选定的方案 A：

> 按**被访问方**建基线（源 IP 那套看不出「服务器被访问」的异常），特征是被访问次数、
> 不同真实客户端数、不同客户端源端口数、不同目标数；资产标识 **hostname 优先**（HTTP Host /
> SSL SNI —— 中继场景下前跳也带它），无则回落 `IP:端口`（内网 DNS 就是 `IP:53`）。

中继去重已在检测器入口完成（后跳不进检测），所以这一层看到的就是「一次业务访问一条」。
"""

from __future__ import annotations

import importlib
from datetime import UTC, datetime, timedelta
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest


@pytest.fixture(scope="module")
def asset(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("被访问方基线只在 NDR 侧")
    return importlib.import_module("app.baseline.asset")


@pytest.fixture(scope="module")
def baseline_route(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("基线路由只在 NDR 侧")
    return importlib.import_module("app.api.routes.baseline")


def _entry(**kw: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "hostname": None,
        "dst_ip": "10.0.0.80",
        "dst_port": 80,
        "src_ip": "203.0.113.9",
        "src_port": 40000,
        "real_client_ip": None,
        "uri_path": "",
        "query": "",
    }
    base.update(kw)
    return SimpleNamespace(**base)


# ---------- 资产标识 ----------


def test_asset_key_prefers_hostname_and_lowercases(asset: ModuleType) -> None:
    assert asset.asset_key(_entry(hostname="WWW.NCZY.edu.cn", dst_ip="10.0.0.1")) == "www.nczy.edu.cn"


def test_asset_key_falls_back_to_ip_port(asset: ModuleType) -> None:
    """没有 Host/SNI 的流量（conn、内网 DNS 查询）只能落 IP:端口。"""
    assert asset.asset_key(_entry(hostname=None, dst_ip="10.0.0.53", dst_port=53)) == "10.0.0.53:53"
    assert asset.asset_key(_entry(hostname=None, dst_ip="10.0.0.53", dst_port=None)) == "10.0.0.53"
    assert asset.asset_key(_entry(hostname=None, dst_ip=None, dst_port=None)) == ""


def test_role_of_marks_dns_by_port(asset: ModuleType) -> None:
    assert asset.role_of("10.0.0.53:53") == "dns"
    assert asset.role_of("www.nczy.edu.cn") == "site"
    assert asset.role_of("172.16.196.112:443") == "site"


# ---------- 窗口累计 ----------


def test_observe_counts_visits_and_dedups(asset: ModuleType) -> None:
    buckets: dict[str, dict[str, Any]] = {}
    entry = _entry(hostname="a.example", real_client_ip="198.51.100.7", uri_path="/api/x")
    assert asset.observe_entry(buckets, entry) == 1
    asset.observe_entry(buckets, entry)  # 同一客户端同一路径：访问次数 +1，集合不变
    asset.observe_entry(
        buckets, _entry(hostname="a.example", real_client_ip="198.51.100.8", uri_path="/api/y")
    )
    bucket = buckets["a.example"]
    assert bucket["visits"] == 3
    assert bucket["clients"] == {"198.51.100.7", "198.51.100.8"}
    assert bucket["targets"] == {"/api/x", "/api/y"}


def test_observe_uses_real_client_when_proxied(asset: ModuleType) -> None:
    """中继链路上 src 是代理，客户端必须取 real_client_ip（否则"不同客户端数"永远是 1）。"""
    buckets: dict[str, dict[str, Any]] = {}
    asset.observe_entry(buckets, _entry(src_ip="172.16.199.203", real_client_ip="202.120.8.186"))
    assert buckets["10.0.0.80:80"]["clients"] == {"202.120.8.186"}


def test_observe_skips_entries_without_target(asset: ModuleType) -> None:
    buckets: dict[str, dict[str, Any]] = {}
    assert asset.observe_entry(buckets, _entry(hostname=None, dst_ip=None)) == 0
    assert buckets == {}


def test_window_values_shape(asset: ModuleType) -> None:
    buckets: dict[str, dict[str, Any]] = {}
    for _ in range(4):
        asset.observe_entry(buckets, _entry(hostname="a.example", uri_path="/p"))
    asset.observe_entry(buckets, _entry(hostname="a.example", real_client_ip="1.1.1.1", uri_path="/q"))
    values = asset.window_values(buckets)
    assert values["a.example:visits"] == [5.0]
    assert values["a.example:distinct_clients"] == [2.0]
    assert values["a.example:distinct_targets"] == [2.0]
    assert len(values["a.example:distinct_client_ports"]) == 1


def test_window_values_empty(asset: ModuleType) -> None:
    assert asset.window_values({}) == {}


# ---------- 落库（复用数值基线那套 Welford） ----------


class _Row:
    def __init__(self, key: str, count: int = 0, mean: float = 0.0, first_seen: Any = None) -> None:
        self.key = key
        self.count = count
        self.mean = mean
        self.m2 = 0.0
        self.first_seen = first_seen


class _Session:
    def __init__(self, rows: list[_Row] | None = None, scalars: list[_Row] | None = None) -> None:
        self.rows = rows or []
        self.by_scalars = scalars or []
        self.added: list[Any] = []
        self.commits = 0

    def scalars(self, _stmt: Any) -> Any:
        return SimpleNamespace(all=lambda: list(self.rows or self.by_scalars))

    def scalar(self, _stmt: Any) -> Any:
        return len(self.by_scalars or self.rows)

    def execute(self, _stmt: Any) -> Any:
        return SimpleNamespace(one=lambda: (1, 0, None), rowcount=0)

    def add(self, row: Any) -> None:
        self.added.append(row)

    def commit(self) -> None:
        self.commits += 1

    def __enter__(self) -> Any:
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool:
        return False


def test_apply_window_writes_asset_stats(
    asset: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """一个窗口的观测要落进 `asset_stats`（复用 stats.apply_stats，只是换模型）。"""
    session = _Session()
    monkeypatch.setattr(asset.stats_mod, "SessionLocal", lambda: session)
    out = asset.apply_window(
        {
            "a.example": {
                "visits": 3,
                "clients": {"1.1.1.1"},
                "client_ports": {1000},
                "targets": {"/p"},
            }
        }
    )
    assert set(out) == {
        "a.example:visits",
        "a.example:distinct_clients",
        "a.example:distinct_client_ports",
        "a.example:distinct_targets",
    }
    assert out["a.example:visits"]["count"] == 1
    assert len(session.added) == 4  # 四个特征各新建一行
    assert session.commits == 1
    assert all(type(row).__name__ == "AssetStat" for row in session.added)


def test_apply_window_noop_on_empty(asset: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    session = _Session()
    monkeypatch.setattr(asset.stats_mod, "SessionLocal", lambda: session)
    assert asset.apply_window({}) == {}
    assert session.added == []


# ---------- 读（列表 / 明细 / 概览） ----------


def test_list_assets_reports_state_and_means(
    asset: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = datetime.now(UTC) - timedelta(days=9)  # 已过观测期 → 生效中
    rows = [
        _Row("www.a.com:visits", count=3, mean=120.0, first_seen=old),
        _Row("www.a.com:distinct_clients", count=3, mean=42.0, first_seen=old),
        _Row("www.a.com:distinct_targets", count=3, mean=7.0, first_seen=old),
        _Row("www.a.com:distinct_client_ports", count=3, mean=50.0, first_seen=old),
    ]
    session = _Session(rows=rows, scalars=rows)
    monkeypatch.setattr(asset, "SessionLocal", lambda: session)
    out = asset.list_assets()
    assert out["total"] == 4  # fake 里 total 取的是行数（真实库是 :visits 行的条数）
    item = out["items"][0]
    assert item["asset"] == "www.a.com" and item["role"] == "site"
    assert item["state"] == "ready"
    assert item["visits_mean"] == 120.0 and item["clients_mean"] == 42.0
    assert item["window_seconds"] >= 1


def test_list_assets_learning_state(asset: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    fresh = datetime.now(UTC) - timedelta(hours=1)
    rows = [_Row("10.0.0.53:53:visits", count=1, mean=5.0, first_seen=fresh)]
    monkeypatch.setattr(asset, "SessionLocal", lambda: _Session(rows=rows, scalars=rows))
    out = asset.list_assets()
    assert out["items"][0]["state"] == "learning"
    assert out["items"][0]["role"] == "dns"


def test_asset_detail_returns_features(asset: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    fresh = datetime.now(UTC)
    rows = [
        _Row("a.example:visits", count=2, mean=9.0, first_seen=fresh),
        _Row("a.example:distinct_clients", count=2, mean=3.0, first_seen=fresh),
    ]
    monkeypatch.setattr(asset, "SessionLocal", lambda: _Session(rows=rows))
    out = asset.asset_detail("a.example")
    assert out["asset"] == "a.example"
    assert [item["feature"] for item in out["items"]] == ["distinct_clients", "visits"]
    assert out["observe_days"] >= 0


def test_asset_detail_needs_asset(asset: ModuleType) -> None:
    assert "error" in asset.asset_detail("")


def test_snapshot_degrades_on_db_error(asset: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> Any:
        raise RuntimeError("pg down")

    monkeypatch.setattr(asset, "SessionLocal", boom)
    out = asset.snapshot()
    assert out["total_assets"] == 0 and "pg down" in out["error"]


# ---------- 端点接线 ----------


def test_assets_route_passes_filters(
    baseline_route: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def fake_list(**kw: Any) -> dict[str, Any]:
        seen.update(kw)
        return {"total": 0, "items": []}

    monkeypatch.setattr(baseline_route, "list_assets", fake_list)
    baseline_route.baseline_assets(_=None, q="nczy", sort="visits", limit=5, offset=10)
    assert seen == {"q": "nczy", "sort": "visits", "limit": 5, "offset": 10}


def test_asset_stats_route_passes_asset(
    baseline_route: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def fake_detail(asset: str) -> dict[str, Any]:
        seen["asset"] = asset
        return {"asset": asset, "items": []}

    monkeypatch.setattr(baseline_route, "asset_detail", fake_detail)
    baseline_route.baseline_asset_stats(_=None, asset="a.example")
    assert seen["asset"] == "a.example"


def test_overview_includes_asset_snapshot(
    baseline_route: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(baseline_route, "assets_snapshot", lambda: {"total_assets": 7})
    monkeypatch.setattr(baseline_route.stats_mod, "snapshot", lambda: {"total_keys": 1})
    monkeypatch.setattr(baseline_route.profiles, "top_anomalies", lambda *a, **k: {"items": []})
    monkeypatch.setattr(baseline_route, "_detector_counters", lambda: {"alive": False})
    out = baseline_route._build_overview(10)
    assert out["assets"] == {"total_assets": 7}
