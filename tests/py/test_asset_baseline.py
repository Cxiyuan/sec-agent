"""被访问方（内网源站 / 内网 DNS）基线：`ndr/backend/app/baseline/asset.py`。

只跑 NDR 栈。它要回答的是用户 2026-10 选定的方案 A + 口径 B2：

> 按**被访问方**建基线（源 IP 那套看不出「服务器被访问」的异常）。
> **口径 B2：按连接算** —— 一个 Zeek `uid` = 一次「访问」；同一条连接里的
> `conn`（无 Host/SNI，落 `IP:端口`）与 `http`/`ssl`（有 Host/SNI，落 hostname）
> 合成**同一个身份**；请求数（http/dns）单独记。
> 资产标识 **hostname 优先**（中继场景下前跳也带 Host/SNI），无则回落 `IP:端口`（内网 DNS = `IP:53`）；
> **中继自身不作为资产**（端口 53 除外）；主机监控与没有 `uid` 的日志不进基线。
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


@pytest.fixture(scope="module")
def main_mod(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("启动迁移只在 NDR 侧")
    return importlib.import_module("app.main")


def _entry(**kw: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "uid": "C1",
        "log_type": "http",
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


# ---------- 资产标识（单条事件视角） ----------


def test_asset_key_prefers_hostname_and_lowercases(asset: ModuleType) -> None:
    assert (
        asset.asset_key(_entry(hostname="WWW.NCZY.edu.cn", dst_ip="10.0.0.1")) == "www.nczy.edu.cn"
    )


def test_asset_key_falls_back_to_ip_port(asset: ModuleType) -> None:
    """没有 Host/SNI 的流量（conn、内网 DNS 查询）只能落 IP:端口。"""
    assert asset.asset_key(_entry(hostname=None, dst_ip="10.0.0.53", dst_port=53)) == "10.0.0.53:53"
    assert asset.asset_key(_entry(hostname=None, dst_ip="10.0.0.53", dst_port=None)) == "10.0.0.53"
    assert asset.asset_key(_entry(hostname=None, dst_ip=None, dst_port=None)) == ""


def test_role_of_marks_dns_by_port(asset: ModuleType) -> None:
    assert asset.role_of("10.0.0.53:53") == "dns"
    assert asset.role_of("www.nczy.edu.cn") == "site"
    assert asset.role_of("172.16.196.112:443") == "site"


# ---------- 按连接（uid）累计 ----------


def test_conn_then_http_same_uid_is_one_visit(asset: ModuleType) -> None:
    """B2 的核心：`conn` 与 `http` 是同一条连接 → 一次访问，身份取 hostname。"""
    records: dict[str, dict[str, Any]] = {}
    assert (
        asset.observe_entry(
            records, _entry(uid="C1", log_type="conn", hostname=None, dst_ip="10.0.0.80")
        )
        == 1
    )
    assert (
        asset.observe_entry(
            records,
            _entry(uid="C1", log_type="http", hostname="a.example", uri_path="/api/x"),
        )
        == 0
    )
    buckets, dropped = asset.finalize(records)
    assert dropped == 0
    # 只落在 hostname 上，不再另外产生一行 `10.0.0.80:80`
    assert set(buckets) == {"a.example"}
    assert buckets["a.example"]["visits"] == 1
    assert buckets["a.example"]["requests"] == 1
    assert buckets["a.example"]["targets"] == {"/api/x"}


def test_http_then_conn_same_uid_is_one_visit(asset: ModuleType) -> None:
    """与事件到达顺序无关：http 先到、conn 后到，身份同样归到 hostname。"""
    records: dict[str, dict[str, Any]] = {}
    asset.observe_entry(records, _entry(uid="C9", log_type="http", hostname="b.example"))
    asset.observe_entry(records, _entry(uid="C9", log_type="conn", hostname=None))
    buckets, _ = asset.finalize(records)
    assert set(buckets) == {"b.example"}
    assert buckets["b.example"]["visits"] == 1


def test_keepalive_requests_counted_but_visit_once(asset: ModuleType) -> None:
    """一条长连接上多条请求：访问数仍是 1，请求数按应用层日志累计。"""
    records: dict[str, dict[str, Any]] = {}
    for path in ("/a", "/b", "/c", "/a"):
        asset.observe_entry(
            records, _entry(uid="C2", log_type="http", hostname="a.example", uri_path=path)
        )
    buckets, _ = asset.finalize(records)
    assert buckets["a.example"]["visits"] == 1
    assert buckets["a.example"]["requests"] == 4
    assert buckets["a.example"]["targets"] == {"/a", "/b", "/c"}


def test_conn_only_is_not_an_asset(asset: ModuleType) -> None:
    """纯 TCP 连接（无 Host/SNI、零请求）**不算被访问方**（v4 口径）。

    实机依据（2026-10）：资产表 95,443 个资产里 94,642 个是 `IP:端口`，其中 48,971 个端口
    ≥32768（如 `172.16.199.106:53650` 只有 305 条 conn、零请求）—— 那是「收到过连接的目标」，
    不是「被访问的站点」，界面上的资产数因此虚高几十倍。
    """
    records: dict[str, dict[str, Any]] = {}
    asset.observe_entry(records, _entry(uid="C3", log_type="conn", hostname=None))
    buckets, dropped = asset.finalize(records)
    assert buckets == {}, "只有 conn、没有任何请求的连接不该进资产表"
    assert dropped == 1


def test_conn_only_with_hostname_is_still_an_asset(asset: ModuleType) -> None:
    """但同一连接里带 Host/SNI（如纯 TLS 站点）：即使没有 http 日志，也还是被访问方。"""
    records: dict[str, dict[str, Any]] = {}
    asset.observe_entry(records, _entry(uid="C3b", log_type="conn", hostname=None))
    asset.observe_entry(records, _entry(uid="C3b", log_type="ssl", hostname="tls.example"))
    buckets, dropped = asset.finalize(records)
    assert dropped == 0
    assert buckets["tls.example"]["visits"] == 1
    assert buckets["tls.example"]["requests"] == 0


def test_dns_resolver_is_an_asset_even_without_hostname(asset: ModuleType) -> None:
    """内网 DNS 转发器（`IP:53`）有 dns 请求 → 仍是资产（不能因为没域名就被丢掉）。"""
    records: dict[str, dict[str, Any]] = {}
    asset.observe_entry(
        records, _entry(uid="C3c", log_type="dns", hostname=None, dst_port=53, query="a.example")
    )
    buckets, dropped = asset.finalize(records)
    assert dropped == 0
    assert buckets["10.0.0.80:53"]["requests"] == 1


def test_real_client_ip_wins_over_src_ip(asset: ModuleType) -> None:
    """中继链路上 src 是代理，客户端必须取 real_client_ip（否则「不同客户端数」永远是 1）。"""
    records: dict[str, dict[str, Any]] = {}
    asset.observe_entry(records, _entry(uid="C4", log_type="conn", hostname=None))
    asset.observe_entry(
        records,
        _entry(uid="C4", log_type="http", hostname="a.example", real_client_ip="202.120.8.186"),
    )
    buckets, _ = asset.finalize(records)
    assert buckets["a.example"]["clients"] == {"202.120.8.186"}


def test_one_connection_can_carry_many_real_clients(asset: ModuleType) -> None:
    """一条长连接上可以有很多个真实客户端（WAF 复用/承载）——只记一个会把客户端数压成 1。

    实测：`www.nczy.edu.cn` 近 5 分钟 206 个请求只走了 11 条连接，XFF 里却有 112 个不同客户端。
    """
    records: dict[str, dict[str, Any]] = {}
    for i in range(3):
        asset.observe_entry(
            records,
            _entry(
                uid="K1", log_type="http", hostname="a.example", real_client_ip=f"198.51.100.{i}"
            ),
        )
    buckets, _ = asset.finalize(records)
    assert buckets["a.example"]["visits"] == 1  # 一条连接 = 一次访问
    assert buckets["a.example"]["requests"] == 3
    assert buckets["a.example"]["clients"] == {"198.51.100.0", "198.51.100.1", "198.51.100.2"}


def test_many_connections_aggregate_by_asset(asset: ModuleType) -> None:
    """多条连接落到同一资产：访问数按连接算，客户端/端口/目标各自去重。"""
    records: dict[str, dict[str, Any]] = {}
    plan = (
        ("U1", "203.0.113.9", 40001),
        ("U2", "203.0.113.9", 40002),
        ("U3", "198.51.100.7", 40003),
    )
    for i, (uid, src, port) in enumerate(plan):
        asset.observe_entry(
            records,
            _entry(
                uid=uid,
                log_type="http",
                hostname="a.example",
                src_ip=src,
                src_port=port,
                uri_path=f"/p{i}",
            ),
        )
    buckets, dropped = asset.finalize(records)
    assert dropped == 0
    bucket = buckets["a.example"]
    assert bucket["visits"] == 3
    assert bucket["requests"] == 3
    assert bucket["clients"] == {"203.0.113.9", "198.51.100.7"}
    assert bucket["client_ports"] == {40001, 40002, 40003}
    assert bucket["targets"] == {"/p0", "/p1", "/p2"}


# ---------- 中继自身不作为资产 ----------


def test_front_hop_to_relay_is_dropped(asset: ModuleType, set_relays: Any) -> None:
    """前跳的 dst 就是中继：非 HTTP 没有 Host/SNI 时身份会落到它身上 —— 那是「代理被连接」。"""
    set_relays("172.16.199.203")
    records: dict[str, dict[str, Any]] = {}
    asset.observe_entry(
        records,
        _entry(uid="F1", log_type="conn", hostname=None, dst_ip="172.16.199.203", dst_port=8000),
    )
    buckets, dropped = asset.finalize(records)
    assert buckets == {} and dropped == 1


def test_relay_hop_with_hostname_is_kept(asset: ModuleType, set_relays: Any) -> None:
    """有 Host/SNI 时身份是站点（不是中继），照常计入 —— 这正是「经代理的访问归到站点上」。"""
    set_relays("172.16.199.203")
    records: dict[str, dict[str, Any]] = {}
    asset.observe_entry(
        records,
        _entry(
            uid="F2",
            log_type="http",
            hostname="www.nczy.edu.cn",
            dst_ip="172.16.199.203",
            dst_port=8000,
        ),
    )
    buckets, dropped = asset.finalize(records)
    assert dropped == 0
    assert set(buckets) == {"www.nczy.edu.cn"}


def test_dns_relay_kept_on_port_53(asset: ModuleType, set_relays: Any) -> None:
    """端口 53 的中继要保留：内网 DNS 被多少客户端查询正是要看的东西。"""
    set_relays("172.16.199.211")
    records: dict[str, dict[str, Any]] = {}
    asset.observe_entry(
        records,
        _entry(
            uid="D1",
            log_type="dns",
            hostname=None,
            dst_ip="172.16.199.211",
            dst_port=53,
            query="evil.example",
        ),
    )
    asset.observe_entry(
        records,
        _entry(
            uid="D2",
            log_type="dns",
            hostname=None,
            dst_ip="172.16.199.211",
            dst_port=53,
            query="good.example",
        ),
    )
    buckets, dropped = asset.finalize(records)
    assert dropped == 0
    assert buckets["172.16.199.211:53"]["visits"] == 2
    assert buckets["172.16.199.211:53"]["requests"] == 2
    assert buckets["172.16.199.211:53"]["targets"] == {"evil.example", "good.example"}


def test_finalize_drops_connection_without_identity(asset: ModuleType) -> None:
    records: dict[str, dict[str, Any]] = {}
    asset.observe_entry(records, _entry(uid="X1", hostname=None, dst_ip=None, dst_port=None))
    buckets, dropped = asset.finalize(records)
    assert buckets == {} and dropped == 1


# ---------- 不进基线的输入 ----------


def test_entries_without_uid_do_not_enter(asset: ModuleType) -> None:
    records: dict[str, dict[str, Any]] = {}
    assert asset.observe_entry(records, _entry(uid="", log_type="files")) == -1
    assert records == {}


def test_max_uids_caps_memory(asset: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """连接记录数有上限：超出的连接不再入桶（避免突发流量把内存顶爆）。"""
    monkeypatch.setattr(asset.settings, "asset_max_uids", 1)
    records: dict[str, dict[str, Any]] = {}
    assert asset.observe_entry(records, _entry(uid="U1")) == 1
    assert asset.observe_entry(records, _entry(uid="U2")) == -1
    assert list(records) == ["U1"]


def test_request_log_types_configurable(asset: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """请求数口径可配：把名单清空 → 不再累计请求数（访问数仍按连接算）。"""
    monkeypatch.setattr(asset.settings, "asset_request_log_types", "")
    records: dict[str, dict[str, Any]] = {}
    asset.observe_entry(records, _entry(uid="U3", log_type="http", hostname="a.example"))
    buckets, _ = asset.finalize(records)
    assert buckets["a.example"]["visits"] == 1
    assert buckets["a.example"]["requests"] == 0


def test_window_values_shape(asset: ModuleType) -> None:
    buckets: dict[str, dict[str, Any]] = {
        "a.example": {
            "visits": 5,
            "requests": 9,
            "clients": {"1.1.1.1", "2.2.2.2"},
            "client_ports": {1000},
            "targets": {"/p", "/q"},
        }
    }
    values = asset.window_values(buckets)
    assert values["a.example:visits"] == [5.0]
    assert values["a.example:requests"] == [9.0]
    assert values["a.example:distinct_clients"] == [2.0]
    assert values["a.example:distinct_targets"] == [2.0]
    assert values["a.example:distinct_client_ports"] == [1.0]


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
                "requests": 7,
                "clients": {"1.1.1.1"},
                "client_ports": {1000},
                "targets": {"/p"},
            }
        }
    )
    assert set(out) == {
        "a.example:visits",
        "a.example:requests",
        "a.example:distinct_clients",
        "a.example:distinct_client_ports",
        "a.example:distinct_targets",
    }
    assert out["a.example:visits"]["count"] == 1
    assert out["a.example:requests"]["mean"] == 7.0
    assert len(session.added) == 5  # 五个特征各新建一行
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
        _Row("www.a.com:requests", count=3, mean=280.0, first_seen=old),
        _Row("www.a.com:distinct_clients", count=3, mean=42.0, first_seen=old),
        _Row("www.a.com:distinct_targets", count=3, mean=7.0, first_seen=old),
        _Row("www.a.com:distinct_client_ports", count=3, mean=50.0, first_seen=old),
    ]
    session = _Session(rows=rows, scalars=rows)
    monkeypatch.setattr(asset, "SessionLocal", lambda: session)
    out = asset.list_assets()
    assert out["total"] == 5  # fake 里 total 取的是行数（真实库是 :visits 行的条数）
    item = out["items"][0]
    assert item["asset"] == "www.a.com" and item["role"] == "site"
    assert item["state"] == "ready"
    assert item["visits_mean"] == 120.0 and item["clients_mean"] == 42.0
    assert item["requests_mean"] == 280.0
    assert item["window_seconds"] >= 1


def test_list_assets_learning_state(asset: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    fresh = datetime.now(UTC) - timedelta(hours=1)
    rows = [_Row("10.0.0.53:53:visits", count=1, mean=5.0, first_seen=fresh)]
    monkeypatch.setattr(asset, "SessionLocal", lambda: _Session(rows=rows, scalars=rows))
    out = asset.list_assets()
    assert out["items"][0]["state"] == "learning"
    assert out["items"][0]["role"] == "dns"
    assert out["items"][0]["requests_mean"] == 0.0  # 没有 requests 行时给 0，不是 null


def test_asset_detail_returns_features(asset: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    fresh = datetime.now(UTC)
    rows = [
        _Row("a.example:visits", count=2, mean=9.0, first_seen=fresh),
        _Row("a.example:requests", count=2, mean=21.0, first_seen=fresh),
        _Row("a.example:distinct_clients", count=2, mean=3.0, first_seen=fresh),
    ]
    monkeypatch.setattr(asset, "SessionLocal", lambda: _Session(rows=rows))
    out = asset.asset_detail("a.example")
    assert out["asset"] == "a.example"
    assert [item["feature"] for item in out["items"]] == [
        "distinct_clients",
        "requests",
        "visits",
    ]
    assert out["observe_days"] >= 0


def test_asset_detail_needs_asset(asset: ModuleType) -> None:
    assert "error" in asset.asset_detail("")


def test_snapshot_degrades_on_db_error(asset: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> Any:
        raise RuntimeError("pg down")

    monkeypatch.setattr(asset, "SessionLocal", boom)
    out = asset.snapshot()
    assert out["total_assets"] == 0 and "pg down" in out["error"]


# ---------- 口径版本迁移（清空旧口径统计，幂等） ----------


class _MigSession:
    """够 `_migrate_asset_semantics` 用的小号 Session（只读一行版本配置）。"""

    def __init__(self, row: Any = None, version: int = 0) -> None:
        self.row = row
        self.version = version
        self.executed: list[Any] = []
        self.added: list[Any] = []
        self.commits = 0

    def get(self, _model: Any, _key: str) -> Any:
        return self.row

    def execute(self, stmt: Any) -> Any:
        self.executed.append(stmt)
        return SimpleNamespace(rowcount=1215)

    def add(self, row: Any) -> None:
        self.added.append(row)

    def commit(self) -> None:
        self.commits += 1

    def __enter__(self) -> Any:
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool:
        return False


def test_migrate_asset_semantics_clears_when_version_missing(
    main_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = _MigSession(row=None)
    monkeypatch.setattr(main_mod, "SessionLocal", lambda: session)
    main_mod._migrate_asset_semantics()
    assert len(session.executed) == 1  # 清空旧口径统计
    assert session.commits == 1
    assert session.added and session.added[0].value == {"value": main_mod._ASSET_SEMANTICS_VERSION}


def test_migrate_asset_semantics_upgrades_old_version(
    main_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    row = SimpleNamespace(key="asset.semantics_version", value={"value": "1"})
    session = _MigSession(row=row)
    monkeypatch.setattr(main_mod, "SessionLocal", lambda: session)
    main_mod._migrate_asset_semantics()
    assert len(session.executed) == 1 and row.value == {"value": main_mod._ASSET_SEMANTICS_VERSION}


def test_migrate_asset_semantics_is_idempotent(
    main_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """版本已到位就不再动库（可重复启动）。"""
    row = SimpleNamespace(
        key="asset.semantics_version", value={"value": main_mod._ASSET_SEMANTICS_VERSION}
    )
    session = _MigSession(row=row)
    monkeypatch.setattr(main_mod, "SessionLocal", lambda: session)
    main_mod._migrate_asset_semantics()
    assert session.executed == [] and session.added == [] and session.commits == 0


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
