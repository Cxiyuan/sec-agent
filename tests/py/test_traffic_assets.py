"""可视化流量 + 资产中心：纯函数与过滤口径（不连 ES / 数据库）。

为什么先测这几条：这两页最容易出的错是**口径**而不是代码——
主语/对端选错字段（对外业务看 dst、横向/外连看 src）、内外网过滤没生效（把公网当资产）、
端口没映射成应用名（界面上一排数字）。这些都能在纯函数层面钉住。
"""

from __future__ import annotations

import importlib
from types import ModuleType

import pytest


@pytest.fixture(scope="module")
def traffic(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("可视化流量只在 NDR 侧")
    return importlib.import_module("app.api.routes.traffic_views")


@pytest.fixture(scope="module")
def assets(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("资产中心只在 NDR 侧")
    return importlib.import_module("app.api.routes.assets_center")


def test_subject_and_peer_fields_per_view(traffic: ModuleType) -> None:
    """对外业务看"被访问资产"（dst / 客户端 src），横向与外连看"发起方"（src / 对端 dst）。"""
    assert traffic._subject_field("outbound") == "dst_ip"
    assert traffic._peer_field("outbound") == "src_ip"
    assert traffic._subject_field("lateral") == "src_ip"
    assert traffic._peer_field("lateral") == "dst_ip"
    assert traffic._subject_field("egress") == "src_ip"
    assert traffic._peer_field("egress") == "dst_ip"


def test_app_of_maps_ports(traffic: ModuleType) -> None:
    assert traffic.app_of(443) == "HTTPS/TLS"
    assert traffic.app_of(53) == "DNS"
    assert traffic.app_of(9999, "tcp") == "9999/tcp"
    assert traffic.app_of(None) == "其它"


def _bucket(ip: str, *, out: int = 100, inb: int = 50, peers: list[str] | None = None) -> dict:
    return {
        "key": ip,
        "doc_count": 10,
        "bytes_out": {"value": out},
        "bytes_in": {"value": inb},
        "peers": {"value": len(peers or [])},
        "last_seen": {"value_as_string": "2026-10-17T12:00:00.000Z"},
        "hostname": {"buckets": [{"key": "srv.example"}]},
        "log_types": {"buckets": [{"key": "http", "doc_count": 5}]},
        "ports": {
            "buckets": [
                {"key": 443, "bytes": {"value": 120}, "doc_count": 5},
                {"key": 22, "bytes": {"value": 30}, "doc_count": 2},
            ]
        },
        "top_peers": {
            "buckets": [
                {
                    "key": p,
                    "bytes": {"value": 10},
                    "hostname": {"buckets": []},
                }
                for p in (peers or [])
            ]
        },
    }


def test_shape_rows_filters_non_monitored_subjects(
    traffic: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """主语不在监控网段的桶要被丢掉（否则"公网→公网"的噪声会混进资产列表）。"""
    import ipaddress

    monkeypatch.setattr(
        traffic, "_nets", lambda: [ipaddress.ip_network("10.0.0.0/8")]
    )
    resp = {
        "aggregations": {
            "subject": {
                "buckets": [
                    _bucket("10.1.2.3", peers=["198.51.100.9"]),  # 内网资产：保留
                    _bucket("198.51.100.77", peers=["203.0.113.5"]),  # 公网：丢掉
                ]
            }
        }
    }
    out = traffic.shape_rows(resp, view="outbound", limit=50)
    ips = [row["ip"] for row in out["items"]]
    assert ips == ["10.1.2.3"]
    assert out["filtered_out"] == 1
    row = out["items"][0]
    assert row["bytes_total"] == 150
    assert [p["app"] for p in row["ports"]] == ["HTTPS/TLS", "SSH"]


def test_shape_rows_lateral_keeps_only_internal_peers(
    traffic: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """横向视角的对端只保留网段内地址；外连视角反过来只保留网段外地址。"""
    import ipaddress

    monkeypatch.setattr(traffic, "_nets", lambda: [ipaddress.ip_network("10.0.0.0/8")])
    resp = {
        "aggregations": {
            "subject": {"buckets": [_bucket("10.1.2.3", peers=["10.9.9.9", "198.51.100.9"])]}
        }
    }
    lateral = traffic.shape_rows(resp, view="lateral", limit=50)["items"][0]
    assert [p["ip"] for p in lateral["peers_top"]] == ["10.9.9.9"]
    egress = traffic.shape_rows(resp, view="egress", limit=50)["items"][0]
    assert [p["ip"] for p in egress["peers_top"]] == ["198.51.100.9"]


def test_regions_are_unknown_without_geoip(traffic: ModuleType) -> None:
    """没配地理库时，地域显示「未知」而不是瞎猜（也不抛错）。"""
    rows = traffic._regions_from_peers([{"ip": "198.51.100.9"}, {"ip": "203.0.113.5"}])
    assert rows, "至少要给出占位"
    assert all(set(r) == {"region", "count"} for r in rows)


def test_asset_internal_check(assets: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    import ipaddress

    nets = [ipaddress.ip_network("10.0.0.0/8")]
    assert assets._in("10.1.5.5", nets) is True
    assert assets._in("8.8.8.8", nets) is False
    assert assets._in("not-an-ip", nets) is False


def test_shape_hosts_marks_managed(
    assets: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """发现结果要标出「已在台账」的主机，并且只保留网段内的。"""
    import ipaddress

    resp = {
        "aggregations": {
            "hosts": {
                "buckets": [
                    {
                        "key": "10.1.2.3",
                        "doc_count": 100,
                        "bytes_out": {"value": 10},
                        "bytes_in": {"value": 20},
                        "clients": {"value": 7},
                        "first_seen": {"value_as_string": "2026-10-17T00:00:00.000Z"},
                        "last_seen": {"value_as_string": "2026-10-17T12:00:00.000Z"},
                        "hostname": {"buckets": [{"key": "srv.example"}]},
                        "ports": {"buckets": [{"key": 443, "bytes": {"value": 5}}]},
                    },
                    {
                        "key": "8.8.8.8",
                        "doc_count": 1,
                        "bytes_out": {"value": 1},
                        "bytes_in": {"value": 1},
                        "clients": {"value": 1},
                        "first_seen": {},
                        "last_seen": {},
                        "hostname": {"buckets": []},
                        "ports": {"buckets": []},
                    },
                ]
            }
        }
    }
    rows = assets._shape_hosts(
        resp, nets=[ipaddress.ip_network("10.0.0.0/8")], managed={"10.1.2.3"}
    )
    assert len(rows) == 1
    row = rows[0]
    assert row["ip"] == "10.1.2.3" and row["managed"] is True
    assert row["exposure"] == 1 and row["clients"] == 7
    assert row["ports"][0]["app"] == "HTTPS/TLS"
