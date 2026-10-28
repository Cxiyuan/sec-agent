"""可视化流量 + 资产中心：纯函数与过滤口径（不连 ES / 数据库）。

为什么先测这几条：这两页最容易出的错是**口径**而不是代码——
主语/对端选错字段（对外业务看 dst、横向/外连看 src）、内外网过滤没生效（把公网当资产）、
端口没映射成应用名（界面上一排数字）。这些都能在纯函数层面钉住。
"""

from __future__ import annotations

import importlib
import ipaddress
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


def _pair(
    src: str, dst: str, *, bo: int = 100, bi: int = 50, ports: list[int] | None = None
) -> dict:
    """一条 (源,目的) 对聚结果（`shape_pairs` 的输入形态）。"""
    return {
        "key": {"s": src, "d": dst},
        "doc_count": 1,
        "bo": {"value": bo},
        "bi": {"value": bi},
        "docs": {"value": 10},
        "last_seen": {"value_as_string": "2026-10-17T12:00:00.000Z"},
        "hostname": {"buckets": [{"key": "srv.example"}]},
        "ports": {
            "buckets": [
                {"key": port, "bo": {"value": 30}, "bi": {"value": 10}} for port in (ports or [443])
            ]
        },
    }


def test_shape_pairs_classifies_each_view(
    traffic: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """三视角的分母必须按「方向」切：同一批数据在三个视角下数字不能一样。

    （2026-10 QA 实测到的错：只在 Python 里过滤"显示出来的对端"、总量仍算全方向，
    结果横向与外连返回一模一样的行。）
    """
    import ipaddress

    monkeypatch.setattr(traffic, "_nets", lambda: [ipaddress.ip_network("10.0.0.0/8")])
    # 测试用的是文档保留段（is_global=False），用桩把"非 10/8 即公网"表达出来
    monkeypatch.setattr(traffic, "is_public_ip", lambda ip: not str(ip).startswith("10."))
    resp = {
        "aggregations": {
            # 主机名单独按主语给（字节在 conn、域名在 http，按"对"取会全空）
            "subject_hosts": {
                "buckets": [{"key": "10.1.2.3", "names": {"buckets": [{"key": "srv.example"}]}}]
            },
            "pairs": {
                "buckets": [
                    _pair("198.51.100.9", "10.1.2.3", bo=1000, bi=9000),  # 公网 → 内网资产
                    _pair("10.1.2.3", "10.9.9.9", bo=200, bi=100),  # 内网 → 内网
                    _pair("10.1.2.3", "203.0.113.5", bo=300, bi=50),  # 内网 → 公网
                ]
            },
        }
    }
    outbound = traffic.shape_pairs(resp, view="outbound", limit=50)["items"]
    assert [r["ip"] for r in outbound] == ["10.1.2.3"]
    assert outbound[0]["bytes_total"] == 10000  # 只算公网→资产那一对
    assert outbound[0]["hostname"] == "srv.example"  # 对外业务才有资产域名

    lateral = traffic.shape_pairs(resp, view="lateral", limit=50)["items"]
    assert [r["ip"] for r in lateral] == ["10.1.2.3"]
    assert lateral[0]["bytes_total"] == 300  # 只算内网↔内网那一对
    assert lateral[0]["hostname"] == ""  # 横向视角的 hostname 不是它自己的名字

    egress = traffic.shape_pairs(resp, view="egress", limit=50)["items"]
    assert [r["ip"] for r in egress] == ["10.1.2.3"]
    assert egress[0]["bytes_total"] == 350  # 只算内网→公网那一对


def test_shape_pairs_port_apps_and_peers(
    traffic: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ipaddress

    monkeypatch.setattr(traffic, "_nets", lambda: [ipaddress.ip_network("10.0.0.0/8")])
    monkeypatch.setattr(traffic, "is_public_ip", lambda ip: not str(ip).startswith("10."))
    resp = {
        "aggregations": {
            "pairs": {
                "buckets": [
                    _pair("198.51.100.9", "10.1.2.3", ports=[443, 22]),
                    _pair("203.0.113.5", "10.1.2.3", ports=[443]),
                ]
            }
        }
    }
    row = traffic.shape_pairs(resp, view="outbound", limit=50)["items"][0]
    apps = {p["app"] for p in row["ports"]}
    assert {"HTTPS/TLS", "SSH"} <= apps
    assert row["peers"] == 2, "两个不同公网客户端"
    assert len(row["peers_top"]) == 2


def test_clean_hostname_drops_ip_port(traffic: ModuleType) -> None:
    """Zeek 有时把 `IP:端口` 写进 host 字段，那不是主机名。"""
    assert traffic._clean_hostname("10.1.2.3:8080", "10.1.2.3") == ""
    assert traffic._clean_hostname("srv.example", "10.1.2.3") == "srv.example"


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


def test_shape_hosts_marks_managed(assets: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
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
                        "ports": {
                            "buckets": [{"key": 443, "bo": {"value": 5}, "bi": {"value": 1}}]
                        },
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


def test_agg_queries_avoid_painless_sum(traffic: ModuleType, assets: ModuleType) -> None:
    """聚合里不许用 Painless 把 bytes_out+bytes_in 加起来（2026-10 实机踩过的坑）。

    `doc['bytes_out'].value` 在缺该字段的文档（dns/weird 等没有字节量）上会抛
    "A document doesn't have a value for a field"，一抛就整个分片失败；ES 照样返回 200，
    buckets 却是空的 —— 界面上显示成「近期没有流量」，根因完全看不见。
    所以这里钉住：查询体里不许出现 script / painless。
    """
    import json

    # 现在三视角共用一个「按 (源,目的) 对聚合」的查询体
    body = traffic._pair_body(minutes=60, size=50)
    assert "script" not in json.dumps(body).lower()
    assert "composite" in json.dumps(body).lower(), "必须按对聚合，否则三视角口径分不开"
    assert "script" not in json.dumps(assets._discovery_body(minutes=60, size=50)).lower()


def test_shard_problem_is_reported(traffic: ModuleType) -> None:
    """分片失败要能说出来（否则 0 桶永远查不出原因）。"""
    ok = {"_shards": {"total": 1, "successful": 1, "failed": 0}}
    assert traffic.shard_problem(ok) == ""
    bad = {
        "_shards": {
            "total": 2,
            "successful": 1,
            "failed": 1,
            "failures": [
                {
                    "reason": {
                        "type": "script_exception",
                        "reason": "A document doesn't have a value",
                    }
                }
            ],
        }
    }
    msg = traffic.shard_problem(bad)
    assert "分片" in msg and "script_exception" in msg
    assert traffic.shard_problem({"aggregations": {"subject": {"buckets": []}}}) == ""


def test_unmonitored_private_src_is_not_outbound(
    traffic: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """未监控的内网段（如 10.1.90.x）→ 监控网段资产，**不算对外业务**。

    2026-10 QA 实测：只用"不在监控网段"判公网，会把 10.90.x 当成公网客户端，
    对外业务视角里全是内网地址、地域一栏清一色「内网」。
    """
    import ipaddress

    monkeypatch.setattr(traffic, "_nets", lambda: [ipaddress.ip_network("10.1.2.0/24")])
    monkeypatch.setattr(traffic, "is_public_ip", lambda ip: not str(ip).startswith("10."))
    resp = {
        "aggregations": {
            "pairs": {
                "buckets": [
                    _pair("10.1.90.5", "10.1.2.20"),  # 未监控内网 → 资产：不属于任何视角
                    _pair("198.51.100.9", "10.1.2.20"),  # 真公网 → 资产：属于对外业务
                ]
            }
        }
    }
    rows = traffic.shape_pairs(resp, view="outbound", limit=50)["items"]
    assert [r["ip"] for r in rows] == ["10.1.2.20"]
    assert rows[0]["peers"] == 1, "只有那个真公网客户端"


def test_outbound_uses_full_public_peer_set(traffic: ModuleType) -> None:
    """对外业务的取数口径：**公网来源全量**，不按流量取 TOP-N 主语。

    2026-10 实机踩过：被公网扫一枪的资产 `bytes_in` 接近 0，按流量排名永远进不了
    候选集（1 小时 13 台只剩 8 台）；composite 又只取字典序第一页（24 小时 40 台只剩 1 台）。
    这里钉住：第一段同时取 src_ip 与 real_client_ip（公网来源是少数，全取回来再过滤）。
    """
    body = traffic._public_peers_body(1440)
    aggs = body["aggs"]
    assert aggs["src"]["terms"]["field"] == "src_ip.keyword"
    assert aggs["real"]["terms"]["field"] == "real_client_ip.keyword"
    assert aggs["src"]["terms"]["size"] >= 10_000

    out = traffic._outbound_body(
        minutes=1440, peers=["203.0.113.9"], real_peers=[], size=500
    )
    query = out["query"]["bool"]
    assert query["minimum_should_match"] == 1
    assert {"terms": {"src_ip.keyword": ["203.0.113.9"]}} in query["should"]
    # 不允许再出现"按主语候选"的 terms 过滤（那正是漏数据的地方）
    assert all("dst_ip.keyword" not in str(f) for f in query["filter"])
    assert out["aggs"]["assets"]["terms"]["field"] == "dst_ip.keyword"


def test_outbound_rows_keeps_small_assets_and_filters_foreign_dst(
    traffic: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """资产行：0 字节的小流量资产也要留下；非监控网段的 dst 不能算资产。"""
    monkeypatch.setattr(
        traffic,
        "_nets",
        lambda: [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("192.168.0.0/16")],
    )
    resp = {
        "aggregations": {
            "assets": {
                "buckets": [
                    {
                        "key": "10.1.2.3",
                        "bo": {"value": 0},
                        "bi": {"value": 0},
                        "docs": {"value": 1},
                        "last_seen": {"value_as_string": "2026-10-17T12:00:00.000Z"},
                        "clients": {"value": 1},
                        "hostname": {"buckets": [{"key": "portal.example"}]},
                        "peer_top": {"buckets": [{"key": "203.0.113.9", "bo": {"value": 0}, "bi": {"value": 0}}]},
                        "ports": {"buckets": [{"key": 443, "bo": {"value": 0}, "bi": {"value": 0}}]},
                    },
                    {
                        "key": "8.8.8.8",
                        "bo": {"value": 9},
                        "bi": {"value": 9},
                        "docs": {"value": 9},
                        "last_seen": {"value_as_string": ""},
                        "clients": {"value": 1},
                        "hostname": {"buckets": []},
                        "peer_top": {"buckets": []},
                        "ports": {"buckets": []},
                    },
                ]
            }
        }
    }
    out = traffic._outbound_rows(resp, limit=50, minutes=1440)
    items = out["items"]
    assert [row["ip"] for row in items] == ["10.1.2.3"], "公网 dst 不是资产，小流量资产不能被丢"
    row = items[0]
    assert row["hostname"] == "portal.example"
    assert row["peers"] == 1
    assert row["ports"][0]["app"] == "HTTPS/TLS"
    assert out["kept_pairs"] == 1 and out["filtered_out"] == 1
    assert out["truncated"] is False
