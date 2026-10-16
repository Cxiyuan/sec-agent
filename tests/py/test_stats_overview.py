"""24h 流量（字节量）与协议占比（``app/api/routes/stats_overview.py``）。

只跑 NDR 栈。ES 全部打桩，钉住：

- 查询结构：流量**必须过滤 `log_type=conn`**（否则 HTTP 的 `bytes_in` 被重复计入），
  协议占比**不能**过滤（要的是全部类型分桶）；
- 形状换算：逐小时点带 `bytes_per_sec`、协议百分比以「top N + 其他」为分母；
- 300 秒缓存：页面 15 秒轮询不许穿透到 ES；**失败不写缓存**（下一轮能立刻重试）。
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import Any

import pytest


@pytest.fixture(scope="module")
def stats(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("流量/协议聚合端点只在 NDR 侧")
    return importlib.import_module("app.api.routes.stats_overview")


@pytest.fixture(autouse=True)
def _clear_cache(stats: ModuleType) -> Any:
    stats._cache.clear()
    yield
    stats._cache.clear()


# ---------- 时间窗 ----------


@pytest.mark.parametrize(
    ("value", "want"),
    [(24, 24), ("24", 24), (None, 24), ("dirty", 24), (0, 1), (-5, 1), (999, 168)],
)
def test_clamp_hours(stats: ModuleType, value: Any, want: int) -> None:
    assert stats.clamp_hours(value) == want


# ---------- 查询结构 ----------


def test_build_query_filters_traffic_on_conn_only(stats: ModuleType) -> None:
    q = stats.build_query(24, start="2026-10-03T00:00:00Z", end="2026-10-04T00:00:00Z")
    assert q["size"] == 0
    assert q["query"]["range"]["@timestamp"] == {
        "gte": "2026-10-03T00:00:00Z",
        "lt": "2026-10-04T00:00:00Z",
    }
    # 流量侧带 conn 过滤（HTTP 也填 bytes_in，不过滤会重复计数）
    traffic = q["aggs"]["traffic"]
    assert traffic["filter"] == {"term": {"log_type.keyword": "conn"}}
    hist = traffic["aggs"]["per_hour"]["date_histogram"]
    assert hist["fixed_interval"] == "1h"
    assert hist["min_doc_count"] == 0
    assert hist["extended_bounds"]["min"] == "2026-10-03T00:00:00Z"
    # 协议侧：只算协议识别类日志 —— 用白名单 `include` 限住，而不是拉全量再前端过滤
    assert "filter" not in q["aggs"]["protocols"]
    assert q["aggs"]["protocols"]["terms"]["field"] == "log_type.keyword"
    assert q["aggs"]["protocols"]["terms"]["size"] == stats.PROTOCOL_TOP_N
    include = q["aggs"]["protocols"]["terms"]["include"]
    assert isinstance(include, list) and include
    # 非协议日志决不能在白名单里（用户明确要求：不想看到 conn/weird 这些）
    for bad in ("conn", "weird", "files", "notice", "x509", "syslog", "stats", "reporter"):
        assert bad not in include, bad
    # 协议识别类必须在（不然图就空了）
    for good in ("http", "dns", "ssl", "ssh", "mysql", "pgsql", "smtp", "ftp"):
        assert good in include, good
    # 被排除的量单独一个 filter agg（给图上写「另有 X% 未计入」，不静默消失）
    must_not = q["aggs"]["excluded"]["filter"]["bool"]["must_not"]
    assert must_not == [{"terms": {"log_type.keyword": include}}]


# ---------- 形状换算 ----------


def _resp_with(
    buckets: list[dict[str, Any]], *, other: int = 0, excluded: int = 0
) -> dict[str, Any]:
    return {
        "aggregations": {
            "traffic": {"per_hour": {"buckets": buckets}},
            "protocols": {"buckets": [], "sum_other_doc_count": other},
            "excluded": {"doc_count": excluded},
        }
    }


def test_shape_minute_traffic_carries_rate_and_drops(stats: ModuleType) -> None:
    """近期流量：每点必须是**每秒**口径 + 带 Zeek 上报的掉包值（不是桶内总量）。"""
    import datetime as _dt

    start = _dt.datetime(2026, 10, 16, 10, 0, tzinfo=_dt.UTC)
    end = start + _dt.timedelta(seconds=40)
    resp = {
        "aggregations": {
            "traffic": {
                "per_interval": {
                    "buckets": [
                        {
                            "key": 1,
                            "doc_count": 2,
                            "bytes_out": {"value": 1000.0},
                            "bytes_in": {"value": 3000.0},
                        },
                        {
                            "key": 2,
                            "doc_count": 1,
                            "bytes_out": {"value": 500.0},
                            "bytes_in": {"value": 500.0},
                        },
                    ]
                }
            },
            "drops": {
                "per_interval": {
                    "buckets": [
                        {"key": 1, "doc_count": 0, "pkts_dropped": {"value": 0.0}},
                        {"key": 2, "doc_count": 1, "pkts_dropped": {"value": 7.0}},
                    ]
                }
            },
        }
    }
    out = stats.shape_minute_traffic(resp, minutes=30, now=end)
    first = out["points"][0]
    # 4000 字节落在 20 秒的桶里 → 每秒 200，而不是 4000
    assert first["bytes_per_sec"] == 200.0
    assert first["bytes_out_per_sec"] == 50.0
    assert first["bytes_in_per_sec"] == 150.0
    assert out["points"][1]["pkts_dropped"] == 7.0
    assert out["pkts_dropped_latest"] == 7.0


def test_shape_traffic_computes_bytes_per_sec(stats: ModuleType) -> None:
    resp = _resp_with(
        [
            {
                "key_as_string": "2026-10-04T10:00:00.000Z",
                "doc_count": 100,
                "bytes_out": {"value": 7200},
                "bytes_in": {"value": 3600},
            },
            {
                "key_as_string": "2026-10-04T11:00:00.000Z",
                "doc_count": 0,
                "bytes_out": {},
                "bytes_in": {},
            },
        ]
    )
    out = stats.shape_traffic(resp, hours=2)
    assert len(out["points"]) == 2
    first = out["points"][0]
    assert first["bytes_total"] == 10800
    assert first["bytes_per_sec"] == 3.0  # 10800 / 3600
    # 空桶也要给点（曲线不断线），值为 0
    assert out["points"][1]["bytes_total"] == 0
    assert out["total_bytes"] == 10800
    assert out["total_docs"] == 100
    assert out["avg_bytes_per_sec"] == round(10800 / (2 * 3600), 1)


def test_shape_traffic_skips_bad_buckets(stats: ModuleType) -> None:
    out = stats.shape_traffic(_resp_with([{"key_as_string": "x"}, "junk"]), hours=1)  # type: ignore[list-item]
    assert len(out["points"]) == 1
    assert out["points"][0]["bytes_total"] == 0


def test_shape_protocols_uses_topn_plus_other_as_denominator(stats: ModuleType) -> None:
    """分母只算协议类文档（top N 之和 + other），**不含**被排除的非协议日志。"""
    resp = _resp_with([], other=300, excluded=4000)
    resp["aggregations"]["protocols"]["buckets"] = [
        {"key": "http", "doc_count": 500},
        {"key": "dns", "doc_count": 200},
    ]
    out = stats.shape_protocols(resp)
    assert out["total"] == 1000  # 500 + 200 + other(300)：协议类总数
    assert out["other_docs"] == 300
    # 百分比的分母必须是协议类总数（1000），不是全量（5000）
    assert out["items"][0] == {"log_type": "http", "docs": 500, "percent": 50.0}
    assert out["items"][1]["percent"] == 20.0
    # 被排除的那部分单独报（4000 / 5000 = 80%）
    assert out["excluded_docs"] == 4000
    assert out["excluded_percent"] == 80.0


def test_shape_protocols_handles_empty(stats: ModuleType) -> None:
    out = stats.shape_protocols({})
    assert out == {
        "total": 0,
        "other_docs": 0,
        "items": [],
        "excluded_docs": 0,
        "excluded_percent": 0.0,
    }


def test_shape_protocols_excluded_only(stats: ModuleType) -> None:
    """全是被排除的非协议日志：协议图为空，但「未计入 100%」要说得出来，不能除零。"""
    out = stats.shape_protocols(_resp_with([], excluded=42))
    assert out["items"] == []
    assert out["total"] == 0
    assert out["excluded_docs"] == 42
    assert out["excluded_percent"] == 100.0


def test_shape_protocols_names_empty_log_type(stats: ModuleType) -> None:
    resp = _resp_with([])
    resp["aggregations"]["protocols"]["buckets"] = [{"key": "", "doc_count": 5}]
    out = stats.shape_protocols(resp)
    assert out["items"][0]["log_type"] == "(空)"


# ---------- 缓存 ----------


def test_endpoint_caches_and_reports_hit(
    stats: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"n": 0}

    def fake_fetch(hours: int) -> dict[str, Any]:
        calls["n"] += 1
        return {
            "hours": hours,
            "traffic": {"points": [], "total_docs": 0, "total_bytes": 0, "avg_bytes_per_sec": 0.0},
            "protocols": {
                "total": 0,
                "other_docs": 0,
                "items": [],
                "excluded_docs": 0,
                "excluded_percent": 0.0,
            },
            "computed_at": "x",
            "cached": False,
            "error": "",
        }

    monkeypatch.setattr(stats, "_fetch", fake_fetch)
    first = stats.stats_overview(_=None, hours=24)
    second = stats.stats_overview(_=None, hours=24)
    assert first["cached"] is False
    assert second["cached"] is True
    assert calls["n"] == 1
    # 不同窗口各自缓存
    stats.stats_overview(_=None, hours=6)
    assert calls["n"] == 2


def test_endpoint_does_not_cache_errors(stats: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def failing(hours: int) -> dict[str, Any]:
        calls["n"] += 1
        return {"hours": hours, "traffic": {}, "protocols": {}, "error": "es down", "cached": False}

    monkeypatch.setattr(stats, "_fetch", failing)
    stats.stats_overview(_=None, hours=24)
    stats.stats_overview(_=None, hours=24)
    assert calls["n"] == 2  # 失败不钉缓存，下一轮立刻重试


def test_fetch_returns_error_payload_when_es_fails(
    stats: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    es_client = importlib.import_module("app.ingestion.es_client")

    def boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("no es")

    monkeypatch.setattr(es_client, "get_es", boom)
    out = stats._fetch(24)
    assert out["error"]
    assert out["traffic"]["points"] == []
    assert out["protocols"]["items"] == []


class _EsObjectResponse:
    """模拟 elasticsearch-py 8.x 的 `elastic_transport.ObjectApiResponse`。

    真实类的 MRO 是 `[ObjectApiResponse, ApiResponse, Generic, object]` —— **既不是 dict，
    也不是 Mapping**，只是鸭子类型地实现了 `.get` / `__getitem__`。所以这里刻意不继承
    Mapping：只要代码里再出现 `isinstance(resp, dict/Mapping)` 之类的类型判定，本用例就会红。
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __iter__(self) -> Any:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)


def test_fetch_accepts_mapping_response_from_es_client(
    stats: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ES 客户端返回的不是普通 dict —— 不能拿 `isinstance(resp, dict)` 当有效性判定。"""
    es_client = importlib.import_module("app.ingestion.es_client")
    body = _resp_with(
        [
            {
                "key_as_string": "2026-10-04T10:00:00.000Z",
                "doc_count": 3,
                "bytes_out": {"value": 3600},
                "bytes_in": {"value": 0},
            }
        ],
        other=1,
    )
    body["aggregations"]["protocols"]["buckets"] = [{"key": "http", "doc_count": 3}]

    class _Client:
        def search(self, **_kw: Any) -> Any:
            return _EsObjectResponse(body)

    monkeypatch.setattr(es_client, "get_es", lambda: _Client())
    out = stats._fetch(24)
    assert out["error"] == "", out["error"]
    assert len(out["traffic"]["points"]) == 1
    assert out["traffic"]["points"][0]["bytes_per_sec"] == 1.0
    assert out["protocols"]["items"][0]["log_type"] == "http"
