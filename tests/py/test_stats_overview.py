"""24h 流量（字节量）与协议占比（``app/api/routes/stats_overview.py``）。

只跑 NDR 栈。ES 全部打桩，钉住：

- 查询结构：流量**必须过滤 `log_type=conn`**（否则 HTTP 的 `bytes_in` 被重复计入），
  协议占比**不能**过滤（要的是全部类型分桶）；
- 形状换算：逐小时点带 `bytes_per_sec`、协议百分比以「top N + 其他」为分母；
- 300 秒缓存：页面 15 秒轮询不许穿透到 ES；**失败不写缓存**（下一轮能立刻重试）。
"""

from __future__ import annotations

import importlib
from collections.abc import Iterator, Mapping
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
    # 协议侧不过滤
    assert "filter" not in q["aggs"]["protocols"]
    assert q["aggs"]["protocols"]["terms"]["field"] == "log_type.keyword"
    assert q["aggs"]["protocols"]["terms"]["size"] == stats.PROTOCOL_TOP_N
    # 顺带按白名单内外分桶
    assert q["aggs"]["known"]["terms"]["field"] == "log_type_known"


# ---------- 形状换算 ----------


def _resp_with(buckets: list[dict[str, Any]], *, other: int = 0, known: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "aggregations": {
            "traffic": {"per_hour": {"buckets": buckets}},
            "protocols": {"buckets": [], "sum_other_doc_count": other},
            "known": {"buckets": known or []},
        }
    }


def test_shape_traffic_computes_bytes_per_sec(stats: ModuleType) -> None:
    resp = _resp_with(
        [
            {
                "key_as_string": "2026-10-04T10:00:00.000Z",
                "doc_count": 100,
                "bytes_out": {"value": 7200},
                "bytes_in": {"value": 3600},
            },
            {"key_as_string": "2026-10-04T11:00:00.000Z", "doc_count": 0, "bytes_out": {}, "bytes_in": {}},
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
    resp = _resp_with(
        [],
        other=300,
        known=[
            {"key_as_string": "true", "doc_count": 700},
            {"key_as_string": "false", "doc_count": 300},
        ],
    )
    resp["aggregations"]["protocols"]["buckets"] = [
        {"key": "conn", "doc_count": 500},
        {"key": "dns", "doc_count": 200},
    ]
    out = stats.shape_protocols(resp)
    assert out["total"] == 1000  # 500 + 200 + other(300)
    assert out["other_docs"] == 300
    assert out["items"][0] == {"log_type": "conn", "docs": 500, "percent": 50.0}
    assert out["items"][1]["percent"] == 20.0
    assert out["unclassified_docs"] == 300
    assert out["unclassified_percent"] == 30.0


def test_shape_protocols_handles_empty(stats: ModuleType) -> None:
    out = stats.shape_protocols({})
    assert out == {
        "total": 0,
        "other_docs": 0,
        "items": [],
        "unclassified_docs": 0,
        "unclassified_percent": 0.0,
    }


def test_shape_protocols_names_empty_log_type(stats: ModuleType) -> None:
    resp = _resp_with([])
    resp["aggregations"]["protocols"]["buckets"] = [{"key": "", "doc_count": 5}]
    out = stats.shape_protocols(resp)
    assert out["items"][0]["log_type"] == "(空)"


# ---------- 缓存 ----------


def test_endpoint_caches_and_reports_hit(stats: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def fake_fetch(hours: int) -> dict[str, Any]:
        calls["n"] += 1
        return {
            "hours": hours,
            "traffic": {"points": [], "total_docs": 0, "total_bytes": 0, "avg_bytes_per_sec": 0.0},
            "protocols": {"total": 0, "other_docs": 0, "items": [], "unclassified_docs": 0, "unclassified_percent": 0.0},
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


class _EsObjectResponse(Mapping[str, Any]):
    """模拟 elasticsearch-py 8.x 的 `ObjectApiResponse`：**是 Mapping，但不是 dict**。

    实机曾因此整张图空白：`_fetch` 用 `isinstance(resp, dict)` 判，把正常响应当成坏响应
    报「ES 返回了非预期结构」；而本地测试用的是 dict 桩，所以完全没抓到。
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)


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
    body["aggregations"]["protocols"]["buckets"] = [{"key": "conn", "doc_count": 3}]

    class _Client:
        def search(self, **_kw: Any) -> Any:
            return _EsObjectResponse(body)

    monkeypatch.setattr(es_client, "get_es", lambda: _Client())
    out = stats._fetch(24)
    assert out["error"] == "", out["error"]
    assert len(out["traffic"]["points"]) == 1
    assert out["traffic"]["points"][0]["bytes_per_sec"] == 1.0
    assert out["protocols"]["items"][0]["log_type"] == "conn"
