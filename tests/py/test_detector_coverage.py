"""检测器覆盖率口径（``ndr/backend/app/api/routes/detector.py`` 的 /coverage）回归测试。

QA 应修 4 的现场：分子取累计 ``delivered``、分母取窗口 ``es_docs``，实机出现
``delivered_total=5 / es_docs=55251 → ratio 0.0 / warn=true`` 的**恒假警**。
现在分子用最近统计区间的 ``d_delivered`` 折算窗口增量，快照过期则明确标注、不下判警。

只在 NDR 栈跑；``FakeRedis`` 从同目录的 ``test_detector_push`` 复用。
"""

from __future__ import annotations

import importlib
import time
from datetime import UTC, datetime
from typing import Any

import pytest


@pytest.fixture(scope="module")
def detector_route(request: pytest.FixtureRequest) -> Any:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("检测器路由只存在于 NDR 侧")
    return importlib.import_module("app.api.routes.detector")


@pytest.fixture(scope="module")
def fakes(request: pytest.FixtureRequest) -> Any:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("检测器路由只存在于 NDR 侧")
    return importlib.import_module("test_detector_push")


class _FakeES:
    """只实现 /coverage 用到的 count()。"""

    def __init__(self, count: int) -> None:
        self.count_value = count
        self.calls: list[dict[str, Any]] = []

    def count(self, index: str | None = None, query: Any = None) -> dict[str, int]:
        self.calls.append({"index": index, "query": query})
        return {"count": self.count_value}


def _patch_redis(monkeypatch: pytest.MonkeyPatch, client: Any) -> None:
    import redis

    monkeypatch.setattr(redis.Redis, "from_url", lambda *args, **kwargs: client)


def _patch_es(monkeypatch: pytest.MonkeyPatch, count: int) -> _FakeES:
    es_client = importlib.import_module("app.ingestion.es_client")
    es_config = importlib.import_module("app.ingestion.es_config")
    fake = _FakeES(count)
    monkeypatch.setattr(es_client, "get_es", lambda: fake)
    monkeypatch.setattr(es_config, "current", lambda: {"es.events_index": "shentong-events-*"})
    return fake


# ---------- 纯函数 ----------


def test_window_estimate_scales_interval_increment(detector_route: Any) -> None:
    # 区间 300s、请求窗口 3600s、区间增量 5 → 窗口估 60（量纲对齐的关键）
    assert detector_route._window_estimate(5, 300, 3600) == 60.0
    assert detector_route._window_estimate(0, 300, 3600) == 0.0
    assert detector_route._window_estimate(5, 0, 3600) is None
    assert detector_route._window_estimate(-3, 300, 3600) == 0.0


def test_snapshot_stale_rules(detector_route: Any) -> None:
    assert detector_route._snapshot_stale(1200, 300) is True  # > max(600, 900)
    assert detector_route._snapshot_stale(600, 300) is False
    assert detector_route._snapshot_stale(None, 300) is False
    assert detector_route._snapshot_stale(10**9, 0) is False  # 没区间就没法判，别误报


# ---------- 路由集成 ----------


def test_coverage_uses_window_increment_not_cumulative(
    detector_route: Any, fakes: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """累计值小、区间增量大时不能再恒假警（旧实现会 warn=true）。"""
    client = fakes.FakeRedis()
    client.hset(
        "shentong:detector:rates",
        mapping={
            "delivered": "5",  # 累计（进程重启后从 0 重新开始，因此常年很小）
            "d_delivered": "100",  # 最近 300s 真正投递了 100 条
            "interval_seconds": "300",
            "ts": str(datetime.now(UTC).timestamp()),
        },
    )
    _patch_redis(monkeypatch, client)
    _patch_es(monkeypatch, 1000)

    out = detector_route.detector_coverage(_=None, minutes=60)

    assert out["delivered_total"] == 5
    assert out["delivered_interval"] == 100
    assert out["delivered_window_est"] == 1200.0  # 100 * (3600/300)
    assert out["es_docs"] == 1000
    assert out["stale"] is False
    assert out["coverage_ratio"] == 1.2  # 窗口增量/窗口文档，而不是累计值
    assert out["warn"] is False


def test_coverage_stale_snapshot_does_not_false_alarm(
    detector_route: Any, fakes: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """检测器停了 → 快照过期：明确标注 stale，不拿 0 去下判警。"""
    client = fakes.FakeRedis()
    client.hset(
        "shentong:detector:rates",
        mapping={
            "delivered": "5",
            "d_delivered": "0",
            "interval_seconds": "300",
            "ts": str(time.time() - 4000),  # 4000s 没更新
        },
    )
    _patch_redis(monkeypatch, client)
    _patch_es(monkeypatch, 55251)

    out = detector_route.detector_coverage(_=None, minutes=60)

    assert out["stale"] is True
    assert out["coverage_ratio"] is None
    assert out["warn"] is False
    assert out["warn_reason"]
    assert out["es_docs"] == 55251
