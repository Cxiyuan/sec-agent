"""组件健康判据与聚合（``app/api/routes/health_components.py``）——总览页 7 个呼吸灯。

只跑 NDR 栈。全部探测都 monkeypatch 掉（不连 ES/Redis/HTTP/DB），钉住：

- 判据边界（5/30 分钟、2/15 分钟、green/yellow/red、未配置 ≠ 坏了）；
- 八个 key 一个不少，且**任一探测抛异常只影响它自己那盏灯**；
- 30 秒缓存生效（页面 15 秒轮询，不能每轮都真探一遍）。
"""

from __future__ import annotations

import importlib
from contextlib import contextmanager
from types import ModuleType
from typing import Any

import pytest

ALL_KEYS = ("zeek", "capture", "wazuh", "redis", "logstash", "elasticsearch", "normalizer", "agent")


@pytest.fixture(scope="module")
def hc(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("组件健康端点只在 NDR 侧")
    return importlib.import_module("app.api.routes.health_components")


@pytest.fixture(autouse=True)
def _clear_cache(hc: ModuleType) -> Any:
    """模块级缓存跨用例会串味，每个用例前后都清。"""
    hc._cache["at"] = 0.0
    hc._cache["payload"] = None
    yield
    hc._cache["at"] = 0.0
    hc._cache["payload"] = None


# ---------- 纯判据 ----------


@pytest.mark.parametrize(
    ("age", "want"),
    [(0.0, "ok"), (300.0, "ok"), (300.1, "degraded"), (1800.0, "degraded"), (1800.1, "down")],
)
def test_judge_age_boundaries(hc: ModuleType, age: float, want: str) -> None:
    assert hc.judge_age(age, hc.ZEEK_OK_WITHIN, hc.ZEEK_DEGRADED_WITHIN) == want


def test_judge_age_none_is_unknown(hc: ModuleType) -> None:
    assert hc.judge_age(None, 300.0, 1800.0) == "unknown"


@pytest.mark.parametrize(
    ("status", "want"),
    [("green", "ok"), ("yellow", "degraded"), ("red", "down"), (None, "unknown"), ("", "unknown")],
)
def test_judge_es(hc: ModuleType, status: Any, want: str) -> None:
    assert hc.judge_es(status) == want


@pytest.mark.parametrize(
    ("reachable", "warn", "want"),
    [(False, False, "down"), (True, False, "ok"), (True, True, "degraded")],
)
def test_judge_redis(hc: ModuleType, reachable: bool, warn: bool, want: str) -> None:
    assert hc.judge_redis(reachable, warn) == want


@pytest.mark.parametrize(
    ("runtime", "want"),
    [
        (None, "down"),
        ({"alive": False}, "down"),
        ({"alive": True, "reloads_failures": 0}, "ok"),
        ({"alive": True, "reloads_failures": "2"}, "degraded"),
        ({"alive": True, "reloads_failures": None}, "ok"),
    ],
)
def test_judge_logstash(hc: ModuleType, runtime: Any, want: str) -> None:
    assert hc.judge_logstash(runtime) == want


@pytest.mark.parametrize(
    ("reachable", "alerts", "want"),
    [
        (False, 100, "down"),
        (True, 0, "degraded"),
        (True, None, "ok"),
        (True, 12, "ok"),
    ],
)
def test_judge_wazuh(hc: ModuleType, reachable: bool, alerts: Any, want: str) -> None:
    assert hc.judge_wazuh(reachable, alerts) == want


@pytest.mark.parametrize(
    ("active", "last_success", "has_error", "want"),
    [
        (False, "", False, "unknown"),  # 没配 = 不知道，而不是坏了
        (True, "", False, "degraded"),  # 配了但还没成功过
        (True, "", True, "degraded"),
        (True, "2026-10-04T10:00:00+00:00", True, "ok"),
        (True, "2026-10-04T10:00:00+00:00", False, "ok"),
    ],
)
def test_judge_agent(
    hc: ModuleType, active: bool, last_success: str, has_error: bool, want: str
) -> None:
    assert hc.judge_agent(active, last_success, has_error) == want


# ---------- 聚合（全部探测打桩） ----------


class _FakeRedis:
    def ping(self) -> bool:
        return True


def _patch_all(hc: ModuleType, monkeypatch: pytest.MonkeyPatch, **overrides: Any) -> None:
    @contextmanager
    def fake_session() -> Any:
        yield object()

    defaults = {
        "_es_health": lambda: ("green", "green · 1 节点 · 未分配 0"),
        "_es_freshness": lambda: {"zeek_age": 10.0, "wazuh_age": 60.0, "any_age": 5.0, "error": ""},
        "_capture_stats": lambda: {
            "count": 100,
            "top": [("possible_split_routing", 60), ("data_before_established", 40)],
            "error": "",
        },
        "_redis_client": lambda: _FakeRedis(),
    }
    defaults.update(overrides)
    for name, fn in defaults.items():
        monkeypatch.setattr(hc, name, fn)

    monkeypatch.setattr(hc, "SessionLocal", fake_session)
    monkeypatch.setattr(
        hc.health, "redis_memory", lambda _c: {"used": 100, "max": 1000, "perc": 10.0}
    )
    monkeypatch.setattr(hc.health, "describe", lambda _m: "100/1000（10%）")
    monkeypatch.setattr(
        hc.logstash_route,
        "pipeline_runtime",
        lambda: {"alive": True, "reloads_failures": 0, "events_in": 5, "events_out": 5},
    )
    monkeypatch.setattr(
        hc.wazuh_route,
        "probe_status",
        lambda: {"reachable": True, "version": "v4.14.8", "detail": "连通"},
    )
    monkeypatch.setattr(hc.wazuh_route, "ingest_stats", lambda: {"alerts": 1187})
    monkeypatch.setattr(
        hc.push, "load_config", lambda _db=None: {"url": "http://agent:8000/x", "enabled": True}
    )
    monkeypatch.setattr(hc.push, "is_on", lambda _cfg: True)
    monkeypatch.setattr(
        hc.push,
        "status",
        lambda _c: {
            "last_success_at": "2026-10-04T10:00:00+00:00",
            "undelivered": 3,
            "last_error": "",
        },
    )


def test_collect_returns_all_seven_components_ok(
    hc: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_all(hc, monkeypatch)
    payload = hc._collect()
    items = {item["key"]: item for item in payload["items"]}
    assert tuple(items) == ALL_KEYS
    assert all(item["state"] == "ok" for item in items.values()), items
    assert "green" in items["elasticsearch"]["detail"]
    assert "10 秒前" in items["zeek"]["detail"]
    assert "5 秒前" in items["normalizer"]["detail"]
    assert "1187" in items["wazuh"]["detail"]
    assert "未投递 3" in items["agent"]["detail"]
    # 采集质量灯：条数 + 最常见的异常名都在 detail 里
    assert "100 条" in items["capture"]["detail"]
    assert "possible_split_routing 60" in items["capture"]["detail"]


@pytest.mark.parametrize(
    ("count", "want"),
    [
        (0, "ok"),
        (4999, "ok"),
        (5000, "degraded"),
        (19999, "degraded"),
        (20000, "down"),
        (None, "unknown"),
    ],
)
def test_judge_capture(hc: ModuleType, count: int | None, want: str) -> None:
    """采集类协议异常的数量判据（阈值 5000/20000）：突增 = 采集在丢包（会漏检）。"""
    assert hc.judge_capture(count, 5000, 20000) == want


def test_capture_light_degrades_on_probe_failure(
    hc: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """读不到统计时只影响这盏灯（不把整页拖成不可用）。"""
    _patch_all(
        hc, monkeypatch, _capture_stats=lambda: {"count": None, "top": [], "error": "es 超时"}
    )
    items = {item["key"]: item for item in hc._collect()["items"]}
    assert items["capture"]["state"] == "unknown"
    assert "es 超时" in items["capture"]["detail"]
    assert [k for k, v in items.items() if v["state"] != "ok"] == ["capture"]


def test_capture_yellow_when_over_threshold(
    hc: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_all(
        hc,
        monkeypatch,
        _capture_stats=lambda: {"count": 9999, "top": [], "error": ""},
    )
    items = {item["key"]: item for item in hc._collect()["items"]}
    assert items["capture"]["state"] == "degraded"


def test_one_probe_failure_only_affects_its_own_light(
    hc: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom() -> Any:
        raise RuntimeError("wazuh 挂了")

    _patch_all(hc, monkeypatch, _es_health=lambda: ("green", "ok"))
    monkeypatch.setattr(hc.wazuh_route, "probe_status", boom)
    monkeypatch.setattr(hc.wazuh_route, "ingest_stats", boom)

    items = {item["key"]: item for item in hc._collect()["items"]}
    assert items["wazuh"]["state"] == "down"
    # 其余六盏灯不受影响
    assert [k for k, v in items.items() if v["state"] != "ok"] == ["wazuh"]


def test_es_and_redis_down_are_visible(hc: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> Any:
        raise RuntimeError("es down")

    _patch_all(hc, monkeypatch)
    monkeypatch.setattr(hc, "_es_health", boom)

    def bad_client() -> Any:
        raise RuntimeError("redis down")

    monkeypatch.setattr(hc, "_redis_client", bad_client)

    items = {item["key"]: item for item in hc._collect()["items"]}
    assert items["elasticsearch"]["state"] == "unknown"  # 读不到健康色 ≠ 一定红
    assert items["redis"]["state"] == "down"
    assert items["agent"]["state"] == "unknown"  # 没有 Redis 就读不到推送状态
    assert items["zeek"]["state"] == "ok"  # 新鲜度是另一次 ES 往返，不受影响


def test_endpoint_caches_for_ttl(hc: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def counted() -> dict[str, Any]:
        calls["n"] += 1
        return {"checked_at": "x", "items": [], "notes": [], "cached": False}

    monkeypatch.setattr(hc, "_collect", counted)
    first = hc.health_components(_=None)
    second = hc.health_components(_=None)
    assert first["cached"] is False
    assert second["cached"] is True
    assert calls["n"] == 1


def test_endpoint_cache_disabled_when_ttl_zero(
    hc: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"n": 0}

    def counted() -> dict[str, Any]:
        calls["n"] += 1
        return {"checked_at": "x", "items": [], "notes": [], "cached": False}

    monkeypatch.setattr(hc, "_collect", counted)
    monkeypatch.setattr(hc.settings, "status_probe_cache_seconds", 0, raising=False)
    hc.health_components(_=None)
    hc.health_components(_=None)
    assert calls["n"] == 2
