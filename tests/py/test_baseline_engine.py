"""基线引擎的心跳计数与清理接线（``ndr/backend/app/baseline/engine.py``）。

只跑 NDR 栈。要钉住 2026-10 实机 QA 的两件事：

- 心跳里混了两种语义的量：``observed`` / ``numeric_samples`` / ``flushes`` /
  ``profiles_*`` 是**累计**，而原来的 ``anomalies`` / ``numeric_keys`` 其实是
  **上一轮的值**（覆盖写）。实机就出现「心跳 anomalies=0，而库里有 54 条风险>0 的画像」——
  读的人会当成「没有异常」。现在名字里必须带 ``last_round``，累计量另给名字。
- 数值基线的保留期清理必须真的挂在 ``flush()`` 的清理段上（画像清理一直都在，
  数值基线以前一行清理逻辑都没有）。
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import Any

import pytest


@pytest.fixture(scope="module")
def engine_mod(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("基线引擎只在 NDR 侧")
    return importlib.import_module("app.baseline.engine")


class _FakeRedis:
    def __init__(self) -> None:
        self.hashes: dict[str, dict[str, Any]] = {}
        self.expires: list[tuple[str, int]] = []
        self.deleted: list[tuple[str, ...]] = []

    def hset(self, key: str, mapping: dict[str, Any] | None = None, **_kw: Any) -> int:
        self.hashes[key] = dict(mapping or {})
        return 1

    def expire(self, key: str, seconds: int) -> bool:
        self.expires.append((key, seconds))
        return True

    def hdel(self, key: str, *fields: str) -> int:
        self.deleted.append((key, *fields))
        return len(fields)


def test_heartbeat_separates_last_round_from_totals(engine_mod: ModuleType) -> None:
    client = _FakeRedis()
    engine = engine_mod.BaselineEngine(client)
    engine._remember_anomalies(
        [{"kind": "session", "key": "a", "risk": 0.8}, {"kind": "account", "key": "b", "risk": 0.7}]
    )
    engine._remember_anomalies([{"kind": "session", "key": "a", "risk": 0.9}])
    engine._publish()

    mapping = next(iter(client.hashes.values()))
    # 「上一轮」语义：最后一轮只有 1 个异常
    assert mapping["anomalies_last_round"] == 1
    # 累计语义：两轮加起来 3 个异常、其中 2 轮有异常
    assert mapping["anomalies_total"] == 3
    assert mapping["anomaly_rounds"] == 2
    # 旧的歧义字段不能再发布（名字本身就是防误读的手段）
    assert "anomalies" not in mapping
    assert "numeric_keys" not in mapping
    assert client.expires  # 心跳要有 TTL，进程没了不留僵尸值


def test_heartbeat_deletes_legacy_field_names(engine_mod: ModuleType) -> None:
    """改名前的 `anomalies` / `numeric_keys` 必须从哈希里删掉。

    哈希只增不删（TTL 24h）：不删就新旧并存，读的人又可能拿到那个被当成累计值的 `anomalies`。
    """
    client = _FakeRedis()
    engine = engine_mod.BaselineEngine(client)
    engine._publish()
    assert client.deleted == [(engine_mod.settings.baseline_stats_key, "anomalies", "numeric_keys")]


def test_route_hides_legacy_fields(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """接口侧再拦一道：就算 Redis 里残留旧字段（老进程写的），也不能回给前端。"""
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("基线路由只在 NDR 侧")
    import importlib

    route = importlib.import_module("app.api.routes.baseline")
    redis_mod = importlib.import_module("redis")

    class _Client:
        def hgetall(self, _key: str) -> dict[str, str]:
            return {
                "observed": "894",
                "anomalies": "0",  # 旧字段：实际是「上一轮」，不是累计
                "numeric_keys": "102",
                "anomalies_last_round": "2",
                "anomalies_total": "37",
            }

    monkeypatch.setattr(redis_mod.Redis, "from_url", lambda *_a, **_k: _Client())
    out = route._detector_counters()
    assert "anomalies" not in out and "numeric_keys" not in out
    assert out["anomalies_last_round"] == 2
    assert out["anomalies_total"] == 37
    assert out["observed"] == 894


def test_numeric_keys_last_round_is_overwritten(engine_mod: ModuleType) -> None:
    """`_flush_stats` 里那个键数也是「上一轮」——名字必须一致，别混进累计量。"""
    client = _FakeRedis()
    engine = engine_mod.BaselineEngine(client)
    engine.stats["numeric_keys_last_round"] = 42
    engine._publish()
    assert next(iter(client.hashes.values()))["numeric_keys_last_round"] == 42


def test_flush_runs_numeric_baseline_cleanup(
    engine_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """flush 的清理段必须同时清数值基线（不依赖 profile_enabled）。"""
    calls: list[str] = []
    monkeypatch.setattr(engine_mod, "stats_cleanup", lambda: calls.append("stats") or {"deleted": 3})
    monkeypatch.setattr(engine_mod.profiles, "cleanup", lambda: calls.append("profiles") or {"deleted": 0})

    engine = engine_mod.BaselineEngine(_FakeRedis())
    engine._last_cleanup = -1e9  # 一定过期 → 本轮必须触发清理
    engine.flush()
    assert "stats" in calls and "profiles" in calls


def test_flush_skips_cleanup_before_interval(
    engine_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(engine_mod, "stats_cleanup", lambda: calls.append("stats") or {"deleted": 0})
    monkeypatch.setattr(engine_mod.profiles, "cleanup", lambda: calls.append("profiles") or {"deleted": 0})

    engine = engine_mod.BaselineEngine(_FakeRedis())
    engine.flush()  # _last_flush/_last_cleanup 都是 0 → 会跑一次
    calls.clear()
    engine.flush()  # 立刻再来一次：间隔没到，不该再清
    assert calls == []
