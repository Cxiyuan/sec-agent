"""画像异常进入 observation（D4，2026-10-29 架构整改）。

旧问题：新源 IP / 新 UA / 新接口路径 / 非常用时段这些画像异常只写 `entity_profiles`
和摘要标签 —— agent 不领摘要就完全看不到，等于没发现。

整改：`engine._emit_profile_anomalies` 把过阈值异常发成 `profile_anomaly` 事实：
- 带监控网段内来源 → 资产主体事实；纯外部来源 → 账号/会话主体；
- 与 login_bruteforce/geo_jump 去重；
- 强度 = 画像风险分（客观分，不是严重度）；
- 开关 `baseline.profile_anomaly_enabled`（默认开，关掉即回滚）。
"""

from __future__ import annotations

import importlib
from typing import Any

import pytest


@pytest.fixture()
def engine(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> Any:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("画像异常只在 NDR 侧")
    iputil = importlib.import_module("app.iputil")
    monkeypatch.setattr(iputil, "_net_texts", lambda: ("10.1.1.0/24",))
    for attr in ("_cache_at", "_nets_at"):
        monkeypatch.setattr(iputil, attr, 0.0, raising=False)
    mod = importlib.import_module("app.baseline.engine")
    params = importlib.import_module("app.baseline.params")
    monkeypatch.setattr(params, "profile_anomaly_enabled", lambda: True)
    monkeypatch.setattr(mod.observations, "has_recent", lambda *_a, **_k: False)
    return mod


def _capture(monkeypatch: pytest.MonkeyPatch, engine: Any) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def fake_emit(kind: str, subject_kind: str, subject: str, facts: dict[str, Any], **kw: Any) -> bool:
        calls.append(
            {"kind": kind, "subject_kind": subject_kind, "subject": subject, "facts": facts, **kw}
        )
        return True

    monkeypatch.setattr(engine.observations, "emit", fake_emit)
    return calls


def _anomaly(**over: Any) -> dict[str, Any]:
    base = {
        "kind": "account",
        "key": "alice",
        "display": "alice@corp",
        "risk": 0.86,
        "reasons": ["新源 IP：1.1.1.1（占本窗口来源地址 80%）", "新 User-Agent：curl/8"],
        "obs_count": 30,
        "src_ips": ["1.1.1.1"],
        "dst_ips": [],
        "count": 40,
    }
    base.update(over)
    return base


def _fake_self() -> Any:
    from types import SimpleNamespace

    return SimpleNamespace(stats={})


def test_internal_source_emits_asset_fact(engine: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _capture(monkeypatch, engine)
    engine.BaselineEngine._emit_profile_anomalies(
        _fake_self(), [_anomaly(src_ips=["10.1.1.20", "1.1.1.1"])]
    )
    assert len(calls) == 1
    row = calls[0]
    assert row["kind"] == "profile_anomaly"
    assert row["subject_kind"] == "asset"
    assert row["subject"] == "10.1.1.20"
    assert row["strength"] == 0.86
    assert row["facts"]["风险分"] == 0.86
    assert row["facts"]["判定理由"][0].startswith("新源 IP")
    assert row["facts"]["来源地址"] == ["10.1.1.20", "1.1.1.1"]
    assert row["key"].startswith("profile_anomaly:")


def test_external_only_source_keeps_account_subject(
    engine: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _capture(monkeypatch, engine)
    engine.BaselineEngine._emit_profile_anomalies(_fake_self(), [_anomaly(src_ips=["1.1.1.1"])])
    assert calls[0]["subject_kind"] == "account"
    assert calls[0]["subject"] == "alice@corp"


def test_dedup_with_login_facts(engine: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """同一对象已有爆破/异地事实 → 不重复发（避免一条账号异常三个事实）。"""
    monkeypatch.setattr(engine.observations, "has_recent", lambda *_a, **_k: True)
    calls = _capture(monkeypatch, engine)
    engine.BaselineEngine._emit_profile_anomalies(_fake_self(), [_anomaly()])
    assert calls == []


def test_switch_off_means_no_fact(engine: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    params = importlib.import_module("app.baseline.params")
    monkeypatch.setattr(params, "profile_anomaly_enabled", lambda: False)
    calls = _capture(monkeypatch, engine)
    engine.BaselineEngine._emit_profile_anomalies(_fake_self(), [_anomaly()])
    assert calls == []


def test_empty_reasons_skipped(engine: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _capture(monkeypatch, engine)
    engine.BaselineEngine._emit_profile_anomalies(
        _fake_self(), [_anomaly(reasons=[])]
    )
    assert calls == []


def test_knob_defaults_on() -> None:
    params = importlib.import_module("app.baseline.params")
    settings = importlib.import_module("app.config").settings
    assert settings.baseline_profile_anomaly_enabled is True
    assert params._BY_KEY["baseline.profile_anomaly_enabled"].default is True
    obs = importlib.import_module("app.baseline.observations")
    assert obs.KIND_LABELS["profile_anomaly"]
