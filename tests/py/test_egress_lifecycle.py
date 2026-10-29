"""外连基线生命周期（D5，2026-10-29 架构整改）。

旧问题：
- 自动白名单默认开（7 天/20 次就放行），首次任务漏掉后目标会静默消失；
- `egress_new` 强度固定，常见站点和孤僻目标同权；
- `egress_rare` 强度 0.35 低于 0.45 派工门槛，实际永远不派工，也不说清；
- `MAX_PER_WINDOW` 截断静默、不排序。

整改：自动白名单默认关 + 护栏；新增 `egress_sustained` 持续跟踪；全舰队稀有度；
截断可见（egress_capped）并按稀有度优先。
"""

from __future__ import annotations

import importlib
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, Self

import pytest

NETS = ("10.1.1.0/24",)
OUR_HOST = "10.1.1.10"
NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


class FakeResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return list(self._rows)

    def first(self) -> Any:
        return self._rows[0] if self._rows else None

    def scalar(self) -> Any:
        return self._rows[0] if self._rows else None

    def __iter__(self) -> Any:
        return iter(self._rows)


class FakeDB:
    """只模拟 observe_window 用得到的那几段查询。"""

    def __init__(self, *, baseline_rows: list[Any] | None = None, fleet: list[Any] | None = None) -> None:
        self.baseline_rows = list(baseline_rows or [])
        self.fleet = list(fleet or [])
        self.added: list[Any] = []
        self.committed = False

    def scalars(self, stmt: Any) -> FakeResult:
        text = str(stmt)
        if "egress_allow" in text.lower():
            return FakeResult([])
        return FakeResult(self.baseline_rows)

    def execute(self, stmt: Any) -> FakeResult:
        text = str(stmt)
        if "count" in text.lower() and "group by" in text.lower():
            return FakeResult(self.fleet)
        # 墓碑 / 已存在白名单 检查：一律查不到
        return FakeResult([])

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    def commit(self) -> None:
        self.committed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False


@pytest.fixture()
def egress(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> Any:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("外连基线只在 NDR 侧")
    iputil = importlib.import_module("app.iputil")
    monkeypatch.setattr(iputil, "_net_texts", lambda: NETS)
    for attr in ("_cache_at", "_nets_at"):
        monkeypatch.setattr(iputil, attr, 0.0, raising=False)
    mod = importlib.import_module("app.baseline.egress")
    mod.invalidate_allow_cache()
    params = importlib.import_module("app.baseline.params")
    monkeypatch.setattr(params, "egress_enabled", lambda: True)
    monkeypatch.setattr(params, "egress_rare_min", lambda: 3)
    monkeypatch.setattr(params, "egress_learn_days", lambda: 7)
    monkeypatch.setattr(params, "egress_learn_occurrences", lambda: 20)
    monkeypatch.setattr(params, "egress_auto_allow", lambda: False)
    monkeypatch.setattr(params, "egress_sustained_minutes", lambda: 60)
    return mod


def _sample(dst: str = "8.8.8.8", domain: str = "", port: str = "") -> dict[str, Any]:
    return {
        "src_ip": OUR_HOST,
        "egress_dsts": [dst] if dst else [],
        "egress_domains": [domain] if domain else [],
        "egress_ports": [port] if port else [],
    }


def _row(kind: str = "dst_ip", value: str = "8.8.8.8", count: int = 1, age_days: int = 0) -> Any:
    return SimpleNamespace(
        src_ip=OUR_HOST,
        kind=kind,
        value=value,
        count=count,
        first_seen=NOW - timedelta(days=age_days),
        last_seen=NOW,
    )


def _capture_emit(monkeypatch: pytest.MonkeyPatch, egress: Any) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def fake_emit(kind: str, subject_kind: str, subject: str, facts: dict[str, Any], **kw: Any) -> bool:
        calls.append({"kind": kind, "subject": subject, "facts": facts, **kw})
        return True

    monkeypatch.setattr(egress.observations, "emit", fake_emit)
    return calls


def test_auto_allow_default_off(egress: Any) -> None:
    """默认不自动放行：7 天 20 次的老目标也不进白名单（只能人工加）。"""
    params = importlib.import_module("app.baseline.params")
    settings = importlib.import_module("app.config").settings
    assert settings.egress_auto_allow is False
    assert params._BY_KEY["egress.auto_allow"].default is False


def test_learning_skipped_when_switch_off(
    egress: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = FakeDB(baseline_rows=[_row(count=50, age_days=30)])
    monkeypatch.setattr(egress, "SessionLocal", lambda: db)
    _capture_emit(monkeypatch, egress)
    counts = egress.observe_window([_sample()], now=NOW)
    assert counts["learned"] == 0
    assert not [o for o in db.added if o.__class__.__name__ == "EgressAllow"]


def test_learning_with_switch_on_and_no_guardrail(
    egress: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    params = importlib.import_module("app.baseline.params")
    monkeypatch.setattr(params, "egress_auto_allow", lambda: True)
    monkeypatch.setattr(egress, "_learning_blocked", lambda *a, **k: False)
    db = FakeDB(baseline_rows=[_row(count=50, age_days=30)])
    monkeypatch.setattr(egress, "SessionLocal", lambda: db)
    _capture_emit(monkeypatch, egress)
    counts = egress.observe_window([_sample()], now=NOW)
    assert counts["learned"] == 1
    allow = [o for o in db.added if o.__class__.__name__ == "EgressAllow"]
    assert allow and allow[0].source == "learned"


def test_learning_guardrail_blocks_true_positive_target(
    egress: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """有真阳性/可疑结论、或被待办任务跟踪的目标绝不自动放行。"""
    params = importlib.import_module("app.baseline.params")
    monkeypatch.setattr(params, "egress_auto_allow", lambda: True)
    monkeypatch.setattr(egress, "_learning_blocked", lambda *a, **k: True)
    db = FakeDB(baseline_rows=[_row(count=50, age_days=30)])
    monkeypatch.setattr(egress, "SessionLocal", lambda: db)
    _capture_emit(monkeypatch, egress)
    counts = egress.observe_window([_sample()], now=NOW)
    assert counts["learned"] == 0


def test_sustained_fact_after_rare_threshold(
    egress: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """目的地在罕见期之后继续可见（egress_sustained，强度 ≥0.45），不再静默。"""
    db = FakeDB(baseline_rows=[_row(count=5)])
    monkeypatch.setattr(egress, "SessionLocal", lambda: db)
    calls = _capture_emit(monkeypatch, egress)
    counts = egress.observe_window([_sample()], now=NOW)
    assert counts["sustained"] == 1
    sustained = [c for c in calls if c["kind"] == "egress_sustained"]
    assert sustained, calls
    assert sustained[0]["strength"] >= 0.45
    assert sustained[0]["cooldown_minutes"] == 60


def test_fleet_rarity_adjusts_new_strength(
    egress: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """只有 1 台资产连过 → 0.7；几十台都连的常见站点 → 0.35（低价值事实）。"""
    # 稀有目标
    db = FakeDB(fleet=[("dst_ip", "8.8.8.8", 1)])
    monkeypatch.setattr(egress, "SessionLocal", lambda: db)
    calls = _capture_emit(monkeypatch, egress)
    egress.observe_window([_sample(dst="8.8.8.8")], now=NOW)
    new = [c for c in calls if c["kind"] == "egress_new"]
    assert new and new[0]["strength"] == 0.7
    assert new[0]["facts"]["全舰队访问资产数"] == 1

    # 常见站点
    db2 = FakeDB(fleet=[("dst_ip", "8.8.8.8", 50)])
    monkeypatch.setattr(egress, "SessionLocal", lambda: db2)
    calls2 = _capture_emit(monkeypatch, egress)
    egress.observe_window([_sample(dst="8.8.8.8")], now=NOW)
    new2 = [c for c in calls2 if c["kind"] == "egress_new"]
    assert new2 and new2[0]["strength"] == 0.35


def test_truncation_is_visible_and_rarest_first(
    egress: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """超上限时先按全舰队稀有度排序，并如实计数（不静默丢）。"""
    monkeypatch.setattr(egress, "MAX_PER_WINDOW", 2)
    fleet = [
        ("dst_ip", "1.1.1.2", 1),   # 最稀有 → 必留
        ("dst_ip", "1.1.1.1", 30),  # 常见 → 被截
        ("dst_ip", "9.9.9.9", 2),   # 次稀有 → 留
    ]
    db = FakeDB(fleet=fleet)
    monkeypatch.setattr(egress, "SessionLocal", lambda: db)
    calls = _capture_emit(monkeypatch, egress)
    counts = egress.observe_window(
        [
            _sample(dst="1.1.1.1"),
            _sample(dst="1.1.1.2"),
            _sample(dst="9.9.9.9"),
        ],
        now=NOW,
    )
    assert counts["capped"] == 1
    kept = {c["facts"]["目标"] for c in calls if c["kind"] == "egress_new"}
    assert kept == {"1.1.1.2", "9.9.9.9"}
