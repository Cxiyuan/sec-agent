"""资产侧（被访问方）基线判异 + asset_shift 事实（D3，2026-10-29 架构整改）。

现状问题：`asset.apply_window` 只学不判 —— 内网站点「平时 5 个客户端、今天 200 个」
在库里只是均值，没有任何事实进入智能体视野。整改后：
- `judge_window` 用**旧**基线判本窗口（先判后学），只对监控网段内资产生效；
- 偏离发成 `asset_shift` 事实（客观量 + p 值，不含结论）；
- 默认开关关着（`baseline.asset_shift_enabled=false`），观察一周假阳率再开；
- `asset_baseline` 只读工具让 agent 能看到均值/方差/样本数/是否预热。
"""

from __future__ import annotations

import importlib
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, Self

import pytest

NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


@pytest.fixture()
def asset(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> Any:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("资产基线只在 NDR 侧")
    mod = importlib.import_module("app.baseline.asset")
    mod._dev_budget.clear()
    monkeypatch.setattr(mod, "_dev_budget", mod._dev_budget)
    params = importlib.import_module("app.baseline.params")
    monkeypatch.setattr(params, "baseline_enabled", lambda: True)
    monkeypatch.setattr(params, "asset_shift_enabled", lambda: True)
    monkeypatch.setattr(params, "alpha", lambda: 1e-3)
    monkeypatch.setattr(params, "asset_deviation_cap_per_entity_hour", lambda: 3)
    return mod


def _bucket(
    *,
    scope: str = "internal",
    visits: int = 8,
    requests: int = 10,
    clients: int = 1,
    ports: int = 1,
    targets: int = 1,
) -> dict[str, Any]:
    return {
        "scope": scope,
        "visits": visits,
        "requests": requests,
        "clients": {f"198.51.100.{i}" for i in range(clients)},
        "client_ports": {str(40000 + i) for i in range(ports)},
        "targets": {f"t{i}" for i in range(targets)},
    }


def _stats(mean: float, std: float, count: int = 100, warmed: bool = True) -> dict[str, Any]:
    return {"count": count, "mean": mean, "std": std, "warmed": warmed, "first_seen": ""}


def test_client_burst_becomes_asset_shift(asset: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """验收：内网站点 distinct_clients 从平时 5 涨到 200 → 产生 asset_shift。"""
    monkeypatch.setattr(
        asset.stats_mod,
        "load_stats",
        lambda keys, **_kw: {
            "www.example.com:distinct_clients": _stats(5.0, 2.0),
            "www.example.com:visits": _stats(5.0, 2.0),
        },
    )
    items = asset.judge_window({"www.example.com": _bucket(clients=200, visits=8)}, NOW)
    features = {i["feature"] for i in items}
    assert "distinct_clients" in features
    item = next(i for i in items if i["feature"] == "distinct_clients")
    assert item["asset"] == "www.example.com"
    assert item["value"] == 200
    assert item["mean"] == 5.0
    assert item["p"] < 1e-3
    assert item["clients"] == 200


def test_external_scope_never_judged(asset: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """验收：外部目标（scope=external）不产生该事实。"""
    monkeypatch.setattr(
        asset.stats_mod,
        "load_stats",
        lambda keys, **_kw: {"8.8.8.8:distinct_clients": _stats(5.0, 2.0)},
    )
    items = asset.judge_window({"8.8.8.8": _bucket(scope="external", clients=200)}, NOW)
    assert items == []


def test_warming_baseline_is_not_judged(asset: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """观测期没结束不判：没报偏离 ≠ 正常（与数值基线同一口径）。"""
    monkeypatch.setattr(
        asset.stats_mod,
        "load_stats",
        lambda keys, **_kw: {"www.example.com:distinct_clients": _stats(5.0, 2.0, warmed=False)},
    )
    assert asset.judge_window({"www.example.com": _bucket(clients=200)}, NOW) == []


def test_too_few_samples_not_judged(asset: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """样本 <2 不判（Welford 的方差没有意义）。"""
    monkeypatch.setattr(
        asset.stats_mod,
        "load_stats",
        lambda keys, **_kw: {"www.example.com:distinct_clients": _stats(5.0, 2.0, count=1)},
    )
    assert asset.judge_window({"www.example.com": _bucket(clients=200)}, NOW) == []


def test_downward_change_is_not_a_shift(asset: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """只关心上偏：访问量骤降不是"异常访问"的证据（可能是业务停了）。"""
    monkeypatch.setattr(
        asset.stats_mod,
        "load_stats",
        lambda keys, **_kw: {"www.example.com:visits": _stats(50.0, 5.0)},
    )
    items = asset.judge_window({"www.example.com": _bucket(visits=2)}, NOW)
    assert [i for i in items if i["feature"] == "visits"] == []


def test_per_entity_hour_cap(asset: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """限额：单资产每小时最多报 N 条（统计显著 ≠ 值得人看）。"""
    params = importlib.import_module("app.baseline.params")
    monkeypatch.setattr(params, "asset_deviation_cap_per_entity_hour", lambda: 1)
    monkeypatch.setattr(
        asset.stats_mod,
        "load_stats",
        lambda keys, **_kw: {
            f"www.example.com:{f}": _stats(1.0, 1.0)
            for f in asset.JUDGE_FEATURES
        },
    )
    buckets = {"www.example.com": _bucket(clients=200, visits=200, requests=200, ports=200, targets=200)}
    items = asset.judge_window(buckets, NOW)
    assert len(items) == 1
    # 下一个小时额度重置
    asset._dev_budget.clear()
    assert len(asset.judge_window(buckets, NOW.replace(hour=13))) == 1


def test_switch_off_means_no_judgement(asset: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """回滚开关：baseline.asset_shift_enabled=false → 只看不判（与改造前一致）。"""
    params = importlib.import_module("app.baseline.params")
    monkeypatch.setattr(params, "asset_shift_enabled", lambda: False)
    monkeypatch.setattr(
        asset.stats_mod,
        "load_stats",
        lambda keys, **_kw: {"www.example.com:distinct_clients": _stats(5.0, 2.0)},
    )
    assert asset.judge_window({"www.example.com": _bucket(clients=200)}, NOW) == []


def test_emit_asset_shift_facts_have_no_conclusion(
    asset: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """事实里只有客观量（特征/值/基线/p/客户端数），没有任何"疑似攻击"措辞。"""
    engine = importlib.import_module("app.baseline.engine")
    captured: list[dict[str, Any]] = []

    def fake_emit(kind: str, subject_kind: str, subject: str, facts: dict[str, Any], **kw: Any) -> bool:
        captured.append({"kind": kind, "subject_kind": subject_kind, "subject": subject, "facts": facts, **kw})
        return True

    monkeypatch.setattr(engine.observations, "emit", fake_emit)
    monkeypatch.setattr(engine.params, "alpha", lambda: 1e-3)
    fake_self = SimpleNamespace(stats={})
    engine.BaselineEngine._emit_asset_shift(
        fake_self,
        {
            "asset": "www.example.com",
            "feature": "distinct_clients",
            "value": 200,
            "mean": 5.0,
            "std": 2.0,
            "p": 1e-9,
            "clients": 200,
            "targets": 3,
        },
    )
    assert len(captured) == 1
    row = captured[0]
    assert row["kind"] == "asset_shift"
    assert row["subject_kind"] == "asset"
    assert row["subject"] == "www.example.com"
    assert row["facts"]["本窗口值"] == 200
    assert row["facts"]["基线均值"] == 5.0
    assert row["facts"]["p"] == 1e-9
    assert row["facts"]["涉及客户端数"] == 200
    text = " ".join(str(v) for v in row["facts"].values())
    for banned in ("疑似", "攻击", "恶意", "确认"):
        assert banned not in text, f"事实里不该有结论措辞：{banned}"
    assert row["key"] == "asset_shift:distinct_clients"
    assert 0.5 <= row["strength"] <= 0.7
    assert fake_self.stats.get("asset_shift_reported") == 1


def test_kind_label_and_strength_registered() -> None:
    obs = importlib.import_module("app.baseline.observations")
    assert obs.KIND_LABELS["asset_shift"]
    assert obs.KIND_STRENGTH["asset_shift"] == 0.5


def test_baseline_rows_reads_warming_status(
    asset: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """asset_baseline 工具面：均值/标准差/样本数/预热/归属都要给。"""
    rows = [
        SimpleNamespace(
            key="www.example.com:distinct_clients",
            count=10,
            mean=5.5,
            m2=9.0,
            first_seen=datetime.now(UTC),
            scope="internal",
        )
    ]

    class FakeDB:
        def scalars(self, _stmt: Any) -> Any:
            class R:
                def all(self) -> list[Any]:
                    return rows

            return R()

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_exc: object) -> bool:
            return False

    monkeypatch.setattr(asset, "SessionLocal", lambda: FakeDB())
    out = asset.baseline_rows(asset="example.com")
    assert out["available"] is True
    item = out["items"][0]
    assert item["asset"] == "www.example.com"
    assert item["feature"] == "distinct_clients"
    assert item["mean"] == 5.5
    assert item["count"] == 10
    assert item["warmed"] is False, "刚建的基线还在观测期"
    assert item["scope"] == "internal"


def test_baseline_rows_reports_failure_honestly(
    asset: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """读失败必须如实说，不能返回空表让 agent 当成"没有基线"。"""
    monkeypatch.setattr(asset, "SessionLocal", lambda: (_ for _ in ()).throw(RuntimeError("pg down")))
    out = asset.baseline_rows()
    assert out["available"] is False
    assert "pg down" in str(out["error"])


def test_asset_baseline_tool_registered() -> None:
    tools = importlib.import_module("app.mcp.ndr_tools")
    server = importlib.import_module("app.mcp.server")
    assert "asset_baseline" in tools.TOOLS
    assert "asset_baseline" in server._TOOL_PROFILES["analyst"]
    assert "asset_baseline" in {fn.__name__ for fn in server._NDR_TOOL_FUNCS}
    assert tools.dispatch("asset_baseline", {"feature": "nope"})["error"]
