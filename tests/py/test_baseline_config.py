"""基线/画像的**可调参数**：白名单、校验、落库与生效路径。

只跑 NDR 栈。这层是 2026-10 新加的（后台「行为分析」页要能在界面上改观测期、σ、阈值、门槛、
路径正则这些调参项，而不是改 `.env` 重启），所以钉住三件事：

1. **只有白名单里的键能被改**（前端传来的 values 里出现别的键 → 400，绝不写库）；
2. **校验要拦得住**：越界、非数字、写坏的正则、以及「保留期 ≤ 观测期」这种跨字段约束；
3. **读侧要夹紧**：库里存了脏值（越界/非数字）也不能把运行时搞坏 —— 存取器回落并夹到范围内。
"""

from __future__ import annotations

import importlib
import json
from types import ModuleType, SimpleNamespace
from typing import Any, Self

import pytest


@pytest.fixture(scope="module")
def params_mod(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("基线/画像只在 NDR 侧")
    return importlib.import_module("app.baseline.params")


@pytest.fixture(scope="module")
def baseline_route(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("基线路由只在 NDR 侧")
    return importlib.import_module("app.api.routes.baseline")


# ---------- 参数定义（单一定义源） ----------


def test_knobs_are_unique_and_well_formed(params_mod: ModuleType) -> None:
    keys = [k.key for k in params_mod.KNOBS]
    assert len(keys) == len(set(keys)), "参数键重复了"
    assert tuple(keys) == params_mod.EDITABLE_KEYS
    for knob in params_mod.KNOBS:
        assert knob.kind in ("int", "float", "bool", "regex", "text"), knob.key
        assert knob.label and knob.note, f"{knob.key} 少了标签或说明"
        if knob.kind in ("int", "float"):
            assert knob.low is not None and knob.high is not None, f"{knob.key} 没给范围"


def test_items_expose_default_and_current(params_mod: ModuleType) -> None:
    row = next(i for i in params_mod.items() if i["key"] == "profile.risk_threshold")
    assert row["kind"] == "float"
    assert row["default"] == params_mod.effective()["profile.risk_threshold"]
    assert row["overridden"] is False  # 测试环境里没人改过
    assert row["low"] == 0.0 and row["high"] == 1.0


# ---------- 校验 ----------


def test_validate_rejects_unknown_key(params_mod: ModuleType) -> None:
    errs = params_mod.validate({"baseline.nope": 1})
    assert errs and errs[0]["field"] == "baseline.nope"


def test_validate_rejects_out_of_range_and_wrong_type(params_mod: ModuleType) -> None:
    fields = {e["field"] for e in params_mod.validate({"profile.risk_threshold": 5})}
    assert "profile.risk_threshold" in fields
    fields = {e["field"] for e in params_mod.validate({"baseline.observe_days": "abc"})}
    assert "baseline.observe_days" in fields
    # int 参数给小数也要拦（不能静默取整）
    fields = {e["field"] for e in params_mod.validate({"baseline.observe_days": 1.5})}
    assert "baseline.observe_days" in fields


def test_validate_rejects_broken_regex(params_mod: ModuleType) -> None:
    errs = params_mod.validate({"profile.path_include_regex": "(["})
    assert errs and errs[0]["field"] == "profile.path_include_regex"


def test_validate_allows_empty_regex(params_mod: ModuleType) -> None:
    """空正则 = 那一步不过滤，是合法值（默认 include 就是空）。"""
    assert params_mod.validate({"profile.path_include_regex": ""}) == []


def test_validate_cross_field_retention_gt_observe(params_mod: ModuleType) -> None:
    """保留期必须大于观测期，否则维度还没判过就被清掉。"""
    errs = params_mod.validate({"baseline.retention_days": 7, "baseline.observe_days": 7})
    assert errs and errs[0]["field"] == "baseline.retention_days"
    assert params_mod.validate({"baseline.retention_days": 30, "baseline.observe_days": 7}) == []


def test_validate_accepts_good_values(params_mod: ModuleType) -> None:
    assert (
        params_mod.validate(
            {
                "baseline.observe_days": 14,
                "profile.risk_threshold": 0.7,
                "profile.path_include_regex": "(?i)/api/",
                "profile.enabled": False,
            }
        )
        == []
    )


# ---------- 读侧：脏值要夹紧 ----------


def test_accessors_clamp_dirty_stored_values(
    params_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """库里被手改成越界/非数字时，存取器不能把运行时带坏。"""
    monkeypatch.setattr(
        params_mod,
        "get",
        lambda key, default: {
            "profile.risk_threshold": "999",  # 越界 → 夹到 1.0
            "baseline.observe_days": "abc",  # 非数字 → 回落默认
            "profile.enabled": "no",  # bool 字符串
        }.get(key, default),
    )
    assert params_mod.risk_threshold() == 1.0
    assert params_mod.observe_days() == params_mod._BY_KEY["baseline.observe_days"].default
    assert params_mod.profile_enabled() is False


# ---------- 写侧：白名单 + 落库 ----------


class _FakeSession:
    """够 `params.save/reset` 用：get/add/delete/commit。"""

    def __init__(self) -> None:
        self.rows: dict[str, Any] = {}
        self.deleted: list[str] = []
        self.commits = 0

    def get(self, _model: Any, key: str) -> Any:
        return self.rows.get(key)

    def add(self, row: Any) -> None:
        self.rows[row.key] = row

    def delete(self, row: Any) -> None:
        self.deleted.append(row.key)
        self.rows.pop(row.key, None)

    def commit(self) -> None:
        self.commits += 1

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool:
        return False


def test_save_writes_only_whitelisted_keys(
    params_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    invalidated: list[str] = []
    monkeypatch.setattr(params_mod, "invalidate", lambda: invalidated.append("x"))
    session = _FakeSession()
    written = params_mod.save(
        session,  # type: ignore[arg-type]
        {"profile.risk_threshold": "0.75", "baseline.observe_days": 14, "evil.key": 1},
    )
    assert written == 2  # 白名单外的键被丢掉
    assert set(session.rows) == {"profile.risk_threshold", "baseline.observe_days"}
    assert session.rows["profile.risk_threshold"].value == {"value": 0.75}
    assert session.rows["baseline.observe_days"].value == {"value": 14}
    assert session.commits == 1
    assert invalidated == ["x"]  # 缓存必须失效，否则改了不生效


def test_save_coerces_bool_from_string(
    params_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(params_mod, "invalidate", lambda: None)
    session = _FakeSession()
    params_mod.save(session, {"profile.enabled": "false"})  # type: ignore[arg-type]
    assert session.rows["profile.enabled"].value == {"value": False}


def test_reset_only_removes_whitelisted(
    params_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(params_mod, "invalidate", lambda: None)
    session = _FakeSession()
    session.rows["profile.risk_threshold"] = SimpleNamespace(key="profile.risk_threshold")
    session.rows["other.key"] = SimpleNamespace(key="other.key")
    removed = params_mod.reset(session, ["profile.risk_threshold", "other.key"])  # type: ignore[arg-type]
    assert removed == 1
    assert session.deleted == ["profile.risk_threshold"]
    assert "other.key" in session.rows


# ---------- 端点接线 ----------


def test_get_config_lists_knobs(baseline_route: ModuleType) -> None:
    out = baseline_route.baseline_config(_=None)
    assert out["items"] and out["effective"]
    assert any(i["key"] == "profile.risk_threshold" for i in out["items"])


def test_put_config_returns_400_with_field_errors(baseline_route: ModuleType) -> None:
    resp = baseline_route.save_baseline_config(
        baseline_route.ConfigIn(values={"profile.risk_threshold": 9}), db=object(), _=None
    )
    assert resp.status_code == 400
    body = json.loads(bytes(resp.body).decode())
    assert body["conflict"] == "field_error"
    assert body["field_errors"][0]["field"] == "profile.risk_threshold"


def test_put_config_rejects_empty_body(baseline_route: ModuleType) -> None:
    resp = baseline_route.save_baseline_config(
        baseline_route.ConfigIn(values={}), db=object(), _=None
    )
    assert resp.status_code == 400


def test_put_config_saves_and_returns_items(
    baseline_route: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def fake_save(_db: Any, values: dict[str, Any]) -> int:
        seen.update(values)
        return len(values)

    monkeypatch.setattr(baseline_route.params, "save", fake_save)
    out = baseline_route.save_baseline_config(
        baseline_route.ConfigIn(values={"baseline.observe_days": 14}), db=object(), _=None
    )
    assert seen == {"baseline.observe_days": 14}
    assert out["written"] == 1
    assert any(i["key"] == "baseline.observe_days" for i in out["items"])


def test_numeric_route_passes_filters(
    baseline_route: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def fake_list(**kw: Any) -> dict[str, Any]:
        seen.update(kw)
        return {"total": 0, "returned": 0, "observe_days": 7, "items": []}

    monkeypatch.setattr(baseline_route.stats_mod, "list_stats", fake_list)
    baseline_route.baseline_numeric(
        _=None, q="10.0.0", feature="conn_count", sort="count", limit=5, offset=10
    )
    assert seen == {
        "q": "10.0.0",
        "feature": "conn_count",
        # 2026-10：新增 scope（默认 entity，排除 grp: 组先验行）
        "scope": "entity",
        "sort": "count",
        "limit": 5,
        "offset": 10,
        "group": "key",  # 默认一行一个 key；页面传 group=ip 时一行一个 IP
    }
    # 页面用的分组模式要能透传下去（分组时**分页按 IP 走**，后端实现）
    seen.clear()
    baseline_route.baseline_numeric(_=None, group="ip", limit=5, offset=0)
    assert seen["group"] == "ip"


def test_profiles_route_passes_search(
    baseline_route: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def fake_list(**kw: Any) -> dict[str, Any]:
        seen.update(kw)
        return {"total": 0, "items": []}

    monkeypatch.setattr(baseline_route.profiles, "list_profiles", fake_list)
    baseline_route.baseline_profiles(
        _=None, kind="account", q="zhang", min_risk=0.3, limit=10, offset=0
    )
    assert seen["kind"] == "account"
    assert seen["q"] == "zhang"
    assert seen["min_risk"] == pytest.approx(0.3)
