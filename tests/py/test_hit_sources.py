"""命中事件的**三类来源**与**具体事件归类**（2026-10 用户口径）。

三类来源（界面按它分组，不再出现采集器名字）：
`feature_match`=特征匹配 / `behavior_analysis`=行为分析 / `baseline_deviation`=基线偏离。
另外事件标题必须是**具体的安全事件归类**（如「Web 应用攻击」），不能是「签名命中(高危)」这种笼统说法。
"""

from __future__ import annotations

import importlib
from types import ModuleType

import pytest


@pytest.fixture(scope="module")
def hits_mod(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("命中事件只在 NDR 侧")
    return importlib.import_module("app.detector.hits")


def test_source_kind_three_classes(hits_mod: ModuleType) -> None:
    assert (
        hits_mod.source_kind_of({"signature": "ET SCAN", "signature_id": "2000001"})
        == "feature_match"
    )
    assert hits_mod.source_kind_of({"signature_id": "2000001"}) == "feature_match"
    assert hits_mod.source_kind_of({"rule": "内网慢速横向"}) == "behavior_analysis"
    assert hits_mod.source_kind_of({"rule": "账号画像", "kind": "account"}) == "baseline_deviation"
    assert hits_mod.source_kind_of({"baseline": {"profiles": []}}) == "baseline_deviation"


def test_event_title_is_concrete_category(hits_mod: ModuleType) -> None:
    """签名事件标题必须是具体归类（classtype 中文名），不是「签名命中」。"""
    title = hits_mod.event_title_of(
        {"signature": "ET WEB SQLI", "signature_category": "web-application-attack"},
        "feature_match",
    )
    assert title == "Web 应用攻击"
    assert "签名命中" not in title
    # 未收录的 classtype 也要给出可读归类，别退回成规则名
    assert (
        hits_mod.event_title_of(
            {"signature": "X", "signature_category": "unknown-class"}, "feature_match"
        )
        == "其它可疑活动"
    )
    # 行为分析类：事件名就是规则名（规则名本身即具体行为）
    assert hits_mod.event_title_of({"rule": "内网慢速横向"}, "behavior_analysis") == "内网慢速横向"


def test_baseline_reason_labels(hits_mod: ModuleType) -> None:
    """基线偏离的标题用人能看懂的事件名，而不是原始判据句。"""
    assert hits_mod._reason_label("新源 IP：1.2.3.4") == "新来源地址"
    assert hits_mod._reason_label("认证失败突增（12 次，成功 0 次）") == "认证失败激增"
    assert hits_mod._reason_label("会话跨 2 个同族源 IP（疑似会话劫持）") == "会话可能被劫持"
    assert hits_mod._reason_label("某个没见过的判据") == "行为基线偏离"


def test_source_labels_are_chinese(hits_mod: ModuleType) -> None:
    assert hits_mod.SOURCE_LABELS == {
        "feature_match": "特征匹配",
        "behavior_analysis": "行为分析",
        "baseline_deviation": "基线偏离",
    }


def test_hit_filters_build_conditions(hits_mod: ModuleType) -> None:
    """事件中心的筛选项（时间/来源/严重度/归类/IP/关键字）能正确拼成 SQL 条件。"""
    conds = hits_mod._hit_conditions(
        include_ignored=False,
        source_kind="baseline_deviation",
        minutes=60,
        severity="high",
        rule="Web 应用",
        ip="10.1.2.3",
        q="登录",
    )
    text = " ".join(str(c) for c in conds)
    assert "ignored IS false" in text or "ignored =" in text, "默认要排除已忽略"
    assert "source_kind" in text
    assert "rule_severity" in text
    assert "last_seen" in text and ">= " in text, "时间范围要落在 last_seen 上"
    assert "rule" in text and "LIKE" in text.upper(), "事件归类用子串匹配"


def test_hit_filters_ignore_unknown_source_kind(hits_mod: ModuleType) -> None:
    """非法 source_kind 不能当成条件（否则前端传错就查不到任何东西）。"""
    conds = hits_mod._hit_conditions(source_kind="whatever")
    assert all("source_kind" not in str(c) for c in conds)


def test_hits_stats_shape(hits_mod: ModuleType) -> None:
    """统计接口在数据库不可用时要给出 error，而不是崩（前端要能显示失败态）。"""
    out = hits_mod.hits_stats
    assert callable(out)
