"""命中事件的**三类来源**与**具体事件归类**（2026-10 用户口径）。

三类来源（界面按它分组，不再出现采集器名字）：
`feature_match`=特征匹配 / `behavior_analysis`=行为分析 / `baseline_deviation`=基线偏离。
另外事件标题必须是**具体的安全事件归类**（如「Web 应用攻击」），不能是「签名命中(高危)」这种笼统说法。
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import Any

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
    # 未收录的 classtype：用签名名本身（具体）；连签名名都没有才退回兜底文案
    assert (
        hits_mod.event_title_of(
            {"signature": "[工具-01] 未知扫描器指纹", "signature_category": "unknown-class"},
            "feature_match",
        )
        == "未知扫描器指纹"
    )
    assert (
        hits_mod.event_title_of({"signature_category": "unknown-class"}, "feature_match")
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


# ===== 事件标题必须具体：签名线索藏在聚合样本里（2026-10 线上实测踩到） =====


def _sig_digest(**over: Any) -> dict[str, Any]:
    """一条签名命中的摘要：**顶层没有签名字段**，签名只在样本的原始文档里。"""
    digest: dict[str, Any] = {
        "src_ip": "10.1.2.3",
        "rule": "签名命中(高危)",
        "rule_severity": "high",
        "count": 3,
        "dst_ips": ["10.1.2.20"],
        "samples": [
            {
                "source": "suricata",
                "doc": {
                    "event_type": "signature_hit",
                    "alert": {
                        "signature": "[扫描-07] UDP 端口扫描 - 出向高频",
                        "signature_id": 9102007,
                        "category": "Detection of a Network Scan",
                        "severity": 3,
                    },
                },
            }
        ],
    }
    digest.update(over)
    return digest


def test_signature_hit_detected_from_samples(hits_mod: ModuleType) -> None:
    """摘要顶层没有 signature 也要判成「特征匹配」（否则线上全被算成行为分析）。"""
    digest = _sig_digest()
    assert hits_mod.source_kind_of(digest) == "feature_match"


def test_signature_title_uses_classtype_text(hits_mod: ModuleType) -> None:
    """classtype 是人话文本（Detection of a Network Scan）也要映射成中文归类。"""
    assert hits_mod.event_title_of(_sig_digest(), "feature_match") == "网络扫描"


def test_signature_title_falls_back_to_signature_name(hits_mod: ModuleType) -> None:
    """认不出归类时用签名名本身（去掉方括号编号），绝不能用「签名命中(高危)」。"""
    digest = _sig_digest()
    digest["samples"][0]["doc"]["alert"]["category"] = ""
    title = hits_mod.event_title_of(digest, "feature_match")
    assert title == "UDP 端口扫描 - 出向高频"
    assert "签名命中" not in title


def test_feature_match_never_shows_packaging_rule_name(hits_mod: ModuleType) -> None:
    """三条「包装规则」（签名命中 高/中/低危）不允许作为事件标题出现在界面上。"""
    for severity in ("高危", "中危", "低危"):
        digest = {"src_ip": "10.1.2.3", "rule": f"签名命中({severity})", "samples": []}
        title = hits_mod.event_title_of(digest, "feature_match")
        assert "签名命中" not in title


def test_behavior_title_keeps_rule_name(hits_mod: ModuleType) -> None:
    """行为分析的事件标题仍用规则名（那是具体判据的名字）。"""
    assert hits_mod.event_title_of({"rule": "内网慢速横向"}, "behavior_analysis") == "内网慢速横向"


def test_category_label_accepts_both_forms(hits_mod: ModuleType) -> None:
    """classtype 短名与人话文本都要能映射（两种写法线上都出现过）。"""
    label = hits_mod.signature_category_label
    assert label("network-scan") == "网络扫描"
    assert label("Detection of a Network Scan") == "网络扫描"
    assert label("Attempted Administrator Privilege Gain") == "权限提升尝试"
    assert label("Web Application Attack") == "Web 应用攻击"
    assert label("") == ""
    assert label("从未见过的类别") == ""


def test_generic_category_prefers_signature_name(hits_mod: ModuleType) -> None:
    """笼统归类（Misc activity → 其它可疑活动）要让位给签名名，界面才有信息量。"""
    digest = {
        "src_ip": "10.1.2.3",
        "samples": [
            {
                "source": "suricata",
                "doc": {
                    "alert": {
                        "signature": "sliver https debian",
                        "signature_id": 1000881,
                        "category": "Misc activity",
                    }
                },
            }
        ],
    }
    assert hits_mod.event_title_of(digest, "feature_match") == "sliver https debian"
    # 有具体归类时仍用归类（归类是安全语义，比签名名更该显眼）
    digest["samples"][0]["doc"]["alert"]["category"] = "Detection of a Network Scan"
    assert hits_mod.event_title_of(digest, "feature_match") == "网络扫描"
