"""检测规则列表口径（2026-10 用户要求）：特征匹配与行为分析同表，不再有独立签名规则集。

用户原话：检测规则列表里只有行为分析和签名规则集，删除签名规则集这个功能，
把特征匹配的规则放进检测规则管理列表内。
"""

from __future__ import annotations

import importlib
import pathlib
import re
from typing import Any

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _mod(name: str) -> Any:
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError:  # pragma: no cover - agent 栈
        pytest.skip(f"该栈没有 {name}（属 NDR 侧）")


def test_signature_catalog_lists_builtin_rules() -> None:
    """签名规则目录：能读出内置规则集（180 条），字段与规则列表同构。"""
    catalog = _mod("app.suricata.catalog")
    items = catalog.builtin_catalog()
    assert len(items) >= 100, f"内置签名规则应上百条，实际 {len(items)}"
    sample = items[0]
    for field in ("id", "name", "severity", "source_kind", "source_label", "category", "readonly"):
        assert field in sample, f"缺少字段 {field}"
    assert sample["source_kind"] == "feature_match"
    assert sample["source_label"] == "特征匹配"
    assert sample["readonly"] is True, "签名规则随镜像发布，界面上必须只读"


def test_signature_catalog_has_expected_categories() -> None:
    """分类来自 index.json（中文名），不是文件名。"""
    catalog = _mod("app.suricata.catalog")
    labels = {item["category"] for item in catalog.builtin_catalog()}
    assert any("扫描" in x for x in labels), labels
    assert any("Web" in x for x in labels), labels


def test_rules_api_merges_both_kinds() -> None:
    """/api/rules 必须同时返回行为分析与特征匹配（特征匹配只读）。"""
    src = (ROOT / "ndr" / "backend" / "app" / "api" / "routes" / "rules.py").read_text(
        encoding="utf-8"
    )
    assert "catalog.builtin_catalog()" in src, "特征匹配规则要并进列表"
    assert "behavior + feature" in src.replace("feature = ", ""), "两类要合并成同一个 items 数组"


def test_signature_ruleset_feature_is_removed() -> None:
    """「签名规则集」功能（接口 + 前端面板 + 定时检查）已移除。"""
    assert not (ROOT / "ndr" / "backend" / "app" / "api" / "routes" / "suricata.py").exists()
    assert not (ROOT / "ndr" / "frontend" / "components" / "suricata-rules-panel.tsx").exists()
    router = (ROOT / "ndr" / "backend" / "app" / "api" / "router.py").read_text(encoding="utf-8")
    assert "suricata_router" not in router
    main = (ROOT / "ndr" / "backend" / "app" / "main.py").read_text(encoding="utf-8")
    assert "suricata_check_loop" not in main, "在线规则更新检查随功能一起删除"


def test_rules_page_has_no_signature_node() -> None:
    """规则页不该再有「签名规则集」节点（特征匹配走正常分组）。"""
    page = (ROOT / "ndr" / "frontend" / "app" / "config" / "rules" / "page.tsx").read_text(
        encoding="utf-8"
    )
    assert "tree-signature" not in page
    assert "SuricataRulesPanel" not in page
    assert not re.search(r"签名规则集[^\n]*\{", page), "不应再有签名规则集树节点"


def test_backend_image_ships_rules_for_catalog() -> None:
    """后端镜像要带一份签名规则（catalog 读它），且 CI 上下文是 ndr/。"""
    dockerfile = (ROOT / "ndr" / "backend" / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY suricata/rules/builtin" in dockerfile
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "context: ./ndr" in ci, "上下文必须是 ndr/（要带 suricata/rules/builtin）"


# ===== C2 信标规则强化（2026-10 误报治理，用户要求"规则强加强"）=====


def _c2_rules_text() -> str:
    return (ROOT / "ndr" / "suricata" / "rules" / "builtin" / "10-c2-beacon.rules").read_text(
        encoding="utf-8"
    )


def test_c2_rules_are_direction_bound() -> None:
    """C2 信标只会「内网主机 → 外网」：不能再用 any -> any（否则把"外网访问我们网站"也算进去）。"""
    text = _c2_rules_text()
    assert "any any -> any any" not in text, "C2 信标规则必须限定方向"
    assert "$HOME_NET any -> $EXTERNAL_NET any" in text


def test_signature_9110004_is_hardened() -> None:
    """9110004（缺 Accept 头）实测占了 204/285 条「木马与后门活动」事件 —— 必须多条件 + 高阈值 + 降级。"""
    text = _c2_rules_text()
    rev = re.search(r"sid:9110004; rev:(\d+);", text)
    assert rev and int(rev.group(1)) >= 2, "这条规则强化后要升 rev"
    seg_start = text.index("sid:9110004;")
    seg = text[max(0, seg_start - 1600) : seg_start]
    assert 'content:!"Accept";' in seg
    assert 'content:!"Accept-Language";' in seg, "只靠一个头缺失太弱，要三个头同时缺"
    assert 'content:!"Referer";' in seg
    assert "count 3, seconds 300" in seg, "阈值要从 1 次/60 秒抬到 3 次/300 秒"
    assert "classtype:misc-activity" in seg, "低置信判据不该归类成「木马与后门活动」"


def test_weak_beacon_rules_raise_threshold() -> None:
    """同类弱判据（极简查询串/信标 URI）也不该一次就报。"""
    text = _c2_rules_text()
    for sid in ("9110001", "9110002", "9110006"):
        idx = text.index(f"sid:{sid};")
        seg = text[max(0, idx - 900) : idx]
        assert "count 3, seconds 300" in seg, f"{sid} 阈值仍是 1 次/60 秒"


def test_severity_prefers_rule_metadata() -> None:
    """事件严重度取规则作者标注的 metadata.severity（低置信判据不该展示成 high）。"""
    from types import SimpleNamespace

    se = _mod("app.detector.signature_events")
    low_dict = SimpleNamespace(raw={"alert": {"severity": 1, "metadata": {"severity": ["Low"]}}})
    low_list = SimpleNamespace(raw={"alert": {"severity": 1, "metadata": ["severity Low"]}})
    no_meta = SimpleNamespace(raw={"alert": {"severity": 1}})
    assert se.severity_of(low_dict) == "low"
    assert se.severity_of(low_list) == "low"
    assert se.severity_of(no_meta) == "high", "没有作者标注时才回落 classtype 推导"
