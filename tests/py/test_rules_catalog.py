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
    page = (ROOT / "ndr" / "frontend" / "app" / "admin" / "rules" / "page.tsx").read_text(
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
