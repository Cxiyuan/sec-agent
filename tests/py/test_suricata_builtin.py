"""内置签名规则集（按攻击类型分类）的守卫。

规则来源：开发者提供的规则全集 → `ndr/suricata/tools/classify_rules.py` 按 `classtype`
分成 7 类 → 作为镜像的**内置默认**规则集（`ndr/suricata/rules/builtin/`）。
权威语法校验在 CI 的 `tests/suricata/run.sh`（拿真实 suricata 跑 `-T` 全量加载）；
这里钉住的是「分类与索引一致、没有重复 sid、规则外形完整」这类不跑引擎也能查的东西。
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
BUILTIN = ROOT / "ndr" / "suricata" / "rules" / "builtin"
TOOL = ROOT / "ndr" / "suricata" / "tools" / "classify_rules.py"

_ACTION_RE = re.compile(r"^\s*(alert|drop|reject|pass)\s")
_CLASSTYPE_RE = re.compile(r"classtype:\s*([a-zA-Z0-9_-]+)")
_SID_RE = re.compile(r"\bsid:\s*(\d+)")


@pytest.fixture(scope="module")
def index() -> dict:
    path = BUILTIN / "index.json"
    assert path.exists(), f"缺少分类索引 {path}"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def tool() -> Any:
    """把分类脚本当模块加载（它不在 app 包里，只看它的映射表，不执行分类）。"""
    spec = importlib.util.spec_from_file_location("classify_rules", TOOL)
    assert spec is not None and spec.loader is not None, "分类脚本不存在"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_index_covers_seven_attack_categories(index: dict) -> None:
    cats = {c["category"] for c in index["categories"]}
    assert cats == {
        "10-web-attack",
        "20-exploit",
        "30-credential",
        "40-scan",
        "50-malware-c2",
        "60-sensitive-data",
        "90-other",
    }
    assert index["total"] == sum(c["rules"] for c in index["categories"])


def test_every_category_file_matches_index(index: dict) -> None:
    """每类文件里的规则条数必须与索引一致（防手工改文件、防漏生成）。"""
    for cat in index["categories"]:
        path = BUILTIN / cat["file"]
        assert path.exists(), f"缺少分类文件 {cat['file']}"
        rules = [ln for ln in path.read_text(encoding="utf-8").splitlines() if _ACTION_RE.match(ln)]
        assert len(rules) == cat["rules"], f"{cat['file']} 实际 {len(rules)} 条，索引写 {cat['rules']}"


def test_sids_are_globally_unique(index: dict) -> None:
    """sid 全局唯一：重复 sid 会让引擎报错/告警混淆。"""
    seen: dict[str, str] = {}
    dup: list[str] = []
    for cat in index["categories"]:
        text = (BUILTIN / cat["file"]).read_text(encoding="utf-8")
        for sid in _SID_RE.findall(text):
            if sid in seen:
                dup.append(sid)
            seen[sid] = cat["file"]
    assert not dup, f"重复 sid {dup[:5]}（共 {len(dup)}）"
    assert len(seen) == index["total"], f"sid 数 {len(seen)} 与索引 total {index['total']} 不一致"


def _balanced_quotes(line: str) -> bool:
    """未转义的引号必须成对（`\"` 是 pcre/content 里的正常转义，别误判）。"""
    count = 0
    i = 0
    while i < len(line):
        if line[i] == "\\":
            i += 2
            continue
        if line[i] == '"':
            count += 1
        i += 1
    return count % 2 == 0


def test_rules_look_syntactically_complete(index: dict) -> None:
    """规则外形：动作 + msg + sid + 成对的引号 + 以 `)` 收尾（真实语法由 CI 的 suricata -T 判）。"""
    for cat in index["categories"]:
        for no, line in enumerate((BUILTIN / cat["file"]).read_text(encoding="utf-8").splitlines(), 1):
            if not _ACTION_RE.match(line):
                continue
            where = f"{cat['file']}:{no}"
            assert line.rstrip().endswith(")"), f"{where} 没有以 ')' 收尾"
            assert _balanced_quotes(line), f"{where} 引号不成对"
            assert "msg:" in line, f"{where} 缺 msg"
            assert _SID_RE.search(line), f"{where} 缺 sid"
            assert _CLASSTYPE_RE.search(line), f"{where} 缺 classtype"


def test_every_classtype_is_mapped(tool: Any, index: dict) -> None:
    """内置集里出现过的 classtype 必须在分类表里登记（否则会被静默丢进 90-other）。"""
    mapped = tool.CATEGORY_OF
    cats = tool.CATEGORY_LABELS
    used = set(index["classtypes"])
    assert used - set(mapped) == set(), f"未登记的 classtype: {sorted(used - set(mapped))}"
    assert set(mapped.values()) <= set(cats), "分类表里有没写中文名的分类"
