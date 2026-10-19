"""内置签名规则集（按攻击类型分类）的守卫。

规则来源：**开发者按攻击类型分好文件**提供的规则包（2026-10 换代，15 类 / 185 条），
放在 `ndr/suricata/rules/builtin/`、由 `tools/build_builtin_index.py` 生成 `index.json`。
旧的"按 classtype 自动分 7 类"那套（已删除的自动分类工具）不再使用。
权威语法校验在 CI 的 `tests/suricata/run.sh`（拿真实 suricata 跑 `-T` 全量加载）；
这里钉住的是「分类与索引一致、没有重复 sid、规则外形完整」这类不跑引擎也能查的东西。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BUILTIN = ROOT / "ndr" / "suricata" / "rules" / "builtin"
_ACTION_RE = re.compile(r"^\s*(alert|drop|reject|pass)\s")
_CLASSTYPE_RE = re.compile(r"classtype:\s*([a-zA-Z0-9_-]+)")
_SID_RE = re.compile(r"\bsid:\s*(\d+)")


@pytest.fixture(scope="module")
def index() -> dict:
    path = BUILTIN / "index.json"
    assert path.exists(), f"缺少分类索引 {path}"
    return json.loads(path.read_text(encoding="utf-8"))


def test_index_matches_files_on_disk(index: dict) -> None:
    """索引必须与磁盘上的分类文件**一一对应**（换代后最容易出的错：加了文件忘了重建索引）。"""
    files = {p.name for p in BUILTIN.glob("*.rules")}
    indexed = {c["file"] for c in index["categories"]}
    assert indexed == files, f"索引与文件不一致：多 {sorted(indexed - files)} 缺 {sorted(files - indexed)}"
    assert index["total"] == sum(c["rules"] for c in index["categories"])
    assert index["total"] > 0
    for cat in index["categories"]:
        assert cat["rules"] > 0, f"{cat['file']} 一条规则都没有"
        assert cat["label"] and cat["label"] != cat["category"], f"{cat['file']} 缺中文名"


def test_every_category_file_matches_index(index: dict) -> None:
    """每类文件里的规则条数必须与索引一致（防手工改文件、防漏生成）。"""
    for cat in index["categories"]:
        path = BUILTIN / cat["file"]
        assert path.exists(), f"缺少分类文件 {cat['file']}"
        rules = [ln for ln in path.read_text(encoding="utf-8").splitlines() if _ACTION_RE.match(ln)]
        assert len(rules) == cat["rules"], (
            f"{cat['file']} 实际 {len(rules)} 条，索引写 {cat['rules']}"
        )


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


def _logical_rules(path: Path) -> list[tuple[int, str]]:
    """把文件读成「一条规则一行」——多行规则用 `\\` 续行，必须先拼接再校验外形。

    2026-10 换代后规则基本都是多行写法（`alert http any any -> any any ( \\` + 若干条匹配项），
    原来那种"一行必须已 `)` 收尾"的断言会误报。
    """
    out: list[tuple[int, str]] = []
    buf: list[str] = []
    start = 0
    for no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.rstrip()
        if not buf and not _ACTION_RE.match(line):
            continue
        if not buf:
            start = no
        if line.endswith("\\"):
            buf.append(line[:-1])
            continue
        buf.append(line)
        out.append((start, " ".join(buf).strip()))
        buf = []
    if buf:  # 文件末尾还挂着续行（写坏了）：也交给断言去报
        out.append((start, " ".join(buf).strip()))
    return out


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
    """规则外形：动作 + msg + sid + 成对的引号 + 以 `)` 收尾（真实语法由 CI 的 suricata -T 判）。

    多行规则先由 `_logical_rules()` 拼成一条再校验（换代后 15 个文件里绝大多数是多行写法）。
    """
    for cat in index["categories"]:
        for no, line in _logical_rules(BUILTIN / cat["file"]):
            where = f"{cat['file']}:{no}"
            assert line.rstrip().endswith(")"), f"{where} 没有以 ')' 收尾"
            assert _balanced_quotes(line), f"{where} 引号不成对"
            assert "msg:" in line, f"{where} 缺 msg"
            assert _SID_RE.search(line), f"{where} 缺 sid"
            assert _CLASSTYPE_RE.search(line), f"{where} 缺 classtype"


#: Suricata 自带的 `classification.config` 里的**标准 classtype**（用到的都在这里）。
#: 为什么不再依赖自动分类工具：分类已由开发者按文件给出，工具不再参与内置集生成；
#: 这条守卫生的是"出现了不在标准表里的 classtype"（引擎会只告警不拦截，等于静默失效）。
STANDARD_CLASSTYPES = {
    "attempted-admin",
    "attempted-dos",
    "attempted-recon",
    "attempted-user",
    "bad-unknown",
    "default-login-attempt",
    "denial-of-service",
    "exploit-kit",
    "external-ip-check",
    "insufficient-content",
    "kickass-porn",
    "misc-activity",
    "misc-attack",
    "network-scan",
    "non-standard-protocol",
    "not-suspicious",
    "policy-violation",
    "protocol-command-decode",
    "rpc-portmap-decode",
    "shellcode-detect",
    "string-detect",
    "successful-admin",
    "successful-dos",
    "successful-recon-large-number",
    "successful-recon-limited",
    "successful-user",
    "suspicious-filename-detect",
    "suspicious-login",
    "suspicious-traffic",
    "system-call-detect",
    "trojan-activity",
    "unknown",
    "unusual-client-port-connection",
    "unsuccessful-user",
    "web-application-activity",
    "web-application-attack",
}


def test_classtypes_are_standard(index: dict) -> None:
    """内置集里用到的 classtype 必须都是 Suricata 标准分类（否则引擎只告警、不按策略处置）。"""
    used: set[str] = set()
    for cat in index["categories"]:
        used |= set(cat["classtypes"])
    unknown = sorted(used - STANDARD_CLASSTYPES)
    assert not unknown, f"非标准 classtype（引擎不认）：{unknown}"
