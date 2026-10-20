"""签名规则目录：把 Suricata 内置规则**读成检测规则列表里的一员**（只读）。

## 为什么需要它

以前签名规则藏在「签名规则集」这个独立功能里（另一套页面 + 校验/生效/重置接口），
运维要在两个地方看规则：检测规则管理里只有行为分析，签名规则在别处。用户口径（2026-10）：

> 检测规则列表里就应该同时有「行为分析」和「特征匹配」，不需要单独一个签名规则集功能。

所以这里把内置规则文件解析成与数据库规则**同构**的条目，由 `/api/rules` 一并返回：
- `source_kind="feature_match"`、`source_label="特征匹配"`、`source="signature"`；
- `readonly=True`：签名规则是随镜像发布的文件，不能在界面上增删改（不是"漏了开关"，
  而是它们由规则包决定，改了会和 `suricata -T` 校验/镜像内容不一致）。

## 解析口径

Suricata 规则是多行文本（用行尾 `\\` 续行），这里按"逻辑规则"拼行后再抽字段：
`msg`（事件名）/ `sid`（唯一 ID）/ `classtype`（归类）/ `metadata` 里的 `severity`。
解析失败的规则跳过并记 debug 日志 —— 目录只是展示，不能因为一条怪规则让整个接口 500。
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.workers.log import get_logger

log = get_logger(__name__)


def _builtin_dir() -> Path:
    """规则目录：环境变量优先，其次按仓库/镜像两种布局找。

    - 仓库里：`ndr/backend/app/suricata/catalog.py` → `ndr/suricata/rules/builtin`（parents[3]）；
    - 镜像里：`/app/app/suricata/catalog.py`（Dockerfile 把规则 COPY 到 `/app/suricata/`）
      → parents[2] = `/app` → `/app/suricata/rules/builtin`。

    找不到就返回第一个候选（`builtin_catalog()` 会当成空目录处理，接口不 500）。
    """
    override = os.environ.get("ST_SIGNATURE_RULES_DIR", "").strip()
    here = Path(__file__).resolve()
    candidates = [
        here.parents[3] / "suricata" / "rules" / "builtin",  # 仓库布局
        here.parents[2] / "suricata" / "rules" / "builtin",  # 镜像布局（/app/suricata/...）
    ]
    if override:
        candidates.insert(0, Path(override))
    for path in candidates:
        if path.is_dir():
            return path
    return candidates[0]


_MSG = re.compile(r'msg\s*:\s*"([^"]*)"')
_SID = re.compile(r"\bsid\s*:\s*(\d+)")
_CLASSTYPE = re.compile(r"\bclasstype\s*:\s*([\w-]+)")
_REV = re.compile(r"\brev\s*:\s*(\d+)")
_SEVERITY = re.compile(r"\bseverity\s+([A-Za-z]+)")

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "low",
}


def _logical_rules(text: str) -> list[str]:
    """把多行规则拼成逻辑规则（行尾 `\\` 续行；`#` 开头是注释）。"""
    out: list[str] = []
    buf = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        buf += line.rstrip("\\").strip() + " "
        if not line.endswith("\\"):
            if buf.lstrip().startswith(("alert", "drop", "reject", "pass")):
                out.append(buf.strip())
            buf = ""
    return out


def _severity_of(rule: str) -> str:
    """优先级：metadata 里的 severity 字段 → 否则按 medium。"""
    found = _SEVERITY.search(rule)
    if found:
        return _SEVERITY_MAP.get(found.group(1).strip().lower(), "medium")
    return "medium"


def _category_labels(builtin_dir: Path) -> dict[str, str]:
    """分类索引：文件名 → 中文分类名（`index.json` 由 build_builtin_index.py 生成）。"""
    index = builtin_dir / "index.json"
    try:
        data = json.loads(index.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.debug("读不到签名规则分类索引 %s：%s", index, exc)
        return {}
    out: dict[str, str] = {}
    for item in data.get("categories") or []:
        if not isinstance(item, dict):
            continue
        file_name = str(item.get("file") or "")
        label = str(item.get("label") or "")
        if file_name and label:
            out[file_name] = label
    return out


@lru_cache(maxsize=1)
def builtin_catalog() -> tuple[dict[str, Any], ...]:
    """内置签名规则目录（只读）。返回元组便于缓存（调用方不要改）。"""
    builtin_dir = _builtin_dir()
    labels = _category_labels(builtin_dir)
    items: list[dict[str, Any]] = []
    if not builtin_dir.is_dir():
        log.debug("签名规则目录不存在（跳过目录展示）：%s", builtin_dir)
        return ()
    for path in sorted(builtin_dir.glob("*.rules")):
        category = labels.get(path.name, path.stem)
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            log.debug("读不到签名规则文件 %s：%s", path, exc)
            continue
        for rule in _logical_rules(text):
            msg = _MSG.search(rule)
            sid = _SID.search(rule)
            if not msg or not sid:
                continue
            classtype = _CLASSTYPE.search(rule)
            rev = _REV.search(rule)
            items.append(
                {
                    "id": f"sig-{sid.group(1)}",
                    "name": msg.group(1).strip(),
                    "severity": _severity_of(rule),
                    "source": "signature",
                    "source_kind": "feature_match",
                    "source_label": "特征匹配",
                    "category": category,
                    # 契约与库里的行为分析规则同构（前端一套表格渲染两类规则）
                    "conditions": {},
                    "scope": "network",
                    "description": (
                        f"{category} · SID {sid.group(1)}"
                        + (f" · {classtype.group(1)}" if classtype else "")
                        + (f" · rev {rev.group(1)}" if rev else "")
                    ),
                    # 随镜像发布的规则文件：界面上不能增删改
                    "readonly": True,
                    "enabled": True,
                    "priority": 0,
                }
            )
    return tuple(items)


def catalog_size() -> int:
    return len(builtin_catalog())
