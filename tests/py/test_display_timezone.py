"""时间显示口径：**全部北京时间**（用户 2026-10 口径）。

背景：展示层把时间统一交给 `packages/ui/src/lib/format.ts`（Intl + `Asia/Shanghai`）。
绕过它自己 `new Date(...).getHours()` 或裸切 ISO 串，显示就会跟**浏览器时区**走、
或者把后端的 UTC 串（`+00:00`）当北京时间显示 —— 值班对时间线时就会对不上。

这个文件是那句口径的守门人：**只查前端源码里的写法**，不跑浏览器。
新增页面时如果写了这类代码，这里会直接红。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
#: 允许出现这些写法的唯一位置：共享格式化模块自己（它内部才做时区处理）
WHITELIST = {Path("packages/ui/src/lib/format.ts")}
#: 扫描范围：两个前端 + 共享 UI
SCOPES = ("ndr/frontend", "agent/frontend")
#: 禁止的写法：按浏览器本地时区取时间 / 一键本地化 / 裸切 ISO 串
FORBIDDEN = (
    r"\.getHours\(\)",
    r"\.getMinutes\(\)",
    r"\.getMonth\(\)",
    r"\.getDate\(\)",
    r"\.getFullYear\(\)",
    r"toLocaleString\(",
    r"toLocaleTimeString\(",
    r"toLocaleDateString\(",
    r'\.slice\(0, 19\)\.replace\("T", " "\)',
    r'\.replace\("T", " "\)\.slice\(',
)


def _sources() -> list[Path]:
    files: list[Path] = []
    for scope in SCOPES:
        base = ROOT / scope
        if not base.is_dir():
            continue
        files += [p for p in base.rglob("*.ts*") if p.is_file()]
    return files


@pytest.mark.parametrize("pattern", FORBIDDEN)
def test_no_browser_local_time_patterns(pattern: str) -> None:
    regex = re.compile(pattern)
    offenders: list[str] = []
    for path in _sources():
        rel = path.relative_to(ROOT)
        if rel in WHITELIST:
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if regex.search(line):
                offenders.append(f"{rel}:{lineno}: {line.strip()[:100]}")
    assert not offenders, (
        "以下位置绕过了共享的北京时间格式化（改用 @shentong/ui 的 "
        "formatDateTime / formatDate / formatTime / formatClock / formatShort / formatHourSlot）：\n"
        + "\n".join(offenders)
    )
