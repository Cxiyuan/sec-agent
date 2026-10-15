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


def test_recent_traffic_dashboard_contract() -> None:
    """「近期流量」仪表盘的口径（2026-10 用户要求，参考 ESXi 主机资源占用那种画法）。

    - 后端：**每 20 秒一个点**、窗口默认**近 30 分钟**、**每 5 分钟一个分区**、结果缓存 30 秒；
    - 前端：**X 轴不显示刻度**（时间靠 5 分钟分区线感知，曲线随时间滚动）、
      绿色**锯齿**折线（不平滑、不填充）、右上角「实时发送 / 实时接收 / 峰值」大字。
    """
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    backend = (
        root / "ndr" / "backend" / "app" / "api" / "routes" / "stats_overview.py"
    ).read_text(encoding="utf-8")
    assert "TRAFFIC_INTERVAL_SECONDS = 20" in backend, "打点粒度必须是 20 秒"
    assert "TRAFFIC_MINUTES_DEFAULT = 30" in backend, "窗口默认近半小时"
    assert "TRAFFIC_SEGMENT_MINUTES = 5" in backend, "每 5 分钟一个分区"
    assert "TRAFFIC_CACHE_SECONDS = 30" in backend, "要缓存，别让 5 秒轮询穿透 ES"
    assert "segment_marks" in backend and "per_interval" in backend
    assert "current_bytes_per_sec" in backend and "peak_bytes_per_sec" in backend

    charts = (root / "ndr" / "frontend" / "components" / "status-charts.ts").read_text(
        encoding="utf-8"
    )
    start = charts.index("export function minuteTrafficOption(")
    _nxt = charts.find("\nexport function", start + 10)
    body = charts[start : len(charts) if _nxt < 0 else _nxt]
    assert "interval: everyPoints - 1" in body, "X 轴要**每 5 分钟一个时间标签**（不能藏起来）"
    assert "axisTick: { show: false }" in body, "不画密集刻度线"
    assert "smooth: true" in body, "现代观感：平滑曲线"
    assert "areaStyle: { opacity: 0.22 }" in body, "面积用本页同款低透明度纯色"
    assert "#0ea5e9" in body, "线条沿用本页主色"
    assert "backgroundColor: \"#ffffff\"" not in body, "提示框不要白色（那是 Excel 观感）"
    assert "splitLine: { lineStyle: { color: \"#e5e7eb\" } }" not in body, "不要整片浅灰网格"
    # 每 5 分钟一个分区，粒度从后端字段算，不写死
    assert "everyPoints" in body and "segment_minutes" in body

    panel = (
        root / "ndr" / "frontend" / "components" / "status-panel.tsx"
    ).read_text(encoding="utf-8")
    assert '"/api/stats/traffic?minutes=30"' in panel, "取数窗口近半小时"
    assert "实时发送" in panel and "实时接收" in panel and "峰值" in panel
