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
WHITELIST = {
    Path("packages/ui/src/lib/format.ts"),
    # events-panel.tsx 那一行 `n.toLocaleString("zh-CN")` 是**数字千分位**
    # （格式化事件计数），不是时间 —— 本规则管的是"时间交给浏览器本地化"，
    # 不应拦。后续如果再出现"时间/时区"相关的 toLocaleString 才需要新守卫。
    Path("ndr/frontend/components/events-panel.tsx"),
}
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
    backend = (root / "ndr" / "backend" / "app" / "api" / "routes" / "stats_overview.py").read_text(
        encoding="utf-8"
    )
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
    # X 轴：时间要看得见，但每 5 分钟才一个标签、不画密集刻度
    assert "interval: everyPoints - 1" in body, "X 轴要每 5 分钟一个时间标签"
    assert "axisTick: { show: false }" in body, "不画密集刻度线"
    # 用户口径：**波浪线**（平滑），**不填充区域**
    assert "smooth: true" in body, "波浪线（平滑曲线）"
    assert "areaStyle" not in body, "不要填充区域"
    assert 'step: "end"' not in body, "不要折叠线"
    # 用户口径：流量绿、掉包黄；掉包走右 Y 轴。
    # 2026-10 前端改造后颜色统一到**设计 token**（`chartTokens()`，读 CSS 变量），
    # 不再写死 hex —— 所以断言"用的是 token"，不再断言具体色值。
    assert "chartTokens()" in body, "颜色要取设计 token（不许写死 hex）"
    assert "t.series[" in body, "流量用序列色（token）"
    assert "t.sev.medium" in body, "掉包用严重度语义色（token，琥珀系）"
    assert '"#' not in body, "图表里不应再出现写死的 hex 颜色"
    assert "yAxisIndex: 1" in body, "掉包在右 Y 轴"
    # 容量尺（字节）在**左**轴、用**对数**刻度（线性时低位数据贴 X 轴像没数据）
    assert 'type: "log"' in body, "左轴要用对数刻度"
    assert "markLine" in body and 'position: "start"' in body, "容量尺标注要画在左边"
    # 8 档固定阶梯一个不少
    for tick in ("200KB", "1M", "5M", "50M", "100M", "200M", "500M", "1G"):
        assert f'"{tick}"' in charts, f"容量尺缺 {tick}"
    # 掉包要能算掉包率（同区间处理包数）
    assert "pkts_proc" in body, "提示框要能算掉包率"

    # 末尾"进行中的桶"必须丢掉：它刚出现时速率必然偏低 → 曲线会"一冒出来先掉到 0 再涨上去"
    assert "raw[raw.length - 1].partial ? raw.slice(0, -1) : raw" in body, "要丢掉末尾进行中的桶"
    # 容量尺最低那档（200KB）压在轴高约 1/5：用户口径「200KB 刻度太高了，减少一半的高度」
    # （原来下限固定 1KB → 200KB 在 38.5%，砍一半 ≈ 19%）
    assert "LADDER_BOTTOM_FRACTION = 0.19" in charts, "200KB 阶梯高度要压到轴高 ~19%"
    assert "flowAxisMin(flowMax)" in body, "轴下限要由「200KB 落 19%」反推，不能固定"
    assert "Math.max(flowMin, v)" in body, "低于下限的值贴底（对数轴不能画 0）"
    # 画的是**每秒**口径，不是 20 秒桶内总量（否则虚高 20 倍）
    assert "p.bytes_per_sec" in body, "曲线必须画每秒速率"
    assert "p.bytes_total" not in body, "不能把桶内总量当每秒"
    # 掉包来自 Zeek stats.log 上报值
    assert "pkts_dropped" in body, "掉包折线取 Zeek 上报值"
    assert "everyPoints" in body and "segment_minutes" in body, "分区粒度从后端字段算"

    panel = (root / "ndr" / "frontend" / "components" / "status-panel.tsx").read_text(
        encoding="utf-8"
    )
    assert '"/api/stats/traffic?minutes=30"' in panel, "取数窗口近半小时"
    assert "实时发送" in panel and "实时接收" in panel and "峰值" in panel
    assert "trafficPeak: traffic?.peak_bytes_per_sec" in panel, "峰值用服务端算好的每秒口径"
    assert "bytes_out_per_sec" in panel, "实时发送/接收必须用每秒速率（不能直接用桶内总量）"
