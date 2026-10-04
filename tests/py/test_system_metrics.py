"""服务器状态解析（``app/api/routes/system_metrics.py``）：CPU / 内存 / 磁盘。

只跑 NDR 栈。不碰真 `/proc`：解析函数是纯函数，直接用固定文本喂；端点用 monkeypatch
把 `/proc` 与 `disk_usage` 换掉。重点钉住两件事：

- 数字算得对（CPU 要两次采样、内存用 MemAvailable、磁盘百分比）；
- **读不到任一指标时端点不 500**，而是给 `null` + `notes`（总览页不能整页空白）。
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import Any

import pytest

_CPU = "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 1 2 3 4 5 6 7 8 9 0\n"
_MEM = "MemTotal:       11534336 kB\nMemFree:         1000000 kB\nMemAvailable:    2097152 kB\n"
_MEM_NO_AVAIL = "MemTotal:       11534336 kB\nMemFree:         1048576 kB\n"


@pytest.fixture(scope="module")
def metrics_mod(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("服务器指标端点只在 NDR 侧")
    return importlib.import_module("app.api.routes.system_metrics")


# ---------- /proc/stat ----------


def test_parse_cpu_totals_uses_aggregate_line(metrics_mod: ModuleType) -> None:
    got = metrics_mod.parse_cpu_totals(_CPU)
    assert got is not None
    idle, total = got
    assert idle == 800.0  # idle(800) + iowait(0)
    assert total == 1000.0


@pytest.mark.parametrize("text", ["", "cpu0 1 2 3 4 5\n", "cpu  1 2 x 4 5\n", "cpu  1 2\n"])
def test_parse_cpu_totals_handles_bad_input(metrics_mod: ModuleType, text: str) -> None:
    assert metrics_mod.parse_cpu_totals(text) is None


def test_cpu_percent_math(metrics_mod: ModuleType) -> None:
    # 1000 jiffy 里 idle 涨 500 → 忙 50%
    assert metrics_mod.cpu_percent((800.0, 1000.0), (1300.0, 2000.0)) == 50.0


@pytest.mark.parametrize(
    ("first", "second"),
    [(None, (1.0, 2.0)), ((1.0, 2.0), None), ((1.0, 2.0), (1.0, 2.0))],
)
def test_cpu_percent_returns_none_without_delta(
    metrics_mod: ModuleType, first: Any, second: Any
) -> None:
    assert metrics_mod.cpu_percent(first, second) is None


def test_cpu_percent_handles_counter_regression(metrics_mod: ModuleType) -> None:
    # idle 回退（计数器乱/进程重启）→ 宁可不报，也不要算出 100% 假负载
    assert metrics_mod.cpu_percent((900.0, 1000.0), (100.0, 2000.0)) is None
    # 总时间没前进（采样太近）→ null
    assert metrics_mod.cpu_percent((500.0, 1000.0), (500.0, 1000.0)) is None


def test_cpu_percent_clamps_at_100(metrics_mod: ModuleType) -> None:
    # idle 一点没涨（1000 → 2000 全是忙）→ 100%，不越界
    assert metrics_mod.cpu_percent((0.0, 1000.0), (0.0, 2000.0)) == 100.0


# ---------- /proc/meminfo ----------


def test_parse_meminfo_prefers_memavailable(metrics_mod: ModuleType) -> None:
    used, total = metrics_mod.parse_meminfo(_MEM)  # type: ignore[misc]
    assert total == 11534336 * 1024
    assert used == (11534336 - 2097152) * 1024  # 用 MemAvailable，不是 MemFree


def test_parse_meminfo_falls_back_to_memfree(metrics_mod: ModuleType) -> None:
    used, total = metrics_mod.parse_meminfo(_MEM_NO_AVAIL)  # type: ignore[misc]
    assert total == 11534336 * 1024
    assert used == (11534336 - 1048576) * 1024


def test_parse_meminfo_requires_total(metrics_mod: ModuleType) -> None:
    assert metrics_mod.parse_meminfo("MemFree: 10 kB\n") is None


# ---------- /proc/loadavg ----------


def test_parse_loadavg(metrics_mod: ModuleType) -> None:
    assert metrics_mod.parse_loadavg("4.25 4.07 3.44 2/812 12345\n") == 4.25
    assert metrics_mod.parse_loadavg("") is None
    assert metrics_mod.parse_loadavg("abc def\n") is None


# ---------- 端点 ----------


def test_endpoint_returns_all_three_gauges(
    metrics_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 第二次读 /proc/stat 要真的多走一点时间，否则算不出占比（代码会返回 null）
    # 样本1：idle=800 total=1000；样本2：idle=1300 total=2000 → Δidle=500 Δtotal=1000 → 忙 50%
    cpu_samples = [
        "cpu  50 0 150 800 0 0 0 0 0 0\n",
        "cpu  200 0 500 1300 0 0 0 0 0 0\n",
    ]
    reads = {"stat": 0}
    texts = {"/proc/meminfo": _MEM, "/proc/loadavg": "2.5 2.0 1.5 1/10 9\n"}

    def fake_read(path: str) -> str | None:
        if path == "/proc/stat":
            idx = min(reads["stat"], len(cpu_samples) - 1)
            reads["stat"] += 1
            return cpu_samples[idx]
        return texts.get(path)

    class _Usage:
        total = 1000
        used = 400
        free = 600

    monkeypatch.setattr(metrics_mod, "_read_text", fake_read)
    monkeypatch.setattr(metrics_mod.time, "sleep", lambda _s: None)
    monkeypatch.setattr(metrics_mod.shutil, "disk_usage", lambda _p: _Usage())

    out = metrics_mod.system_metrics(_=None)
    assert out["cpu_percent"] == 50.0
    assert out["mem_percent"] == round((11534336 - 2097152) * 100 / 11534336, 1)
    assert out["disk_percent"] == 40.0
    assert out["load_1m"] == 2.5
    assert out["disk_path"] == "/"
    assert out["notes"] == []
    assert out["mem_used_bytes"] == (11534336 - 2097152) * 1024
    assert out["disk_used_bytes"] == 400


def test_endpoint_degrades_without_500(
    metrics_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(metrics_mod, "_read_text", lambda _p: None)
    monkeypatch.setattr(metrics_mod.time, "sleep", lambda _s: None)

    def boom(_p: str) -> Any:
        raise OSError("no disk")

    monkeypatch.setattr(metrics_mod.shutil, "disk_usage", boom)

    out = metrics_mod.system_metrics(_=None)
    assert out["cpu_percent"] is None
    assert out["mem_percent"] is None
    assert out["disk_percent"] is None
    # 三项都读不到 → 三条 note，端点仍然返回 200 结构
    assert len(out["notes"]) == 3
    assert any("磁盘" in n for n in out["notes"])
