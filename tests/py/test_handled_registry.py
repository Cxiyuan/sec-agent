"""已处理文档登记的分桶上限与告警限频（``app/detector/handled.py``）。

只跑 NDR 栈。钉住两件事：

- 单桶到 ``max_members`` 后超出部分被丢弃，但 ``skipped`` 计数**不丢**（周期统计日志
  与 Redis ``...:skipped`` 仍能看到「丢了多少」）；
- 同类告警**限频**：高流量下每个桶都会被顶满，逐条 WARNING 会把日志刷满
  （2026-10-04 实机实测：最近 2000 行全被这一条占满，真告警被淹没）。
"""

from __future__ import annotations

import importlib
import logging
from typing import Any

import pytest


class _FakePipeline:
    def __init__(self, redis: _FakeSetRedis) -> None:
        self.r = redis
        self.ops: list[tuple[str, str, Any]] = []

    def sadd(self, key: str, *values: str) -> _FakePipeline:
        self.ops.append(("sadd", key, values))
        return self

    def expire(self, key: str, seconds: int) -> _FakePipeline:
        self.ops.append(("expire", key, seconds))
        return self

    def execute(self) -> list[Any]:
        out: list[Any] = []
        for op, key, val in self.ops:
            if op == "sadd":
                out.append(self.r.sadd(key, *val))
            else:
                out.append(self.r.expire(key, val))
        self.ops.clear()
        return out


class _FakeSetRedis:
    """只实现 HandledRegistry 用到的那几个 set 命令。"""

    def __init__(self) -> None:
        self.sets: dict[str, set[str]] = {}
        self.expires: dict[str, int] = {}

    def scard(self, key: str) -> int:
        return len(self.sets.get(key, set()))

    def sadd(self, key: str, *values: str) -> int:
        s = self.sets.setdefault(key, set())
        s.update(values)
        return len(s)

    def expire(self, key: str, seconds: int) -> bool:
        self.expires[key] = int(seconds)
        return True

    def sismember(self, key: str, value: str) -> bool:
        return value in self.sets.get(key, set())

    def pipeline(self) -> _FakePipeline:
        return _FakePipeline(self)


@pytest.fixture(scope="module")
def handled(request: pytest.FixtureRequest) -> Any:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("登记表只存在于 NDR 侧")
    return importlib.import_module("app.detector.handled")


@pytest.fixture(autouse=True)
def _reset_cap_throttle(handled: Any) -> Any:
    """限频是模块级状态，跨用例必须复位，否则用例之间互相影响。"""
    handled._last_cap_log = 0.0
    yield
    handled._last_cap_log = 0.0


def test_cap_drops_excess_but_keeps_counting(handled: Any) -> None:
    reg = handled.HandledRegistry(
        _FakeSetRedis(), "k", ttl=7200, bucket_seconds=600, max_members=1000
    )
    now = 1_000_000.0
    reg.mark_many([f"h{i}" for i in range(1200)], now=now)
    # 计数不丢：超限的 200 条记进 skipped（周期统计日志与 Redis 里能看到）
    assert reg.skipped == 200
    assert reg.r.scard(reg._keys(now)[0]) == 1000


def test_cap_warning_is_throttled(handled: Any, caplog: pytest.LogCaptureFixture) -> None:
    # max_members 下限是 1000，所以先用 1000 条把桶填满，再逐条超限。
    reg = handled.HandledRegistry(
        _FakeSetRedis(), "k", ttl=7200, bucket_seconds=600, max_members=1000
    )
    now = 1_000_000.0
    reg.mark_many([f"fill{i}" for i in range(1000)], now=now)
    with caplog.at_level(logging.WARNING, logger="app.detector.handled"):
        for i in range(50):
            reg.mark_many([f"x{i}"], now=now)  # 桶已满：这 50 条全超限
    warnings = [r for r in caplog.records if r.name == "app.detector.handled"]
    assert len(warnings) == 1, f"限频失效，收到 {len(warnings)} 条告警"
    assert reg.skipped == 50
    assert "累计丢弃" in warnings[0].getMessage()


def test_cap_warning_reappears_after_interval(
    handled: Any, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """限频窗口过去后应重新告警（不能一次之后永久静音）。"""
    reg = handled.HandledRegistry(
        _FakeSetRedis(), "k", ttl=7200, bucket_seconds=600, max_members=1000
    )
    now = 1_000_000.0
    reg.mark_many([f"fill{i}" for i in range(1000)], now=now)
    clock = {"t": 1_000_000.0}
    monkeypatch.setattr(handled.time, "time", lambda: clock["t"])
    with caplog.at_level(logging.WARNING, logger="app.detector.handled"):
        reg.mark_many(["b"], now=now)  # 超限 → 第一条告警
        clock["t"] += handled._CAP_LOG_INTERVAL_SECONDS + 1
        reg.mark_many(["c"], now=now)  # 超限 → 第二条告警
    warnings = [r for r in caplog.records if r.name == "app.detector.handled"]
    assert len(warnings) == 2
    # 两条都带出来了「丢了多少」，说明计数没因限频而丢
    assert "累计丢弃" in warnings[0].getMessage()
    assert "近 60 秒内" in warnings[1].getMessage()
