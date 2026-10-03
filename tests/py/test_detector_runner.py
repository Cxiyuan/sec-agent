"""检测器主循环（``ndr/backend/app/detector/runner.py``）回归测试。

覆盖 QA 必修 1/2 与应修 6/7 中可在无 Redis 环境验证的部分：

- ``_flush`` 在「没配推送地址」时不再写已退役的 ``shentong:events:dispatch``，
  而是计 ``dropped_undelivered`` + push 统计的 ``undelivered``，且**不计** delivered；
- ``_quarantine`` 把处理异常的消息落隔离队列（有上限、保最新），并计 ``handle_failed``；
- ``_mark_paused``/``_clear_paused`` 让「配置关闭检测器」在状态接口里可见；
- ``_aggregate`` 不再吞掉聚合器「满额丢弃」的返回值；
- ``Leader`` 的租约过期判定不再依赖主循环节奏（后台续约线程 + 墙上时钟）。

只在 NDR 栈跑。``FakeRedis`` 从同目录的 ``test_detector_push`` 复用（该模块顶层不 import app）。
"""

from __future__ import annotations

import importlib
import json
import time
from collections import Counter
from datetime import UTC, datetime
from typing import Any

import pytest


@pytest.fixture(scope="module")
def runner(request: pytest.FixtureRequest) -> Any:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("检测器只存在于 NDR 侧")
    return importlib.import_module("app.detector.runner")


@pytest.fixture(scope="module")
def fakes(request: pytest.FixtureRequest) -> Any:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("检测器只存在于 NDR 侧")
    return importlib.import_module("test_detector_push")


def _payload(rule: str = "scan_attempt") -> str:
    return json.dumps(
        {
            "rule": rule,
            "severity": "medium",
            "count": 1,
            "last_seen": datetime.now(UTC).isoformat(),
            "src_ip": "172.16.196.10",
        }
    )


# ---------- 必修 1：没配地址不算投递成功 ----------


def test_flush_off_counts_undelivered_and_skips_retired_queue(
    runner: Any, fakes: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = fakes.FakeRedis()
    q = runner.ReliableQueue(
        client, runner.settings.detector_digest_queue, "test:detector:processing"
    )
    for _ in range(2):
        q.push(_payload())

    cfg = dict(runner.push.env_defaults())
    cfg["url"] = ""
    cfg["enabled"] = True
    monkeypatch.setattr(runner.push, "load_config", lambda db=None: cfg)

    stats: Counter[str] = Counter()
    runner._flush(q, client, stats)

    assert stats["delivered"] == 0
    assert stats["dropped_undelivered"] == 2
    assert client.hgetall(runner.settings.detector_drop_key)["undelivered"] == "2"
    assert int(client.hgetall(runner.settings.detector_push_stats_key)["undelivered"]) == 2
    # 已退役的交接队列一个字节都不能写
    assert client.exists(runner.settings.detector_delivery_queue) == 0
    assert client.llen(q.raw) == 0
    assert client.llen(q.processing) == 0


# ---------- 必修 2：处理异常落隔离队列 ----------


def test_quarantine_keeps_message_and_counts(runner: Any, fakes: Any) -> None:
    client = fakes.FakeRedis()
    stats: Counter[str] = Counter()
    runner._quarantine(client, "broken-payload", stats)

    assert client.lrange(runner.FAILED_KEY, 0, -1) == ["broken-payload"]
    assert runner._failed_depth(client) == 1
    assert stats["dropped_handle_failed"] == 1
    assert client.hgetall(runner.settings.detector_drop_key)["handle_failed"] == "1"


def test_failed_queue_is_bounded_and_keeps_newest(
    runner: Any, fakes: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = fakes.FakeRedis()
    monkeypatch.setattr(runner, "_FAILED_MAX", 2)
    stats: Counter[str] = Counter()
    for i in range(3):
        runner._quarantine(client, f"payload-{i}", stats)

    assert client.lrange(runner.FAILED_KEY, 0, -1) == ["payload-2", "payload-1"]
    assert stats["dropped_handle_failed"] == 3


# ---------- 应修 5/状态可见性 ----------


def test_paused_marker_roundtrip(runner: Any, fakes: Any) -> None:
    client = fakes.FakeRedis()
    assert client.get(runner.PAUSED_KEY) is None
    runner._mark_paused(client)
    assert client.get(runner.PAUSED_KEY)
    runner._clear_paused(client)
    assert client.get(runner.PAUSED_KEY) is None


# ---------- 应修 6：聚合满额丢弃可见 ----------


class _EntryStub:
    src_ip = "172.16.196.10"


class _FullAgg:
    """模拟聚合器到上限：``add`` 返回 False。"""

    def add(self, **kwargs: Any) -> bool:
        return False


def test_aggregate_counts_full_drop(runner: Any) -> None:
    stats: Counter[str] = Counter()
    runner._aggregate(
        _FullAgg(),
        _EntryStub(),
        {"name": "scan_attempt", "severity": "medium", "source": "builtin"},
        {"raw": "doc"},
        "conn",
        stats=stats,
    )
    assert stats["dropped_agg_full"] == 1


class _OkAgg:
    def add(self, **kwargs: Any) -> bool:
        return True


def test_aggregate_no_drop_when_accepted(runner: Any) -> None:
    stats: Counter[str] = Counter()
    runner._aggregate(
        _OkAgg(),
        _EntryStub(),
        {"name": "scan_attempt", "severity": "medium", "source": "builtin"},
        {"raw": "doc"},
        "conn",
        stats=stats,
    )
    assert stats["dropped_agg_full"] == 0


# ---------- 应修 7：租约续约不靠主循环节奏 ----------


def test_leader_detects_expired_lease_with_background_renew(
    runner: Any, fakes: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = fakes.FakeRedis()
    leader = runner.Leader(client, ttl=30, renew_seconds=5, me="me-1")
    assert leader.try_acquire() is True

    leader.start_auto_renew()
    try:
        # 后台线程已经接手续约：主循环里的兜底判定必须按墙上时钟认出租约已过期，
        # 否则「主循环被卡住」时它会继续以为自己还是主（双主写聚合态）。
        monkeypatch.setattr(leader, "_last_renew_wall", time.time() - 999)
        assert leader.try_acquire() is False
    finally:
        leader.stop_auto_renew()


def test_leader_release_drops_lease(runner: Any, fakes: Any) -> None:
    client = fakes.FakeRedis()
    leader = runner.Leader(client, ttl=30, renew_seconds=5, me="me-2")
    assert leader.try_acquire() is True
    leader.release()
    assert leader.is_leader is False
