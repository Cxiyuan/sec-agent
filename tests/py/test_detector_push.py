"""检测器投递（``ndr/backend/app/detector/push.py``）回归测试。

覆盖 QA 必修 3 的三个修复点与 ``docs/ndr-redesign.md`` 验收表里声称存在的
「queued → retry_pending 全成功」：

1. 重试队列有硬上限，超限丢最老并计 ``retry_dropped``（原实现只 lpush 不裁剪）；
2. 「整体不可达」保留「放回队尾 + 结束本轮」的既有设计，不被改成无限重试；
3. 「单批永久失败（持续 4xx）」累加尝试次数、挪到最新端，超过阈值判 ``lost``，
   不再永久堵住队首；
4. 检测循环与 ``/api/agent-push/retry`` 用 Redis 锁串行化，不再抢同一批 processing。

只在 NDR 栈跑（推送模块只存在于 ndr 侧）。本模块顶层的 ``FakeRedis`` 也被
``test_detector_runner.py`` 复用，所以除了标准库与 pytest 之外不要在顶层 import app。
"""

from __future__ import annotations

import importlib
import json
from typing import Any

import pytest


class FakeRedis:
    """够用的内存版 Redis：列表 / 哈希 / 字符串（过期时间只记录不生效）。"""

    def __init__(self) -> None:
        self.lists: dict[str, list[str]] = {}
        self.hashes: dict[str, dict[str, str]] = {}
        self.strings: dict[str, str] = {}
        self.expires: dict[str, int] = {}

    # ---------- 列表 ----------
    def lpush(self, key: str, *values: Any) -> int:
        lst = self.lists.setdefault(key, [])
        for value in values:
            lst.insert(0, str(value))
        return len(lst)

    def rpush(self, key: str, *values: Any) -> int:
        lst = self.lists.setdefault(key, [])
        for value in values:
            lst.append(str(value))
        return len(lst)

    def llen(self, key: str) -> int:
        return len(self.lists.get(key, []))

    def ltrim(self, key: str, start: int, stop: int) -> bool:
        lst = self.lists.get(key, [])
        if not lst:
            return True
        n = len(lst)
        s = start if start >= 0 else n + start
        e = stop if stop >= 0 else n + stop
        s = max(0, s)
        e = min(n - 1, e)
        self.lists[key] = lst[s : e + 1] if s <= e else []
        return True

    def lrem(self, key: str, count: int, value: Any) -> int:
        lst = self.lists.get(key, [])
        removed = 0
        kept: list[str] = []
        for item in lst:
            if item == str(value) and (count == 0 or removed < count):
                removed += 1
                continue
            kept.append(item)
        self.lists[key] = kept
        return removed

    def rpoplpush(self, src: str, dst: str) -> str | None:
        source = self.lists.get(src, [])
        if not source:
            return None
        item = source.pop()
        self.lists.setdefault(dst, []).insert(0, item)
        return item

    def lrange(self, key: str, start: int, stop: int) -> list[str]:
        lst = self.lists.get(key, [])
        n = len(lst)
        s = start if start >= 0 else max(0, n + start)
        e = stop if stop >= 0 else n + stop
        return lst[s : e + 1]

    # ---------- 哈希 ----------
    def hincrby(self, key: str, field: str, amount: int = 1) -> int:
        h = self.hashes.setdefault(key, {})
        h[field] = str(int(h.get(field, 0)) + int(amount))
        return int(h[field])

    def hset(
        self,
        key: str,
        field: str | None = None,
        value: Any = None,
        mapping: dict[str, Any] | None = None,
    ) -> int:
        h = self.hashes.setdefault(key, {})
        if mapping:
            for k, v in mapping.items():
                h[str(k)] = str(v)
        if field is not None:
            h[str(field)] = str(value)
        return 1

    def hgetall(self, key: str) -> dict[str, str]:
        return dict(self.hashes.get(key, {}))

    # ---------- 字符串 ----------
    def set(
        self,
        key: str,
        value: Any,
        nx: bool = False,
        ex: int | None = None,
        **kwargs: Any,
    ) -> Any:
        if nx and key in self.strings:
            return None
        self.strings[key] = str(value)
        if ex:
            self.expires[key] = int(ex)
        return True

    def get(self, key: str) -> str | None:
        return self.strings.get(key)

    def delete(self, *keys: str) -> int:
        removed = 0
        for key in keys:
            if key in self.strings:
                removed += 1
            self.strings.pop(key, None)
        return removed

    def exists(self, key: str) -> int:
        return int(key in self.strings or key in self.hashes or key in self.lists)

    def incrby(self, key: str, amount: int = 1) -> int:
        self.strings[key] = str(int(self.strings.get(key, 0)) + int(amount))
        return int(self.strings[key])

    def expire(self, key: str, seconds: int) -> bool:
        self.expires[key] = int(seconds)
        return True


@pytest.fixture(scope="module")
def push(request: pytest.FixtureRequest) -> Any:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("推送模块只存在于 NDR 侧")
    return importlib.import_module("app.detector.push")


@pytest.fixture
def client() -> FakeRedis:
    return FakeRedis()


def _digest(index: int) -> dict[str, Any]:
    return {
        "rule": f"rule-{index}",
        "count": 1,
        "last_seen": "2026-01-01T00:00:00+00:00",
        "event_type": "conn",
    }


def _cfg(push: Any, url: str) -> dict[str, Any]:
    cfg = dict(push.env_defaults())
    cfg["url"] = url
    cfg["enabled"] = True
    cfg["token"] = ""
    cfg["timeout_seconds"] = 1.0
    cfg["max_per_push"] = 200
    return cfg


def _queued(push: Any, client: FakeRedis, batch: list[dict[str, Any]]) -> None:
    assert push._enqueue_retry(client, batch, error="HTTP 400: bad") is True


# ---------- 载荷与失败分类 ----------


def test_pack_unpack_roundtrip_and_legacy_list(push: Any) -> None:
    packed = push._pack([_digest(1)], attempts=2, last_error="HTTP 400: x")
    batch, attempts, err = push._unpack(packed)
    assert [d["rule"] for d in batch] == ["rule-1"]
    assert attempts == 2
    assert "HTTP 400" in err

    legacy_batch, legacy_attempts, legacy_err = push._unpack(json.dumps([_digest(9)]))
    assert [d["rule"] for d in legacy_batch] == ["rule-9"]
    assert legacy_attempts == 0
    assert legacy_err == ""

    assert push._unpack("not json") == ([], 0, "")


def test_is_transient_classification(push: Any) -> None:
    for err in ("HTTP 500: boom", "HTTP 429: slow down", "HTTP 408: timeout", "connection refused"):
        assert push._is_transient(err) is True, err
    for err in ("HTTP 400: bad payload", "HTTP 404: no route", "HTTP 401: unauthorized"):
        assert push._is_transient(err) is False, err


# ---------- 队列上限 ----------


def test_enqueue_retry_trims_queue_to_cap(
    push: Any, client: FakeRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(push, "_RETRY_QUEUE_MAX", 3)
    stats: dict[str, int] = {}
    for i in range(5):
        assert push._enqueue_retry(client, [_digest(i)], error="HTTP 400: bad", stats=stats) is True
    assert client.llen(push.settings.detector_push_retry_queue) == 3
    # 保最新、丢最老：留下的是最后三批
    remaining = client.lrange(push.settings.detector_push_retry_queue, 0, -1)
    rules = [push._unpack(p)[0][0]["rule"] for p in remaining]
    assert rules == ["rule-4", "rule-3", "rule-2"]
    stats_hash = client.hgetall(push.settings.detector_push_stats_key)
    assert int(stats_hash["retry_dropped"]) == 2
    assert stats["push_lost"] == 2


# ---------- 重发 ----------


def test_retry_pending_drains_queued_batch(
    push: Any, client: FakeRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    """docs/ndr-redesign.md 验收表声称的「queued → retry_pending 全成功」。"""
    _queued(push, client, [_digest(1), _digest(2)])
    monkeypatch.setattr(push, "load_config", lambda db=None: _cfg(push, "http://agent/api/push"))
    monkeypatch.setattr(push, "push_batch", lambda cfg, digests, timeout=0.0: (True, ""))

    stats: dict[str, int] = {}
    out = push.retry_pending(client, stats)
    assert out == {"tried": 1, "sent": 2, "failed": 0, "lost": 0, "locked": False}
    assert client.llen(push.settings.detector_push_retry_queue) == 0
    assert client.llen(push.settings.detector_push_processing_queue) == 0
    assert int(client.hgetall(push.settings.detector_push_stats_key)["retried"]) == 2
    assert stats["push_retried"] == 2


def test_retry_pending_transient_failure_requeues_and_stops(
    push: Any, client: FakeRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    """整体不可达：放回队尾 + 结束本轮（第 5 期定的行为，不许改成空转重试）。"""
    _queued(push, client, [_digest(1)])
    _queued(push, client, [_digest(2)])
    monkeypatch.setattr(push, "load_config", lambda db=None: _cfg(push, "http://agent/api/push"))
    calls: list[int] = []

    def _fail(cfg: Any, digests: list[dict[str, Any]], timeout: float = 0.0) -> tuple[bool, str]:
        calls.append(len(digests))
        return False, "HTTP 503: unavailable"

    monkeypatch.setattr(push, "push_batch", _fail)
    out = push.retry_pending(client, {})
    assert out["tried"] == 1
    assert out["failed"] == 1
    assert out["sent"] == 0
    assert out["lost"] == 0
    assert len(calls) == 1  # 首败即结束本轮
    assert client.llen(push.settings.detector_push_retry_queue) == 2  # 批放回队尾，没丢
    assert client.llen(push.settings.detector_push_processing_queue) == 0


def test_retry_pending_permanent_failure_defers_then_lost(
    push: Any, client: FakeRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    _queued(push, client, [_digest(3)])
    monkeypatch.setattr(push, "load_config", lambda db=None: _cfg(push, "http://agent/api/push"))
    monkeypatch.setattr(
        push, "push_batch", lambda cfg, digests, timeout=0.0: (False, "HTTP 400: bad payload")
    )

    for _ in range(int(push._RETRY_MAX_ATTEMPTS) - 1):
        out = push.retry_pending(client, {})
        assert out["lost"] == 0
        assert client.llen(push.settings.detector_push_retry_queue) == 1
        assert client.llen(push.settings.detector_push_processing_queue) == 0

    out = push.retry_pending(client, {})
    assert out["lost"] == 1
    assert client.llen(push.settings.detector_push_retry_queue) == 0
    stats_hash = client.hgetall(push.settings.detector_push_stats_key)
    assert int(stats_hash["retry_lost"]) == 1
    assert "永久失败" in stats_hash["last_error"]


def test_retry_pending_lock_serializes_drain(
    push: Any, client: FakeRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    _queued(push, client, [_digest(1)])
    monkeypatch.setattr(push, "load_config", lambda db=None: _cfg(push, "http://agent/api/push"))
    monkeypatch.setattr(push, "push_batch", lambda cfg, digests, timeout=0.0: (True, ""))

    token = push._acquire_drain_lock(client)
    assert token
    out = push.retry_pending(client, {})
    assert out == {"tried": 0, "sent": 0, "failed": 0, "lost": 0, "locked": True}
    assert client.llen(push.settings.detector_push_retry_queue) == 1

    push._release_drain_lock(client, token)
    out2 = push.retry_pending(client, {})
    assert out2["sent"] == 1


# ---------- 没配地址（QA 必修 1） ----------


def test_deliver_off_does_not_touch_retired_queue(
    push: Any, client: FakeRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(push, "load_config", lambda db=None: _cfg(push, ""))
    stats: dict[str, int] = {}
    outcome, detail = push.deliver(client, [_digest(1)], stats)
    assert outcome == "off"
    assert detail
    # 已退役的 shentong:events:dispatch 一个字节都不能写（全仓无消费者）
    assert client.exists(push.settings.detector_delivery_queue) == 0
    assert client.llen(push.settings.detector_push_retry_queue) == 0
    assert stats.get("push_lost", 0) == 0


def test_retry_pending_noop_when_push_off(
    push: Any, client: FakeRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    _queued(push, client, [_digest(1)])
    monkeypatch.setattr(push, "load_config", lambda db=None: _cfg(push, ""))
    out = push.retry_pending(client, {})
    assert out == {"tried": 0, "sent": 0, "failed": 0, "lost": 0, "locked": False}
    assert client.llen(push.settings.detector_push_retry_queue) == 1


# ---------- 状态口径 ----------


def test_status_separates_cumulative_counters_from_backlog(
    push: Any, client: FakeRedis
) -> None:
    push.record(client, "undelivered", 3, "未配置推送地址或已关闭")
    push.record(client, "retry_lost", 2, "连续 5 次永久失败：HTTP 400: bad payload")
    _queued(push, client, [_digest(1)])

    st = push.status(client)
    assert st["undelivered"] == 3
    assert st["retry_lost"] == 2
    assert st["queue_depth"] == 1
    assert st["processing_depth"] == 0
    assert st["retry_backlog_batches"] == 1
    assert "永久失败" in st["last_error"]
