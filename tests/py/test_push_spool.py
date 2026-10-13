"""摘要老化（5 分钟）落磁盘缓存 + 智能体恢复后按序补推（用户 2026-10 口径）。

口径：摘要在队列里最多待 `detector_push_age_seconds`（默认 300 秒）。超时就从 Redis 挪到
磁盘缓存，不再占内存；等智能体**能正常响应**（有一批推送成功）后，再从磁盘按先后顺序补推，
推成功即删缓存。这个用例用桩 Redis + 桩推送把这条链路锁住。

这是 NDR 栈专属用例（agent 栈下没有 `app.detector`）：按仓库既有写法用 fixture 里
`importlib` 取模块，agent 栈直接 skip —— 不能在模块顶层 import，否则 agent 栈收集就报错。
"""

from __future__ import annotations

import importlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def push_mod(stack: str) -> Any:
    """取 NDR 侧的推送模块；agent 栈跳过。"""
    if stack != "ndr":
        pytest.skip("摘要老化只在 NDR 侧")
    return importlib.import_module("app.detector.push")


class _FakeRedis:
    """只实现老化/补推用到的列表操作。"""

    def __init__(self) -> None:
        self.lists: dict[str, list[str]] = {}

    def lpush(self, key: str, value: str) -> None:
        self.lists.setdefault(key, []).insert(0, value)

    def lrange(self, key: str, start: int, end: int) -> list[str]:
        items = self.lists.get(key, [])
        return items[start:] if end == -1 else items[start : end + 1]

    def lrem(self, key: str, count: int, value: str) -> int:
        items = self.lists.get(key, [])
        for i, item in enumerate(items):
            if item == value:
                del items[i]
                return 1
        return 0

    def llen(self, key: str) -> int:
        return len(self.lists.get(key, []))


@pytest.fixture
def spool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, push_mod: Any) -> Path:
    monkeypatch.setattr(push_mod.settings, "detector_push_spool_dir", str(tmp_path / "spool"), raising=False)
    monkeypatch.setattr(push_mod.settings, "detector_push_age_seconds", 300, raising=False)
    monkeypatch.setattr(push_mod.settings, "detector_push_spool_max_mb", 8, raising=False)
    monkeypatch.setattr(push_mod, "record", lambda *a, **k: None)
    monkeypatch.setattr(push_mod, "load_config", lambda *a, **k: {})
    monkeypatch.setattr(push_mod, "is_on", lambda cfg: True)
    return tmp_path


def _payload(push_mod: Any, *, age_seconds: int, digests: list[dict] | None = None) -> str:
    raw = json.loads(push_mod._pack(digests or [{"id": "x"}]))
    raw["queued_at"] = (datetime.now(UTC) - timedelta(seconds=age_seconds)).isoformat()
    return json.dumps(raw, ensure_ascii=False)


def test_old_batches_move_to_disk_and_fresh_stay(spool: Path, push_mod: Any) -> None:
    """超龄的批挪到磁盘缓存并从 Redis 队列删掉；没超龄的留在队列里。"""
    r = _FakeRedis()
    key = push_mod.settings.detector_push_retry_queue
    old, fresh = _payload(push_mod, age_seconds=600), _payload(push_mod, age_seconds=5)
    r.lpush(key, old)
    r.lpush(key, fresh)

    stats: dict[str, int] = {}
    moved = push_mod.age_out_to_spool(r, stats, force=True)

    assert moved == 1
    assert r.llen(key) == 1, "只有超龄的那批被移走"
    assert push_mod.spool_stats()["spool_batches"] == 1
    assert stats["push_spooled"] == 1


def test_legacy_payload_without_timestamp_ages_out(spool: Path, push_mod: Any) -> None:
    """老载荷没有 queued_at 字段：按已超龄处理（否则永远堵在队列里）。"""
    r = _FakeRedis()
    key = push_mod.settings.detector_push_retry_queue
    r.lpush(key, json.dumps({"v": 2, "digests": [{"id": "legacy"}], "attempts": 3}, ensure_ascii=False))
    assert push_mod.age_out_to_spool(r, {}, force=True) == 1


def test_replay_after_agent_recovers(spool: Path, push_mod: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """智能体恢复（推送成功）后从磁盘按序补推；推成功的行从缓存删掉。"""
    r = _FakeRedis()
    key = push_mod.settings.detector_push_retry_queue
    for _ in range(3):
        r.lpush(key, _payload(push_mod, age_seconds=600, digests=[{"id": "a"}]))
    push_mod.age_out_to_spool(r, {}, force=True)
    assert push_mod.spool_stats()["spool_batches"] == 3

    sent: list[list[dict]] = []
    monkeypatch.setattr(push_mod, "push_batch", lambda cfg, batch: (sent.append(batch) or (True, "")))
    stats: dict[str, int] = {}
    out = push_mod.replay_spool(r, stats, limit=1)

    assert out["sent"] == 1, "每轮补推受 limit 约束"
    assert len(sent) == 1
    assert push_mod.spool_stats()["spool_batches"] == 2, "推成功的行从缓存删掉，其余留着"
    assert stats["push_spool_sent"] == 1


def test_replay_stops_when_agent_still_down(spool: Path, push_mod: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """智能体还没恢复：补推失败就停，缓存一行都不删（下次继续）。"""
    r = _FakeRedis()
    key = push_mod.settings.detector_push_retry_queue
    r.lpush(key, _payload(push_mod, age_seconds=600))
    push_mod.age_out_to_spool(r, {}, force=True)

    monkeypatch.setattr(push_mod, "push_batch", lambda cfg, batch: (False, "HTTP 502"))
    out = push_mod.replay_spool(r, {})

    assert out["sent"] == 0
    assert push_mod.spool_stats()["spool_batches"] == 1


def test_status_exposes_spool(spool: Path, push_mod: Any) -> None:
    """状态里必须能看到「磁盘缓存还有多少」——不然用户只看到队列占用率，看不到已经落盘的积压。"""
    r = _FakeRedis()
    r.lpush(push_mod.settings.detector_push_retry_queue, _payload(push_mod, age_seconds=600))
    push_mod.age_out_to_spool(r, {}, force=True)
    st = push_mod.spool_stats()
    assert st["spool_batches"] == 1 and st["spool_bytes"] > 0
    assert st["spool_oldest_age"] >= 0


def test_compose_has_8g_redis_and_spool_volume() -> None:
    """编排里必须同时有：Redis 8G 上限、队列上限调大、磁盘缓存目录挂卷。"""
    root = Path(__file__).resolve().parents[2]
    for name in ("ndr/docker-compose.yml", "ndr/docker-compose.deploy.yml"):
        text = (root / name).read_text(encoding="utf-8")
        assert "ST_DETECTOR_RAW_QUEUE_MAX" in text, f"{name}: 要能调大归一化队列上限"
        assert "ST_DETECTOR_PUSH_SPOOL_DIR: /var/lib/shentong/push-spool" in text, f"{name}: 摘要磁盘缓存"
        assert "- push-spool:/var/lib/shentong/push-spool" in text, f"{name}: 磁盘缓存必须挂卷"
    deploy = (root / "ndr" / "docker-compose.deploy.yml").read_text(encoding="utf-8")
    assert "      - 8gb\n" in deploy, "部署编排：Redis 内存上限应为 8gb"
