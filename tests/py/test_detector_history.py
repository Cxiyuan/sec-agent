"""检测器历史采样（``app/detector/history.py``）——总览页 24h 趋势的数据底座。

只跑 NDR 栈。钉住四件事：

- 采样是**有界**的（LPUSH + LTRIM 到上限 + TTL），不能像历史事故那样把 Redis 撑爆；
- 读出来是**时间正序**（图表直接用），坏行跳过、Redis 故障返回空表而不抛；
- 「按规则」计数必须是**本区间**的（用后即清），否则规则 TOP 会变成自进程启动以来的累计；
- 检测器统计块确实调了采样（否则总览页永远空白）。
"""

from __future__ import annotations

import importlib
import json
from collections import Counter
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


class FakeRedis:
    """够用的内存版 Redis：列表 + TTL（TTL 只记录不生效）。"""

    def __init__(self) -> None:
        self.lists: dict[str, list[str]] = {}
        self.expires: dict[str, int] = {}
        self.fail = False

    def lpush(self, key: str, *values: Any) -> int:
        if self.fail:
            raise RuntimeError("boom")
        lst = self.lists.setdefault(key, [])
        for value in values:
            lst.insert(0, str(value))
        return len(lst)

    def ltrim(self, key: str, start: int, stop: int) -> bool:
        if self.fail:
            raise RuntimeError("boom")
        lst = self.lists.get(key, [])
        n = len(lst)
        s = max(0, start if start >= 0 else n + start)
        e = min(n - 1, stop if stop >= 0 else n + stop)
        self.lists[key] = lst[s : e + 1] if s <= e else []
        return True

    def expire(self, key: str, seconds: int) -> bool:
        if self.fail:
            raise RuntimeError("boom")
        self.expires[key] = int(seconds)
        return True

    def lrange(self, key: str, start: int, stop: int) -> list[str]:
        if self.fail:
            raise RuntimeError("boom")
        lst = self.lists.get(key, [])
        n = len(lst)
        s = max(0, start if start >= 0 else n + start)
        e = min(n - 1, stop if stop >= 0 else n + stop)
        return lst[s : e + 1] if s <= e else []


@pytest.fixture(scope="module")
def history(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("检测器历史只在 NDR 侧")
    return importlib.import_module("app.detector.history")


@pytest.fixture
def client() -> FakeRedis:
    return FakeRedis()


# ---------- 写入：有界 + TTL ----------


def test_append_writes_json_and_sets_ttl(history: ModuleType, client: FakeRedis) -> None:
    assert history.append(client, {"ts": 1, "hit": 5}, key="k", max_items=10) is True
    assert client.expires["k"] > 0
    assert json.loads(client.lists["k"][0]) == {"ts": 1, "hit": 5}


def test_append_is_bounded_keeping_newest(history: ModuleType, client: FakeRedis) -> None:
    for i in range(12):
        history.append(client, {"ts": i}, key="k", max_items=5)
    assert len(client.lists["k"]) == 5
    # LPUSH：最新的在头部；LTRIM 0..4 保住的就是最近 5 条
    assert [json.loads(x)["ts"] for x in client.lists["k"]] == [11, 10, 9, 8, 7]


def test_append_never_raises(history: ModuleType, client: FakeRedis) -> None:
    client.fail = True
    assert history.append(client, {"ts": 1}, key="k", max_items=5) is False


@pytest.mark.parametrize(("key", "max_items"), [("", 5), ("k", 0)])
def test_append_skips_invalid_target(
    history: ModuleType, client: FakeRedis, key: str, max_items: int
) -> None:
    assert history.append(client, {"ts": 1}, key=key, max_items=max_items) is False


# ---------- 读取：时间正序 + 容错 ----------


def test_read_returns_chronological_and_honours_limit(
    history: ModuleType, client: FakeRedis
) -> None:
    for i in range(5):
        history.append(client, {"ts": i}, key="k", max_items=10)
    items = history.read(client, key="k", limit=3)
    # 最近 3 条（ts=4,3,2）反转成时间正序
    assert [x["ts"] for x in items] == [2, 3, 4]


def test_read_skips_bad_lines(history: ModuleType, client: FakeRedis) -> None:
    client.lists["k"] = ['{"ts": 2}', "not-json", "[1,2]", '{"ts": 1}']
    items = history.read(client, key="k", limit=10)
    assert [x["ts"] for x in items] == [1, 2]


def test_read_returns_empty_on_redis_error(history: ModuleType, client: FakeRedis) -> None:
    client.fail = True
    assert history.read(client, key="k", limit=10) == []


def test_read_returns_empty_on_empty_queue(history: ModuleType, client: FakeRedis) -> None:
    assert history.read(client, key="k", limit=10) == []


# ---------- 区间计数：用后即清 ----------


def test_extract_interval_rules_pops_keys(history: ModuleType) -> None:
    stats: Counter[str] = Counter()
    history.mark_digest(stats, {"rule": "A", "rule_severity": "high"})
    history.mark_digest(stats, {"rule": "A", "rule_severity": "low"})
    history.mark_digest(stats, {"rule": "B", "rule_severity": "high"})
    stats["scanned"] = 999  # 无关键不能被带走

    by_rule = history.extract_interval_rules(stats)
    assert by_rule == {"A": 2, "B": 1}
    # 抽走之后计数器里不该再残留（否则下一次采样会变成累计值）
    assert history.extract_interval_rules(stats) == {}
    assert stats["scanned"] == 999
    assert stats["digest_sev_high"] == 2
    assert stats["digest_sev_low"] == 1


def test_mark_digest_maps_unknown_severity_to_info(history: ModuleType) -> None:
    stats: Counter[str] = Counter()
    history.mark_digest(stats, {"rule": "r", "rule_severity": "高危"})
    assert stats["digest_sev_info"] == 1


def test_mark_digest_without_rule_does_not_create_rule_key(history: ModuleType) -> None:
    stats: Counter[str] = Counter()
    history.mark_digest(stats, {"rule": "", "rule_severity": "high"})
    assert history.extract_interval_rules(stats) == {}


def test_severity_deltas_computes_and_advances(history: ModuleType) -> None:
    stats: Counter[str] = Counter()
    stats["digest_sev_high"] = 7
    stats["digest_sev_critical"] = 2
    prev: dict[str, float] = {"digest_sev_high": 5.0, "digest_sev_critical": 2.0}

    deltas = history.severity_deltas(stats, prev)
    assert deltas["d_digest_sev_high"] == 2.0
    assert deltas["d_digest_sev_critical"] == 0.0
    assert prev["digest_sev_high"] == 7.0
    # 计数器回退（进程重启）也不能算出负数
    stats["digest_sev_high"] = 1
    assert history.severity_deltas(stats, prev)["d_digest_sev_high"] == 0.0


# ---------- 接线：统计块必须真的采样 ----------


def test_runner_samples_history_in_stats_block() -> None:
    source = (ROOT / "ndr" / "backend" / "app" / "detector" / "runner.py").read_text(
        encoding="utf-8"
    )
    assert "history_append(" in source, "检测器没有调用 history.append，总览页趋势会永远空"
    assert "mark_digest(stats, digest)" in source, "摘要入队处没有记严重度/规则计数"
    # 采样必须在 rate_prev 更新之前算增量，否则 d_* 全是 0
    append_at = source.index("history_append(")
    update_at = source.index("rate_prev.update(", append_at)
    assert append_at < update_at
