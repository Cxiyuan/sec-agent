"""观察事实派工公平性（D7）+ 规则证据按 dst 匹配（D6），2026-10-29 架构整改。

旧问题：
- 每 5 分钟只取强度最高的 5 条、且不记录"派过没有" → 同一条强事实反复占位，
  低强度事实（login_bruteforce / asset_shift）永远轮不到；
- 规则证据只按 src 查 → 内网资产**被外网打**时带不上任何命中证据。
"""

from __future__ import annotations

import importlib
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, Self

import pytest

NOW = datetime.now(UTC)
ASSET = "10.1.1.20"


@pytest.fixture()
def cand(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> Any:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("观察事实派工只在 NDR 侧")
    return importlib.import_module("app.analysis.candidates")


class FakeQueue:
    def __init__(self, result: str = "new") -> None:
        self.calls: list[dict[str, Any]] = []
        self.bumps: list[tuple[str, int]] = []
        self.result = result

    def enqueue(self, **kwargs: Any) -> str:
        self.calls.append(kwargs)
        return self.result

    def bump(self, _client: Any, field: str, count: int = 1) -> None:
        self.bumps.append((field, count))


def _obs(
    kind: str,
    subject: str = ASSET,
    strength: float = 0.6,
    idx: str = "o1",
    reuse_identity: str = "",
) -> Any:
    return SimpleNamespace(
        id=idx,
        kind=kind,
        subject_kind="asset",
        subject=subject,
        facts={"目标": "8.8.8.8"},
        strength=strength,
        count=1,
        first_seen=NOW,
        last_seen=NOW,
        dedupe_key=f"{kind}:asset:{subject}:dst_ip:8.8.8.8",
        reuse_identity=reuse_identity,
        last_enqueued_at=None,
    )


class FakeDB:
    def __init__(self, rows: list[Any], scalar_values: list[int]) -> None:
        self.rows = rows
        self.scalar_values = list(scalar_values)
        self.marked: list[tuple[str, datetime]] = []
        self.committed = False

    def scalars(self, _stmt: Any) -> Any:
        rows = list(self.rows)

        class R:
            def all(self) -> list[Any]:
                return rows

            def __iter__(self) -> Any:
                return iter(rows)

        return R()

    def scalar(self, _stmt: Any) -> int:
        return self.scalar_values.pop(0) if self.scalar_values else 0

    def get(self, _model: Any, key: str) -> Any:
        for row in self.rows:
            if row.id == key:
                return row
        return None

    def commit(self) -> None:
        self.committed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False


def test_dispatch_marks_cooldown_and_counts(cand: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """派出去的事实要记 last_enqueued_at（6 小时冷却），并计 observation_enqueued。"""
    rows = [_obs("asset_shift", idx="o1"), _obs("login_bruteforce", idx="o2")]
    db = FakeDB(rows, scalar_values=[2, 0])  # recent_total=2, cooling=0
    monkeypatch.setattr(cand, "SessionLocal", lambda: db)
    fake_queue = FakeQueue()
    monkeypatch.setattr(cand, "queue", fake_queue)
    monkeypatch.setattr(cand.params, "candidate_kinds", lambda: {"observation"})
    monkeypatch.setattr(cand, "_recent_rule_hits", lambda *_a, **_k: [])

    made = cand.enqueue_observations(client=SimpleNamespace())
    assert made == 2
    assert all(row.last_enqueued_at is not None for row in rows)
    assert ("observation_enqueued", 2) in fake_queue.bumps
    assert ("observation_starved", 1) not in fake_queue.bumps
    # 两类事实各一条，hint 带稳定复用身份
    kinds = {c["hint"]["事实类型"] for c in fake_queue.calls}
    assert kinds == {"asset_shift", "login_bruteforce"}
    assert all(c["hint"]["reuse_identity"].startswith(c["hint"]["事实类型"]) for c in fake_queue.calls)


def test_dispatch_prefers_observation_canonical_identity(
    cand: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """有 canonical 身份时用它派工；没有时回退 dedupe_key（兼容旧数据）。"""
    canonical = "profile_anomaly|entity:session:dde03ed6|codes:cross_ip"
    rows = [
        _obs("profile_anomaly", idx="o1", reuse_identity=canonical),
        _obs("profile_anomaly", idx="o2", reuse_identity=""),
    ]
    db = FakeDB(rows, scalar_values=[2, 0])
    monkeypatch.setattr(cand, "SessionLocal", lambda: db)
    fake_queue = FakeQueue()
    monkeypatch.setattr(cand, "queue", fake_queue)
    monkeypatch.setattr(cand.params, "candidate_kinds", lambda: {"observation"})
    monkeypatch.setattr(cand, "_recent_rule_hits", lambda *_a, **_k: [])
    cand.enqueue_observations(client=SimpleNamespace())
    assert fake_queue.calls[0]["hint"]["reuse_identity"] == canonical
    assert fake_queue.calls[1]["hint"]["reuse_identity"].startswith("profile_anomaly:")


def test_suppressed_observation_still_gets_cooldown(cand: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """被抑制的事实也要记 last_enqueued_at，否则每 5 分钟重撞一次、刷高 hits。"""
    rows = [_obs("profile_anomaly", idx="o1")]
    db = FakeDB(rows, scalar_values=[1, 0])
    monkeypatch.setattr(cand, "SessionLocal", lambda: db)
    fake_queue = FakeQueue("suppressed")
    monkeypatch.setattr(cand, "queue", fake_queue)
    monkeypatch.setattr(cand.params, "candidate_kinds", lambda: {"observation"})
    monkeypatch.setattr(cand, "_recent_rule_hits", lambda *_a, **_k: [])
    made = cand.enqueue_observations(client=SimpleNamespace())
    assert made == 0
    assert rows[0].last_enqueued_at is not None


def test_starved_counter_when_quota_blocks(cand: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """有事实但被同类/总配额挡住 → observation_starved（低强度事实在挨饿）。"""
    rows = [_obs("egress_new", idx="o1"), _obs("egress_new", idx="o2")]
    db = FakeDB(rows, scalar_values=[10, 6])  # 10 条里 6 条冷却中、只派出 2 条
    monkeypatch.setattr(cand, "SessionLocal", lambda: db)
    fake_queue = FakeQueue()
    monkeypatch.setattr(cand, "queue", fake_queue)
    monkeypatch.setattr(cand.params, "candidate_kinds", lambda: {"observation"})
    monkeypatch.setattr(cand, "_recent_rule_hits", lambda *_a, **_k: [])
    cand.enqueue_observations(client=SimpleNamespace())
    assert ("observation_starved", 1) in fake_queue.bumps
    assert ("observation_skipped_cooldown", 6) in fake_queue.bumps


def test_dispatch_limits_are_pinned(cand: Any) -> None:
    """配额是验收口径：总数 5、每类 2、冷却 6 小时。"""
    assert cand._OBS_PER_ROUND == 5
    assert cand._OBS_PER_KIND == 2
    assert cand._OBS_COOLDOWN_HOURS == 6
    # 低于派工门槛的事实只可查询（conn_shift 0.2 / egress_rare 0.35）
    assert cand._OBS_MIN_STRENGTH >= 0.45


def test_rule_evidence_matches_destination(cand: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """D6：内网资产被外网源命中时，资产侧事实的 hint 能带出该规则命中。"""
    hit_as_dst = SimpleNamespace(
        id="ev-dst",
        rule="端口扫描",
        source_kind="feature_match",
        count=12,
        src_ip="1.1.1.1",
        client="1.1.1.1",
        dst_ips=[ASSET],
        direction="out→in",
        first_seen=NOW,
        last_seen=NOW,
        created_at=NOW,
    )
    hit_as_src = SimpleNamespace(
        id="ev-src",
        rule="可疑外连",
        source_kind="behavior_analysis",
        count=2,
        src_ip=ASSET,
        client=ASSET,
        dst_ips=["8.8.8.8"],
        direction="in→out",
        first_seen=NOW,
        last_seen=NOW,
        created_at=NOW,
    )

    class DB:
        def scalars(self, _stmt: Any) -> Any:
            rows = [hit_as_src, hit_as_dst]

            class R:
                def all(self) -> list[Any]:
                    return rows

            return R()

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *_exc: object) -> bool:
            return False

    monkeypatch.setattr(cand, "SessionLocal", lambda: DB())
    out = cand._recent_rule_hits(ASSET)
    assert {item["event_id"] for item in out} == {"ev-dst", "ev-src"}
    dst_item = next(item for item in out if item["event_id"] == "ev-dst")
    assert dst_item["as_destination"] is True and dst_item["as_source"] is False
    assert dst_item["direction"] == "out→in"
    src_item = next(item for item in out if item["event_id"] == "ev-src")
    assert src_item["as_source"] is True and src_item["as_destination"] is False
    # 目的侧证据排在前面（"它被谁打了"优先）
    assert out[0]["event_id"] == "ev-dst"


class DigestDB:
    """Minimal DB for `enqueue_obs_digest`: first query existing task, then rows."""

    def __init__(self, rows: list[Any]) -> None:
        self.rows = rows
        self.calls = 0
        self.committed = False

    def scalars(self, _stmt: Any) -> Any:
        self.calls += 1
        rows = [] if self.calls == 1 else list(self.rows)

        class R:
            def first(self) -> Any:
                return rows[0] if rows else None

            def all(self) -> list[Any]:
                return rows

            def __iter__(self) -> Any:
                return iter(rows)

        return R()

    def get(self, _model: Any, key: str) -> Any:
        for row in self.rows:
            if row.id == key:
                return row
        return None

    def commit(self) -> None:
        self.committed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False


def test_obs_digest_combines_facts_and_marks_cooldown(
    cand: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [_obs("egress_new", idx="o1"), _obs("profile_anomaly", idx="o2")]
    db = DigestDB(rows)
    monkeypatch.setattr(cand, "SessionLocal", lambda: db)
    fake_queue = FakeQueue()
    monkeypatch.setattr(cand, "queue", fake_queue)
    monkeypatch.setattr(cand, "_recent_rule_hits", lambda *_a, **_k: [])
    monkeypatch.setattr(cand.params, "enabled", lambda: True)

    made = cand.enqueue_obs_digest(client=SimpleNamespace())
    assert made == 1
    assert fake_queue.calls[0]["kind"] == "obs_digest"
    assert fake_queue.calls[0]["hint"]["条目数"] == 2
    assert [x["observation_id"] for x in fake_queue.calls[0]["hint"]["items"]] == ["o1", "o2"]
    assert all(row.last_enqueued_at is not None for row in rows)


def test_escalate_digest_creates_obs_cases_only_for_attention(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue_mod = importlib.import_module("app.analysis.queue")
    parent = SimpleNamespace(
        id="digest-1",
        kind="obs_digest",
        state="claimed",
        hint={
            "items": [
                {"observation_id": "o1", "kind": "egress_new", "subject_kind": "asset", "subject": "10.0.0.5", "strength": 0.6, "facts": {"目标": "1.2.3.4"}},
                {"observation_id": "o2", "kind": "profile_anomaly", "subject_kind": "asset", "subject": "10.0.0.5", "strength": 0.8, "facts": {"风险分": 0.8}},
            ]
        },
        lease_until=None,
        updated_at=NOW,
        note="",
        depth=0,
        window_start=NOW,
        window_end=NOW,
    )

    class DB:
        def get(self, _model: Any, key: str) -> Any:
            return parent if key == "digest-1" else None

        def commit(self) -> None:
            return None

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_exc: object) -> bool:
            return False

    created: list[dict[str, Any]] = []
    monkeypatch.setattr(queue_mod, "SessionLocal", lambda: DB())
    monkeypatch.setattr(queue_mod, "enqueue", lambda **kwargs: created.append(kwargs) or "new")
    monkeypatch.setattr(queue_mod, "bump", lambda *_a, **_k: None)

    out = queue_mod.escalate_digest(SimpleNamespace(), "digest-1", ["o2", "missing"], note="test")
    assert out["ok"] is True
    assert out["accepted"] == 1
    assert parent.state == "done"
    assert created[0]["kind"] == "obs_case"
    assert created[0]["hint"]["observation_id"] == "o2"
    assert created[0]["force"] is True


def test_structure_tasks_become_one_digest(cand: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    db = DigestDB([])  # existing struct_digest → none; _structure_tasks has no row query
    monkeypatch.setattr(cand, "SessionLocal", lambda: db)
    fake_queue = FakeQueue()
    monkeypatch.setattr(cand, "queue", fake_queue)
    monkeypatch.setattr(cand.feedback, "apply", lambda value, *_a, **_k: value)
    monkeypatch.setattr(cand.cold_start_mod, "damped", lambda value, *_a, **_k: value)
    made = cand._structure_tasks(
        {"10.0.0.5": 30},
        {"10.0.0.5": 40},
        1_000.0,
        NOW,
        SimpleNamespace(),
    )
    assert made == 1
    call = fake_queue.calls[0]
    assert call["kind"] == "struct_digest"
    assert call["hint"]["条目数"] == 1
    assert call["hint"]["items"][0]["item_id"].startswith("structure|10.0.0.5|fail_ratio|")
    assert call["force"] is True
