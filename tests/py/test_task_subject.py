"""任务主体资产化（C2）+ coverage 标签修复（C4），2026-10-29 架构整改。

原则：**任务主体 = 监控网段内资产**，外部地址只能当对端/证据。
- 外→内命中：主体是被访问资产，hint 带方向与外部 peer；
- 内→外命中：主体是我方发起资产；
- 外部↔外部：不派工（旧行为会给外部 IP 建任务）；
- 盲区任务保留原主体类型（签名盲区仍是签名，不能一律改 asset）；
- novelty 只给资产/端口/账号，协议/签名不再单独立线索。
"""

from __future__ import annotations

import importlib
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

NETS = ("10.1.1.0/24",)
INTERNAL = "10.1.1.20"
EXTERNAL = "198.51.100.9"


@pytest.fixture()
def cand(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> Any:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("任务主体口径只在 NDR 侧")
    iputil = importlib.import_module("app.iputil")
    monkeypatch.setattr(iputil, "_net_texts", lambda: NETS)
    for attr in ("_cache_at", "_nets_at"):
        monkeypatch.setattr(iputil, attr, 0.0, raising=False)
    mod = importlib.import_module("app.analysis.candidates")
    monkeypatch.setattr(mod.feedback, "apply", lambda s, *_a, **_k: s)
    monkeypatch.setattr(mod.subjects, "staleness", lambda *_a, **_k: 0.5)
    return mod


class EnqueueSpy:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def enqueue(self, **kwargs: Any) -> str:
        self.calls.append(kwargs)
        return "new"


# ---------- C2-1：_task_dict 提成一等字段 ----------


def test_task_dict_exposes_principal_and_affected_assets() -> None:
    queue = importlib.import_module("app.analysis.queue")
    row = SimpleNamespace(
        id="t1",
        kind="hit_cluster",
        strength=0.6,
        priority=60,
        subject_kind="asset",
        subject=INTERNAL,
        dedupe_key="hit_cluster|asset:10.1.1.20|cluster:abc|2026102912#0",
        hint={
            "主体资产": {"kind": "ip", "value": INTERNAL},
            "受影响资产": [{"kind": "ip", "value": INTERNAL}],
            "对端": [EXTERNAL],
            "方向": "out→in",
        },
        window_start=None,
        window_end=None,
        coalesced=0,
        attempts=0,
        depth=0,
        parent_id="",
        state="pending",
        lease_until=None,
        created_at=datetime.now(UTC),
    )
    out = queue._task_dict(row)
    assert out["principal_asset"] == INTERNAL
    assert out["affected_assets"] == [{"kind": "ip", "value": INTERNAL}]
    assert out["direction"] == "out→in"
    assert out["peers"] == [EXTERNAL]
    assert out["feature"] == "cluster:abc"


def test_task_dict_defaults_principal_to_subject() -> None:
    queue = importlib.import_module("app.analysis.queue")
    row = SimpleNamespace(
        id="t2",
        kind="observation",
        strength=0.5,
        priority=50,
        subject_kind="asset",
        subject="www.example.com",
        dedupe_key="observation|asset:www.example.com|egress_new|2026102912#0",
        hint={},
        window_start=None,
        window_end=None,
        coalesced=0,
        attempts=0,
        depth=0,
        parent_id="",
        state="pending",
        lease_until=None,
        created_at=datetime.now(UTC),
    )
    out = queue._task_dict(row)
    assert out["principal_asset"] == "www.example.com"
    assert out["affected_assets"] == []
    assert out["direction"] == ""


# ---------- C2-3：逐条 hit 的主体 ----------


def _digest(**over: Any) -> dict[str, Any]:
    base = {
        "src_ip": EXTERNAL,
        "dst_ips": [INTERNAL],
        "dst_ports": ["22"],
        "rule": "端口扫描",
        "count": 5,
        "first_seen": datetime.now(UTC),
        "last_seen": datetime.now(UTC),
        "direction": "out→in",
        "real_client_ips": [],
    }
    base.update(over)
    return base


def test_hit_subject_is_internal_asset_with_peer(
    cand: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """外→内：主体是被访问资产，hint 同时给方向/对端（中英两套键）。"""
    spy = EnqueueSpy()
    monkeypatch.setattr(cand, "queue", spy)
    result = cand.enqueue_hit(_digest(), "ev-1", None)
    assert result == "new"
    call = spy.calls[0]
    assert call["subject_kind"] == "asset"
    assert call["subject"] == INTERNAL
    assert call["hint"]["方向"] == "out→in"
    assert call["hint"]["direction"] == "out→in"
    assert call["hint"]["peer"] == [EXTERNAL]


def test_hit_subject_is_our_source_when_outbound(cand: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """内→外：主体是我方发起资产，对端是外部目的地。"""
    spy = EnqueueSpy()
    monkeypatch.setattr(cand, "queue", spy)
    cand.enqueue_hit(
        _digest(src_ip=INTERNAL, dst_ips=[EXTERNAL], direction="in→out", real_client_ips=[]),
        "ev-2",
        None,
    )
    call = spy.calls[0]
    assert call["subject_kind"] == "ip"
    assert call["subject"] == INTERNAL
    assert call["hint"]["peer"] == [EXTERNAL]


def test_hit_external_to_external_is_skipped(cand: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """外部↔外部不是我们的资产：不派工（旧行为会给外部 IP 建任务）。"""
    spy = EnqueueSpy()
    monkeypatch.setattr(cand, "queue", spy)
    result = cand.enqueue_hit(
        _digest(src_ip=EXTERNAL, dst_ips=["8.8.8.8"], direction="out→out"), "ev-3", None
    )
    assert result == "skipped"
    assert spy.calls == []


# ---------- C4：coverage 主体类型不能被压成 asset ----------


def test_coverage_task_keeps_subject_kind(cand: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """签名盲区的任务主体类型必须还是 signature（C4 验收）。"""
    spy = EnqueueSpy()
    monkeypatch.setattr(cand, "queue", spy)
    monkeypatch.setattr(
        cand.subjects,
        "coverage",
        lambda **_kw: {
            "items": [
                {"kind": "signature", "subject_kind": "signature", "subject": "sid:2000001"},
            ]
        },
    )
    monkeypatch.setattr(cand.params, "coverage_stale_days", lambda: 7)
    cand.enqueue_coverage(None)
    call = spy.calls[0]
    assert call["kind"] == "coverage"
    assert call["subject_kind"] == "signature"
    assert call["hint"]["reuse_identity"] == "coverage|signature:sid:2000001"


def test_coverage_items_report_their_own_kind() -> None:
    """`subjects.coverage` 的 items[].kind 就是登记类型（不是写死 asset）。"""
    subjects = importlib.import_module("app.analysis.subjects")
    row = SimpleNamespace(
        kind="signature",
        value="sid:2000001",
        first_seen_at=None,
        last_seen_at=datetime.now(UTC),
        seen_count=3,
        analyzed_count=0,
        last_analyzed_at=None,
    )

    class FakeDB:
        def scalar(self, _stmt: Any) -> int:
            return 1

        def scalars(self, stmt: Any) -> Any:
            # never 查询返回这一行，stale 查询返回空
            text = str(stmt)
            rows = [] if "last_analyzed_at IS NOT NULL" in text.upper() else [row]

            class R:
                def all(self) -> list[Any]:
                    return rows

                def __iter__(self) -> Any:
                    return iter(rows)

            return R()

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *_exc: object) -> bool:
            return False

    import app.analysis.subjects as subjects_mod

    old = subjects_mod.SessionLocal
    subjects_mod.SessionLocal = lambda: FakeDB()  # type: ignore[assignment]
    try:
        out = subjects.coverage(days=7)
    finally:
        subjects_mod.SessionLocal = old  # type: ignore[assignment]
    assert out["items"][0]["kind"] == "signature"
    assert out["items"][0]["subject_kind"] == "signature"


# ---------- C3：claim_tasks 带回监控网段 ----------


def test_scope_payload_reports_networks(monkeypatch: pytest.MonkeyPatch) -> None:
    queue = importlib.import_module("app.analysis.queue")
    scope_mod = importlib.import_module("app.ingestion.scope")
    monkeypatch.setattr(scope_mod, "monitored_nets", lambda: ["10.1.1.0/24", "10.2.0.0/24"])
    out = queue._scope_payload()
    assert out["configured"] is True
    assert out["monitored_nets"] == ["10.1.1.0/24", "10.2.0.0/24"]
    assert "监控网段内" in out["note"]

    monkeypatch.setattr(scope_mod, "monitored_nets", list)
    empty = queue._scope_payload()
    assert empty["configured"] is False
    assert empty["monitored_nets"] == []
    assert "未配置" in empty["note"]


# ---------- C2-1：novelty 只管资产/端口/账号 ----------

def test_novelty_skips_protocol_and_signature(cand: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    spy = EnqueueSpy()
    monkeypatch.setattr(cand, "queue", spy)
    now = datetime.now(UTC)
    made = cand._novelty_tasks(
        None,
        [
            ("asset", "10.1.1.20", now),
            ("signature", "sid:1", now),
            ("protocol", "dns", now),
            ("service_port", "10.1.1.20:22", now),
            ("account", "alice", now),
        ],
        now,
        None,
    )
    assert made == 3
    assert [c["subject_kind"] for c in spy.calls] == ["asset", "service_port", "account"]
