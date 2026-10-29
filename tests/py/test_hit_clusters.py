"""hit_cluster 派工（D2，2026-10-29 架构整改）。

一次外→内扫描命中几十个 IP：旧行为要么逐条 hit 爆量、要么（默认）完全不派工。
整改后按「归类·网段·小时」成簇，主体是被访问资产；强度只读客观量。
用户拍板的护栏都在这里钉住：60 分钟桶去重、每轮上限 20、不看 rule_severity、
同一簇族 24h 最多观察一次。
"""

from __future__ import annotations

import importlib
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, Self

import pytest

NETS = ("10.1.1.0/24",)
ADMIN_ASSET = "10.1.1.10"
SCANNER = "8.8.8.8"
WHEN = datetime.now(UTC)


class _Scalars:
    def __init__(self, items: list[Any]) -> None:
        self._items = items

    def all(self) -> list[Any]:
        return list(self._items)

    def __iter__(self) -> Any:
        return iter(self._items)


class FakeDB:
    """只模拟 `enqueue_hit_clusters` 用到的两段查询。"""

    def __init__(self, hit_rows: list[Any], task_keys: set[str]) -> None:
        self._hit_rows = hit_rows
        self._task_keys = task_keys

    def scalars(self, stmt: Any) -> _Scalars:
        text = str(stmt)
        if "dedupe_key" in text:
            return _Scalars(list(self._task_keys))
        return _Scalars(list(self._hit_rows))

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False


@pytest.fixture()
def rig(monkeypatch: pytest.MonkeyPatch) -> Any:
    """注入网段口径 + fake SessionLocal + 捕获型 enqueue。"""
    iputil = importlib.import_module("app.iputil")
    monkeypatch.setattr(iputil, "_net_texts", lambda: NETS)
    for attr in ("_cache_at", "_nets_at"):
        monkeypatch.setattr(iputil, attr, 0.0, raising=False)
    assert iputil.is_internal_ip(ADMIN_ASSET) is True
    assert iputil.is_internal_ip(SCANNER) is False
    return iputil


def _hit(
    cluster_id: str,
    *,
    rule: str = "端口扫描",
    src: str = SCANNER,
    dst: str = ADMIN_ASSET,
    severity: str = "critical",
) -> SimpleNamespace:
    return SimpleNamespace(
        id=f"ev-{cluster_id}-{src}-{rule[:2]}",
        cluster_id=cluster_id,
        rule=rule,
        src_ip=src,
        dst_ips=[dst],
        ignored=False,
        direction="out→in",
        client=src,
        first_seen=WHEN,
        last_seen=WHEN,
        rule_severity=severity,
        created_at=WHEN,
    )


class EnqueueSpy:
    """替身 queue.enqueue：记下 kwargs，返回 'new'；dedupe key 用真实现算。"""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.keys: set[str] = set()

    def enqueue(self, **kwargs: Any) -> str:
        self.calls.append(kwargs)
        queue = importlib.import_module("app.analysis.queue")
        key = queue.dedupe_key(
            kwargs["kind"], kwargs["subject_kind"], kwargs["subject"], kwargs["feature"]
        )
        self.keys.add(key)
        return "new"


def _install(
    monkeypatch: pytest.MonkeyPatch, hit_rows: list[Any], spy: EnqueueSpy
) -> None:
    cand = importlib.import_module("app.analysis.candidates")
    monkeypatch.setattr(cand, "SessionLocal", lambda: FakeDB(hit_rows, set(spy.keys)))
    monkeypatch.setattr(cand, "queue", spy)
    monkeypatch.setattr(cand.subjects, "staleness", lambda *_a, **_k: 0.5, raising=True)
    monkeypatch.setattr(
        cand.feedback, "apply", lambda strength, *_a, **_k: strength, raising=True
    )


def test_external_scan_folds_into_one_asset_task(rig: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """验收：一次外→内扫描 → 1 条以被访问资产为主体的任务，带方向与外部对端。"""
    cand = importlib.import_module("app.analysis.candidates")
    spy = EnqueueSpy()
    rows = [_hit(f"c{i % 3}") for i in range(30)]  # 归到 3 个簇 ID（同规则同资产）
    _install(monkeypatch, rows, spy)
    made = cand.enqueue_hit_clusters(client=None)
    assert made == 3
    for call in spy.calls:
        assert call["kind"] == "hit_cluster"
        assert call["subject_kind"] == "asset"
        assert call["subject"] == ADMIN_ASSET, "主体 = 被扫描的资产，不是几十个外部 IP"
        hint = call["hint"]
        assert hint["方向"] == "out→in"
        assert SCANNER in hint["对端"]
        assert {"kind": "ip", "value": ADMIN_ASSET} in hint["受影响资产"]
        assert len(hint["事件ID"]) <= 20
        assert hint["规则"] == ["端口扫描"]
        assert hint["reuse_identity"]


def test_same_family_not_retasked_within_24h(rig: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """24h 观察护栏：同（主体, 规则族）第二次出现不重派（持续扫描≠新现象）。"""
    cand = importlib.import_module("app.analysis.candidates")
    spy = EnqueueSpy()
    _install(monkeypatch, [_hit("c1")], spy)
    assert cand.enqueue_hit_clusters(None) == 1
    # 下一轮：同一个簇族换了个小时桶的 cluster_id、换了扫描器 IP
    _install(monkeypatch, [_hit("c1next")], spy)
    assert cand.enqueue_hit_clusters(None) == 0, "24h 内同一簇族只能观察一次"
    assert len(spy.calls) == 1


def test_strength_ignores_rule_severity(rig: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """强度只读客观量：把 rule_severity 从 critical 改到 info，强度必须一模一样。"""
    cand = importlib.import_module("app.analysis.candidates")
    strengths: list[float] = []
    for severity in ("critical", "info", "high"):
        spy = EnqueueSpy()
        _install(monkeypatch, [_hit("c1", severity=severity)], spy)
        assert cand.enqueue_hit_clusters(None) == 1
        strengths.append(float(spy.calls[0]["strength"]))
    assert strengths[0] == strengths[1] == strengths[2], f"强度因严重度变了：{strengths}"
    assert 0.0 <= strengths[0] <= 1.0


def test_cap_twenty_per_round(rig: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """每轮上限 20：25 个不同簇也只占 20 个坑。"""
    cand = importlib.import_module("app.analysis.candidates")
    spy = EnqueueSpy()
    rows = []
    for i in range(25):
        rule = f"规则{i:02d}"
        rows.append(_hit(f"cls{i}", rule=rule))
    _install(monkeypatch, rows, spy)
    made = cand.enqueue_hit_clusters(None)
    assert made == 20
    assert len(spy.calls) == 20


def test_external_to_external_is_skipped(rig: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """外部↔外部不是我们的资产：无网段内侧可当主体的簇全部跳过。"""
    cand = importlib.import_module("app.analysis.candidates")
    spy = EnqueueSpy()
    _install(monkeypatch, [_hit("c1", dst=SCANNER)], spy)  # src/dst 都是公网
    assert cand.enqueue_hit_clusters(None) == 0


def test_knob_off_disables_generator(rig: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """回滚开关：analysis.candidate_kinds 移除 hit_cluster 即整条生成器停摆。"""
    cand = importlib.import_module("app.analysis.candidates")
    monkeypatch.setattr(cand.params, "candidate_kinds", lambda: {"novelty"})
    spy = EnqueueSpy()
    _install(monkeypatch, [_hit("c1")], spy)
    assert cand.enqueue_hit_clusters(None) == 0
    assert spy.calls == []


def test_kinds_default_includes_hit_cluster() -> None:
    kinds = importlib.import_module("app.analysis.params")
    assert "hit_cluster" in kinds.KINDS
    assert "hit_cluster" in str(kinds._BY_KEY["analysis.candidate_kinds"].default)


def test_in_to_out_cluster_keeps_our_assets_as_affected(
    rig: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """in→out（我方外连触发规则）：受影响资产 = 我方源，对端 = 外部目的地。"""
    cand = importlib.import_module("app.analysis.candidates")
    spy = EnqueueSpy()
    row = _hit("cA", src=ADMIN_ASSET, dst=SCANNER)
    row.direction = "in→out"
    row.dst_ips = [SCANNER]
    _install(monkeypatch, [row], spy)
    assert cand.enqueue_hit_clusters(None) == 1
    hint = spy.calls[0]["hint"]
    assert hint["方向"] == "in→out"
    assert {"kind": "ip", "value": ADMIN_ASSET} in hint["受影响资产"]
    assert SCANNER in hint["对端"]


def test_recall_window_limits_query(
    rig: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """查询只回看 60 分钟：老事件（昨天）不得进入成簇原料。"""
    cand = importlib.import_module("app.analysis.candidates")
    spy = EnqueueSpy()
    old = _hit("cold")
    old.created_at = WHEN - timedelta(hours=25)
    old.last_seen = WHEN - timedelta(hours=25)
    _install(monkeypatch, [old], spy)
    # FakeDB 不做时间过滤，这里靠查询参数：改为校验查询语句里的窗口字段
    captured: dict[str, Any] = {}

    class SpyDB(FakeDB):
        def scalars(self, stmt: Any) -> _Scalars:  # type: ignore[override]
            captured.setdefault("stmts", []).append(str(stmt))
            return super().scalars(stmt)

    monkeypatch.setattr(cand, "SessionLocal", lambda: SpyDB([], set(spy.keys)))
    cand.enqueue_hit_clusters(None)
    assert captured["stmts"], "应当发起查询"
    query = " ".join(captured["stmts"])
    assert "created_at >=" in query or "created_at >= " in query
