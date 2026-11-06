"""hit_cluster 派工（D2，2026-10-29；2026-11 改为小时摘要）。

一次外→内扫描命中几十个 IP：旧行为要么逐条 hit 爆量、要么（默认）完全不派工。
整改后按「归类·网段·小时」成簇，主体是被访问资产；强度只读客观量。

2026-11 成本整改：每个簇直接起完整 agent 变成「每小时一条 `hit_digest`」，
由便宜闸门挑出需要完整调查的簇，只有被点名的才生成 `hit_case`。
用户拍板的护栏继续钉住：60 分钟回看、每小时一条、单条最多 30 个簇、
不看 rule_severity、同一簇族 24h 最多观察一次。
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

    def first(self) -> Any:
        return self._items[0] if self._items else None

    def __iter__(self) -> Any:
        return iter(self._items)


class FakeDB:
    """只模拟 `enqueue_hit_digest` 用到的四段查询（按 SQL 文本分流）。"""

    def __init__(
        self,
        hit_rows: list[Any],
        task_families: set[str] | None = None,
        digest_hints: list[dict[str, Any]] | None = None,
        existing: Any = None,
    ) -> None:
        self._hit_rows = hit_rows
        self._task_families = task_families or set()
        self._digest_hints = digest_hints or []
        self._existing = existing

    def scalars(self, stmt: Any) -> _Scalars:
        # 参数是绑定占位符，SQL 文本里看不到 kind 的字面值；按选择列区分查询。
        text = str(stmt)
        if "hit_events" in text:
            return _Scalars(list(self._hit_rows))
        # 同一小时是否已有摘要：select(AnalysisTask) 展开成全部列
        if "analysis_tasks.id" in text:
            return _Scalars([self._existing] if self._existing is not None else [])
        # 已派工/已完成的 hit_cluster/hit_case → hint.reuse_identity
        if "analysis_tasks.hint ->>" in text:
            return _Scalars(list(self._task_families))
        # 已完成分流的 hit_digest.hint（闸门看过哪些条目）
        if "analysis_tasks.hint" in text:
            return _Scalars(list(self._digest_hints))
        return _Scalars([])

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
        self.families: set[str] = set()
        self.bumps: list[str] = []

    def enqueue(self, **kwargs: Any) -> str:
        self.calls.append(kwargs)
        queue = importlib.import_module("app.analysis.queue")
        key = queue.dedupe_key(
            kwargs["kind"], kwargs["subject_kind"], kwargs["subject"], kwargs["feature"]
        )
        self.keys.add(key)
        hint = kwargs.get("hint") or {}
        items = hint.get("items")
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and str(item.get("reuse_identity") or ""):
                    self.families.add(str(item["reuse_identity"]))
        elif str(hint.get("reuse_identity") or ""):
            self.families.add(str(hint["reuse_identity"]))
        return "new"

    def bump(self, _client: Any, key: str, _amount: int = 1) -> None:
        self.bumps.append(key)


def _install(
    monkeypatch: pytest.MonkeyPatch,
    hit_rows: list[Any],
    spy: EnqueueSpy,
    *,
    task_families: set[str] | None = None,
    digest_hints: list[dict[str, Any]] | None = None,
    existing: Any = None,
) -> None:
    cand = importlib.import_module("app.analysis.candidates")
    monkeypatch.setattr(
        cand,
        "SessionLocal",
        lambda: FakeDB(
            hit_rows,
            task_families if task_families is not None else set(spy.families),
            digest_hints,
            existing,
        ),
    )
    monkeypatch.setattr(cand, "queue", spy)
    monkeypatch.setattr(cand.subjects, "staleness", lambda *_a, **_k: 0.5, raising=True)
    monkeypatch.setattr(
        cand.feedback, "apply", lambda strength, *_a, **_k: strength, raising=True
    )
    monkeypatch.setattr(
        cand.suppression, "decide_task", lambda **_k: None, raising=True
    )


def test_external_scan_folds_into_one_hourly_digest(
    rig: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """验收：一次外→内扫描 → 1 条摘要，条目主体是被访问资产，带方向与外部对端。"""
    cand = importlib.import_module("app.analysis.candidates")
    spy = EnqueueSpy()
    rows = [_hit(f"c{i % 3}") for i in range(30)]  # 归到 3 个簇 ID（同规则同资产）
    _install(monkeypatch, rows, spy)
    made = cand.enqueue_hit_digest(client=None)
    assert made == 1
    call = spy.calls[0]
    assert call["kind"] == "hit_digest"
    assert call["subject_kind"] == "digest"
    assert "条目数" in call["hint"] and call["hint"]["条目数"] == 3
    items = call["hint"]["items"]
    for item in items:
        assert item["subject"] == ADMIN_ASSET, "主体 = 被扫描的资产，不是几十个外部 IP"
        assert item["kind"] == "hit_cluster"
        assert item["subject_kind"] == "asset"
        facts = item["facts"]
        assert facts["方向"] == "out→in"
        assert SCANNER in facts["对端"]
        case_hint = item["case_hint"]
        assert {"kind": "ip", "value": ADMIN_ASSET} in case_hint["受影响资产"]
        assert len(case_hint["事件ID"]) <= 20
        assert case_hint["规则"] == ["端口扫描"]
        assert item["reuse_identity"]
    assert call["force"] is True


def test_same_family_not_retasked_within_24h(
    rig: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """24h 观察护栏：同（主体, 规则族）第二次出现不重派（持续扫描≠新现象）。"""
    cand = importlib.import_module("app.analysis.candidates")
    spy = EnqueueSpy()
    _install(monkeypatch, [_hit("c1")], spy)
    assert cand.enqueue_hit_digest(None) == 1
    # 下一轮：同一个簇族换了个小时桶的 cluster_id、换了扫描器 IP
    _install(monkeypatch, [_hit("c1next")], spy)
    assert cand.enqueue_hit_digest(None) == 0, "24h 内同一簇族只能观察一次"
    assert len(spy.calls) == 1


def test_completed_digest_also_guards_families(
    rig: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """已完成分流的摘要也算“看过”：闸门没点名的正常簇不能每小时重复展示。"""
    cand = importlib.import_module("app.analysis.candidates")
    first = EnqueueSpy()
    _install(monkeypatch, [_hit("c1")], first)
    assert cand.enqueue_hit_digest(None) == 1
    family = next(iter(first.families))
    # 下一小时：同一个簇族换了 cluster_id，但上一小时的摘要已经把它交给闸门看过
    digest_hints = [{"items": [{"item_id": "hit|c1", "reuse_identity": family}]}]
    spy = EnqueueSpy()
    _install(monkeypatch, [_hit("c1next")], spy, digest_hints=digest_hints)
    assert cand.enqueue_hit_digest(None) == 0
    assert spy.calls == []


def test_strength_ignores_rule_severity(rig: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """强度只读客观量：把 rule_severity 从 critical 改到 info，强度必须一模一样。"""
    cand = importlib.import_module("app.analysis.candidates")
    strengths: list[float] = []
    for severity in ("critical", "info", "high"):
        spy = EnqueueSpy()
        _install(monkeypatch, [_hit("c1", severity=severity)], spy)
        assert cand.enqueue_hit_digest(None) == 1
        strengths.append(float(spy.calls[0]["strength"]))
    assert strengths[0] == strengths[1] == strengths[2], f"强度因严重度变了：{strengths}"
    assert 0.0 <= strengths[0] <= 1.0


def test_digest_caps_items_per_hour(rig: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """单条摘要最多 30 个簇：35 个不同簇也只列 30 个，其余留给下一小时。"""
    cand = importlib.import_module("app.analysis.candidates")
    spy = EnqueueSpy()
    rows = [_hit(f"cls{i}", rule=f"规则{i:02d}") for i in range(35)]
    _install(monkeypatch, rows, spy)
    made = cand.enqueue_hit_digest(None)
    assert made == 1
    assert len(spy.calls[0]["hint"]["items"]) == 30


def test_one_digest_per_hour(rig: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """同一小时已经排过摘要就不重复建：新簇进入下一个小时。"""
    cand = importlib.import_module("app.analysis.candidates")
    spy = EnqueueSpy()
    _install(monkeypatch, [_hit("c1")], spy, existing=SimpleNamespace(id="digest-1"))
    assert cand.enqueue_hit_digest(None) == 0
    assert spy.calls == []


def test_suppressed_cluster_never_reaches_gate(
    rig: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """已有抑制覆盖的簇不占摘要位置，也不再消耗一次闸门调用。"""
    cand = importlib.import_module("app.analysis.candidates")
    spy = EnqueueSpy()
    _install(monkeypatch, [_hit("c1")], spy)
    noted: list[str] = []
    monkeypatch.setattr(
        cand.suppression, "decide_task", lambda **_k: SimpleNamespace(id="sup-1"), raising=True
    )
    monkeypatch.setattr(
        cand.suppression, "note_hit", lambda sup_id: noted.append(str(sup_id)), raising=True
    )
    assert cand.enqueue_hit_digest(None) == 0
    assert spy.calls == []
    assert noted == ["sup-1"]


def test_external_to_external_is_skipped(rig: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """外部↔外部不是我们的资产：无网段内侧可当主体的簇全部跳过。"""
    cand = importlib.import_module("app.analysis.candidates")
    spy = EnqueueSpy()
    _install(monkeypatch, [_hit("c1", dst=SCANNER)], spy)  # src/dst 都是公网
    assert cand.enqueue_hit_digest(None) == 0


def test_knob_off_disables_generator(rig: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """回滚开关：analysis.candidate_kinds 移除 hit_cluster 即整条生成器停摆。"""
    cand = importlib.import_module("app.analysis.candidates")
    monkeypatch.setattr(cand.params, "candidate_kinds", lambda: {"novelty"})
    spy = EnqueueSpy()
    _install(monkeypatch, [_hit("c1")], spy)
    assert cand.enqueue_hit_digest(None) == 0
    assert spy.calls == []


def test_kinds_default_includes_hit_cluster() -> None:
    kinds = importlib.import_module("app.analysis.params")
    assert "hit_cluster" in kinds.KINDS
    assert "hit_digest" in kinds.KINDS
    assert "hit_case" in kinds.KINDS
    assert "hit_cluster" in str(kinds._BY_KEY["analysis.candidate_kinds"].default)


def test_lateral_cluster_principal_is_source_actor(
    rig: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """in→in 横向扫描：主体必须是发起方，不能取“最小内网地址”把受害者当攻击者。"""
    cand = importlib.import_module("app.analysis.candidates")
    spy = EnqueueSpy()
    actor = "10.1.1.20"
    victim = "10.1.1.10"  # 地址比 actor 小：旧实现会错选成主体
    row = _hit("cL", src=actor, dst=victim)
    row.direction = "in→in"
    row.client = actor
    _install(monkeypatch, [row], spy)
    assert cand.enqueue_hit_digest(None) == 1
    item = spy.calls[0]["hint"]["items"][0]
    assert item["subject"] == actor
    case_hint = item["case_hint"]
    assert case_hint["主体角色"] == "actor"
    assert case_hint["actor_asset"] == {"kind": "ip", "value": actor}
    assert {"kind": "ip", "value": victim} in case_hint["victim_assets"]
    assert {"kind": "ip", "value": victim} in case_hint["受影响资产"]


def test_dns_cluster_family_separates_domains(
    rig: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """同源/同规则的 DNS 簇必须按主域分族，不能把 CDN 误报复用到另一个域。"""
    cand = importlib.import_module("app.analysis.candidates")
    spy = EnqueueSpy()
    first = _hit("cDns1", src=ADMIN_ASSET, dst=SCANNER)
    first.direction = "in→out"
    first.evidence = [
        {"query": "aafd8cefac83e7667d4b1020157fd6db.v.smtcdns.com"}
    ]
    second = _hit("cDns2", src=ADMIN_ASSET, dst=SCANNER)
    second.direction = "in→out"
    second.evidence = [
        {"query": "32849170ffb36267323742377076e244.rdt.tfogc.com"}
    ]
    _install(monkeypatch, [first, second], spy)
    assert cand.enqueue_hit_digest(None) == 1
    items = spy.calls[0]["hint"]["items"]
    assert len(items) == 2
    assert len(spy.families) == 2, "不同 DNS 主域不能共享同一个 reuse_identity"
    domains = {tuple(item["case_hint"]["dns_domains"]) for item in items}
    assert domains == {("smtcdns.com",), ("tfogc.com",)}


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
    assert cand.enqueue_hit_digest(None) == 1
    case_hint = spy.calls[0]["hint"]["items"][0]["case_hint"]
    assert case_hint["方向"] == "in→out"
    assert {"kind": "ip", "value": ADMIN_ASSET} in case_hint["受影响资产"]
    assert SCANNER in case_hint["对端"]


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
    cand.enqueue_hit_digest(None)
    assert captured["stmts"], "应当发起查询"
    query = " ".join(captured["stmts"])
    assert "created_at >=" in query or "created_at >= " in query
