"""智能体驱动分析机制的守卫（方案与决策见 `docs/ndr-analysis-mechanism.md`）。

要钉住的是"这次改造没偷偷退回老样子"。六条红线：

1. **不替智能体下判断**：任务载荷里不得出现严重度/结论字段；
2. **队列有边界**：容量、租约、任务有效期与追问深度在服务端强制；领取额度不设上限；
3. **门铃不含数据**：载荷只能是队列状况（含了事件数据，智能体就又变成被动解释器）；
4. **每事件零 I/O**：候选累积器不得碰数据库/网络（否则 240 事件/秒会把检测器压垮）；
5. **回滚开关存在**：关掉 `analysis.enabled` 就回到"摘要直接推送"的老契约；
6. **原始数据不受影响**：派工与抑制只改变"要不要打扰分析"。

这些守卫大部分是**纯函数 + 源码断言**：队列行为要真库真 Redis，CI 里没有；
而"改造有没有被改回去"这类约束，源码断言反而更稳（不依赖环境）。
"""

from __future__ import annotations

import importlib
import inspect
import pathlib
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _mod(name: str) -> Any:
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError:  # pragma: no cover - agent 侧已无 Python 后端
        pytest.skip(f"该栈没有 {name}（属 NDR 侧）")


@pytest.fixture()
def cand() -> Any:
    return _mod("app.analysis.candidates")


@pytest.fixture()
def queue_mod() -> Any:
    return _mod("app.analysis.queue")


@pytest.fixture()
def params_mod() -> Any:
    return _mod("app.analysis.params")


# ===== ① 客观强度：取最大不求和（求和会重演"三个弱信号≈一个强信号"）=====


def test_strength_takes_max_not_sum(cand: Any) -> None:
    assert cand.combined_strength(0.3, 0.2, 0.1) == 0.3
    assert cand.combined_strength(0.9, 0.1) == 0.9
    assert cand.combined_strength() == 0.0


def test_strength_clamps_out_of_range(cand: Any) -> None:
    assert cand.combined_strength(5.0, -3.0) == 1.0
    assert cand.combined_strength(-1.0) == 0.0


def test_significance_strength_is_monotonic_in_p(cand: Any) -> None:
    """p 越小越显著；p=1（完全不显著）必须是 0 分。"""
    strong = cand.significance_strength(1e-8)
    weak = cand.significance_strength(0.01)
    assert strong > weak
    assert strong == 1.0
    assert cand.significance_strength(1.0) == 0.0
    assert cand.significance_strength("坏值") == 0.0  # 脏值不抛异常


def test_rarity_decays_with_seen_count(cand: Any) -> None:
    assert cand.rarity_strength(0, first_seen=True) == 1.0
    assert cand.rarity_strength(2, first_seen=False) == 0.4
    assert cand.rarity_strength(9999, first_seen=False) == 0.1
    assert cand.rarity_strength(None, first_seen=False) == 0.4  # 脏计数不炸


def test_scale_strength_is_log_capped(cand: Any) -> None:
    assert cand.scale_strength(1) == 0.0
    assert cand.scale_strength(10) < 0.3
    assert cand.scale_strength(10**9) == 1.0  # 上限封顶，规模不该无限放大分数


# ===== ② 去重键：同现象同桶只一条 =====


def test_dedupe_key_same_bucket_same_key(queue_mod: Any) -> None:
    ts = datetime(2026, 10, 23, 9, 5, tzinfo=UTC)
    later = datetime(2026, 10, 23, 9, 55, tzinfo=UTC)
    key = queue_mod.dedupe_key("shift", "ip", "10.0.0.5", "conn_count", ts)
    assert key == queue_mod.dedupe_key("shift", "ip", "10.0.0.5", "conn_count", later)
    # 换特征 / 换对象 / 换类型都必须不同键（否则不同现象会互相吞掉）
    assert key != queue_mod.dedupe_key("shift", "ip", "10.0.0.5", "distinct_dst_ips", ts)
    assert key != queue_mod.dedupe_key("shift", "ip", "10.0.0.6", "conn_count", ts)
    assert key != queue_mod.dedupe_key("hit", "ip", "10.0.0.5", "conn_count", ts)


def test_coverage_bucket_is_daily(queue_mod: Any) -> None:
    """盲区一天提醒一次就够：小时桶会让同一盲区刷出 24 条任务。"""
    morning = datetime(2026, 10, 23, 1, 0, tzinfo=UTC)
    evening = datetime(2026, 10, 23, 23, 0, tzinfo=UTC)
    assert queue_mod.dedupe_key("coverage", "asset", "10.0.0.9", "coverage", morning) == (
        queue_mod.dedupe_key("coverage", "asset", "10.0.0.9", "coverage", evening)
    )


# ===== ③ 任务载荷不带威胁语义（D2：判断权在智能体）=====


def test_task_payload_has_no_severity_field(queue_mod: Any) -> None:
    row = _task_row()
    out = queue_mod._task_dict(row)
    assert "severity" not in out
    assert "verdict" not in out
    want = {"id", "kind", "strength", "subject", "feature", "hint"}
    assert want <= set(out)
    assert out["feature"] == "conn_count"
    assert "suggested_tools" not in out and "suggested_tools" not in out["hint"], (
        "NDR 只派元数据，不替智能体规划取数工具"
    )


def test_task_payload_exposes_only_objective_feature(queue_mod: Any) -> None:
    """feature 只用于智能体侧结论复用身份，不把 severity/verdict 偷渡进任务。"""
    args = ("hit", "ip", "10.0.0.5")
    assert queue_mod._feature_of("hit|ip:10.0.0.5|rule|with|pipe|2026102309#0", *args) == "rule|with|pipe"
    assert queue_mod._feature_of("hit|ip:10.0.0.5|-|2026102309#0", *args) == ""
    assert queue_mod._feature_of("malformed", *args) == ""


def test_confidence_keeps_fraction(monkeypatch: pytest.MonkeyPatch) -> None:
    """0.9 的置信度必须原样到达数据库写入层，不能被 int 截成 0。"""
    ndr_tools = _mod("app.mcp.ndr_tools")

    assert ndr_tools._bounded_float(0.9, default=0.0, lo=0.0, hi=1.0) == 0.9
    assert ndr_tools._bounded_float("0.42", default=0.0, lo=0.0, hi=1.0) == 0.42
    assert ndr_tools._bounded_float(3, default=0.0, lo=0.0, hi=1.0) == 1.0
    assert ndr_tools._bounded_float(None, default=0.0, lo=0.0, hi=1.0) == 0.0

    seen: dict[str, Any] = {}

    def complete(_client: Any, _task_id: str, **kwargs: Any) -> dict[str, Any]:
        seen.update(kwargs)
        return {"ok": True}

    monkeypatch.setattr(ndr_tools, "_client", lambda: None)
    monkeypatch.setattr(ndr_tools.analysis_queue, "complete_task", complete)
    result = ndr_tools._complete_task(
        {"task_id": "t-confidence", "verdict": "true_positive", "confidence": 0.9}
    )
    assert result["ok"] is True
    assert seen["confidence"] == 0.9


def _task_row() -> Any:
    from types import SimpleNamespace

    return SimpleNamespace(
        id="t-1",
        dedupe_key="shift|ip:10.0.0.5|conn_count|2026102309#0",
        kind="shift",
        strength=0.72,
        priority=72,
        subject_kind="ip",
        subject="10.0.0.5",
        window_start=None,
        window_end=None,
        hint={"事实": "conn_count 本窗口=42，历史均值=6"},
        coalesced=2,
        attempts=0,
        depth=0,
        parent_id="",
        state="pending",
        lease_until=None,
        created_at=datetime(2026, 10, 23, 9, 0, tzinfo=UTC),
    )


# ===== ④ 门铃只能是"队列状况"，不得夹带事件数据 =====


def test_doorbell_payload_shape_is_minimal(queue_mod: Any) -> None:
    """门铃载荷的键必须是固定白名单。加了任何事件字段，就等于回到推送老路。"""
    src = inspect.getsource(queue_mod.doorbell_payload)
    for key in ("queue_len", "top_kind", "max_strength", "watermark", "ts"):
        assert f'"{key}"' in src, f"门铃缺字段 {key}"
    # 门铃只能带队列状况：出现任何"事件内容"字段就等于回到推送老路
    for forbidden in ("digest", "evidence", "severity", "src_ip", '"rule"', "samples"):
        assert forbidden not in src, f"门铃不该带 {forbidden}"
    # 键集合必须正好是那五个（多加一个字段就是往数据方向滑）
    body = src[src.index("return {") :]
    keys = {
        k for k in ("queue_len", "top_kind", "max_strength", "watermark", "ts") if f'"{k}"' in body
    }
    assert keys == {"queue_len", "top_kind", "max_strength", "watermark", "ts"}


def test_doorbell_coalesces_and_jumps_on_empty_to_nonempty(queue_mod: Any) -> None:
    class FakeRedis:
        def __init__(self) -> None:
            self.store: dict[str, str] = {}

        def get(self, key: str) -> str | None:
            return self.store.get(key)

        def set(self, key: str, value: str, nx: bool = False, ex: int = 0) -> bool:
            if nx and key in self.store:
                return False
            self.store[key] = value
            return True

        def delete(self, key: str) -> int:
            return self.store.pop(key, None) is not None and 1 or 0

    fake = FakeRedis()
    payload = {"queue_len": 3, "top_kind": "shift", "max_strength": 0.8}
    assert queue_mod.should_ring(fake, payload) is True, "队列首次非空要立即叫醒"
    assert queue_mod.should_ring(fake, payload) is False, "冷却期内不重复按门铃"
    assert queue_mod.should_ring(fake, {"queue_len": 0}) is False, "空队列不该按门铃"


def test_send_doorbell_posts_only_the_doorbell() -> None:
    """推送通道复用老地址/令牌，但载荷只能是 `{"doorbell": ...}`。"""
    push = _mod("app.detector.push")
    src = inspect.getsource(push.send_doorbell)
    assert 'json={"doorbell": payload}' in src
    assert "build_items" not in src, "门铃不得再夹带摘要条目"


# ===== ⑤ 每事件零 I/O + 累积器必须被清空 =====


def test_collector_observe_does_no_io(cand: Any) -> None:
    src = inspect.getsource(cand.Collector)
    for forbidden in ("SessionLocal", "db.", "client", "requests", "httpx", "redis"):
        assert forbidden not in src, f"累积器不该做 I/O，却出现了 {forbidden}"


def test_flush_resets_collector_even_on_failure(cand: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """常驻进程里累积器不清空就是内存泄漏；落库失败也必须清。"""
    collector = cand.Collector()
    collector.seen.setdefault("asset", set()).add("10.0.0.5")

    class _Boom:
        def __enter__(self) -> Any:
            raise RuntimeError("pg down")

        def __exit__(
            self,
            exc_type: object,
            exc_value: object,
            tb: object,
        ) -> bool:
            return False

    monkeypatch.setattr(cand, "SessionLocal", _Boom)
    monkeypatch.setattr(cand, "queue", SimpleNamespaceBump())
    out = cand.flush(collector, client=None)
    assert collector.seen == {}, "flush 后必须清空累积器"
    assert out["novelty"] == 0


class SimpleNamespaceBump:
    """替身：只用到 bump()，避免测试真连 Redis。"""

    @staticmethod
    def bump(client: Any, field: str, count: int = 1) -> None:
        return None

    @staticmethod
    def enqueue(**kwargs: Any) -> str:
        return "skipped"


# ===== ⑥ 领取不设额度限制（领取节奏由智能体决定）=====


def test_claim_has_no_quota_gate(queue_mod: Any) -> None:
    """领取必须直接按请求数量捞任务：不再有小时额度、保留名额或并发额度闸门。"""
    src = inspect.getsource(queue_mod.claim_tasks)
    for forbidden in ("_budget", "rate_per_token_hour", "rate_total_hour",
                      "reserved_slots", "reserved_min_strength", "max_inflight"):
        assert forbidden not in src, f"claim_tasks 仍包含额度限制：{forbidden}"
    assert "_pick(" in src, "领取应直接按请求数量/筛选条件取任务"


def test_queue_policy_reads_are_clamped(params_mod: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """存储/保留期参数仍要有区间夹紧（脏值不能把队列容量或 TTL 弄成 0）。"""
    monkeypatch.setattr(params_mod, "rc_get", lambda key, default=None: 999999)
    assert params_mod.queue_capacity() <= 200000  # 上限夹紧
    monkeypatch.setattr(params_mod, "rc_get", lambda key, default=None: 0)
    assert params_mod.queue_capacity() >= 10, "队列容量不能是 0"
    assert params_mod.pending_ttl_hours() >= 1


def test_queue_overflow_is_never_silent(queue_mod: Any) -> None:
    """队列满的三条路都要计数：合并、挤掉、丢弃 —— 界面看得见才有得调。"""
    src = inspect.getsource(queue_mod.enqueue)
    for counter in ("merged", "superseded", "dropped_overflow", "candidate_error"):
        assert counter in src, f"缺少 {counter} 计数（不静默丢是这次改造的前提）"


# ===== ⑦ 回滚开关与热路径接线 =====


def test_runner_wiring_and_rollback_switch() -> None:
    runner = _mod("app.detector.runner")
    src = inspect.getsource(runner)
    assert "candidates.enqueue_shift" in src
    assert "candidates.enqueue_hit" in src
    assert "_analysis_round(" in src
    # 回滚开关：关掉 analysis.enabled 就恢复"摘要投递"
    assert "if analysis_params.enabled():" in src
    assert "digest_q.push(" in src
    # 派工机制异常不能影响检测
    assert "派工机制本轮失败" in src


def test_analysis_rest_surface_is_registered() -> None:
    """前端要"完备 API"：队列/详情/结论/统计/覆盖率/清单/人工派工/参数读写都得在。"""
    fastapi_app = _mod("app.main").app
    paths = set(fastapi_app.openapi()["paths"])
    want = {
        "/api/analysis/tasks",
        "/api/analysis/tasks/{task_id}",
        "/api/analysis/results",
        "/api/analysis/stats",
        "/api/analysis/coverage",
        "/api/analysis/inventory",
        "/api/analysis/config",
        "/api/analysis/config/reset",
    }
    assert not want - paths, f"缺接口：{want - paths}"


def test_mcp_tools_are_exposed_with_explicit_params() -> None:
    """MCP 的 inputSchema 由函数签名推导：必须显式形参、且每个工具都有 desc/params。"""
    server = _mod("app.mcp.server")
    tools = _mod("app.mcp.ndr_tools")
    names = (
        "claim_tasks",
        "complete_task",
        "defer_task",
        "task_stats",
        "asset_map",
        "coverage_report",
    )
    funcs = {f.__name__: f for f in server._NDR_TOOL_FUNCS}
    for name in names:
        fn = funcs.get(name)
        assert fn is not None, f"MCP 服务层没注册 {name}"
        params = inspect.signature(fn).parameters
        assert not any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()), (
            f"{name} 用了 **kwargs，MCP 会把它当成单个必填参数"
        )
        spec = tools.TOOLS.get(name) or {}
        assert spec.get("desc"), f"{name} 缺描述"
        assert spec.get("params"), f"{name} 缺参数说明"


def test_suppression_submission_needs_freshly_fetched_refs() -> None:
    """伪造证据引用换不到抑制：`_valid_refs` 必须是本会话真取回过的（关键防线）。

    校验点在**统一提交实现** `_apply_suppression`（`complete_task` 内联与独立工具
    `submit_suppression` 共用一份），所以这里对行为断言，而不是对某个入口的源码断言。
    """
    tools = _mod("app.mcp.ndr_tools")
    body = {
        "name": "t",
        "match": {
            "logic": "and",
            "rules": [
                {"field": "src_ip", "op": "eq", "value": "10.1.2.3"},
                {"field": "signature_id", "op": "eq", "value": "9110004"},
            ],
        },
        "reason_code": "known_service",
        "evidence_refs": ["es:idx/forged"],
        "confidence": 0.9,
    }
    out = tools._apply_suppression(  # pyright: ignore[reportPrivateUsage]
        body,
        token="t",
        refs=body["evidence_refs"],
        valid_refs={"es:idx/real"},
        tool_usage={"search_events": 1, "net_flows": 2},
    )
    assert "field_errors" in out, "伪造引用必须被拒"
    assert "没真取回过" in out["field_errors"][0]["msg"]
    # 两个入口都要走这份实现（内联与独立提交不能各写一套）
    assert "_apply_suppression(" in inspect.getsource(tools._complete_task)
    assert "_apply_suppression(" in inspect.getsource(tools._submit_suppression)


def test_followup_depth_is_capped(queue_mod: Any) -> None:
    """追问可以派生，但深度与单次条数都有上限，超限要说明原因而不是静默丢。"""
    src = inspect.getsource(queue_mod.add_followups)
    assert "followup_depth" in src or "max_depth" in src
    assert "rejected" in src
    assert "父任务不存在" in src


# ===== ⑧ P4 反馈学习：结论驱动强度 + 误抑制回弹 =====


def test_feedback_factor_decays_by_count_not_ratio() -> None:
    """按"误报次数"分级衰减：新对象只有 1 条误报记录时不该直接压到地板。"""
    fb = _mod("app.analysis.feedback")
    assert fb._factor(1, 0) == 0.85
    assert fb._factor(2, 0) == 0.7
    assert fb._factor(5, 0) == 0.4
    assert fb._factor(0, 0) == 1.0


def test_feedback_true_positive_overrides_decay() -> None:
    """判真过就该加权回来：真凭据优先于历史误报。"""
    fb = _mod("app.analysis.feedback")
    assert fb._factor(9, 1) >= 1.25


def test_feedback_factor_is_bounded() -> None:
    fb = _mod("app.analysis.feedback")
    assert fb._factor(999, 0) >= 0.4, "只衰减不否决：清零等于 NDR 又替智能体判断"
    assert fb._factor(0, 999) <= 1.6, "加权也要有上限，否则一个真阳性就永久置顶"


def test_feedback_apply_clamps_to_unit_range() -> None:
    fb = _mod("app.analysis.feedback")
    assert fb.apply(0.8, "shift", "10.0.0.5", table={("10.0.0.5", "shift"): 0.5}) == 0.4
    assert fb.apply(0.8, "shift", "10.0.0.5", table={("10.0.0.5", "shift"): 3.0}) == 1.0
    assert fb.apply(0.8, "shift", "10.0.0.9", table={}) == 0.8, "无历史就不动"


def test_feedback_params_are_whitelisted() -> None:
    params_mod = _mod("app.analysis.params")
    keys = {k.key for k in params_mod.KNOBS}
    for key in (
        "analysis.feedback_enabled",
        "analysis.feedback_days",
        "analysis.feedback_tp_factor",
    ):
        assert key in keys, f"{key} 不在可调参数里（界面改不了）"
    assert set(params_mod.effective()) == keys, "effective 要覆盖全部参数"


def test_note_verdict_only_rebounds_on_true_positive(monkeypatch: pytest.MonkeyPatch) -> None:
    """回弹只由真阳性触发；其它结论只失效系数缓存。"""
    fb = _mod("app.analysis.feedback")
    calls: list[tuple[str, str]] = []
    sup = _mod("app.detector.suppression")
    monkeypatch.setattr(
        sup, "rebound_for_subject", lambda kind, subject: calls.append((kind, subject)) or 2
    )
    monkeypatch.setattr(fb, "invalidate", lambda: None)
    assert fb.note_verdict("shift", "10.0.0.5", "false_positive") == {"rebound": 0}
    assert calls == [], "误报结论不该撤销抑制"
    assert fb.note_verdict("shift", "10.0.0.5", "true_positive") == {"rebound": 2}
    assert calls == [("shift", "10.0.0.5")]


def test_rebound_matches_only_that_source_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """回弹要保守：只撤条件树里**明确写了该 src_ip** 的条目。

    条件树是 v2 的匹配口径，所以回弹改成"遍历条件树的叶子找 src_ip"；
    这里用一个真条件树验证：命中该 IP 的条目被撤，只涉及别的 IP 的不动。
    """
    sup = _mod("app.detector.suppression")

    def tree(ip: str) -> dict[str, Any]:
        return {
            "logic": "and",
            "rules": [
                {"field": "src_ip", "op": "eq", "value": ip},
                {"field": "signature_id", "op": "eq", "value": "9110004"},
            ],
        }

    mine = SimpleNamespace(
        id="a",
        name="mine",
        match=tree("10.1.2.3"),
        enabled=True,
        revoked_at=None,
        revoke_reason="",
    )
    other = SimpleNamespace(
        id="b",
        name="other",
        match=tree("10.9.9.9"),
        enabled=True,
        revoked_at=None,
        revoke_reason="",
    )
    saved: list[Any] = []

    class _Sess:
        def __enter__(self) -> Any:
            return self

        def __exit__(self, *exc: object) -> bool:
            return False

        def scalars(self, stmt: Any) -> Any:
            return SimpleNamespace(all=lambda: [mine, other])

        def commit(self) -> None:
            saved.extend([mine, other])

    monkeypatch.setattr(sup, "SessionLocal", _Sess)
    monkeypatch.setattr(sup, "invalidate_cache", lambda: None)
    assert sup.rebound_for_subject("shift", "10.1.2.3") == 1
    assert mine.enabled is False and other.enabled is True, "不得顺带放开无关抑制"
    assert "真阳性" in mine.revoke_reason
    assert sup.rebound_for_subject("shift", "") == 0, "空对象直接返回 0（不该打库）"


def test_complete_task_reports_rebound_and_counters() -> None:
    """交回结论必须把回弹结果带回去并计数（全自动抑制的自动纠错路径要可见）。"""
    queue_mod = _mod("app.analysis.queue")
    src = inspect.getsource(queue_mod.complete_task)
    assert "feedback.note_verdict" in src
    assert "suppression_rebound" in src
    assert "reused_from" in src
    assert "if not reused_from" in src, "复用旧真阳性不能当新证据触发抑制回弹"
    assert "feedback" in inspect.getsource(queue_mod)


def test_every_candidate_kind_uses_feedback() -> None:
    """五类线索都要套系数 —— 漏一类就是那一类永远学不乖。"""
    cand = _mod("app.analysis.candidates")
    src = pathlib.Path(cand.__file__).read_text(encoding="utf-8")
    for kind in ("novelty", "shift", "hit", "coverage", "structure"):
        assert f'"{kind}"' in src
    assert src.count("feedback.apply(") >= 5, "五类线索都要套反馈系数"


def test_describe_data_exposes_volume_and_freshness(monkeypatch: pytest.MonkeyPatch) -> None:
    """数据地图第一步要能看出"有多少、新不新"，否则智能体无法规划窗口。"""
    tools = _mod("app.investigation.tools")
    es_query = _mod("app.investigation.es_query")

    def fake_sources() -> list[dict[str, Any]]:
        return [
            {
                "source": "zeek",
                "index": "events-*",
                "fields": ["src_ip", "dst_ip"],
                "agg_fields": ["src_ip"],
                "bounds": {
                    "earliest": "2026-10-01T00:00:00Z",
                    "latest": "2026-10-24T00:00:00Z",
                    "docs_total": 40_000_000,
                    "docs_last_24h": 34_000_000,
                    "docs_total_of_source": 39_000_000,
                    "docs_last_24h_of_source": 33_000_000,
                },
            }
        ]

    monkeypatch.setattr(es_query, "describe_sources", fake_sources)
    run_tool = tools.execute  # 取局部别名：测试里调的是仓内分发器，不是任何 SQL 执行
    out = run_tool("describe_data", {}, tools.ToolCtx())
    src0 = out["sources"][0]
    assert src0["docs_total"] == 40_000_000
    assert src0["docs_last_24h_of_source"] == 33_000_000
    assert src0["field_count"] == 2
    assert "list_filters" in out["hint"], "要提醒「查不到不等于没发生」（可能被入库过滤挡了）"
    assert "planning_note" in out


def test_describe_data_volume_is_one_round_trip() -> None:
    """量级/新鲜度/按来源分布必须在**同一次**聚合里拿全（describe_data 是规划第一步）。"""
    es_query = _mod("app.investigation.es_query")
    src = inspect.getsource(es_query.time_bounds)
    assert "track_total_hits" in src, "不设会撞 ES 的 1 万计数上限，量级会失真"
    assert src.count("_es().search(") == 1, "不该为量级再发第二次查询"
    for agg in ("min_ts", "max_ts", "by_source", "last_24h"):
        assert agg in src


# ===== ⑨ G1/G2/G3 补的六个工具：注册齐全 + 护栏在早退路径上生效 =====

NEW_TOOLS = (
    "search_hits",
    "get_event_detail",
    "prior_findings",
    "list_suppressions",
    "revoke_suppression",
    "add_task",
)


def test_new_tools_registered_and_described() -> None:
    tools = _mod("app.mcp.ndr_tools")
    for name in NEW_TOOLS:
        spec = tools.TOOLS.get(name) or {}
        assert spec.get("run"), f"{name} 没进 TOOLS 注册表"
        assert spec.get("desc"), f"{name} 缺描述（模型看不到用途就不会用）"
        assert spec.get("params"), f"{name} 缺参数说明"


def test_new_tools_exposed_via_server_wrappers() -> None:
    """注册表里有、服务层没包装 = 对外不存在（MCP 的 schema 只认显式形参）。"""
    server = _mod("app.mcp.server")
    names = {f.__name__ for f in server._NDR_TOOL_FUNCS}
    for name in NEW_TOOLS:
        assert name in names, f"{name} 未注册到 MCP 服务层"
    tools = _mod("app.mcp.ndr_tools")
    es_names = {f.__name__ for f in server._ES_TOOL_FUNCS}
    missing = set(tools.TOOLS) - names
    assert not missing, f"注册表里有但服务层没包装（对外不可见）：{missing}"
    assert es_names & set(tools.TOOLS) == set(), (
        "查 ES 的工具不该出现在 NDR 原生注册表里（两套会漂移）"
    )


def test_search_hits_rejects_unknown_source_kind() -> None:
    """来源键写错要早退并列可选值（不能静默返回空，那会被读成"没有事件"）。"""
    tools = _mod("app.mcp.ndr_tools")
    out = tools.dispatch("search_hits", {"source_kinds": "signature_hit,zeek_notice"})
    assert "error" in out, "未知来源键必须报错（不能静默返回空，会被读成没有事件）"
    assert "feature_match" in out["error"], "错误里要列出可选值，让模型自我纠正"


def test_guard_actions_require_a_reason_or_subject() -> None:
    """撤销要写原因、登记与查历史要给对象：空参数必须在打库之前就被拒。"""
    tools = _mod("app.mcp.ndr_tools")
    out = tools.dispatch("revoke_suppression", {"suppression_id": "x"})
    assert "原因" in str(out), "撤销必须写原因：抑制是关掉一部分检测，放开同样要留审计"
    assert "subject" in str(tools.dispatch("add_task", {}))
    assert "subject" in str(tools.dispatch("prior_findings", {}))
    assert "event_id" in str(tools.dispatch("get_event_detail", {}))


def test_asset_map_rejects_unknown_kind_before_query() -> None:
    subj = _mod("app.analysis.subjects")
    out = subj.inventory(kind="not_a_kind")
    assert "error" in out and out["known_kinds"], "kind 写错要早退并列出可选类"
    assert "只认" in out["error"]
    # 合法 kind 不在早退路径上（会去读库）：这里只断言它没被当成"未知类型"拒掉
    ok = subj.inventory(kind="asset")
    assert "只认" not in str(ok.get("error", ""))


def test_mcp_instructions_tell_the_new_flow() -> None:
    """契约说明不能再停在"推送载荷带 ID / 全部只读"——那两条已经随改造失效。"""
    server = _mod("app.mcp.server")
    src = pathlib.Path(server.__file__).read_text(encoding="utf-8")
    assert "推送载荷" not in src, "instructions 里还留着已退役的推送前提"
    assert "除 record_conclusion（写回结论）外全部只读" not in src
    for token in (
        "prior_findings",
        "search_hits",
        "list_suppressions",
        "revoke_suppression",
        "add_task",
    ):
        assert token in src, f"instructions 没提到 {token}"


def test_mcp_boundary_guard_still_holds() -> None:
    """新工具有 6 个、跨了 3 个子系统，但 MCP 仍只准依赖 `app.mcpapi`。"""
    mcp_dir = ROOT / "ndr" / "backend" / "app" / "mcp"
    allowed = ("app.config", "app.mcp", "app.mcpapi")
    offenders: list[str] = []
    for path in sorted(mcp_dir.glob("*.py")):
        for line in path.read_text(encoding="utf-8").splitlines():
            text = line.strip()
            if not text.startswith(("from app.", "import app.")):
                continue
            name = text.split()[1].split("(")[0]
            if not name.startswith(allowed):
                offenders.append(f"{path.name}: {name}")
    assert not offenders, f"MCP 穿透了门面：{offenders}"


# ===== ⑩ M1-M6：资产台账 / 簇 / 统计 / 规则 / 中继 / 画像降权 =====

M_TOOLS = (
    "asset_context",
    "hit_clusters",
    "hit_stats",
    "list_rules",
    "relay_nodes",
    "record_disposition",
)


def test_m_tools_registered_wrapped_and_described() -> None:
    tools = _mod("app.mcp.ndr_tools")
    server = _mod("app.mcp.server")
    wrapped = {f.__name__ for f in server._NDR_TOOL_FUNCS}
    for name in M_TOOLS:
        assert name in tools.TOOLS, f"{name} 没进注册表"
        assert name in wrapped, f"{name} 没在服务层包装（对外不可见）"
        spec = tools.TOOLS[name]
        assert spec.get("desc"), f"{name} 缺描述（模型看不到用途就不会调用）"
        assert "params" in spec, f"{name} 缺 params 键（无参数工具也要显式写空表）"
        # 每个参数都要有实质说明（枚举校验是否真的执行由行为用例守，
        # 不靠在这里匹配关键词——那种断言既脆又挡不住漏写）
        for pname, pdesc in spec["params"].items():
            assert isinstance(pdesc, str) and len(pdesc.strip()) >= 8, (
                f"{name}.{pname} 的参数说明太短，模型无从照做"
            )
        fn = next(f for f in server._NDR_TOOL_FUNCS if f.__name__ == name)
        assert not any(
            p.kind is inspect.Parameter.VAR_KEYWORD
            for p in inspect.signature(fn).parameters.values()
        ), f"{name} 用了 **kwargs，MCP schema 会失真"


def test_asset_context_requires_a_selector() -> None:
    tools = _mod("app.mcp.ndr_tools")
    out = tools.dispatch("asset_context", {})
    assert "error" in out and "ips" in out["error"], "既不给他 IP 也不给筛选项时必须早退"


def test_hit_clusters_and_rules_reject_unknown_source_kind() -> None:
    """未知来源键必须报错并列出可选值 —— 静默返回空会被模型读成"没有这类事件"。"""
    tools = _mod("app.mcp.ndr_tools")
    for name in ("hit_clusters", "list_rules"):
        out = tools.dispatch(name, {"source_kind": "suricata"})
        assert "error" in out, f"{name} 没校验 source_kind"
        assert "feature_match" in out["error"], f"{name} 的报错没列出可选值"


def test_record_disposition_validates_verdict_and_signal() -> None:
    """处置只认 false_positive/confirm；signal 只认那八个信号码（写错会静默降错东西）。"""
    tools = _mod("app.mcp.ndr_tools")
    out = tools.dispatch("record_disposition", {"profile_id": "p", "verdict": "ignore"})
    assert "error" in out and "false_positive" in out["error"]
    out2 = tools.dispatch(
        "record_disposition", {"profile_id": "p", "verdict": "false_positive", "signal": "weird"}
    )
    assert "error" in out2 and "cross_ip" in out2["error"]


def test_relay_nodes_snapshot_has_no_raw_text() -> None:
    """中继快照不给清单原文（含注释，对分析无用还吃上下文），只给结构化角色/侧向。"""
    subj = _mod("app.mcpapi")
    src = inspect.getsource(subj.relay_inventory)
    assert 'snap.pop("text"' in src
    assert "describe()" in src, "必须复用界面那份快照，别拼第二套口径"


def test_single_source_of_truth_for_shared_paths() -> None:
    """界面与智能体必须共用同一份实现，不能各查各的（否则加了新维度一定漏一处）。"""
    assets = pathlib.Path(str(_mod("app.api.routes.assets_center").__file__)).read_text(
        encoding="utf-8"
    )
    assert "return records(" in assets, "路由应委托给无鉴权的 records()"
    assert "AssetRecord.ip.ilike" in assets.split("def records(")[-1][:1200]

    rules = pathlib.Path(str(_mod("app.api.routes.rules").__file__)).read_text(encoding="utf-8")
    assert 'return {"items": all_rules(db)}' in rules, "路由应委托 all_rules()"

    base = pathlib.Path(str(_mod("app.api.routes.baseline").__file__)).read_text(encoding="utf-8")
    assert "profiles.disposition_for(" in base
    assert "EntityProfile.entity_key ==" not in base, "画像解析逻辑不该在路由里再留一份"


# ===== ⑪ 派工模式不能把运营指标读成假红灯 =====


def test_coverage_metric_is_mode_independent() -> None:
    """`analysis.enabled` 开着时摘要不再投递，覆盖率分子必须换掉。

    回归背景：漏报兜底率原来固定用 `d_delivered` 当分子；改成派工后它恒为 0，
    运营中心会一直显示「大批事件没进分析」——一个由架构变更引入的**恒假告警**。
    """
    src = pathlib.Path(str(_mod("app.api.routes.detector").__file__)).read_text(encoding="utf-8")
    assert "dispatch_mode" in src
    assert "hits.hits_stats(minutes=window_minutes)" in src, "派工模式要用窗口内命中事件数当分子"
    assert "entered = events_window if dispatch_mode else delivered_window" in src
    # 旧的那行条件必须已经改掉，否则派工模式仍会恒发假警
    assert "if es_docs and delivered_window is not None and not stale" not in src


def test_coverage_reports_which_basis_it_used() -> None:
    """口径必须自证：界面上要说清这次算的是事件数还是投递数。"""
    src = pathlib.Path(str(_mod("app.api.routes.detector").__file__)).read_text(encoding="utf-8")
    assert 'out["entered_basis"]' in src
    assert 'out["mode"]' in src


# ===== ⑫ 去重桶宽与公平调度（计划 §3 / §4）=====


def test_dedupe_bucket_is_configurable(queue_mod: Any) -> None:
    """桶宽按 `analysis.dedupe_bucket_minutes` 走：同一小时但不同桶必须生成不同键。"""
    importlib.reload(queue_mod)
    assert queue_mod.dedupe_key(
        "shift", "ip", "10.0.0.5", "conn_count", datetime(2026, 10, 25, 9, 5, tzinfo=UTC)
    ) == queue_mod.dedupe_key(
        "shift", "ip", "10.0.0.5", "conn_count", datetime(2026, 10, 25, 9, 55, tzinfo=UTC)
    )
    assert queue_mod.dedupe_key(
        "shift", "ip", "10.0.0.5", "conn_count", datetime(2026, 10, 25, 9, 5, tzinfo=UTC)
    ) != queue_mod.dedupe_key(
        "shift", "ip", "10.0.0.5", "conn_count", datetime(2026, 10, 25, 10, 5, tzinfo=UTC)
    )


def test_coverage_bucket_stays_daily_with_custom_bucket(queue_mod: Any) -> None:
    """盲区一天提醒一次就够：跨小时同一天必须同键。"""
    assert queue_mod.dedupe_key(
        "coverage", "asset", "10.0.0.9", "coverage", datetime(2026, 10, 25, 1, 0, tzinfo=UTC)
    ) == queue_mod.dedupe_key(
        "coverage", "asset", "10.0.0.9", "coverage", datetime(2026, 10, 25, 23, 0, tzinfo=UTC)
    )


def test_claim_ordering_includes_fairness(queue_mod: Any) -> None:
    """领取排序必须带"等待加成"（封顶 20 分）：否则高分线索会长期占住队列。

    没有等待加成时，一个 5 分钟前的高分线索每次都排在 3 小时前的低分线索前面，
    冷门对象永远等不到 —— 这正是"公平性"要解决的问题。
    """
    src = inspect.getsource(queue_mod._pick)
    assert "func.least" in src, "缺少等待加成封顶"
    assert "20.0" in src, "加成上限应为 20 分"
    assert "created_at" in src


# ===== ⑬ 延后必须真的挡住下一次领取（2026-10-28 线上事故）=====


def test_deferred_task_is_not_reclaimable_before_its_lease(queue_mod: Any) -> None:
    """`defer_task` 写的「下次可领时间」必须被领取查询尊重。

    线上症状：同 3 个任务 ID 在日志里刷了 40 多次「未交回（state=claimed，已延后）」——
    领取查询把 pending 与 deferred 一视同仁，延后形同虚设：领走 → 没交回 → 延后 →
    立刻又被领走，反复重跑，白烧模型调用。
    """
    import re

    src = inspect.getsource(queue_mod._pick)
    assert 'AnalysisTask.state == "pending"' in src, "pending 必须单独判（随时可领）"
    assert 'AnalysisTask.state == "deferred"' in src, "deferred 必须单独判（到期才可领）"
    # deferred 分支里必须带租约判断
    clause = re.search(
        r'\(AnalysisTask\.state == "deferred"\)(.{0,240}?)\)\s*,', src, re.DOTALL
    )
    assert clause is not None, "找不到 deferred 的领取条件"
    assert "lease_until" in clause.group(1), "deferred 必须等租约到期才能再领"
    # 旧的「pending 与 deferred 一视同仁」写法不能再出现
    assert 'state.in_(("pending", "deferred"))' not in src
    # defer_task 必须写下次可领时间
    assert "lease_until" in inspect.getsource(queue_mod.defer_task)


def test_defer_writes_next_due_time(queue_mod: Any) -> None:
    """延后要给出「下次可领时间」，否则界面与智能体都看不懂这条线索还要等多久。"""
    src = inspect.getsource(queue_mod.defer_task)
    assert "retry_after_seconds" in src
    assert "next_due_at" in src


# ===== ⑭ novelty 只派"反复出现"的对象（2026-10-28 队列洪水）=====


def test_only_recurring_subjects_become_novelty_tasks(cand: Any) -> None:
    """一次性对象不派 novelty。

    线上症状：镜像口上的一次性连接（代理/NAT 的临时套接字）会造出海量
    「第一次见到的服务端口」——实测一个采集窗口 25 万个，队列常年满、
    真正值得看的新服务被挤掉（累计丢弃 1.5 万条线索）。
    """
    assert cand.is_recurring(1) is False, "只出现一次的对象不是新服务"
    assert cand.is_recurring(2) is True, "跨窗口再现才算值得派工"
    assert cand.is_recurring(37) is True
    assert cand.is_recurring(0) is False
    assert cand.is_recurring("坏数据") is False


def test_novelty_hint_matches_the_recurring_rule(cand: Any) -> None:
    """派工理由必须跟口径一致：不是「第一次见到」，而是「反复出现」。"""
    src = inspect.getsource(cand._novelty_tasks)
    assert "反复出现" in src, "hint 应说明对象是反复出现的"
    assert "第一次见到该" not in src, "旧口径（第一次见到）已不成立"
    assert "首次出现" in src, "首次出现时间要一并给出"


def test_structure_clue_uses_a_snapshot_before_reset(cand: Any) -> None:
    """结构线索的计数要在清空累积器之前留快照。

    以前 `flush()` 先 `collector.reset()` 再算结构线索，计数已经被清空，
    这条线索其实一直没产出过（开关默认关，问题被盖住了）。
    """
    src = inspect.getsource(cand.flush)
    reset_at = src.index("collector.reset()")
    snapshot_at = src.index("fail_events = dict(collector.fail_events)")
    assert snapshot_at < reset_at, "快照必须早于 reset"


# ===== ⑮ 首见是一次性事件：新面孔窗口 + 不带时间桶 =====


def test_novelty_dedupe_key_has_no_time_bucket(queue_mod: Any) -> None:
    """「首见」这件事只发生一次：同一个对象不该每个小时再派一遍工。

    线上症状：同一个资产每小时排一条，3581 个资产轮着来，队列每小时涨 700，
    真正该看的规则命中（强度更低）被挤在后面。
    """
    key_a = queue_mod.dedupe_key(
        "novelty", "asset", "10.0.0.5", "first:asset", datetime(2026, 10, 28, 1, 0, tzinfo=UTC)
    )
    key_b = queue_mod.dedupe_key(
        "novelty", "asset", "10.0.0.5", "first:asset", datetime(2026, 10, 28, 9, 30, tzinfo=UTC)
    )
    assert key_a == key_b, "首见线索不应随时间桶变化"
    # 其它类型的线索仍按时间桶去重（hit/shift 还得能在新窗口里再报一次）
    hit_a = queue_mod.dedupe_key(
        "hit", "ip", "10.0.0.5", "sid:1", datetime(2026, 10, 28, 1, 0, tzinfo=UTC)
    )
    hit_b = queue_mod.dedupe_key(
        "hit", "ip", "10.0.0.5", "sid:1", datetime(2026, 10, 28, 9, 30, tzinfo=UTC)
    )
    assert hit_a != hit_b, "规则命中仍要按时间桶去重"


def test_newcomer_window_bounds_novelty(cand: Any) -> None:
    """过了新面孔窗口，对象就不再是"新东西"（该由 coverage 盲区提醒接手）。"""
    now = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
    assert cand.is_newcomer(now, now, 24) is True
    assert cand.is_newcomer(datetime(2026, 10, 28, 1, 0, tzinfo=UTC), now, 24) is True
    assert cand.is_newcomer(datetime(2026, 10, 27, 1, 0, tzinfo=UTC), now, 24) is False
    assert cand.is_newcomer(None, now, 24) is True
    assert cand.is_newcomer(now, now, 0) is True, "窗口至少 1 小时"


def test_newcomer_window_is_a_tunable_knob(params_mod: Any) -> None:
    """窗口是旋钮（现场网段的"新东西"节奏不一样），不是写死的常量。"""
    assert params_mod.novelty_newcomer_hours() >= 1
    src = inspect.getsource(params_mod)
    assert "analysis.novelty_newcomer_hours" in src


def test_squeezed_novelty_task_comes_back(queue_mod: Any) -> None:
    """一次性现象被挤出队列（容量挤掉/超期）后要能重新排队。

    否则这个对象就再也不会被看了 —— 一次性语义变成了"一次机会"。
    """
    src = inspect.getsource(queue_mod.enqueue)
    assert 'kind == "novelty"' in src
    assert 'existing.state = "pending"' in src


def test_operational_todo_can_bypass_candidate_kinds(queue_mod: Any) -> None:
    """运维类待办不受「生成哪些线索」开关约束。

    例："你之前提交的抑制没生效，请收窄后重提" —— 那不是检测线索，
    不该被 `analysis.candidate_kinds`（默认不含 structure）悄悄关掉，
    否则闭环就断在这里：智能体永远收不到这条待办。
    """
    src = inspect.getsource(queue_mod.enqueue)
    assert "force: bool = False" in src
    assert "not force and kind not in params.candidate_kinds()" in src
    follow = inspect.getsource(_mod("app.analysis.candidates").enqueue_suppression_followup)
    assert "force=True" in follow


# ===== ⑯ 复用交回不算"又分析了一遍"（0 token 的那部分单列）=====


def test_reuse_rows_are_excluded_from_cost_stats(queue_mod: Any) -> None:
    """成本口径只算真分析：复用交回的行（0 工具 / 0 毫秒）要剔出去。

    线上症状：复用交回也往 analysis_results 写一行，把"累计结论"算成又分析了一次，
    平均工具数还被这些 0 值拉低 —— 看起来像智能体变便宜了，其实是同一件事被重复交回。
    """
    src = inspect.getsource(queue_mod.stats)
    assert 'has_key("reused_from")' in src, "成本统计要按 findings.reused_from 区分复用行"
    assert "reused_total" in src, "复用次数要单列"
    assert "where(real)" in src, "平均值只算真分析"


def test_result_payload_marks_reuse(queue_mod: Any) -> None:
    """结论列表要能标出复用行（界面标「复用」，不显示成本）。"""
    assert "reused_from" in inspect.getsource(queue_mod.reused_from)
    view = _mod("app.api.routes.analysis")
    src = inspect.getsource(view.inventory_results)
    assert '"reused": bool(tasks.reused_from(r))' in src
