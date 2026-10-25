"""精准抑制 v2 的守卫（方案 §6）。

要钉住的是"全自动仍然安全"的五件事：

1. **匹配必须精准**：结构化条件树 + 字段白名单 + ≥2 个独立维度（单维＝关掉一条规则）；
2. **证据必须真实且多样**：引用要在会话白名单里、≥3 条、≥2 种取数工具、置信度达标；
3. **新现象有保护期**：首见不足 24h 不许自动抑制（先积累观测）；
4. **影响面过大自动降级**：`mode=record_only` 时事件仍生成、只不派工不推送；
5. **可复核、可撤销、会过期、会熔断**：命中数记账、到期失效、撤销立即生效、
   单条吞太多事件自动撤销。

另外守一条底线：**抑制永不影响采集/E入库/ES 原始数据** —— 抑制错了也能事后重建。
"""

from __future__ import annotations

import importlib
import inspect
import pathlib
from datetime import UTC, datetime, timedelta
from types import ModuleType, SimpleNamespace
from typing import Any, Self

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _mod(name: str) -> Any:
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError:  # pragma: no cover - agent 栈没有这些模块
        pytest.skip(f"该栈没有 {name}（属 NDR 侧）")


@pytest.fixture()
def sup() -> Any:
    module = _mod("app.detector.suppression")
    module.invalidate_cache()
    yield module
    module.invalidate_cache()


def _entry(**over: Any) -> Any:
    base: dict[str, Any] = {
        "src_ip": "10.1.2.3",
        "dst_ip": "10.1.2.9",
        "dst_port": 80,
        "protocol": "tcp",
        "log_type": "http",
        "event_type": "http_request",
        "query": "/admin/shell.aspx",
        "uri_path": "/admin/shell.aspx",
        "hostname": "www.example.edu.cn",
        "user_agent": "Mozilla/5.0",
        "ja3": "",
        "fuid": "",
        "signature_id": "9110004",
        "raw": {"app_proto": "http"},
    }
    base.update(over)
    return SimpleNamespace(**base)


def _tree(*pairs: tuple[str, str, Any], logic: str = "and") -> dict[str, Any]:
    """构造条件树：`("src_ip", "eq", "10.1.2.3")` → `{logic, rules:[{field,op,value}]}`。"""
    return {
        "logic": logic,
        "rules": [{"field": f, "op": o, "value": v} for f, o, v in pairs],
    }


def _body(**over: Any) -> dict[str, Any]:
    """一条**合格**的提交（各用例只改自己关心的那一项）。"""
    base: dict[str, Any] = {
        "name": "t",
        "match": _tree(("src_ip", "eq", "10.1.2.3"), ("signature_id", "eq", "9110004")),
        "reason_code": "benign_client_quirk",
        "note": "",
        "evidence_refs": ["es:idx/1", "es:idx/2", "es:idx/3"],
        "confidence": 0.9,
    }
    base.update(over)
    return base


# ===== ① 条件树校验：字段白名单 / 维度数 / 宽域 =====


def test_match_must_be_condition_tree(sup: ModuleType) -> None:
    """旧的扁平写法（src_ip/dst/payload_regex）不再被接受，必须给条件树。"""
    for bad in (None, {}, {"src_ip": "10.1.2.3"}, [], "src_ip=1.2.3.4"):
        errors = sup.validate_match(bad)
        assert errors and errors[0]["field"] == "match", f"{bad!r} 应被拒"


@pytest.mark.parametrize("field", ["payload", "body", "resp_body", "payload_regex", "commands"])
def test_content_fields_are_not_allowed(sup: ModuleType, field: str) -> None:
    """正文类字段不许当判据：攻击者能在正文里写"这是测试流量"，那就是投毒入口。"""
    assert field not in sup.ALLOWED_FIELDS
    errors = sup.validate_match(_tree(("src_ip", "eq", "10.1.2.3"), (field, "contains", "x")))
    assert any("不允许" in e["msg"] for e in errors)


def test_single_dimension_is_rejected(sup: ModuleType) -> None:
    """只写一条签名/一条规则＝关掉一条检测规则，必须拒。"""
    for only in (
        _tree(("signature_id", "eq", "9110004")),
        _tree(("rule", "eq", "网络扫描")),
        _tree(("protocol", "eq", "tcp")),
    ):
        errors = sup.validate_match(only)
        assert any("独立匹配维度" in e["msg"] for e in errors), only


def test_two_dimensions_are_accepted(sup: ModuleType) -> None:
    assert (
        sup.validate_match(_tree(("signature_id", "eq", "9110004"), ("src_ip", "eq", "10.1.2.3")))
        == []
    )
    # 同一字段写两次不算两个维度
    errors = sup.validate_match(_tree(("src_ip", "eq", "10.1.2.3"), ("src_ip", "eq", "10.1.2.4")))
    assert any("独立匹配维度" in e["msg"] for e in errors)


def test_min_dims_floor_is_two(sup: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """参数被调低到 1 也不给单维抑制（下限是硬编码的 max(2, …)）。"""
    monkeypatch.setattr(sup, "rc_get", lambda key, default=None: 1)
    assert sup.min_match_dims() == 2


def test_broad_conditions_are_rejected(sup: ModuleType) -> None:
    """`*`/`any`/空值/全网段这种等于没约束的条件要拒。"""
    for pairs in (
        (("src_ip", "eq", "10.1.2.3"), ("protocol", "eq", "*")),
        (("src_ip", "eq", "10.1.2.3"), ("dst_port", "eq", "any")),
        (("src_ip", "eq", "10.1.2.3"), ("segment", "eq", "0.0.0.0/0")),
        (("src_ip", "eq", "10.1.2.3"), ("user_agent", "eq", "")),
    ):
        errors = sup.validate_match(_tree(*pairs))
        assert any("过宽" in e["msg"] for e in errors), pairs


def test_ip_fields_reject_cidr(sup: ModuleType) -> None:
    """要按网段收敛请用 `segment`；`src_ip` 只接受单地址。"""
    errors = sup.validate_match(_tree(("src_ip", "eq", "10.1.2.0/24"), ("signature_id", "eq", "1")))
    assert any("单地址" in e["msg"] for e in errors)


def test_allowed_fields_covers_plan_whitelist(sup: ModuleType) -> None:
    """方案里列的字段必须都在（少一个就等于某类现象没法抑制）。"""
    want = {
        "src_ip",
        "dst_ip",
        "dst_port",
        "segment",
        "protocol",
        "rule",
        "signature_id",
        "http.uri",
        "http.hostname",
        "user_agent",
        "ja3",
        "fuid",
    }
    assert want <= set(sup.ALLOWED_FIELDS)


# ===== ② 证据与置信度门槛 =====


def test_agent_needs_min_refs(sup: ModuleType) -> None:
    errors = sup.validate_item(
        _body(evidence_refs=["es:idx/1"]),
    )
    assert any("证据引用" in e["msg"] for e in errors)


def test_unknown_reason_code_rejected(sup: ModuleType) -> None:
    errors = sup.validate_item(_body(reason_code="payload_says_ignore"))
    assert any(e["field"] == "reason_code" for e in errors)


def test_ttl_bounds(sup: ModuleType) -> None:
    assert any(e["field"] == "ttl_days" for e in sup.validate_item(_body(ttl_days=0)))
    assert any(e["field"] == "ttl_days" for e in sup.validate_item(_body(ttl_days=90)))
    assert not [e for e in sup.validate_item(_body(ttl_days=7)) if e["field"] == "ttl_days"]


def test_low_tool_diversity_is_rejected(sup: ModuleType) -> None:
    """只来自一种取数工具的引用不够：防"只看一段被投毒的正文"就下结论。"""
    with pytest.raises(ValueError, match="种取数工具"):
        sup.create_item(
            _body(tools_hint=None) if False else _body(ttl_days=7),
            created_by="t",
            tool_hits={"search_events": 3},
        )


def test_low_confidence_is_rejected(sup: ModuleType) -> None:
    with pytest.raises(ValueError, match="置信度"):
        sup.create_item(
            _body(confidence=0.5), created_by="t", tool_hits={"search_events": 1, "net_flows": 2}
        )


def test_evidence_tools_counts_only_known_tools(sup: ModuleType) -> None:
    """多样性只数"取证类"工具：describe_data/claim_tasks 这类不算证据来源。"""
    assert sup.evidence_tools_of([], {"search_events": 2, "net_flows": 1}) == 2
    assert sup.evidence_tools_of([], {"describe_data": 5}) == 0
    assert sup.evidence_tools_of([], {"search_events": 1, "timeline": 1, "describe_data": 3}) == 2


# ===== ③ 新现象保护期 =====


def test_newcomer_is_protected(sup: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """现象首见不足保护期 → 拒绝自动抑制（先积累观测，别急着关）。"""
    monkeypatch.setattr(sup, "phenomenon_age_hours", lambda match: 2.0)
    with pytest.raises(ValueError, match="保护期"):
        sup.create_item(_body(), created_by="t", tool_hits={"search_events": 2, "net_flows": 2})


def test_mature_phenomenon_passes(sup: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sup, "phenomenon_age_hours", lambda match: 200.0)
    monkeypatch.setattr(
        sup, "estimate_trial", lambda match: {"events": 3, "srcs": 1, "segments": 1}
    )
    monkeypatch.setattr(sup, "SessionLocal", _FakeSession)
    out = sup.create_item(_body(), created_by="t", tool_hits={"search_events": 2, "net_flows": 2})
    assert out["mode"] == sup.MODE_SUPPRESS
    assert out["dims"] == 2


class _Row:
    """假 ORM 行：只带 create_item 会读写的字段。"""

    def __init__(self, **kw: Any) -> None:
        self.id = kw.get("id", "s1")
        self.name = kw.get("name", "")
        self.match = kw.get("match", {})
        self.mode = kw.get("mode", "")
        self.trial = kw.get("trial", {})
        self.reason_code = kw.get("reason_code", "")
        self.note = kw.get("note", "")
        self.evidence_refs = kw.get("evidence_refs", [])
        self.evidence_tools = kw.get("evidence_tools", 0)
        self.confidence = kw.get("confidence", 0.0)
        self.source_task_id = kw.get("source_task_id", "")
        self.created_by = kw.get("created_by", "")
        self.origin = kw.get("origin", "agent")
        self.enabled = True
        self.hits = 0
        self.last_hit_at = None
        self.expires_at = kw.get("expires_at", datetime.now(UTC) + timedelta(days=14))
        self.revoked_at = None
        self.revoke_reason = ""
        self.created_at = datetime.now(UTC)
        self.updated_at = datetime.now(UTC)


class _FakeSession:
    """假会话：`create_item` 只需要 add/commit/refresh 与一次 count 查询。"""

    def __init__(self, **kw: Any) -> None:
        self.added: list[_Row] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        return False

    def scalar(self, stmt: Any) -> int:
        return 0

    def add(self, row: _Row) -> None:
        self.added.append(row)

    def commit(self) -> None:
        return None

    def refresh(self, row: _Row) -> None:
        return None

    def scalars(self, stmt: Any) -> Any:
        return SimpleNamespace(all=list)


# ===== ④ 影响面降级 =====


def test_broad_impact_downgrades_to_record_only(
    sup: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """影响面超阈值 → 只不派工（事件仍生成），不静默掉一整类流量。"""
    monkeypatch.setattr(sup, "trial_max_hits", lambda: 5000)
    monkeypatch.setattr(sup, "trial_max_srcs", lambda: 200)
    monkeypatch.setattr(sup, "trial_max_segments", lambda: 8)
    assert sup.choose_mode({"events": 9000, "srcs": 5, "segments": 1}) == sup.MODE_RECORD_ONLY
    assert sup.choose_mode({"events": 5, "srcs": 900, "segments": 1}) == sup.MODE_RECORD_ONLY
    assert sup.choose_mode({"events": 5, "srcs": 5, "segments": 90}) == sup.MODE_RECORD_ONLY
    assert sup.choose_mode({"events": 9, "srcs": 3, "segments": 1}) == sup.MODE_SUPPRESS


def test_trial_failure_is_conservative(sup: ModuleType) -> None:
    """试算失败（影响面未知）走保守档：事件仍生成。"""
    assert sup.choose_mode({"events": -1, "srcs": -1, "segments": -1}) == sup.MODE_RECORD_ONLY


# ===== ⑤ 生效开关与降级 =====


def test_disabled_switch_stops_suppressing(
    sup: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sup, "enabled", lambda: False)
    monkeypatch.setattr(
        sup,
        "_active_rows",
        lambda: (
            _Row(match=_tree(("src_ip", "eq", "10.1.2.3"), ("signature_id", "eq", "9110004"))),
        ),
    )
    assert sup.decide(_entry()) is None


def test_auto_apply_off_downgrades_to_record_only(
    sup: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """灰度开关：关掉自动生效后只抑制派工，事件必须继续生成。"""
    row = _Row(match=_tree(("src_ip", "eq", "10.1.2.3"), ("signature_id", "eq", "9110004")))
    row.mode = sup.MODE_SUPPRESS
    monkeypatch.setattr(sup, "_active_rows", lambda: (row,))
    monkeypatch.setattr(sup, "auto_apply", lambda: False)
    hit = sup.decide(_entry())
    assert hit is not None and hit.mode == sup.MODE_RECORD_ONLY


def test_decision_respects_all_dimensions(sup: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """四维全中才抑制；任一项不符就不抑制。"""
    row = _Row(
        match=_tree(
            ("src_ip", "eq", "10.1.2.3"),
            ("dst_port", "eq", 80),
            ("signature_id", "eq", "9110004"),
            ("http.hostname", "eq", "www.example.edu.cn"),
        )
    )
    monkeypatch.setattr(sup, "_active_rows", lambda: (row,))
    monkeypatch.setattr(sup, "auto_apply", lambda: True)
    assert sup.decide(_entry()) is not None
    for override in (
        {"src_ip": "10.9.9.9"},
        {"dst_port": 8080},
        {"signature_id": "9000001"},
        {"hostname": "other.example.cn"},
    ):
        assert sup.decide(_entry(**override)) is None, override


def test_rule_dimension_uses_hit_rule(sup: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """`rule` 维度匹配的是"命中的规则名"，由调用方传进来（runner 会传）。"""
    row = _Row(match=_tree(("rule", "eq", "网络扫描"), ("dst_port", "eq", 80)))
    monkeypatch.setattr(sup, "_active_rows", lambda: (row,))
    assert sup.decide(_entry(), rule="网络扫描") is not None
    assert sup.decide(_entry(), rule="协议异常") is None


def test_segment_dimension_derives_from_src(
    sup: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    row = _Row(match=_tree(("segment", "eq", "10.1.2.0/24"), ("dst_port", "eq", 80)))
    monkeypatch.setattr(sup, "_active_rows", lambda: (row,))
    assert sup.decide(_entry()) is not None
    assert sup.decide(_entry(src_ip="10.2.0.4")) is None


# ===== ⑥ 记账、熔断、到期、回弹 =====


def test_hit_counter_batches(sup: ModuleType) -> None:
    sup._pending_hits.clear()
    sup.note_hit("abc")
    sup.note_hit("abc")
    assert sup._pending_hits.get("abc") == 2
    sup._pending_hits.clear()


def test_hit_cap_triggers_auto_revoke() -> None:
    """一条抑制吞掉异常大量事件 → 自动撤销（投毒/误配的典型征兆）。"""
    src = pathlib.Path(str(_mod("app.detector.suppression").__file__)).read_text(encoding="utf-8")
    assert "熔断" in src
    assert "row.hits > cap" in src
    assert "row.enabled = False" in src


def test_expired_rows_are_not_matched() -> None:
    """到期判定必须按时区正确的 UTC 比较（naive 时间会误判）。"""
    sup = _mod("app.detector.suppression")
    src = pathlib.Path(str(sup.__file__)).read_text(encoding="utf-8")
    assert "expires_at > cutoff" in src
    now = datetime.now(UTC)
    assert (now - timedelta(days=1)) <= now


def test_rebound_only_revokes_matching_src(sup: ModuleType) -> None:
    """回弹要保守：只撤条件树里明确写了该 src_ip 的条目。"""
    src = inspect.getsource(sup.rebound_for_subject)
    assert '"src_ip"' in src
    assert sup.rebound_for_subject("shift", "") == 0


# ===== ⑦ 参数面与接口 =====


def test_config_knobs_are_whitelisted(sup: ModuleType) -> None:
    keys = {k.key for k in sup.KNOBS}
    for key in (
        "suppression.enabled",
        "suppression.auto_apply",
        "suppression.min_match_dims",
        "suppression.min_refs",
        "suppression.min_tools",
        "suppression.min_confidence",
        "suppression.default_ttl_days",
        "suppression.max_active",
        "suppression.hit_cap",
        "suppression.trial_days",
        "suppression.trial_max_srcs",
        "suppression.trial_max_hits",
        "suppression.trial_max_segments",
        "suppression.newcomer_hours",
    ):
        assert key in keys, f"{key} 不在可调参数里"
    assert set(sup.effective()) == keys, "effective 要覆盖全部参数"


def test_config_validation_rejects_out_of_range(sup: ModuleType) -> None:
    assert sup.validate_config({"suppression.unknown": 1})
    assert sup.validate_config({"suppression.default_ttl_days": 99})
    assert sup.validate_config({"suppression.min_match_dims": 1})
    assert sup.validate_config({"suppression.default_ttl_days": 3}) == []


def test_routes_registered_on_the_app() -> None:
    """界面要"完备 API"：清单/统计/参数读写/试算/新建/修改/撤销/恢复。"""
    fastapi_app = _mod("app.main").app
    paths = set(fastapi_app.openapi()["paths"])
    want = {
        "/api/suppressions",
        "/api/suppressions/stats",
        "/api/suppressions/config",
        "/api/suppressions/config/reset",
        "/api/suppressions/preview",
        "/api/suppressions/{item_id}",
        "/api/suppressions/{item_id}/revoke",
        "/api/suppressions/{item_id}/restore",
    }
    assert not want - paths, f"缺接口：{want - paths}"


# ===== ⑧ 热路径与逃生门 =====


def test_runner_suppresses_before_generating_events() -> None:
    """求值点在规则命中之后、聚合之前：`suppress` 不生成事件也不派工。"""
    runner = pathlib.Path(str(_mod("app.detector.runner").__file__)).read_text(encoding="utf-8")
    assert "suppression.decide(entry, rule=" in runner
    assert "suppression.note_hit(" in runner
    assert "suppression.MODE_SUPPRESS" in runner
    assert "excluded=True" in runner, "降级档要带 excluded（事件保留、不投递、不进基线）"


def test_suppression_never_touches_ingest_or_es(sup: ModuleType) -> None:
    """底线：抑制只改"要不要打扰分析"，不碰采集/入库/ES 查询路径。"""
    src = pathlib.Path(str(sup.__file__)).read_text(encoding="utf-8")
    for forbidden in ("ingest_filter", "filebeat", "logstash", "es_client", "delete(HitEvent)"):
        assert forbidden not in src, f"抑制模块不该碰 {forbidden}"


def test_mcp_exposes_submit_suppression() -> None:
    """智能体要能**独立**申请抑制（不只借 complete_task 内联）。"""
    tools = _mod("app.mcp.ndr_tools")
    server = _mod("app.mcp.server")
    spec = tools.TOOLS.get("submit_suppression") or {}
    assert spec.get("run") and spec.get("desc") and spec.get("params")
    assert "submit_suppression" in {f.__name__ for f in server._NDR_TOOL_FUNCS}


def test_mcp_checks_forged_refs_and_tool_diversity() -> None:
    """伪造引用换不到抑制；只来自一种工具的引用也不行（两道都在 MCP 层判）。"""
    tools = _mod("app.mcp.ndr_tools")
    out = tools.dispatch(
        "submit_suppression",
        {
            "match": _tree(("src_ip", "eq", "10.1.2.3"), ("signature_id", "eq", "1")),
            "reason_code": "known_service",
            "evidence_refs": ["es:idx/forged"],
            "confidence": 0.9,
            "_valid_refs": ["es:idx/real"],
        },
    )
    assert "field_errors" in out
    assert "没真取回" in out["field_errors"][0]["msg"]
    src = inspect.getsource(tools._apply_suppression)
    assert "tool_hits" in src and "min_tools" in src or "create_item" in src
