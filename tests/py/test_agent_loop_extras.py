"""智能体闭环新增件：工具档位、锚点、过程轨迹、冷摘要、复测、终态原因。

这些能力的共同点是"给智能体省钱且让结论可解释"，所以守住三件事：
1. **工具档位**：analyst 档只暴露闭环必需的工具，高级/危险动作（撤销抑制、改规则、
   取提取件正文）不在里面；两档共用同一层鉴权；
2. **信任级别**：过程轨迹只能当线索，**永远不能**成为抑制证据；
3. **归一化在服务端**：锚点的 IP 写法差异（端口 / `::ffff:`）不许把同一资产拆成两条。
"""

from __future__ import annotations

import importlib
from typing import Any

import pytest


def _stack(request: pytest.FixtureRequest) -> str:
    return str(request.config.getoption("--stack"))


@pytest.fixture(scope="module")
def mods(request: pytest.FixtureRequest) -> dict[str, Any]:
    if _stack(request) != "ndr":
        pytest.skip("这些都是 NDR 侧能力")
    return {
        "server": importlib.import_module("app.mcp.server"),
        "ndr_tools": importlib.import_module("app.mcp.ndr_tools"),
        "anchors": importlib.import_module("app.analysis.anchors"),
        "traces": importlib.import_module("app.analysis.traces"),
        "params": importlib.import_module("app.analysis.params"),
        "verdicts": importlib.import_module("app.analysis.verdicts"),
    }


# ---------- ① 工具档位 ----------


def test_analyst_profile_is_a_strict_subset(mods: dict[str, Any]) -> None:
    """analyst 档必须是 full 的真子集。

    旧版还有「不得超过 full 的 60%」这条收窄线，2026-10-29 架构整改推翻（A1）：
    analyst 档现在**开放全部只读取证工具**（40/43 取数/上下文/过程），测试再拦比例
    就等于拦正确性；真正的护栏是下面那条「禁止动作不得入档」+ 数量下限。
    """
    server = mods["server"]
    analyst = set(server.build_server("analyst")._tool_manager._tools)
    full = set(server.build_server("full")._tool_manager._tools)
    assert analyst < full, "analyst 必须是 full 的真子集"
    assert len(analyst) >= 40, f"analyst 档被改小了：{len(analyst)}（A1 要求 ≥40 个只读工具）"


def test_analyst_profile_covers_whole_loop(mods: dict[str, Any]) -> None:
    """闭环必需的动作一个都不能少：领、交、延后、查状态、查历史、取数、申请抑制。"""
    server = mods["server"]
    analyst = set(server.build_server("analyst")._tool_manager._tools)
    required = {
        "claim_tasks",
        "complete_task",
        "defer_task",
        "task_state",
        "prior_findings",
        "search_hits",
        "get_event_detail",
        "describe_data",
        "search_events",
        "asset_context",
        "submit_suppression",
        "list_suppressions",
    }
    assert required <= analyst, f"analyst 档缺闭环必需工具：{sorted(required - analyst)}"


def test_analyst_profile_has_direction_and_rule_context(mods: dict[str, Any]) -> None:
    """方向与规则上下文是分析必需件（2026-10 MCP QA）。

    - `relay_nodes`：不查反代/DNS 转发，代理访问会被误判成"内网主动外联"；
      分析提示词本来就让 agent 调它，但档位里没有 → 必然 tool-not-found。
    - `hit_clusters`：一次扫描命中几十个地址要靠簇折叠，否则逐个分析烧预算。
    - `get_rule` / `list_rules`：hint 只给规则名，看不到匹配条件只能猜。
    """
    server = mods["server"]
    analyst = set(server.build_server("analyst")._tool_manager._tools)
    required = {"relay_nodes", "hit_clusters", "get_rule", "list_rules"}
    assert required <= analyst, f"analyst 档缺分析必需件：{sorted(required - analyst)}"


def test_instructions_only_mention_available_tools(mods: dict[str, Any]) -> None:
    """契约说明里只能出现当前档位真实存在的工具（tool-not-found 的根因）。

    模型是先读 instructions 再动手的：说明里写着一个档位没有的工具，它会照着调，
    失败会被记成 tool_error，还会白烧一轮预算。
    """
    import re as _re

    server = mods["server"]
    catalog = set(server.ndr_tools.TOOLS) | {fn.__name__ for fn in server._ES_TOOL_FUNCS}
    for profile in ("analyst", "full"):
        built = server.build_server(profile)
        tools = set(built._tool_manager._tools)
        mentioned = {
            name for name in catalog if _re.search(rf"\b{_re.escape(name)}\b", built.instructions)
        }
        assert mentioned <= tools, f"{profile} 档说明提到不存在的工具：{sorted(mentioned - tools)}"
        assert mentioned == tools, f"{profile} 档说明漏了工具：{sorted(tools - mentioned)}"


def test_analyst_profile_excludes_privileged_actions(mods: dict[str, Any]) -> None:
    """危险/运维动作不进 analyst 档：撤销抑制、改结论/处置、凭空添任务等。

    `file_content` / `fetch_window` 是取证能力件，2026-10-29 A1 决策（用户拍板）
    默认开放给 analyst 档：调用走 MCP 调用记录审计，涉密部署由部署侧收紧令牌档位。
    """
    server = mods["server"]
    analyst = set(server.build_server("analyst")._tool_manager._tools)
    forbidden = {
        "revoke_suppression",
        "record_conclusion",
        "record_disposition",
        "add_task",
    }
    leaked = forbidden & analyst
    assert not leaked, f"这些动作不该出现在 analyst 档：{sorted(leaked)}"
    assert "raw_evidence" in analyst
    assert "file_content" in analyst
    assert "fetch_window" in analyst


def test_unknown_profile_is_rejected(mods: dict[str, Any]) -> None:
    """档位名写错必须报错，不能悄悄退回全量（那等于把权限放开）。"""
    server = mods["server"]
    with pytest.raises(ValueError):
        server.build_server("no-such-profile")


def test_two_profiles_share_one_auth_layer(mods: dict[str, Any]) -> None:
    """两个档位挂在同一层 Bearer 鉴权下：外层只有一把锁。

    最外层多了一层 `ServerIdentityHeader`（给所有响应加 `x-ndr-auth-id`，不参与鉴权），
    所以这里剥掉它再看鉴权层 —— 断言的是"只有一把锁"，不是"锁在最外面"。
    """
    server = mods["server"]
    app = server.build_app()
    while type(app).__name__ == "ServerIdentityHeader":
        app = app.app
    assert type(app).__name__ == "BearerAuth"
    inner = app.app
    assert type(inner).__name__ == "TieredMCP"
    prefixes = [prefix for prefix, _ in inner.tiers]
    assert server.settings.mcp_path in prefixes
    assert server.settings.mcp_full_path in prefixes


# ---------- ② 锚点归一化（服务端口径，不交给模型） ----------


def test_anchor_ip_normalization(mods: dict[str, Any]) -> None:
    """同一资产的三种写法必须归一成一条：带端口 / `::ffff:` 前缀 / 完整 IPv6 压缩。"""
    anchors = mods["anchors"]
    assert anchors.normalize_ip("10.1.2.3:8080") == "10.1.2.3"
    assert anchors.normalize_ip("::ffff:10.1.2.3") == "10.1.2.3"
    assert anchors.normalize_ip("2001:0db8:0:0:0:0:0:1") == anchors.normalize_ip("2001:db8::1")


def test_anchor_domain_and_service_normalization(mods: dict[str, Any]) -> None:
    anchors = mods["anchors"]
    assert anchors.normalize_anchor("domain", "WWW.Example.COM.") == ("domain", "www.example.com")
    assert anchors.normalize_anchor("service", "10.0.0.5:443") == ("service", "10.0.0.5:443")
    assert anchors.normalize_anchor("payload", "x") is None, "内容类字段不许当资产"


def test_anchor_limits_and_errors(mods: dict[str, Any]) -> None:
    """非法项报错而不是静默丢：丢掉会让覆盖度少算且没人知道。"""
    anchors = mods["anchors"]
    too_many = [{"kind": "ip", "value": f"10.0.0.{i % 250}"} for i in range(60)]
    cleaned, errors = anchors.clean_anchors(too_many)
    assert cleaned == [] and errors, "超过上限必须整批拒绝并说明"

    cleaned, errors = anchors.clean_anchors(
        [{"kind": "ip", "value": "10.0.0.1"}, {"kind": "bogus", "value": "x"}]
    )
    assert cleaned == [("ip", "10.0.0.1")]
    assert errors and "bogus" in errors[0]

    # 重复项去重（同结论同资产只留一条）
    cleaned, errors = anchors.clean_anchors(
        [{"kind": "ip", "value": "10.0.0.1"}, {"kind": "ip", "value": "10.0.0.1:8080"}]
    )
    assert cleaned == [("ip", "10.0.0.1")] and not errors


def test_anchor_kinds_are_declared(mods: dict[str, Any]) -> None:
    anchors = mods["anchors"]
    assert set(anchors.ANCHOR_KINDS) == {"ip", "host", "domain", "endpoint", "service"}


# ---------- ③ 过程轨迹的信任级别与限额 ----------


def test_trace_limits_are_bounded(mods: dict[str, Any]) -> None:
    traces = mods["traces"]
    assert traces.MAX_STEPS_PER_TASK <= 50, "轨迹上限要有界，否则会变成第二份日志库"
    assert traces.MAX_SUMMARY < 2000 and traces.MAX_DETAIL < 5000


def test_trace_requires_summary_and_task(mods: dict[str, Any]) -> None:
    traces = mods["traces"]
    assert "error" in traces.log_step(task_id="", summary="x")
    assert "error" in traces.log_step(task_id="t1", summary="")
    too_long = traces.log_step(task_id="t1", summary="x" * (traces.MAX_SUMMARY + 1))
    assert "error" in too_long


def test_trace_results_are_marked_unverified(
    mods: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """任何轨迹读取都必须自带 `trust: unverified`，防止被下游当成结论。"""
    from unittest.mock import MagicMock

    traces = mods["traces"]
    session = MagicMock()
    session.__enter__.return_value = session
    session.scalars.return_value.all.return_value = []
    session.scalar.return_value = 0
    # `search_traces` 内部按需 `from app.db.base import SessionLocal`，
    # 所以要替换模块属性本身，替换 traces.SessionLocal 不影响它。
    db_base = importlib.import_module("app.db.base")
    monkeypatch.setattr(db_base, "SessionLocal", lambda: session)
    out = traces.search_traces(q="proxy")
    assert out["trust"] == "unverified"
    assert "未经核实" in out["note"]
    assert "不能作为抑制证据" in out["note"]


def test_trace_cannot_be_used_as_suppression_evidence(mods: dict[str, Any]) -> None:
    """红线：轨迹**不能**当抑制证据 —— 真正的手段是本会话取过的引用白名单。

    轨迹行没有 `es:`/`ev:` 形态的引用，也从不进 `valid_refs`，
    所以拿它的 ID 去申请抑制必须被拒；这里用行为断言钉住这条红线。
    """
    ndr_tools = mods["ndr_tools"]
    out = ndr_tools._apply_suppression(
        {
            "match": {
                "logic": "and",
                "rules": [
                    {"field": "src_ip", "op": "eq", "value": "10.0.0.1"},
                    {"field": "signature_id", "op": "eq", "value": "9110004"},
                ],
            },
            "reason_code": "known_service",
            "confidence": 0.99,
        },
        token="t",
        refs=["trace:0f3a-abc"],  # 轨迹 ID，本会话没取过
        valid_refs={"es:conn-2026.10.25/abc"},
        tool_usage={"search_events": 3, "search_hits": 1},
    )
    errors = out.get("field_errors") or []
    assert errors, "轨迹引用必须被拒"
    assert any(e.get("field") == "evidence_refs" for e in errors)


# ---------- ④ 冷摘要 ----------


def test_digest_summary_is_readable(mods: dict[str, Any]) -> None:
    digests = importlib.import_module("app.analysis.digests")
    text = digests._summary(5, {"false_positive": 4, "benign": 1}, "false_positive")
    assert "5 次判定" in text and "false_positive" in text


def test_digest_never_deletes_rows() -> None:
    """冷摘要只能"换个视图"，绝不能删原始结论（否则等于丢证据）。"""
    import pathlib

    src = pathlib.Path("ndr/backend/app/analysis/digests.py").read_text(encoding="utf-8")
    assert ".delete(" not in src, "digests 模块不许删除原始行"
    assert "digested_at=" in src, "应回标 digested_at 而不是删行"


# ---------- ⑤ 复测线索 ----------


def test_retest_only_targets_inconclusive_free_verdicts(mods: dict[str, Any]) -> None:
    candidates = importlib.import_module("app.analysis.candidates")
    assert set(candidates.RETESTABLE_VERDICTS) == {"false_positive", "benign"}


def test_retest_respects_zero_limit(mods: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    """`retest_max_per_round=0` 必须是彻底关闭（不是"跑一轮 0 条"）。"""
    candidates = importlib.import_module("app.analysis.candidates")
    params = mods["params"]
    monkeypatch.setattr(params, "retest_max_per_round", lambda: 0)
    assert candidates.enqueue_retest(object()) == 0


# ---------- ⑥ 终态原因 ----------


def test_terminal_reason_vocabulary(mods: dict[str, Any]) -> None:
    verdicts = mods["verdicts"]
    assert set(verdicts.TERMINAL_REASONS) == {
        "concluded",
        "budget_exhausted",
        "tool_error",
        "timeout",
        "aborted",
    }
    # 空值给默认，脏值报错（不许兜底，否则统计失真）
    assert verdicts.clean_terminal_reason("") == ("concluded", "")
    assert verdicts.clean_terminal_reason("超时") == ("timeout", "")
    value, error = verdicts.clean_terminal_reason("whatever")
    assert value == "" and "只能填" in error


def test_complete_task_validates_before_io(
    mods: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """脏的 terminal_reason / anchors 必须**在任何 I/O 之前**被拒（fail-closed）。"""
    queue = importlib.import_module("app.analysis.queue")

    def _boom(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("不该碰数据库")

    monkeypatch.setattr(queue, "SessionLocal", _boom)
    out = queue.complete_task(None, "t1", verdict="true_positive", terminal_reason="nonsense")
    assert "error" in out and out["field"] == "terminal_reason"
    out = queue.complete_task(
        None, "t1", verdict="true_positive", anchors=[{"kind": "bogus", "value": "x"}]
    )
    assert "error" in out and out["field"] == "anchors"


# ---------- ⑦ 参数齐备 ----------


def test_new_knobs_are_registered(mods: dict[str, Any]) -> None:
    params = mods["params"]
    keys = {knob.key for knob in params.KNOBS}
    for key in (
        "analysis.digest_enabled",
        "analysis.digest_after_days",
        "analysis.retest_days",
        "analysis.retest_max_per_round",
        "analysis.trace_retention_days",
    ):
        assert key in keys, f"缺参数 {key}"
    assert "retest" in params.KINDS
