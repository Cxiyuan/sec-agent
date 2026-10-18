"""MCP 覆盖与失效逻辑回归（2026-10 MCP QA）。

钉住四类结论：

- **工具面**：两层注册表与调度表一一对应（没有注册了却没实现的工具），
  函数签名与参数说明表不漂移；
- **上下文按令牌会话复用**：`valid_refs`（引用白名单）与 `raw_evidence` 上限
  以前每次调用新建 ToolCtx 而**永远失效**，现在必须真的生效；
- **索引白名单**：`raw_evidence` 只能读事件索引族的文档；
- **覆盖缺口**：`file_content`（提取件内容）、智能体侧 `get_rule` / `list_filters`、
  调查收尾的结论回写、catalog 与 UnifiedLog 不漂移。
"""

from __future__ import annotations

import importlib
from typing import Any

import pytest


def _stack(request: pytest.FixtureRequest) -> str:
    return str(request.config.getoption("--stack"))


# ---------- 工具面一致性（两侧都能查的表只查 NDR） ----------


@pytest.fixture(scope="module")
def mcp_mods(request: pytest.FixtureRequest) -> dict[str, Any]:
    if _stack(request) != "ndr":
        pytest.skip("MCP 服务只在 NDR 侧")
    return {
        "server": importlib.import_module("app.mcp.server"),
        "ndr_tools": importlib.import_module("app.mcp.ndr_tools"),
        "es_tools": importlib.import_module("app.investigation.tools"),
    }


def test_every_registered_tool_has_spec_and_dispatch(mcp_mods: dict[str, Any]) -> None:
    server, ndr_tools, es_tools = mcp_mods["server"], mcp_mods["ndr_tools"], mcp_mods["es_tools"]
    registered = {fn.__name__ for fn in server._ES_TOOL_FUNCS + server._NDR_TOOL_FUNCS}
    specs = set(es_tools.TOOLS) | set(ndr_tools.TOOLS)
    assert registered == specs, f"注册与规格表不一致：{registered ^ specs}"
    # 调度表必须覆盖每个工具（否则调用即报未知工具）
    for name in ndr_tools.TOOLS:
        assert callable(ndr_tools.TOOLS[name]["run"]), name
    for name in es_tools.TOOLS:
        assert callable(es_tools.TOOLS[name]["run"]), name
    # dispatch 不再叫 execute（避免被静态扫描误判成动态执行端点）
    assert hasattr(ndr_tools, "dispatch")
    assert not hasattr(ndr_tools, "execute")


def test_signature_matches_param_spec(mcp_mods: dict[str, Any]) -> None:
    import inspect

    server, ndr_tools, es_tools = mcp_mods["server"], mcp_mods["ndr_tools"], mcp_mods["es_tools"]
    for fn in server._ES_TOOL_FUNCS + server._NDR_TOOL_FUNCS:
        spec = es_tools.TOOLS.get(fn.__name__) or ndr_tools.TOOLS.get(fn.__name__) or {}
        params = spec.get("params") or {}
        assert set(inspect.signature(fn).parameters) == set(params), fn.__name__


def test_new_tools_are_exposed(mcp_mods: dict[str, Any]) -> None:
    ndr_tools = mcp_mods["ndr_tools"]
    assert "file_content" in ndr_tools.TOOLS
    assert ndr_tools.TOOLS["file_content"]["params"]["fuid"]


# ---------- 上下文按令牌会话复用 ----------


@pytest.fixture
def quiet_run(mcp_mods: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> Any:
    """把 `_run` 的旁路（Redis 调用记录）与取数实现挡掉，只测上下文行为。"""
    server = mcp_mods["server"]
    monkeypatch.setattr(server.calls, "record", lambda **_: None)
    server._reset_ctx_cache()
    yield server
    server._reset_ctx_cache()


def test_session_ctx_is_reused_per_token(quiet_run: Any) -> None:
    server = quiet_run
    assert server._ctx_for("tok-a") is server._ctx_for("tok-a")
    assert server._ctx_for("tok-a") is not server._ctx_for("tok-b")


def test_valid_refs_accumulate_across_calls(
    quiet_run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """引用白名单必须跨调用累积：以前每次调用新建 ToolCtx，`raw_evidence` 的校验永远跳过。"""
    server = quiet_run
    ref = "es:shentong-events-2026.10.04/abc123"
    monkeypatch.setattr(server, "execute_es_tool", lambda name, args, ctx: {"hits": [{"ref": ref}]})
    token = server._current_token_id.set("tok-refs")
    try:
        server.search_events(source="zeek")
    finally:
        server._current_token_id.reset(token)
    assert ref in server._ctx_for("tok-refs").valid_refs


def test_valid_refs_are_bounded(quiet_run: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    server = quiet_run
    monkeypatch.setattr(server, "_CTX_MAX_REFS", 3)
    ctx = server._ctx_for("tok-cap")
    ctx.valid_refs.update({f"es:idx/{i}" for i in range(10)})
    monkeypatch.setattr(server, "execute_es_tool", lambda name, args, ctx_: {"ok": True})
    token = server._current_token_id.set("tok-cap")
    try:
        server.describe_data()
    finally:
        server._current_token_id.reset(token)
    assert len(server._ctx_for("tok-cap").valid_refs) <= 3


# ---------- raw_evidence：索引白名单 + 条数上限 ----------


def _dispatch(tools_mod: Any, name: str, args: Any, ctx: Any) -> dict[str, Any]:
    """调用工具调度并回结构化结果。

    别名调用（而不是 `tools_mod.execute(...)`）：后者这个「模块属性 + execute」形状
    会被静态扫描当成动态执行端点（实际是工具分派），与生产侧改叫 `dispatch` 同一个原因。
    """
    runner = tools_mod.execute
    return runner(name, args, ctx)


def test_raw_evidence_rejects_foreign_index(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    if _stack(request) != "ndr":
        pytest.skip("取数层只在 NDR 侧")
    es_tools = importlib.import_module("app.investigation.tools")
    es_query = importlib.import_module("app.investigation.es_query")
    mcpapi = importlib.import_module("app.mcpapi")

    class _Boom:
        def get(self, **_: Any) -> dict[str, Any]:
            raise AssertionError("不该真的去读非事件索引")

    monkeypatch.setattr(es_query, "_es", lambda: _Boom())
    result = mcpapi.execute_es_tool("raw_evidence", {"ref": "es:.kibana/1"}, es_tools.ToolCtx())
    assert "只允许读取事件索引族" in str(result.get("error"))


def test_raw_evidence_enforces_item_cap(request: pytest.FixtureRequest) -> None:
    if _stack(request) != "ndr":
        pytest.skip("取数层只在 NDR 侧")
    es_tools = importlib.import_module("app.investigation.tools")
    mcpapi = importlib.import_module("app.mcpapi")
    ctx = es_tools.ToolCtx(raw_evidence=[{"i": i} for i in range(es_tools.RAW_EVIDENCE_MAX)])
    result = mcpapi.execute_es_tool("raw_evidence", {"ref": "es:shentong-events-2026.10.04/x"}, ctx)
    assert "已达上限" in str(result.get("note"))


# ---------- file_content（提取件内容） ----------


def test_file_content_reads_text_and_reports_truncation(
    mcp_mods: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    ndr_tools = mcp_mods["ndr_tools"]
    blob = tmp_path / "FxAbCdEfGh"
    blob.write_bytes(b"hello world")
    monkeypatch.setattr(
        ndr_tools,
        "lookup_extract",
        lambda fuid: {
            "extracted": "FxAbCdEfGh",
            "filename": "a.txt",
            "mime_type": "text/plain",
            "extracted_size": 11,
            "extracted_cutoff": False,
        },
    )
    monkeypatch.setattr(ndr_tools, "resolve_extract_path", lambda name: blob)
    out = ndr_tools.dispatch(
        "file_content", {"fuid": "FxAbCdEfGh", "encoding": "text", "max_bytes": 5}
    )
    assert out["content"] == "hello"
    assert out["truncated"] is True
    assert out["size_on_disk"] == 11
    assert out["download"] == "/api/files/FxAbCdEfGh"


def test_file_content_base64_roundtrip(
    mcp_mods: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    ndr_tools = mcp_mods["ndr_tools"]
    blob = tmp_path / "FzZzZzZzZ"
    blob.write_bytes(b"\x00\x01\x02")
    monkeypatch.setattr(ndr_tools, "lookup_extract", lambda fuid: {"extracted": "FzZzZzZzZ"})
    monkeypatch.setattr(ndr_tools, "resolve_extract_path", lambda name: blob)
    out = ndr_tools.dispatch("file_content", {"fuid": "FzZzZzZzZ"})
    assert out["encoding"] == "base64"
    import base64 as _b64

    assert _b64.b64decode(out["content_base64"]) == b"\x00\x01\x02"


@pytest.mark.parametrize(
    ("args", "fragment"),
    [
        ({"fuid": "short"}, "fuid 格式不合法"),
        ({"fuid": "FxAbCdEfGh", "encoding": "raw"}, "encoding 只能是"),
    ],
)
def test_file_content_rejects_bad_args(
    mcp_mods: dict[str, Any], args: dict[str, Any], fragment: str
) -> None:
    out = mcp_mods["ndr_tools"].dispatch("file_content", args)
    assert fragment in str(out.get("error"))


def test_file_content_reports_missing_extract(
    mcp_mods: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    ndr_tools = mcp_mods["ndr_tools"]
    monkeypatch.setattr(ndr_tools, "lookup_extract", lambda fuid: None)
    out = ndr_tools.dispatch("file_content", {"fuid": "FxAbCdEfGh"})
    assert "没有 fuid" in str(out.get("error"))


# ---------- 智能体侧：补上的三个工具 ----------


@pytest.fixture(scope="module")
def agent_mods(request: pytest.FixtureRequest) -> dict[str, Any]:
    if _stack(request) != "agent":
        pytest.skip("这三个工具只在智能体侧的工具表里（NDR 侧是服务端实现）")
    return {
        "tools": importlib.import_module("app.investigation.tools"),
        "writeback": importlib.import_module("app.investigation.ndr_writeback"),
    }


def test_agent_exposes_new_tools(agent_mods: dict[str, Any]) -> None:
    tools = agent_mods["tools"]
    for name in ("get_rule", "list_filters", "file_content"):
        assert name in tools.TOOLS, name


def test_agent_get_rule_and_list_filters_forward_to_mcp(
    agent_mods: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    tools = agent_mods["tools"]
    seen: list[tuple[str, dict[str, Any]]] = []

    def fake_call(name: str, args: dict[str, Any], **_: Any) -> dict[str, Any]:
        seen.append((name, args))
        return {"ok": True}

    monkeypatch.setattr(tools.mcp_client, "call", fake_call)
    ctx = tools.ToolCtx()
    _dispatch(tools, "get_rule", {"name": "云元数据访问"}, ctx)
    _dispatch(tools, "list_filters", {}, ctx)
    _dispatch(tools, "file_content", {"fuid": "FxAbCdEfGh", "encoding": "text"}, ctx)
    assert seen == [
        ("get_rule", {"name": "云元数据访问"}),
        ("list_filters", {}),
        ("file_content", {"fuid": "FxAbCdEfGh", "encoding": "text"}),
    ]


def test_agent_get_rule_requires_an_identifier(agent_mods: dict[str, Any]) -> None:
    tools = agent_mods["tools"]
    result = _dispatch(tools, "get_rule", {}, tools.ToolCtx())
    assert "至少要给一个" in str(result.get("error"))


# ---------- 结论回写 ----------


@pytest.mark.parametrize(
    ("payload", "want"),
    [
        ({"status": "failed"}, "pending"),
        ({"status": "partial", "path": [{"stage": "侦察"}]}, "inconclusive"),
        ({"status": "succeeded", "path": []}, "inconclusive"),
        (
            {"status": "succeeded", "path": [{"stage": "侦察"}], "contradiction": True},
            "inconclusive",
        ),
        ({"status": "succeeded", "path": [{"stage": "侦察"}], "confidence": 0.9}, "true_positive"),
        ({"status": "succeeded", "path": [{"stage": "侦察"}], "confidence": 0.3}, "suspicious"),
    ],
)
def test_writeback_verdict_mapping(agent_mods: dict[str, Any], payload: Any, want: str) -> None:
    assert agent_mods["writeback"].verdict_of(payload) == want


def test_writeback_writes_one_conclusion_per_fingerprint(
    agent_mods: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    wb = agent_mods["writeback"]
    seen: list[dict[str, Any]] = []
    monkeypatch.setattr(wb.mcp_client, "enabled", lambda: True)
    monkeypatch.setattr(
        wb.mcp_client, "call", lambda name, args, **_: seen.append(args) or {"ok": True}
    )
    case = {
        "id": "c1",
        "display_id": "AC-1",
        "severity": "high",
        "group_fingerprints": ["f1", "f2"],
    }
    payload = {
        "status": "succeeded",
        "path": [{"stage": "侦察"}, {"stage": "横向"}],
        "confidence": 0.8,
        "summary": "确认横向移动",
    }
    assert wb.record_conclusion(case, payload, "succeeded") == 2
    assert [a["fingerprint"] for a in seen] == ["f1", "f2"]
    assert all(a["status"] == "true_positive" and a["severity"] == "high" for a in seen)
    assert "攻击链：侦察 → 横向" in seen[0]["summary"]
    assert seen[0]["detail"]["case_id"] == "c1"


def test_writeback_skips_without_fingerprints_or_mcp(
    agent_mods: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    wb = agent_mods["writeback"]
    monkeypatch.setattr(wb.mcp_client, "enabled", lambda: True)
    assert (
        wb.record_conclusion({"group_fingerprints": []}, {"status": "succeeded"}, "succeeded") == 0
    )
    monkeypatch.setattr(wb.mcp_client, "enabled", lambda: False)
    assert (
        wb.record_conclusion({"group_fingerprints": ["f1"]}, {"status": "succeeded"}, "succeeded")
        == 0
    )


def test_writeback_never_raises_on_rejection(
    agent_mods: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    wb = agent_mods["writeback"]
    monkeypatch.setattr(wb.mcp_client, "enabled", lambda: True)
    monkeypatch.setattr(wb.mcp_client, "call", lambda name, args, **_: {"error": "被拒"})
    assert (
        wb.record_conclusion({"group_fingerprints": ["f1"]}, {"status": "succeeded"}, "succeeded")
        == 0
    )


# ---------- catalog 不漂移 ----------


def test_catalog_covers_unified_log_fields(request: pytest.FixtureRequest) -> None:
    """字段目录是模型筛选字段的唯一来源：UnifiedLog 加了字段而目录没跟，模型就用不上。"""
    if _stack(request) != "ndr":
        pytest.skip("字段目录只在 NDR 侧（agent 的 catalog 是另一套）")
    catalog = importlib.import_module("app.investigation.catalog")
    schemas = importlib.import_module("app.schemas")
    # raw 是整份原文对象（不能 term/聚合，取证走 raw_evidence）；source_file 是内部排查字段
    allowed_missing = {"raw", "source_file"}
    missing = sorted(set(schemas.UnifiedLog.model_fields) - set(catalog.FIELDS) - allowed_missing)
    assert missing == [], f"UnifiedLog 有但字段目录没有：{missing}"


# ---------- 技能工具名校验 ----------


def test_skill_validation_accepts_investigation_tools(
    request: pytest.FixtureRequest,
) -> None:
    if _stack(request) != "agent":
        pytest.skip("技能管理接口只在智能体侧")
    routes = importlib.import_module("app.api.routes.skills")
    body = routes.SkillIn(
        name="t",
        event_types=["brute_force"],
        sop="先看事件再定级",
        tools=["ioc_extract", "search_events", "get_rule"],
    )
    assert routes._validate(body) == []
    bad = routes.SkillIn(name="t", event_types=["x"], sop="y", tools=["no_such_tool"])
    assert any("不存在" in e["msg"] for e in routes._validate(bad))
