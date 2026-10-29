"""工具档位与角色边界（架构整改 A1）。

analyst 档的定位：**全部只读取证工具开放**（取数/上下文/过程/成本），收窄的仅限
写/破坏性动作（改规则、撤销抑制、替 agent 写结论、系统配置）。之前只给 25 个，
把 timeline/net_flows/dns_queries 这类关键取证工具裁掉了，agent 只能切 /mcp/full
或瞎调不存在的工具（白烧一轮预算还把终态记成 tool_error）。
"""

from __future__ import annotations

import importlib
from types import ModuleType

import pytest


@pytest.fixture(scope="module")
def server(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("MCP 工具档位只在 NDR 侧")
    return importlib.import_module("app.mcp.server")


@pytest.fixture(scope="module")
def ndr_tools(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("NDR 工具谱只在 NDR 侧")
    return importlib.import_module("app.mcp.ndr_tools")


#: A1 要求 analyst 档具备的只读工具（按用途分组，与 `_TOOL_PROFILES` 注释同源）
_READ_ONLY_REQUIRED = (
    # 取数
    "timeline",
    "net_flows",
    "dns_queries",
    "tls_fingerprints",
    "web_requests",
    "file_hashes",
    "file_content",
    "fetch_window",
    # 上下文
    "list_networks",
    "list_filters",
    "detector_status",
    # 过程/成本
    "task_stats",
    "log_step",
    "search_traces",
    "get_trace",
)
#: 只允许 full 档的写/破坏性动作
_WRITE_ONLY = (
    "record_conclusion",
    "revoke_suppression",
    "add_task",
    "record_disposition",
)
#: 必须存在的派工闭环工具（历史档位没这些，闭环就是空的）
_DISPATCH_REQUIRED = (
    "claim_tasks",
    "complete_task",
    "defer_task",
    "task_state",
    "submit_suppression",
    "list_suppressions",
)


def test_analyst_has_read_only_evidence_tools(server: ModuleType) -> None:
    analyst = server._TOOL_PROFILES["analyst"]
    missing = [t for t in _READ_ONLY_REQUIRED if t not in analyst]
    assert missing == [], f"analyst 档缺少只读取证工具：{missing}"


def test_analyst_has_dispatch_loop(server: ModuleType) -> None:
    analyst = server._TOOL_PROFILES["analyst"]
    missing = [t for t in _DISPATCH_REQUIRED if t not in analyst]
    assert missing == [], f"analyst 档缺少派工闭环工具：{missing}"


def test_analyst_keeps_write_tools_out(server: ModuleType) -> None:
    analyst = server._TOOL_PROFILES["analyst"]
    leaked = [t for t in _WRITE_ONLY if t in analyst]
    assert leaked == [], f"analyst 档不该出现写/破坏性工具：{leaked}"


def test_profile_tools_all_registered(server: ModuleType, ndr_tools: ModuleType) -> None:
    """档位里的每个名字都必须真的可注册（防止提词和工具面脱节 → tool-not-found）。"""
    registered = {fn.__name__ for fn in server._ES_TOOL_FUNCS + server._NDR_TOOL_FUNCS}
    es_names = {fn.__name__ for fn in server._ES_TOOL_FUNCS}
    for name in server._TOOL_PROFILES["analyst"]:
        assert name in registered, f"analyst 档里的 {name} 没有注册函数"
        if name in es_names:
            continue  # ES 取数工具的描述在 investigation 谱，native 工具的描述在 ndr_tools 谱
        spec = ndr_tools.TOOLS.get(name)
        assert spec is not None, f"NDR 工具谱缺 {name} 的描述"


def test_analyst_profile_expanded_from_25(server: ModuleType) -> None:
    """A1 前是 25 个；整改后至少覆盖原 25 + 新增 15 = 40。"""
    analyst = server._TOOL_PROFILES["analyst"]
    assert len(analyst) >= 40, f"analyst 档工具数 {len(analyst)} < 40，A1 未完成"


def test_instructions_mention_only_existing_tools(server: ModuleType) -> None:
    """按档位生成的说明不能提到档位外工具（2026-10 MCP QA：说了没有的 = tool-not-found）。"""
    analyst = set(server._TOOL_PROFILES["analyst"])
    text = server._instructions_for(analyst)
    for name in _WRITE_ONLY:
        assert name not in text, f"analyst 档说明提到了不该有的工具 {name}"
    full_text = server._instructions_for(None)
    for name in _READ_ONLY_REQUIRED:
        assert name in full_text, f"full 档说明没提到只读工具 {name}"


def test_unknown_profile_raises(server: ModuleType) -> None:
    """档位名写错必须报错：悄悄退回全量等于把权限放开。"""
    with pytest.raises(ValueError, match="未知工具档位"):
        server.build_server("no_such_profile")
