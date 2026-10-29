"""complete_task 的证据引用硬校验（架构整改 B4）。

之前只有提抑制才校 `valid_refs`，普通结论可以编引用；编造的证据一旦进库，
后续 prior_findings / 结果复用会把它当真的（依据链被污染）。整改后：
- 非空 refs 必须本会话真取回过（valid_refs 空集时非空 refs 全算伪造）；
- verdict=true_positive 至少 1 条有效引用；
- benign/error 类允许空引用（轻量初筛关单没有引用是常态，不能误伤）；
- 复用交回（findings.reused_from 非空）豁免「至少 1 条」——取证在原始那轮会话。

测试直接打 ndr_tools.dispatch，绕过 MCP 传输层；数据库走 conftest 的事务回滚。
"""

from __future__ import annotations

from typing import Any

import pytest


@pytest.fixture()
def ndr(request: pytest.FixtureRequest) -> Any:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("complete_task 只在 NDR 侧")
    mod = pytest.importorskip("app.mcp.ndr_tools")
    return mod


def _complete_args(**overrides: Any) -> dict[str, Any]:
    return {
        # 不存在的任务 ID 就够用：证据校验发生在任务查询**之前**，
        # 被证据校验拒绝时返回的是 field_errors，根本到不了「任务不存在」
        "task_id": "",
        "verdict": "benign",
        "summary": "测",
        "confidence": 0.5,
        "findings": {},
        "evidence_refs": [],
        "_valid_refs": [],
        **overrides,
    }


def test_forged_ref_rejected(ndr: Any) -> None:
    """编造的引用直接拒，不写库。"""
    out = ndr.dispatch(
        "complete_task",
        _complete_args(
            task_id="00000000-0000-0000-0000-000000000001",
            verdict="true_positive",
            evidence_refs=["es:fake/1"],
            _valid_refs=["es:real/2"],
        ),
    )
    assert "error" in out
    assert "es:fake/1" in str(out["error"])
    fields = {e["field"] for e in out.get("field_errors", [])}
    assert fields == {"evidence_refs"}


def test_all_forged_when_session_fetched_nothing(ndr: Any) -> None:
    """会话没取过任何证据（valid_refs 空）时，非空 refs 全部算伪造。"""
    out = ndr.dispatch(
        "complete_task",
        _complete_args(
            task_id="00000000-0000-0000-0000-000000000002",
            evidence_refs=["es:looks/real"],
            _valid_refs=[],
        ),
    )
    assert "error" in out
    assert "没真取回过" in str(out["error"])


def test_true_positive_requires_one_valid_ref(ndr: Any) -> None:
    out = ndr.dispatch(
        "complete_task",
        _complete_args(
            task_id="00000000-0000-0000-0000-000000000003",
            verdict="true_positive",
            evidence_refs=[],
            _valid_refs=["es:real/2"],
        ),
    )
    assert "error" in out
    assert "至少" in str(out["error"])


def test_true_positive_with_valid_ref_accepted_semantics(ndr: Any) -> None:
    """有真引用时不再因证据被拒（可能因任务不存在返回别的 error，但不是证据校验）。"""
    out = ndr.dispatch(
        "complete_task",
        _complete_args(
            task_id="00000000-0000-0000-0000-000000000004",
            verdict="true_positive",
            evidence_refs=["es:real/2"],
            _valid_refs=["es:real/2"],
        ),
    )
    msgs = "；".join(e["msg"] for e in out.get("field_errors", []) if e["field"] == "evidence_refs")
    assert msgs == "", f"不该被证据校验拦：{msgs}"


def test_benign_without_refs_allowed(ndr: Any) -> None:
    """benign/初筛关单没有引用是常态，不许被证据校验误伤。"""
    out = ndr.dispatch(
        "complete_task",
        _complete_args(
            task_id="00000000-0000-0000-0000-000000000005",
            verdict="benign",
            evidence_refs=[],
            _valid_refs=["es:real/2"],
        ),
    )
    msgs = "；".join(e["msg"] for e in out.get("field_errors", []) if e["field"] == "evidence_refs")
    assert msgs == ""


def test_reused_true_positive_without_refs_allowed(ndr: Any) -> None:
    """复用交回：取证发生在原始会话，豁免「至少 1 条」。"""
    out = ndr.dispatch(
        "complete_task",
        _complete_args(
            task_id="00000000-0000-0000-0000-000000000006",
            verdict="true_positive",
            findings={"reused_from": "task-old"},
            evidence_refs=[],
            _valid_refs=["es:real/2"],
        ),
    )
    msgs = "；".join(e["msg"] for e in out.get("field_errors", []) if e["field"] == "evidence_refs")
    assert msgs == ""


def test_bad_verdict_rejected(ndr: Any) -> None:
    out = ndr.dispatch(
        "complete_task",
        _complete_args(task_id="00000000-0000-0000-0000-000000000007", verdict="随便说"),
    )
    assert "error" in out
