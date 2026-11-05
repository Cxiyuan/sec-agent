"""DSH 运行审计的纯函数守卫（不依赖 PG）。"""

from __future__ import annotations

from app.analysis import audits


def test_audit_redacts_secrets_and_bounds_tool_calls() -> None:
    out = audits._clean_trace(
        {
            "tool_calls": [
                {
                    "callId": "c1",
                    "name": "raw_evidence",
                    "arguments": 'Authorization: Bearer abcdefghijklmnop password=hunter2',
                    "result": "Cookie: sid=deadbeef",
                    "isError": True,
                    "error": "token=leaked",
                    "durationMs": 12,
                }
            ],
            "turn_ends": [{"turn": 1, "reason": "max-tokens"}],
            "tokens": {"input": 10, "output": 2, "reported": True},
            "errors": ["api_key=leaked"],
        }
    )
    text = str(out)
    for secret in ("abcdefghijklmnop", "hunter2", "deadbeef", "leaked"):
        assert secret not in text
    assert out["tool_calls"][0]["name"] == "raw_evidence"
    assert out["tool_calls"][0]["duration_ms"] == 12
    assert out["turn_ends"][0]["reason"] == "max-tokens"
    assert out["tokens"]["total"] == 12


def test_audit_tokens_keep_reported_flag_and_nonnegative() -> None:
    tokens = audits._clean_tokens({"input": -4, "output": 3, "reported": True})
    assert tokens["input"] == 0
    assert tokens["output"] == 3
    assert tokens["reported"] is True


def test_audit_rejects_unsafe_session_id_without_touching_db() -> None:
    out = audits.record_audit(task_id="t", session_id="../etc/passwd")
    assert "error" in out
    assert out["field"] == "session_id"
