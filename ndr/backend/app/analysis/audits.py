"""DSH 运行审计：把“这次分析到底跑了什么”落成可回溯的事实。

与 `traces.py` 的边界：
- `traces` 是模型主动写的一句观察，信任级别 `unverified`，只能当线索；
- 本模块收的是 Agent 从 DSH session log 投影出来的运行事实（工具名/次数/token/
  turn 终态/错误摘要），用于回溯、成本与质量统计；**仍然不是结论证据**。

没有 DSH 会话的路径（复用/抑制/初筛关单）也写一行，`session_id=''`，
`decision` 说明为什么没起会话；否则控制台只能看到“跳过了”，看不见原因。
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select

from app.db.base import SessionLocal
from app.db.models import AnalysisAudit, AnalysisResult, AnalysisTask

MAX_TRACE_ROWS = 200
MAX_TEXT = 4000
MAX_ERRORS = 100
_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{0,128}$")
_SECRET = re.compile(
    r"(?i)\b(authorization|cookie|set-cookie|token|api[_-]?key|password|passwd|secret)"
    r"(\s*[:=]\s*)(?:(?:bearer|basic)\s+)?([^\s,;]+)"
)
_BEARER = re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9._~+/=-]{8,})")


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _redact(value: Any, limit: int = 800) -> str:
    text = str(value or "")
    text = _SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)
    text = _BEARER.sub(lambda m: f"{m.group(1)}[REDACTED]", text)
    text = " ".join(text.split())
    return text[:limit]


def _iso(value: Any) -> datetime | None:
    if value is None or str(value).strip() == "":
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _clean_tokens(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    out: dict[str, Any] = {}
    for key in ("input", "output", "cacheRead", "cacheWrite", "total"):
        try:
            out[key] = max(0, int(raw.get(key) or 0))
        except (TypeError, ValueError):
            out[key] = 0
    if out["total"] == 0:
        out["total"] = out["input"] + out["output"] + out["cacheRead"]
    out["reported"] = bool(raw.get("reported"))
    return out


def _clean_trace(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    calls: list[dict[str, Any]] = []
    rows = raw.get("tool_calls")
    if isinstance(rows, list):
        for item in rows[:MAX_TRACE_ROWS]:
            if not isinstance(item, dict):
                continue
            calls.append(
                {
                    "call_id": _redact(item.get("callId") or item.get("call_id"), 96),
                    "name": _redact(item.get("name"), 80),
                    "started_at": _redact(item.get("startedAt") or item.get("started_at"), 40),
                    "ended_at": _redact(item.get("endedAt") or item.get("ended_at"), 40),
                    "duration_ms": max(0, _int(item.get("durationMs") or item.get("duration_ms"))),
                    "is_error": bool(item.get("isError") or item.get("is_error")),
                    "error": _redact(item.get("error"), 400),
                    "arguments": _redact(item.get("arguments"), 500),
                    "result": _redact(item.get("result"), 500),
                }
            )
    turn_ends: list[dict[str, Any]] = []
    rows = raw.get("turn_ends")
    if isinstance(rows, list):
        for item in rows[-40:]:
            if not isinstance(item, dict):
                continue
            turn_ends.append(
                {
                    "turn": max(0, _int(item.get("turn"))),
                    "reason": _redact(item.get("reason"), 80),
                    "at": _redact(item.get("at"), 40),
                }
            )
    errors = raw.get("errors")
    return {
        "ok": bool(raw.get("ok")),
        "started_at": _redact(raw.get("started_at"), 40),
        "ended_at": _redact(raw.get("ended_at"), 40),
        "turns": max(0, _int(raw.get("turns"))),
        "steps": max(0, _int(raw.get("steps"))),
        "tool_count": max(0, _int(raw.get("tool_count"), len(calls))),
        "tool_errors": max(0, _int(raw.get("tool_errors"))),
        "tokens": _clean_tokens(raw.get("tokens")),
        "errors": [_redact(item, 400) for item in errors[:MAX_ERRORS]]
        if isinstance(errors, list)
        else [],
        "turn_ends": turn_ends,
        "redacted": bool(raw.get("redacted")),
        "truncated": bool(raw.get("truncated")) or len(calls) >= MAX_TRACE_ROWS,
        "tool_calls": calls,
    }


def record_audit(
    *,
    task_id: str,
    session_id: str = "",
    attempt: int = 0,
    result_id: str = "",
    outcome: str = "",
    verdict: str = "",
    source: str = "agent",
    model: str = "",
    started_at: str = "",
    ended_at: str = "",
    tools_used: int = 0,
    tool_errors: int = 0,
    turns: int = 0,
    turn_end_reason: str = "",
    tokens: Any = None,
    error: str = "",
    note: str = "",
    decision: Any = None,
    trace: Any = None,
) -> dict[str, Any]:
    """写入/更新一次 attempt 的审计。同一 `(task_id, session_id, attempt)` 幂等。"""
    tid = str(task_id or "").strip()
    if tid == "":
        return {"error": "task_id 必填", "field": "task_id"}
    sid = str(session_id or "").strip()[:128]
    if sid != "" and not _SAFE_ID.match(sid):
        return {"error": "session_id 含非法字符", "field": "session_id"}
    attempt_value = max(0, min(10_000, _int(attempt)))
    clean_trace = _clean_trace(trace)
    clean_decision = decision if isinstance(decision, dict) else {}
    clean_tokens = _clean_tokens(tokens or clean_trace.get("tokens"))
    start = _iso(started_at)
    end = _iso(ended_at)
    with SessionLocal() as db:
        task = db.get(AnalysisTask, tid)
        if task is None:
            return {"error": "任务不存在"}
        existing = None
        # 有 session 的 attempt 幂等更新；无 session 的复用/抑制决定允许每次各留一行。
        if sid != "":
            existing = db.scalar(
                select(AnalysisAudit)
                .where(
                    AnalysisAudit.task_id == tid,
                    AnalysisAudit.session_id == sid,
                    AnalysisAudit.attempt == attempt_value,
                )
                .order_by(AnalysisAudit.created_at.desc())
                .limit(1)
            )
        row = existing or AnalysisAudit(task_id=tid, session_id=sid, attempt=attempt_value)
        row.result_id = str(result_id or row.result_id or "")[:64]
        row.source = str(source or "agent")[:16]
        row.model = _redact(model, 160)
        row.started_at = start or row.started_at
        row.ended_at = end or row.ended_at
        row.outcome = str(outcome or "")[:24]
        row.verdict = str(verdict or "")[:24]
        row.tools_used = max(0, _int(tools_used or clean_trace.get("tool_count")))
        row.tool_errors = max(0, _int(tool_errors or clean_trace.get("tool_errors")))
        row.turns = max(0, _int(turns or clean_trace.get("turns")))
        row.turn_end_reason = _redact(turn_end_reason, 32)
        row.tokens = clean_tokens
        row.error = _redact(error, MAX_TEXT)
        row.note = _redact(note, MAX_TEXT)
        row.decision = clean_decision
        row.trace = clean_trace
        if existing is None:
            db.add(row)
        db.flush()
        # 结论行补上运行关联：正常分析时 Agent 交回后再写审计；
        # 只有空值才补，避免把同一任务较新的 attempt 覆盖成旧的。
        result = None
        result_key = str(result_id or "").strip()
        if result_key != "":
            try:
                uuid.UUID(result_key)
                candidate = db.get(AnalysisResult, result_key)
            except (ValueError, TypeError):
                candidate = None
            if candidate is not None and str(candidate.task_id or "") == tid:
                result = candidate
        if result is None:
            result = db.scalar(
                select(AnalysisResult)
                .where(AnalysisResult.task_id == tid)
                .order_by(AnalysisResult.created_at.desc())
                .limit(1)
            )
        if result is not None and sid != "" and str(outcome or "") in (
            "done", "reused", "suppressed", "triaged",
        ):
            # 运行审计是会话关联的权威来源：结论行可能先于审计写入（模型先交回），
            # 这里补上/纠正会话与 attempt；deferred/failed 没有新结论，不能把
            # 上一轮结论误标成本轮会话。没有会话的复用/初筛决定不覆盖结论行。
            result.session_id = sid
            if attempt_value > 0:
                result.attempt = attempt_value
        task.updated_at = datetime.now(UTC)
        db.commit()
        return {
            "ok": True,
            "audit_id": str(row.id),
            "task_id": tid,
            "session_id": sid,
            "attempt": attempt_value,
            "source": row.source,
            "trust": "runtime_fact",
            "note": "DSH 运行事实，可用于回溯/质量审计；不能替代结论证据。",
        }


def _audit_dict(row: AnalysisAudit, *, with_trace: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": str(row.id),
        "task_id": str(row.task_id or ""),
        "result_id": str(row.result_id or ""),
        "session_id": str(row.session_id or ""),
        "attempt": int(row.attempt or 0),
        "source": str(row.source or ""),
        "model": str(row.model or ""),
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "ended_at": row.ended_at.isoformat() if row.ended_at else None,
        "outcome": str(row.outcome or ""),
        "verdict": str(row.verdict or ""),
        "tools_used": int(row.tools_used or 0),
        "tool_errors": int(row.tool_errors or 0),
        "turns": int(row.turns or 0),
        "turn_end_reason": str(row.turn_end_reason or ""),
        "tokens": dict(row.tokens or {}),
        "error": str(row.error or ""),
        "note": str(row.note or ""),
        "decision": dict(row.decision or {}),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "trust": "runtime_fact",
        "trace_available": bool(row.trace),
    }
    if with_trace:
        out["trace"] = dict(row.trace or {})
    return out


def list_audits(
    *,
    task_id: str = "",
    session_id: str = "",
    limit: int = 50,
    offset: int = 0,
    with_trace: bool = False,
) -> dict[str, Any]:
    cap = max(1, min(int(limit or 50), 200))
    start = max(0, int(offset or 0))
    conds: list[Any] = []
    if str(task_id or "").strip():
        conds.append(AnalysisAudit.task_id == str(task_id).strip())
    if str(session_id or "").strip():
        conds.append(AnalysisAudit.session_id == str(session_id).strip())
    with SessionLocal() as db:
        total = int(db.scalar(select(func.count()).select_from(AnalysisAudit).where(*conds)) or 0)
        rows = list(
            db.scalars(
                select(AnalysisAudit)
                .where(*conds)
                .order_by(AnalysisAudit.created_at.desc())
                .limit(cap)
                .offset(start)
            ).all()
        )
    return {
        "total": total,
        "returned": len(rows),
        "items": [_audit_dict(row, with_trace=with_trace) for row in rows],
        "trust": "runtime_fact",
        "note": "审计是 DSH 运行事实，不是模型结论；用于回溯/成本/质量，不作为抑制证据。",
    }


def get_audit(audit_id: str) -> dict[str, Any]:
    aid = str(audit_id or "").strip()
    if aid == "":
        return {"error": "audit_id 必填", "field": "audit_id"}
    with SessionLocal() as db:
        row = db.get(AnalysisAudit, aid)
        if row is None:
            return {"error": "审计记录不存在"}
        return _audit_dict(row, with_trace=True)


def audits_for_task(task_id: str, *, limit: int = 20) -> list[dict[str, Any]]:
    cap = max(1, min(int(limit or 20), 100))
    with SessionLocal() as db:
        rows = list(
            db.scalars(
                select(AnalysisAudit)
                .where(AnalysisAudit.task_id == str(task_id or "").strip())
                .order_by(AnalysisAudit.created_at.desc())
                .limit(cap)
            ).all()
        )
    return [_audit_dict(row, with_trace=False) for row in rows]


def purge_old(days: int = 90) -> int:
    """清理过期审计。保留期默认 90 天，覆盖过程/结论的常见审计窗口。"""
    from datetime import timedelta

    cutoff = datetime.now(UTC) - timedelta(days=max(7, int(days or 90)))
    with SessionLocal() as db:
        rows = list(
            db.scalars(
                select(AnalysisAudit).where(AnalysisAudit.created_at < cutoff).limit(5000)
            ).all()
        )
        for row in rows:
            db.delete(row)
        db.commit()
        return len(rows)


def quality_summary(days: int = 30) -> dict[str, Any]:
    """审计覆盖率与成本/错误聚合（质量接口用）。"""
    from datetime import timedelta

    since = datetime.now(UTC) - timedelta(days=max(1, min(int(days or 30), 365)))
    with SessionLocal() as db:
        result_total = int(
            db.scalar(
                select(func.count())
                .select_from(AnalysisResult)
                .where(AnalysisResult.created_at >= since)
            )
            or 0
        )
        audited = int(
            db.scalar(
                select(func.count(func.distinct(AnalysisAudit.task_id)))
                .select_from(AnalysisAudit)
                .join(AnalysisResult, AnalysisResult.task_id == AnalysisAudit.task_id)
                .where(
                    AnalysisAudit.created_at >= since,
                    AnalysisResult.created_at >= since,
                )
            )
            or 0
        )
        no_session = int(
            db.scalar(
                select(func.count())
                .select_from(AnalysisAudit)
                .where(
                    AnalysisAudit.created_at >= since,
                    AnalysisAudit.session_id == "",
                )
            )
            or 0
        )
        avg_tools = db.scalar(
            select(func.avg(AnalysisAudit.tools_used)).where(
                AnalysisAudit.created_at >= since,
                AnalysisAudit.session_id != "",
            )
        ) or 0
        token_rows = list(
            db.scalars(
                select(AnalysisAudit.tokens).where(
                    AnalysisAudit.created_at >= since,
                    AnalysisAudit.session_id != "",
                )
            ).all()
        )
        token_totals = [
            int((row or {}).get("total") or 0)
            for row in token_rows
            if isinstance(row, dict)
        ]
        avg_tokens = sum(token_totals) / len(token_totals) if token_totals else 0
        tool_errors = int(
            db.scalar(
                select(func.coalesce(func.sum(AnalysisAudit.tool_errors), 0))
                .where(AnalysisAudit.created_at >= since)
            )
            or 0
        )
        turn_reasons = [
            {"reason": str(reason or "unknown"), "count": int(count)}
            for reason, count in db.execute(
                select(AnalysisAudit.turn_end_reason, func.count())
                .where(AnalysisAudit.created_at >= since)
                .group_by(AnalysisAudit.turn_end_reason)
                .order_by(func.count().desc())
            ).all()
        ]
        decision_actions = [
            {"action": str(action or "unknown"), "count": int(count)}
            for action, count in db.execute(
                select(AnalysisAudit.decision["action"].astext, func.count())
                .where(AnalysisAudit.created_at >= since)
                .group_by(AnalysisAudit.decision["action"].astext)
                .order_by(func.count().desc())
            ).all()
        ]
    return {
        "results": result_total,
        "audited_tasks": audited,
        "audit_coverage": round(audited / result_total, 4) if result_total else 0.0,
        "no_session_audits": no_session,
        "avg_tools": round(float(avg_tools or 0), 2),
        "avg_tokens": int(avg_tokens or 0),
        "tool_errors": tool_errors,
        "turn_end_reasons": turn_reasons,
        "decision_actions": decision_actions,
        "note": "audit_coverage 按去重 task 数/结论数；同一任务多次 attempt 只算一次。",
    }
