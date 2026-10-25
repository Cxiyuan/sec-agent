"""过程轨迹：让"某次分析里的观察"能被后来的任务看到（借鉴 artex 的 worker 间过程级检索）。

为什么不只留最终结论：
很多有价值的观察（"这 IP 是反代"、"这条签名在 8080 上噪声很大"）出现在某次分析的
**过程**里，却未必写进结论；下一个任务看不到就只能重复烧预算重查一遍。

**信任级别（最重要的一条）**：
轨迹是"他人未经核实的观察"，只能当线索。
它**不能**作为抑制证据 —— `submit_suppression` 的 `evidence_refs` 只收 `es:`/`ev:`，
轨迹没有这类引用；读接口的返回里也显式标注 `trust: "unverified"`。
这不是小心过度：轨迹是模型写的自由文本，攻击者可以诱导它写"这是测试流量"，
而抑制的门槛必须建立在**取数工具真返回过的数据**上。
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, or_, select

from app.db.models import AnalysisTask, AnalysisTrace

#: 每个任务最多写多少条步骤（防止把轨迹表当日志刷）
MAX_STEPS_PER_TASK = 20
#: 单条长度上限
MAX_SUMMARY = 500
MAX_DETAIL = 2000


def log_step(
    *,
    task_id: str,
    tool: str = "",
    summary: str = "",
    detail: str = "",
) -> dict[str, Any]:
    """记一条过程观察。任务必须存在且在租约内，否则拒绝（避免往空气里写）。"""
    from datetime import UTC, datetime

    from app.db.base import SessionLocal

    tid = str(task_id or "").strip()
    text = str(summary or "").strip()
    if not tid:
        return {"error": "task_id 必填", "field": "task_id"}
    if not text:
        return {"error": "summary 必填（一句话说清这条观察）", "field": "summary"}
    if len(text) > MAX_SUMMARY:
        return {"error": f"summary 超过 {MAX_SUMMARY} 字（收到 {len(text)}）", "field": "summary"}
    detail_text = str(detail or "").strip()
    if len(detail_text) > MAX_DETAIL:
        return {
            "error": f"detail 超过 {MAX_DETAIL} 字（收到 {len(detail_text)}）",
            "field": "detail",
        }

    with SessionLocal() as db:
        task = db.get(AnalysisTask, tid)
        if task is None:
            return {"error": "任务不存在"}
        if str(task.state) not in ("claimed", "pending", "deferred"):
            return {"error": f"任务状态 {task.state} 不接受过程记录"}
        used = int(
            db.scalar(
                select(func.count()).select_from(AnalysisTrace).where(AnalysisTrace.task_id == tid)
            )
            or 0
        )
        if used >= MAX_STEPS_PER_TASK:
            return {
                "error": f"本任务过程记录已达上限 {MAX_STEPS_PER_TASK} 条",
                "hint": "把多条观察合并成一条再写；结论请用 complete_task",
            }
        row = AnalysisTrace(
            task_id=tid,
            subject_kind=str(task.subject_kind or ""),
            subject=str(task.subject or ""),
            step_index=used,
            tool=str(tool or "")[:48],
            summary=text,
            detail=detail_text,
        )
        db.add(row)
        task.updated_at = datetime.now(UTC)
        db.commit()
        return {"ok": True, "step_index": used, "remaining": MAX_STEPS_PER_TASK - used - 1}


def search_traces(
    *,
    q: str = "",
    exclude_task: str = "",
    subject: str = "",
    limit: int = 20,
) -> dict[str, Any]:
    """按关键字在本会话之外的过程记录里检索（自动排除自己这条任务）。

    信息以"执行过程"为粒度流动：即便探索链上还没有正式结论，后来的任务也能复用
    他人过程中的观察，而不必把同样的取数再做一遍。
    """
    from app.db.base import SessionLocal

    cap = max(1, min(int(limit or 20), 50))
    conds: list[Any] = []
    keyword = str(q or "").strip()
    if keyword:
        like = f"%{keyword}%"
        conds.append(or_(AnalysisTrace.summary.ilike(like), AnalysisTrace.detail.ilike(like)))
    subject_text = str(subject or "").strip()
    if subject_text:
        conds.append(AnalysisTrace.subject == subject_text[:128])
    exclude = str(exclude_task or "").strip()
    if exclude:
        conds.append(AnalysisTrace.task_id != exclude)
    try:
        with SessionLocal() as db:
            rows = db.scalars(
                select(AnalysisTrace)
                .where(*conds)
                .order_by(AnalysisTrace.created_at.desc())
                .limit(cap)
            ).all()
            total = int(
                db.scalar(select(func.count()).select_from(AnalysisTrace).where(*conds)) or 0
            )
    except Exception as exc:  # noqa: BLE001
        return {"error": f"检索过程记录失败：{exc}", "items": [], "total": 0}
    return {
        "total": total,
        "returned": len(rows),
        "trust": "unverified",
        "note": "这些是别的任务未经核实的观察，只能当线索；不能作为抑制证据。",
        "items": [_trace_dict(r) for r in rows],
    }


def get_trace(*, task_id: str, limit: int = 20) -> dict[str, Any]:
    """取某个任务的全部过程步骤（细节交换：先看到有哪些任务跑过，再看具体几步）。"""
    from app.db.base import SessionLocal

    tid = str(task_id or "").strip()
    if not tid:
        return {"error": "task_id 必填", "field": "task_id"}
    cap = max(1, min(int(limit or 20), MAX_STEPS_PER_TASK))
    with SessionLocal() as db:
        rows = db.scalars(
            select(AnalysisTrace)
            .where(AnalysisTrace.task_id == tid)
            .order_by(AnalysisTrace.step_index.asc())
            .limit(cap)
        ).all()
    return {
        "task_id": tid,
        "returned": len(rows),
        "trust": "unverified",
        "items": [_trace_dict(r, with_detail=True) for r in rows],
    }


def purge_old(days: int = 60) -> int:
    """清掉过期轨迹。轨迹是**派生线索**，过期就不该再影响判断。"""
    from datetime import UTC, datetime, timedelta

    from app.db.base import SessionLocal

    cutoff = datetime.now(UTC) - timedelta(days=max(1, int(days or 60)))
    with SessionLocal() as db:
        rows = db.scalars(
            select(AnalysisTrace).where(AnalysisTrace.created_at < cutoff).limit(5000)
        ).all()
        for row in rows:
            db.delete(row)
        db.commit()
        return len(rows)


def _trace_dict(row: AnalysisTrace, *, with_detail: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "task_id": str(row.task_id),
        "step_index": int(row.step_index or 0),
        "tool": str(row.tool or ""),
        "summary": str(row.summary or ""),
        "subject_kind": str(row.subject_kind or ""),
        "subject": str(row.subject or ""),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "trust": "unverified",
    }
    if with_detail:
        out["detail"] = str(row.detail or "")
    return out
