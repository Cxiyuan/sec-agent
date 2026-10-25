"""冷摘要：把"变冷"的历史结论按对象聚合成一行概览（借鉴 artex 的 cold-digest）。

为什么需要：
`prior_findings` / 覆盖率这类概览视图如果逐条吐原始结论，返回量会随历史线性膨胀，
智能体的上下文迟早被"三个月前的历史"撑爆，而真正有用的是最近几条 + 一句总结。
摘要化后**概览恒定大小**，要看明细再 `detail=true` 下钻。

红线：原始 `analysis_results` 行**永不删除**，这里只是另一份聚合视图。
所以摘要算错了、或者以后口径要改，都能从原始行重算。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, update

from app.analysis import params
from app.db.models import AnalysisDigest, AnalysisResult

#: 单轮最多摘要多少个对象：这是后台节拍任务，不能一次把所有历史扫完把库顶住。
MAX_GROUPS_PER_ROUND = 200


def run_digest_round(
    *, after_days: int | None = None, limit: int = MAX_GROUPS_PER_ROUND
) -> dict[str, Any]:
    """把 `after_days` 天以前、还没摘要过的结论按对象折叠成 digest。

    幂等：`digested_at` 非空的行不再参与；同一对象再次聚合时**累加**到已有摘要行
    （因为老结论可能分批过期，一批一批进来）。
    """
    from app.db.base import SessionLocal

    days = int(after_days if after_days is not None else params.digest_after_days())
    cutoff = datetime.now(UTC) - timedelta(days=max(1, days))
    cap = max(1, min(int(limit or MAX_GROUPS_PER_ROUND), 1000))

    try:
        with SessionLocal() as db:
            groups = db.execute(
                select(
                    AnalysisResult.subject_kind,
                    AnalysisResult.subject,
                    func.count(AnalysisResult.id),
                    func.min(AnalysisResult.created_at),
                    func.max(AnalysisResult.created_at),
                )
                .where(
                    AnalysisResult.created_at < cutoff,
                    AnalysisResult.digested_at.is_(None),
                )
                .group_by(AnalysisResult.subject_kind, AnalysisResult.subject)
                .limit(cap)
            ).all()
            if not groups:
                return {"ok": True, "groups": 0, "results": 0}
            digested_rows = 0
            for subject_kind, subject, count, first_at, last_at in groups:
                mix_rows = db.execute(
                    select(AnalysisResult.verdict, func.count(AnalysisResult.id))
                    .where(
                        AnalysisResult.subject_kind == subject_kind,
                        AnalysisResult.subject == subject,
                        AnalysisResult.created_at < cutoff,
                        AnalysisResult.digested_at.is_(None),
                    )
                    .group_by(AnalysisResult.verdict)
                ).all()
                mix = {str(v or "unknown"): int(c or 0) for v, c in mix_rows}
                last_verdict = str(
                    db.scalar(
                        select(AnalysisResult.verdict)
                        .where(
                            AnalysisResult.subject_kind == subject_kind,
                            AnalysisResult.subject == subject,
                            AnalysisResult.created_at < cutoff,
                            AnalysisResult.digested_at.is_(None),
                        )
                        .order_by(AnalysisResult.created_at.desc())
                        .limit(1)
                    )
                    or ""
                )
                _upsert_digest(
                    db,
                    subject_kind=str(subject_kind or ""),
                    subject=str(subject or ""),
                    add_count=int(count or 0),
                    window_start=first_at,
                    window_end=last_at,
                    mix=mix,
                    last_verdict=last_verdict,
                )
                db.execute(
                    update(AnalysisResult)
                    .where(
                        AnalysisResult.subject_kind == subject_kind,
                        AnalysisResult.subject == subject,
                        AnalysisResult.created_at < cutoff,
                        AnalysisResult.digested_at.is_(None),
                    )
                    .values(digested_at=datetime.now(UTC))
                )
                digested_rows += int(count or 0)
            db.commit()
            return {"ok": True, "groups": len(groups), "results": digested_rows}
    except Exception as exc:  # noqa: BLE001
        # 摘要失败不影响派工：概览退化成"直接看原始行"，只是贵一点
        return {"ok": False, "error": f"冷摘要失败：{exc}"}


def _upsert_digest(
    db: Any,
    *,
    subject_kind: str,
    subject: str,
    add_count: int,
    window_start: datetime | None,
    window_end: datetime | None,
    mix: dict[str, int],
    last_verdict: str,
) -> None:
    row = db.scalar(
        select(AnalysisDigest).where(
            AnalysisDigest.subject_kind == subject_kind, AnalysisDigest.subject == subject
        )
    )
    if row is None:
        db.add(
            AnalysisDigest(
                subject_kind=subject_kind,
                subject=subject,
                window_start=window_start,
                window_end=window_end,
                result_count=add_count,
                verdict_mix=mix,
                last_verdict=last_verdict,
                summary=_summary(add_count, mix, last_verdict),
            )
        )
        return
    merged = {**dict(row.verdict_mix or {})}
    for key, value in mix.items():
        merged[key] = int(merged.get(key) or 0) + int(value or 0)
    row.verdict_mix = merged
    row.result_count = int(row.result_count or 0) + add_count
    row.window_start = _earliest(row.window_start, window_start)
    row.window_end = _latest(row.window_end, window_end)
    if last_verdict:
        row.last_verdict = last_verdict
    row.summary = _summary(int(row.result_count or 0), merged, str(row.last_verdict or ""))
    row.updated_at = datetime.now(UTC)


def _earliest(a: datetime | None, b: datetime | None) -> datetime | None:
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


def _latest(a: datetime | None, b: datetime | None) -> datetime | None:
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


def _summary(count: int, mix: dict[str, int], last_verdict: str) -> str:
    """一句人/模型都能直接读的总结（不堆数字，挑最关键的）。"""
    parts = [f"{verdict}×{n}" for verdict, n in sorted(mix.items(), key=lambda kv: -kv[1])]
    tail = f"，最近一次 {last_verdict}" if last_verdict else ""
    return f"历史 {count} 次判定：" + "、".join(parts[:4]) + tail


def get_digests(
    *, subject: str = "", subject_kind: str = "", limit: int = 20
) -> list[dict[str, Any]]:
    """读摘要（供 `prior_findings` 的概览视图）。"""
    from app.db.base import SessionLocal

    cap = max(1, min(int(limit or 20), 100))
    conds: list[Any] = []
    if str(subject or "").strip():
        conds.append(AnalysisDigest.subject == str(subject).strip()[:128])
    if str(subject_kind or "").strip():
        conds.append(AnalysisDigest.subject_kind == str(subject_kind).strip()[:16])
    try:
        with SessionLocal() as db:
            rows = db.scalars(
                select(AnalysisDigest)
                .where(*conds)
                .order_by(AnalysisDigest.updated_at.desc())
                .limit(cap)
            ).all()
    except Exception:  # noqa: BLE001
        return []
    return [
        {
            "kind": "digest",
            "subject_kind": str(r.subject_kind or ""),
            "subject": str(r.subject or ""),
            "result_count": int(r.result_count or 0),
            "verdict_mix": dict(r.verdict_mix or {}),
            "last_verdict": str(r.last_verdict or ""),
            "summary": str(r.summary or ""),
            "window_start": r.window_start.isoformat() if r.window_start else None,
            "window_end": r.window_end.isoformat() if r.window_end else None,
        }
        for r in rows
    ]
