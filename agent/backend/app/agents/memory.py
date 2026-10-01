"""分析记忆：历史比对（recall）与写入（write），两级：group / run。"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, delete, select
from sqlalchemy.orm import Session

from app.config import settings
from app.db.base import SessionLocal
from app.db.models import AnalysisMemory
from app.workers.log import get_logger

log = get_logger(__name__)

RECENT_SCAN_LIMIT = 2000  # 单次召回最多扫描的近期记忆条数


def _recent_group_memories(db: Session, since: datetime) -> list[AnalysisMemory]:
    return list(
        db.scalars(
            select(AnalysisMemory)
            .where(AnalysisMemory.kind == "group", AnalysisMemory.created_at >= since)
            .order_by(AnalysisMemory.created_at.desc())
            .limit(RECENT_SCAN_LIMIT)
        ).all()
    )


def _persistence(matched: list[AnalysisMemory]) -> dict[str, Any]:
    times = [m.created_at for m in matched if m.created_at]
    severities: dict[str, int] = {}
    for m in matched:
        if m.severity:
            severities[m.severity] = severities.get(m.severity, 0) + 1
    count = len(matched)
    return {
        "count": count,
        "first_seen": min(times).isoformat() if times else None,
        "last_seen": max(times).isoformat() if times else None,
        "severities": severities,
        "persistent": count >= settings.memory_persistence_threshold,
        "window_days": settings.memory_persistence_days,
    }


def recall(ips: list[str], asset_ids: list[str], fingerprint: str) -> dict[str, Any]:
    """召回该对象的历史记忆 + 持续性统计（出错返回空，不阻断分析）。"""
    empty = {"memories": [], "persistence": _persistence([])}
    if not ips and not asset_ids and not fingerprint:
        return empty
    since = datetime.now(UTC) - timedelta(days=settings.memory_persistence_days)
    try:
        with SessionLocal() as db:
            rows = _recent_group_memories(db, since)
    except Exception as exc:  # noqa: BLE001
        log.warning("召回分析记忆失败: %s", exc)
        return empty

    ip_set = set(ips)
    asset_set = set(asset_ids)
    matched = [
        m
        for m in rows
        if m.fingerprint == fingerprint
        or bool(ip_set & set(m.ips or []))
        or bool(asset_set & set(m.asset_ids or []))
    ]
    memories = [
        {
            "id": m.id,
            "summary": m.summary,
            "severity": m.severity,
            "created_at": m.created_at.isoformat() if m.created_at else None,
            "ips": m.ips or [],
        }
        for m in matched[: settings.memory_recall_limit]
    ]
    return {"memories": memories, "persistence": _persistence(matched)}


def write_group(
    *,
    fingerprint: str,
    window_start: datetime | None,
    window_end: datetime | None,
    ips: list[str],
    asset_ids: list[str],
    severity: str | None,
    summary: str,
    detail: dict[str, Any],
) -> None:
    """写入对象级记忆。"""
    try:
        with SessionLocal() as db:
            db.add(
                AnalysisMemory(
                    kind="group",
                    fingerprint=fingerprint,
                    window_start=window_start,
                    window_end=window_end,
                    ips=ips,
                    asset_ids=asset_ids,
                    severity=severity,
                    summary=summary,
                    detail=detail,
                )
            )
            db.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("写入对象记忆失败 %s: %s", fingerprint, exc)


def write_run(
    *,
    thread_id: str,
    window_start: datetime | None,
    window_end: datetime | None,
    ips: list[str],
    summary: str,
    detail: dict[str, Any],
) -> None:
    """写入轮次级记忆。"""
    try:
        with SessionLocal() as db:
            db.add(
                AnalysisMemory(
                    kind="run",
                    fingerprint=thread_id or "unknown",
                    window_start=window_start,
                    window_end=window_end,
                    ips=ips,
                    asset_ids=[],
                    severity=None,
                    summary=summary,
                    detail=detail,
                )
            )
            db.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("写入轮次记忆失败: %s", exc)


def cleanup() -> dict[str, int]:
    """机会式清理：轮次记忆保留 N 天，对象记忆保留 M 天。"""
    now = datetime.now(UTC)
    run_before = now - timedelta(days=settings.memory_retention_run_days)
    object_before = now - timedelta(days=settings.memory_retention_object_days)
    deleted = {"run": 0, "group": 0}
    try:
        with SessionLocal() as db:
            r1 = cast(
                CursorResult[Any],
                db.execute(
                    delete(AnalysisMemory).where(
                        AnalysisMemory.kind == "run", AnalysisMemory.created_at < run_before
                    )
                ),
            )
            r2 = cast(
                CursorResult[Any],
                db.execute(
                    delete(AnalysisMemory).where(
                        AnalysisMemory.kind == "group", AnalysisMemory.created_at < object_before
                    )
                ),
            )
            db.commit()
            deleted["run"] = r1.rowcount or 0
            deleted["group"] = r2.rowcount or 0
    except Exception as exc:  # noqa: BLE001
        log.warning("清理分析记忆失败: %s", exc)
    return deleted


def list_memories(
    *,
    kind: str | None = None,
    severity: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    with SessionLocal() as db:
        stmt = select(AnalysisMemory).order_by(AnalysisMemory.created_at.desc())
        if kind:
            stmt = stmt.where(AnalysisMemory.kind == kind)
        if severity:
            stmt = stmt.where(AnalysisMemory.severity == severity)
        rows = list(db.scalars(stmt.limit(limit).offset(offset)).all())
        total = len(db.scalars(select(AnalysisMemory)).all())
    return {
        "total": total,
        "items": [
            {
                "id": m.id,
                "kind": m.kind,
                "fingerprint": m.fingerprint,
                "severity": m.severity,
                "summary": m.summary,
                "ips": m.ips or [],
                "asset_ids": m.asset_ids or [],
                "window_start": m.window_start.isoformat() if m.window_start else None,
                "window_end": m.window_end.isoformat() if m.window_end else None,
                "created_at": m.created_at.isoformat() if m.created_at else None,
            }
            for m in rows
        ],
    }


def memory_text(recalled: dict[str, Any]) -> str:
    """把召回结果渲染成提示词文本块。"""
    memories = recalled.get("memories") or []
    persistence = recalled.get("persistence") or {}
    if not memories and not persistence.get("count"):
        return "（无历史分析记忆）"
    lines: list[str] = []
    if persistence.get("count"):
        flag = "⚠️ 持续性/反复出现" if persistence.get("persistent") else "偶发"
        lines.append(
            f"该对象在最近 {persistence.get('window_days')} 天内出现 "
            f"{persistence.get('count')} 次（判定：{flag}）"
        )
        if persistence.get("first_seen"):
            lines.append(
                f"首次 {persistence['first_seen'][:19]}，最近 {str(persistence.get('last_seen'))[:19]}"
            )
        if persistence.get("severities"):
            lines.append(
                "历史定级分布："
                + "，".join(f"{k}×{v}" for k, v in persistence["severities"].items())
            )
    for m in memories:
        when = str(m.get("created_at") or "")[:19]
        lines.append(f"- [{when}][{m.get('severity') or '-'}] {m.get('summary') or ''}")
    return "\n".join(lines)
