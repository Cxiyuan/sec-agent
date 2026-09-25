"""分析结果持久化 + 滚动基线。"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agents.metrics import merge_aggregates
from app.config import settings
from app.db.base import SessionLocal
from app.db.models import BaselineStat, Event, EventGroup, Report, Rule, Skill
from app.runtime_config import get as runtime_get
from app.schemas import EventGroup as EventGroupSchema
from app.workers.pubsub import publish


def _now() -> datetime:
    return datetime.now(UTC)


# ---------- 规则 ----------


def get_enabled_rules(db: Session) -> list[dict[str, Any]]:
    rows = db.execute(select(Rule).where(Rule.enabled.is_(True)).order_by(Rule.priority)).scalars()
    return [
        {
            "name": r.name,
            "description": r.description,
            "conditions": r.conditions,
            "severity": r.severity,
            "source": r.source,
            "priority": r.priority,
        }
        for r in rows
    ]


def get_enabled_skills(db: Session) -> list[dict[str, Any]]:
    """取启用中的技能（按 priority 升序）。"""
    rows = db.execute(
        select(Skill).where(Skill.enabled.is_(True)).order_by(Skill.priority)
    ).scalars()
    return [
        {
            "name": s.name,
            "description": s.description,
            "sop": s.sop,
            "event_types": s.event_types or [],
            "tools": s.tools or [],
            "priority": s.priority,
            "source": s.source,
        }
        for s in rows
    ]


# ---------- 事件组 ----------


def save_groups(groups: list[EventGroupSchema], thread_id: str) -> None:
    """保存事件组及其事件（按 fingerprint 幂等）。

    事件组指纹现在按**时间桶**（默认 30 分钟）——同一对象会在桶内复用同一个组，
    因此这里必须做两件事，否则会重复膨胀：
    1) **事件级去重**：同组内相同事件指纹只插一次（否则每批都会重插一遍）
    2) **已有行字段合并**：IP 并集、窗口前移、分数取最大、聚合规模累加
    """
    touched: list[tuple[EventGroupSchema, bool, int]] = []
    with SessionLocal() as db:
        for g in groups:
            row = db.execute(
                select(EventGroup).where(EventGroup.fingerprint == g.fingerprint)
            ).scalar_one_or_none()
            created = row is None
            if row is None:
                row = EventGroup(
                    fingerprint=g.fingerprint,
                    src_ips=list(g.src_ips or []),
                    dst_ips=list(g.dst_ips or []),
                    window_start=g.window_start,
                    window_end=g.window_end,
                    event_count=0,
                    triage_score=g.triage_score,
                    status="analyzing",
                    thread_id=thread_id or None,
                    aggregate=g.aggregate or {},
                )
                db.add(row)
                db.flush()
            else:
                row.src_ips = sorted(set(row.src_ips or []) | set(g.src_ips or []))
                row.dst_ips = sorted(set(row.dst_ips or []) | set(g.dst_ips or []))
                if g.window_start and (
                    row.window_start is None or g.window_start < row.window_start
                ):
                    row.window_start = g.window_start
                if g.window_end and (row.window_end is None or g.window_end > row.window_end):
                    row.window_end = g.window_end
                row.triage_score = max(float(row.triage_score or 0.0), float(g.triage_score or 0.0))
                if thread_id:
                    row.thread_id = thread_id
                row.aggregate = merge_aggregates([row.aggregate, g.aggregate])
                row.status = "analyzing"

            existing = {
                fp
                for (fp,) in db.execute(
                    select(Event.fingerprint).where(Event.group_id == row.id)
                ).all()
            }
            for ev in g.events:
                fp = ev.log.fingerprint()
                if fp in existing:
                    continue
                existing.add(fp)
                db.add(
                    Event(
                        group_id=row.id,
                        fingerprint=fp,
                        source_system=ev.log.source_system,
                        ts=ev.log.ts,
                        event_type=ev.log.event_type,
                        src_ip=ev.log.src_ip,
                        dst_ip=ev.log.dst_ip,
                        src_port=ev.log.src_port,
                        dst_port=ev.log.dst_port,
                        protocol=ev.log.protocol,
                        severity=ev.log.severity,
                        hit_rule=ev.hit_rule,
                        edge_score=ev.edge_score,
                        summary=ev.log.summary,
                        raw=ev.log.raw,
                    )
                )
            row.event_count = len(existing)
            touched.append((g, created, row.event_count))
        db.commit()

    # 推送给驾驶舱 WebSocket（实时）
    for g, created, event_count in touched:
        publish(
            "shentong:events",
            {
                "type": "new_group" if created else "updated_group",
                "fingerprint": g.fingerprint,
                "src_ips": g.src_ips,
                "dst_ips": g.dst_ips,
                "event_count": event_count,
                "triage_score": g.triage_score,
            },
        )


def save_business_context(contexts: dict[str, dict[str, Any]]) -> None:
    """保存事件组的业务背景快照。"""
    with SessionLocal() as db:
        for fp, ctx in contexts.items():
            row = db.execute(
                select(EventGroup).where(EventGroup.fingerprint == fp)
            ).scalar_one_or_none()
            if row is not None:
                row.business_context = ctx
        db.commit()


def update_group_lookback(fingerprint: str, lookback: dict[str, Any]) -> None:
    """保存回溯决策与历史行为摘要。"""
    with SessionLocal() as db:
        row = db.execute(
            select(EventGroup).where(EventGroup.fingerprint == fingerprint)
        ).scalar_one_or_none()
        if row is not None:
            row.lookback = lookback
            db.commit()


def update_group_memory_hits(fingerprint: str, memory: dict[str, Any]) -> None:
    """保存召回的历史记忆摘要（供详情页展示）。"""
    with SessionLocal() as db:
        row = db.execute(
            select(EventGroup).where(EventGroup.fingerprint == fingerprint)
        ).scalar_one_or_none()
        if row is not None:
            row.memory_hits = memory
            db.commit()


def update_group_skill_hits(fingerprint: str, skill_hits: dict[str, Any]) -> None:
    """保存命中的技能与工具结果（供详情页展示）。"""
    with SessionLocal() as db:
        row = db.execute(
            select(EventGroup).where(EventGroup.fingerprint == fingerprint)
        ).scalar_one_or_none()
        if row is not None:
            row.skill_hits = skill_hits
            db.commit()


def update_group_profile_hits(fingerprint: str, profile: dict[str, Any]) -> None:
    """保存账号/会话画像异常（供详情页与驾驶舱展示）。"""
    with SessionLocal() as db:
        row = db.execute(
            select(EventGroup).where(EventGroup.fingerprint == fingerprint)
        ).scalar_one_or_none()
        if row is not None:
            row.profile_hits = profile
            db.commit()


def update_group_analysis(
    fingerprint: str,
    *,
    severity: str | None = None,
    status: str | None = None,
    attack_chain: dict[str, Any] | None = None,
    profile: dict[str, Any] | None = None,
    anomaly: dict[str, Any] | None = None,
    response_suggestions: list[dict[str, Any]] | None = None,
) -> None:
    with SessionLocal() as db:
        row = db.execute(
            select(EventGroup).where(EventGroup.fingerprint == fingerprint)
        ).scalar_one_or_none()
        if row is None:
            return
        if severity is not None:
            row.severity = severity
        if status is not None:
            row.status = status
        if attack_chain is not None:
            row.attack_chain = attack_chain
        if profile is not None:
            row.profile = profile
        if anomaly is not None:
            row.anomaly = anomaly
        if response_suggestions is not None:
            row.response_suggestions = response_suggestions
        db.commit()


def set_groups_pending(fingerprints: list[str]) -> None:
    with SessionLocal() as db:
        for fp in fingerprints:
            row = db.execute(
                select(EventGroup).where(EventGroup.fingerprint == fp)
            ).scalar_one_or_none()
            if row:
                row.status = "pending_confirmation"
        db.commit()


def save_report(
    group_fingerprint: str, title: str, severity: str, html: str, pdf_path: str | None
) -> None:
    """保存报告。

    同一事件组在 report_min_interval_minutes 内**只保留一份报告**（更新而不是新增）：
    事件组按时间桶复用后，持续攻击会反复跑到报告节点，否则会刷出大量重复报告。
    """
    with SessionLocal() as db:
        grp = db.execute(
            select(EventGroup).where(EventGroup.fingerprint == group_fingerprint)
        ).scalar_one_or_none()
        if grp is None:
            return

        existing: Report | None = None
        if settings.report_min_interval_minutes > 0:
            since = _now() - timedelta(minutes=settings.report_min_interval_minutes)
            existing = (
                db.execute(
                    select(Report)
                    .where(Report.group_id == grp.id, Report.created_at >= since)
                    .order_by(Report.created_at.desc())
                )
                .scalars()
                .first()
            )

        if existing is not None:
            existing.title = title
            existing.severity = severity
            existing.html = html
            existing.pdf_path = pdf_path
        else:
            db.add(
                Report(
                    group_id=grp.id, title=title, severity=severity, html=html, pdf_path=pdf_path
                )
            )
        grp.status = "report_generated"
        db.commit()


# ---------- 滚动基线（Welford） ----------


def update_baseline(key: str, value: float) -> None:
    with SessionLocal() as db:
        row = db.get(BaselineStat, key)
        if row is None:
            row = BaselineStat(key=key, count=0, mean=0.0, m2=0.0, first_seen=_now())
            db.add(row)
        row.count += 1
        delta = value - row.mean
        row.mean += delta / row.count
        row.m2 += delta * (value - row.mean)
        db.commit()


def get_baseline(key: str) -> dict[str, float] | None:
    """取基线统计；观测期（baseline_observe_days）内返回 None（只学习、不判异常）。"""
    with SessionLocal() as db:
        row = db.get(BaselineStat, key)
        if row is None or row.count < 2:
            return None
        # 冷启动保护：观测不足 N 天时不报统计异常，避免上线首日大量误报
        # （后台「系统配置」可改，30 秒 TTL 内生效）
        observe_days = runtime_get("baseline_observe_days", settings.baseline_observe_days)
        in_observe = (
            observe_days > 0
            and row.first_seen is not None
            and (_now() - row.first_seen).days < observe_days
        )
        if in_observe:
            return None
        variance = row.m2 / (row.count - 1)
        std = variance**0.5
        return {"count": row.count, "mean": row.mean, "std": std}
