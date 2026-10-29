"""首见登记表（`observed_subjects`）：novelty 与覆盖率的数据源。

为什么落库而不是 Redis：
- novelty 要**长期记忆** —— Redis 靠 TTL 会把"半年没见"误判成"新出现"；
- 覆盖率是这次改造的验收指标（近 N 天有多少资产被分析过），必须能查、能聚合；
- 只增不减的表这个项目吃过亏，所以按 `last_seen_at` 有保留期清理。

`record()` 走单条 UPSERT（不"先查后写"）：检测热路径每秒几百次，两次往返会翻倍。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.analysis import params
from app.db.base import SessionLocal
from app.db.models import ObservedSubject

#: 等价于 3.11 的 `datetime.UTC`（本仓库 requires-python >=3.11）；用别名写法
#: 免得按旧语法解析的静态检查工具报「unknown import symbol」。
UTC = timezone.utc

#: 允许登记的观察对象类型（同时是界面「覆盖率」的分组维度）
KIND_ASSET = "asset"
KIND_PORT = "service_port"
KIND_PEER = "peer"
KIND_PROTOCOL = "protocol"
KIND_SIGNATURE = "signature"
KIND_ACCOUNT = "account"
SUBJECT_KINDS = (KIND_ASSET, KIND_PORT, KIND_PEER, KIND_PROTOCOL, KIND_SIGNATURE, KIND_ACCOUNT)

#: 任务里的 subject_kind 到登记表 kind 的映射（不一致时按 ip→asset 兜底）
_TASK_KIND_MAP = {
    "ip": KIND_ASSET,
    "asset": KIND_ASSET,
    "segment": KIND_ASSET,
    "account": KIND_ACCOUNT,
    "protocol": KIND_PROTOCOL,
    "signature": KIND_SIGNATURE,
    "cluster": KIND_ASSET,
}


def mapped_task_kind(subject_kind: str) -> str:
    return _TASK_KIND_MAP.get(str(subject_kind or "").strip(), KIND_ASSET)


def record(db: Any, kind: str, value: str, now: datetime) -> bool:
    """记一次"见到"。返回**是否首次出现**（True = 首见 → 该出 novelty 线索）。"""
    kind = str(kind or "").strip()[:24]
    value = str(value or "").strip()[:160]
    if not kind or not value:
        return False
    stmt = (
        pg_insert(ObservedSubject)
        .values(
            kind=kind,
            value=value,
            first_seen_at=now,
            last_seen_at=now,
            seen_count=1,
            analyzed_count=0,
        )
        .on_conflict_do_update(
            index_elements=["kind", "value"],
            set_={
                "last_seen_at": now,
                "seen_count": ObservedSubject.seen_count + 1,
            },
        )
        .returning(ObservedSubject.first_seen_at)
    )
    first_seen_at = db.execute(stmt).scalar()
    # first_seen 就等于本次时间戳 → 这行是刚建的（首见）
    return bool(first_seen_at and abs((first_seen_at - now).total_seconds()) < 2)


def mark_analyzed(db: Any, subject_kind: str, subject: str, now: datetime) -> None:
    """任务完成时记账：覆盖率与 staleness 分量都靠它。"""
    kind = mapped_task_kind(subject_kind)
    value = str(subject or "").strip()[:160]
    if not value:
        return
    row = db.scalars(
        select(ObservedSubject).where(ObservedSubject.kind == kind, ObservedSubject.value == value)
    ).first()
    if row is None:
        db.add(
            ObservedSubject(
                kind=kind,
                value=value,
                first_seen_at=now,
                last_seen_at=now,
                seen_count=1,
                analyzed_count=1,
                last_analyzed_at=now,
            )
        )
        return
    row.analyzed_count = int(row.analyzed_count or 0) + 1
    row.last_analyzed_at = now


def seen_info(kind: str, value: str) -> dict[str, Any]:
    """查某个对象的"见过多少次 / 分析过多少次 / 上次分析在何时"。"""
    with SessionLocal() as db:
        row = db.scalars(
            select(ObservedSubject).where(
                ObservedSubject.kind == kind, ObservedSubject.value == value
            )
        ).first()
        if row is None:
            return {"known": False, "seen_count": 0, "analyzed_count": 0, "last_analyzed_at": ""}
        return {
            "known": True,
            "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else "",
            "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else "",
            "seen_count": int(row.seen_count or 0),
            "analyzed_count": int(row.analyzed_count or 0),
            "last_analyzed_at": row.last_analyzed_at.isoformat() if row.last_analyzed_at else "",
        }


def staleness(subject_kind: str, subject: str, now: datetime | None = None) -> float:
    """距上次分析的**客观**时长 → 0~1（从未分析 = 1.0）。不含任何威胁判断。"""
    ts = now or datetime.now(UTC)
    info = seen_info(mapped_task_kind(subject_kind), subject)
    last = info.get("last_analyzed_at") or ""
    if not last:
        return 1.0
    try:
        when = datetime.fromisoformat(str(last))
    except (TypeError, ValueError):
        return 1.0
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    days = max(0.0, (ts - when).total_seconds() / 86400.0)
    if days > 7:
        return 0.9
    if days > 2:
        return 0.5
    return 0.1


def coverage(days: int = 7, kind: str = "", limit: int = 100) -> dict[str, Any]:
    """覆盖率与盲区清单：哪些对象从来没看过、哪些久未看。

    这是智能体"自主找活"的数据面 —— 没有它，智能体只能被动接单，谈不上规划。
    """
    window = max(1, int(days or 7))
    k = str(kind or "").strip()[:24]
    cap = max(1, min(int(limit or 100), 500))
    cutoff = datetime.now(UTC) - timedelta(days=window)
    conds: list[Any] = [ObservedSubject.last_seen_at >= cutoff]
    if k:
        conds.append(ObservedSubject.kind == k)
    try:
        with SessionLocal() as db:
            total = int(
                db.scalar(select(func.count()).select_from(ObservedSubject).where(*conds)) or 0
            )
            analyzed = int(
                db.scalar(
                    select(func.count())
                    .select_from(ObservedSubject)
                    .where(*conds, ObservedSubject.last_analyzed_at >= cutoff)
                )
                or 0
            )
            never = db.scalars(
                select(ObservedSubject)
                .where(*conds, ObservedSubject.last_analyzed_at.is_(None))
                .order_by(ObservedSubject.last_seen_at.desc())
                .limit(cap)
            ).all()
            stale = db.scalars(
                select(ObservedSubject)
                .where(
                    *conds,
                    ObservedSubject.last_analyzed_at.is_not(None),
                    ObservedSubject.last_analyzed_at < cutoff,
                )
                .order_by(ObservedSubject.last_analyzed_at.asc())
                .limit(cap)
            ).all()
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读覆盖率失败：{exc}", "days": window, "items": []}
    items = [
        {
            # C4：主体类型就是登记时的类型（资产的盲区任务不该写成 signature，反之亦然）
            "kind": r.kind,
            "subject": r.value,
            "subject_kind": r.kind,
            "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else "",
            "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else "",
            "seen_count": int(r.seen_count or 0),
            "analyzed_count": int(r.analyzed_count or 0),
            "last_analyzed_at": r.last_analyzed_at.isoformat() if r.last_analyzed_at else "",
            "why": "从未分析" if r.last_analyzed_at is None else "久未分析",
        }
        for r in list(never) + list(stale)
    ]
    return {
        "days": window,
        "subjects_total": total,
        "analyzed": analyzed,
        "coverage_ratio": round(analyzed / total, 4) if total else 0.0,
        "never_analyzed": len(never),
        "stale": len(stale),
        "returned": len(items),
        "items": items[:cap],
    }


def inventory(limit_per_kind: int = 200, kind: str = "") -> dict[str, Any]:
    """对象清单（数据地图的一路：资产/端口/对端/协议/签名）。

    `kind` 留空 = 每一类各取一批；给了就只看那一类（智能体说「我只看内网资产」）。
    """
    cap = max(1, min(int(limit_per_kind or 200), 1000))
    picked = [k for k in SUBJECT_KINDS if not kind or k == str(kind).strip().lower()]
    out: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "kinds": {},
        "known_kinds": list(SUBJECT_KINDS),
    }
    if kind and not picked:
        out["error"] = f"kind 只认：{'、'.join(SUBJECT_KINDS)}"
        return out
    try:
        with SessionLocal() as db:
            for item_kind in picked:
                rows = db.scalars(
                    select(ObservedSubject)
                    .where(ObservedSubject.kind == item_kind)
                    .order_by(ObservedSubject.last_seen_at.desc())
                    .limit(cap)
                ).all()
                if not rows:
                    continue
                out["kinds"][item_kind] = {
                    "count": int(
                        db.scalar(
                            select(func.count())
                            .select_from(ObservedSubject)
                            .where(ObservedSubject.kind == item_kind)
                        )
                        or 0
                    ),
                    "items": [
                        {
                            "value": r.value,
                            "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else "",
                            "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else "",
                            "seen_count": int(r.seen_count or 0),
                            "analyzed_count": int(r.analyzed_count or 0),
                        }
                        for r in rows
                    ],
                }
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"读对象清单失败：{exc}"
    return out


def cleanup() -> dict[str, Any]:
    """按保留期清理长期没再见到的对象（表不许只增不减）。"""
    days = params.subject_retention_days()
    before = datetime.now(UTC) - timedelta(days=days)
    try:
        with SessionLocal() as db:
            rows = list(
                db.scalars(
                    select(ObservedSubject).where(ObservedSubject.last_seen_at < before)
                ).all()
            )
            for row in rows:
                db.delete(row)
            db.commit()
            return {"deleted": len(rows)}
    except Exception as exc:  # noqa: BLE001
        return {"deleted": 0, "error": str(exc)[:200]}
