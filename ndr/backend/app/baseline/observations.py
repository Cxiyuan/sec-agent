"""观察事实（Observation）：行为基线发现"和平时不一样"，只描述事实，不下结论。

与 `hit_events` 的分工：

| | hit_events | observations |
|---|---|---|
| 谁产生 | 规则命中（含签名/内置规则） | 基线偏离（外连目的地 / 地理 / 爆破 / 404 / 计数） |
| 内容 | 规则名 + 严重度 + 证据 | 改了哪一维、基线值、观测值、时间 |
| 判定 | 规则已经"判"过了 | **不判**，判断权在智能体 |

同一 `dedupe_key` 在冷却期内只留一行：重复出现只累加次数与最近时间，
不会把同一条事实刷成一屏（2026-10 首见线索洪水踩过一次）。

暴露给智能体的 MCP 工具见 `app/mcp/ndr_tools.py::list_observations`；
界面接口见 `app/api/routes/observations.py`。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select

from app.db.base import SessionLocal
from app.db.models import Observation
from app.workers.log import get_logger

UTC = timezone.utc

log = get_logger(__name__)

#: 同一事实的冷却期（分钟）：期间重复出现只累加次数
DEFAULT_COOLDOWN_MINUTES = 120

#: 各 kind 的默认强度（客观强度，不是严重度；只用于排序与预算）
KIND_STRENGTH: dict[str, float] = {
    "egress_new": 0.6,
    "egress_rare": 0.35,
    "geo_jump": 0.7,
    "login_bruteforce": 0.6,
    "path_probe": 0.45,
    "conn_shift": 0.2,
}

KIND_LABELS: dict[str, str] = {
    "egress_new": "外连目的地首次出现",
    "egress_rare": "外连目的地罕见",
    "geo_jump": "账号登录地点变化",
    "login_bruteforce": "账号被多来源尝试登录",
    "path_probe": "客户端大量 404",
    "conn_shift": "连接数高于自身基线",
}


def emit(
    kind: str,
    subject_kind: str,
    subject: str,
    facts: dict[str, Any],
    *,
    key: str = "",
    strength: float | None = None,
    cooldown_minutes: int = DEFAULT_COOLDOWN_MINUTES,
    now: datetime | None = None,
) -> bool:
    """写一条事实（冷却期内合并）。失败只告警，**绝不影响检测热路径**。

    `key` 用来区分同一对象的多个事实（例如同一台服务器的不同目的地）；
    不传就用 `facts` 的键集合当签名 —— 调用方最好显式传。
    """
    subject = str(subject or "").strip()[:128]
    if subject == "" or kind == "":
        return False
    moment = now or datetime.now(UTC)
    fingerprint = key or ",".join(sorted(str(k) for k in facts))
    dedupe = f"{kind}:{subject_kind}:{subject}:{fingerprint}"[:200]
    value = KIND_STRENGTH.get(kind, 0.3) if strength is None else max(0.0, min(1.0, strength))
    try:
        with SessionLocal() as db:
            row = db.execute(
                select(Observation).where(Observation.dedupe_key == dedupe)
            ).scalar_one_or_none()
            if row is not None:
                last = row.last_seen
                if last is not None and last.tzinfo is None:
                    last = last.replace(tzinfo=UTC)
                if last is not None and moment - last < timedelta(minutes=cooldown_minutes):
                    row.count = int(row.count or 0) + 1
                    row.last_seen = moment
                    row.strength = max(float(row.strength or 0), value)
                    row.facts = facts
                    db.commit()
                    return True
                # 冷却期过了：复用同一行（保留 first_seen，刷新内容与计数起点）
                row.count = 1
                row.facts = facts
                row.strength = value
                row.last_seen = moment
                db.commit()
                return True
            db.add(
                Observation(
                    kind=kind[:32],
                    subject_kind=subject_kind[:16],
                    subject=subject,
                    facts=facts,
                    strength=value,
                    count=1,
                    first_seen=moment,
                    last_seen=moment,
                    dedupe_key=dedupe,
                )
            )
            db.commit()
            return True
    except Exception as exc:  # noqa: BLE001 — 事实写失败不能拖垮检测
        log.warning("写观察事实失败（%s/%s）：%s", kind, subject, exc)
        return False


def list_observations(
    *,
    kind: str = "",
    subject: str = "",
    minutes: int = 24 * 60,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """按时间倒序分页（界面 / MCP 共用）。"""
    cap = max(1, min(int(limit or 50), 200))
    start = max(0, int(offset or 0))
    since = datetime.now(UTC) - timedelta(minutes=max(1, int(minutes or 1440)))
    try:
        with SessionLocal() as db:
            conds = [Observation.last_seen >= since]
            if kind:
                conds.append(Observation.kind == kind)
            if subject:
                conds.append(Observation.subject == subject)
            total = int(
                db.scalar(select(func.count()).select_from(Observation).where(*conds)) or 0
            )
            rows = list(
                db.scalars(
                    select(Observation)
                    .where(*conds)
                    .order_by(Observation.last_seen.desc())
                    .limit(cap)
                    .offset(start)
                ).all()
            )
    except Exception as exc:  # noqa: BLE001 — 读失败返回空表并说明原因
        log.warning("读观察事实失败：%s", exc)
        return {"available": False, "error": str(exc)[:200], "total": 0, "items": []}
    return {"available": True, "total": total, "items": [_row_dict(r) for r in rows]}


def stats(minutes: int = 1440) -> dict[str, Any]:
    """按 kind 汇总（界面顶部卡片用）。"""
    since = datetime.now(UTC) - timedelta(minutes=max(1, int(minutes or 1440)))
    try:
        with SessionLocal() as db:
            rows = db.execute(
                select(Observation.kind, func.count(), func.max(Observation.last_seen))
                .where(Observation.last_seen >= since)
                .group_by(Observation.kind)
            ).all()
    except Exception as exc:  # noqa: BLE001
        log.warning("观察事实统计失败：%s", exc)
        return {"available": False, "error": str(exc)[:200], "kinds": []}
    kinds = [
        {
            "kind": str(row[0] or ""),
            "label": KIND_LABELS.get(str(row[0] or ""), str(row[0] or "")),
            "count": int(row[1] or 0),
            "last_seen": row[2].isoformat() if row[2] is not None else "",
        }
        for row in rows
    ]
    kinds.sort(key=lambda item: -int(item["count"]))
    return {"available": True, "kinds": kinds}


def recent_for_subject(subject: str, *, limit: int = 5, hours: int = 24) -> list[dict[str, Any]]:
    """某个对象最近的事实（把规则命中作为附加证据时用）。"""
    since = datetime.now(UTC) - timedelta(hours=max(1, hours))
    try:
        with SessionLocal() as db:
            rows = list(
                db.scalars(
                    select(Observation)
                    .where(Observation.subject == subject, Observation.last_seen >= since)
                    .order_by(Observation.last_seen.desc())
                    .limit(max(1, min(limit, 50)))
                ).all()
            )
    except Exception:  # noqa: BLE001
        return []
    return [_row_dict(row) for row in rows]


def _row_dict(row: Observation) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "kind": row.kind,
        "kind_label": KIND_LABELS.get(str(row.kind or ""), str(row.kind or "")),
        "subject_kind": row.subject_kind,
        "subject": row.subject,
        "facts": row.facts or {},
        "strength": round(float(row.strength or 0), 3),
        "count": int(row.count or 0),
        "first_seen": row.first_seen.isoformat() if row.first_seen else "",
        "last_seen": row.last_seen.isoformat() if row.last_seen else "",
    }
