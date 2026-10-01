"""数值基线的存取（Welford 在线均值 / 方差）。

第 8 期从智能体侧迁来（原 `agent/backend/app/agents/persistence.py` 的 `update_baseline` /
`get_baseline`，以及 `agents/deep_analysis.py` 的 `_stat_features`）：算法与字段一致，
只是换成批量接口 —— 检测器每个聚合窗口一次带出多条摘要的统计量。

**观测期**：`baseline_observe_days` 天之内只学习、不判异常（`warmed=False`）。

**单写者**：只有持锁的检测器实例会调 `apply_stats`，所以不用加锁。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select

from app.config import settings
from app.db.base import SessionLocal
from app.db.models import BaselineStat
from app.workers.log import get_logger

log = get_logger(__name__)

_BATCH = 500  # 单条 SQL 的 in_ 参数上限，分批查


def _std(m2: float, count: int) -> float:
    """样本标准差（与智能体侧 `variance = m2 / (count - 1)` 一致）。"""
    if count < 2:
        return 0.0
    return max(0.0, m2 / (count - 1)) ** 0.5


def _warmed(first_seen: datetime | None, now: datetime) -> bool:
    if first_seen is None:
        return False
    days = max(0, int(settings.baseline_observe_days))
    if days <= 0:
        return True
    return first_seen <= now - timedelta(days=days)


def _state(row: BaselineStat, now: datetime) -> dict[str, Any]:
    count = int(row.count or 0)
    m2 = float(row.m2 or 0.0)
    return {
        "count": count,
        "mean": round(float(row.mean or 0.0), 4),
        "m2": round(m2, 4),
        "std": round(_std(m2, count), 4),
        "first_seen": row.first_seen.isoformat() if row.first_seen else "",
        "warmed": _warmed(row.first_seen, now),
    }


def load_stats(keys: list[str]) -> dict[str, dict[str, Any]]:
    """批量读基线；库里没有的键不出现在结果里。"""
    wanted = [k for k in dict.fromkeys(keys) if k][: _BATCH * 8]
    if not wanted:
        return {}
    now = datetime.now(UTC)
    out: dict[str, dict[str, Any]] = {}
    try:
        with SessionLocal() as db:
            for start in range(0, len(wanted), _BATCH):
                chunk = wanted[start : start + _BATCH]
                rows = db.scalars(select(BaselineStat).where(BaselineStat.key.in_(chunk))).all()
                for row in rows:
                    out[row.key] = _state(row, now)
    except Exception as exc:  # noqa: BLE001
        log.warning("读取基线失败（按“还没学到”处理）: %s", exc)
    return out


def apply_stats(values: dict[str, list[float]]) -> dict[str, dict[str, Any]]:
    """把一批观测并进基线（Welford 增量），返回并入后的状态。"""
    merged: dict[str, list[float]] = {k: v for k, v in values.items() if k and v}
    if not merged:
        return {}
    now = datetime.now(UTC)
    out: dict[str, dict[str, Any]] = {}
    try:
        with SessionLocal() as db:
            keys = list(merged)
            rows: dict[str, BaselineStat] = {}
            for start in range(0, len(keys), _BATCH):
                chunk = keys[start : start + _BATCH]
                for row in db.scalars(select(BaselineStat).where(BaselineStat.key.in_(chunk))).all():
                    rows[row.key] = row
            for key, samples in merged.items():
                row = rows.get(key)
                if row is None:
                    row = BaselineStat(key=key, count=0, mean=0.0, m2=0.0, first_seen=now)
                    db.add(row)
                count = int(row.count or 0)
                mean = float(row.mean or 0.0)
                m2 = float(row.m2 or 0.0)
                for value in samples:
                    count += 1
                    delta = value - mean
                    mean += delta / count
                    m2 += delta * (value - mean)
                row.count = count
                row.mean = mean
                row.m2 = m2
                row.updated_at = now
                out[key] = {
                    "count": count,
                    "mean": round(mean, 4),
                    "m2": round(m2, 4),
                    "std": round(_std(m2, count), 4),
                    "first_seen": (row.first_seen or now).isoformat(),
                    "warmed": _warmed(row.first_seen or now, now),
                }
            db.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("写入基线失败（下一轮重试）: %s", exc)
        return {}
    return out


def lookup(ip: str = "", key: str = "", limit: int = 50) -> dict[str, Any]:
    """按 IP（该 IP 的全部维度）或完整 key 查基线。"""
    try:
        cap = max(1, min(int(limit or 50), 500))
    except (TypeError, ValueError):
        cap = 50
    ip = (ip or "").strip()
    key = (key or "").strip()
    if not ip and not key:
        return {"error": "ip 与 key 至少给一个（ip 查这个 IP 的全部基线维度）"}
    cond = BaselineStat.key == key if key else BaselineStat.key.like(f"{ip}:%")
    now = datetime.now(UTC)
    try:
        with SessionLocal() as db:
            rows = list(
                db.scalars(
                    select(BaselineStat).where(cond).order_by(BaselineStat.key).limit(cap)
                ).all()
            )
            total = int(db.scalar(select(func.count()).select_from(BaselineStat).where(cond)) or 0)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读基线失败：{exc}"}
    return {
        "ip": ip,
        "key": key,
        "total": total,
        "returned": len(rows),
        "observe_days": int(settings.baseline_observe_days),
        "items": [
            {"key": row.key, "feature": row.key.split(":")[-1], **_state(row, now)} for row in rows
        ],
    }


def snapshot() -> dict[str, Any]:
    """运行状态页用：基线规模与观测期进度。"""
    now = datetime.now(UTC)
    days = max(0, int(settings.baseline_observe_days))
    warmed_cut = now - timedelta(days=days)
    try:
        with SessionLocal() as db:
            total = int(db.scalar(select(func.count()).select_from(BaselineStat)) or 0)
            warmed = int(
                db.scalar(
                    select(func.count())
                    .select_from(BaselineStat)
                    .where(
                        BaselineStat.first_seen.is_not(None),
                        BaselineStat.first_seen <= warmed_cut,
                    )
                )
                or 0
            )
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读基线失败：{exc}", "total_keys": 0, "warmed_keys": 0}
    return {
        "observe_days": days,
        "total_keys": total,
        "warmed_keys": warmed,
        "learning_keys": max(0, total - warmed),
    }
