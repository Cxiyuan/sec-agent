"""数值基线的存取（Welford 在线均值 / 方差）。

第 8 期从智能体侧迁来（原 `agent/backend/app/agents/persistence.py` 的 `update_baseline` /
`get_baseline`，以及 `agents/deep_analysis.py` 的 `_stat_features`）：算法与字段一致，
只是换成批量接口 —— 检测器每个聚合窗口一次带出多条摘要的统计量。

**观测期**：`baseline_observe_days` 天之内只学习、不判异常（`warmed=False`）。

**单写者**：只有持锁的检测器实例会调 `apply_stats`，所以不用加锁。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, delete, func, select

from app.baseline import params
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
    days = params.observe_days()
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
                for row in db.scalars(
                    select(BaselineStat).where(BaselineStat.key.in_(chunk))
                ).all():
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


def like_pattern(q: str) -> str:
    """把用户输入转成安全的 LIKE 模式（转义通配符，避免 `%`/`_` 变成未知查询）。"""
    text = (q or "").strip()
    for ch in ("\\", "%", "_"):
        text = text.replace(ch, "\\" + ch)
    return f"%{text}%"


_SORTS: dict[str, Any] = {
    "count": lambda: BaselineStat.count.desc(),
    "updated": lambda: BaselineStat.updated_at.desc(),
    "key": lambda: BaselineStat.key.asc(),
}


def list_stats(
    *,
    q: str = "",
    feature: str = "",
    sort: str = "count",
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """浏览数值基线（后台「行为分析」页用）。

    为什么要有它：`lookup()` 必须指名 IP 或完整 key，页面根本没法「翻着看」。
    过滤：`q` 匹配 key 子串（填 IP 前缀就等于看那个 IP 的维度）；`feature` 按维度后缀匹配。
    排序：count（观测次数，默认）/ updated（最近更新）/ key。
    """
    cap = max(1, min(int(limit or 50), 500))
    start = max(0, int(offset or 0))
    now = datetime.now(UTC)
    conds = []
    if (q or "").strip():
        conds.append(BaselineStat.key.like(like_pattern(q), escape="\\"))
    if (feature or "").strip():
        conds.append(BaselineStat.key.like(like_pattern(f":{feature.strip()}"), escape="\\"))
    order = _SORTS.get((sort or "count").strip(), _SORTS["count"])()
    try:
        with SessionLocal() as db:
            total = int(
                db.scalar(select(func.count()).select_from(BaselineStat).where(*conds)) or 0
            )
            rows = db.scalars(
                select(BaselineStat).where(*conds).order_by(order).limit(cap).offset(start)
            ).all()
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读数值基线失败：{exc}", "total": 0, "items": []}
    items = [
        {"key": row.key, "feature": row.key.split(":")[-1], **_state(row, now)} for row in rows
    ]
    return {
        "total": total,
        "returned": len(items),
        "observe_days": params.observe_days(),
        "items": items,
    }


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
        "observe_days": params.observe_days(),
        "items": [
            {"key": row.key, "feature": row.key.split(":")[-1], **_state(row, now)} for row in rows
        ],
    }


def cleanup(retention_days: int | None = None) -> dict[str, int]:
    """按 ``updated_at`` 删除长期没再观测过的数值基线键。

    为什么必须有（2026-10 实机 QA）：key = ``{src_ip}:{feature}``，被扫过一次的 IP
    （尤其是外网/攻击者地址）会永久留下 3 行；而画像有 `profile_retention_days` 清理、
    数值基线一行清理逻辑都没有 —— 只增不减。
    """
    days = max(0, int(retention_days if retention_days is not None else params.retention_days()))
    if days <= 0:
        return {"deleted": 0}  # 0 = 不清理（与 observe_days 不同，这里允许显式关掉）
    before = datetime.now(UTC) - timedelta(days=days)
    try:
        with SessionLocal() as db:
            result = cast(
                CursorResult[Any],
                db.execute(delete(BaselineStat).where(BaselineStat.updated_at < before)),
            )
            db.commit()
            return {"deleted": result.rowcount or 0}
    except Exception as exc:  # noqa: BLE001
        log.warning("清理数值基线失败: %s", exc)
        return {"deleted": 0}


def snapshot() -> dict[str, Any]:
    """运行状态页用：基线规模与观测期进度。

    **一条 SQL 同时算 total 与 warmed**：以前是两条 ``COUNT(*)``（其中 warmed 还过滤一个
    没有索引的列），而总览页每 15 秒轮询一次 —— 2026-10 实机 QA 发现 seq_scan 已 1660。
    """
    now = datetime.now(UTC)
    days = params.observe_days()
    warmed_cut = now - timedelta(days=days)
    warmed_cond = (BaselineStat.first_seen.is_not(None)) & (BaselineStat.first_seen <= warmed_cut)
    try:
        with SessionLocal() as db:
            # FILTER (WHERE ...) 是 PG 的聚合过滤语法，一次扫描就出三个数
            row = db.execute(
                select(
                    func.count(),
                    func.coalesce(func.count().filter(warmed_cond), 0),
                    func.min(BaselineStat.first_seen),
                ).select_from(BaselineStat)
            ).one()
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读基线失败：{exc}", "total_keys": 0, "warmed_keys": 0}
    total = int(row[0] or 0)
    warmed = int(row[1] or 0)
    oldest = row[2]
    if oldest is not None and oldest.tzinfo is None:
        oldest = oldest.replace(tzinfo=UTC)
    return {
        "observe_days": days,
        "total_keys": total,
        "warmed_keys": warmed,
        "learning_keys": max(0, total - warmed),
        # 观测期进度（界面显示倒计时）：最早观测的维度 + 它什么时候过观测期
        "oldest_first_seen": oldest.isoformat() if oldest else None,
        "next_warm_at": (oldest + timedelta(days=days)).isoformat() if oldest else None,
    }
