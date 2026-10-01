"""基线（第 8 期从智能体侧迁来）：数值 2σ 规模、账号/会话画像、按 IP 查维度。

读取分两处：
- **库**：`baseline_stats` / `entity_profiles` 两张表（学习进度与画像内容）；
- **Redis**：检测器进程每轮落库时写的心跳计数（判断基线有没有在跑）。
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from app.api.deps import get_current_user
from app.baseline import profile as profiles, stats as stats_mod
from app.config import settings
from app.db.models import User
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/baseline", tags=["baseline"])


def _detector_counters() -> dict[str, Any]:
    """检测器进程写入 Redis 的基线心跳（进程不在就没有，属正常）。"""
    try:
        import redis as _redis

        client = _redis.Redis.from_url(settings.redis_url, decode_responses=True)
        raw = client.hgetall(settings.baseline_stats_key)
    except Exception as exc:  # noqa: BLE001
        log.debug("读基线计数失败: %s", exc)
        return {"alive": False}
    if not isinstance(raw, dict) or not raw:
        return {"alive": False}
    out: dict[str, Any] = {"alive": bool(raw)}
    for field, value in raw.items():
        if field == "flush_at":
            out[field] = int(float(value or 0))
        else:
            try:
                out[field] = int(float(value or 0))
            except (TypeError, ValueError):
                out[field] = value
    return out


@router.get("")
def baseline_overview(
    _: Annotated[User, Depends(get_current_user)],
    limit: int = 10,
):
    """运行状态页用：基线规模、观测期进度、过阈值画像 TOP、检测器侧计数。"""
    top = max(1, min(int(limit or 10), 50))
    snap = stats_mod.snapshot()
    anomalies = profiles.top_anomalies(top)
    return {
        "enabled": bool(settings.baseline_enabled),
        "profile_enabled": bool(settings.profile_enabled),
        "observe_days": int(settings.baseline_observe_days),
        "zscore": float(settings.baseline_zscore),
        "risk_threshold": float(settings.profile_risk_threshold),
        "flush_seconds": int(settings.baseline_flush_seconds),
        "stats": snap,
        "anomalies": anomalies,
        "detector": _detector_counters(),
        "note": (
            "观测期内的维度不参与判定；「没报偏离」不等于正常。"
            "判据 当前值 > mean + zσ，NDR 只在摘要里打标，定性由智能体做。"
        ),
    }


@router.get("/profiles")
def baseline_profiles(
    _: Annotated[User, Depends(get_current_user)],
    kind: str = "",
    min_risk: float = 0.0,
    limit: int = 50,
    offset: int = 0,
):
    """账号/会话画像列表（按风险降序），可按 kind / 风险下限过滤。"""
    kind_clean = kind.strip().lower() if kind else ""
    return profiles.list_profiles(
        kind=kind_clean if kind_clean in (profiles.ACCOUNT, profiles.SESSION) else None,
        min_risk=max(0.0, float(min_risk or 0.0)),
        limit=max(1, min(int(limit or 50), 200)),
        offset=max(0, int(offset or 0)),
    )


@router.get("/stats")
def baseline_stats(
    _: Annotated[User, Depends(get_current_user)],
    ip: str = "",
    key: str = "",
    limit: int = 50,
):
    """数值基线明细：给 IP 查它的全部维度，或给完整 key 查单个维度。"""
    return stats_mod.lookup(ip=ip, key=key, limit=max(1, min(int(limit or 50), 500)))
