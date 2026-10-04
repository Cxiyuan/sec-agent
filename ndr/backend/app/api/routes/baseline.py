"""基线（第 8 期从智能体侧迁来）：数值 2σ 规模、账号/会话画像、按 IP 查维度。

读取分两处：
- **库**：`baseline_stats` / `entity_profiles` 两张表（学习进度与画像内容）；
- **Redis**：检测器进程每轮落库时写的心跳计数（判断基线有没有在跑）。
"""

from __future__ import annotations

import threading
import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends

from app.api.deps import get_current_user
from app.baseline import profile as profiles, stats as stats_mod
from app.config import settings
from app.db.models import User
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/baseline", tags=["baseline"])

#: 进程内缓存：总览页每 15 秒轮询一次，而这个端点要跑聚合 SQL + 读 Redis。
#: 复用组件探测那个 30 秒 TTL（同一张页、同一个节奏），与项目「15s 轮询不得穿透」的约定一致。
_cache: dict[int, tuple[float, dict[str, Any]]] = {}
_cache_lock = threading.Lock()


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
        # Redis 里全是字符串，统一按数字解析；解不出来就原样回（别把 None 变成 0）
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
    """运行状态页用：基线规模、观测期进度、过阈值画像 TOP、检测器侧计数。

    结果进程内缓存 `status_probe_cache_seconds`（默认 30s，0 = 关）。
    """
    top = max(1, min(int(limit or 10), 50))
    ttl = max(0.0, float(settings.status_probe_cache_seconds))
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(top)
        if ttl > 0 and hit is not None and now - hit[0] < ttl:
            return {**hit[1], "cached": True}
    payload = _build_overview(top)
    with _cache_lock:
        _cache[top] = (now, payload)
        # 只要最近用过的 limit（界面只会用 10），不影响其它请求
        if len(_cache) > 8:
            for key in list(_cache)[: len(_cache) - 8]:
                _cache.pop(key, None)
    return {**payload, "cached": False}


def _build_overview(top: int) -> dict[str, Any]:
    """真去读库/Redis（不缓存）。"""
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
            "画像风险分按「当前窗口」算：本轮无异常就归零并清空，risk_at 是判定时间。"
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
    """账号/会话画像列表（按风险降序），可按 kind / 风险下限过滤。

    界面目前只画了 `GET /api/baseline` 总览里的 TOP 画像，这个列表接口还**没接前端**；
    它是第 8 期交付时写进 `docs/ndr-redesign.md` 的对外只读能力，保留（未删）。
    """
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
    """数值基线明细：给 IP 查它的全部维度，或给完整 key 查单个维度。

    同 `/profiles`：文档里的对外只读能力，尚未接前端，保留。
    """
    return stats_mod.lookup(ip=ip, key=key, limit=max(1, min(int(limit or 50), 500)))
