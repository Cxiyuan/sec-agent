"""基线（第 8 期从智能体侧迁来）：数值 2σ 规模、账号/会话画像、按 IP 查维度。

读取分两处：
- **库**：`baseline_stats` / `entity_profiles` 两张表（学习进度与画像内容）；
- **Redis**：检测器进程每轮落库时写的心跳计数（判断基线有没有在跑）。

后台「行为分析」页用这里的接口：`/api/baseline`（总览 + 当前风险 TOP）、`/profiles`（画像列表，
支持搜索/筛选/分页）、`/numeric`（数值基线浏览）、`/stats`（按 IP 或 key 精查）、
`/config`（**可调参数的读与写**，白名单见 `app/baseline/params.py`）。
"""

from __future__ import annotations

import threading
import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.baseline import params, profile as profiles, stats as stats_mod
from app.baseline.asset import (
    asset_detail,
    list_assets,
    snapshot as assets_snapshot,
)
from app.config import settings
from app.db.base import get_db
from app.db.models import AlertDisposition, EntityProfile, User
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
    for raw_field, raw_value in raw.items():
        # redis-py 的类型签名是 `bytes | str`（`decode_responses=True` 只是运行时行为，
        # 类型上不收窄）—— 这里显式归一，既过类型检查，也顺手兼容没解码的连接。
        field = raw_field.decode() if isinstance(raw_field, bytes) else str(raw_field)
        value = raw_value.decode() if isinstance(raw_value, bytes) else raw_value
        # 改名前的歧义字段不往外吐（旧字段名叫 anomalies，实际是「上一轮的值」，
        # 被当成累计值读就会误判「没有异常」）。心跳键有 24h TTL，老进程写过的值会残留。
        if field in ("anomalies", "numeric_keys"):
            continue
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
    # 界面只展示**账号**画像（会话的展示名是 cookie 哈希前 8 位，运维看不懂）。
    # 会话画像本身仍在算，摘要标签与 MCP `entity_profile` 都还看得到。
    anomalies = profiles.top_anomalies(top, kind=profiles.ACCOUNT)
    return {
        "enabled": params.baseline_enabled(),
        "profile_enabled": params.profile_enabled(),
        "observe_days": params.observe_days(),
        "zscore": params.zscore(),
        "risk_threshold": params.risk_threshold(),
        "flush_seconds": params.flush_seconds(),
        "stats": snap,
        "assets": assets_snapshot(),
        "anomalies": anomalies,
        "detector": _detector_counters(),
        "note": (
            "观测期内的维度不参与判定；「没报偏离」不等于正常。"
            "判据 当前值 > mean + zσ，NDR 只在摘要里打标，定性由智能体做。"
            "画像风险分按「当前窗口」算：本轮无异常就归零并清空，risk_at 是判定时间；"
            "这里只列账号画像（会话展示名是哈希，用 MCP entity_profile 查）。"
        ),
    }


@router.get("/profiles")
def baseline_profiles(
    _: Annotated[User, Depends(get_current_user)],
    kind: str = "",
    q: str = "",
    min_risk: float = 0.0,
    limit: int = 50,
    offset: int = 0,
):
    """账号/会话画像列表（按风险降序）：可按 kind / 名称搜索 / 风险下限过滤，带分页。

    后台「行为分析」页的画像表就是它。`q` 匹配展示名或实体键（账号的展示名就是账号名；
    会话是 cookie 哈希，只能按哈希前几位搜）。风险分是「当前窗口」的值，
    每行都带 `risk_at`（判定时间）好判断新旧。
    """
    kind_clean = kind.strip().lower() if kind else ""
    return profiles.list_profiles(
        kind=kind_clean if kind_clean in (profiles.ACCOUNT, profiles.SESSION) else None,
        q=q,
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


@router.get("/numeric")
def baseline_numeric(
    _: Annotated[User, Depends(get_current_user)],
    q: str = "",
    feature: str = "",
    sort: str = "count",
    limit: int = 50,
    offset: int = 0,
    group: str = "key",
    scope: str = "entity",
):
    """数值基线浏览（「行为分析」页的表格）：按 key 子串 / 维度过滤，排序 + 分页。

    `scope`：`entity`（默认，只看 `源IP:维度`）／`group`（只看 `grp:{网段}:维度` 组先验）／
    `all`（两者都返回）。组先验是等组池化的内部统计，不是"某个 IP 的基线"。

    `group=ip` 时**一行一个 IP**（各维度放进 `features`）且**分页按 IP 走** —— 页面用这个模式，
    列表从 3×IP 行降到 1×IP 行；`group=key`（默认）是一行一个 `源IP:维度`。
    与 `/stats` 的区别：`/stats` 要指名 IP 或完整 key（适合精确查），这个能「翻着看」。
    """
    return stats_mod.list_stats(
        q=q,
        feature=feature,
        sort=sort,
        limit=limit,
        offset=offset,
        group=group,
        scope=scope,
    )


@router.get("/assets")
def baseline_assets(
    _: Annotated[User, Depends(get_current_user)],
    q: str = "",
    sort: str = "visits",
    limit: int = 50,
    offset: int = 0,
    scope: str = "",
):
    """**被访问方（内网源站 / 内网 DNS 转发器）列表**：分页 + 搜索 + 归属过滤。

    与源头数值基线的区别：那份是按**发起方（源 IP）**建的，服务器被访问这件事在那里没有归属
    （外网打内网服务器时事件都记在客户端那侧）；这份按**被访问方**建，看的是
    「被访问连接数 / 请求数 / 不同真实客户端数 / 不同目标数」的窗口间波动
    （访问数按 **Zeek 连接（uid）**算：同一连接里的 conn 与 http/ssl 只算一次）。

    `scope`：`internal` = 内网被访问方（**异常判定只看这一块**）/ `external` = 公网目标
    （含公共 DNS 解析器，如 `1.1.1.1`、`8.8.8.8`）；留空 = 全部。
    """
    return list_assets(q=q, sort=sort, limit=limit, offset=offset, scope=scope)


@router.get("/assets/stats")
def baseline_asset_stats(
    _: Annotated[User, Depends(get_current_user)],
    asset: str = "",
):
    """单个被访问方资产的全部特征明细（均值/标准差/观测次数/是否过观测期）。"""
    return asset_detail(asset)


class ConfigIn(BaseModel):
    values: dict[str, Any] = Field(default_factory=dict)


class ConfigResetIn(BaseModel):
    keys: list[str] = Field(default_factory=list)


def _invalidate_overview_cache() -> None:
    """参数改了以后，总览缓存里的标量（观测期/阈值…）立刻就旧了，清掉。"""
    with _cache_lock:
        _cache.clear()


@router.get("/config")
def baseline_config(_: Annotated[User, Depends(get_current_user)]):
    """可调参数清单：类型/范围/默认值/当前值/是否被后台改过（前端据此渲染表单）。"""
    return {"items": params.items(), "effective": params.effective()}


@router.put("/config")
def save_baseline_config(
    payload: ConfigIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """保存可调参数（**只允许白名单里的键**）；校验不过 400 + `field_errors`。

    改完立即生效（配置缓存被 invalidate）——检测器下一个窗口就用新值，不用重启。
    """
    values = payload.values or {}
    if not values:
        return JSONResponse(
            status_code=400, content={"conflict": "field_error", "detail": "没有要保存的参数"}
        )
    errors = params.validate(values)
    if errors:
        return JSONResponse(
            status_code=400,
            content={
                "conflict": "field_error",
                "detail": errors[0]["msg"],
                "field_errors": errors,
            },
        )
    written = params.save(db, values)
    _invalidate_overview_cache()
    log.info("基线/画像参数已更新：%d 项（%s）", written, ", ".join(sorted(values)))
    return {"written": written, "items": params.items(), "effective": params.effective()}


@router.post("/config/reset")
def reset_baseline_config(
    payload: ConfigResetIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """恢复默认：删掉后台覆盖值（`keys` 为空 = 全部恢复）。"""
    removed = params.reset(db, payload.keys or None)
    _invalidate_overview_cache()
    log.info("基线/画像参数已恢复默认：%d 项", removed)
    return {"removed": removed, "items": params.items(), "effective": params.effective()}


# ---------- 误报闭环（2026-10）----------


class DispositionIn(BaseModel):
    """处置标注：`false_positive`（误报，降权）或 `confirm`（确认，仅留档）。"""

    verdict: str = "false_positive"
    #: 空 = 整条告警级别；填信号码（如 `new_src_ip`）= 只降权那一路证据
    signal: str = ""
    note: str = ""


def _disposition_item(row: AlertDisposition) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "kind": row.kind,
        "entity_key": row.entity_key,
        "signal": row.signal,
        "verdict": row.verdict,
        "operator": row.operator,
        "note": row.note,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.post("/alerts/{profile_id}/disposition")
def save_alert_disposition(
    profile_id: str,
    payload: DispositionIn,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    """给一条画像告警打上处置结论（误报 / 确认），用于后续**自动降权**。

    `profile_id` 既接受画像 UUID，也接受实体键（会话是 cookie/设备哈希、账号就是账号名）——
    前端两种地方都能发起，不必先查 UUID。

    降权口径：判成误报后，该实体（或该信号）在 `profile.false_positive_suppress_days`
    天内不再参与打分；只影响打分，理由仍会展示，运维能看到"当初为什么报"。
    """
    row = db.get(EntityProfile, profile_id)
    if row is None:
        row = db.scalars(
            select(EntityProfile).where(EntityProfile.entity_key == profile_id).limit(1)
        ).first()
    if row is None:
        return JSONResponse(
            status_code=404, content={"detail": f"画像不存在：{profile_id}"}
        )
    out = profiles.record_disposition(
        row.kind,
        row.entity_key,
        payload.verdict,
        signal=payload.signal,
        operator=getattr(user, "username", "") or "",
        note=payload.note,
    )
    _invalidate_overview_cache()
    log.info(
        "告警处置：%s %s → %s（signal=%s）",
        row.kind,
        row.entity_key[:12],
        out["verdict"],
        out["signal"] or "整条",
    )
    return out


@router.get("/alerts/dispositions")
def list_alert_dispositions(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    limit: int = 50,
    kind: str = "",
):
    """最近的处置记录（界面「误报记录」用；也可用来核对降权是否生效）。"""
    stmt = select(AlertDisposition).order_by(AlertDisposition.created_at.desc())
    if kind:
        stmt = stmt.where(AlertDisposition.kind == kind)
    rows = db.scalars(stmt.limit(max(1, min(limit, 500)))).all()
    return {"items": [_disposition_item(r) for r in rows], "limit": limit}
