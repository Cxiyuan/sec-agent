"""账号 / 会话跨窗口长期画像（UEBA 式统计基线）。

- **提取**：账号（`user` 字段优先；归一化阶段已从登录路径参数兜底提取）；
  会话（从 Cookie 提取会话 id → **SHA-256 哈希**）
- **基线**：频次分布（源 IP / UA / 时段 / 路径）+ 成功失败计数，跨窗口增量累积
- **异常**：新源 IP / 新 UA / 非常用时段 / 认证失败突增 / 会话跨 IP / 认证失败突增
- **安全**：会话只存哈希；**不落库明文 cookie / 口令 / Token**
"""

from __future__ import annotations

import hashlib
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, and_, delete, func, or_, select

from app.config import settings
from app.db.base import SessionLocal
from app.db.models import EntityProfile
from app.schemas import UnifiedLog
from app.workers.log import get_logger

log = get_logger(__name__)

ACCOUNT = "account"
SESSION = "session"

# 基线分布各字段保留的条目上限（避免 JSON 无限膨胀）
_LIMITS: dict[str, int] = {"src_ips": 50, "user_agents": 20, "paths": 30, "hour_hist": 24}


def _csv(value: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in (value or "").split(",") if x.strip())


def _safe_int(value: Any, default: int = 0) -> int:
    """安全转 int（JSONB 里可能是 None / 非数值）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ---------- 实体提取 ----------


def session_id_from_cookie(cookie: str) -> str:
    """从 Cookie 串中按配置的会话 cookie 名提取会话 id 值。"""
    if not cookie:
        return ""
    names = {n.lower() for n in _csv(settings.session_cookie_names)}
    for part in cookie.split(";"):
        if "=" not in part:
            continue
        name, _, value = part.partition("=")
        if name.strip().lower() in names and value.strip():
            return value.strip().strip('"')
    return ""


def session_entity(cookie: str) -> tuple[str, str]:
    """返回 (entity_key=哈希, display=前 8 位)；无法识别返回 ("", "")。"""
    sid = session_id_from_cookie(cookie)
    if not sid:
        return "", ""
    digest = hashlib.sha256(sid.encode("utf-8", errors="ignore")).hexdigest()
    return digest, digest[:8]


def account_entity(entry: UnifiedLog) -> str:
    """账号：归一化阶段已做提取（user 字段优先，其次登录路径参数）。"""
    return (entry.account or entry.user or "").strip()[:128]


# ---------- 窗口观测聚合 ----------


def _new_bucket(kind: str, key: str, display: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "key": key,
        "display": display,
        "src_ips": Counter(),
        "user_agents": Counter(),
        "paths": Counter(),
        "hours": Counter(),
        "success": 0,
        "fail": 0,
        "count": 0,
    }


def _accumulate(bucket: dict[str, Any], entry: UnifiedLog) -> None:
    bucket["count"] += 1
    if entry.src_ip:
        bucket["src_ips"][str(entry.src_ip)] += 1
    if entry.user_agent:
        bucket["user_agents"][entry.user_agent[:128]] += 1
    if entry.uri_path:
        bucket["paths"][entry.uri_path[:128]] += 1
    bucket["hours"][str(entry.ts.hour)] += 1
    if entry.status_code:
        if entry.status_code in (401, 403):
            bucket["fail"] += 1
        elif entry.status_code < 400:
            bucket["success"] += 1


def window_observations(logs: list[UnifiedLog]) -> dict[str, dict[str, Any]]:
    """按实体聚合本窗口观测，key = f"{kind}|{entity_key}"。"""
    out: dict[str, dict[str, Any]] = {}
    for entry in logs:
        account = account_entity(entry)
        if account:
            bucket_key = f"{ACCOUNT}|{account}"
            out.setdefault(bucket_key, _new_bucket(ACCOUNT, account, account))
            _accumulate(out[bucket_key], entry)

        skey, sdisplay = session_entity(entry.cookie)
        if skey:
            bucket_key = f"{SESSION}|{skey}"
            out.setdefault(bucket_key, _new_bucket(SESSION, skey, sdisplay))
            _accumulate(out[bucket_key], entry)
    return out


# ---------- 读画像 ----------


def load_profiles(keys: list[tuple[str, str]]) -> dict[str, EntityProfile]:
    """按 (kind, key) 批量读取画像。"""
    pairs = keys[:500]
    if not pairs:
        return {}
    conds = [
        and_(EntityProfile.kind == kind, EntityProfile.entity_key == key) for kind, key in pairs
    ]
    try:
        with SessionLocal() as db:
            rows = db.scalars(select(EntityProfile).where(or_(*conds))).all()
    except Exception as exc:  # noqa: BLE001
        log.warning("读取实体画像失败: %s", exc)
        return {}
    return {f"{r.kind}|{r.entity_key}": r for r in rows}


# ---------- 异常判定 ----------


def detect(kind: str, obs: dict[str, Any], profile: EntityProfile | None) -> dict[str, Any]:
    """与长期基线比对，返回 {reasons, risk, cold_start}。冷启动只学习不告警。"""
    if profile is None or (profile.obs_count or 0) < settings.profile_min_obs:
        return {"reasons": [], "risk": 0.0, "cold_start": True}

    reasons: list[str] = []
    risk = 0.0

    known_ips = set((profile.src_ips or {}).keys())
    new_ips = sorted(ip for ip in obs["src_ips"] if ip not in known_ips)
    if new_ips:
        reasons.append(f"新源 IP：{', '.join(new_ips[:3])}")
        risk += 0.35

    known_ua = set((profile.user_agents or {}).keys())
    new_ua = sorted(ua for ua in obs["user_agents"] if ua not in known_ua)
    if new_ua:
        reasons.append(f"新 User-Agent：{new_ua[0][:60]}")
        risk += 0.2

    hist = profile.hour_hist or {}
    total_hours = sum(_safe_int(v) for v in hist.values())
    if total_hours >= settings.profile_min_obs and obs["hours"]:
        rare = [h for h in obs["hours"] if _safe_int(hist.get(h, 0)) / total_hours < 0.01]
        if len(rare) == len(obs["hours"]):
            reasons.append(f"非常用时段：{','.join(sorted(rare))} 时")
            risk += 0.15

    if kind == SESSION and len(obs["src_ips"]) >= 2:
        reasons.append(f"会话跨 {len(obs['src_ips'])} 个源 IP（疑似会话劫持）")
        risk += 0.45

    if obs["fail"] >= 5 and obs["fail"] > obs["success"]:
        reasons.append(f"认证失败突增（{obs['fail']} 次，成功 {obs['success']} 次）")
        risk += 0.25

    return {"reasons": reasons, "risk": min(risk, 1.0), "cold_start": False}


def recall_entities(logs: list[UnifiedLog]) -> dict[str, Any]:
    """对本窗口日志做画像比对，返回 {entities: [...], anomalies: [...]}。"""
    if not settings.profile_enabled:
        return {"entities": [], "anomalies": []}
    observations = window_observations(logs)
    if not observations:
        return {"entities": [], "anomalies": []}

    profiles = load_profiles([(o["kind"], o["key"]) for o in observations.values()])
    entities: list[dict[str, Any]] = []
    for key, obs in observations.items():
        profile = profiles.get(key)
        detection = detect(obs["kind"], obs, profile)
        if not detection["reasons"]:
            continue
        entities.append(
            {
                "kind": obs["kind"],
                "key": obs["key"],
                "display": obs["display"],
                "risk": round(detection["risk"], 3),
                "reasons": detection["reasons"],
                "obs_count": _safe_int(profile.obs_count) if profile else 0,
                "src_ips": sorted(obs["src_ips"].keys())[:5],
                "count": obs["count"],
            }
        )
    entities.sort(key=lambda x: -x["risk"])
    threshold = settings.profile_risk_threshold
    return {
        "entities": entities,
        "anomalies": [e for e in entities if e["risk"] >= threshold],
    }


# ---------- 基线更新 ----------


def _merge(base: Any, add: Counter, limit: int) -> dict[str, int]:
    merged: dict[str, int] = {str(k): _safe_int(v) for k, v in dict(base or {}).items()}
    for key, value in add.items():
        merged[str(key)] = merged.get(str(key), 0) + _safe_int(value)
    return dict(sorted(merged.items(), key=lambda item: -item[1])[:limit])


def update_profiles(observations: dict[str, dict[str, Any]]) -> dict[str, int]:
    """把本窗口观测并入画像基线（增量累积）。"""
    if not observations or not settings.profile_enabled:
        return {"created": 0, "updated": 0}
    now = datetime.now(UTC)
    created = updated = 0
    try:
        with SessionLocal() as db:
            for obs in observations.values():
                row = db.scalars(
                    select(EntityProfile).where(
                        EntityProfile.kind == obs["kind"],
                        EntityProfile.entity_key == obs["key"],
                    )
                ).first()
                if row is None:
                    row = EntityProfile(
                        kind=obs["kind"],
                        entity_key=obs["key"],
                        entity_display=obs["display"],
                        first_seen=now,
                    )
                    db.add(row)
                    created += 1
                else:
                    updated += 1
                if obs["display"]:
                    row.entity_display = obs["display"]
                row.obs_count = (row.obs_count or 0) + _safe_int(obs["count"])
                row.last_seen = now
                row.src_ips = _merge(row.src_ips, obs["src_ips"], _LIMITS["src_ips"])
                row.user_agents = _merge(row.user_agents, obs["user_agents"], _LIMITS["user_agents"])
                row.paths = _merge(row.paths, obs["paths"], _LIMITS["paths"])
                row.hour_hist = _merge(row.hour_hist, obs["hours"], _LIMITS["hour_hist"])
                row.success_count = (row.success_count or 0) + _safe_int(obs["success"])
                row.fail_count = (row.fail_count or 0) + _safe_int(obs["fail"])
            db.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("更新实体画像失败: %s", exc)
    return {"created": created, "updated": updated}


def cleanup() -> dict[str, int]:
    """清理长期无观测的画像。"""
    before = datetime.now(UTC) - timedelta(days=settings.profile_retention_days)
    try:
        with SessionLocal() as db:
            result = cast(
                CursorResult[Any],
                db.execute(delete(EntityProfile).where(EntityProfile.last_seen < before)),
            )
            db.commit()
            return {"deleted": result.rowcount or 0}
    except Exception as exc:  # noqa: BLE001
        log.warning("清理实体画像失败: %s", exc)
        return {"deleted": 0}


# ---------- 列表与渲染 ----------


def list_profiles(
    *, kind: str | None = None, min_risk: float = 0.0, limit: int = 50, offset: int = 0
) -> dict[str, Any]:
    with SessionLocal() as db:
        conds = []
        if kind:
            conds.append(EntityProfile.kind == kind)
        if min_risk > 0:
            conds.append(EntityProfile.risk_score >= min_risk)

        count_q = select(func.count()).select_from(EntityProfile)
        stmt = select(EntityProfile).order_by(EntityProfile.risk_score.desc())
        for cond in conds:
            count_q = count_q.where(cond)
            stmt = stmt.where(cond)
        total = db.scalar(count_q) or 0
        rows = db.scalars(stmt.limit(limit).offset(offset)).all()
    return {"total": total, "items": [_profile_dict(r) for r in rows]}


def _profile_dict(p: EntityProfile) -> dict[str, Any]:
    return {
        "id": p.id,
        "kind": p.kind,
        "entity_key": p.entity_key,
        "entity_display": p.entity_display,
        "obs_count": p.obs_count,
        "risk_score": p.risk_score,
        "first_seen": p.first_seen.isoformat() if p.first_seen else None,
        "last_seen": p.last_seen.isoformat() if p.last_seen else None,
        "src_ips": p.src_ips or {},
        "user_agents": p.user_agents or {},
        "paths": p.paths or {},
        "hour_hist": p.hour_hist or {},
        "success_count": p.success_count,
        "fail_count": p.fail_count,
        "anomalies": p.anomalies or [],
    }


def top_anomalies(limit: int = 10) -> dict[str, Any]:
    """驾驶舱用：按风险分取 TOP。"""
    with SessionLocal() as db:
        rows = db.scalars(
            select(EntityProfile)
            .where(EntityProfile.risk_score >= settings.profile_risk_threshold)
            .order_by(EntityProfile.risk_score.desc())
            .limit(limit)
        ).all()
    return {"threshold": settings.profile_risk_threshold, "items": [_profile_dict(r) for r in rows]}


def profile_text(profile_info: dict[str, Any] | None) -> str:
    """把画像异常渲染成提示词文本块。"""
    entities = (profile_info or {}).get("entities") or []
    if not entities:
        return "（无账号/会话画像异常）"
    lines = ["账号/会话画像异常（跨窗口长期基线）："]
    for entity in entities[:6]:
        kind = "账号" if entity.get("kind") == ACCOUNT else "会话"
        lines.append(
            f"- [{kind}] {entity.get('display')} 风险 {entity.get('risk')}："
            + "；".join(entity.get("reasons") or [])
        )
    return "\n".join(lines)
