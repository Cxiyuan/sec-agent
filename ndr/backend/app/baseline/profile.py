"""账号 / 会话跨窗口长期画像（UEBA 式统计基线）。

第 8 期从智能体侧迁来（原 `agent/backend/app/agents/profile.py`）：基线是纯统计、
不需要模型，而检测器本来就逐条看到归一化事件，所以在数据产生侧算、算完随摘要打标。

- **提取**：账号（`user` 字段优先；归一化阶段已从登录路径参数兜底提取）；
  会话（从 Cookie 提取会话 id → **SHA-256 哈希**）
- **基线**：频次分布（源 IP / UA / 时段 / 路径）+ 成功失败计数，跨窗口增量累积
- **异常**：新源 IP / 新 UA / 非常用时段 / 认证失败突增 / 会话跨 IP
- **安全**：会话只存哈希；**不落库明文 cookie / 口令 / Token**
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from functools import lru_cache
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
_LIMITS: dict[str, int] = {
    "src_ips": 50,
    "dst_ips": 30,
    "user_agents": 20,
    "paths": 30,
    "hour_hist": 24,
}
# `_LIMITS` 的键是**落库列名**（`hour_hist` 列对的是观测桶里的 `hours`），
# 这里给出列名 -> 观测桶字段的映射，剪枝与落库共用同一份上限。
_BUCKET_FIELDS: dict[str, str] = {
    "src_ips": "src_ips",
    "dst_ips": "dst_ips",
    "user_agents": "user_agents",
    "paths": "paths",
    "hour_hist": "hours",
}
# 窗口内的 Counter 也设个上限：一个窗口里同一实体可能撞出成千上万个路径，
# 落库时才裁剪就晚了（内存先炸）。超出这个倍数就先裁一次，保留 top N。
_TRIM_FACTOR = 4


def _csv(value: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in (value or "").split(",") if x.strip())


def _v6_prefix(ip: str) -> str:
    """取 IPv6 的 /64 前缀。

    为什么需要：IPv6 隐私扩展地址（RFC 4941）会在同一 /64 里不断轮换新地址，
    「没见过这个地址」并不等于「换了客户端」。所以 v6 只在**前缀**也新时才算新源 IP。
    """
    try:
        return str(ipaddress.IPv6Network(f"{ip}/64", strict=False))
    except ValueError:
        return str(ip)


def _families(ips: Iterable[str]) -> tuple[set[str], set[str]]:
    """把地址按 v4 / v6 分开。

    为什么要分：同一个客户端在双栈网络（移动端尤甚）会同时用 v4 与 v6 访问，
    把「v4+v6 各一个」当成「会话跨 2 个源 IP（疑似会话劫持）」是纯误报——
    2026-10 实机 QA：被判会话劫持的 5 条**全部**是这种双栈（或 v6 换地址），
    没有一条是真的多 IPv4。所以「跨 IP」只在**同族内** ≥ 2 个时才成立。
    """
    v4: set[str] = set()
    v6: set[str] = set()
    for ip in ips:
        text = str(ip)
        (v6 if ":" in text else v4).add(text)
    return v4, v6


@lru_cache
def _path_regexes() -> tuple[re.Pattern[str] | None, re.Pattern[str] | None]:
    """（include, exclude）两个路径正则；空字符串 = 那一步不过滤。"""

    def build(pattern: str) -> re.Pattern[str] | None:
        text = (pattern or "").strip()
        if not text:
            return None
        try:
            return re.compile(text)
        except re.error:
            log.warning("路径正则写错了，已忽略：%r", text)
            return None

    return build(settings.profile_path_include_regex), build(settings.profile_path_exclude_regex)


def api_path(path: str) -> bool:
    """这条路径要不要计进画像（只留接口、排掉静态资源与页面）。

    为什么要排：前端 js/css/图片/字体访问次数天然最多，会把 30 条上限占满
    （2026-10 实机：会话画像的 paths 里全是前端 js 与字体，如 /static/app.js、
    /assets/font.woff2），有价值的接口路径反而被挤出去。两个正则都能在配置里改；
    默认**只用排除名单**（include 为空），因为实测真实接口不一定会带 `/api/`。
    """
    text = (path or "").strip()
    if not text:
        return False
    include, exclude = _path_regexes()
    if include is not None and not include.search(text):
        return False
    return not (exclude is not None and exclude.search(text))


def _old_enough(profile: EntityProfile) -> bool:
    """画像建立是否已满 `profile_hour_min_age_hours` 小时。"""
    min_hours = max(0, int(settings.profile_hour_min_age_hours))
    if min_hours <= 0:
        return True
    first = profile.first_seen
    if first is None:
        return False
    if first.tzinfo is None:
        first = first.replace(tzinfo=UTC)
    return datetime.now(UTC) - first >= timedelta(hours=min_hours)


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
    """账号：归一化阶段已做提取（`user` 字段优先，其次登录路径参数）。"""
    return (entry.account or entry.user or "").strip()[:128]


# ---------- 窗口观测聚合 ----------


def _new_bucket(kind: str, key: str, display: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "key": key,
        "display": display,
        "src_ips": Counter(),
        "dst_ips": Counter(),
        "user_agents": Counter(),
        "paths": Counter(),
        "hours": Counter(),
        "success": 0,
        "fail": 0,
        "count": 0,
    }


def _accumulate(bucket: dict[str, Any], entry: UnifiedLog) -> None:
    bucket["count"] += 1
    # 源 IP 优先用代理头解析出的真实客户端 IP（real_client_ip），没有才用 TCP 对端：
    # 经反向代理进来的流量，画像要统计真实客户端，而不是代理地址。
    client_ip = entry.real_client_ip or entry.src_ip
    if client_ip:
        bucket["src_ips"][str(client_ip)] += 1
    # 服务端 IP（被访问的监控资产）：界面要展示「账号 + 关联服务端 IP」，
    # 让运维能直接看出「哪个账号在哪台服务器上活动」。
    if entry.dst_ip:
        bucket["dst_ips"][str(entry.dst_ip)] += 1
    if entry.user_agent:
        bucket["user_agents"][entry.user_agent[:128]] += 1
    # 路径只收接口形态（静态资源会让 30 条上限满掉，见 api_path 的说明）
    if entry.uri_path and api_path(entry.uri_path):
        bucket["paths"][entry.uri_path[:128]] += 1
    bucket["hours"][str(entry.ts.hour)] += 1
    if entry.status_code:
        if entry.status_code in (401, 403):
            bucket["fail"] += 1
        elif entry.status_code < 400:
            bucket["success"] += 1


def _trim(bucket: dict[str, Any]) -> None:
    """窗口内的分布先裁一刀，别等落库（内存优先）。"""
    for column, limit in _LIMITS.items():
        field = _BUCKET_FIELDS.get(column, column)
        counter = bucket.get(field)
        if not isinstance(counter, Counter) or len(counter) <= limit * _TRIM_FACTOR:
            continue
        bucket[field] = Counter(dict(counter.most_common(limit)))


def observe_entry(buckets: dict[str, dict[str, Any]], entry: UnifiedLog) -> int:
    """把一条事件并进观测桶，返回并入的实体数（账号 / 会话各算一个）。

    引擎逐条调用它（`app/baseline/engine.py`），所以这里不做任何 I/O。
    """
    added = 0
    account = account_entity(entry)
    if account:
        bucket_key = f"{ACCOUNT}|{account}"
        bucket = buckets.get(bucket_key)
        if bucket is None:
            bucket = buckets[bucket_key] = _new_bucket(ACCOUNT, account, account)
        _accumulate(bucket, entry)
        _trim(bucket)
        added += 1

    skey, sdisplay = session_entity(entry.cookie)
    if skey:
        bucket_key = f"{SESSION}|{skey}"
        bucket = buckets.get(bucket_key)
        if bucket is None:
            bucket = buckets[bucket_key] = _new_bucket(SESSION, skey, sdisplay)
        _accumulate(bucket, entry)
        _trim(bucket)
        added += 1
    return added


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
    known_v6_prefixes = {_v6_prefix(ip) for ip in known_ips if ":" in ip}
    new_ips: list[str] = []
    for ip in obs["src_ips"]:
        ip = str(ip)
        if ip in known_ips:
            continue
        # v6 同 /64 内的新地址：同一个客户端的隐私地址轮换，不算新源 IP
        if ":" in ip and _v6_prefix(ip) in known_v6_prefixes:
            continue
        new_ips.append(ip)
    new_ips.sort()
    if new_ips:
        reasons.append(f"新源 IP：{', '.join(new_ips[:3])}")
        risk += 0.35

    known_ua = set((profile.user_agents or {}).keys())
    new_ua = sorted(ua for ua in obs["user_agents"] if ua not in known_ua)
    if new_ua:
        reasons.append(f"新 User-Agent：{new_ua[0][:60]}")
        risk += 0.2

    # 新接口路径：只算接口形态（静态资源已在采集时排掉），且要求画像已认识若干条路径，
    # 否则刚建的画像「第一条路径就是新的」等于白报。
    known_paths = set((profile.paths or {}).keys())
    new_paths = sorted(p for p in obs["paths"] if p not in known_paths)
    if new_paths and len(known_paths) >= max(0, int(settings.profile_path_min_known)):
        reasons.append(f"新接口路径：{', '.join(new_paths[:3])}")
        risk += 0.25

    # 非常用时段：三个条件都要满足才判（否则就是整点批量误报，见 config 里那两个门槛）
    hist = profile.hour_hist or {}
    total_hours = sum(_safe_int(v) for v in hist.values())
    covered = sum(1 for v in hist.values() if _safe_int(v) > 0)
    if (
        obs["hours"]
        and total_hours >= settings.profile_min_obs
        and covered >= max(1, int(settings.profile_hour_min_coverage))
        and _old_enough(profile)
    ):
        rare = [h for h in obs["hours"] if _safe_int(hist.get(h, 0)) / total_hours < 0.01]
        if len(rare) == len(obs["hours"]):
            reasons.append(f"非常用时段：{','.join(sorted(rare))} 时")
            risk += 0.15

    if kind == SESSION:
        # 只在**同族内** ≥ 2 个才算会话跨 IP：v4+v6 是同一客户端的双栈，不是劫持
        v4, v6 = _families(obs["src_ips"])
        if len(v4) >= 2 or len(v6) >= 2:
            reasons.append(f"会话跨 {len(v4) + len(v6)} 个同族源 IP（疑似会话劫持）")
            risk += 0.45

    if obs["fail"] >= 5 and obs["fail"] > obs["success"]:
        reasons.append(f"认证失败突增（{obs['fail']} 次，成功 {obs['success']} 次）")
        risk += 0.25

    return {"reasons": reasons, "risk": min(risk, 1.0), "cold_start": False}


def recall_from_observations(observations: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """对一批窗口观测做画像比对，返回 {entities: [...], anomalies: [...]}。

    `entities` 是「有异常理由」的全部实体（按风险降序），`anomalies` 是其中过阈值的
    （`profile_risk_threshold`）—— 后者才会被写进摘要标签。
    """
    if not settings.profile_enabled or not observations:
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
                "dst_ips": sorted(obs["dst_ips"].keys())[:5],
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


def _kept_paths(paths: Any) -> dict[str, int]:
    """把库里已有的路径按当前口径再过一遗（自愈）。

    为什么要过：口径是后加上的，老库里已经存了一堆静态资源路径（实测某环境有 5237 条
    不含 `/api/` 的旧值：.css/.png/页面）。合并前先剔掉，否则 30 条上限永远被它们占着，
    新口径等于没生效。（不需要额外的数据迁移：每个画像被再次观测时就自愈一次。）
    """
    return {k: _safe_int(v) for k, v in dict(paths or {}).items() if api_path(k)}


def update_profiles(
    observations: dict[str, dict[str, Any]],
    risks: dict[str, dict[str, Any]] | None = None,
) -> dict[str, int]:
    """把本窗口观测并入画像基线（增量累积），并回写本轮异常风险分。

    risks：key = f"{kind}|{key}"，值含 {risk, reasons}（来自 `recall_from_observations`）；
    回写后按风险排序的列表与 TOP 才生效。
    """
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
                row.dst_ips = _merge(row.dst_ips, obs["dst_ips"], _LIMITS["dst_ips"])
                row.user_agents = _merge(
                    row.user_agents, obs["user_agents"], _LIMITS["user_agents"]
                )
                row.paths = _merge(_kept_paths(row.paths), obs["paths"], _LIMITS["paths"])
                row.hour_hist = _merge(row.hour_hist, obs["hours"], _LIMITS["hour_hist"])
                row.success_count = (row.success_count or 0) + _safe_int(obs["success"])
                row.fail_count = (row.fail_count or 0) + _safe_int(obs["fail"])

                # 回写本轮异常风险（供列表排序与 TOP）：**本轮没理由就归零**。
                # 不归零的后果（2026-10 实机 QA）：实体一旦被报过就永久挂在「画像风险 TOP」，
                # 实测 4 条 risk≥0.6 的画像已 2~4 小时没再出现，界面仍当当前风险看。
                risk = (risks or {}).get(f"{obs['kind']}|{obs['key']}") or {}
                if risk:
                    row.risk_score = float(risk.get("risk") or 0.0)
                    row.anomalies = list(risk.get("reasons") or [])[:20]
                    row.risk_at = now
                else:
                    row.risk_score = 0.0
                    row.anomalies = []
                    # 风险时间跟着归零：只保留「当前风险」的判定时间，避免陈旧时间被当新时间
                    row.risk_at = None
            db.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("更新实体画像失败: %s", exc)
    return {"created": created, "updated": updated}


def cleanup() -> dict[str, int]:
    """清理长期无观测的画像，并顺手把不合口径的旧路径剔掉。

    为什么在这里做路径自愈：路径口径是后加上的，老库里已经存了一堆静态资源/页面路径
    （实测某环境 3934 条），它们会把 30 条上限占着。只靠「该画像又被观测到」自愈的话，
    不再活跃的画像永远不会清；放到小时级清理里，一小时内全库都会对齐，
    而且口径仍然只来自配置（不在 SQL 里重写一份正则，避免两处漂移）。
    """
    before = datetime.now(UTC) - timedelta(days=settings.profile_retention_days)
    deleted = pruned = 0
    try:
        with SessionLocal() as db:
            result = cast(
                CursorResult[Any],
                db.execute(delete(EntityProfile).where(EntityProfile.last_seen < before)),
            )
            deleted = result.rowcount or 0
            for row in db.scalars(select(EntityProfile)).all():
                current = row.paths or {}
                kept = _kept_paths(current)
                if len(kept) != len(current):
                    pruned += len(current) - len(kept)
                    row.paths = kept
            db.commit()
            return {"deleted": deleted, "pruned": pruned}
    except Exception as exc:  # noqa: BLE001
        log.warning("清理实体画像失败: %s", exc)
        return {"deleted": 0, "pruned": 0}


# ---------- 列表 ----------


def _profile_dict(p: EntityProfile) -> dict[str, Any]:
    return {
        "id": p.id,
        "kind": p.kind,
        "entity_key": p.entity_key,
        "entity_display": p.entity_display,
        "obs_count": p.obs_count,
        "risk_score": p.risk_score,
        # 风险分的判定时间：没有它，界面无法区分「现在异常」与「几小时前的陈旧结果」
        # （`updated_at` 每轮观测都刷新，不能当风险时间用）。
        "risk_at": p.risk_at.isoformat() if p.risk_at else None,
        "first_seen": p.first_seen.isoformat() if p.first_seen else None,
        "last_seen": p.last_seen.isoformat() if p.last_seen else None,
        "src_ips": p.src_ips or {},
        # 服务端 IP（被访问的监控资产）：界面展示「账号 + 关联服务端 IP」靠它
        "dst_ips": p.dst_ips or {},
        "user_agents": p.user_agents or {},
        "paths": p.paths or {},
        "hour_hist": p.hour_hist or {},
        "success_count": p.success_count,
        "fail_count": p.fail_count,
        "anomalies": p.anomalies or [],
    }


def list_profiles(
    *,
    kind: str | None = None,
    keys: list[str] | None = None,
    min_risk: float = 0.0,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    try:
        with SessionLocal() as db:
            conds = []
            if kind:
                conds.append(EntityProfile.kind == kind)
            if keys:
                # 指名道姓查几个实体（智能体问「这组 IP 关联的账号/会话画像」走这里）
                conds.append(EntityProfile.entity_key.in_(list(keys)[:500]))
            if min_risk > 0:
                conds.append(EntityProfile.risk_score >= min_risk)

            count_q = select(func.count()).select_from(EntityProfile)
            stmt = select(EntityProfile).order_by(EntityProfile.risk_score.desc())
            for cond in conds:
                count_q = count_q.where(cond)
                stmt = stmt.where(cond)
            total = db.scalar(count_q) or 0
            rows = db.scalars(stmt.limit(limit).offset(offset)).all()
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读实体画像失败：{exc}", "total": 0, "items": []}
    return {"total": total, "items": [_profile_dict(r) for r in rows]}


def top_anomalies(limit: int = 10, *, kind: str | None = None) -> dict[str, Any]:
    """按风险分取 TOP（运行状态页用）。

    只取``risk_at`` 在有效期（`profile_risk_ttl_minutes`）内的：本函数是「**当前**风险」，
    不是历史榜单 —— 实测旧实现会把 2~4 小时前判过、之后再没出现过的实体一直列出来。

    `kind`：界面只传 `"account"`（会话的展示名是 cookie 哈希前 8 位，运维看不懂；
    会话画像本身仍在算，摘要标签与 MCP 调查还看得到）。
    """
    ttl = max(0, int(settings.profile_risk_ttl_minutes))
    stmt = select(EntityProfile).where(EntityProfile.risk_score >= settings.profile_risk_threshold)
    if kind:
        stmt = stmt.where(EntityProfile.kind == kind)
    if ttl > 0:
        cutoff = datetime.now(UTC) - timedelta(minutes=ttl)
        stmt = stmt.where(EntityProfile.risk_at.is_not(None), EntityProfile.risk_at >= cutoff)
    try:
        with SessionLocal() as db:
            rows = db.scalars(
                stmt.order_by(EntityProfile.risk_score.desc()).limit(
                    max(1, min(int(limit or 10), 100))
                )
            ).all()
    except Exception as exc:  # noqa: BLE001
        return {
            "threshold": settings.profile_risk_threshold,
            "ttl_minutes": ttl,
            "items": [],
            "error": str(exc),
        }
    return {
        "threshold": settings.profile_risk_threshold,
        "ttl_minutes": ttl,
        "items": [_profile_dict(r) for r in rows],
    }
