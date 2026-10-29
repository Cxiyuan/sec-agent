"""服务器主动外连的**目的地身份**基线。

为什么不是"连接数/端口数"基线：一台服务器每天连多少条连接，取决于业务量与用户分布，
天然没有稳定值；但"这台机器以前有没有连过这个 IP / 域名 / 端口"是稳定的、可解释的。
异常程序（木马、挖矿、被利用的 WebShell）最典型的痕迹就是**第一次**连上一个新目的地。

口径（2026-10 用户定）：

- 监控网段内**全部 IP** 都建基线（不筛服务器角色）；
- 只统计**主动外连**（源在内网、目的在公网）；入口流量不参与；
- 维度：目的 IP / 域名（SNI、Host）/ 目的端口；
- 只产出事实（`observations`），不带严重度、不下结论 —— 判断权在智能体；
- 白名单：自学习（稳定出现 N 天/次自动入表）+ 手工新增/编辑/删除；
  **删除留墓碑**，否则下一窗口又学回来，删除等于没删。
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import Text, cast, func, select

from app.baseline import observations, params
from app.db.base import SessionLocal
from app.db.models import EgressAllow, EgressBaseline
from app.iputil import is_internal_ip, is_public_ip
from app.workers.log import get_logger

UTC = timezone.utc
log = get_logger(__name__)

KIND_DST = "dst_ip"
KIND_DOMAIN = "domain"
KIND_PORT = "port"

#: 单窗口最多处理多少条"新目的地"（防扫描器/代理把内存与写库打爆）
MAX_PER_WINDOW = 400

_allow_lock = threading.Lock()
_allow_cache: dict[str, Any] = {"at": 0.0, "entries": []}
_ALLOW_TTL_SECONDS = 60


# `_nets()` 已删（E 整改 2026-10-29）：源口径统一走 `iputil.is_internal_ip()`、
# 目的口径走 `is_public_ip()`（见 `observe_window`）；孤儿函数留着只会掩盖口径问题。


def _normalize(kind: str, value: str) -> str:
    text = str(value or "").strip()
    if kind == KIND_DOMAIN:
        text = text.lower().rstrip(".")
        if ":" in text:  # Zeek 偶尔把 `IP:端口` 写进 host 字段，那不是域名
            return ""
        return text[:255]
    if kind == KIND_PORT:
        try:
            return str(int(text))
        except (TypeError, ValueError):
            return ""
    return text[:64]


def _allowed_entries() -> list[EgressAllow]:
    now = time.monotonic()
    with _allow_lock:
        if now - float(_allow_cache["at"]) < _ALLOW_TTL_SECONDS:
            return list(_allow_cache["entries"])
    try:
        with SessionLocal() as db:
            rows = list(
                db.scalars(
                    select(EgressAllow).where(
                        EgressAllow.enabled.is_(True), EgressAllow.tombstone.is_(False)
                    )
                ).all()
            )
    except Exception as exc:  # noqa: BLE001 — 白名单读失败按"空表"处理（宁可多报，不漏）
        log.warning("读外连白名单失败：%s", exc)
        rows = []
    with _allow_lock:
        _allow_cache["at"] = now
        _allow_cache["entries"] = rows
    return rows


def invalidate_allow_cache() -> None:
    with _allow_lock:
        _allow_cache["at"] = 0.0
        _allow_cache["entries"] = []


def _is_allowed(entries: list[EgressAllow], src: str, kind: str, value: str) -> bool:
    for entry in entries:
        if entry.kind != kind or entry.value != value:
            continue
        if entry.scope == "global" or entry.asset == src:
            entry.hit_count = int(entry.hit_count or 0) + 1
            return True
    return False


def _tombstoned(kind: str, value: str) -> bool:
    try:
        with SessionLocal() as db:
            return db.execute(
                select(EgressAllow.id).where(
                    EgressAllow.kind == kind,
                    EgressAllow.value == value,
                    EgressAllow.tombstone.is_(True),
                ).limit(1)
            ).first() is not None
    except Exception:  # noqa: BLE001
        return False


def _fleet_counts(db: Any, pairs: list[tuple[str, str]]) -> dict[tuple[str, str], int]:
    """全舰队稀有度（D5）：每个 (kind, value) 被多少台资产连过。

    为什么需要：同一个"新目标"，一台机器连是可疑，几百台客户端都连的常见网站
    是噪声。之前 egress_new 强度固定 0.6，常见站点和孤僻目标同权。
    """
    if not pairs:
        return {}
    kinds = sorted({k for k, _ in pairs})
    values = sorted({v for _, v in pairs})
    out: dict[tuple[str, str], int] = {}
    rows = db.execute(
        select(EgressBaseline.kind, EgressBaseline.value, func.count(func.distinct(EgressBaseline.src_ip)))
        .where(EgressBaseline.kind.in_(kinds), EgressBaseline.value.in_(values))
        .group_by(EgressBaseline.kind, EgressBaseline.value)
    ).all()
    for kind, value, count in rows:
        out[(str(kind), str(value))] = int(count or 0)
    return out


def _learning_blocked(kind: str, value: str, now: datetime) -> bool:
    """自动白名单护栏（D5-4）：目标有真阳性/可疑结论，或正被待办任务跟踪 → 不学习。"""
    from app.db.models import AnalysisResult, AnalysisTask

    needle = f"%{value}%"
    try:
        with SessionLocal() as db:
            pending = db.scalar(
                select(AnalysisTask.id)
                .where(
                    AnalysisTask.state.in_(("pending", "claimed", "deferred")),
                    cast(AnalysisTask.hint, Text).like(needle),
                )
                .limit(1)
            )
            if pending is not None:
                return True
            bad = db.scalar(
                select(AnalysisResult.id)
                .where(
                    AnalysisResult.verdict.in_(("true_positive", "suspicious")),
                    AnalysisResult.created_at >= now - timedelta(days=30),
                    cast(AnalysisResult.findings, Text).like(needle),
                )
                .limit(1)
            )
            return bad is not None
    except Exception:  # noqa: BLE001 — 护栏查不到时宁可不学习（安全侧）
        return True


def observe_window(
    samples: list[dict[str, Any]], *, now: datetime | None = None
) -> dict[str, int]:
    """一个采样窗口的外连事实：判"首次/罕见"、持续跟踪、必要时自动入白名单。

    一个窗口只打几次库，不在事件热路径上。

    D5（2026-10-29）整改：
    - `egress_new` 强度按**全舰队稀有度**调整（只有 1–2 台资产连的目标更强；
      被大量资产访问的常见站点降成低价值事实）；
    - 未判定的目标按 `egress.sustained_minutes` 持续产出 `egress_sustained`（强度≥0.45），
      不再"首次没派到就永远静默"；
    - 自动白名单默认关闭（`egress.auto_allow`），开启也有护栏；
    - `MAX_PER_WINDOW` 截断时先按稀有度排序，并如实计数（`egress_capped`）。
    """
    if not params.egress_enabled():
        return {"new": 0, "rare": 0, "learned": 0, "sustained": 0, "capped": 0}
    moment = now or datetime.now(UTC)
    # 只处理"监控网段内源 → 公网目的地"的外连（口径 C1 2026-10-29）：
    # 源用 is_internal_ip() —— 未监控内网段连公网不是"我们的外连"，学进去会把
    # 别的网段的访问当我们的基线；目的保持 is_public_ip()。
    candidates: list[tuple[str, str, str]] = []
    for sample in samples:
        src = str(sample.get("src_ip") or "")
        if src == "" or not is_internal_ip(src):
            continue
        for dst in sample.get("egress_dsts") or ():
            if is_public_ip(dst):
                candidates.append((src, KIND_DST, str(dst)))
        for domain in sample.get("egress_domains") or ():
            value = _normalize(KIND_DOMAIN, domain)
            if value:
                candidates.append((src, KIND_DOMAIN, value))
        for port in sample.get("egress_ports") or ():
            value = _normalize(KIND_PORT, port)
            if value:
                candidates.append((src, KIND_PORT, value))
    if not candidates:
        return {"new": 0, "rare": 0, "learned": 0, "sustained": 0, "capped": 0}
    # 同一窗口内同一 (src, kind, value) 只算一次，避免自造计数
    candidates = list(dict.fromkeys(candidates))

    allow = _allowed_entries()
    srcs = sorted({src for src, _, _ in candidates})
    counts = {"new": 0, "rare": 0, "learned": 0, "sustained": 0, "capped": 0}
    try:
        with SessionLocal() as db:
            # 全舰队稀有度要在截断**之前**算：先按稀有条数排序，再截断（D5-5）
            fleet = _fleet_counts(db, [(kind, value) for _, kind, value in candidates])
            candidates.sort(key=lambda c: fleet.get((c[1], c[2]), 99))
            if len(candidates) > MAX_PER_WINDOW:
                counts["capped"] = len(candidates) - MAX_PER_WINDOW
                log.warning(
                    "外连窗口候选 %d 条，超过单窗口上限 %d，按全舰队稀有度保留前 %d 条",
                    len(candidates),
                    MAX_PER_WINDOW,
                    MAX_PER_WINDOW,
                )
                candidates = candidates[:MAX_PER_WINDOW]
            rows = list(
                db.scalars(select(EgressBaseline).where(EgressBaseline.src_ip.in_(srcs))).all()
            )
            known = {(row.src_ip, row.kind, row.value): row for row in rows}
            rare_min = int(params.egress_rare_min())
            learn_days = int(params.egress_learn_days())
            learn_occurrences = int(params.egress_learn_occurrences())
            auto_allow = params.egress_auto_allow()
            sustained_minutes = max(15, int(params.egress_sustained_minutes()))
            dims = {KIND_DST: "目的 IP", KIND_DOMAIN: "域名", KIND_PORT: "目的端口"}
            for src, kind, value in candidates:
                if _is_allowed(allow, src, kind, value):
                    continue
                fleet_n = fleet.get((kind, value), 1)
                # 稀有度系数：只有 1–2 台资产连过 = 更值得看；很多资产都连 = 常见站点
                if fleet_n <= 2:
                    new_strength = 0.7
                    rare_strength = 0.5
                elif fleet_n >= 10:
                    new_strength = 0.35
                    rare_strength = 0.3
                else:
                    new_strength = 0.6
                    rare_strength = 0.45
                row = known.get((src, kind, value))
                if row is None:
                    if _tombstoned(kind, value):
                        continue
                    db.add(
                        EgressBaseline(
                            src_ip=src, kind=kind, value=value, count=1,
                            first_seen=moment, last_seen=moment,
                        )
                    )
                    known[(src, kind, value)] = EgressBaseline(
                        src_ip=src, kind=kind, value=value, count=1,
                        first_seen=moment, last_seen=moment,
                    )
                    observations.emit(
                        "egress_new",
                        "asset",
                        src,
                        {
                            "维度": dims[kind],
                            "目标": value,
                            "全舰队访问资产数": fleet_n,
                            "说明": "该资产以前没有连过这个目标（主动外连）",
                            "首次观测": moment.isoformat(),
                        },
                        key=f"{kind}:{value}",
                        strength=new_strength,
                        now=moment,
                    )
                    counts["new"] += 1
                    continue
                row.count = int(row.count or 0) + 1
                row.last_seen = moment
                if row.count < rare_min:
                    observations.emit(
                        "egress_rare",
                        "asset",
                        src,
                        {
                            "维度": dims[kind],
                            "目标": value,
                            "累计窗口次数": row.count,
                            "判定门槛": rare_min,
                            "全舰队访问资产数": fleet_n,
                            "说明": "该资产连这个目标的次数仍然很少（可能是临时/异常外连）",
                        },
                        key=f"{kind}:{value}",
                        strength=rare_strength,
                        now=moment,
                    )
                    counts["rare"] += 1
                else:
                    # D5-2 持续跟踪：目标还没被 agent 判定前，按较低频率继续产出事实
                    observations.emit(
                        "egress_sustained",
                        "asset",
                        src,
                        {
                            "维度": dims[kind],
                            "目标": value,
                            "累计窗口次数": row.count,
                            "全舰队访问资产数": fleet_n,
                            "说明": "该资产在持续连这个目标；尚未有分析结论前保持可见",
                        },
                        key=f"{kind}:{value}",
                        strength=max(0.45, rare_strength),
                        cooldown_minutes=sustained_minutes,
                        now=moment,
                    )
                    counts["sustained"] += 1
                # 自学习（默认关闭）：稳定出现足够久 + 足够多次，且有护栏
                first = row.first_seen
                if first is not None and first.tzinfo is None:
                    first = first.replace(tzinfo=UTC)
                age_days = (moment - first).days if first is not None else 0
                if (
                    auto_allow
                    and row.count >= learn_occurrences
                    and age_days >= learn_days
                    and not _learning_blocked(kind, value, moment)
                ):
                    existing = db.execute(
                        select(EgressAllow.id).where(
                            EgressAllow.kind == kind,
                            EgressAllow.value == value,
                            EgressAllow.scope == "global",
                        ).limit(1)
                    ).first()
                    if existing is None:
                        db.add(
                            EgressAllow(
                                kind=kind, value=value, scope="global", asset="",
                                source="learned", enabled=True, tombstone=False,
                                note=f"自学习：{src} 连续 {age_days} 天出现 {row.count} 次",
                            )
                        )
                        counts["learned"] += 1
                        invalidate_allow_cache()
            db.commit()
            return counts
    except Exception as exc:  # noqa: BLE001 — 外连基线失败不能影响检测
        log.warning("外连目的地基线失败：%s", exc)
        return {"new": 0, "rare": 0, "learned": 0, "sustained": 0, "capped": 0}


# ------------------------------------------------------------------ 白名单管理


def list_allow(
    *, kind: str = "", scope: str = "", include_tombstone: bool = False, limit: int = 200
) -> list[dict[str, Any]]:
    with SessionLocal() as db:
        conds: list[Any] = []
        if kind:
            conds.append(EgressAllow.kind == kind)
        if scope:
            conds.append(EgressAllow.scope == scope)
        if not include_tombstone:
            conds.append(EgressAllow.tombstone.is_(False))
        rows = list(
            db.scalars(
                select(EgressAllow).where(*conds).order_by(EgressAllow.updated_at.desc()).limit(max(1, min(limit, 500)))
            ).all()
        )
    return [_allow_dict(row) for row in rows]


def save_allow(body: dict[str, Any]) -> dict[str, Any]:
    """新增/编辑一条白名单（手工来源）。"""
    kind = str(body.get("kind") or "").strip()
    value = _normalize(kind, str(body.get("value") or ""))
    if kind not in (KIND_DST, KIND_DOMAIN, KIND_PORT):
        return {"ok": False, "error": "kind 必须是 dst_ip / domain / port"}
    if value == "":
        return {"ok": False, "error": "value 必填（且格式要对）"}
    scope = "asset" if str(body.get("scope") or "") == "asset" else "global"
    asset = str(body.get("asset") or "").strip()[:64]
    if scope == "asset" and asset == "":
        return {"ok": False, "error": "scope=asset 时必须给 asset（资产 IP）"}
    try:
        with SessionLocal() as db:
            row = db.execute(
                select(EgressAllow).where(
                    EgressAllow.kind == kind,
                    EgressAllow.value == value,
                    EgressAllow.scope == scope,
                    EgressAllow.asset == asset,
                )
            ).scalar_one_or_none()
            if row is None:
                row = EgressAllow(
                    kind=kind, value=value, scope=scope, asset=asset, source="manual"
                )
                db.add(row)
            row.source = "manual"
            row.enabled = bool(body.get("enabled", True))
            row.tombstone = False
            row.note = str(body.get("note") or "")[:200]
            db.commit()
            db.refresh(row)
            out = _allow_dict(row)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"保存失败：{exc}"[:200]}
    invalidate_allow_cache()
    return {"ok": True, "entry": out}


def remove_allow(entry_id: str, *, tombstone: bool = True) -> bool:
    """删除白名单条目。默认**留墓碑**：以后不再自动学回来。"""
    try:
        with SessionLocal() as db:
            row = db.get(EgressAllow, str(entry_id or "").strip())
            if row is None:
                return False
            if tombstone:
                row.tombstone = True
                row.enabled = False
                row.source = "manual"
                row.note = (row.note or "")[:160] + "；已人工删除，不再自动学习"
            else:
                db.delete(row)
            db.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("删除外连白名单失败：%s", exc)
        return False
    invalidate_allow_cache()
    return True


def remove_tombstone(entry_id: str) -> bool:
    """撤销墓碑（允许重新学习）。"""
    try:
        with SessionLocal() as db:
            row = db.get(EgressAllow, str(entry_id or "").strip())
            if row is None:
                return False
            row.tombstone = False
            row.enabled = True
            db.commit()
    except Exception:  # noqa: BLE001
        return False
    invalidate_allow_cache()
    return True



def check_allow(src_ip: str, kind: str, value: str) -> dict[str, Any]:
    """某个目标对某台资产是否已放行（只读；给 MCP 工具判断用）。"""
    entries = _allowed_entries()
    for entry in entries:
        if entry.kind == kind and entry.value == value and (entry.scope == "global" or entry.asset == src_ip):
            return {"allowed": True, "scope": entry.scope, "source": entry.source, "note": entry.note}
    return {"allowed": False, "scope": "", "source": "", "note": ""}

def list_baseline(src_ip: str = "", *, kind: str = "", limit: int = 100) -> list[dict[str, Any]]:
    """某台资产（或全部）已学到的外连目的地。"""
    with SessionLocal() as db:
        conds: list[Any] = []
        if src_ip:
            conds.append(EgressBaseline.src_ip == src_ip)
        if kind:
            conds.append(EgressBaseline.kind == kind)
        rows = list(
            db.scalars(
                select(EgressBaseline)
                .where(*conds)
                .order_by(EgressBaseline.last_seen.desc())
                .limit(max(1, min(limit, 500)))
            ).all()
        )
    return [
        {
            "src_ip": row.src_ip,
            "kind": row.kind,
            "value": row.value,
            "count": int(row.count or 0),
            "first_seen": row.first_seen.isoformat() if row.first_seen else "",
            "last_seen": row.last_seen.isoformat() if row.last_seen else "",
        }
        for row in rows
    ]


def cleanup(retention_days: int = 90) -> int:
    """清理长期没再出现的目的地（默认 90 天）。"""
    cutoff = datetime.now(UTC) - timedelta(days=max(1, int(retention_days)))
    try:
        with SessionLocal() as db:
            rows = db.query(EgressBaseline).filter(EgressBaseline.last_seen < cutoff).delete()
            db.commit()
            return int(rows or 0)
    except Exception:  # noqa: BLE001
        return 0


def _allow_dict(row: EgressAllow) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "kind": row.kind,
        "value": row.value,
        "scope": row.scope,
        "asset": row.asset,
        "source": row.source,
        "enabled": bool(row.enabled),
        "tombstone": bool(row.tombstone),
        "hit_count": int(row.hit_count or 0),
        "note": row.note,
        "updated_at": row.updated_at.isoformat() if row.updated_at else "",
    }
