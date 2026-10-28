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

import ipaddress
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select

from app.baseline import observations, params
from app.db.base import SessionLocal
from app.db.models import EgressAllow, EgressBaseline
from app.iputil import is_public_ip
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


def _nets() -> list[ipaddress._BaseNetwork]:
    from app.ingestion import scope as scope_mod

    out: list[ipaddress._BaseNetwork] = []
    for text in scope_mod.monitored_nets():
        try:
            out.append(ipaddress.ip_network(str(text), strict=False))
        except ValueError:
            continue
    return out


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


def observe_window(
    samples: list[dict[str, Any]], *, now: datetime | None = None
) -> dict[str, int]:
    """一个采样窗口的外连事实：判"首次/罕见"、累加计数、必要时自动入白名单。

    一个窗口只打两次库（一次读基线、一次写回），不在事件热路径上。
    """
    if not params.egress_enabled():
        return {"new": 0, "rare": 0, "learned": 0}
    moment = now or datetime.now(UTC)
    # 只处理有公网目的地的样本
    candidates: list[tuple[str, str, str]] = []
    for sample in samples:
        src = str(sample.get("src_ip") or "")
        if src == "":
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
        return {"new": 0, "rare": 0, "learned": 0}
    candidates = candidates[:MAX_PER_WINDOW]

    allow = _allowed_entries()
    srcs = sorted({src for src, _, _ in candidates})
    try:
        with SessionLocal() as db:
            rows = list(
                db.scalars(select(EgressBaseline).where(EgressBaseline.src_ip.in_(srcs))).all()
            )
            known = {(row.src_ip, row.kind, row.value): row for row in rows}
            counts = {"new": 0, "rare": 0, "learned": 0}
            rare_min = int(params.egress_rare_min())
            learn_days = int(params.egress_learn_days())
            learn_occurrences = int(params.egress_learn_occurrences())
            for src, kind, value in candidates:
                if _is_allowed(allow, src, kind, value):
                    continue
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
                            "维度": {KIND_DST: "目的 IP", KIND_DOMAIN: "域名", KIND_PORT: "目的端口"}[kind],
                            "目标": value,
                            "说明": "该资产以前没有连过这个目标（主动外连）",
                            "首次观测": moment.isoformat(),
                        },
                        key=f"{kind}:{value}",
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
                            "维度": {KIND_DST: "目的 IP", KIND_DOMAIN: "域名", KIND_PORT: "目的端口"}[kind],
                            "目标": value,
                            "累计窗口次数": row.count,
                            "判定门槛": rare_min,
                            "说明": "该资产连这个目标的次数仍然很少（可能是临时/异常外连）",
                        },
                        key=f"{kind}:{value}",
                        now=moment,
                    )
                    counts["rare"] += 1
                # 自学习：稳定出现足够久 + 足够多次 → 入白名单（墓碑不学）
                first = row.first_seen
                if first is not None and first.tzinfo is None:
                    first = first.replace(tzinfo=UTC)
                age_days = (moment - first).days if first is not None else 0
                if row.count >= learn_occurrences and age_days >= learn_days:
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
        return {"new": 0, "rare": 0, "learned": 0}


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
