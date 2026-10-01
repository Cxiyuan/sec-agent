"""存量全量重建：按新的键/归并规则重新生成攻击者案件（可 dry-run、可回滚）。

为什么需要：旧归并规则允许「任一单键交集即合并」，加上域名键被 MIME 污染，
线上出现 149 组的巨案与 `domain:vnd.ms` 这类假攻击者。规则修好后历史数据仍是脏的，
必须一次性重算（口径：全量重建）。

安全设计：
- ``plan()`` 是纯函数（只算不写），dry-run 直接把计划与计数返回给接口核对；
- ``apply()`` 只动「案件与组上的指针列」，不改事件、不改图；
- 每批落 ``rebuild_runs``（计数 + 旧→新映射），支持 ``rollback``。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.config import settings
from app.db.base import SessionLocal
from app.db.models import AttackerCase, Event, EventGroup, RebuildRun
from app.investigation import cases as case_service, keys as key_utils
from app.workers.log import get_logger

log = get_logger(__name__)

# 重建涉及的“活跃”案件状态（终态不再参与，避免重复处理）
_ACTIVE_STATUS = ("open", "shelved", "investigating", "investigated", "failed")
_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class CasePlan:
    """一个待落库的案件计划。"""

    attacker_key: str
    keys: dict[str, list[str]] = field(default_factory=dict)
    fingerprints: list[str] = field(default_factory=list)
    severity: str = "info"
    merge_basis: list[str] = field(default_factory=list)
    split_reason: str = ""
    src_ips: list[str] = field(default_factory=list)
    dst_ips: list[str] = field(default_factory=list)
    event_types: list[str] = field(default_factory=list)
    event_count: int = 0
    first_seen: Any = None
    last_seen: Any = None

    def brief(self) -> dict[str, Any]:
        return {
            "attacker_key": self.attacker_key,
            "groups": len(self.fingerprints),
            "severity": self.severity,
            "merge_basis": self.merge_basis[:6],
            "split_reason": self.split_reason,
        }


def _safe_int(value: Any, default: int = 0) -> int:
    """安全转 int（值可能来自配置、事件原文或接口，可能是字符串/脏值）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(str(value)))
        except (TypeError, ValueError):
            return default


def _rank(sev: Any) -> int:
    return _RANK.get(str(sev or "info").lower(), 0)


def _build_plan(refs: list[dict[str, Any]], idxs: list[int], *, split_reason: str = "") -> CasePlan:
    merged: dict[str, list[str]] = {}
    severity = "info"
    src: set[str] = set()
    dst: set[str] = set()
    types: set[str] = set()
    events = 0
    first: Any = None
    last: Any = None
    for idx in idxs:
        ref = refs[idx]
        merged = key_utils.merge_keys(merged, ref.get("keys") or {})
        if _rank(ref.get("severity")) > _rank(severity):
            severity = str(ref.get("severity") or "info")
        src.update(str(x) for x in (ref.get("src_ips") or []))
        dst.update(str(x) for x in (ref.get("dst_ips") or []))
        types.update(str(x) for x in (ref.get("event_types") or []))
        events += _safe_int(ref.get("event_count"), 0)
        f, l = ref.get("first_seen"), ref.get("last_seen")
        if f:
            first = f if first is None else min(first, f)
        if l:
            last = l if last is None else max(last, l)
    basis = sorted(
        k for k in key_utils.key_set(merged) if k.split(":", 1)[0] in key_utils.STRONG_KEYS
    )
    return CasePlan(
        attacker_key=key_utils.primary_key(merged),
        keys=key_utils.compact(merged),
        fingerprints=[str(refs[i].get("fingerprint") or "") for i in idxs],
        severity=severity,
        merge_basis=basis[:20],
        split_reason=split_reason,
        src_ips=sorted(src)[:200],
        dst_ips=sorted(dst)[:200],
        event_types=sorted(types)[:50],
        event_count=events,
        first_seen=first,
        last_seen=last,
    )


def _bucket(refs: list[dict[str, Any]], members: list[int], field: str) -> dict[str, list[int]]:
    """按某个键字段分桶（取首个值；缺值归 unknown）。"""
    out: dict[str, list[int]] = {}
    for idx in members:
        keys = refs[idx].get("keys") or {}
        values = [str(v) for v in (keys.get(field) or [])]
        out.setdefault(values[0] if values else "unknown", []).append(idx)
    return out


def _split_bucket(
    refs: list[dict[str, Any]], members: list[int], cap: int
) -> list[tuple[list[int], str]]:
    """把一个超大分量拆到 ≤cap：先按攻击源 ip，再按源主机 host，最后按指纹顺序切块。

    为什么要三级：同一公网 IP 下面可能挂着一批内网主机（一个攻击者控的一大片），
    只按 ip 拆仍然超限；再按 host 拆能把“一个源一台案”落下来；最后一级切块是保险丝，
    保证任何输入都不会造出超过上限的案件（且每块都写明拆分原因）。
    """
    result: list[tuple[list[int], str]] = []
    for actor, ip_idxs in sorted(_bucket(refs, members, "ip").items()):
        for host, sub in sorted(_bucket(refs, ip_idxs, "host").items()):
            label = f"按攻击源 {actor} / 源主机 {host} 自动拆分"
            if len(sub) <= cap:
                result.append((sub, label))
                continue
            ordered = sorted(sub, key=lambda i: str(refs[i].get("fingerprint") or ""))
            for start in range(0, len(ordered), cap):
                piece = ordered[start : start + cap]
                result.append((piece, f"{label}（第 {start // cap + 1} 块）"))
    return result


def _similar_refs(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """弱键归并的**附加条件**（与 cases._similar 同判据）：目标重叠 + 手法相同 + 时间接近。

    为什么需要它：内网源只有 host 弱键，光靠弱键不能归并；但“同一台内网主机、
    打同一批目标、同样手法、时间连着”就是同一次活动 —— 不加这条会把案件层拆成
    一组一案（实测 1362 组→ 1345 案，案件层就废物了）。
    """
    window = max(1, int(settings.investigation_link_window_hours)) * 3600

    def _ts(value: Any) -> float | None:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.timestamp()

    a_first, a_last = _ts(a.get("first_seen")), _ts(a.get("last_seen"))
    b_first, b_last = _ts(b.get("first_seen")), _ts(b.get("last_seen"))
    if a_first is not None and a_last is not None and b_first is not None and b_last is not None:
        gap = min(abs(a_first - b_last), abs(b_first - a_last))
        if gap > window:
            return False
    if not (
        {str(x) for x in (a.get("dst_ips") or [])} & {str(x) for x in (b.get("dst_ips") or [])}
    ):
        return False
    return bool(
        {str(x) for x in (a.get("event_types") or [])}
        & {str(x) for x in (b.get("event_types") or [])}
    )


def partition_groups(
    refs: list[dict[str, Any]], *, max_groups: int | None = None
) -> list[CasePlan]:
    """按**强键连通分量**分区；分量超过上限时按攻击源二次拆分（纯函数，幂等）。

    为什么只用强键做连接边：实测一个脏域名键（vnd.ms）或一个内网主机键就能把几十个
    无关事件组粘成巨案。弱键（host/domain）只用于案件内 IOC 丰富，不参与连接。
    """
    cap = max(1, _safe_int(max_groups or settings.case_max_groups, 40))
    parent: dict[int, int] = {i: i for i in range(len(refs))}

    def find(x: int) -> int:
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:  # 路径压缩
            parent[x], x = root, parent[x]
        return root

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    anchor: dict[str, int] = {}
    weak_anchor: dict[str, list[int]] = {}
    for idx, ref in enumerate(refs):
        for key in sorted(key_utils.key_set(ref.get("keys") or {})):
            if key.split(":", 1)[0] in key_utils.STRONG_KEYS:
                if key in anchor:
                    union(anchor[key], idx)
                else:
                    anchor[key] = idx
                continue
            # 弱键（host/domain）：仅当“同一批目标 + 同样手法 + 时间接近”时才连接
            for other in weak_anchor.get(key, []):
                if _similar_refs(refs[other], ref):
                    union(other, idx)
            weak_anchor.setdefault(key, []).append(idx)

    components: dict[int, list[int]] = {}
    for idx in range(len(refs)):
        components.setdefault(find(idx), []).append(idx)

    plans: list[CasePlan] = []
    for members in components.values():
        if len(members) > cap and settings.case_split_by_actor:
            for idxs, label in _split_bucket(refs, members, cap):
                plans.append(_build_plan(refs, idxs, split_reason=label))
            continue
        plans.append(_build_plan(refs, members))
    plans.sort(key=lambda p: (-len(p.fingerprints), p.attacker_key))
    return plans


def collect_refs(*, limit: int | None = None, hours: int | None = None) -> list[dict[str, Any]]:
    """读取事件组并重新抽键（含事件 raw —— 键提取必须基于原文）."""
    from datetime import timedelta

    out: list[dict[str, Any]] = []
    with SessionLocal() as db:
        query = select(EventGroup).where(EventGroup.status != "excluded")
        if hours:
            query = query.where(
                EventGroup.created_at
                > datetime.now(UTC) - timedelta(hours=max(1, _safe_int(hours, 24)))
            )
        query = query.order_by(EventGroup.created_at.desc()).limit(
            max(1, _safe_int(limit or 5000, 5000))
        )
        for group in db.scalars(query).all():
            events = db.scalars(select(Event).where(Event.group_id == group.id).limit(20)).all()
            raws = [e.raw for e in events if isinstance(e.raw, dict)]
            out.append(
                case_service.group_ref(
                    fingerprint=str(group.fingerprint or ""),
                    src_ips=list(group.src_ips or []),
                    dst_ips=list(group.dst_ips or []),
                    severity=group.severity,
                    event_types=[str(e.event_type or "") for e in events][:50],
                    texts=[str(e.summary or "") for e in events][:20],
                    raws=raws,
                    event_count=int(group.event_count or 0),
                    first_seen=group.window_start,
                    last_seen=group.window_end,
                )
            )
    return out


def dry_run(*, limit: int | None = None, hours: int | None = None) -> dict[str, Any]:
    """只算不写：返回新案件计划与对比计数（供人工核对后再 apply）。"""
    refs = collect_refs(limit=limit, hours=hours)
    plans = partition_groups(refs)
    with SessionLocal() as db:
        old_cases = db.scalars(
            select(AttackerCase).where(AttackerCase.status.in_(_ACTIVE_STATUS))
        ).all()
        old_sizes = sorted((len(row.group_fingerprints or []) for row in old_cases), reverse=True)
    sizes = sorted((len(p.fingerprints) for p in plans), reverse=True)
    return {
        "groups": len(refs),
        "old_cases": len(old_cases),
        "new_cases": len(plans),
        "old_max_groups": old_sizes[0] if old_sizes else 0,
        "new_max_groups": sizes[0] if sizes else 0,
        "oversized_before": sum(
            1 for n in old_sizes if n > _safe_int(settings.case_max_groups, 40)
        ),
        "oversized_after": sum(1 for n in sizes if n > _safe_int(settings.case_max_groups, 40)),
        "junk_keys_before": sum(
            1
            for row in old_cases
            if any(
                d.split(".", 1)[0].lower() in {"vnd", "application", "octet", "msword"}
                for d in ((row.keys or {}).get("domain") or [])
            )
        ),
        "sample_new": [p.brief() for p in plans[:15]],
        "sample_old": [
            {
                "id": row.id,
                "attacker_key": row.attacker_key,
                "groups": len(row.group_fingerprints or []),
                "severity": row.severity,
            }
            for row in sorted(old_cases, key=lambda r: -len(r.group_fingerprints or []))[:10]
        ],
    }


def apply(
    *,
    run_id: str,
    limit: int | None = None,
    hours: int | None = None,
    dispatch_after: bool = False,
    mapping: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """落库：新建案件 + 旧案件置 superseded + 组上写指针与案件视角副本（不改事件/图）。"""
    refs = collect_refs(limit=limit, hours=hours)
    plans = partition_groups(refs)
    by_fp = {str(r.get("fingerprint") or ""): r for r in refs}

    created_ids: list[str] = []
    superseded_ids: list[str] = []
    group_updates = 0
    new_mapping: dict[str, list[str]] = dict(mapping or {})

    with SessionLocal() as db:
        # 幂等：先清掉同一批次上次创建的案件（若有）
        for old_ids in new_mapping.values():
            for cid in old_ids:
                row = db.get(AttackerCase, cid)
                if row is not None and row.superseded_by == "":
                    db.delete(row)
        db.commit()

        old_cases = db.scalars(
            select(AttackerCase).where(AttackerCase.status.in_(_ACTIVE_STATUS))
        ).all()
        old_by_fp: dict[str, str] = {}
        for row in old_cases:
            for fp in row.group_fingerprints or []:
                old_by_fp.setdefault(str(fp), row.id)

        for plan in plans:
            if not plan.fingerprints:
                continue
            case_row = AttackerCase(
                attacker_key=plan.attacker_key,
                title=f"攻击者 {plan.attacker_key}",
                keys=plan.keys,
                status=case_service._initial_status(plan.severity),
                severity=plan.severity,
                src_ips=plan.src_ips,
                dst_ips=plan.dst_ips,
                group_fingerprints=plan.fingerprints,
                event_types=plan.event_types,
                group_count=len(plan.fingerprints),
                event_count=plan.event_count,
                first_seen=plan.first_seen,
                last_seen=plan.last_seen,
                merge_basis=plan.merge_basis,
                split_reason=plan.split_reason,
                pending_signal={},
            )
            db.add(case_row)
            db.flush()
            created_ids.append(case_row.id)
            for fp in plan.fingerprints:
                old_id = old_by_fp.get(fp)
                if old_id:
                    new_mapping.setdefault(old_id, [])
                    if case_row.id not in new_mapping[old_id]:
                        new_mapping[old_id].append(case_row.id)
            # 组上只写指针 + 案件视角副本
            context = {
                "case_id": case_row.id,
                "title": case_row.title,
                "severity": plan.severity,
                "status": "rebuilt",
                "summary": "（重建生成的案件，尚未调查）",
                "path": [],
                "confidence": None,
                "rounds": 0,
                "updated_at": datetime.now(UTC).isoformat(),
                "superseded": False,
                "rebuilt_by": run_id,
            }
            for fp in plan.fingerprints:
                group = db.scalars(
                    select(EventGroup).where(EventGroup.fingerprint == fp)
                ).one_or_none()
                if group is None:
                    continue
                # 旧叙事（attack_chain 里带 case_id 的）迁移到 case_context，不删除、不改写
                previous = group.case_context if isinstance(group.case_context, dict) else None
                if previous and previous.get("summary"):
                    context_prev = {**previous, "superseded": True}
                    group.case_context = {"case_id": case_row.id, "superseded_from": context_prev}
                else:
                    group.case_context = context
                group.case_id = case_row.id
                group_updates += 1

            # 证据阶梯重算级别（只动被旧叙事影响的组）
            for fp in plan.fingerprints:
                group = db.scalars(
                    select(EventGroup).where(EventGroup.fingerprint == fp)
                ).one_or_none()
                if group is None:
                    continue
                ref = by_fp.get(fp) or {}
                events = db.scalars(select(Event).where(Event.group_id == group.id).limit(50)).all()
                from app.agents import triage_policy

                tier = triage_policy.evidence_tier(
                    event_types=[str(e.event_type or "") for e in events],
                    conn_states=[str((e.raw or {}).get("conn_state") or "") for e in events],
                    bytes_out=max(
                        (int((e.raw or {}).get("resp_bytes") or 0) for e in events), default=0
                    ),
                    rule_severity=ref.get("severity"),
                    hits=_safe_int(ref.get("event_count"), 0),
                )
                capped, reason = triage_policy.cap_severity(
                    severity=group.severity,
                    direction=group.direction or "",
                    has_evidence=True,
                    tier=tier,
                )
                if capped != (group.severity or "info"):
                    group.severity = capped
                    group.severity_cap_reason = (reason or "")[:500]

        for row in old_cases:
            # 旧案件全部退场（新案件已按新规则重建）；superseded 列表默认隐藏但可查
            row.status = "superseded"
            row.superseded_by = run_id
            superseded_ids.append(row.id)
        db.commit()

    result = {
        "groups": len(refs),
        "new_cases": len(created_ids),
        "superseded_cases": len(superseded_ids),
        "group_updates": group_updates,
        "dispatch_after": bool(dispatch_after),
        "created_ids": created_ids[:200],
    }
    with SessionLocal() as db:
        run = db.get(RebuildRun, run_id)
        if run is not None:
            run.status = "finished"
            run.finished_at = datetime.now(UTC)
            run.counts = {**result, "created_ids": len(created_ids)}
            run.mapping = new_mapping
        db.commit()
    log.info(
        "重建完成（run %s）：组 %d → 新案件 %d，旧案件 superseded %d，组指针更新 %d",
        run_id,
        len(refs),
        len(created_ids),
        len(superseded_ids),
        group_updates,
    )
    return result


def rollback(run_id: str) -> dict[str, Any]:
    """回滚：删掉该批次新建的案件，恢复被 superseded 的旧案件。"""
    with SessionLocal() as db:
        run = db.get(RebuildRun, run_id)
        if run is None:
            return {"ok": False, "error": "批次不存在"}
        mapping = run.mapping or {}
        removed = 0
        for ids in mapping.values():
            for cid in ids:
                row = db.get(AttackerCase, cid)
                if row is not None and row.superseded_by == "" and row.rounds_total == 0:
                    db.delete(row)
                    removed += 1
        restored = 0
        for old_id in mapping:
            row = db.get(AttackerCase, old_id)
            if row is not None and row.superseded_by == run_id:
                row.superseded_by = ""
                row.status = "investigated" if row.investigation else "open"
                restored += 1
        groups = db.scalars(select(EventGroup).where(EventGroup.case_id != "")).all()
        cleared = 0
        for group in groups:
            context = group.case_context if isinstance(group.case_context, dict) else {}
            if context.get("rebuilt_by") == run_id:
                group.case_id = ""
                group.case_context = context.get("superseded_from") or None
                cleared += 1
        run.status = "rolled_back"
        run.finished_at = datetime.now(UTC)
        db.commit()
    log.warning(
        "重建回滚（run %s）：删新案件 %d，恢复旧案件 %d，清组指针 %d",
        run_id,
        removed,
        restored,
        cleared,
    )
    return {"ok": True, "removed": removed, "restored": restored, "groups_cleared": cleared}


def new_run(*, dry: bool, limit: int | None = None, hours: int | None = None) -> str:
    with SessionLocal() as db:
        row = RebuildRun(dry_run=dry, status="running", counts={"limit": limit, "hours": hours})
        db.add(row)
        db.commit()
        return row.id
