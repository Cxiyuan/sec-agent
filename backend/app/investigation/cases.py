"""案件归集与人工操作。

归集策略（三层，按可靠性降级）：
1. **键交集**：与已有案件的键集合有交集 → 挂过去（记录 link_reason，可解释、可复现）；
   同时命中多个案件 → 挂交集最大的，另一个案件写 merge_suggestion 供人工合并。
2. **相似度 + 模型裁定**：键无交集但"目标资产重叠 + 手法相同 + 时间接近"→ 交给 deep 裁定
   （每批上限 ``investigation_link_max_calls``，裁定理由入库）。
3. **新建案件**：都不满足 → 新案件。

触发调查的闸门：准入级别 + 冷却窗口 + 是否有新证据 + 单案每日轮次上限。
冷却期内不重跑，只把新证据累积进 ``pending_signal``——避免"同一个案件被反复调查"烧钱。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import redis
from sqlalchemy import select

from app.config import settings
from app.db.base import SessionLocal
from app.db.models import AttackerCase, CaseInvestigation, EventGroup
from app.investigation import keys as key_utils
from app.workers.log import get_logger

log = get_logger(__name__)

_ACTIVE_STATUS = ("open", "investigating", "investigated", "failed")
_LOCK_TTL = 3600


def _now() -> datetime:
    return datetime.now(UTC)


def _dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip())
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def _severity_rank(sev: str | None) -> int:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(str(sev or "info").lower(), 0)


def _safe_int(value: Any, default: int = 0) -> int:
    """安全转 int（接口/模型给的值可能是字符串或脏值，不该让归集/落库崩掉）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def case_dict(row: AttackerCase, *, with_investigation: bool = True) -> dict[str, Any]:
    """案件 → 接口字典。"""
    data: dict[str, Any] = {
        "id": row.id,
        # 展示用唯一编号（人工沟通/报告引用都靠它）：AC-<8位>
        "display_id": f"AC-{str(row.id)[:8].upper()}",
        "attacker_key": row.attacker_key,
        "title": row.title,
        "keys": row.keys or {},
        "status": row.status,
        "severity": row.severity,
        "src_ips": row.src_ips or [],
        "dst_ips": row.dst_ips or [],
        "group_fingerprints": row.group_fingerprints or [],
        "group_count": row.group_count,
        "event_count": row.event_count,
        "event_types": row.event_types or [],
        "first_seen": row.first_seen.isoformat() if row.first_seen else None,
        "last_seen": row.last_seen.isoformat() if row.last_seen else None,
        "rounds_total": row.rounds_total,
        "rounds_today": row.rounds_today,
        "last_dispatched_at": row.last_dispatched_at.isoformat()
        if row.last_dispatched_at
        else None,
        "next_allowed_at": row.next_allowed_at.isoformat() if row.next_allowed_at else None,
        "last_error": row.last_error,
        "merge_suggestion": row.merge_suggestion,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "pending_signal": row.pending_signal or {},
    }
    if with_investigation:
        data["investigation"] = row.investigation
    return data


def _find_cases_by_keys(wanted: set[str]) -> list[AttackerCase]:
    """按键取候选案件（键存 JSONB，量小 → 直接全表扫活跃案件再算交集，简单可靠）。"""
    if not wanted:
        return []
    with SessionLocal() as db:
        rows = db.scalars(select(AttackerCase).where(AttackerCase.status.in_(_ACTIVE_STATUS))).all()
        # 先把需要的字段读出来（避免会话关闭后再访问 ORM 属性）
        return list(rows)


def group_ref(
    *,
    fingerprint: str,
    src_ips: list[str],
    dst_ips: list[str],
    severity: str | None,
    event_types: list[str],
    texts: list[str],
    raws: list[dict[str, Any]] | None,
    event_count: int,
    first_seen: Any = None,
    last_seen: Any = None,
) -> dict[str, Any]:
    """把事件组压成可投递的引用（键抽取在此完成，任务端只做归集）。"""
    extracted = key_utils.extract_keys(
        src_ips=src_ips, dst_ips=dst_ips, texts=list(texts or [])[:20], raws=list(raws or [])[:20]
    )
    first = _dt(first_seen)
    last = _dt(last_seen)
    return {
        "fingerprint": fingerprint,
        "src_ips": list(src_ips or []),
        "dst_ips": list(dst_ips or []),
        "severity": str(severity or "info"),
        "event_types": list(event_types or []),
        "event_count": _safe_int(event_count),
        "first_seen": first.isoformat() if first else None,
        "last_seen": last.isoformat() if last else None,
        "keys": extracted,
        "texts": [str(t)[:300] for t in (texts or [])[:20]],
    }


def _link_case(rows: list[AttackerCase], wanted: set[str]) -> tuple[AttackerCase | None, list[str]]:
    """选出交集最大的案件；返回 (案件, 其它也有交集的案件 id)。"""
    scored: list[tuple[int, datetime, AttackerCase]] = []
    for row in rows:
        overlap = wanted & key_utils.key_set(row.keys)
        if overlap:
            last = row.last_seen or row.created_at or _now()
            scored.append((len(overlap), last, row))
    if not scored:
        return None, []
    scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
    return scored[0][2], [r.id for _n, _t, r in scored[1:]]


def _similar(row: AttackerCase, ref: dict[str, Any]) -> bool:
    """相似判定：目标资产重叠 + 手法相同 + 时间接近（三者同时满足才交给模型裁定）。"""
    window = max(1, settings.investigation_link_window_hours)
    ref_last = _dt(ref.get("last_seen")) or _now()
    ref_first = _dt(ref.get("first_seen")) or ref_last
    case_last = row.last_seen or row.created_at or _now()
    case_first = row.first_seen or row.created_at or case_last
    if (
        min(
            abs((ref_first - case_last).total_seconds()),
            abs((case_first - ref_last).total_seconds()),
        )
        > window * 3600
    ):
        return False
    if not ({str(x) for x in (ref.get("dst_ips") or [])} & {str(x) for x in (row.dst_ips or [])}):
        return False
    return bool(
        {str(x) for x in (ref.get("event_types") or [])} & {str(x) for x in (row.event_types or [])}
    )


def _adjudicate(ref: dict[str, Any], candidates: list[AttackerCase]) -> tuple[str | None, str]:
    """模型裁定归属：返回 (案件id 或 None, 理由)。失败一律按"不属于"处理（保守）。"""
    from app.models import prompts
    from app.models.llm import deep_invoke_json

    payload = [
        {
            "case_id": row.id,
            "attacker_key": row.attacker_key,
            "severity": row.severity,
            "dst_ips": (row.dst_ips or [])[:10],
            "event_types": (row.event_types or [])[:10],
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            "keys": key_utils.compact(row.keys),
        }
        for row in candidates[:3]
    ]
    group_brief = {
        "src_ips": (ref.get("src_ips") or [])[:5],
        "dst_ips": (ref.get("dst_ips") or [])[:5],
        "event_types": (ref.get("event_types") or [])[:10],
        "severity": ref.get("severity"),
        "first_seen": ref.get("first_seen"),
        "last_seen": ref.get("last_seen"),
        "keys": key_utils.compact(ref.get("keys") or {}),
        "summaries": (ref.get("texts") or [])[:5],
    }
    try:
        reply = deep_invoke_json(
            prompts.CASE_LINK_SYSTEM,
            prompts.CASE_LINK_USER.format(
                group=_json(group_brief),
                candidates=_json(payload),
            ),
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("案件归属裁定失败（按新建处理）: %s", exc)
        return None, f"裁定失败：{exc}"
    case_id = str(reply.get("case_id") or "none").strip()
    reason = str(reply.get("reason") or "")[:200]
    if case_id in {"none", "", "null"} or not any(row.id == case_id for row in candidates):
        return None, reason or "模型判定不属于任何候选案件"
    return case_id, reason


def _json(value: Any) -> str:
    import json

    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def _signal_for(ref: dict[str, Any]) -> dict[str, Any]:
    return {
        "groups": [str(ref.get("fingerprint") or "")],
        "event_types": list(ref.get("event_types") or [])[:20],
        "iocs": list((ref.get("keys") or {}).get("domain") or [])[:20],
        "hashes": list((ref.get("keys") or {}).get("hash") or [])[:20],
        "severity": str(ref.get("severity") or "info"),
    }


def _merge_signal(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    out = dict(old or {})
    for key in ("groups", "event_types", "iocs", "hashes"):
        out[key] = sorted({*(out.get(key) or []), *(new.get(key) or [])})[:50]
    if _severity_rank(new.get("severity")) > _severity_rank(out.get("severity")):
        out["severity"] = new.get("severity")
    out["new_since_last_round"] = True
    return out


def _has_new_evidence(signal: dict[str, Any]) -> bool:
    return bool(
        signal.get("groups")
        or signal.get("iocs")
        or signal.get("hashes")
        or signal.get("event_types")
    )


def should_investigate(row: AttackerCase, *, is_new: bool) -> tuple[bool, str]:
    """是否需要（重新）调查：准入级别 + 冷却 + 新证据 + 每日轮次。"""
    if not settings.investigation_enabled:
        return False, "自主调查未开启"
    if row.status == "closed":
        return False, "案件已关闭"
    if _severity_rank(row.severity) < _severity_rank(settings.investigation_min_severity):
        return False, f"严重度 {row.severity} 低于准入级别 {settings.investigation_min_severity}"
    if is_new:
        return True, "新建案件首次调查"
    if row.rounds_today >= settings.investigation_max_rounds_per_day:
        return False, f"今日调查轮次已达上限 {settings.investigation_max_rounds_per_day}"
    now = _now()
    if row.next_allowed_at is not None and row.next_allowed_at > now:
        return False, f"冷却中（下次可调查 {row.next_allowed_at.isoformat()}）"
    if not _has_new_evidence(row.pending_signal or {}):
        return False, "冷却期内没有新证据"
    return True, "有新证据且冷却已过"


def upsert_from_groups(refs: list[dict[str, Any]]) -> dict[str, Any]:
    """归集主入口：把事件组引用挂到案件上，返回需要调查的案件 id 与原因。"""
    if not refs:
        return {"created": 0, "linked": 0, "skipped": 0, "dispatch": []}
    created = linked = skipped = adjudications = 0
    dispatch: list[dict[str, Any]] = []
    for ref in refs:
        wanted = key_utils.key_set(ref.get("keys") or {})
        rows = _find_cases_by_keys(wanted)
        target, others = _link_case(rows, wanted)
        link_reason = ""
        if target is not None:
            link_reason = f"键交集 {sorted(wanted & key_utils.key_set(target.keys))[:5]}"
        else:
            similar = [row for row in rows if _similar(row, ref)]
            if similar and adjudications < max(0, settings.investigation_link_max_calls):
                adjudications += 1
                chosen, reason = _adjudicate(ref, similar)
                if chosen:
                    target = next((row for row in similar if row.id == chosen), None)
                    link_reason = f"模型裁定：{reason}"
            if target is None and similar:
                link_reason = "相似但未归并（裁定否 / 达裁定上限）"

        if target is None:
            case_id, is_new = _create_case(ref), True
            created += 1
        else:
            case_id, is_new = target.id, False
            linked += 1
        with SessionLocal() as db:
            row = db.get(AttackerCase, case_id)
            if row is None:
                skipped += 1
                continue
            _attach(db, row, ref, link_reason=link_reason, is_new=is_new, others=others)
            db.commit()
            ok, reason = should_investigate(row, is_new=is_new)
            if ok:
                dispatch.append({"case_id": row.id, "reason": reason, "kind": "auto"})
            else:
                skipped += 1
    return {
        "created": created,
        "linked": linked,
        "skipped": skipped,
        "adjudications": adjudications,
        "dispatch": dispatch,
    }


def _qualifies(severity: Any) -> bool:
    """严重度是否达到调查门槛（纯函数，便于桩测）。"""
    return _severity_rank(str(severity or "info")) >= _severity_rank(
        settings.investigation_min_severity
    )


def _initial_status(severity: Any) -> str:
    """新建案件的初始状态：低于门槛 → shelved（归档、列表默认隐藏、不派发调查）。"""
    return "open" if _qualifies(severity) else "shelved"


def _create_case(ref: dict[str, Any]) -> str:
    extracted = key_utils.compact(ref.get("keys") or {})
    primary = key_utils.primary_key(extracted)
    sev = str(ref.get("severity") or "info")
    row = AttackerCase(
        attacker_key=primary,
        title=f"攻击者 {primary}",
        keys=extracted,
        status=_initial_status(sev),
        severity=sev,
        src_ips=sorted({str(x) for x in (ref.get("src_ips") or [])}),
        dst_ips=sorted({str(x) for x in (ref.get("dst_ips") or [])}),
        group_fingerprints=[str(ref.get("fingerprint") or "")],
        event_types=sorted({str(x) for x in (ref.get("event_types") or [])}),
        group_count=1,
        event_count=_safe_int(ref.get("event_count")),
        first_seen=_dt(ref.get("first_seen")),
        last_seen=_dt(ref.get("last_seen")),
        pending_signal={},
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        return row.id


def _attach(
    db: Any,
    row: AttackerCase,
    ref: dict[str, Any],
    *,
    link_reason: str,
    is_new: bool,
    others: list[str],
) -> None:
    """把事件组挂到案件（幂等：同一指纹不重复计数）。"""
    fp = str(ref.get("fingerprint") or "")
    fps = list(row.group_fingerprints or [])
    if fp and fp not in fps:
        fps.append(fp)
        row.group_count = len(fps)
        row.event_count = _safe_int(row.event_count) + _safe_int(ref.get("event_count"))
    row.group_fingerprints = fps[:500]
    row.src_ips = sorted({*(row.src_ips or []), *(str(x) for x in (ref.get("src_ips") or []))})
    row.dst_ips = sorted({*(row.dst_ips or []), *(str(x) for x in (ref.get("dst_ips") or []))})
    row.event_types = sorted(
        {*(row.event_types or []), *(str(x) for x in (ref.get("event_types") or []))}
    )[:50]
    row.keys = key_utils.merge_keys(row.keys, ref.get("keys"))
    row.attacker_key = key_utils.primary_key(row.keys)
    if _severity_rank(ref.get("severity")) > _severity_rank(row.severity):
        row.severity = str(ref.get("severity"))
    # 达标信号复活：搁置案件收到达门槛的严重度 → 回到 open（是否派发由 should_investigate 判）
    if row.status == "shelved" and _qualifies(row.severity):
        row.status = "open"
    for attr, value in (
        ("first_seen", _dt(ref.get("first_seen"))),
        ("last_seen", _dt(ref.get("last_seen"))),
    ):
        current = getattr(row, attr)
        if value is None:
            continue
        if (
            current is None
            or (attr == "first_seen" and value < current)
            or (attr == "last_seen" and value > current)
        ):
            setattr(row, attr, value)
    if not is_new:
        row.pending_signal = _merge_signal(row.pending_signal or {}, _signal_for(ref))
    if link_reason:
        row.pending_signal = {**(row.pending_signal or {}), "last_link_reason": link_reason}
    if others:
        row.merge_suggestion = {
            "case_ids": others[:5],
            "reason": f"本次事件组同时命中 {len(others) + 1} 个案件，建议人工确认是否合并",
            "at": _now().isoformat(),
        }
    if row.status == "open" and row.investigation:
        row.status = "investigated"


def mark_dispatched(case_id: str, *, error: str = "") -> None:
    """记录派发：写冷却时间与派发时刻。"""
    with SessionLocal() as db:
        row = db.get(AttackerCase, case_id)
        if row is None:
            return
        now = _now()
        row.last_dispatched_at = now
        row.next_allowed_at = now + timedelta(
            minutes=max(0, settings.investigation_cooldown_minutes)
        )
        row.status = "investigating"
        if error:
            row.last_error = error[:1000]
        db.commit()


def start_round(case_id: str, *, kind: str, instruction: str = "") -> tuple[int, str] | None:
    """开一轮调查（建 case_investigations 行，返回轮次与 id）。拿不到案件返回 None。"""
    with SessionLocal() as db:
        row = db.get(AttackerCase, case_id)
        if row is None:
            return None
        today = _now().strftime("%Y-%m-%d")
        if row.rounds_day != today:
            row.rounds_day = today
            row.rounds_today = 0
        round_no = _safe_int(row.rounds_total) + 1
        inv = CaseInvestigation(
            case_id=case_id, round=round_no, kind=kind, instruction=instruction, status="running"
        )
        db.add(inv)
        db.flush()
        inv_id = inv.id
        row.rounds_total = round_no
        row.rounds_today = _safe_int(row.rounds_today) + 1
        db.commit()
        return round_no, inv_id


def finish_round(
    investigation_id: str,
    *,
    result: dict[str, Any],
    budget: dict[str, Any],
    trail: list[dict[str, Any]],
    status: str,
    error: str = "",
) -> None:
    with SessionLocal() as db:
        inv = db.get(CaseInvestigation, investigation_id)
        if inv is None:
            return
        inv.status = status
        inv.result = result
        inv.budget = budget
        inv.query_trail = trail[:200]
        inv.steps = _safe_int(budget.get("steps"))
        inv.llm_calls = _safe_int(budget.get("llm_calls"))
        inv.tokens = _safe_int(budget.get("tokens_est"))
        inv.elapsed_ms = _safe_int(budget.get("elapsed_ms"))
        inv.error = error[:1000]
        inv.finished_at = _now()
        db.commit()


def apply_result(case_id: str, result: dict[str, Any], *, status: str) -> None:
    """把结果落到案件，并把**成员组**的 attack_chain/profile 写成超集（旧界面零改动）。"""
    findings = list(result.get("path") or [])
    iocs = list(result.get("iocs") or [])
    gaps = list(result.get("gaps") or [])
    with SessionLocal() as db:
        row = db.get(AttackerCase, case_id)
        if row is None:
            return
        row.investigation = result
        # 案件状态只有 open/investigating/investigated/failed/closed；
        # 轮次的细节状态（partial/budget_exhausted）存在 case_investigations 与 pending_signal 里
        row.status = (
            "investigated" if status in ("succeeded", "partial", "budget_exhausted") else "failed"
        )
        row.last_error = (
            "" if status != "failed" else str(result.get("summary") or "调查失败")[:1000]
        )
        row.pending_signal = {
            **(row.pending_signal or {}),
            "groups": [],
            "iocs": [],
            "hashes": [],
            "event_types": [],
            "last_round_status": status,
        }
        if result.get("confidence") is not None:
            row.pending_signal = {
                **(row.pending_signal or {}),
                "confidence": result.get("confidence"),
            }
        fps = list(row.group_fingerprints or [])
        groups = (
            db.scalars(select(EventGroup).where(EventGroup.fingerprint.in_(fps))).all()
            if fps
            else []
        )
        for group in groups:
            group.attack_chain = result
            profile = result.get("attacker") or {}
            if isinstance(profile, dict) and (profile.get("basic") or profile.get("behavior")):
                group.profile = {
                    "basic": profile.get("basic") or {},
                    "behavior": profile.get("behavior") or {},
                    "case_id": case_id,
                }
        db.commit()
    log.info(
        "案件 %s 调查结果落库：阶段 %d / IOC %d / 缺口 %d（状态 %s）",
        case_id,
        len(findings),
        len(iocs),
        len(gaps),
        status,
    )


def merge_cases(target_id: str, source_id: str) -> dict[str, Any]:
    """把 source 案件并入 target（人工纠正模型归集）。"""
    if target_id == source_id:
        return {"ok": False, "error": "不能与自己合并"}
    with SessionLocal() as db:
        target = db.get(AttackerCase, target_id)
        source = db.get(AttackerCase, source_id)
        if target is None or source is None:
            return {"ok": False, "error": "案件不存在"}
        target.group_fingerprints = sorted(
            {*(target.group_fingerprints or []), *(source.group_fingerprints or [])}
        )
        target.group_count = len(target.group_fingerprints)
        target.event_count = _safe_int(target.event_count) + _safe_int(source.event_count)
        target.src_ips = sorted({*(target.src_ips or []), *(source.src_ips or [])})
        target.dst_ips = sorted({*(target.dst_ips or []), *(source.dst_ips or [])})
        target.event_types = sorted({*(target.event_types or []), *(source.event_types or [])})[:50]
        target.keys = key_utils.merge_keys(target.keys, source.keys)
        if _severity_rank(source.severity) > _severity_rank(target.severity):
            target.severity = source.severity
        for attr in ("first_seen", "last_seen"):
            current, other = getattr(target, attr), getattr(source, attr)
            if other is not None and (
                current is None
                or (attr == "first_seen" and other < current)
                or (attr == "last_seen" and other > current)
            ):
                setattr(target, attr, other)
        target.pending_signal = _merge_signal(
            target.pending_signal or {}, {"groups": source.group_fingerprints or []}
        )
        target.merge_suggestion = None
        for inv in db.scalars(
            select(CaseInvestigation).where(CaseInvestigation.case_id == source_id)
        ).all():
            inv.case_id = target_id
        db.delete(source)
        db.commit()
        return {"ok": True, "target": target_id, "merged_from": source_id}


def detach_group(case_id: str, fingerprint: str) -> dict[str, Any]:
    """把一个事件组从案件拆出（拆错挂的组时用；拆出的组会另建案件）。"""
    with SessionLocal() as db:
        row = db.get(AttackerCase, case_id)
        if row is None:
            return {"ok": False, "error": "案件不存在"}
        fps = [f for f in (row.group_fingerprints or []) if f != fingerprint]
        if len(fps) == len(row.group_fingerprints or []):
            return {"ok": False, "error": "该事件组不在这个案件里"}
        row.group_fingerprints = fps
        row.group_count = len(fps)
        db.commit()
    # 拆出的组按"新组"重新归集（可能挂到别的案件或新建）
    with SessionLocal() as db:
        group = db.scalars(
            select(EventGroup).where(EventGroup.fingerprint == fingerprint)
        ).one_or_none()
        if group is None:
            return {"ok": True, "detached": fingerprint, "reattached": None}
        ref = group_ref(
            fingerprint=group.fingerprint,
            src_ips=list(group.src_ips or []),
            dst_ips=list(group.dst_ips or []),
            severity=group.severity,
            event_types=sorted({e.event_type for e in group.events}) if group.events else [],
            texts=[e.summary for e in (group.events or [])][:20],
            raws=[e.raw for e in (group.events or [])][:20],
            event_count=group.event_count,
            first_seen=group.window_start,
            last_seen=group.window_end,
        )
    outcome = upsert_from_groups([ref])
    return {"ok": True, "detached": fingerprint, "reattached": outcome}


def attach_group(case_id: str, fingerprint: str) -> dict[str, Any]:
    """把事件组人工挂到指定案件。"""
    with SessionLocal() as db:
        group = db.scalars(
            select(EventGroup).where(EventGroup.fingerprint == fingerprint)
        ).one_or_none()
        row = db.get(AttackerCase, case_id)
        if group is None or row is None:
            return {"ok": False, "error": "案件或事件组不存在"}
        ref = group_ref(
            fingerprint=group.fingerprint,
            src_ips=list(group.src_ips or []),
            dst_ips=list(group.dst_ips or []),
            severity=group.severity,
            event_types=sorted({e.event_type for e in group.events}) if group.events else [],
            texts=[e.summary for e in (group.events or [])][:20],
            raws=[e.raw for e in (group.events or [])][:20],
            event_count=group.event_count,
            first_seen=group.window_start,
            last_seen=group.window_end,
        )
        _attach(db, row, ref, link_reason="人工挂载", is_new=False, others=[])
        db.commit()
    return {"ok": True, "case_id": case_id, "fingerprint": fingerprint}


def set_status(case_id: str, status: str) -> dict[str, Any]:
    if status not in ("open", "closed"):
        return {"ok": False, "error": "status 只能是 open / closed"}
    with SessionLocal() as db:
        row = db.get(AttackerCase, case_id)
        if row is None:
            return {"ok": False, "error": "案件不存在"}
        row.status = status
        db.commit()
    return {"ok": True, "case_id": case_id, "status": status}


def rounds(case_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
    """调查轮次历史（含查询轨迹与预算）。"""
    with SessionLocal() as db:
        rows = db.scalars(
            select(CaseInvestigation)
            .where(CaseInvestigation.case_id == case_id)
            .order_by(CaseInvestigation.round.desc())
            .limit(max(1, limit))
        ).all()
        return [
            {
                "id": r.id,
                "round": r.round,
                "kind": r.kind,
                "instruction": r.instruction,
                "status": r.status,
                "steps": r.steps,
                "llm_calls": r.llm_calls,
                "tokens": r.tokens,
                "elapsed_ms": r.elapsed_ms,
                "error": r.error,
                "query_trail": r.query_trail or [],
                "budget": r.budget or {},
                "result": r.result,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            }
            for r in rows
        ]


def stats() -> dict[str, Any]:
    """调查运行统计（队列积压/失败/轮次/预算消耗，供运维面板）。"""
    today = _now().strftime("%Y-%m-%d")
    with SessionLocal() as db:
        rows = db.scalars(select(AttackerCase)).all()
        total = len(rows)
        by_status: dict[str, int] = {}
        rounds_today = 0
        for row in rows:
            by_status[row.status] = by_status.get(row.status, 0) + 1
            if row.rounds_day == today:
                rounds_today += _safe_int(row.rounds_today)
        inv_rows = db.scalars(select(CaseInvestigation)).all()
        by_result: dict[str, int] = {}
        tokens = 0
        # 护栏计数（来自每轮落库的 budget）：一眼看出空转是“模型不听话”还是“数据查不到”
        guards = {"invalid_json": 0, "truncated": 0, "salvaged": 0, "no_progress": 0, "repeat": 0}
        for inv in inv_rows:
            by_result[inv.status] = by_result.get(inv.status, 0) + 1
            tokens += _safe_int(inv.tokens)
            budget = inv.budget or {}
            guards["invalid_json"] += _safe_int(budget.get("invalid_json"))
            guards["truncated"] += _safe_int(budget.get("truncated"))
            guards["salvaged"] += _safe_int(budget.get("salvaged"))
            guards["no_progress"] += _safe_int(budget.get("no_progress_hits"))
            guards["repeat"] += _safe_int(budget.get("repeat_hits"))
    empty_cases = sum(1 for row in rows if _safe_int(row.rounds_total) == 0)
    return {
        "enabled": settings.investigation_enabled,
        "min_severity": settings.investigation_min_severity,
        "cases_total": total,
        "cases_by_status": by_status,
        # 空壳可见性：零轮次案件数与占比（归档后应明显下降）
        "cases_empty": empty_cases,
        "cases_empty_perc": round(empty_cases * 100.0 / total, 1) if total else 0.0,
        "cases_shelved": by_status.get("shelved", 0),
        "cases_closed": by_status.get("closed", 0),
        "guards": guards,
        "rounds_today": rounds_today,
        "max_rounds_per_day": settings.investigation_max_rounds_per_day,
        "cooldown_minutes": settings.investigation_cooldown_minutes,
        "rounds_by_status": by_result,
        "tokens_est_total": tokens,
        "limits": {
            "max_steps": settings.investigation_max_steps,
            "max_queries": settings.investigation_max_queries,
            "max_llm_calls": settings.investigation_max_llm_calls,
            "max_steps_hard": settings.investigation_max_steps_hard,
            "max_llm_calls_hard": settings.investigation_max_llm_calls_hard,
            "timeout_seconds": settings.investigation_timeout_seconds,
            "invalid_json_limit": settings.investigation_invalid_json_limit,
            "no_progress_steps": settings.investigation_no_progress_steps,
            "docs_per_query": settings.investigation_max_docs_per_query,
        },
    }


# ---------- 单实例锁（Redis）：同一案件不并发调查 ----------


def acquire_lock(case_id: str) -> bool:
    try:
        client = redis.Redis.from_url(settings.redis_url)
        return bool(
            client.set(f"shentong:investigation:lock:{case_id}", "1", nx=True, ex=_LOCK_TTL)
        )
    except Exception as exc:  # noqa: BLE001
        # Redis 不可用时**放行**（宁可重复调查，也不要因为锁拿不到就永远不调查）
        log.warning("获取调查锁失败（放行）: %s", exc)
        return True


def release_lock(case_id: str) -> None:
    try:
        redis.Redis.from_url(settings.redis_url).delete(f"shentong:investigation:lock:{case_id}")
    except Exception as exc:  # noqa: BLE001
        log.debug("释放调查锁失败: %s", exc)


def list_cases(
    *,
    status: str | None = None,
    severity: str | None = None,
    keyword: str = "",
    limit: int = 50,
    offset: int = 0,
    include_shelved: bool = False,
) -> dict[str, Any]:
    """案件列表（分页 + 过滤）。

    默认不返回 shelved/closed：实测 25 个新案件里 20 个是零轮次空壳（info 级不够门槛），
    把列表刷满了。归档而不是删除——需要排查时用 ``include_shelved`` 显式打开。
    """
    with SessionLocal() as db:
        query = select(AttackerCase).order_by(AttackerCase.last_seen.desc().nullslast())
        if status:
            query = query.where(AttackerCase.status == status)
        elif not include_shelved:
            query = query.where(AttackerCase.status.notin_(["shelved", "closed"]))
        if severity:
            query = query.where(AttackerCase.severity == severity)
        if keyword:
            like = f"%{keyword}%"
            query = query.where(
                AttackerCase.attacker_key.ilike(like) | AttackerCase.title.ilike(like)
            )
        rows = db.scalars(query.limit(max(1, min(limit, 200))).offset(max(0, offset))).all()
        items = [case_dict(row, with_investigation=False) for row in rows]
        for item, row in zip(items, rows, strict=False):
            inv = row.investigation or {}
            item["summary"] = str(inv.get("summary") or "")[:300]
            item["confidence"] = inv.get("confidence")
            item["path_stages"] = [
                p.get("stage") for p in (inv.get("path") or []) if isinstance(p, dict)
            ]
        return {"total": len(items), "items": items}


def get_case(case_id: str) -> dict[str, Any] | None:
    with SessionLocal() as db:
        row = db.get(AttackerCase, case_id)
        if row is None:
            return None
        data = case_dict(row)
        fps = list(row.group_fingerprints or [])
        groups = (
            db.scalars(
                select(EventGroup)
                .where(EventGroup.fingerprint.in_(fps))
                .order_by(EventGroup.window_start)
            ).all()
            if fps
            else []
        )
        data["groups"] = [
            {
                "fingerprint": g.fingerprint,
                "window_start": g.window_start.isoformat() if g.window_start else None,
                "window_end": g.window_end.isoformat() if g.window_end else None,
                "src_ips": g.src_ips or [],
                "dst_ips": g.dst_ips or [],
                "event_count": g.event_count,
                "severity": g.severity,
                "status": g.status,
                "triage_score": g.triage_score,
            }
            for g in groups
        ]
        return data
