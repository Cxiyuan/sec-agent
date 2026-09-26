"""事件组查询 + HITL 确认 + 证据链。"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.agents.runner import resume_graph
from app.api.deps import get_current_user
from app.config import settings
from app.db.base import get_db
from app.db.models import Event, EventGroup, User
from app.investigation import export as investigation_export
from app.tools.context import is_public_ip

router = APIRouter(prefix="/api/events", tags=["events"])

# 证据链上限：证据要能下钻到原始记录，但**不能把详情页拖慢**
MAX_EVIDENCE_EVENTS = 100
MAX_EVIDENCE_RESOLVED = 60
MAX_RAW_CHARS = 4000
# 详情页突出展示的关键 IP 个数（其余折叠，避免把这一批涉及的 IP 全铺开）
MAX_KEY_IPS = 5


def _key_ips(g: EventGroup) -> dict[str, Any]:
    """挑出**真正有问题**的 IP（详情只突出这些，不把本批涉及的 IP 全列出来）。

    为什么需要：一个事件组是按 IP 集合归并出来的，里面往往包含十几个源/目标 IP
    （同网段的一批机器），全列出来会让人分不清“到底是谁有问题”。

    判定依据（可解释、可回溯）：
    - 只统计**命中事件**（被排除的不算）：源侧按命中次数排序 = 可疑来源，
      目标侧按命中次数排序 = 被打目标；
    - **外网来源优先置顶**（真正的外部攻击者）；内网源多为漏扫/监控等运维流量，
      需要人工核对；
    - 带上该 IP 命中的规则与时间范围，供人工判断；
    - 只给前 MAX_KEY_IPS 个，其余放进 other_* 供界面折叠展开。
    """
    src_stat: dict[str, dict[str, Any]] = {}
    dst_stat: dict[str, dict[str, Any]] = {}
    for e in g.events:
        if e.excluded:
            continue
        ts = e.ts.isoformat() if e.ts else None
        if e.src_ip:
            s = src_stat.setdefault(
                str(e.src_ip), {"hits": 0, "rules": [], "types": [], "first": None, "last": None}
            )
            s["hits"] += 1
            if e.hit_rule and e.hit_rule not in s["rules"]:
                s["rules"].append(e.hit_rule)
            if e.event_type and e.event_type not in s["types"]:
                s["types"].append(e.event_type)
            if ts:
                s["first"] = min(s["first"] or ts, ts)
                s["last"] = max(s["last"] or ts, ts)
        if e.dst_ip:
            d = dst_stat.setdefault(str(e.dst_ip), {"hits": 0, "rules": [], "ports": []})
            d["hits"] += 1
            if e.hit_rule and e.hit_rule not in d["rules"]:
                d["rules"].append(e.hit_rule)
            if e.dst_port is not None and int(e.dst_port) not in d["ports"]:
                d["ports"].append(int(e.dst_port))

    def rank(stat: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        rows = [{"ip": ip, "external": is_public_ip(ip), **s} for ip, s in stat.items()]
        rows.sort(key=lambda r: (not r["external"], -int(r["hits"]), str(r["ip"])))
        return rows

    actors = rank(src_stat)
    targets = rank(dst_stat)
    group_src = [str(x) for x in (g.src_ips or [])]
    group_dst = [str(x) for x in (g.dst_ips or [])]
    key_src = {str(r["ip"]) for r in actors[:MAX_KEY_IPS]}
    key_dst = {str(r["ip"]) for r in targets[:MAX_KEY_IPS]}
    return {
        "actors": actors[:MAX_KEY_IPS],
        "targets": targets[:MAX_KEY_IPS],
        "external_actors": [r for r in actors if r["external"]][:MAX_KEY_IPS],
        "other_src": [ip for ip in group_src if ip not in key_src][:50],
        "other_dst": [ip for ip in group_dst if ip not in key_dst][:50],
        "total_src": len(group_src),
        "total_dst": len(group_dst),
    }


def _group_dict(g: EventGroup, with_events: bool = False) -> dict[str, Any]:
    data = {
        "id": g.id,
        "fingerprint": g.fingerprint,
        "src_ips": g.src_ips,
        "dst_ips": g.dst_ips,
        "window_start": g.window_start.isoformat() if g.window_start else None,
        "window_end": g.window_end.isoformat() if g.window_end else None,
        "event_count": g.event_count,
        "triage_score": g.triage_score,
        "status": g.status,
        "severity": g.severity,
        "business_context": g.business_context,
        "lookback": g.lookback,
        "memory_hits": g.memory_hits,
        "attack_chain": g.attack_chain,
        "profile": g.profile,
        "anomaly": g.anomaly,
        "response_suggestions": g.response_suggestions,
        # 聚合规模（实时链路）：命中次数/规则分布/目标与端口/首末时间
        "aggregate": g.aggregate or {},
        # 被排除过滤命中：事件可见、可回溯，但不参与模型分析与报告
        "excluded": g.status == "excluded",
        # 误报治理：内外网方向、跳过原因、定级被约束的原因（都要能解释清楚）
        "direction": g.direction or "",
        "exclude_reason": g.exclude_reason or "",
        "severity_cap_reason": g.severity_cap_reason or "",
        "created_at": g.created_at.isoformat() if g.created_at else None,
    }
    if with_events:
        # 关键 IP：详情只突出真正有问题的（外网优先、按命中排序），其余折叠
        data["key_ips"] = _key_ips(g)
        data["events"] = [
            {
                "id": e.id,
                "source_system": e.source_system,
                "ts": e.ts.isoformat() if e.ts else None,
                "event_type": e.event_type,
                "src_ip": e.src_ip,
                "dst_ip": e.dst_ip,
                "src_port": e.src_port,
                "dst_port": e.dst_port,
                "protocol": e.protocol,
                "severity": e.severity,
                "hit_rule": e.hit_rule,
                "edge_score": e.edge_score,
                "summary": e.summary,
                "excluded": e.excluded,
            }
            for e in g.events
        ]
    return data


@router.get("/groups")
def list_groups(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    status: str | None = None,
    severity: str | None = None,
    include_excluded: bool = False,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    count_q = select(func.count()).select_from(EventGroup)
    q = select(EventGroup).order_by(EventGroup.window_start.desc())
    if status:
        count_q = count_q.where(EventGroup.status == status)
        q = q.where(EventGroup.status == status)
    elif not include_excluded:
        # 默认不显示“已排除”组（噪声不刷屏）；要看就传 status=excluded 或 include_excluded=true
        count_q = count_q.where(EventGroup.status != "excluded")
        q = q.where(EventGroup.status != "excluded")
    if severity:
        count_q = count_q.where(EventGroup.severity == severity)
        q = q.where(EventGroup.severity == severity)
    total = db.scalar(count_q) or 0
    rows = db.scalars(q.limit(limit).offset(offset)).all()
    return {"total": total, "items": [_group_dict(g) for g in rows]}


@router.get("/groups/{group_id}")
def get_group(
    group_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    g = db.execute(
        select(EventGroup).where(EventGroup.id == group_id).options(selectinload(EventGroup.events))
    ).scalar_one_or_none()
    if g is None:
        raise HTTPException(status_code=404, detail="事件组不存在")
    return _group_dict(g, with_events=True)


def _clip_raw(raw: Any) -> Any:
    """原始文档可能很大：超长就截断并标注（详情页要一次拿完，不能被单个文档拖慢）。"""
    if not isinstance(raw, (dict, list)):
        return raw
    try:
        text = json.dumps(raw, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return {"_truncated": True, "_preview": str(raw)[:MAX_RAW_CHARS]}
    if len(text) <= MAX_RAW_CHARS:
        return raw
    return {"_truncated": True, "_chars": len(text), "_preview": text[:MAX_RAW_CHARS]}


def _evidence_item_from_event(e: Event) -> dict[str, Any]:
    """组内命中日志 → 证据条目（ref 用 ev:<事件id>，与调查侧的引用格式统一）。"""
    ts = e.ts
    if ts is not None and ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return {
        "ref": f"ev:{e.id}",
        "kind": "event",
        "ts": ts.isoformat() if ts else None,
        "event_type": e.event_type,
        "source_system": e.source_system,
        "src": f"{e.src_ip}:{e.src_port}" if e.src_port else e.src_ip,
        "dst": f"{e.dst_ip}:{e.dst_port}" if e.dst_port else e.dst_ip,
        "src_ip": e.src_ip,
        "dst_ip": e.dst_ip,
        "protocol": e.protocol,
        "severity": e.severity,
        "hit_rule": e.hit_rule,
        "edge_score": e.edge_score,
        "summary": str(e.summary or "")[:300],
        "excluded": bool(e.excluded),
        "raw": _clip_raw(e.raw or {}),
    }


def _normalize_resolved(row: dict[str, Any]) -> dict[str, Any]:
    """把调查侧解析出的证据行归一成与上面一致的形状（前端只认一种结构）。"""
    ref = str(row.get("ref") or "")
    is_event = row.get("kind") == "event" and bool(row.get("id"))
    if is_event:
        return {
            "ref": ref,
            "kind": "event",
            "ts": row.get("ts"),
            "event_type": row.get("event_type"),
            "source_system": row.get("source_system"),
            "src": (
                f"{row.get('src_ip')}:{row.get('src_port')}"
                if row.get("src_port")
                else row.get("src_ip")
            ),
            "dst": (
                f"{row.get('dst_ip')}:{row.get('dst_port')}"
                if row.get("dst_port")
                else row.get("dst_ip")
            ),
            "protocol": row.get("protocol"),
            "severity": row.get("severity"),
            "hit_rule": row.get("hit_rule"),
            "edge_score": None,
            "src_ip": row.get("src_ip"),
            "dst_ip": row.get("dst_ip"),
            "summary": str(row.get("summary") or "")[:300],
            "excluded": False,
            "raw": _clip_raw(row.get("raw") or {}),
        }
    error = row.get("error")
    return {
        "ref": ref,
        "kind": str(row.get("kind") or "es_doc"),
        "ts": None,
        "event_type": None,
        "source_system": None,
        "src": None,
        "dst": None,
        "protocol": None,
        "severity": None,
        "hit_rule": None,
        "edge_score": None,
        "src_ip": None,
        "dst_ip": None,
        "summary": "原始证据文档" if not error else str(error)[:300],
        "excluded": False,
        "raw": {} if error else _clip_raw(row.get("raw") or {}),
        "error": error,
    }


def _link_fixed_stage_evidence(
    chain: dict[str, Any], items: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """把**固定深度分析**的阶段证据链到组内事件上。

    固定版 ``stages[].evidence`` 里是已被 attack_chain_node 映射回真实日志的摘要
    （type/src/dst/summary）。按「摘要前 120 字 + 源/目的 IP」精确匹配：
    - 匹配上 → 给那条证据打上阶段标记（证据链建立）；
    - 匹配不上 → 单列一条 kind=stage_evidence 并声明出处，**绝不错链**
      （错链比不链更糟：会让人以为某条日志支撑了某个结论）。
    """
    stages = chain.get("stages")
    if not isinstance(stages, list):
        return []
    index: dict[tuple[str, str, str], dict[str, Any]] = {}
    for it in items:
        key = (
            str(it.get("summary") or "")[:120],
            str(it.get("src_ip") or ""),
            str(it.get("dst_ip") or ""),
        )
        index.setdefault(key, it)
    out: list[dict[str, Any]] = []
    for st in stages:
        if not isinstance(st, dict):
            continue
        stage = str(st.get("stage") or "")
        evidence = st.get("evidence")
        for ev in evidence if isinstance(evidence, list) else []:
            if not isinstance(ev, dict):
                continue
            key = (
                str(ev.get("summary") or "")[:120],
                str(ev.get("src") or ""),
                str(ev.get("dst") or ""),
            )
            target = index.get(key)
            if target is not None:
                marked = target.setdefault("stages", [])
                if stage and stage not in marked:
                    marked.append(stage)
                continue
            out.append(
                {
                    "ref": "",
                    "kind": "stage_evidence",
                    "ts": None,
                    "event_type": str(ev.get("type") or ""),
                    "source_system": None,
                    "src": str(ev.get("src") or "") or None,
                    "dst": str(ev.get("dst") or "") or None,
                    "src_ip": str(ev.get("src") or "") or None,
                    "dst_ip": str(ev.get("dst") or "") or None,
                    "protocol": None,
                    "severity": None,
                    "hit_rule": None,
                    "edge_score": None,
                    "summary": str(ev.get("summary") or "")[:300],
                    "excluded": False,
                    "raw": {},
                    "stages": [stage] if stage else [],
                    "note": "来自攻击链分析（未在本组事件列表中找到对应条目）",
                }
            )
    return out


def _stage_evidence(chain: dict[str, Any]) -> list[dict[str, Any]]:
    """各阶段引用的证据：自主调查版看 path[].evidence_refs，固定版只有 stages。"""
    out: list[dict[str, Any]] = []
    path = chain.get("path")
    if isinstance(path, list) and path:
        for st in path:
            if not isinstance(st, dict):
                continue
            refs = st.get("evidence_refs")
            out.append(
                {
                    "stage": str(st.get("stage") or ""),
                    "description": str(st.get("description") or "")[:200],
                    "evidence_refs": (
                        [str(r) for r in refs if isinstance(r, str)]
                        if isinstance(refs, list)
                        else []
                    ),
                }
            )
        return out
    stages = chain.get("stages")
    if isinstance(stages, list):
        for st in stages:
            if isinstance(st, dict):
                out.append(
                    {
                        "stage": str(st.get("stage") or ""),
                        "description": str(st.get("description") or "")[:200],
                        "evidence_refs": [],
                    }
                )
    return out


def _fill_stage_refs(stages: list[dict[str, Any]], items: list[dict[str, Any]]) -> None:
    """用条目上的阶段标记**反向回填** stages[].evidence_refs。

    为什么必须回填：固定深度分析的 stages 只有 evidence（摘要）没有 refs，
    不回填就会出现"阶段显示 0 条证据、而证据却标着该阶段"的自相矛盾（部署后实测到）。
    """
    linked: dict[str, list[str]] = {}
    for item in items:
        ref = str(item.get("ref") or "")
        if not ref:
            continue
        for stage_name in item.get("stages") or []:
            bucket = linked.setdefault(str(stage_name), [])
            if ref not in bucket:
                bucket.append(ref)
    for st in stages:
        stage_name = str(st.get("stage") or "")
        if not st.get("evidence_refs") and stage_name in linked:
            st["evidence_refs"] = linked[stage_name]


@router.get("/groups/{group_id}/evidence")
def get_group_evidence(
    group_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """事件组证据链：把「命中的日志」与「调查引用的证据」解析成可下钻的清单。

    为什么单开一个接口（不塞进组详情）：证据带原始文档，体积大、条数多，
    塞进详情会让详情页变慢；这里单独拉，界面也能按需展开。

    两类证据来源：
    - **组内命中的真实日志**（ref=``ev:<事件id>``）：规则命中的直接依据，
      按时间排序，带命中规则/边缘分/原始文档；
    - **自主调查引用的证据**（``ev:``/``es:``）：调查结论依赖的证据，会去重
      （已在组内事件里的不再重复），并从 PG（已脱敏）或 ES（导出前过同一个脱敏）取原始文档。
    """
    g = db.execute(
        select(EventGroup).where(EventGroup.id == group_id).options(selectinload(EventGroup.events))
    ).scalar_one_or_none()
    if g is None:
        raise HTTPException(status_code=404, detail="事件组不存在")

    chain: dict[str, Any] = g.attack_chain if isinstance(g.attack_chain, dict) else {}
    all_events = list(g.events)
    events = sorted(all_events, key=lambda e: e.ts or datetime.min.replace(tzinfo=UTC))
    items = [_evidence_item_from_event(e) for e in events[:MAX_EVIDENCE_EVENTS]]
    covered = {str(i["ref"]) for i in items}

    # 调查引用的证据：去重后补进来（这类证据可能在组内事件之外，如 ES 历史文档）
    resolved: list[dict[str, Any]] = []
    if chain:
        try:
            rows = investigation_export.collect_evidence(chain, with_raw=True)
        except Exception as exc:  # noqa: BLE001
            rows = []
            items_note = f"解析调查证据失败：{exc}"
        else:
            items_note = ""
        for row in rows:
            if not isinstance(row, dict) or str(row.get("ref")) in covered:
                continue
            resolved.append(_normalize_resolved(row))
            if len(resolved) >= MAX_EVIDENCE_RESOLVED:
                break
        if items_note:
            resolved.append(
                {
                    "ref": "",
                    "kind": "note",
                    "ts": None,
                    "event_type": None,
                    "source_system": None,
                    "src": None,
                    "dst": None,
                    "protocol": None,
                    "severity": None,
                    "hit_rule": None,
                    "edge_score": None,
                    "summary": items_note[:300],
                    "excluded": False,
                    "raw": {},
                    "error": items_note,
                }
            )

    stages = _stage_evidence(chain)
    # 固定深度分析的阶段证据 → 链到组内事件（链不上的单列，不错链）
    stage_items = _link_fixed_stage_evidence(chain, items)
    stage_refs = {r for st in stages for r in st["evidence_refs"]}
    all_items = [*items, *stage_items, *resolved]
    for item in all_items:
        if item["ref"] and item["ref"] in stage_refs:
            marked = item.setdefault("stages", [])
            for st in stages:
                if item["ref"] in st["evidence_refs"] and st["stage"] not in marked:
                    marked.append(st["stage"])
    # 两个视图必须一致：把匹配到的证据回填到阶段上
    _fill_stage_refs(stages, all_items)

    return {
        "group_id": g.id,
        "fingerprint": g.fingerprint,
        "severity": g.severity,
        "stages": stages,
        "items": all_items,
        "investigation": {
            "case_id": chain.get("case_id"),
            "status": chain.get("status"),
            "round": chain.get("round"),
            "confidence": chain.get("confidence"),
            "has_result": bool(chain),
        },
        "counts": {
            "events": len(items),
            "stage_evidence": len(stage_items),
            "investigation_refs": len(resolved),
            "total": len(all_items),
            "stages": len(stages),
            "linked": sum(1 for i in all_items if i.get("stages")),
            "events_truncated": len(all_events) > MAX_EVIDENCE_EVENTS,
            "raw_max_chars": MAX_RAW_CHARS,
            "raw_enabled": settings.investigation_raw_evidence_max > 0,
        },
    }


class ConfirmRequest(BaseModel):
    action: str  # "confirm" | "dismiss"


@router.post("/groups/{group_id}/confirm")
async def confirm_group(
    group_id: str,
    req: ConfirmRequest,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    g = db.get(EventGroup, group_id)
    if g is None:
        raise HTTPException(status_code=404, detail="事件组不存在")
    if g.thread_id is None:
        raise HTTPException(status_code=400, detail="该事件组无待确认状态")

    decision = {"confirmations": {g.fingerprint: req.action}}
    await asyncio.to_thread(resume_graph, g.thread_id, decision)
    return {"ok": True, "action": req.action, "fingerprint": g.fingerprint}
