"""任务事实包：把智能体判断需要的事实一次性算清楚。

为什么单独一层：模型不应该靠“规则名 + 几条截断样本”自己猜方向、资产角色、
DNS 类型和证据是否充分。这里只输出**客观事实**（没有 verdict/severity），
由智能体和证据契约决定结论。

当前实现优先使用 NDR 已落库的 HitEvent/AssetRecord/AnalysisResult；
ES 原始文档的覆盖率在 `evidence` 里显式标注，取不到就标 unknown，不猜。
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import String, cast, select

from app.analysis import domain_intel
from app.db.base import SessionLocal
from app.db.models import AnalysisAnchor, AnalysisResult, AnalysisTask, AssetRecord, HitEvent
from app.detector import suppression

_FACTS_VERSION = 1


def _event_ids(task: AnalysisTask) -> list[str]:
    raw = (task.hint or {}).get("事件ID")
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    return [str(item).strip() for item in raw if str(item).strip()][:50]


def _asset_map(ips: list[str]) -> dict[str, dict[str, Any]]:
    wanted = sorted({ip for ip in ips if ip})[:200]
    if not wanted:
        return {}
    with SessionLocal() as db:
        rows = db.scalars(select(AssetRecord).where(AssetRecord.ip.in_(wanted))).all()
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        out[str(row.ip)] = {
            "ip": str(row.ip),
            "hostname": row.hostname or "",
            "owner": row.owner or "",
            "criticality": row.criticality or "normal",
            "tags": [x.strip() for x in (row.tags or "").split(",") if x.strip()],
            "note": row.note or "",
            "role": row.role or "unknown",
            "authorization": row.authorization or "unknown",
            "authorization_note": row.authorization_note or "",
            "authorized_by": row.authorized_by or "",
            "authorized_at": row.authorized_at.isoformat() if row.authorized_at else "",
            "expected_scan": bool(row.expected_scan),
        }
    return out


def _qtype_of(sample: dict[str, Any]) -> str:
    value = sample.get("qtype")
    if value is None:
        nested = sample.get("dns")
        if isinstance(nested, dict):
            value = nested.get("qtype") or nested.get("rrtype")
    return str(value or "").strip()


def _rcode_of(sample: dict[str, Any]) -> str:
    value = sample.get("rcode")
    if value is None:
        nested = sample.get("dns")
        if isinstance(nested, dict):
            value = nested.get("rcode")
    return str(value or "").strip()


def _answers_of(sample: dict[str, Any]) -> list[str]:
    value = sample.get("answers")
    if not isinstance(value, list):
        nested = sample.get("dns")
        value = nested.get("answers") if isinstance(nested, dict) else []
    return [str(x)[:200] for x in value][:20] if isinstance(value, list) else []


def _success_state(events: list[HitEvent]) -> dict[str, Any]:
    states = {str(x) for ev in events for x in (ev.conn_states or []) if str(x).strip()}
    statuses = {
        int(sample["status_code"])
        for ev in events
        for sample in (ev.evidence or [])
        if isinstance(sample, dict) and str(sample.get("status_code") or "").isdigit()
    }
    established = bool(states & {"SF", "S1", "S2", "S3"})
    http_ok = any(200 <= code < 400 for code in statuses)
    if established or http_ok:
        value = "success"
    elif states or statuses:
        value = "failure_or_unconfirmed"
    else:
        value = "unknown"
    return {
        "state": value,
        "conn_states": sorted(states),
        "http_statuses": sorted(statuses),
        "note": "success 只表示观察到成功建连/HTTP 2xx-3xx，不等于攻击成功",
    }


def _history(task: AnalysisTask, domains: list[str]) -> list[dict[str, Any]]:
    with SessionLocal() as db:
        rows = db.scalars(
            select(AnalysisResult)
            .where(AnalysisResult.subject == str(task.subject or ""))
            .order_by(AnalysisResult.created_at.desc())
            .limit(10)
        ).all()
        domain_rows: list[AnalysisResult] = []
        if domains:
            result_ids = list(
                db.scalars(
                    select(AnalysisAnchor.result_id).where(
                        AnalysisAnchor.asset_kind == "domain",
                        AnalysisAnchor.asset_value.in_(domains),
                    )
                ).all()
            )
            if result_ids:
                domain_rows = list(
                    db.scalars(
                        select(AnalysisResult)
                        .where(cast(AnalysisResult.id, String).in_([str(x) for x in result_ids]))
                        .order_by(AnalysisResult.created_at.desc())
                        .limit(10)
                    ).all()
                )

    def _rows(values: Sequence[AnalysisResult]) -> list[dict[str, Any]]:
        return [
            {
                "task_id": str(row.task_id),
                "verdict": str(row.verdict or ""),
                "confidence": float(row.confidence or 0),
                "summary": str(row.summary or "")[:500],
                "created_at": row.created_at.isoformat() if row.created_at else "",
            }
            for row in values
        ]

    return [
        {
            "query_domains": domains,
            "same_subject": _rows(rows),
            "same_domain": _rows(domain_rows),
        }
    ]


def build_task_facts(task_id: str) -> dict[str, Any]:
    """构建并返回任务事实包；任务不存在时返回 error。"""
    with SessionLocal() as db:
        task = db.get(AnalysisTask, str(task_id or "").strip())
        if task is None:
            return {"error": f"任务不存在：{task_id}"}
        events = list(
            db.scalars(select(HitEvent).where(HitEvent.id.in_(_event_ids(task)))).all()
        )

    hint = dict(task.hint or {})
    principal = ""
    principal_hint = hint.get("主体资产")
    if isinstance(principal_hint, dict):
        principal = str(principal_hint.get("value") or "")
    principal = principal or str(task.subject or "")
    affected = [
        str(x.get("value") or "")
        for x in (hint.get("受影响资产") or [])
        if isinstance(x, dict) and str(x.get("value") or "").strip()
    ][:50]
    peers = [str(x) for x in (hint.get("对端") or [])][:50]
    role = str(hint.get("主体角色") or "unknown")

    dns_queries: dict[str, dict[str, Any]] = {}
    qtypes: Counter[str] = Counter()
    rcodes: Counter[str] = Counter()
    answers: set[str] = set()
    has_dns_facts = False
    # 聚合事实优先：不受 evidence 只保留 3 条样本的限制。
    for event in events:
        dns_facts = getattr(event, "dns_facts", None)
        if not isinstance(dns_facts, dict):
            continue
        if dns_facts.get("qtypes") or dns_facts.get("rcodes") or dns_facts.get("queries"):
            has_dns_facts = True
        qtypes.update({str(k): int(v) for k, v in (dns_facts.get("qtypes") or {}).items()})
        rcodes.update({str(k): int(v) for k, v in (dns_facts.get("rcodes") or {}).items()})
        for qname, count in (dns_facts.get("queries") or {}).items():
            item = dns_queries.setdefault(
                str(qname),
                {
                    "qname": str(qname),
                    "registrable_domain": domain_intel.registrable_domain(str(qname)),
                    "qtypes": Counter(),
                    "rcodes": Counter(),
                    "samples": 0,
                },
            )
            item["samples"] += int(count or 0)
    for event in events:
        for sample in event.evidence or []:
            if not isinstance(sample, dict):
                continue
            qname = suppression.dns_query_from_sample(sample)
            qtype = _qtype_of(sample)
            rcode = _rcode_of(sample)
            if qtype and not has_dns_facts:
                qtypes[qtype] += 1
            if rcode and not has_dns_facts:
                rcodes[rcode] += 1
            answers.update(_answers_of(sample))
            if not qname:
                continue
            existed = qname in dns_queries
            item = dns_queries.setdefault(
                qname,
                {
                    "qname": qname,
                    "registrable_domain": domain_intel.registrable_domain(qname),
                    "qtypes": Counter(),
                    "rcodes": Counter(),
                    "samples": 0,
                },
            )
            if not has_dns_facts or not existed:
                item["samples"] += 1
            if qtype and not has_dns_facts:
                item["qtypes"][qtype] += 1
            if rcode and not has_dns_facts:
                item["rcodes"][rcode] += 1

    dns_list: list[dict[str, Any]] = []
    for item in dns_queries.values():
        # 热路径不查外部 RDAP：facts 只带离线情报，智能体需要时再调 domain_intel。
        info = domain_intel.lookup_domain(item["qname"])
        dns_list.append(
            {
                **item,
                "qtypes": dict(item["qtypes"]),
                "rcodes": dict(item["rcodes"]),
                "domain_intel": info,
            }
        )
    domains = sorted({str(x["registrable_domain"]) for x in dns_list if x["registrable_domain"]})
    assets = _asset_map([principal, *affected, *peers])
    facts: dict[str, Any] = {
        "facts_version": _FACTS_VERSION,
        "task_id": str(task.id),
        "kind": str(task.kind or ""),
        "subject": str(task.subject or ""),
        "subject_kind": str(task.subject_kind or ""),
        "subject_role": role,
        "principal_asset": principal,
        "affected_assets": affected,
        "peers": peers,
        "direction": str(hint.get("方向") or ""),
        "assets": assets,
        "signals": {
            "rules": hint.get("规则") or [],
            "event_count": len(events),
            "event_ids": [str(ev.id) for ev in events[:50]],
            "source_kinds": sorted({str(ev.source_kind or "") for ev in events} - {""}),
        },
        "dns": {
            "queries": dns_list,
            "registrable_domains": domains,
            "qtypes": dict(qtypes),
            "rcodes": dict(rcodes),
            "answers": sorted(answers)[:50],
            "note": (
                "qtype/rcode/answers 来自命中事件样本；没有这些字段时不能据此判 DNS 隧道 TP"
            ),
        },
        "success": _success_state(events),
        "evidence": {
            "samples": sum(len(ev.evidence or []) for ev in events),
            "events_with_evidence": sum(1 for ev in events if ev.evidence),
            "status": "samples_only" if events else "missing",
            "note": "samples 是落库样例；完整原始文档仍需 raw_evidence/search_events 取证",
        },
        "history": _history(task, domains),
        "generated_at": datetime.now(UTC).isoformat(),
    }
    # facts_hash 用于复用/契约：只比较事实，不比较时间戳/展示文案。
    stable = {k: v for k, v in facts.items() if k not in ("generated_at", "history")}
    facts["facts_hash"] = hashlib.sha256(
        json.dumps(stable, ensure_ascii=False, sort_keys=True, default=str).encode()
    ).hexdigest()[:32]
    return facts
