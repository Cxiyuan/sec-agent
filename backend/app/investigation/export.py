"""取证成果导出：证据包 ZIP、取证报告生成与留档。

导出纪律：
- 原始证据**先脱敏再出包**（PG 里的 ``events.raw`` 在归一化时已脱敏；从 ES 取的文档
  在导出前过同一个 ``_sanitize_raw``，避免把 cookie/口令带出去）；
- 出包体积有界（原始证据条数上限 ``investigation_raw_evidence_max``），超出只导引用清单。
"""

from __future__ import annotations

import csv
import io
import json
import zipfile
from typing import Any

from sqlalchemy import select

from app.config import settings
from app.db.base import SessionLocal
from app.db.models import CaseReport
from app.investigation import pg_query
from app.reports.render import render_forensic_report
from app.workers.log import get_logger

log = get_logger(__name__)

_MAX_REPORTS_PER_CASE = 5


def _refs_of(investigation: dict[str, Any]) -> list[str]:
    """收集一份调查结果里出现的全部证据引用（顺序稳定、去重）。"""
    out: list[str] = []
    seen: set[str] = set()

    def add(value: Any) -> None:
        if isinstance(value, str) and value.startswith(("ev:", "es:")) and value not in seen:
            seen.add(value)
            out.append(value)
        elif isinstance(value, list):
            for item in value:
                add(item)

    for stage in investigation.get("path") or []:
        if isinstance(stage, dict):
            add(stage.get("evidence_refs"))
    for item in investigation.get("timeline") or []:
        if isinstance(item, dict):
            add(item.get("ref"))
    for key in ("lateral", "exfil", "iocs"):
        for item in investigation.get(key) or []:
            if isinstance(item, dict):
                add(item.get("evidence_refs"))
    return out


def _fetch_evidence(ref: str) -> dict[str, Any]:
    """取一条原始证据（已脱敏）。取不到时返回 {"ref":..., "error":...}。

    任何取数异常都降级成 error 字段：导出接口不能因为 DB/ES 抖动而 500。
    """
    if ref.startswith("ev:"):
        try:
            row = pg_query.event_by_id(ref)
        except Exception as exc:  # noqa: BLE001
            return {"ref": ref, "error": f"读取事件失败：{exc}"}
        if row is None:
            return {"ref": ref, "error": "事件不存在（可能已清理）"}
        return {"ref": ref, "kind": "event", **row}
    index_and_id = ref[3:]
    index, _, doc_id = index_and_id.partition("/")
    try:
        from app.ingestion.normalizer import _sanitize_raw
        from app.investigation.es_query import _es, query_timeout

        resp = _es().get(index=index, id=doc_id, request_timeout=query_timeout())
        return {
            "ref": ref,
            "kind": "es_doc",
            "index": index,
            "raw": _sanitize_raw(resp.get("_source") or {}),
        }
    except Exception as exc:  # noqa: BLE001
        return {"ref": ref, "error": f"读取失败：{exc}"}


def collect_evidence(
    investigation: dict[str, Any], *, with_raw: bool = True
) -> list[dict[str, Any]]:
    """按引用收集证据清单；``with_raw`` 为 False 时只出引用（不含原始文档）。"""
    refs = _refs_of(investigation)
    if not with_raw:
        return [{"ref": ref} for ref in refs]
    limit = max(1, settings.investigation_raw_evidence_max)
    rows = [_fetch_evidence(ref) for ref in refs[:limit]]
    rows.extend({"ref": ref, "note": "超出原始证据导出上限，仅列出引用"} for ref in refs[limit:])
    return rows


def _timeline_csv(investigation: dict[str, Any]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ts", "type", "src", "dst", "summary", "ref"])
    for item in investigation.get("timeline") or []:
        if isinstance(item, dict):
            writer.writerow(
                [
                    item.get("ts") or "",
                    item.get("type") or "",
                    item.get("src") or "",
                    item.get("dst") or "",
                    item.get("summary") or "",
                    item.get("ref") or "",
                ]
            )
    return buf.getvalue()


def _iocs_csv(investigation: dict[str, Any]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "value", "intel", "evidence_refs"])
    for item in investigation.get("iocs") or []:
        if isinstance(item, dict):
            writer.writerow(
                [
                    item.get("type") or "",
                    item.get("value") or "",
                    json.dumps(item.get("intel") or {}, ensure_ascii=False),
                    " ".join(item.get("evidence_refs") or []),
                ]
            )
    return buf.getvalue()


def build_evidence_zip(case: dict[str, Any], investigation: dict[str, Any]) -> bytes:
    """证据包 ZIP：manifest + evidence.jsonl + timeline.csv + iocs.csv。"""
    evidence = collect_evidence(investigation)
    manifest = {
        "tool": "深瞳 · 安全分析智能体",
        "kind": "attacker_case_evidence_pack",
        "version": 1,
        "case": {
            "id": case.get("id"),
            "attacker_key": case.get("attacker_key"),
            "title": case.get("title"),
            "severity": case.get("severity"),
            "status": case.get("status"),
            "keys": case.get("keys") or {},
            "src_ips": case.get("src_ips") or [],
            "dst_ips": case.get("dst_ips") or [],
            "first_seen": case.get("first_seen"),
            "last_seen": case.get("last_seen"),
            "group_count": case.get("group_count"),
            "event_count": case.get("event_count"),
        },
        "investigation": {
            "round": investigation.get("round"),
            "status": investigation.get("status"),
            "confidence": investigation.get("confidence"),
            "summary": investigation.get("summary"),
            "path_stages": [
                p.get("stage") for p in (investigation.get("path") or []) if isinstance(p, dict)
            ],
            "gaps": investigation.get("gaps") or [],
            "query_trail": investigation.get("query_trail") or [],
            "budget": investigation.get("budget") or {},
        },
        "evidence_count": len(evidence),
        "raw_evidence_limit": settings.investigation_raw_evidence_max,
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2, default=str)
        )
        zf.writestr(
            "evidence.jsonl",
            "\n".join(json.dumps(row, ensure_ascii=False, default=str) for row in evidence) + "\n",
        )
        zf.writestr("timeline.csv", _timeline_csv(investigation))
        zf.writestr("iocs.csv", _iocs_csv(investigation))
    return buf.getvalue()


def evidence_list(investigation: dict[str, Any]) -> dict[str, Any]:
    """证据清单（接口展示用，含原始文档）。"""
    rows = collect_evidence(investigation)
    return {"total": len(rows), "items": rows}


def generate_report(case_id: str, *, include_trail: bool = True) -> dict[str, Any]:
    """生成并留档取证报告（案件 + 最新调查结果）。"""
    from app.investigation import cases

    case = cases.get_case(case_id)
    if case is None:
        return {"ok": False, "error": "案件不存在"}
    investigation = case.get("investigation") or {}
    if not investigation:
        return {"ok": False, "error": "该案件还没有调查结果，先发起一次调查"}
    html, pdf_path = render_forensic_report(case, investigation, include_trail=include_trail)
    with SessionLocal() as db:
        row = CaseReport(
            case_id=case_id,
            title=f"攻击者取证报告 · {case.get('attacker_key') or case_id}",
            severity=str(case.get("severity") or "info"),
            html=html,
            pdf_path=pdf_path,
        )
        db.add(row)
        db.flush()
        report_id = row.id
        # 只保留最近 N 份（避免报告表无限膨胀）
        old = db.scalars(
            select(CaseReport)
            .where(CaseReport.case_id == case_id)
            .order_by(CaseReport.created_at.desc())
        ).all()
        for extra in old[_MAX_REPORTS_PER_CASE:]:
            db.delete(extra)
        db.commit()
    return {
        "ok": True,
        "report_id": report_id,
        "has_pdf": bool(pdf_path),
        "pdf_path": pdf_path,
        "html_chars": len(html),
    }


def latest_report(case_id: str) -> dict[str, Any] | None:
    with SessionLocal() as db:
        row = db.scalars(
            select(CaseReport)
            .where(CaseReport.case_id == case_id)
            .order_by(CaseReport.created_at.desc())
        ).first()
        if row is None:
            return None
        return {
            "id": row.id,
            "case_id": row.case_id,
            "title": row.title,
            "severity": row.severity,
            "pdf_path": row.pdf_path,
            "has_pdf": bool(row.pdf_path),
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }


def report_html(report_id: str) -> str | None:
    with SessionLocal() as db:
        row = db.get(CaseReport, report_id)
        return row.html if row is not None else None
