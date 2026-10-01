"""报告渲染：Jinja2 模板 + WeasyPrint 生成 PDF。"""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from app.config import settings

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True)


def _render_html(
    group: Any,
    analysis: dict[str, Any],
    body: str = "",
    *,
    event_count: int = 0,
    suggestions: list[dict[str, Any]] | None = None,
) -> str:
    template = _env.get_template("report.html")
    return template.render(
        title="安全事件报告",
        severity=(group.severity or "info").upper(),
        src_ips=group.src_ips,
        dst_ips=group.dst_ips,
        window_start=group.window_start.isoformat(),
        window_end=group.window_end.isoformat(),
        event_count=event_count,
        triage_score=round(group.triage_score, 3),
        attack_chain=(analysis.get("attack_chain") or {}).get("stages", []),
        chain_summary=(analysis.get("attack_chain") or {}).get("summary", ""),
        profile=analysis.get("profile") or {},
        anomaly=(analysis.get("anomaly") or {}).get("findings", []),
        suggestions=suggestions or [],
        business_context=group.business_context or {},
        body=body,
    )


def render_report(
    group: Any,
    analysis: dict[str, Any],
    body: str = "",
    *,
    event_count: int | None = None,
    suggestions: list[dict[str, Any]] | None = None,
) -> tuple[str, str | None]:
    """渲染组报告 HTML 并尽力生成 PDF，返回 (html, pdf_path)。

    为什么要把 ``event_count`` 与 ``suggestions`` 做成显式参数：
    图状态里传递的是 ``schemas.EventGroup``（pydantic），它**没有** event_count、
    也没有 response_suggestions——这两个字段只存在于数据库行上。直接 getattr 会
    AttributeError，结果就是**报告一直生成不出来**（只是在日志里报一句警告，很容易漏掉）。
    两者都给了兼容回退：不传时优先读对象属性，再退到 events 长度。
    """
    if event_count is None:
        declared = getattr(group, "event_count", None)
        event_count = (
            int(declared) if declared is not None else len(getattr(group, "events", []) or [])
        )
    if suggestions is None:
        suggestions = getattr(group, "response_suggestions", None) or []
    html = _render_html(group, analysis, body, event_count=event_count, suggestions=suggestions)
    return html, _write_pdf(html, f"{group.fingerprint}_{uuid.uuid4().hex[:8]}")


def _write_pdf(html: str, name: str) -> str | None:
    """HTML → PDF；WeasyPrint 依赖系统库，失败时降级为仅 HTML（返回 None）。"""
    try:
        from weasyprint import HTML  # type: ignore[import-not-found]

        os.makedirs(settings.report_storage_dir, exist_ok=True)
        pdf_path = os.path.join(settings.report_storage_dir, f"{name}.pdf")
        HTML(string=html).write_pdf(pdf_path)
        return pdf_path
    except Exception:  # noqa: BLE001
        return None


def render_forensic_report(
    case: dict[str, Any],
    investigation: dict[str, Any],
    *,
    include_trail: bool = True,
) -> tuple[str, str | None]:
    """渲染案件取证报告（完整路径 + 证据引用 + 缺口 + 查询轨迹附录）。

    ``investigation`` 是调查结果超集（与 ``event_groups.attack_chain`` 同结构），
    因此本函数对“轮次结果”与“案件最新结果”都适用。
    """
    keys = case.get("keys") or {}
    keys_text = "；".join(
        f"{k}: {', '.join(str(v) for v in vals[:5])}" for k, vals in keys.items() if vals
    )
    template = _env.get_template("forensic_report.html")
    html = template.render(
        severity=str(case.get("severity") or "info").upper(),
        severity_cls=str(case.get("severity") or "info").lower(),
        status=investigation.get("status") or case.get("status") or "-",
        confidence=investigation.get("confidence", 0.0),
        attacker_key=case.get("attacker_key") or "-",
        title=case.get("title") or "攻击者案件",
        keys_text=keys_text,
        keys=keys,
        src_ips=case.get("src_ips") or [],
        dst_ips=case.get("dst_ips") or [],
        first_seen=case.get("first_seen"),
        last_seen=case.get("last_seen"),
        group_count=case.get("group_count") or 0,
        event_count=case.get("event_count") or 0,
        round_no=investigation.get("round") or 0,
        rounds_total=case.get("rounds_total") or 0,
        inv_status=investigation.get("status") or "-",
        summary=investigation.get("summary") or "",
        path=investigation.get("path") or [],
        timeline=investigation.get("timeline") or [],
        lateral=investigation.get("lateral") or [],
        exfil=investigation.get("exfil") or [],
        iocs=investigation.get("iocs") or [],
        assets_impacted=investigation.get("assets_impacted") or [],
        attacker=investigation.get("attacker") or {},
        gaps=investigation.get("gaps") or [],
        dropped=investigation.get("dropped") or [],
        query_trail=investigation.get("query_trail") or [],
        budget=investigation.get("budget") or {},
        include_trail=include_trail,
    )
    return html, _write_pdf(html, f"case_{case.get('id')}_{uuid.uuid4().hex[:8]}")
