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


def _render_html(group: Any, analysis: dict[str, Any], body: str = "") -> str:
    template = _env.get_template("report.html")
    return template.render(
        title="安全事件报告",
        severity=(group.severity or "info").upper(),
        src_ips=group.src_ips,
        dst_ips=group.dst_ips,
        window_start=group.window_start.isoformat(),
        window_end=group.window_end.isoformat(),
        event_count=group.event_count,
        triage_score=round(group.triage_score, 3),
        attack_chain=(analysis.get("attack_chain") or {}).get("stages", []),
        chain_summary=(analysis.get("attack_chain") or {}).get("summary", ""),
        profile=analysis.get("profile") or {},
        anomaly=(analysis.get("anomaly") or {}).get("findings", []),
        suggestions=group.response_suggestions or [],
        business_context=group.business_context or {},
        body=body,
    )


def render_report(
    group: Any, analysis: dict[str, Any], body: str = ""
) -> tuple[str, str | None]:
    """渲染报告 HTML 并生成 PDF，返回 (html, pdf_path)。PDF 失败时返回 (html, None)。"""
    html = _render_html(group, analysis, body)
    try:
        from weasyprint import HTML  # type: ignore[import-not-found]

        os.makedirs(settings.report_storage_dir, exist_ok=True)
        pdf_path = os.path.join(
            settings.report_storage_dir, f"{group.fingerprint}_{uuid.uuid4().hex[:8]}.pdf"
        )
        HTML(string=html).write_pdf(pdf_path)
        return html, pdf_path
    except Exception:  # noqa: BLE001
        # WeasyPrint 依赖系统库，失败时降级为仅 HTML
        return html, None
