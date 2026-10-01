"""业务背景：检索 + 渲染成给 LLM 的文本块。"""

from __future__ import annotations

from typing import Any

from app.rag.retriever import retrieve

NO_CONTEXT = "（无相关资产信息）"


def build_business_context(
    src_ips: list[str], dst_ips: list[str], query_text: str
) -> dict[str, Any]:
    """检索并渲染业务背景，返回含 text 字段的字典。"""
    ctx = retrieve(src_ips, dst_ips, query_text)
    ctx["text"] = render_text(ctx)
    return ctx


def render_text(ctx: dict[str, Any]) -> str:
    """把命中的资产、拓扑与知识片段渲染成提示词文本块。"""
    assets = ctx.get("assets") or []
    knowledge = ctx.get("knowledge") or []
    topology = ctx.get("topology") or []
    if not assets and not knowledge and not topology:
        return NO_CONTEXT

    lines: list[str] = []
    if assets:
        lines.append("【相关资产】")
        for a in assets:
            bits = [f"IP {a['ip']}"]
            if a.get("asset_name") or a.get("hostname"):
                bits.append(f"名称 {a.get('asset_name') or a.get('hostname')}")
            for label, key in [
                ("业务系统", "business_system"),
                ("重要级别", "importance"),
                ("资产类型", "asset_type"),
                ("网络区域", "network_zone"),
                ("负责人", "owner"),
            ]:
                if a.get(key):
                    bits.append(f"{label} {a[key]}")
            if a.get("description"):
                bits.append(f"描述 {a['description']}")
            lines.append("- " + "，".join(bits))
    if topology:
        lines.extend(_render_topology(topology, assets))
    if knowledge:
        lines.append("【相关知识】")
        for k in knowledge:
            lines.append(f"- {str(k['content'])[:300]}")
    return "\n".join(lines)


def _render_topology(topology: list[dict[str, Any]], assets: list[dict[str, Any]]) -> list[str]:
    """渲染拓扑局部视图（命中节点用 ★ 标注）。"""
    asset_map = {a["id"]: a for a in assets}
    out: list[str] = ["【网络拓扑】"]
    for t in topology:
        out.append(f"- 拓扑「{t.get('topology_name')}」中与本次事件相关的设备及上下游：")
        hit = set(t.get("hit_nodes") or [])
        label_of: dict[str, str] = {}
        for n in t.get("nodes") or []:
            data = n.get("data") or {}
            nid = str(n.get("id"))
            label = str(data.get("label") or nid)
            label_of[nid] = label
            bits = [f"{'★' if nid in hit else ''}{label}"]
            if data.get("zone"):
                bits.append(f"区域 {data['zone']}")
            for aid in data.get("asset_ids") or []:
                a = asset_map.get(str(aid))
                if a:
                    bits.append(
                        f"资产 {a.get('ip')} {a.get('business_system') or a.get('asset_name') or ''}".strip()
                    )
            if data.get("note"):
                bits.append(f"备注 {data['note']}")
            out.append("  - " + "，".join(bits))
        links = []
        for e in t.get("edges") or []:
            src = label_of.get(str(e.get("source")), str(e.get("source")))
            dst = label_of.get(str(e.get("target")), str(e.get("target")))
            links.append(f"{src}↔{dst}" + (f"（{e['label']}）" if e.get("label") else ""))
        if links:
            out.append("  - 连接：" + "，".join(links))
    return out


def context_text_for_group(group: Any, business_context: dict[str, Any] | None) -> str:
    """取某事件组的业务背景文本，缺失时返回占位。"""
    if not business_context:
        return NO_CONTEXT
    return str(business_context.get("text") or NO_CONTEXT)
