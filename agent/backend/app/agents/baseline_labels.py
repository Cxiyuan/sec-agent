"""NDR 摘要上的基线标签（第 8 期：基线的计算在 NDR 侧，这里只做提取与渲染）。

NDR 检测器给每条摘要打一个 `baseline` 字段::

    {"checked": 3, "warmed": 2,
     "numeric": [{"feature": "conn_count", "src_ip": "10.0.0.5",
                  "value": 120, "mean": 12.4, "std": 3.1, "z": 34.7}],
     "profiles": [{"kind": "account", "key": "ab12…", "display": "alice",
                   "risk": 0.95, "reasons": ["新源 IP"], "obs_count": 41,
                   "src_ips": ["10.0.0.5"], "count": 7}]}

智能体侧只做三件事：按组把标签合并起来（写进 `EventGroup.aggregate`，驾驶舱展示用）、
把数值偏离转成「异常确认」候选（判定仍由模型下）、渲染成提示词里的文本块。

**判定不在这一层**：`numeric` 只包含 NDR 侧已超过 zσ 的维度，`profiles` 只包含
NDR 侧已过风险阈值的实体。这里既不重算标准差，也不加权重。
"""

from __future__ import annotations

from typing import Any

# 单组最多送几个候选去让模型确认（原来也是 10）
MAX_CANDIDATES = 10
# 提示词文本里最多列几条画像异常
MAX_TEXT_ENTITIES = 6


def labels_of(digest: dict[str, Any]) -> dict[str, Any]:
    """取一条摘要上的基线标签（没有就返回空字典）。"""
    raw = digest.get("baseline")
    return raw if isinstance(raw, dict) else {}


def merge_labels(items: list[Any]) -> dict[str, Any]:
    """把同一组的若干摘要标签合并成一份（偏离按维度去重、画像按实体去重）。

    返回空字典表示这一组没有任何基线标签 —— 调用方据此不往聚合里塞空字段
    （历史数据与关掉基线时都不该多一个 `baseline` 键）。
    """
    numeric: dict[str, dict[str, Any]] = {}
    profiles: dict[str, dict[str, Any]] = {}
    checked = 0
    warmed = 0
    for item in items:
        if not isinstance(item, dict) or not item:
            continue
        checked = max(checked, _safe_int(item.get("checked")))
        warmed = max(warmed, _safe_int(item.get("warmed")))
        for dev in item.get("numeric") or []:
            if isinstance(dev, dict):
                numeric[f"{dev.get('src_ip')}:{dev.get('feature')}"] = dev
        for prof in item.get("profiles") or []:
            if isinstance(prof, dict):
                profiles[f"{prof.get('kind')}|{prof.get('key')}"] = prof
    if not numeric and not profiles and not checked:
        return {}
    out: dict[str, Any] = {"checked": checked, "warmed": warmed}
    if numeric:
        # 偏离大的排前面（模型只确认前 MAX_CANDIDATES 个）
        out["numeric"] = sorted(
            numeric.values(), key=lambda d: abs(_safe_float(d.get("z"))), reverse=True
        )
    if profiles:
        out["profiles"] = sorted(
            profiles.values(), key=lambda p: _safe_float(p.get("risk")), reverse=True
        )
    return out


def candidates_of(info: dict[str, Any] | None) -> list[dict[str, Any]]:
    """数值偏离 → 「异常确认」候选（键名与旧 `_stat_features` 一致，提示词无需改）。"""
    out: list[dict[str, Any]] = []
    for dev in (info or {}).get("numeric") or []:
        if not isinstance(dev, dict):
            continue
        src = str(dev.get("src_ip") or "")
        feature = str(dev.get("feature") or "")
        out.append(
            {
                "key": f"{src}:{feature}",
                "value": dev.get("value"),
                "mean": dev.get("mean"),
                "std": dev.get("std"),
                "z": dev.get("z"),
            }
        )
        if len(out) >= MAX_CANDIDATES:
            break
    return out


def entities_of(info: dict[str, Any] | None) -> list[dict[str, Any]]:
    """画像异常实体（NDR 侧已过阈值）。"""
    return [p for p in (info or {}).get("profiles") or [] if isinstance(p, dict)]


def text_of(info: dict[str, Any] | None) -> str:
    """渲染成提示词文本块（原来 `profile_text` 的位置）。"""
    info = info or {}
    entities = entities_of(info)
    numeric = [d for d in info.get("numeric") or [] if isinstance(d, dict)]
    lines: list[str] = []
    if entities:
        lines.append("账号/会话画像异常（跨窗口长期基线，NDR 侧判定）：")
        for entity in entities[:MAX_TEXT_ENTITIES]:
            kind = "账号" if entity.get("kind") == "account" else "会话"
            lines.append(
                f"- [{kind}] {entity.get('display') or entity.get('key')} 风险 {entity.get('risk')}："
                + "；".join(str(r) for r in entity.get("reasons") or [])
            )
    else:
        lines.append("（无账号/会话画像异常）")
    if numeric:
        lines.append("数值偏离长期基线（NDR 侧 2σ 打标，待定性）：")
        for dev in numeric[:MAX_CANDIDATES]:
            z = dev.get("z")
            lines.append(
                f"- {dev.get('src_ip')} 的 {dev.get('feature')} 当前 {dev.get('value')}"
                f"（长期均值 {dev.get('mean')}，标准差 {dev.get('std')}"
                + (f"，{z}σ）" if z is not None else "）")
            )
    if not _safe_int(info.get("warmed")):
        lines.append("（基线仍在观测期，未报偏离不代表正常）")
    return "\n".join(lines)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError, OverflowError):
        return default
