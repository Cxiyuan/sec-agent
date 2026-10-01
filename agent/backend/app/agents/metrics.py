"""聚合规模合并（实时链路）：把摘要/事件的聚合信息逐层合并成组级规模。

统一形状：{hits, rules, dst_ips(≤50), dst_ports(≤50), first_seen, last_seen}

第 8 期起还带一个可选的 `baseline`（NDR 在摘要上打的基线标签）：数值偏离按维度去重、
画像异常按实体去重，合并结果供驾驶舱展示与深度分析的提示词使用 —— 判定在 NDR 侧算完，
这里只做合并与搬运。

放在独立模块：nodes（组内合并）与 persistence（入库时与旧行合并）都要用，
而 persistence 被 nodes 依赖，写在其中一处会造成循环导入。
"""

from __future__ import annotations

from typing import Any

from app.agents.baseline_labels import merge_labels

_MAX_SET = 50


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _str_list(value: Any) -> list[str]:
    return [str(x) for x in value if x is not None] if isinstance(value, list) else []


def merge_aggregates(items: list[Any]) -> dict[str, Any]:
    """合并多份聚合规模；空输入返回 {}。"""
    valid = [it for it in items if isinstance(it, dict) and it]
    if not valid:
        return {}
    hits = 0
    dst: set[str] = set()
    ports: set[str] = set()
    rules: dict[str, int] = {}
    first_seen: str | None = None
    last_seen: str | None = None

    for it in valid:
        hits += _safe_int(it.get("hits"))
        dst.update(_str_list(it.get("dst_ips")))
        ports.update(_str_list(it.get("dst_ports")))
        # 脏数据保护：rules 不是 dict 时跳过（否则 .items() 抛错会拖塌整个节点）
        raw_rules = it.get("rules")
        if isinstance(raw_rules, dict):
            for rule, cnt in raw_rules.items():
                rules[str(rule)] = rules.get(str(rule), 0) + _safe_int(cnt)
        fs = str(it.get("first_seen") or "")
        ls = str(it.get("last_seen") or "")
        if fs and (first_seen is None or fs < first_seen):
            first_seen = fs
        if ls and (last_seen is None or ls > last_seen):
            last_seen = ls

    merged: dict[str, Any] = {
        "hits": hits,
        "rules": rules,
        "dst_ips": sorted(dst)[:_MAX_SET],
        "dst_ports": sorted(ports, key=lambda x: (_safe_int(x), x))[:_MAX_SET],
        "first_seen": first_seen,
        "last_seen": last_seen,
    }
    # 基线标签（可选）：整批都没有就一个键都不加，历史数据与关掉基线时形状不变
    baseline = merge_labels([it.get("baseline") for it in valid])
    if baseline:
        merged["baseline"] = baseline
    return merged
