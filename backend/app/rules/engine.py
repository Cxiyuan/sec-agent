"""规则引擎：评估结构化条件规则。

规则结构（存 Postgres JSON 字段 conditions）:
{
    "logic": "and" | "or",
    "rules": [
        {"field": "event_type", "op": "eq", "value": "port_scan"},
        {"field": "dst_port", "op": "gt", "value": 1000},
        {"logic": "or", "rules": [...]}   # 支持嵌套
    ]
}

操作符: eq / ne / contains / regex / gt / gte / lt / lte / in / exists
"""

from __future__ import annotations

import re
from typing import Any

from app.schemas import UnifiedLog


def _get_field(log: UnifiedLog, field: str) -> Any:
    return getattr(log, field, None)


def _match(cond: dict[str, Any], log: UnifiedLog) -> bool:
    field = cond.get("field")
    op = cond.get("op", "eq")
    expected = cond.get("value")
    actual = _get_field(log, field) if field else None

    if op == "exists":
        return actual is not None
    if op == "eq":
        return actual == expected
    if op == "ne":
        return actual != expected
    if op == "contains":
        return actual is not None and str(expected) in str(actual)
    if op == "regex":
        try:
            return bool(re.search(str(expected), str(actual or "")))
        except re.error:
            return False
    if op in ("gt", "gte", "lt", "lte"):
        try:
            a, b = float(actual), float(expected)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return False
        return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[op]
    if op == "in":
        return actual in (expected if isinstance(expected, (list, tuple, set)) else [expected])
    return False


def evaluate_conditions(conditions: dict[str, Any], log: UnifiedLog) -> bool:
    """递归评估条件树。空条件视为命中。"""
    if not conditions:
        return True
    logic = (conditions.get("logic") or "and").lower()
    rules = conditions.get("rules") or []
    if not rules:
        return True

    results = []
    for r in rules:
        if "rules" in r:  # 嵌套组
            results.append(evaluate_conditions(r, log))
        else:
            results.append(_match(r, log))

    if logic == "or":
        return any(results)
    return all(results)


def match_rule(rule: dict[str, Any], log: UnifiedLog) -> bool:
    """rule 为 {name, conditions, severity, source, ...} 的字典。"""
    return evaluate_conditions(rule.get("conditions") or {}, log)
