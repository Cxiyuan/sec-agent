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

频率规则（窗口内聚合）：conditions 里带 {"mode": "count", "key": [字段...], "min_count": N}
- 逐条规则：mode 缺省（single）
- 频率规则：mode=count，在 triage 中对整个窗口做分组计数
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
    """逐条规则匹配。

    - 频率规则（mode=count）不参与，返回 False
    - **空条件规则不匹配任何日志**（安全默认：避免空规则全量命中淹没管线）
    """
    conditions = rule.get("conditions") or {}
    if conditions.get("mode") == "count":
        return False
    if not conditions.get("rules"):
        return False
    return evaluate_conditions(conditions, log)


def is_count_rule(rule: dict[str, Any]) -> bool:
    return (rule.get("conditions") or {}).get("mode") == "count"


def has_conditions(rule: dict[str, Any]) -> bool:
    """规则是否含有效条件（供 API 保存校验）。"""
    return bool((rule.get("conditions") or {}).get("rules"))


def validate_rule_regexes(rule: dict[str, Any]) -> list[str]:
    """校验规则里的 regex 是否可编译。

    非法正则在运行期会被静默吞掉（_match 捕获 re.error 返回 False），
    导致规则「看着在、实际永不命中」——启动时自检可避免这种静默死规则。
    """
    errors: list[str] = []

    def walk(conds: dict[str, Any]) -> None:
        for r in conds.get("rules") or []:
            if not isinstance(r, dict):
                continue
            if "rules" in r:
                walk(r)
                continue
            if r.get("op") == "regex":
                try:
                    re.compile(str(r.get("value", "")))
                except re.error as exc:
                    errors.append(f"字段 {r.get('field')} 的正则非法：{exc}")

    walk(rule.get("conditions") or {})
    return errors


def count_key(log: UnifiedLog, fields: list[str]) -> str:
    return "|".join(str(getattr(log, f, "") or "") for f in fields)


def match_count_rule(
    rule: dict[str, Any], logs: list[UnifiedLog]
) -> list[tuple[str, list[UnifiedLog]]]:
    """频率规则：按 key 分组统计命中条数，返回达到 min_count 的分组。"""
    conditions = rule.get("conditions") or {}
    if not conditions.get("rules"):
        return []
    keys = conditions.get("key")
    if not isinstance(keys, list) or not keys:
        keys = ["src_ip"]
    try:
        min_count = int(conditions.get("min_count") or 1)
    except (TypeError, ValueError):
        min_count = 1

    buckets: dict[str, list[UnifiedLog]] = {}
    for log in logs:
        if not evaluate_conditions(conditions, log):
            continue
        buckets.setdefault(count_key(log, [str(k) for k in keys]), []).append(log)
    return [(k, v) for k, v in buckets.items() if len(v) >= min_count]
