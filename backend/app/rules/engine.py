"""规则引擎：评估结构化条件规则。

规则结构（存 Postgres JSON 字段 conditions）:
{
    "mode": "count",              # 缺省=逐条；count=窗口内频率规则
    "key": ["src_ip", "dst_ip"],  # 频率规则分组字段
    "min_count": 30,              # 频率规则最少次数
    "distinct": "user",           # 频率规则：去重统计字段（可选）
    "min_distinct": 5,            # 去重后最少个数（可选）
    "logic": "and" | "or",
    "rules": [
        {"field": "event_type", "op": "eq", "value": "http_login"},
        {"not": {"field": "uri_path", "op": "contains", "value": "/health"}},
        {"logic": "or", "rules": [...]}   # 支持嵌套
    ],
    "whitelist": [ {"field": "src_ip", "op": "in", "value": ["10.0.0.9"]} ]  # 命中即放过
}

操作符: eq / ne / contains / regex / gt / gte / lt / lte / in / exists

虚拟字段（不是日志字段，由引擎计算）：``src_internal`` / ``dst_internal`` / ``src_external`` /
``dst_external`` —— **内外网方向**。用于“内外有别”的规则与排除过滤，
避免把某个客户的网段写死进规则（例：内网巡检的扫摸不该当攻击）。
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote, unquote_plus

from app.schemas import UnifiedLog
from app.tools.context import is_public_ip

# 对这些字段做 contains/regex 时，额外匹配 URL 解码后的文本
# （攻击者常对 payload 做 URL 编码，只匹配原文会漏报）
_DECODE_FIELDS = {"query", "query_string", "uri_path", "body", "referer", "filename"}


def _is_internal(ip: Any) -> bool:
    """是否内网地址（非公网）。地址缺失返回 False（不把脏数据当内网放行）。"""
    value = str(ip or "").strip()
    if not value:
        return False
    return not is_public_ip(value)


# **内外网方向虚拟字段**。
#
# 为什么做成字段：规则与排除过滤经常需要“内外有别”，但**哪个网段算内网是环境相关的**
# —— 不能在规则里写死 “src_ip contains 172.16.”（那样产品就绑死在某个客户环境了）。
# 统一用“是否公网”判定，与情报工具、界面里的内外网口径一致。
VIRTUAL_FIELDS: dict[str, Any] = {
    "src_internal": lambda log: _is_internal(log.src_ip),
    "dst_internal": lambda log: _is_internal(log.dst_ip),
    "src_external": lambda log: is_public_ip(str(log.src_ip or "")),
    "dst_external": lambda log: is_public_ip(str(log.dst_ip or "")),
}


def _get_field(log: UnifiedLog, field: str, extra: dict[str, Any] | None = None) -> Any:
    """取字段值：extra（排除过滤的规则元数据）→ 虚拟字段（内外网方向）→ 日志字段。"""
    if extra and field in extra:
        return extra[field]
    getter = VIRTUAL_FIELDS.get(field)
    if getter is not None:
        return getter(log)
    return getattr(log, field, None)


def _text_candidates(log: UnifiedLog, field: str, extra: dict[str, Any] | None = None) -> list[str]:
    """返回待匹配文本：原文 + URL 解码变体（用于 contains/regex）。"""
    actual = _get_field(log, field, extra)
    if actual is None:
        return []
    text = str(actual)
    if not text:
        return []
    texts = [text]
    if field in _DECODE_FIELDS and ("%" in text or "+" in text):
        # urllib 的 unquote/unquote_plus 对畸形输入宽容，不会抛异常
        for decode in (unquote, unquote_plus):
            decoded = decode(text)
            if decoded and decoded not in texts:
                texts.append(decoded)
    return texts


def _match(cond: dict[str, Any], log: UnifiedLog, extra: dict[str, Any] | None = None) -> bool:
    field = cond.get("field")
    op = cond.get("op", "eq")
    expected = cond.get("value")
    actual = _get_field(log, field, extra) if field else None

    if op == "exists":
        # 非空才算存在（空字符串不应视为存在，否则 JA3/MITRE 等规则会全量误报）
        return actual is not None and str(actual).strip() != ""
    if op == "eq":
        return actual == expected
    if op == "ne":
        return actual != expected
    if op == "contains":
        return any(str(expected) in text for text in _text_candidates(log, str(field or ""), extra))
    if op == "regex":
        try:
            pattern = re.compile(str(expected))
        except re.error:
            return False
        return any(pattern.search(text) for text in _text_candidates(log, str(field or ""), extra))
    if op in ("gt", "gte", "lt", "lte"):
        try:
            a, b = float(actual), float(expected)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return False
        return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[op]
    if op == "in":
        return actual in (expected if isinstance(expected, (list, tuple, set)) else [expected])
    return False


def _eval_node(node: Any, log: UnifiedLog, extra: dict[str, Any] | None = None) -> bool:
    """评估单个节点：支持 not 取反 / 嵌套组 / 单条件。"""
    if not isinstance(node, dict):
        return False
    if "not" in node:
        inner = node["not"]
        if isinstance(inner, dict) and "rules" in inner:
            return not evaluate_conditions(inner, log, extra)
        return not _match(inner if isinstance(inner, dict) else {}, log, extra)
    if "rules" in node:
        return evaluate_conditions(node, log, extra)
    return _match(node, log, extra)


def evaluate_conditions(
    conditions: dict[str, Any], log: UnifiedLog, extra: dict[str, Any] | None = None
) -> bool:
    """递归评估条件树。空条件视为命中（嵌套组用；顶级规则不适用）。

    extra：额外的虚拟字段（排除过滤用来注入命中规则元数据：hit_rule/rule_source/rule_severity）。
    默认 None，对规则匹配完全无影响。
    """
    if not conditions:
        return True
    logic = (conditions.get("logic") or "and").lower()
    rules = conditions.get("rules") or []
    if not rules:
        return True

    results = [_eval_node(r, log, extra) for r in rules]
    if logic == "or":
        return any(results)
    return all(results)


def whitelisted(
    conditions: dict[str, Any], log: UnifiedLog, extra: dict[str, Any] | None = None
) -> bool:
    """规则级白名单：命中任一白名单条件 → 该规则对该日志放过。"""
    whitelist = conditions.get("whitelist")
    if not whitelist:
        return False
    if isinstance(whitelist, list):
        return any(_eval_node(item, log, extra) for item in whitelist)
    if isinstance(whitelist, dict):
        return evaluate_conditions(whitelist, log, extra)
    return False


def match_rule(rule: dict[str, Any], log: UnifiedLog) -> bool:
    """规则是否命中；优先用加载时预编译的闭包（失败则回退解释执行）。"""
    compiled = rule.get("_compiled")
    if compiled is not None:
        extra = {
            "hit_rule": str(rule.get("name") or ""),
            "rule_source": str(rule.get("source") or ""),
            "rule_severity": str(rule.get("severity") or ""),
        }
        try:
            return bool(compiled(log, extra))
        except Exception as exc:  # noqa: BLE001
            log.debug("预编译判定失败，回退解释执行: %s", exc)
    return _match_rule_interpreted(rule, log)


def _match_rule_interpreted(rule: dict[str, Any], log: UnifiedLog) -> bool:
    """原解释执行实现（预编译不可用时的回退，语义与之前完全一致）。"""
        """逐条规则匹配。

        - 频率规则（mode=count）不参与，返回 False
        - **空条件规则不匹配任何日志**（安全默认：避免空规则全量命中淹没管线）
        - 命中白名单则放过
        """
        conditions = rule.get("conditions") or {}
        if conditions.get("mode") == "count":
            return False
        if not conditions.get("rules"):
            return False
        if whitelisted(conditions, log):
            return False
        return evaluate_conditions(conditions, log)


def is_count_rule(rule: dict[str, Any]) -> bool:
    return (rule.get("conditions") or {}).get("mode") == "count"


def has_conditions(rule: dict[str, Any]) -> bool:
    """规则是否含有效条件（供 API 保存校验）。"""
    return bool((rule.get("conditions") or {}).get("rules"))


def count_key(log: UnifiedLog, fields: list[str]) -> str:
    return "|".join(str(getattr(log, f, "") or "") for f in fields)


def match_count_rule(
    rule: dict[str, Any], logs: list[UnifiedLog]
) -> list[tuple[str, list[UnifiedLog]]]:
    """频率规则：按 key 分组统计命中条数（可选 distinct 去重），返回达标分组。"""
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

    distinct_field = str(conditions.get("distinct") or "")
    try:
        min_distinct = int(conditions.get("min_distinct") or 0)
    except (TypeError, ValueError):
        min_distinct = 0

    buckets: dict[str, list[UnifiedLog]] = {}
    for log in logs:
        if whitelisted(conditions, log):
            continue
        if not evaluate_conditions(conditions, log):
            continue
        buckets.setdefault(count_key(log, [str(k) for k in keys]), []).append(log)

    hits: list[tuple[str, list[UnifiedLog]]] = []
    for key, matched in buckets.items():
        if len(matched) < min_count:
            continue
        if distinct_field and min_distinct > 0:
            values = {str(getattr(m, distinct_field, "") or "") for m in matched}
            values.discard("")
            if len(values) < min_distinct:
                continue
        hits.append((key, matched))
    return hits


def validate_rule_regexes(rule: dict[str, Any]) -> list[str]:
    """校验规则里的 regex 是否可编译（含白名单）。

    非法正则在运行期会被静默吞掉（_match 捕获 re.error 返回 False），
    导致规则「看着在、实际永不命中」——启动时自检可避免这种静默死规则。
    """
    errors: list[str] = []

    def walk(conds: Any) -> None:
        if isinstance(conds, list):
            for item in conds:
                walk(item)
            return
        if not isinstance(conds, dict):
            return
        if "not" in conds:
            walk(conds["not"])
        for r in conds.get("rules") or []:
            if not isinstance(r, dict):
                continue
            if "rules" in r or "not" in r:
                walk(r)
                continue
            if r.get("op") == "regex":
                try:
                    re.compile(str(r.get("value", "")))
                except re.error as exc:
                    errors.append(f"字段 {r.get('field')} 的正则非法：{exc}")

    conditions = rule.get("conditions") or {}
    walk({"rules": conditions.get("rules") or []})
    walk(
        {
            "rules": conditions.get("whitelist")
            if isinstance(conditions.get("whitelist"), list)
            else []
        }
    )
    return errors


# ---------- log_type 规则路由（提速：只跑命中概率非零的规则） ----------

# 字段 → 日志类型 的归属表：规则引用了某类型的专有字段，就只挂到该类型。
# 任何"归属不明 / 只引用通用字段"的规则一律进通配集合（每次都会跑）——fail-open，宁可多跑不漏。
_FIELD_TYPES: dict[str, tuple[str, ...]] = {
    # http
    "uri": ("http",),
    "uri_path": ("http",),
    "method": ("http",),
    "status_code": ("http",),
    "user_agent": ("http",),
    "host": ("http",),
    "referrer": ("http",),
    "body": ("http",),
    "request_body_len": ("http",),
    "response_body_len": ("http",),
    # dns
    "query": ("dns",),
    "rcode": ("dns",),
    "qtype": ("dns",),
    "answers": ("dns",),
    # conn
    "conn_state": ("conn",),
    "duration": ("conn",),
    "orig_bytes": ("conn",),
    "resp_bytes": ("conn",),
    "bytes_out": ("conn",),
    "bytes_in": ("conn",),
    "proto": ("conn",),
    "service": ("conn",),
    # files
    "mime_type": ("files",),
    "filename": ("files",),
    "fuid": ("files",),
    "seen_bytes": ("files",),
    # ssl
    "server_name": ("ssl",),
    "ja3": ("ssl",),
    "ja3s": ("ssl",),
    "issuer": ("ssl",),
}
_COMMON_FIELDS = {
    "src_ip",
    "dst_ip",
    "dst_port",
    "src_port",
    "event_type",
    "severity",
    "source_system",
    "log_type",
    "ts",
    "summary",
    "rule",
    "hit_rule",
    "src_internal",
    "dst_internal",
    "src_external",
    "dst_external",
    "event_count",
}


def _rule_fields(cond: Any, out: set[str]) -> None:
    """递归收集规则引用的字段名。"""
    if isinstance(cond, dict):
        field = cond.get("field")
        if isinstance(field, str):
            out.add(field)
        for value in cond.values():
            _rule_fields(value, out)
    elif isinstance(cond, list):
        for item in cond:
            _rule_fields(item, out)


def build_rule_index(rules: list[dict[str, Any]]) -> dict[str, Any]:
    """把逐条规则按 log_type 建索引：{types: {log_type: [规则]}, wild: [规则]}。

    判定依据（按优先级）：
    1) 规则显式写了 ``log_type == X`` → 只挂 X；
    2) 规则引用了某类型的专有字段（如 uri→http、query→dns、conn_state→conn）→ 只挂那些类型；
    3) 其它（只引用通用字段或字段归属不明）→ 进通配集合（每次都会跑）。
    """
    types: dict[str, list[dict[str, Any]]] = {}
    wild: list[dict[str, Any]] = []
    for rule in rules:
        cond = rule.get("conditions") or {}
        fields: set[str] = set()
        _rule_fields(cond.get("rules") if isinstance(cond, dict) else cond, fields)
        explicit = {
            str(c.get("value"))
            for c in (cond.get("rules") or [])
            if isinstance(c, dict) and c.get("field") == "log_type" and c.get("op") == "eq"
        }
        owner: set[str] = set(explicit)
        if not owner:
            for field in fields:
                owner.update(_FIELD_TYPES.get(field, ()))
        if not owner or not (fields - _COMMON_FIELDS - {"log_type"}):
            wild.append(rule)
            continue
        for kind in owner:
            types.setdefault(kind, []).append(rule)
    return {"types": types, "wild": wild}


def rules_for_log_type(index: Any, log_type: Any) -> list[dict[str, Any]]:
    """取"本期日志该跑"的规则（专有规则 + 通配规则）。索引缺失时返回空表（调用方回退全量）。"""
    if not isinstance(index, dict):
        return []
    kind = str(log_type or "").strip().lower()
    return list(index.get("types", {}).get(kind, [])) + list(index.get("wild", []))


# ---------- 条件预编译（提速：把 op 字符串分派从"每条日志"移到"加载时"） ----------

log = __import__("app.workers.log", fromlist=["get_logger"]).get_logger(__name__)


def _pick(entry: Any, extra: Any, field: str) -> Any:
    """取字段值：先看命中规则的附加元数据（hit_rule 等），再取日志字段。"""
    if isinstance(extra, dict) and field in extra:
        return extra.get(field)
    return getattr(entry, field, None)


def _num(value: Any) -> float:
    """安全转数字（编译闭包里的数值比较用）。"""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


_COMPILE_OK = True


def compile_conditions(conditions: dict[str, Any] | None) -> Any:
    """把 conditions 编译成闭包 (entry, extra) -> bool；失败返回 None（回退解释执行）。

    为什么值得做：原来每条日志都要对每个条件做"取字段 → 判类型 → 字符串 op 分派 → 比较"，
    63 条规则 × 多条条件，每条日志上千次分派。编译后只保留取值器与比较函数。
    """
    try:
        return _compile_node(conditions)
    except Exception as exc:  # noqa: BLE001
        log.debug("条件预编译失败（回退解释执行）: %s", exc)
        return None


def _compile_node(cond: Any) -> Any:
    """递归编译条件节点，返回 (entry, extra) -> bool 的闭包。"""
    if isinstance(cond, dict) and "rules" in cond:
        logic = str(cond.get("logic") or "and").lower()
        parts = [_compile_node(x) for x in (cond.get("rules") or [])]
        parts = [x for x in parts if x is not None]
        if not parts:
            return None
        if logic == "or":
            return lambda entry, extra=None, parts=parts: any(f(entry, extra) for f in parts)
        return lambda entry, extra=None, parts=parts: all(f(entry, extra) for f in parts)
    if not isinstance(cond, dict):
        return None
    field = str(cond.get("field") or "")
    op = str(cond.get("op") or "eq").lower()
    value = cond.get("value")
    if not field:
        return None
    if op == "in" and isinstance(value, (list, tuple, set)):
        wanted = {str(v).lower() for v in value}
        return lambda entry, extra=None, f=field, w=wanted: str(_pick(entry, extra, f) or "").lower() in w
    if op == "exists":
        return lambda entry, extra=None, f=field: _pick(entry, extra, f) not in (None, "", [], {})
    if op == "eq":
        target = str(value).lower()
        return lambda entry, extra=None, f=field, t=target: str(_pick(entry, extra, f) or "").lower() == t
    if op == "ne":
        target = str(value).lower()
        return lambda entry, extra=None, f=field, t=target: str(_pick(entry, extra, f) or "").lower() != t
    if op == "contains":
        target = str(value).lower()
        return lambda entry, extra=None, f=field, t=target: t in str(_pick(entry, extra, f) or "").lower()
    if op == "gt":
        return lambda entry, extra=None, f=field, v=value: _num(_pick(entry, extra, f)) > _num(v)
    if op == "gte":
        return lambda entry, extra=None, f=field, v=value: _num(_pick(entry, extra, f)) >= _num(v)
    if op == "lt":
        return lambda entry, extra=None, f=field, v=value: _num(_pick(entry, extra, f)) < _num(v)
    if op == "lte":
        return lambda entry, extra=None, f=field, v=value: _num(_pick(entry, extra, f)) <= _num(v)
    if op == "regex":
        import re as _re
        try:
            rx = _re.compile(str(value), _re.IGNORECASE)
        except _re.error:
            return None
        return lambda entry, extra=None, f=field, r=rx: bool(r.search(str(_pick(entry, extra, f) or "")))
    return None


def prepare_rules(rules: list[dict[str, Any]]) -> dict[str, Any]:
    """加载时预处理：编译条件 + 建 log_type 索引（幂等）。"""
    for rule in rules:
        if "_compiled" not in rule:
            rule["_compiled"] = compile_conditions(rule.get("conditions"))
    return build_rule_index(rules)
