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
    # 条件必须指定字段名：`whitelist: [{}]` 这类空条件以前会静默全命中（`None == None`），
    # 让整条规则永不生效。宁可不求值，也不静默命中。
    if not isinstance(field, str) or not field:
        return False
    expected = cond.get("value")
    actual = _get_field(log, field, extra)

    if op == "exists":
        # 非空才算存在（空字符串不应视为存在，否则 JA3/MITRE 等规则会全量误报）。
        # 布尔值算存在：`file_is_orig` 的 False 是有效取值（=服务端下发），不是"缺失"。
        if actual is None:
            return False
        return not (isinstance(actual, str) and actual.strip() == "")
    if op == "eq":
        # 缺值不算相等：错字段名（getattr → None）配 `value: null` 会静默全命中
        if actual is None or expected is None:
            return False
        return actual == expected
    if op == "ne":
        # 字段缺失（None 或空串）时**不算**"不等于任何值"（否则 `auth_scheme ne basic`
        # 在空值上恒真，等于把"没带认证头"当成"不是 Basic 认证"放行 —— 见 2026-10 规则评审）
        if actual is None or (isinstance(actual, str) and actual.strip() == ""):
            return False
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
#
# 这些 Web 字段只有 Zeek 的 http 日志会填；签名引擎（suricata）走自己的 signature_* 字段。
_FIELD_TYPES: dict[str, tuple[str, ...]] = {
    # Zeek http 日志的 Web 字段
    "uri_path": ("http",),
    "query_string": ("http",),
    "method": ("http",),
    "status_code": ("http",),
    "user_agent": ("http",),
    "body": ("http",),
    "content_type": ("http",),
    "resp_body": ("http",),
    "resp_body_len": ("http",),
    "req_headers": ("http",),
    "resp_headers": ("http",),
    "real_client_ip": ("http",),
    # 会话 id（ingestion/session_cookie.py 按名单从 Cookie 头取）：
    # 「会话跨IP复用」是 count 规则（不走路由），登记在这里是为了口径清晰 + 将来逐条规则可用。
    "session_id": ("http",),
    # dns：`query` 在 dns.log 里是域名，在 http 里是完整 URL，
    "query": ("dns", "http"),
    "qtype": ("dns",),
    # conn：`dst_ip` 本身全来源都有（属通用字段），但把它登记成 conn 的 owner 是为了让
    # 「query/body 命中 + dst_ip 命中」这类 OR 规则**在 conn 日志上也求值** ——
    # 否则 SSRF/云元数据（builtin.py:308/660）的 `dst_ip eq 169.254.169.254` 分支在
    # conn 上永不求值（真实取证路径漏报，2026-10 规则评审 P0-4）。只加不减，安全。
    "dst_ip": ("conn",),
    "conn_state": ("conn",),
    # weird：异常名（`possible_split_routing` / `bad_HTTP_request` …）。
    # 归一化已把采集类（镜像口丢包/非对称路由/offload）标成 `capture_anomaly`，
    # 所以引用 `weird_name` 的规则只会看到真正的协议异常。
    "weird_name": ("weird",),
    "bytes_out": ("conn",),
    "bytes_in": ("conn",),
    # 签名引擎（Suricata）：告警元数据挂在 "suricata" 名下，有两个作用——
    # ① 「签名命中」三条规则只在这类日志上求值；② 其它引用这些字段的规则不会跑到别的日志上。
    "signature": ("suricata",),
    "signature_id": ("suricata",),
    "signature_severity": ("suricata",),
    "signature_category": ("suricata",),
    # 关联键：Zeek 侧在 conn.log 上（community-id 脚本），Suricata 侧在告警上，两边同名同值。
    "community_id": ("conn", "suricata"),
    # files
    "mime_type": ("files",),
    "filename": ("files",),
    "fuid": ("files",),
    "md5": ("files",),
    "sha1": ("files",),
    "sha256": ("files",),
    "file_source": ("files",),
    "file_is_orig": ("files",),
    "extracted": ("files",),
    "extracted_size": ("files",),
    "extracted_cutoff": ("files",),
    # ssl
    "ja3": ("ssl",),
    "ja3s": ("ssl",),
    "ja4": ("ssl",),
    "tls_version": ("ssl",),
    # 握手是否建立（Zeek ssl.log 的 established）：「TLS 握手失败风暴」的判据
    "tls_established": ("ssl",),
    "cert_issuer": ("ssl",),
    "cert_self_signed": ("ssl",),
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
        # 显式写了 `log_type == X` 就是规则作者的明确意图，必须是**权威**的：
        # 反而被归进通配集合（每条日志都跑）—— 显式意图被静默忽略。
        if explicit:
            for kind in explicit:
                types.setdefault(kind, []).append(rule)
            continue
        owner: set[str] = set()
        for field in fields:
            owner.update(_FIELD_TYPES.get(field, ()))
        if not owner or not (fields - _COMMON_FIELDS - {"log_type"}):
            wild.append(rule)
            continue
        for kind in owner:
            types.setdefault(kind, []).append(rule)
    return {"types": types, "wild": wild}


def rules_for_log_type(index: Any, log_type: Any) -> list[dict[str, Any]]:
    """取"本期日志该跑"的规则（专有规则 + 通配规则）。

    索引缺失时返回空表（调用方回退全量）。

    **合并后必须按 (priority, name) 重排**：`types[kind]` 与 `wild` 是两张独立列表，
    直接拼接会把所有专有规则排在所有通配规则之前，而调用方是「首个命中即停」——
    遮蔽。排序一次的开销可忽略（每期日志只算一次）。
    """
    if not isinstance(index, dict):
        return []
    kind = str(log_type or "").strip().lower()
    merged = list(index.get("types", {}).get(kind, [])) + list(index.get("wild", []))
    merged.sort(key=_rule_order)
    return merged


def _rule_order(rule: dict[str, Any]) -> tuple[int, str]:
    """稳定排序键：priority 升序，同优先级按规则名（避免依赖 DB 行序）。"""
    raw = rule.get("priority")
    priority = 1000
    if isinstance(raw, (int, float)):
        priority = int(raw)
    elif isinstance(raw, str):
        try:
            priority = int(raw)
        except ValueError:
            priority = 1000
    return priority, str(rule.get("name") or "")
