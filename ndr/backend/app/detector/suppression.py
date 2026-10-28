"""精准抑制（v2）：智能体给出**可机械核验**的证据后，NDR 自动抑制该类现象。

## 作用点（三处，同一个求值入口）

1. **不再生成命中事件**：`runner` 命中后在聚合/落库之前判一次 → 命中则直接返回，
   `hit_events` 不新增行，只给抑制条目 `hits += 1`；
2. **不再入队、不再门铃**：候选生成器复用同一判定；
3. 历史行不动（不批量删、不批量 ignore），保证审计连续。

**绝对不作用**于采集、归一化、入库与 ES 原始数据 —— 抑制错了也能用
`search_events` / `raw_evidence` 事后重建，这是"全自动"必须保留的逃生门。

## 为什么"全自动"仍然安全：六道机械门槛（缺一不可）

全是服务端能算的客观判据，不依赖人工审批：

| # | 门槛 | 参数 |
|---|---|---|
| G1 | **结构化匹配**（复用规则引擎条件树 `{logic, rules:[{field,op,value}]}`），字段必须白名单 | 见 `ALLOWED_FIELDS` |
| G2 | **至少 2 个独立维度**（只写一条签名/一条规则一律拒绝 = 关掉一条检测规则） | `min_match_dims`（下限锁 2） |
| G3 | **证据真实性**：引用必须全部命中该令牌会话的 `ctx.valid_refs` | — |
| G4 | **证据多样性**：≥3 条引用且来自 ≥2 种取数工具（防"只看一段被投毒的正文"） | `min_refs` / `min_tools` |
| G5 | **置信度**达标 | `min_confidence` |
| G6 | **新现象保护期**：该现象首见不足 24h 不允许自动抑制（先积累观测） | `newcomer_hours` |

外加：**爆炸半径试算**（近 N 天命中量/源数/网段数任一超阈值 → 降级为 `record_only`：
事件仍生成、只是不派工不推送）、**TTL 到期**、**活跃条目上限**、
**单条命中量熔断**（吞掉异常大量事件＝投毒/误配的典型征兆，自动撤销）。

## 求值顺序（避免相互掩盖）

入库过滤 → **抑制匹配（本模块，智能体自动）** → 排除过滤（人工）→ 规则匹配 → 事件落库
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select

from app.db.base import SessionLocal
from app.db.models import AnalysisSuppression, HitEvent
from app.rules.engine import evaluate_conditions
from app.runtime_config import get as rc_get, invalidate, overrides
from app.schemas import UnifiedLog
from app.workers.log import get_logger

#: 等价于 3.11 的 `datetime.UTC`（本仓库 requires-python >=3.11）；用别名写法
#: 免得按旧语法解析的静态检查工具报「unknown import symbol」。
UTC = timezone.utc

log = get_logger(__name__)

#: 允许做抑制匹配的字段（白名单）。刻意**不含 payload/body**：
#: 攻击者可以在正文里写「这是内部测试流量」，若正文能当判据，投毒就能换来一条永久抑制。
#: 要按内容收敛就用 `http.uri` 的 `contains/regex`（URI 是结构性字段，难以借它掩盖真实利用）。
ALLOWED_FIELDS: dict[str, str] = {
    "src_ip": "请求方 IP（精确）",
    "dst_ip": "被访问 IP（精确）",
    "dst_port": "被访问端口（eq / gt / lt 等）",
    "segment": "请求方所在网段（v4 /24、v6 /64，含操作符 contains）",
    "protocol": "协议（tcp/udp/http/dns/tls…）",
    "rule": "命中的行为分析规则名（精确）",
    "signature_id": "签名 SID（精确）",
    "http.uri": "HTTP 请求 URI（含 contains/regex）",
    "http.hostname": "HTTP Host / DNS 名",
    "user_agent": "User-Agent",
    "ja3": "TLS 客户端指纹",
    "fuid": "文件 id（fuid）",
}

#: 允许的理由码（智能体必须说清"凭什么判它是误报"，自由文本不作判据）
REASON_CODES: dict[str, str] = {
    "known_service": "已知的自家服务/客户端行为",
    "internal_scanner": "内部授权扫描器/漏扫平台",
    "vendor_heartbeat": "厂商组件心跳/升级/探测",
    "business_normal": "业务正常行为（OA/打卡/消息等）",
    "duplicate_of_task": "与既有任务/结论重复",
    "repeated_after_analysis": "分析后重复出现的同类流量",
    "manual": "人工创建（界面）",
}

MODE_SUPPRESS = "suppress"  # 连事件都不生成
MODE_RECORD_ONLY = "record_only"  # 事件仍生成，只是不派工不推送

ORIGIN_AGENT = "agent"
ORIGIN_UI = "ui"

#: 取数工具里"算作取证"的那些（证据多样性用它去重计数）
_EVIDENCE_TOOLS = (
    "search_events",
    "aggregate_events",
    "timeline",
    "net_flows",
    "dns_queries",
    "tls_fingerprints",
    "web_requests",
    "file_hashes",
    "fetch_window",
    "raw_evidence",
    "get_event_detail",
    "search_hits",
    "hit_clusters",
)

_IP_RE = re.compile(r"^[0-9a-fA-F:.]{3,64}$")


# ---------- 运行时参数（界面可改、30 秒生效） ----------


@dataclass(frozen=True)
class Knob:
    """一个可调参数：键名、界面标签、类型、默认值、区间与说明。"""

    key: str
    label: str
    kind: str
    default: Any
    low: float | None = None
    high: float | None = None
    unit: str = ""
    note: str = ""


KNOBS: tuple[Knob, ...] = (
    Knob(
        "suppression.enabled",
        "启用精准抑制",
        "bool",
        True,
        note="总开关；关掉后已登记条目全部不生效（条目保留）",
    ),
    Knob(
        "suppression.auto_apply",
        "自动生效",
        "bool",
        True,
        note="关掉则只抑制派工、事件仍生成（灰度/回滚用），不删任何条目",
    ),
    Knob(
        "suppression.min_match_dims",
        "最少匹配维度",
        "int",
        2,
        low=2,
        high=6,
        unit="个",
        note="源IP/目的IP/端口/网段/协议/规则/签名/URI… 至少填这么多个（下限锁 2）",
    ),
    Knob(
        "suppression.min_refs",
        "最少证据条数",
        "int",
        3,
        low=1,
        high=20,
        unit="条",
        note="证据引用条数下限：只看一条就说误报不够",
    ),
    Knob(
        "suppression.min_tools",
        "最少证据工具种类",
        "int",
        2,
        low=1,
        high=6,
        unit="种",
        note="引用要来自这么多种取数工具，防只看一段被投毒的正文就下结论",
    ),
    Knob(
        "suppression.min_confidence",
        "最低置信度",
        "float",
        0.85,
        low=0.0,
        high=1.0,
        note="智能体自报置信度低于它不自动生效",
    ),
    Knob(
        "suppression.default_ttl_days",
        "抑制有效期",
        "int",
        14,
        low=1,
        high=30,
        unit="天",
        note="到期自动失效；要延续须重新申请（会重新试算，噪声变化能被发现）",
    ),
    Knob(
        "suppression.max_active",
        "活跃条目上限",
        "int",
        200,
        low=1,
        high=2000,
        unit="条",
        note="超限时淘汰最早到期的条目并计数（抑制面必须可复核）",
    ),
    Knob(
        "suppression.hit_cap",
        "单条命中量熔断",
        "int",
        20000,
        low=100,
        high=10000000,
        unit="次",
        note="某条抑制累计吞掉这么多事件即自动撤销（投毒/误配的典型征兆）",
    ),
    Knob(
        "suppression.trial_days",
        "爆炸半径试算天数",
        "int",
        7,
        low=1,
        high=90,
        unit="天",
        note="申请时回看这段时间的命中量估计影响面",
    ),
    Knob(
        "suppression.trial_max_srcs",
        "试算·源数上限",
        "int",
        200,
        low=1,
        high=1000000,
        unit="个",
        note="超过就不自动静默（降级为只不派工）",
    ),
    Knob(
        "suppression.trial_max_hits",
        "试算·命中数上限",
        "int",
        5000,
        low=1,
        high=100000000,
        unit="条",
        note="超过就不自动静默",
    ),
    Knob(
        "suppression.trial_max_segments",
        "试算·网段数上限",
        "int",
        8,
        low=1,
        high=1000,
        unit="个",
        note="跨太多网段说明条件过宽，不自动静默",
    ),
    Knob(
        "suppression.newcomer_hours",
        "新现象保护期",
        "int",
        24,
        low=0,
        high=720,
        unit="小时",
        note="现象首见不足这么多小时不允许自动抑制（先积累观测）",
    ),
    Knob(
        "suppression.cache_seconds",
        "抑制表缓存",
        "int",
        45,
        low=0,
        high=600,
        unit="秒",
        note="匹配集合的进程内缓存；新增/撤销会立刻失效",
    ),
)

_BY_KEY: dict[str, Knob] = {k.key: k for k in KNOBS}
EDITABLE_KEYS: tuple[str, ...] = tuple(_BY_KEY)


def _num(knob: Knob) -> float:
    try:
        number = float(rc_get(knob.key, knob.default))
    except (TypeError, ValueError):
        number = float(knob.default)
    if knob.low is not None:
        number = max(float(knob.low), number)
    if knob.high is not None:
        number = min(float(knob.high), number)
    return number


def _flag(knob: Knob) -> bool:
    value = rc_get(knob.key, knob.default)
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on", "是")
    return bool(value)


def enabled() -> bool:
    return _flag(_BY_KEY["suppression.enabled"])


def auto_apply() -> bool:
    """自动生效开关：关掉 = 只抑制派工，事件仍生成（回滚档）。"""
    return _flag(_BY_KEY["suppression.auto_apply"])


def min_match_dims() -> int:
    # 硬下限 2：参数被调低也不给单维抑制（那等于关掉一条检测规则）
    return max(2, int(_num(_BY_KEY["suppression.min_match_dims"])))


def min_refs() -> int:
    return max(1, int(_num(_BY_KEY["suppression.min_refs"])))


def min_tools() -> int:
    return max(1, int(_num(_BY_KEY["suppression.min_tools"])))


def min_confidence() -> float:
    return _num(_BY_KEY["suppression.min_confidence"])


def default_ttl_days() -> int:
    return int(_num(_BY_KEY["suppression.default_ttl_days"]))


def max_active() -> int:
    return int(_num(_BY_KEY["suppression.max_active"]))


def hit_cap() -> int:
    return int(_num(_BY_KEY["suppression.hit_cap"]))


def trial_days() -> int:
    return int(_num(_BY_KEY["suppression.trial_days"]))


def trial_max_srcs() -> int:
    return int(_num(_BY_KEY["suppression.trial_max_srcs"]))


def trial_max_hits() -> int:
    return int(_num(_BY_KEY["suppression.trial_max_hits"]))


def trial_max_segments() -> int:
    return int(_num(_BY_KEY["suppression.trial_max_segments"]))


def newcomer_hours() -> int:
    return int(_num(_BY_KEY["suppression.newcomer_hours"]))


def cache_seconds() -> int:
    return int(_num(_BY_KEY["suppression.cache_seconds"]))


# ---------- 字段取值（把白名单字段映射成事件上的实际值） ----------


def _segment_of(ip: str) -> str:
    """请求方所在网段：v4 /24、v6 /64（与画像「同族来源」同一口径）。"""
    text = str(ip or "").strip()
    if not text or text == "-":
        return ""
    if ":" in text:
        parts = text.split(":")
        return ":".join(parts[:4]) + "::/64" if len(parts) >= 4 else ""
    octets = text.split(".")
    return ".".join(octets[:3]) + ".0/24" if len(octets) == 4 else ""


def field_values(entry: UnifiedLog, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """把抑制白名单里的每个字段都算出来，交给规则引擎按条件树匹配。

    为什么集中算：条件树里的字段名是"分析口径"（`http.uri`/`segment`），
    与 `UnifiedLog` 的属性名不一致；在这里一次性映射，规则引擎不用为抑制改任何代码。
    """
    merged = dict(extra or {})
    return {
        "src_ip": str(entry.src_ip or ""),
        "dst_ip": str(entry.dst_ip or ""),
        "dst_port": entry.dst_port,
        "segment": _segment_of(str(entry.src_ip or "")),
        "protocol": str(entry.protocol or "").lower(),
        "rule": str(merged.get("hit_rule") or ""),
        "signature_id": str(entry.signature_id or ""),
        "http.uri": str(entry.query or entry.uri_path or ""),
        "http.hostname": str(entry.hostname or ""),
        "user_agent": str(entry.user_agent or ""),
        "ja3": str(entry.ja3 or ""),
        "fuid": str(entry.fuid or ""),
    }


# ---------- 条件树校验 ----------


def _walk_rules(node: Any, out: list[dict[str, Any]]) -> None:
    if isinstance(node, list):
        for item in node:
            _walk_rules(item, out)
        return
    if not isinstance(node, dict):
        return
    if "rules" in node:
        _walk_rules(node.get("rules"), out)
        return
    out.append(node)


def match_fields(match: dict[str, Any]) -> list[str]:
    """条件树里出现的字段（去重保序），用来数"独立维度"。"""
    leaves: list[dict[str, Any]] = []
    _walk_rules(match, leaves)
    seen: list[str] = []
    for leaf in leaves:
        field = str(leaf.get("field") or "").strip()
        if field and field not in seen:
            seen.append(field)
    return seen


def _is_broad(leaf: dict[str, Any]) -> bool:
    """宽域条件：`segment=全部`、`dst_port=*`、`protocol=*` 这类等于没约束。"""
    field = str(leaf.get("field") or "")
    value = leaf.get("value")
    text = str(value if value is not None else "").strip()
    if text in ("", "*", "any", "all", "全部"):
        return True
    return field == "segment" and text in ("0.0.0.0/0", "::/0")


def validate_match(match: Any) -> list[dict[str, str]]:
    """校验条件树（结构化、字段白名单、维度数、宽域条件）。"""
    errors: list[dict[str, str]] = []
    if not isinstance(match, dict) or not match.get("rules"):
        return [
            {
                "field": "match",
                "msg": "match 必须是 {logic: and|or, rules: [{field, op, value}]} 结构",
            }
        ]
    leaves: list[dict[str, Any]] = []
    _walk_rules(match, leaves)
    if not leaves:
        errors.append({"field": "match", "msg": "match 里没有任何条件"})
        return errors
    for leaf in leaves:
        field = str(leaf.get("field") or "").strip()
        if field not in ALLOWED_FIELDS:
            errors.append(
                {
                    "field": "match",
                    "msg": f"字段 {field!r} 不允许做抑制匹配。可用：{'、'.join(ALLOWED_FIELDS)}",
                }
            )
            continue
        if _is_broad(leaf):
            errors.append(
                {
                    "field": "match",
                    "msg": f"{field} 的条件过宽（空值/*/any 等于没约束），换成具体值",
                }
            )
        if field in ("src_ip", "dst_ip"):
            value = str(leaf.get("value") or "").strip()
            if value and "/" in value:
                errors.append(
                    {
                        "field": "match",
                        "msg": f"{field} 只接受单地址；要按网段请用 segment",
                    }
                )
            elif value and not _IP_RE.match(value):
                errors.append({"field": "match", "msg": f"{field} 不是合法 IP：{value}"})
    fields = match_fields(match)
    need = min_match_dims()
    if len(fields) < need:
        errors.append(
            {
                "field": "match",
                "msg": (
                    f"至少要 {need} 个独立匹配维度（当前 {len(fields)}：{'、'.join(fields) or '无'}）。"
                    "只写一条签名或一条规则等于关掉一条检测规则"
                ),
            }
        )
    return errors


# ---------- 爆炸半径试算 ----------


def _phenomenon(match: dict[str, Any]) -> tuple[str, str]:
    """从条件树里抽"现象标识"：优先 signature_id，其次 rule，最后 src_ip。"""
    leaves: list[dict[str, Any]] = []
    _walk_rules(match, leaves)
    by_field: dict[str, str] = {}
    for leaf in leaves:
        field = str(leaf.get("field") or "")
        if field in ("signature_id", "rule", "src_ip") and field not in by_field:
            by_field[field] = str(leaf.get("value") or "").strip()
    for field in ("signature_id", "rule", "src_ip"):
        if by_field.get(field):
            return field, by_field[field]
    return "", ""


def _src_ips_of(match: dict[str, Any]) -> list[str]:
    """条件树里写明的**全部** src_ip 取值（OR 组里的多个源也要算上）。

    为什么不能只看第一个：试算要的是"这条抑制真实覆盖多大面"。
    只按第一个源试算，等于让"加一个 src_ip"就能绕过网段护栏。
    """
    values: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        if not isinstance(node, dict):
            return
        if isinstance(node.get("rules"), list):
            for item in node["rules"]:
                walk(item)
            return
        if str(node.get("field") or "") == "src_ip":
            value = str(node.get("value") or "").strip()
            if value and value not in values:
                values.append(value)

    walk(match)
    return values


def _hit_event_matches(row: HitEvent, match: dict[str, Any]) -> bool:
    """这条**命中事件**是否落在条件树里（用落库的样例事件求值）。

    为什么用命中事件而不是任意原始日志：抑制拦的是"规则命中"这条路径，
    条件树必须能匹配**触发噪声的那条规则的命中事件**。智能体常见的错法是
    拿良性流量的字段（UA/URI）去写条件，而噪声那条规则的命中事件是另一种
    日志（没有那些字段）—— 于是抑制一条也拦不住，还以为生效了。
    """
    extra = {"hit_rule": str(row.rule or "")}
    for sample in (row.evidence or [])[:3]:
        if not isinstance(sample, dict):
            continue
        pseudo = UnifiedLog(
            source_system="hit_event",
            ts=row.created_at or datetime.now(UTC),
            event_type=str((row.event_types or [""])[0] or ""),
            log_type=str((row.log_types or [""])[0] or ""),
            src_ip=str(row.src_ip or ""),
            dst_ip=str(sample.get("dst_ip") or (row.dst_ips or [""])[0] or ""),
            dst_port=_as_port(sample.get("dst_port") or (row.dst_ports or ["0"])[0] or 0),
            protocol=str(sample.get("protocol") or ""),
            signature_id=str(sample.get("signature_id") or ""),
            query=str(sample.get("query") or ""),
            uri_path=str(sample.get("uri_path") or ""),
            hostname=str(sample.get("hostname") or ""),
            user_agent=str(sample.get("user_agent") or ""),
            ja3=str(sample.get("ja3") or ""),
            fuid=str(sample.get("fuid") or ""),
        )
        if evaluate_conditions(match, pseudo, extra):
            return True
    return False


def _as_port(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _coverage_of_match(match: dict[str, Any], since: datetime) -> dict[str, Any]:
    """条件树在近 N 天命中事件上的**真实覆盖面**（命中条数 / 源数 / 网段数）。

    这是护栏真正要量的东西：这条抑制会静默掉多少条命中事件。
    """
    try:
        with SessionLocal() as db:
            rows = db.scalars(
                select(HitEvent)
                .where(func.coalesce(HitEvent.last_seen, HitEvent.created_at) >= since)
                .order_by(HitEvent.created_at.desc())
                .limit(2000)
            ).all()
    except Exception as exc:  # noqa: BLE001 — 算不出就按"覆盖面未知"处理
        log.debug("算抑制覆盖面失败: %s", exc)
        return {"scanned": 0, "matched_rows": 0, "events": -1, "srcs": -1, "segments": -1}
    matched = [row for row in rows if _hit_event_matches(row, match)]
    events = sum(max(1, int(row.count or 1)) for row in matched)
    srcs = {str(row.src_ip or "") for row in matched if str(row.src_ip or "").strip()}
    segments = {_segment_of(ip) for ip in srcs}
    return {
        "scanned": len(rows),
        "matched_rows": len(matched),
        "events": events,
        "srcs": len(srcs),
        "segments": len(segments),
    }


def estimate_trial(match: dict[str, Any]) -> dict[str, Any]:
    """回看近 N 天同类命中的规模：命中条数 / 不同源 / 跨网段数。

    只看**已落库的命中事件**（PG），不回 ES 扫原始日志 —— 这是申请时的一次性成本，
    目的是估计"这条抑制会不会把一大片东西静默掉"，不是精确取证。

    口径：
    1. **真实覆盖面**（条件树在命中事件上求值）—— 护栏量的是这个；
    2. 现象维度（同一规则/签名/来源的规模）—— 作为对照一并给出。
    3. 条件树里写了 src_ip 就按**那些源**算（全部，不只是第一个），
       否则"加一个 src_ip"就能把网段护栏绕过去。
    """
    days = trial_days()
    since = datetime.now(UTC) - timedelta(days=days)
    field, value = _phenomenon(match)
    src_ips = _src_ips_of(match)
    base: list[Any] = [func.coalesce(HitEvent.last_seen, HitEvent.created_at) >= since]
    if src_ips:
        base.append(HitEvent.src_ip.in_(src_ips))
    elif field == "rule":
        base.append(HitEvent.rule == value)
    elif field == "signature_id":
        base.append(func.cast(HitEvent.evidence, HitEvent.evidence.type).astext.like(f"%{value}%"))
    elif field == "src_ip":
        base.append(HitEvent.src_ip == value)
    coverage = _coverage_of_match(match, since)
    try:
        with SessionLocal() as db:
            events = int(db.scalar(select(func.count()).select_from(HitEvent).where(*base)) or 0)
            srcs = int(
                db.scalar(select(func.count(func.distinct(HitEvent.src_ip))).where(*base)) or 0
            )
            ips = db.scalars(select(HitEvent.src_ip).where(*base).limit(5000)).all()
    except Exception as exc:  # noqa: BLE001 — 试算失败按"影响面未知"处理（保守降级）
        log.warning("抑制试算失败（按保守档处理）: %s", exc)
        return {"days": days, "error": str(exc)[:200], "events": -1, "srcs": -1, "segments": -1}
    segments = len({_segment_of(str(ip or "")) for ip in ips if str(ip or "").strip()})
    # 覆盖面优先（护栏看它）：条件树匹配不到任何命中事件时，覆盖面为 0 —— 说明这条
    # 抑制压根拦不到东西（多半是拿错了字段），此时不能拿"现象维度"的规模来顶。
    events = coverage["events"] if coverage["events"] >= 0 else events
    srcs = coverage["srcs"] if coverage["srcs"] >= 0 else srcs
    segments = coverage["segments"] if coverage["segments"] >= 0 else segments
    return {
        "days": days,
        "phenomenon": f"{field}:{value}" if field else "",
        "events": events,
        "srcs": srcs,
        "segments": segments,
        "matched_rows": coverage["matched_rows"],
        "scanned_rows": coverage["scanned"],
        "max_events": trial_max_hits(),
        "max_srcs": trial_max_srcs(),
        "max_segments": trial_max_segments(),
    }


def choose_mode(trial: dict[str, Any]) -> str:
    """按试算决定彻底静默还是只不派工。

    任一维度超阈值、或试算失败（影响面未知）→ `record_only`：
    **宁可多生成一条事件，也不在影响面不明时把一整类流量静默掉**。
    """
    if int(trial.get("events") or 0) < 0:
        return MODE_RECORD_ONLY
    if int(trial.get("events") or 0) > trial_max_hits():
        return MODE_RECORD_ONLY
    if int(trial.get("srcs") or 0) > trial_max_srcs():
        return MODE_RECORD_ONLY
    if int(trial.get("segments") or 0) > trial_max_segments():
        return MODE_RECORD_ONLY
    return MODE_SUPPRESS


#: 降级档的四个维度 → (试算字段, 上限旋钮, 人话解释, 收窄建议)
_DOWNGRADE_DIMENSIONS: tuple[tuple[str, str, str, str], ...] = (
    (
        "events",
        "suppression.trial_max_hits",
        "近 {days} 天同类命中 {actual} 条，超过上限 {limit}",
        (
            "把条件收窄到更具体的一类现象（例如加 dst_port、user_agent 或 src_ip），"
            "或改用更短的 TTL 反复确认"
        ),
    ),
    (
        "srcs",
        "suppression.trial_max_srcs",
        "近 {days} 天同类命中涉及 {actual} 个源，超过上限 {limit}",
        "把条件收窄到更具体的一类现象（例如加 dst_port、user_agent 或 src_ip）",
    ),
    (
        "segments",
        "suppression.trial_max_segments",
        "近 {days} 天同类命中跨 {actual} 个网段，超过上限 {limit}",
        (
            "把匹配面收窄到**单个来源**（src_ip 精确匹配一个源）+ 具体行为特征；"
            "同一类现象有多个来源就**每个来源各提一条**（名字里带上来源），"
            "别用 or 把它们并成一条 —— 并了仍然算一个大面"
        ),
    ),
)


def mode_downgrade(trial: dict[str, Any]) -> dict[str, Any]:
    """为什么没按"彻底静默"生效 —— 给出**可执行**的收窄建议。

    为什么要说清楚：智能体提交抑制后不需要人来拍板，它自己按这里的建议收窄条件、
    用同名重新提交就能自动生效（同名覆盖旧条目）。降级不是死胡同，是给它指路。
    """
    if int(trial.get("events") or 0) < 0:
        return {
            "dimension": "trial",
            "actual": -1,
            "limit": 0,
            "reason": "试算失败（影响面未知），按保守档处理",
            "advice": "换更窄的条件（字段与取值都要更具体）后用同名重提",
        }
    days = int(trial.get("days") or 0)
    for field, knob, template, advice in _DOWNGRADE_DIMENSIONS:
        limit = int(
            trial.get(
                {"events": "max_events", "srcs": "max_srcs", "segments": "max_segments"}[field]
            )
            or {"events": trial_max_hits, "srcs": trial_max_srcs, "segments": trial_max_segments}[field]()
        )
        actual = int(trial.get(field) or 0)
        if limit and actual > limit:
            return {
                "dimension": field,
                "actual": actual,
                "limit": limit,
                "knob": knob,
                "reason": template.format(days=days, actual=actual, limit=limit),
                "advice": advice,
            }
    return {}


def phenomenon_age_hours(match: dict[str, Any]) -> float | None:
    """该现象首次出现距今多少小时（新现象保护期用）；查不到返回 None。"""
    field, value = _phenomenon(match)
    if not field or not value:
        return None
    conds: list[Any] = []
    if field == "rule":
        conds.append(HitEvent.rule == value)
    elif field == "signature_id":
        conds.append(func.cast(HitEvent.evidence, HitEvent.evidence.type).astext.like(f"%{value}%"))
    else:
        conds.append(HitEvent.src_ip == value)
    try:
        with SessionLocal() as db:
            oldest = db.scalar(
                select(func.min(func.coalesce(HitEvent.first_seen, HitEvent.created_at))).where(
                    *conds
                )
            )
    except Exception as exc:  # noqa: BLE001
        log.debug("查现象首见时间失败（跳过新现象保护）: %s", exc)
        return None
    if not isinstance(oldest, datetime):
        return None
    if oldest.tzinfo is None:
        oldest = oldest.replace(tzinfo=UTC)
    return max(0.0, (datetime.now(UTC) - oldest).total_seconds() / 3600.0)


# ---------- 匹配执行（热路径） ----------


@dataclass(frozen=True)
class Matched:
    """一次抑制命中：条目 id 与生效模式。"""

    id: str
    name: str
    mode: str


_cache: tuple[float, tuple[AnalysisSuppression, ...]] = (0.0, ())
_pending_hits: dict[str, int] = {}
_last_flush = 0.0
_FLUSH_SECONDS = 30.0


def _active_rows() -> tuple[AnalysisSuppression, ...]:
    now = time.monotonic()
    ttl = max(0, cache_seconds())
    if ttl and now - _cache[0] < ttl:
        return _cache[1]
    cutoff = datetime.now(UTC)
    try:
        with SessionLocal() as db:
            rows = db.scalars(
                select(AnalysisSuppression).where(
                    AnalysisSuppression.enabled.is_(True),
                    (
                        AnalysisSuppression.expires_at.is_(None)
                        | (AnalysisSuppression.expires_at > cutoff)
                    ),
                )
            ).all()
    except Exception as exc:  # noqa: BLE001 — fail-open：读不到就当没有抑制
        log.warning("读取抑制表失败（本次不抑制）: %s", exc)
        return _cache[1]
    _reset_cache(tuple(rows), now)
    return _cache[1]


def _reset_cache(
    rows: tuple[AnalysisSuppression, ...] | None = None, at: float | None = None
) -> None:
    global _cache
    _cache = (time.monotonic() if at is None else at, () if rows is None else rows)


def invalidate_cache() -> None:
    """新增/撤销/改条件后立刻生效（不等缓存 TTL）。"""
    _reset_cache(())


def decide(entry: UnifiedLog, *, rule: str = "") -> Matched | None:
    """这条事件是否被抑制。`rule` 是命中的规则名（条件树可用 `rule` 维度匹配）。

    AUTO_APPLY 关闭时只返回 `record_only` 档命中（事件仍生成、只是不派工）。
    """
    if not enabled():
        return None
    rows = _active_rows()
    if not rows:
        return None
    extra = {"hit_rule": rule} if rule else None
    values = field_values(entry, extra)
    for row in rows:
        match = row.match or {}
        if not match:
            continue
        if not evaluate_conditions(match, entry, extra=values):
            continue
        mode = row.mode or MODE_SUPPRESS
        if mode == MODE_SUPPRESS and not auto_apply():
            mode = MODE_RECORD_ONLY
        return Matched(id=str(row.id), name=str(row.name or ""), mode=mode)
    return None


def note_hit(item_id: str) -> None:
    """记一次抑制命中（内存累加，`flush_hits()` 攒批落库）。"""
    _pending_hits[item_id] = _pending_hits.get(item_id, 0) + 1


def flush_hits() -> int:
    """把攒下的命中计数写回库；单条超熔断阈值即自动撤销并告警。"""
    global _pending_hits, _last_flush
    pending, _pending_hits = _pending_hits, {}
    if not pending:
        _last_flush = time.monotonic()
        return 0
    now = datetime.now(UTC)
    cap = hit_cap()
    wrote = 0
    try:
        with SessionLocal() as db:
            for item_id, count in pending.items():
                row = db.get(AnalysisSuppression, item_id)
                if row is None:
                    continue
                row.hits = int(row.hits or 0) + int(count)
                row.last_hit_at = now
                if row.hits > cap and row.enabled:
                    # 熔断：一条抑制吞掉异常大量事件，是投毒或误配的典型征兆
                    row.enabled = False
                    row.revoked_at = now
                    row.revoke_reason = f"熔断：累计抑制 {row.hits} 条事件，超过上限 {cap}"
                    log.warning(
                        "抑制条目 %s 触发熔断（累计 %d 条），已自动撤销", row.name, row.hits
                    )
                wrote += 1
            db.commit()
    except Exception as exc:  # noqa: BLE001 — 计数写失败不能影响检测
        log.warning("写抑制命中数失败（本轮丢弃 %d 条计数）: %s", len(pending), exc)
    _last_flush = time.monotonic()
    return wrote


def maybe_flush() -> None:
    if _pending_hits and time.monotonic() - _last_flush >= _FLUSH_SECONDS:
        flush_hits()


def ids_for_subject(subject: str) -> list[str]:
    """该对象身上**生效中**的抑制条目 ID（复测线索用：有抑制才值得回头复核）。

    与 `rebound_for_subject` 同一套保守匹配口径：只认条件树里明确写了该 `src_ip` 的条目。
    返回空列表表示"没有抑制指向它"，此时不需要复测。
    """
    value = str(subject or "").strip()
    if not value:
        return []
    try:
        with SessionLocal() as db:
            rows = db.scalars(
                select(AnalysisSuppression).where(AnalysisSuppression.enabled.is_(True))
            ).all()
            out: list[str] = []
            for row in rows:
                leaves: list[dict[str, Any]] = []
                _walk_rules(row.match or {}, leaves)
                if any(
                    str(leaf.get("field")) == "src_ip"
                    and str(leaf.get("value") or "").strip() == value[:64]
                    for leaf in leaves
                ):
                    out.append(str(row.id))
            return out
    except Exception as exc:  # noqa: BLE001 — 读失败按"没有抑制"处理，不影响派工
        log.debug("查询对象抑制条目失败（%s）：%s", value[:64], exc)
        return []


def rebound_for_subject(kind: str, subject: str) -> int:
    """真实事件推翻误抑制：把该对象身上生效中的抑制**自动撤销**，返回撤销条数。

    全自动抑制的兜底不是"等人工来看"，而是"被事实自己打脸"：一旦该对象上的事件被判
    `true_positive`，说明之前"这是误报"的结论至少对这个范围不成立，立刻失效比保留更安全。
    匹配保守：只撤条件树里**明确写了该 src_ip** 的条目，避免一次真阳性放开一大片。
    """
    value = str(subject or "").strip()
    if not value:
        return 0
    now = datetime.now(UTC)
    revoked = 0
    try:
        with SessionLocal() as db:
            rows = db.scalars(
                select(AnalysisSuppression).where(AnalysisSuppression.enabled.is_(True))
            ).all()
            for row in rows:
                leaves: list[dict[str, Any]] = []
                _walk_rules(row.match or {}, leaves)
                if not any(
                    str(leaf.get("field")) == "src_ip"
                    and str(leaf.get("value") or "").strip() == value[:64]
                    for leaf in leaves
                ):
                    continue
                row.enabled = False
                row.revoked_at = now
                row.revoke_reason = f"被真实事件推翻（{kind} 判定为真阳性），自动失效"
                revoked += 1
            db.commit()
    except Exception as exc:  # noqa: BLE001 — 回弹失败不能影响结论写回
        log.warning("误抑制回弹失败（%s）：%s", value, exc)
        return 0
    if revoked:
        invalidate_cache()
        log.warning("误抑制回弹：%s 上有 %d 条抑制被真实事件推翻并自动撤销", value[:64], revoked)
    return revoked


# ---------- 条目读写（界面与智能体同一套校验） ----------


def _item(row: AnalysisSuppression) -> dict[str, Any]:
    trial = dict(row.trial or {})
    return {
        "id": str(row.id),
        "name": row.name,
        "match": dict(row.match or {}),
        "fields": match_fields(row.match or {}),
        "dims": len(match_fields(row.match or {})),
        "mode": row.mode or MODE_SUPPRESS,
        "mode_label": (
            "完全不生成事件"
            if (row.mode or MODE_SUPPRESS) == MODE_SUPPRESS
            else "只不派工（事件保留）"
        ),
        "trial": trial,
        "reason_code": row.reason_code,
        "reason_label": REASON_CODES.get(row.reason_code, row.reason_code),
        "note": row.note,
        "evidence_refs": list(row.evidence_refs or []),
        "evidence_tools": int(row.evidence_tools or 0),
        "confidence": float(row.confidence or 0.0),
        "source_task_id": row.source_task_id or "",
        "created_by": row.created_by,
        "origin": row.origin,
        "enabled": bool(row.enabled),
        "hits": int(row.hits or 0),
        "last_hit_at": row.last_hit_at.isoformat() if row.last_hit_at else None,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "expired": bool(row.expires_at and row.expires_at <= datetime.now(UTC)),
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
        "revoke_reason": row.revoke_reason,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def evidence_tools_of(refs: list[str], tool_hits: dict[str, int] | None = None) -> int:
    """证据多样性：这些引用来自几种取数工具。

    引用本身只带 `es:<index>/<id>`，不带工具名，所以由调用方（MCP 层按会话的调用记录）
    传 `tool_hits`（工具名 → 引用数）。没传时退化为"引用条数"，
    即只看数量不区分来源 —— 界面手工建抑制时就是这个口径。
    """
    if tool_hits:
        return len({name for name, n in tool_hits.items() if n > 0 and name in _EVIDENCE_TOOLS})
    return len(set(refs)) if refs else 0


def validate_item(body: dict[str, Any], *, name: str = "") -> list[dict[str, str]]:
    """字段级校验（返回 `[{field, msg}]`，与规则页同一形状，前端一套渲染就够）。"""
    errors: list[dict[str, str]] = []
    label = str(body.get("name") or name or "").strip()
    if not label or len(label) > 128:
        errors.append({"field": "name", "msg": "名称必填，且不超过 128 字符"})
    errors.extend(validate_match(body.get("match")))
    reason = str(body.get("reason_code") or "").strip()
    if reason not in REASON_CODES:
        errors.append({"field": "reason_code", "msg": f"理由码只认：{'、'.join(REASON_CODES)}"})
    refs = body.get("evidence_refs") or []
    if not isinstance(refs, list):
        errors.append({"field": "evidence_refs", "msg": "证据引用要传数组"})
    else:
        need = min_refs()
        if str(body.get("origin") or ORIGIN_AGENT) == ORIGIN_AGENT and len(refs) < need:
            errors.append(
                {
                    "field": "evidence_refs",
                    "msg": f"智能体提交至少要 {need} 条证据引用（当前 {len(refs)}）",
                }
            )
    ttl = body.get("ttl_days")
    if ttl not in (None, ""):
        try:
            days = int(ttl)
        except (TypeError, ValueError):
            errors.append({"field": "ttl_days", "msg": "ttl_days 要传整数天"})
        else:
            if days < 1 or days > 30:
                errors.append({"field": "ttl_days", "msg": "ttl_days 只能在 1~30 天之间"})
    return errors


def create_item(
    body: dict[str, Any],
    *,
    created_by: str,
    origin: str = ORIGIN_AGENT,
    tool_hits: dict[str, int] | None = None,
) -> dict[str, Any]:
    """新建抑制条目：校验（含 G1~G6）→ 试算 → 定 mode → 落库。"""
    raw_match = body.get("match")
    match: dict[str, Any] = raw_match if isinstance(raw_match, dict) else {}
    refs = [str(x)[:200] for x in (body.get("evidence_refs") or [])][:20]
    tools_used = evidence_tools_of(refs, tool_hits)
    confidence = float(body.get("confidence") or 0.0)
    is_agent = origin != ORIGIN_UI

    if is_agent:
        # G4/G5 只对智能体自动提交生效；界面人工创建由人负责（但仍要 2 维 + 白名单）
        if tools_used < min_tools():
            raise ValueError(
                f"证据只来自 {tools_used} 种取数工具，至少要 {min_tools()} 种（防只看一段正文就下结论）"
            )
        if confidence < min_confidence():
            raise ValueError(f"置信度 {confidence:.2f} 低于门槛 {min_confidence():.2f}，不自动生效")
        age = phenomenon_age_hours(match)
        if age is not None and age < newcomer_hours():
            raise ValueError(
                f"该现象首见仅 {age:.1f} 小时，未满保护期 {newcomer_hours()} 小时，先积累观测"
            )
    trial = estimate_trial(match)
    mode = choose_mode(trial)
    downgrade = mode_downgrade(trial)
    # **拦得住才叫抑制**：条件树在近 N 天的命中事件上一条都匹配不到，说明
    # 字段写错了（常见：拿良性流量的 UA/URI 去写，而噪声那条规则的命中事件
    # 根本没有这些字段 —— 实测「TLS 握手失败风暴」的命中事件里没有 UA）。
    # 这种抑制一条也拦不住，却会让人以为"已经处理了"。要求把来源钉死
    # （src_ip）或用 rule 维度指出是哪条规则。
    # 只卡智能体自动提交：人工在界面建条目时自己负责（人知道自己在拦什么）。
    if (
        is_agent
        and int(trial.get("scanned_rows") or 0) > 0
        and int(trial.get("matched_rows") or 0) == 0
        and not _src_ips_of(match)
    ):
        raise ValueError(
            "你的条件在近 "
            f"{int(trial.get('days') or 0)} 天的命中事件里一条都匹配不到"
            f"（扫了 {int(trial.get('scanned_rows') or 0)} 条命中事件）—— "
            "抑制要匹配的是**触发噪声的那条规则的命中事件**："
            "加 rule 维度指出是哪条规则，或把 src_ip 精确到具体来源；"
            "别拿良性流量自己的字段（UA/URI）去写条件"
        )
    now = datetime.now(UTC)
    ttl = int(body.get("ttl_days") or default_ttl_days())
    ttl = max(1, min(30, ttl))
    name = str(body.get("name") or "").strip()[:128]
    with SessionLocal() as db:
        # **同名覆盖**：智能体收窄条件后用同名重提，就是把上一条改窄（而不是再堆一条半成品）。
        # 这是"自动生效闭环"的关键一环：降级 → 按建议收窄 → 同名重提 → 彻底生效。
        existing = db.scalars(
            select(AnalysisSuppression).where(AnalysisSuppression.name == name)
        ).first() if name else None
        if existing is not None:
            existing.match = match
            existing.mode = mode
            existing.trial = trial
            existing.reason_code = str(body.get("reason_code") or "").strip()[:32]
            existing.note = str(body.get("note") or "").strip()[:500]
            existing.evidence_refs = refs
            existing.evidence_tools = tools_used
            existing.confidence = confidence
            existing.source_task_id = str(body.get("source_task_id") or "")[:64]
            existing.created_by = str(created_by or "")[:64]
            existing.origin = origin if origin in (ORIGIN_AGENT, ORIGIN_UI) else ORIGIN_UI
            existing.enabled = True
            existing.revoked_at = None
            existing.revoke_reason = ""
            existing.expires_at = now + timedelta(days=ttl)
            existing.updated_at = now
            db.commit()
            db.refresh(existing)
            out = _item(existing)
            out["replaced"] = True
            out["downgrade"] = downgrade
            invalidate_cache()
            log.info(
                "更新精准抑制（同名覆盖）：%s（%s 维 mode=%s 试算 %s 条/%s 源/%s 网段，到期 %s）",
                out["name"],
                out["dims"],
                out["mode"],
                trial.get("events"),
                trial.get("srcs"),
                trial.get("segments"),
                out["expires_at"],
            )
            return out
        active = int(
            db.scalar(
                select(func.count())
                .select_from(AnalysisSuppression)
                .where(AnalysisSuppression.enabled.is_(True))
            )
            or 0
        )
        if active >= max_active():
            evicted = db.scalars(
                select(AnalysisSuppression)
                .where(AnalysisSuppression.enabled.is_(True))
                .order_by(AnalysisSuppression.expires_at.asc().nulls_last())
                .limit(active - max_active() + 1)
            ).all()
            for row in evicted:
                row.enabled = False
                row.revoked_at = now
                row.revoke_reason = f"超出活跃上限 {max_active()}，按最早到期淘汰"
            log.warning("抑制条目达上限 %d，淘汰 %d 条（最早的先走）", max_active(), len(evicted))
        row = AnalysisSuppression(
            name=str(body.get("name") or "").strip()[:128],
            match=match,
            mode=mode,
            trial=trial,
            reason_code=str(body.get("reason_code") or "").strip()[:32],
            note=str(body.get("note") or "").strip()[:500],
            evidence_refs=refs,
            evidence_tools=tools_used,
            confidence=confidence,
            source_task_id=str(body.get("source_task_id") or "")[:64],
            created_by=str(created_by or "")[:64],
            origin=origin if origin in (ORIGIN_AGENT, ORIGIN_UI) else ORIGIN_UI,
            enabled=True,
            expires_at=now + timedelta(days=ttl),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        out = _item(row)
        out["replaced"] = False
        out["downgrade"] = downgrade
    invalidate_cache()
    log.info(
        "新增精准抑制：%s（%s 维 mode=%s 试算 %s 条/%s 源/%s 网段，到期 %s）",
        out["name"],
        out["dims"],
        out["mode"],
        trial.get("events"),
        trial.get("srcs"),
        trial.get("segments"),
        out["expires_at"],
    )
    return out


def downgraded_items(*, limit: int = 50) -> list[dict[str, Any]]:
    """生效中但没真正生效（`record_only` 档）的条目：降级原因 + 收窄建议。

    闭环的补齐一环：降级不是终点。NDR 把这些条目当成一条待办派给智能体，
    让它自己按建议收窄后**同名重提**（同名覆盖）——而不是等人想起来。
    """
    try:
        with SessionLocal() as db:
            rows = db.scalars(
                select(AnalysisSuppression)
                .where(
                    AnalysisSuppression.enabled.is_(True),
                    AnalysisSuppression.mode == MODE_RECORD_ONLY,
                )
                .order_by(AnalysisSuppression.created_at.asc())
                .limit(max(1, int(limit or 50)))
            ).all()
            out: list[dict[str, Any]] = []
            for row in rows:
                trial = dict(row.trial or {})
                reason = mode_downgrade(trial)
                if not reason:
                    # 档位是历史遗留的（试算数据不在了）→ 仍然提醒一次，让它重新按最小面提
                    reason = {
                        "dimension": "unknown",
                        "actual": 0,
                        "limit": 0,
                        "reason": "该条目处于「只不派工」档，没有真正生效",
                        "advice": (
                            "按同类现象的最小匹配面重提：收窄到单个来源（src_ip 精确匹配）"
                            "+ 具体行为特征，用同一个 name 提交（同名覆盖）"
                        ),
                    }
                out.append(
                    {
                        "id": str(row.id),
                        "name": str(row.name or ""),
                        "mode": str(row.mode or MODE_RECORD_ONLY),
                        "trial": trial,
                        "downgrade": reason,
                        "source_task_id": str(row.source_task_id or ""),
                        "note": str(row.note or "")[:300],
                        "expires_at": row.expires_at.isoformat() if row.expires_at else "",
                    }
                )
            return out
    except Exception as exc:  # noqa: BLE001 — 读不到就当没有待办，不影响派工
        log.debug("读降级抑制清单失败: %s", exc)
        return []


def list_items(
    *,
    q: str = "",
    enabled_only: bool = False,
    include_expired: bool = False,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """抑制清单（按命中数降序：吞得多的最需要复核）。"""
    cap = max(1, min(int(limit or 100), 500))
    start = max(0, int(offset or 0))
    conds: list[Any] = []
    if enabled_only:
        conds.append(AnalysisSuppression.enabled.is_(True))
    if (q or "").strip():
        needle = f"%{str(q).strip()}%"
        conds.append(
            AnalysisSuppression.name.ilike(needle)
            | AnalysisSuppression.reason_code.ilike(needle)
            | AnalysisSuppression.note.ilike(needle)
        )
    try:
        with SessionLocal() as db:
            rows = db.scalars(
                select(AnalysisSuppression)
                .where(*conds)
                .order_by(AnalysisSuppression.hits.desc(), AnalysisSuppression.created_at.desc())
                .limit(cap)
                .offset(start)
            ).all()
            total = int(
                db.scalar(select(func.count()).select_from(AnalysisSuppression).where(*conds)) or 0
            )
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读抑制清单失败：{exc}", "items": [], "total": 0}
    items = [_item(r) for r in rows]
    if not include_expired:
        items = [i for i in items if not i["expired"]]
    return {
        "total": total,
        "returned": len(items),
        "items": items,
        "limits": {
            "max_active": max_active(),
            "min_match_dims": min_match_dims(),
            "min_refs": min_refs(),
            "min_tools": min_tools(),
            "min_confidence": min_confidence(),
            "default_ttl_days": default_ttl_days(),
            "hit_cap": hit_cap(),
        },
    }


def get_item(item_id: str) -> dict[str, Any]:
    try:
        with SessionLocal() as db:
            row = db.get(AnalysisSuppression, str(item_id or "").strip())
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读抑制条目失败：{exc}"}
    if row is None:
        return {"error": "抑制条目不存在"}
    return _item(row)


def set_enabled(item_id: str, *, enabled: bool, reason: str = "") -> dict[str, Any]:
    """启用/撤销。撤销留原因与时间（审计），缓存立刻失效。"""
    try:
        with SessionLocal() as db:
            row = db.get(AnalysisSuppression, str(item_id or "").strip())
            if row is None:
                return {"error": "抑制条目不存在"}
            row.enabled = bool(enabled)
            if not enabled:
                row.revoked_at = datetime.now(UTC)
                row.revoke_reason = str(reason or "")[:200]
            else:
                row.revoked_at = None
                row.revoke_reason = ""
            db.commit()
            db.refresh(row)
            out = _item(row)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"更新失败：{exc}"}
    invalidate_cache()
    return out


def update_item(item_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """改条件/理由/有效期：改了 match 就重新试算并按结果调 mode。"""
    with SessionLocal() as db:
        row = db.get(AnalysisSuppression, str(item_id or "").strip())
        if row is None:
            return {"error": "抑制条目不存在"}
        merged = {
            "name": body.get("name", row.name),
            "match": body.get("match", row.match),
            "reason_code": body.get("reason_code", row.reason_code),
            "evidence_refs": body.get("evidence_refs", row.evidence_refs),
            "ttl_days": body.get("ttl_days"),
            "origin": ORIGIN_UI,
        }
        errors = validate_item(merged, name=str(row.name))
        if errors:
            return {"field_errors": errors}
        row.match = merged["match"] if isinstance(merged["match"], dict) else row.match
        row.reason_code = str(merged["reason_code"] or "").strip()[:32]
        row.evidence_refs = [str(x)[:200] for x in (merged["evidence_refs"] or [])][:20]
        trial = estimate_trial(row.match or {})
        row.trial = trial
        row.mode = choose_mode(trial)
        ttl = merged.get("ttl_days")
        if ttl not in (None, ""):
            row.expires_at = datetime.now(UTC) + timedelta(days=max(1, min(30, int(ttl))))
        db.commit()
        db.refresh(row)
        out = _item(row)
    invalidate_cache()
    return out


def stats() -> dict[str, Any]:
    """总览：活跃/过期/撤销计数、累计抑制量、两种 mode 分布、当前门槛。"""
    now = datetime.now(UTC)
    try:
        with SessionLocal() as db:
            rows = db.scalars(select(AnalysisSuppression)).all()
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读抑制统计失败：{exc}"}
    active = expired = revoked = total_hits = 0
    by_mode: dict[str, int] = {MODE_SUPPRESS: 0, MODE_RECORD_ONLY: 0}
    for row in rows:
        is_expired = bool(row.expires_at and row.expires_at <= now)
        if row.enabled and not is_expired:
            active += 1
            key = row.mode or MODE_SUPPRESS
            by_mode[key] = by_mode.get(key, 0) + 1
        if is_expired:
            expired += 1
        if row.revoked_at is not None:
            revoked += 1
        total_hits += int(row.hits or 0)
    return {
        "enabled": enabled(),
        "auto_apply": auto_apply(),
        "active": active,
        "expired": expired,
        "revoked": revoked,
        "total": len(rows),
        "suppressed_total": total_hits,
        "by_mode": by_mode,
        "limits": {
            "max_active": max_active(),
            "min_match_dims": min_match_dims(),
            "min_refs": min_refs(),
            "min_tools": min_tools(),
            "min_confidence": min_confidence(),
            "default_ttl_days": default_ttl_days(),
            "hit_cap": hit_cap(),
            "trial_days": trial_days(),
            "trial_max_srcs": trial_max_srcs(),
            "trial_max_hits": trial_max_hits(),
            "trial_max_segments": trial_max_segments(),
            "newcomer_hours": newcomer_hours(),
        },
        "reason_codes": REASON_CODES,
        "allowed_fields": ALLOWED_FIELDS,
    }


# ---------- 参数面（形状与 /api/baseline/config 一致） ----------


def items() -> list[dict[str, Any]]:
    stored = overrides()
    out: list[dict[str, Any]] = []
    for knob in KNOBS:
        raw = stored.get(knob.key)
        out.append(
            {
                "key": knob.key,
                "label": knob.label,
                "kind": knob.kind,
                "default": knob.default,
                "low": knob.low,
                "high": knob.high,
                "unit": knob.unit,
                "note": knob.note,
                "overridden": raw not in (None, ""),
            }
        )
    return out


def effective() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for knob in KNOBS:
        if knob.kind == "bool":
            out[knob.key] = _flag(knob)
        elif knob.kind == "int":
            out[knob.key] = int(_num(knob))
        elif knob.kind == "float":
            out[knob.key] = _num(knob)
        else:
            out[knob.key] = str(rc_get(knob.key, knob.default))
    return out


def validate_config(values: dict[str, Any]) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    for key, value in (values or {}).items():
        knob = _BY_KEY.get(str(key))
        if knob is None:
            errors.append({"field": str(key), "msg": "不在可调参数里"})
            continue
        if knob.kind == "bool":
            if str(value).strip().lower() not in (
                "1",
                "0",
                "true",
                "false",
                "yes",
                "no",
                "on",
                "off",
                "是",
                "否",
            ):
                errors.append({"field": str(key), "msg": "要传布尔值"})
            continue
        try:
            number = float(value)
        except (TypeError, ValueError):
            errors.append({"field": str(key), "msg": "要传数字"})
            continue
        if knob.low is not None and number < float(knob.low):
            errors.append(
                {"field": str(key), "msg": f"不能小于 {knob.low}（最少匹配维度下限锁 2）"}
            )
        if knob.high is not None and number > float(knob.high):
            errors.append({"field": str(key), "msg": f"不能大于 {knob.high}"})
    return errors


def save_config(db: Any, values: dict[str, Any]) -> int:
    from app.db.models import SystemConfig

    written = 0
    for key, value in (values or {}).items():
        knob = _BY_KEY.get(str(key))
        if knob is None:
            continue
        row = db.get(SystemConfig, knob.key)
        coerced: Any = value
        if knob.kind in ("int", "float"):
            coerced = float(value)
        elif knob.kind == "bool":
            coerced = str(value).strip().lower() in ("1", "true", "yes", "on", "是")
        if row is None:
            db.add(SystemConfig(key=knob.key, value={"value": coerced}))
        else:
            row.value = {"value": coerced}
        written += 1
    db.commit()
    invalidate()
    invalidate_cache()
    return written


def reset_config(db: Any, keys: list[str] | None = None) -> int:
    from app.db.models import SystemConfig

    removed = 0
    for key in [k for k in (keys or list(EDITABLE_KEYS)) if k in _BY_KEY]:
        row = db.get(SystemConfig, key)
        if row is None:
            continue
        db.delete(row)
        removed += 1
    db.commit()
    invalidate()
    invalidate_cache()
    return removed
