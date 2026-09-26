"""误报治理策略：内外网方向 × 规则严重度 × 目标扇出 × 连接是否成功。

设计要点
- **判据只有这一份**：同一套规则要在三处使用 —— 检测器（摘要级打标）、图内实时入口、
  图内兜底入口。判据若各写一遍，就会出现"实时跳过了、兜底又捡回来"这类不一致（本项目踩过）。
- **全部环境无关**：内外网按"是否公网"判定，不写死任何客户网段/端口；阈值全部可配
  （后台「系统配置 → 误报治理」即时生效，见 runtime_config）。
- **绝不静默**：每个"跳过/降级"的决定都要返回可读理由，由调用方落库或计数。

三条策略（都可在后台关闭）：
1. 分级放行 —— 内网常规流量（内→内 + 低危逐条规则 + 单目标 + 无成功连接）只落库、不跑模型。
   *为什么不是"内→内一律不分析"：横向移动就藏在内→内，一刀切会致盲。*
2. 定级约束 —— 内→内封顶 medium；无证据链不得 ≥high；critical 仅限外→内。
3. 升级闸门 —— 进深度分析除分数达标外，还要求规则严重度 ≥medium 或 外→内。
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.config import settings
from app.runtime_config import get as runtime_get
from app.tools.context import is_public_ip
from app.workers.log import get_logger

log = get_logger(__name__)

# 策略跳过计数（跨重启可查）：与丢弃计数区分开
POLICY_STATS_KEY = "shentong:policy:stats"

# ---------- 方向 ----------

DIR_IN_TO_IN = "in→in"
DIR_IN_TO_OUT = "in→out"
DIR_OUT_TO_IN = "out→in"
DIR_OUT_TO_OUT = "out→out"
DIR_UNKNOWN = "unknown"  # 缺地址信息，不做方向判定（只保留证据约束）

SEVERITY_RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_RANK_TO_SEVERITY = {v: k for k, v in SEVERITY_RANK.items()}

# 视为"连接成功"的事件类型与 Zeek conn_state
SUCCESS_EVENT_TYPES = {"conn_established", "conn_http", "connection_shutdown"}
SUCCESS_CONN_STATES = {"SF", "S1", "S2", "S3", "RSTO", "RSTR"}


def _is_internal(ip: Any) -> bool:
    """是否内网地址（非公网）。地址缺失返回 False（不把脏数据当内网放行）。"""
    value = str(ip or "").strip()
    if not value:
        return False
    return not is_public_ip(value)


def direction_of(src_ip: Any, dst_ips: Any) -> str:
    """判定方向。

    目标集合里**只要有一个外网**就按外向处理（宁可多分析）；没有目标信息时返回
    ``unknown`` —— 不猜方向，只让证据约束生效（避免凭缺失信息把级别压下去）。
    """
    dst_list = [str(x) for x in (dst_ips or []) if x]
    if not dst_list:
        return DIR_UNKNOWN
    src_internal = _is_internal(src_ip)
    dst_has_external = any(not _is_internal(d) for d in dst_list)
    if dst_has_external:
        return DIR_IN_TO_OUT if src_internal else DIR_OUT_TO_OUT
    return DIR_IN_TO_IN if src_internal else DIR_OUT_TO_IN


def has_success(event_types: Any = None, conn_states: Any = None) -> bool:
    """是否出现过"成功连接"（用于区分探活/扫描 与 真正建立会话）。"""
    types = {str(x).lower() for x in (event_types or []) if x}
    if types & SUCCESS_EVENT_TYPES:
        return True
    states = {str(x).upper() for x in (conn_states or []) if x}
    return bool(states & SUCCESS_CONN_STATES)


# ---------- 配置读取（后台可改，即时生效） ----------


def _flag(key: str) -> bool:
    return bool(runtime_get(key, getattr(settings, key)))


def _num(key: str) -> float:
    try:
        return float(runtime_get(key, getattr(settings, key)))
    except (TypeError, ValueError):
        return float(getattr(settings, key))


def _text(key: str) -> str:
    return str(runtime_get(key, getattr(settings, key)) or "").strip().lower()


def _rank(value: Any) -> int:
    return SEVERITY_RANK.get(str(value or "info").strip().lower(), 0)


def _int_of(value: Any, default: int = 0) -> int:
    """安全转 int（值来自数据库/后台配置，可能是字符串或脏值）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return default


def _int_setting(key: str) -> int:
    return _int_of(runtime_get(key, getattr(settings, key)), 0)


def _severity_of(rank: int) -> str:
    return _RANK_TO_SEVERITY.get(max(0, min(rank, 4)), "info")


# ---------- 策略 1：分级放行 ----------


def internal_routine_reason(
    *,
    direction: str,
    rule_severity: Any,
    dst_count: int,
    success: bool,
) -> str | None:
    """内网常规流量 → 返回可读理由（调用方据此打标跳过）；该分析则返回 None。

    四个条件**全部满足**才跳过（任一不满足都照旧全量分析）：
    内→内、规则严重度 < 门槛、单目标、没有任何成功连接。
    """
    if not _flag("policy_internal_routine_skip"):
        return None
    if direction != DIR_IN_TO_IN:
        return None
    if _rank(rule_severity) >= _rank(_text("policy_internal_routine_min_severity")):
        return None
    dst_total = _int_of(dst_count, 0)
    if dst_total > _int_setting("policy_internal_routine_max_dst"):
        return None
    if success and _flag("policy_internal_routine_require_failed"):
        return None
    return (
        f"内网常规流量（{direction}，规则严重度 {rule_severity or 'info'}，"
        f"{dst_total} 个目标，无成功连接）"
    )


# ---------- 策略 2：定级约束 ----------


def cap_severity(
    *,
    severity: Any,
    direction: str,
    has_evidence: bool,
) -> tuple[str, str]:
    """把模型定级约束到合理范围，返回 (最终级别, 降级原因)；未降级时原因为空串。

    约束顺序：证据 → 方向 → critical 专属（取最严）。每条降级都写明原因，供界面展示。
    """
    rank = _rank(severity)
    original = _severity_of(rank)
    reasons: list[str] = []

    above = _text("severity_require_evidence_above")
    if not has_evidence and above in SEVERITY_RANK:
        cap = SEVERITY_RANK[above] - 1
        if rank > cap:
            rank = cap
            reasons.append("无可验证证据链")

    cap_text = _text("severity_cap_internal")
    if direction == DIR_IN_TO_IN and cap_text in SEVERITY_RANK:
        cap = SEVERITY_RANK[cap_text]
        if rank > cap:
            rank = cap
            reasons.append("内网方向封顶")

    if (
        _flag("severity_critical_requires_external")
        and direction != DIR_OUT_TO_IN
        and rank >= SEVERITY_RANK["critical"]
    ):
        rank = SEVERITY_RANK["high"]
        reasons.append("critical 仅限外→内")

    final = _severity_of(rank)
    if not reasons:
        return final, ""
    return final, f"{'；'.join(reasons)}（{original} → {final}）"


# ---------- 策略 3：升级闸门 ----------


def should_escalate(
    *,
    triage_score: float,
    rule_severity: Any,
    direction: str,
    threshold: float | None = None,
) -> bool:
    """是否进深度分析（回溯 + deep_analysis）。除分数外还要满足方向/规则门槛。

    现状只看分数，而小模型的分数几乎都过线（实测大量 0.85+）→ 等于全部升级，
    深度分析与案件随之爆量。这里加一道方向/严重度门槛。
    """
    if threshold is None:
        limit = _num("escalate_score_threshold")
    else:
        try:
            limit = float(threshold)
        except (TypeError, ValueError):
            limit = _num("escalate_score_threshold")
    try:
        if float(triage_score or 0.0) < limit:
            return False
    except (TypeError, ValueError):
        return False
    if direction == DIR_OUT_TO_IN and _flag("escalate_allow_external"):
        return True
    required = _text("escalate_require_rule_severity")
    if required not in SEVERITY_RANK:
        return True
    return _rank(rule_severity) >= SEVERITY_RANK[required]


# ---------- 计数（降噪绝不能是静默行为） ----------


def count_skip(client: Any, kind: str, count: int = 1) -> None:
    """把"策略跳过"计入 Redis（跨重启可查，界面上能看到数字与最后时间）。

    本项目的一条硬规定：每一个被丢掉/跳过的决定都要可查，否则事后无法回答
    "为什么这条事件没被分析"（历史上有过静默降噪失效的教训）。
    """
    if count <= 0:
        return
    try:
        client.hincrby(POLICY_STATS_KEY, kind, int(count))
        client.hset(POLICY_STATS_KEY, "last_at", datetime.now(UTC).isoformat())
        client.expire(POLICY_STATS_KEY, 30 * 24 * 3600)
    except Exception as exc:  # noqa: BLE001
        log.debug("写入策略计数失败: %s", exc)
