"""分析机制的运行时参数（界面可改、30 秒生效，沿用 runtime_config 约定）。

预算为什么必须有：改造后智能体是"主动领取"，如果 NDR 不设上限，一次攻击面爆发就能把
它的会话数顶上天；反过来队列不设上限，pending 会无限增长。所以**两侧都有硬闸门**：
领取侧（每小时配额 + 并发 + 保留名额）、入队侧（队列容量 + 同族合并 + 强度替换）。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.runtime_config import get as rc_get, invalidate, overrides


@dataclass(frozen=True)
class Knob:
    """一个可调参数：键名、界面标签、类型、默认值、区间与说明。"""

    key: str
    label: str
    kind: str  # bool | int | float | text
    default: Any
    low: float | None = None
    high: float | None = None
    unit: str = ""
    note: str = ""


KNOBS: tuple[Knob, ...] = (
    Knob("analysis.enabled", "启用派工队列", "bool", True,
         note="关掉后不再生成新任务（已有任务保留，智能体仍可领取）"),
    Knob("analysis.candidate_kinds", "生成哪些线索", "text",
         "novelty,shift,coverage,hit",
         note="逗号分隔；structure 需额外统计，默认不开；关掉某类即不再生成该类任务"),
    Knob("analysis.rate_limit_per_hour_per_token", "单令牌每小时领取上限", "int", 20,
         low=1, high=10000, unit="个",
         note="成本上限的主要抓手：一个智能体令牌每小时最多领这么多任务"),
    Knob("analysis.rate_limit_per_hour_total", "全局每小时领取上限", "int", 120,
         low=1, high=100000, unit="个", note="所有令牌合计"),
    Knob("analysis.max_inflight_per_token", "单令牌并发在跑数", "int", 2,
         low=1, high=64, unit="个",
         note="超了直接返回 budget_exhausted（不排队占位），防止会话卡死把任务吊住"),
    Knob("analysis.reserved_slots_per_hour", "高强度保留名额", "int", 5,
         low=0, high=1000, unit="个",
         note="这些名额只给 strength≥0.8 的线索：预算用尽时最异常的事仍能插队（用户定的兜底）"),
    Knob("analysis.reserved_min_strength", "保留名额门槛", "float", 0.8,
         low=0.0, high=1.0, note="客观强度达到它才算「最异常」"),
    Knob("analysis.lease_seconds", "租约", "int", 900,
         low=60, high=7200, unit="秒",
         note="领取后多久没交回就自动回收（LLM 一次分析可能十几分钟，默认给 15 分钟）"),
    Knob("analysis.stuck_after_attempts", "反复不交回判定", "int", 5,
         low=1, high=50, unit="次",
         note="同一任务被领这么多次还没结论就置 stuck 并停止派发（界面可见，不静默）"),
    Knob("analysis.followup_depth", "追问链深度上限", "int", 2,
         low=0, high=8, unit="层",
         note="智能体可以追加活，但超深直接拒绝并说明原因（防任务自我繁殖）"),
    Knob("analysis.followup_max_per_task", "单任务追加上限", "int", 3,
         low=0, high=20, unit="个", note="一次 complete_task 最多派生多少追问"),
    Knob("analysis.queue_capacity", "队列容量", "int", 2000,
         low=10, high=200000, unit="条",
         note="pending+deferred 的硬上限；满了按强度替换或合并计数，绝不静默丢"),
    Knob("analysis.pending_ttl_hours", "线索有效期", "int", 48,
         low=1, high=720, unit="小时",
         note="超过就没分析价值（数据仍在 ES，只是不再打扰智能体）"),
    Knob("analysis.doorbell_cooldown_seconds", "门铃合并限频", "int", 180,
         low=0, high=3600, unit="秒",
         note="最多这么频繁地叫醒智能体；队列从空变非空时立即发一次（不受此限）"),
    Knob("analysis.doorbell_enabled", "启用门铃", "bool", True,
         note="关掉就完全靠智能体自轮询兜底"),
    Knob("analysis.coverage_stale_days", "盲区判定天数", "int", 7,
         low=1, high=365, unit="天",
         note="超过这么多天没被分析过的对象算 coverage 线索（低强度，不抢占）"),
    Knob("analysis.subject_retention_days", "首见登记表保留期", "int", 90,
         low=1, high=3650, unit="天",
         note="observed_subjects 按 last_seen_at 清理（表不许只增不减）"),
    Knob("analysis.feedback_enabled", "反馈学习", "bool", True,
         note="用智能体交回的结论调整客观强度（连续误报衰减、判真过加权），并触发误抑制回弹"),
    Knob("analysis.feedback_days", "反馈回看天数", "int", 14,
         low=1, high=365, unit="天",
         note="只用这段时间内的判定算系数：太短会被单次结论带偏，太长对环境变化不敏感"),
    Knob("analysis.fp_decay_days", "误报衰减回弹天数", "int", 7,
         low=1, high=90, unit="天",
         note="被判误报后强度按天数**线性回弹**：判完立即压到地板，隔这么多天恢复原值"),
    Knob("analysis.feedback_tp_factor", "判真过加权系数", "float", 1.25,
         low=1.0, high=2.0,
         note="该对象+现象被判过 true_positive 就把强度乘这个系数；误报衰减最低压到 0.4（只衰减不否决）"),
    Knob("analysis.dedupe_bucket_minutes", "去重时间桶", "int", 60,
         low=5, high=1440, unit="分钟",
         note="同一现象在这个时间桶内只排一条线索；调小更灵敏但队列会长，调大更省但可能压掉重复发生"),
    Knob("analysis.flush_seconds", "队列节拍", "int", 60,
         low=10, high=3600, unit="秒",
         note="生成线索 + 门铃 + 清理的最短间隔（与聚合窗口同量级）"),
    # ---- 借鉴 artex 双图机制的四个旋钮（锚点无需旋钮，上限是硬编码的）----
    Knob("analysis.digest_enabled", "冷摘要", "bool", True,
         note="把超过保留期的历史结论折叠成一句概览，保证 prior_findings 概览恒定大小"),
    Knob("analysis.digest_after_days", "多久算冷", "int", 30,
         low=1, high=365, unit="天",
         note="结论超过这么多天就折叠进摘要（原始行永不删除，detail=true 仍可下钻）"),
    Knob("analysis.retest_days", "复测间隔", "int", 30,
         low=1, high=365, unit="天",
         note="判过误报/良性且挂着抑制的对象，隔这么久重新复核一次（防止当时判错或环境已变）"),
    Knob("analysis.retest_max_per_round", "每轮复测上限", "int", 5,
         low=0, high=50, unit="个",
         note="复测是老对象的回头检查，不能挤掉新线索；0=关闭复测"),
    Knob("analysis.trace_retention_days", "过程轨迹保留期", "int", 60,
         low=1, high=365, unit="天",
         note="轨迹是派生线索，过期即清理（结论与原始数据不受影响）"),
)

_BY_KEY: dict[str, Knob] = {k.key: k for k in KNOBS}
EDITABLE_KEYS: tuple[str, ...] = tuple(_BY_KEY)

#: 已知的线索类型（校验与界面下拉用）
KINDS: tuple[str, ...] = ("novelty", "shift", "structure", "coverage", "hit", "retest")
#: 保留名额的客观强度门槛不能低于这个值（防止把门槛调到 0 让保留名额形同虚设）
_RESERVED_FLOOR = 0.5


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


def _text(knob: Knob) -> str:
    value = rc_get(knob.key, knob.default)
    return str(value if value is not None else knob.default)


def enabled() -> bool:
    return _flag(_BY_KEY["analysis.enabled"])


def doorbell_enabled() -> bool:
    return _flag(_BY_KEY["analysis.doorbell_enabled"])


def candidate_kinds() -> set[str]:
    """允许的线索类型（脏值忽略；全空则回落默认三类，避免"一个线索都不生成"）。"""
    raw = _text(_BY_KEY["analysis.candidate_kinds"]).lower()
    picked = {p.strip() for p in raw.split(",") if p.strip() in KINDS}
    return picked or {"novelty", "shift", "coverage", "hit"}


def rate_per_token_hour() -> int:
    return int(_num(_BY_KEY["analysis.rate_limit_per_hour_per_token"]))


def rate_total_hour() -> int:
    return int(_num(_BY_KEY["analysis.rate_limit_per_hour_total"]))


def max_inflight() -> int:
    return int(_num(_BY_KEY["analysis.max_inflight_per_token"]))


def reserved_slots() -> int:
    return int(_num(_BY_KEY["analysis.reserved_slots_per_hour"]))


def reserved_min_strength() -> float:
    # 硬下限：调低于 0.5 一律按 0.5（否则保留名额对谁都开放，等于没有兜底）
    return max(_RESERVED_FLOOR, _num(_BY_KEY["analysis.reserved_min_strength"]))


def lease_seconds() -> int:
    return int(_num(_BY_KEY["analysis.lease_seconds"]))


def stuck_after_attempts() -> int:
    return int(_num(_BY_KEY["analysis.stuck_after_attempts"]))


def followup_depth() -> int:
    return int(_num(_BY_KEY["analysis.followup_depth"]))


def followup_max_per_task() -> int:
    return int(_num(_BY_KEY["analysis.followup_max_per_task"]))


def queue_capacity() -> int:
    return int(_num(_BY_KEY["analysis.queue_capacity"]))


def pending_ttl_hours() -> int:
    return int(_num(_BY_KEY["analysis.pending_ttl_hours"]))


def doorbell_cooldown() -> int:
    return int(_num(_BY_KEY["analysis.doorbell_cooldown_seconds"]))


def coverage_stale_days() -> int:
    return int(_num(_BY_KEY["analysis.coverage_stale_days"]))


def subject_retention_days() -> int:
    return int(_num(_BY_KEY["analysis.subject_retention_days"]))


def flush_seconds() -> int:
    return int(_num(_BY_KEY["analysis.flush_seconds"]))


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
            out[knob.key] = _text(knob)
    return out


def validate(values: dict[str, Any]) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    for key, value in (values or {}).items():
        knob = _BY_KEY.get(str(key))
        if knob is None:
            errors.append({"field": str(key), "msg": "不在可调参数里"})
            continue
        if knob.kind == "bool":
            if str(value).strip().lower() not in (
                "1", "0", "true", "false", "yes", "no", "on", "off", "是", "否"
            ):
                errors.append({"field": str(key), "msg": "要传布尔值"})
            continue
        if knob.kind == "text":
            if not str(value or "").strip():
                errors.append({"field": str(key), "msg": "不能为空"})
            continue
        try:
            number = float(value)
        except (TypeError, ValueError):
            errors.append({"field": str(key), "msg": "要传数字"})
            continue
        if knob.low is not None and number < float(knob.low):
            errors.append({"field": str(key), "msg": f"不能小于 {knob.low}"})
        if knob.high is not None and number > float(knob.high):
            errors.append({"field": str(key), "msg": f"不能大于 {knob.high}"})
    return errors


def save(db: Any, values: dict[str, Any]) -> int:
    from app.db.models import SystemConfig

    written = 0
    for key, value in (values or {}).items():
        knob = _BY_KEY.get(str(key))
        if knob is None:
            continue
        coerced: Any = value
        if knob.kind in ("int", "float"):
            coerced = float(value)
        elif knob.kind == "bool":
            coerced = str(value).strip().lower() in ("1", "true", "yes", "on", "是")
        else:
            coerced = str(value)
        row = db.get(SystemConfig, knob.key)
        if row is None:
            db.add(SystemConfig(key=knob.key, value={"value": coerced}))
        else:
            row.value = {"value": coerced}
        written += 1
    db.commit()
    invalidate()
    return written


def reset(db: Any, keys: list[str] | None = None) -> int:
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
    return removed


def feedback_enabled() -> bool:
    return _flag(_BY_KEY["analysis.feedback_enabled"])


def feedback_days() -> int:
    return int(_num(_BY_KEY["analysis.feedback_days"]))


def feedback_tp_factor() -> float:
    return _num(_BY_KEY["analysis.feedback_tp_factor"])


def fp_decay_days() -> int:
    return int(_num(_BY_KEY["analysis.fp_decay_days"]))


def dedupe_bucket_minutes() -> int:
    return int(_num(_BY_KEY["analysis.dedupe_bucket_minutes"]))


def digest_enabled() -> bool:
    return _flag(_BY_KEY["analysis.digest_enabled"])


def digest_after_days() -> int:
    return int(_num(_BY_KEY["analysis.digest_after_days"]))


def retest_days() -> int:
    return int(_num(_BY_KEY["analysis.retest_days"]))


def retest_max_per_round() -> int:
    return int(_num(_BY_KEY["analysis.retest_max_per_round"]))


def trace_retention_days() -> int:
    return int(_num(_BY_KEY["analysis.trace_retention_days"]))
