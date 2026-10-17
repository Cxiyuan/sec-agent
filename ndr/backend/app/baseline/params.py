"""基线与画像的运行时参数（后台「行为分析」页可改，最迟 30 秒生效）。

为什么要这一层：观测期 / σ / 风险阈值 / 时段的两个门槛 / 路径正则 / 保留期 这些原来直接读
`settings`（只能改 `.env` 再重启），但它们是**调参项** —— 运维应该能在界面上改、改完即时生效。
约定与仓库其它运行时配置一致（见 `app/runtime_config.py`）：`SystemConfig` 里有值就用它，
否则回落 `settings` 默认值，类型按默认值强转。

单一定义源：下面的 `KNOBS` 同时驱动「校验」「`GET/PUT /api/baseline/config`」与前端表单，
所以新增一个可调参数只需在这里加一行 —— 不用再改三处。

安全边界：
- 读侧每个存取器都做区间夹紧（脏值不会把运行时搞坏）；
- 写侧只允许 `KNOBS` 里列出的键（白名单），且正则要先编译通过。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from app.config import settings
from app.db.models import SystemConfig
from app.runtime_config import get, invalidate, overrides


@dataclass(frozen=True)
class Knob:
    """一个可调参数：键名、界面标签、类型、默认值（读自 settings，不重复写字面量）。"""

    key: str
    label: str
    kind: str  # int | float | bool | regex | text
    default: Any
    low: float | None = None
    high: float | None = None
    unit: str = ""
    note: str = field(default="")


KNOBS: tuple[Knob, ...] = (
    Knob(
        "baseline.enabled",
        "数值基线开关",
        "bool",
        settings.baseline_enabled,
        note="关掉则摘要不带数值 2σ 标签（画像仍可单独开）",
    ),
    Knob(
        "baseline.observe_days",
        "观测期",
        "int",
        settings.baseline_observe_days,
        low=0,
        high=365,
        unit="天",
        note="不足这么多天的维度只学习、不判偏离；0 = 立即参战（不建议）",
    ),
    Knob(
        "baseline.zscore",
        "偏离阈值",
        "float",
        settings.baseline_zscore,
        low=0.5,
        high=10.0,
        unit="σ",
        note="当前值 > 均值 + N 个标准差才算偏离",
    ),
    Knob(
        "baseline.flush_seconds",
        "落库节奏",
        "int",
        settings.baseline_flush_seconds,
        low=5,
        high=3600,
        unit="秒",
        note="画像观测与数值统计的批量入库间隔（也是判异常的节奏）",
    ),
    Knob(
        "baseline.cleanup_seconds",
        "清理节奏",
        "int",
        settings.baseline_cleanup_seconds,
        low=60,
        high=86400,
        unit="秒",
        note="过期画像清理 + 数值基线保留期清理 + 路径口径自愈的检查间隔",
    ),
    Knob(
        "baseline.retention_days",
        "数值基线保留",
        "int",
        settings.baseline_retention_days,
        low=1,
        high=3650,
        unit="天",
        note="按最近更新时间清理，避免被扫过一次的 IP 永久占行；必须大于观测期",
    ),
    Knob(
        "baseline.max_observations",
        "单窗口观测上限",
        "int",
        settings.baseline_max_observations,
        low=1000,
        high=1000000,
        unit="条",
        note="攒够这么多条就提前落库（防内存堆积）",
    ),
    Knob(
        "baseline.cache_max",
        "数值基线缓存",
        "int",
        settings.baseline_cache_max,
        low=1000,
        high=1000000,
        unit="个键",
        note="检测器进程内缓存上限，超出丢最旧的（会从库里重新捞）",
    ),
    Knob(
        "profile.enabled",
        "账号/会话画像开关",
        "bool",
        settings.profile_enabled,
        note="关掉则只算数值 2σ",
    ),
    Knob(
        "profile.min_obs",
        "冷启动门槛",
        "int",
        settings.profile_min_obs,
        low=1,
        high=100,
        unit="次",
        note="观测次数不足时只学习、不打分",
    ),
    Knob(
        "profile.risk_threshold",
        "异常阈值",
        "float",
        settings.profile_risk_threshold,
        low=0.0,
        high=1.0,
        note="风险分达到它才算异常、才写进摘要标签",
    ),
    Knob(
        "profile.risk_ttl_minutes",
        "当前风险有效期",
        "int",
        settings.profile_risk_ttl_minutes,
        low=0,
        high=1440,
        unit="分钟",
        note="超过这么久没被判过风险就不算「当前风险」（0 = 不限，当历史榜单看）",
    ),
    Knob(
        "profile.hour_min_coverage",
        "时段判据·覆盖门槛",
        "int",
        settings.profile_hour_min_coverage,
        low=1,
        high=24,
        unit="个时段",
        note="至少见过这么多个不同时段才判「非常用时段」（否则每个整点都误报）",
    ),
    Knob(
        "profile.hour_min_age_hours",
        "时段判据·画像年龄",
        "int",
        settings.profile_hour_min_age_hours,
        low=0,
        high=720,
        unit="小时",
        note="画像建立不足这么久不判时段（上线第一天必然全是「新时段」）",
    ),
    Knob(
        "profile.path_include_regex",
        "接口路径·只留",
        "regex",
        settings.profile_path_include_regex,
        note="留空 = 不按形态要求（默认）。填了则只记录命中它的路径",
    ),
    Knob(
        "profile.path_exclude_regex",
        "接口路径·排除",
        "regex",
        settings.profile_path_exclude_regex,
        note="默认排静态资源与页面后缀；命中即不记录/不判定",
    ),
    Knob(
        "profile.path_min_known",
        "接口路径·已知门槛",
        "int",
        settings.profile_path_min_known,
        low=0,
        high=100,
        unit="条",
        note="画像已知接口路径 ≥ 这么多条才判「新接口路径」",
    ),
    Knob(
        "profile.min_windows",
        "冷启动门槛（窗口数）",
        "int",
        settings.profile_min_windows,
        low=1,
        high=100,
        unit="个窗口",
        note="被观测到这么多个落库窗口才参与打分（按窗口、不按事件条数）",
    ),
    Knob(
        "profile.error_min_count",
        "错误响应·次数门槛",
        "int",
        settings.profile_error_min_count,
        low=1,
        high=1000000,
        unit="次",
        note="status ≥ 400（非 401/403）的次数达到它才判「错误响应突增」",
    ),
    Knob(
        "profile.error_ratio",
        "错误响应·占比门槛",
        "float",
        settings.profile_error_ratio,
        low=0.0,
        high=1.0,
        note="错误响应占本窗口事件的比例达到它才算异常",
    ),
    Knob(
        "profile.retention_days",
        "画像保留",
        "int",
        settings.profile_retention_days,
        low=1,
        high=3650,
        unit="天",
        note="长期无观测的画像到期删除",
    ),
)

_BY_KEY: dict[str, Knob] = {k.key: k for k in KNOBS}
EDITABLE_KEYS: tuple[str, ...] = tuple(_BY_KEY)


# ---------- 读：每个参数一个存取器（带区间夹紧） ----------


def _num(knob: Knob) -> float:
    value = get(knob.key, knob.default)
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = float(knob.default)
    if knob.low is not None:
        number = max(float(knob.low), number)
    if knob.high is not None:
        number = min(float(knob.high), number)
    return number


def _flag(knob: Knob) -> bool:
    value = get(knob.key, knob.default)
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on", "是")
    return bool(value)


def _text(knob: Knob) -> str:
    value = get(knob.key, knob.default)
    return str(value if value is not None else knob.default)


def baseline_enabled() -> bool:
    return _flag(_BY_KEY["baseline.enabled"])


def observe_days() -> int:
    return int(_num(_BY_KEY["baseline.observe_days"]))


def zscore() -> float:
    return _num(_BY_KEY["baseline.zscore"])


def flush_seconds() -> int:
    return int(_num(_BY_KEY["baseline.flush_seconds"]))


def cleanup_seconds() -> int:
    return int(_num(_BY_KEY["baseline.cleanup_seconds"]))


def retention_days() -> int:
    return int(_num(_BY_KEY["baseline.retention_days"]))


def max_observations() -> int:
    return int(_num(_BY_KEY["baseline.max_observations"]))


def cache_max() -> int:
    return int(_num(_BY_KEY["baseline.cache_max"]))


def profile_enabled() -> bool:
    return _flag(_BY_KEY["profile.enabled"])


def min_obs() -> int:
    return int(_num(_BY_KEY["profile.min_obs"]))


def min_windows() -> int:
    return max(1, int(_num(_BY_KEY["profile.min_windows"])))


def error_min_count() -> int:
    return max(1, int(_num(_BY_KEY["profile.error_min_count"])))


def error_ratio() -> float:
    return _num(_BY_KEY["profile.error_ratio"])


def risk_threshold() -> float:
    return _num(_BY_KEY["profile.risk_threshold"])


def risk_ttl_minutes() -> int:
    return int(_num(_BY_KEY["profile.risk_ttl_minutes"]))


def hour_min_coverage() -> int:
    return int(_num(_BY_KEY["profile.hour_min_coverage"]))


def hour_min_age_hours() -> int:
    return int(_num(_BY_KEY["profile.hour_min_age_hours"]))


def path_include_regex() -> str:
    return _text(_BY_KEY["profile.path_include_regex"])


def path_exclude_regex() -> str:
    return _text(_BY_KEY["profile.path_exclude_regex"])


def path_min_known() -> int:
    return int(_num(_BY_KEY["profile.path_min_known"]))


def profile_retention_days() -> int:
    return int(_num(_BY_KEY["profile.retention_days"]))


# ---------- 读：给界面用的整体快照 ----------


def _stored() -> dict[str, Any]:
    """库里实际存过的覆盖值（只含被改过的键）。"""
    stored = overrides()
    return {k: stored[k] for k in EDITABLE_KEYS if k in stored}


def effective() -> dict[str, Any]:
    """当前生效值（覆盖值优先，否则默认值）。"""
    out: dict[str, Any] = {}
    for knob in KNOBS:
        if knob.kind == "bool":
            out[knob.key] = _flag(knob)
        elif knob.kind in ("regex", "text"):
            out[knob.key] = _text(knob)
        elif knob.kind == "int":
            out[knob.key] = int(_num(knob))
        else:
            out[knob.key] = _num(knob)
    return out


def items() -> list[dict[str, Any]]:
    """给前端渲染表单：每个参数的类型/范围/默认值/当前值/是否被改过。"""
    stored = _stored()
    current = effective()
    rows: list[dict[str, Any]] = []
    for knob in KNOBS:
        rows.append(
            {
                "key": knob.key,
                "label": knob.label,
                "kind": knob.kind,
                "unit": knob.unit,
                "note": knob.note,
                "low": knob.low,
                "high": knob.high,
                "default": knob.default,
                "value": current[knob.key],
                "overridden": knob.key in stored,
            }
        )
    return rows


# ---------- 写：校验 + 落库 ----------


def validate(values: dict[str, Any]) -> list[dict[str, str]]:
    """返回字段错误清单（空 = 全部合法）。形态与仓库其它配置接口一致。"""
    errors: list[dict[str, str]] = []
    for key, raw in values.items():
        knob = _BY_KEY.get(key)
        if knob is None:
            errors.append({"field": key, "msg": f"未知参数：{key}"})
            continue
        if knob.kind == "bool":
            if isinstance(raw, str):
                if raw.strip().lower() not in (
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
                    errors.append({"field": key, "msg": "布尔值只能是 true/false"})
            elif not isinstance(raw, bool):
                errors.append({"field": key, "msg": "布尔值只能是 true/false"})
            continue
        if knob.kind in ("regex", "text"):
            text = "" if raw is None else str(raw)
            if knob.kind == "regex" and text.strip():
                try:
                    re.compile(text)
                except re.error as exc:
                    errors.append({"field": key, "msg": f"正则写错了：{exc}"})
            continue
        try:
            number = float(raw)
        except (TypeError, ValueError):
            errors.append({"field": key, "msg": "必须是数字"})
            continue
        if knob.kind == "int" and number != int(number):
            errors.append({"field": key, "msg": "必须是整数"})
            continue
        if knob.low is not None and number < knob.low:
            errors.append({"field": key, "msg": f"不得小于 {knob.low:g}{knob.unit}"})
        if knob.high is not None and number > knob.high:
            errors.append({"field": key, "msg": f"不得大于 {knob.high:g}{knob.unit}"})
    # 跨字段约束：数值基线保留期必须大于观测期，否则还没判过就被清掉
    merged = {**effective(), **{k: v for k, v in values.items() if k in _BY_KEY}}
    try:
        if int(float(merged["baseline.retention_days"])) <= int(
            float(merged["baseline.observe_days"])
        ):
            errors.append(
                {
                    "field": "baseline.retention_days",
                    "msg": "保留期必须大于观测期（否则还没判过就被清）",
                }
            )
    except (KeyError, TypeError, ValueError):
        pass
    return errors


def _coerce_bool(raw: Any, knob: Knob) -> bool:
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return _flag(knob)
    return str(raw).strip().lower() in ("1", "true", "yes", "on", "是")


def _coerce_value(knob: Knob, raw: Any) -> Any:
    """把提交上来的值转成该参数该有的类型（已在 validate 里查过合法性）。"""
    if knob.kind == "bool":
        return _coerce_bool(raw, knob)
    if knob.kind in ("regex", "text"):
        return "" if raw is None else str(raw)
    if knob.kind == "int":
        return int(float(raw))
    return float(raw)


def save(db: Session, values: dict[str, Any]) -> int:
    """把覆盖值写进 SystemConfig（`{"value": ...}`），并让缓存立即失效。"""
    written = 0
    for key, raw in values.items():
        knob = _BY_KEY.get(key)
        if knob is None:
            continue
        row = db.get(SystemConfig, key)
        if row is None:
            row = SystemConfig(key=key, value={})
            db.add(row)
        row.value = {"value": _coerce_value(knob, raw)}
        written += 1
    db.commit()
    invalidate()
    return written


def reset(db: Session, keys: list[str] | None = None) -> int:
    """恢复默认：删掉覆盖行（只删白名单里的键）。"""
    targets = [k for k in (keys or list(EDITABLE_KEYS)) if k in _BY_KEY]
    removed = 0
    for key in targets:
        row = db.get(SystemConfig, key)
        if row is not None:
            db.delete(row)
            removed += 1
    db.commit()
    invalidate()
    return removed
