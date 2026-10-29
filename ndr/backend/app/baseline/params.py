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
        "baseline.scheme",
        "数值基线判据",
        "text",
        settings.baseline_scheme,
        note="poisson=计数上尾检验（推荐）／zscore=旧的 mean+z·std（回滚用）",
    ),
    Knob(
        "baseline.alpha",
        "上尾显著性阈值",
        "float",
        settings.baseline_alpha,
        low=1e-9,
        high=0.2,
        note="越小越严；实际阈值会按特征数做 Bonferroni 校正（alpha/3）",
    ),
    Knob(
        "baseline.learn_source",
        "数值基线学习源",
        "text",
        settings.baseline_learn_source,
        note="window=按窗口学全量流量（推荐）／digest=只学命中规则的摘要（旧行为）",
    ),
    Knob(
        "baseline.pool_k",
        "等组池化强度",
        "float",
        settings.baseline_pool_k,
        low=0.0,
        high=1000.0,
        note="自身样本少时向 /24（v6 /64）先验收缩，相当于多少条虚拟样本；0=不池化",
    ),
    Knob(
        "baseline.deviation_cap_per_entity_hour",
        "单实体偏差上限",
        "int",
        settings.baseline_deviation_cap_per_entity_hour,
        low=0,
        high=1000,
        unit="次/小时",
        note="同一源 IP 每小时最多报几次数值偏离；0=不限",
    ),
    Knob(
        "baseline.deviation_cap_per_hour",
        "全局偏差上限",
        "int",
        settings.baseline_deviation_cap_per_hour,
        low=0,
        high=100000,
        unit="次/小时",
        note="全部实体的数值偏离每小时总上限；0=不限",
    ),
    Knob(
        "baseline.asset_shift_enabled",
        "资产基线判异",
        "bool",
        settings.baseline_asset_shift_enabled,
        note=(
            "被访问方资产（站点/服务）的窗口基线判异 → asset_shift 事实（D3）。"
            "默认关：先只学不判，观察一周假阳率再打开；回滚就是关回它"
        ),
    ),
    Knob(
        "baseline.asset_deviation_cap_per_entity_hour",
        "资产偏差上限",
        "int",
        settings.baseline_asset_deviation_cap_per_entity_hour,
        low=0,
        high=1000,
        unit="次/小时",
        note="同一资产每小时最多报几条 asset_shift；统计显著不等于值得人看，0=不限",
    ),
    Knob(
        "baseline.profile_anomaly_enabled",
        "画像异常进事实",
        "bool",
        settings.baseline_profile_anomaly_enabled,
        note=(
            "账号/会话画像过阈值异常（新源 IP、新 UA、新路径、非常用时段）发成 profile_anomaly "
            "事实（D4）。关掉后只在摘要标签里可见，不进入事实派工"
        ),
    ),
    Knob(
        "baseline.std_floor_ratio",
        "标准差下限（均值比例）",
        "float",
        settings.baseline_std_floor_ratio,
        low=0.0,
        high=1.0,
        note="标准差下限 = 均值×此值；恒定基线（std=0）靠它止血，不然多 1 个连接就报",
    ),
    Knob(
        "baseline.std_floor_min",
        "标准差下限（绝对值）",
        "float",
        settings.baseline_std_floor_min,
        low=0.0,
        high=1000.0,
        note="标准差下限的绝对底线（计数类特征用它兜住 0 均值）",
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
        "profile.scoring",
        "画像打分方式",
        "text",
        settings.profile_scoring,
        note="llr=似然比后验概率（默认，可排序）／additive=旧的层级加和分（回滚用）",
    ),
    Knob(
        "profile.prior_odds",
        "恶意会话先验概率",
        "float",
        settings.profile_prior_odds,
        low=1e-9,
        high=0.5,
        note="LLR 打分的先验：0.001 表示「千分之一的会话是恶意的」；有标注数据后校准替换",
    ),
    Knob(
        "profile.posterior_threshold",
        "后验概率阈值",
        "float",
        settings.profile_posterior_threshold,
        low=0.0,
        high=1.0,
        note="LLR 打分下后验概率达到它才算异常（默认 5%，约 1:20）",
    ),
    Knob(
        "profile.signal_damping",
        "弱信号折扣",
        "float",
        settings.profile_signal_damping,
        low=0.0,
        high=1.0,
        note="新 UA / 新接口路径 / 非常用时段 这类弱信号的合计分**乘这个折扣**",
    ),
    Knob(
        "profile.weak_cap_ratio",
        "弱信号封顶",
        "float",
        settings.profile_weak_cap_ratio,
        low=0.0,
        high=1.0,
        note="只有弱信号时风险分封顶在「阈值×此值」，保证弱信号叠加永远不过阈值",
    ),
    Knob(
        "profile.new_ip_min_share",
        "新源 IP 占比门槛",
        "float",
        settings.profile_new_ip_min_share,
        low=0.0,
        high=1.0,
        note="新源 IP 占本窗口来源地址的比例不足此值不计分（多出口/移动网常态）",
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
        "profile.false_positive_suppress_days",
        "误报降权窗口",
        "int",
        settings.profile_false_positive_suppress_days,
        low=0,
        high=365,
        unit="天",
        note="运维标过「误报」的实体/信号在这段时间内不再参与打分；0=不降权",
    ),
    Knob(
        "profile.novelty_max_count",
        "新颖度·已知门槛",
        "int",
        settings.profile_novelty_max_count,
        low=1,
        high=100,
        unit="次",
        note="一个值被见过这么多次就算已知，不再算「新」",
    ),
    Knob(
        "profile.high_cardinality_limit",
        "高基数降级门槛",
        "int",
        settings.profile_high_cardinality_limit,
        low=3,
        high=5000,
        unit="种",
        note="已知种类超过它就停止用「新/旧」判分（门户站点路径成百上千，没信号量）",
    ),
    Knob(
        "profile.ip_rarity_min_entities",
        "共享出口实体数门槛",
        "int",
        settings.profile_ip_rarity_min_entities,
        low=1,
        high=100000,
        unit="个",
        note="一个 /24 里出现这么多不同实体 → 判为共享出口（移动网/代理），新 IP 不计分",
    ),
    Knob(
        "profile.ip_rarity_enabled",
        "启用共享出口判定",
        "bool",
        settings.profile_ip_rarity_enabled,
        note="关闭后只看「已存满上限」这一个降权条件",
    ),
    Knob(
        "profile.entity_key",
        "会话画像实体键",
        "text",
        settings.profile_entity_key,
        note="device=按 UA+TLS 指纹（推荐，cookie 轮换不再拆画像）／cookie=旧行为",
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
    # ---------- 外连目的地基线（2026-10 用户口径） ----------
    Knob(
        "egress.enabled",
        "外连目的地基线",
        "bool",
        True,
        note="监控网段内全部 IP：首次/罕见的外连目标（IP/域名/端口）只产出事实，不下结论",
    ),
    Knob(
        "egress.rare_min",
        "罕见目标门槛",
        "int",
        3,
        low=2,
        high=100,
        unit="次",
        note="同一个目的地累计出现次数少于它，就仍算「罕见」（持续观察，不用首次就报）",
    ),
    Knob(
        "egress.learn_days",
        "白名单·自学习天数",
        "int",
        7,
        low=1,
        high=90,
        unit="天",
        note="稳定出现至少这么多天（且次数达标）才自动进白名单；人工删除的条目不会再学",
    ),
    Knob(
        "egress.learn_occurrences",
        "白名单·自学习次数",
        "int",
        20,
        low=2,
        high=10000,
        unit="次",
        note="与天数同时满足才自动入白名单",
    ),
    Knob(
        "egress.auto_allow",
        "自动入白名单",
        "bool",
        settings.egress_auto_allow,
        note=(
            "稳定出现足够久/足够多次的目的地自动放行（D5，2026-10-29 起**默认关闭**）。"
            "关闭时白名单只能人工新增；开启也有护栏：目标有真阳性/可疑结论、"
            "或被待办任务跟踪时绝不学习"
        ),
    ),
    Knob(
        "egress.sustained_minutes",
        "持续跟踪频率",
        "int",
        60,
        low=15,
        high=1440,
        unit="分钟",
        note=(
            "未被判定的外连目标按这个频率持续产出 egress_sustained 事实（强度≥0.45），"
            "避免首次任务漏掉后彻底静默（D5）"
        ),
    ),
    # ---------- 账号地理 / 爆破 / 404 ----------
    Knob(
        "profile.geo_enabled",
        "账号异地登录",
        "bool",
        True,
        note="与「上一次成功登录的公网 IP」比国家+省；局域网登录只标记、不比较也不更新",
    ),
    Knob(
        "profile.brute_account_ips",
        "同账号多来源门槛",
        "int",
        5,
        low=2,
        high=100,
        unit="个公网 IP",
        note="同一账号在窗口内被这么多个不同公网 IP 尝试登录（失败）才产出事实",
    ),
    Knob(
        "profile.brute_account_fails",
        "同账号失败次数门槛",
        "int",
        20,
        low=2,
        high=10000,
        unit="次",
        note="与多来源同时满足才产出事实",
    ),
    Knob(
        "profile.path_probe_min_requests",
        "404 探测·请求量门槛",
        "int",
        30,
        low=5,
        high=100000,
        unit="次",
        note="单客户端窗口内至少这么多请求，才判「大量 404」",
    ),
    Knob(
        "profile.path_probe_404_ratio",
        "404 探测·占比门槛",
        "float",
        0.5,
        low=0.1,
        high=1.0,
        note="404 占该客户端请求的比例达到它才产出事实",
    ),
    Knob(
        "profile.session_retention_days",
        "会话画像保留",
        "int",
        7,
        low=1,
        high=180,
        unit="天",
        note="会话画像（cookie 哈希）只留最近这么多天；账号画像不受影响",
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


def egress_enabled() -> bool:
    return _flag(_BY_KEY["egress.enabled"])


def egress_rare_min() -> int:
    return int(_num(_BY_KEY["egress.rare_min"]))


def egress_learn_days() -> int:
    return int(_num(_BY_KEY["egress.learn_days"]))


def egress_learn_occurrences() -> int:
    return int(_num(_BY_KEY["egress.learn_occurrences"]))


def egress_auto_allow() -> bool:
    return _flag(_BY_KEY["egress.auto_allow"])


def egress_sustained_minutes() -> int:
    return int(_num(_BY_KEY["egress.sustained_minutes"]))


def geo_enabled() -> bool:
    return _flag(_BY_KEY["profile.geo_enabled"])


def brute_account_ips() -> int:
    return int(_num(_BY_KEY["profile.brute_account_ips"]))


def brute_account_fails() -> int:
    return int(_num(_BY_KEY["profile.brute_account_fails"]))


def path_probe_min_requests() -> int:
    return int(_num(_BY_KEY["profile.path_probe_min_requests"]))


def path_probe_404_ratio() -> float:
    return _num(_BY_KEY["profile.path_probe_404_ratio"])


def session_retention_days() -> int:
    return int(_num(_BY_KEY["profile.session_retention_days"]))


def baseline_enabled() -> bool:
    return _flag(_BY_KEY["baseline.enabled"])


def observe_days() -> int:
    return int(_num(_BY_KEY["baseline.observe_days"]))


def zscore() -> float:
    return _num(_BY_KEY["baseline.zscore"])


def std_floor_ratio() -> float:
    return _num(_BY_KEY["baseline.std_floor_ratio"])


def std_floor_min() -> float:
    return _num(_BY_KEY["baseline.std_floor_min"])


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


def knob(key: str) -> Any:
    """按白名单键名读一个参数的**生效值**（类型按 Knob 定义强转）。

    给"只在个别分支用到"的参数用，省得为每个 Knob 都配一个存取器；
    键不在白名单里返回 `None`（不抛异常，调用方自己给默认值）。
    """
    entry = _BY_KEY.get(str(key or "").strip())
    if entry is None:
        return None
    if entry.kind == "bool":
        return _flag(entry)
    if entry.kind == "int":
        return int(_num(entry))
    if entry.kind == "float":
        return _num(entry)
    return _text(entry)


def entity_key() -> str:
    """会话画像的实体键口径：`device`（默认，UA+TLS 指纹）或 `cookie`（旧行为）。"""
    value = _text(_BY_KEY["profile.entity_key"]).strip().lower()
    return value if value in ("device", "cookie") else "device"


def scoring() -> str:
    """画像打分方式：`llr`（默认，后验概率）或 `additive`（旧的层级加和分）。"""
    value = _text(_BY_KEY["profile.scoring"]).strip().lower()
    return value if value in ("llr", "additive") else "llr"


def prior_odds() -> float:
    """恶意会话的先验概率（不是 odds 的比值，是 P(恶意) 本身）。"""
    return min(0.5, max(1e-9, _num(_BY_KEY["profile.prior_odds"])))


def posterior_threshold() -> float:
    return min(1.0, max(0.0, _num(_BY_KEY["profile.posterior_threshold"])))


def alert_threshold() -> float:
    """当前打分方式下的告警线。

    两种打分的数值空间**不可混用**：加和分的 0.75 是「加权和」，后验概率的 0.05 是
    「1:20 的胜算」。所有比较阈值的地方都必须走这个函数，否则一换开关就全都不报了。
    """
    return posterior_threshold() if scoring() == "llr" else risk_threshold()


def signal_damping() -> float:
    return _num(_BY_KEY["profile.signal_damping"])


def weak_cap_ratio() -> float:
    return _num(_BY_KEY["profile.weak_cap_ratio"])


def new_ip_min_share() -> float:
    return _num(_BY_KEY["profile.new_ip_min_share"])


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


def scheme() -> str:
    """数值基线判据：`poisson`（默认）或 `zscore`。脏值一律回落 poisson。"""
    value = _text(_BY_KEY["baseline.scheme"]).strip().lower()
    return value if value in ("poisson", "zscore") else "poisson"


def alpha() -> float:
    return _num(_BY_KEY["baseline.alpha"])


def learn_source() -> str:
    """学习源：`window`（默认，按窗口学全量）或 `digest`（旧行为）。"""
    value = _text(_BY_KEY["baseline.learn_source"]).strip().lower()
    return value if value in ("window", "digest") else "window"


def pool_k() -> float:
    return _num(_BY_KEY["baseline.pool_k"])


def deviation_cap_per_entity_hour() -> int:
    return int(_num(_BY_KEY["baseline.deviation_cap_per_entity_hour"]))


def deviation_cap_per_hour() -> int:
    return int(_num(_BY_KEY["baseline.deviation_cap_per_hour"]))


def asset_shift_enabled() -> bool:
    return _flag(_BY_KEY["baseline.asset_shift_enabled"])


def asset_deviation_cap_per_entity_hour() -> int:
    return int(_num(_BY_KEY["baseline.asset_deviation_cap_per_entity_hour"]))


def profile_anomaly_enabled() -> bool:
    return _flag(_BY_KEY["baseline.profile_anomaly_enabled"])


def novelty_max_count() -> int:
    return max(1, int(_num(_BY_KEY["profile.novelty_max_count"])))


def high_cardinality_limit() -> int:
    return max(3, int(_num(_BY_KEY["profile.high_cardinality_limit"])))


def ip_rarity_min_entities() -> int:
    return max(1, int(_num(_BY_KEY["profile.ip_rarity_min_entities"])))


def ip_rarity_enabled() -> bool:
    return _flag(_BY_KEY["profile.ip_rarity_enabled"])
