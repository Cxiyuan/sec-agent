"""反馈学习：用智能体交回的结论调整客观强度，并把"判错方向"的抑制自动失效。

## 为什么必须有这一层

派工队列的强度是**客观统计量**（显著性、规模、首见、久未分析）。客观不等于有用：
同一现象如果连续被判 `false_positive`，说明它对**这个环境**没有信息量，继续按同样强度
派工就是白烧智能体的预算。反过来，被判过 `true_positive` 的对象/现象组合应该加权。

这一层就是把 `analysis_results` 里的真实判定回灌成强度系数，让"该看什么"随环境自我修正 ——
这是"AI 驱动"而不是"规则驱动"的落点。

## 三条纪律

1. **一次查询算完**：整张表按 `(subject, kind)` 聚合 verdict 分布，缓存复用；
   不能每生成一条线索就打一次库（检测器是常驻热路径）。
2. **只做系数、不做否决**：最狠也就是压到 0.4 倍，不会把线索清零 ——
   清零等于 NDR 又替智能体做了一次"这不用看"的判断，与 D2 冲突。真正要关掉走精准抑制。
3. **回弹要可见**：误抑制一旦被真实事件推翻，立即失效 + 计数 `suppression_rebound`，
   界面与 `task_stats` 都读得到（这是全自动抑制的自动纠错路径）。
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from app.analysis import params
from app.db.base import SessionLocal
from app.db.models import AnalysisResult
from app.workers.log import get_logger

#: 等价于 3.11 的 `datetime.UTC`（本仓库 requires-python >=3.11）；用别名写法
#: 免得按旧语法解析的静态检查工具报「unknown import symbol」。
UTC = timezone.utc

log = get_logger(__name__)

#: 系数区间：只衰减不否决（见模块 docstring 第 2 条纪律）
_MIN_FACTOR = 0.4
_MAX_FACTOR = 1.6
#: 系数表缓存时长：反馈是"按天线性回弹"的连续量，2 分钟刷新一次足够，
#: 不必为此每轮打库（检测器是常驻热路径）
_CACHE_TTL = 120.0
_cache: tuple[float, dict[tuple[str, str], float]] = (0.0, {})


def _fp_count(result: int) -> int:
    return max(0, int(result or 0))


def _factor(fp: int, tp: int, fp_age_days: float | None = None) -> float:
    """由真实判定算系数：误报越多压得越狠，判真过就加权，并随时间**线性回弹**。

    两段口径（对应方案 §6.6）：

    1. **按次数定地板**：1 次 0.85、2 次 0.7、3 次及以上 0.4（下限）。
       按次数而不是按比例：新对象只有 1 条误报记录时不该被直接压到地板。
    2. **随时间线性回弹**：判完立即处于地板，隔 `analysis.fp_decay_days` 天恢复 1.0。
       为什么必须回弹：环境和业务会变，一次误报不该永久压低某个对象 ——
       但也不能立刻恢复（那等于没学）。

    判真过（`tp`）就在结果上加权（`feedback_tp_factor`），真凭据优先于历史误报。
    """
    fp = _fp_count(fp)
    tp = _fp_count(tp)
    if not fp:
        factor = 1.0
    else:
        floor = {1: 0.85, 2: 0.7}.get(fp, _MIN_FACTOR)
        if fp_age_days is None:
            factor = floor
        else:
            window = max(1.0, float(params.fp_decay_days()))
            ratio = min(1.0, max(0.0, float(fp_age_days) / window))
            factor = floor + (1.0 - floor) * ratio
    if tp:
        factor = max(factor, params.feedback_tp_factor())
    return max(_MIN_FACTOR, min(_MAX_FACTOR, round(factor, 3)))


def _load(days: int) -> dict[tuple[str, str], float]:
    """一次 GROUP BY 把近 N 天的 verdict 分布换算成系数表 `(subject, kind) -> factor`。"""
    since = datetime.now(UTC) - timedelta(days=days)
    out: dict[tuple[str, str], float] = {}
    try:
        with SessionLocal() as db:
            rows = db.execute(
                select(
                    AnalysisResult.subject,
                    AnalysisResult.kind,
                    func.count().filter(AnalysisResult.verdict == "false_positive"),
                    func.count().filter(AnalysisResult.verdict == "true_positive"),
                    func.max(AnalysisResult.created_at).filter(
                        AnalysisResult.verdict == "false_positive"
                    ),
                )
                .where(AnalysisResult.created_at >= since)
                .group_by(AnalysisResult.subject, AnalysisResult.kind)
            ).all()
    except Exception as exc:  # noqa: BLE001 — 读不到就按"无历史"处理，不影响派工
        log.debug("读反馈历史失败（本次不加系数）: %s", exc)
        return out
    now = datetime.now(UTC)
    for subject, kind, fp, tp, last_fp in rows:
        key = (str(subject or ""), str(kind or ""))
        age_days: float | None = None
        if isinstance(last_fp, datetime):
            when = last_fp if last_fp.tzinfo else last_fp.replace(tzinfo=UTC)
            age_days = max(0.0, (now - when).total_seconds() / 86400.0)
        out[key] = _factor(int(fp or 0), int(tp or 0), age_days)
    return out


def factors(*, refresh: bool = False) -> dict[tuple[str, str], float]:
    """带 TTL 的系数表（默认 120 秒，比派工节拍长、比参数生效快）。"""
    global _cache
    now = time.monotonic()
    if not refresh and now - _cache[0] < _CACHE_TTL:
        return _cache[1]
    table = _load(params.feedback_days()) if params.feedback_enabled() else {}
    _cache = (now, table)
    return table


def invalidate() -> None:
    """交回结论后调用：下一轮就能用上新系数（不等 TTL）。"""
    global _cache
    _cache = (0.0, {})


def reset_cache() -> None:
    """测试用：强制丢掉系数表，避免用例之间互相污染。"""
    invalidate()


def apply(
    strength: float, kind: str, subject: str, table: dict[tuple[str, str], float] | None = None
):
    """给一条客观强度套上反馈系数（越界一律夹回区间）。"""
    if not params.feedback_enabled():
        return round(max(0.0, min(1.0, float(strength))), 3)
    mapping = factors() if table is None else table
    factor = mapping.get((str(subject or ""), str(kind or "")), 1.0)
    value = float(strength) * float(factor)
    return round(max(0.0, min(1.0, value)), 3)


def verdict_counts(subject: str) -> dict[str, int]:
    """某个对象的历史判定分布（界面/智能体判断"这类东西看过几次"）。"""
    since = datetime.now(UTC) - timedelta(days=params.feedback_days())
    try:
        with SessionLocal() as db:
            rows = db.execute(
                select(AnalysisResult.verdict, func.count())
                .where(AnalysisResult.subject == str(subject or ""))
                .where(AnalysisResult.created_at >= since)
                .group_by(AnalysisResult.verdict)
            ).all()
    except Exception as exc:  # noqa: BLE001
        log.debug("读判定分布失败: %s", exc)
        return {}
    return {str(v or ""): int(c or 0) for v, c in rows}


def note_verdict(kind: str, subject: str, verdict: str) -> dict[str, int]:
    """交回结论后记一笔，并触发误抑制回弹判定。

    回弹条件：本次判为 `true_positive`，且该对象身上还挂着**生效中的**精准抑制 ——
    说明那条抑制把真东西挡住了，立即撤销它（撤销原因写明是哪次判定推翻的）。
    """
    invalidate()
    if str(verdict or "") != "true_positive":
        return {"rebound": 0}
    from app.detector import suppression

    return {"rebound": suppression.rebound_for_subject(kind, subject)}
