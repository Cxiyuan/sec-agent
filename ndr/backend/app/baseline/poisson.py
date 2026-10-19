"""计数数据的显著性检验（泊松 / 负二项上尾），**纯标准库、不引入 scipy**。

## 为什么不用 z-score

数值基线原来的判据是 `value > mean + z*std`。对**计数型**数据这个判据在两端都错：

- `std` 极小时（生产实测 54.6% 的键 `std < 10%·mean`，32% `std = 0`）2σ 带极窄，
  正常波动就过线；`std = 0` 时更荒唐 —— "比均值多 1 个连接"就算偏离。
- 计数数据的方差天然随均值增长（泊松：`var = mean`），用固定倍数的 std 等于对不同量级
  的实体用不同灵敏度。

换成**上尾概率检验**：给定历史均值 λ（与离散度），问"这次观测到 x 或更大"的概率有多小。
小到 `alpha` 以下才算偏离。小均值天然被保护（λ=1.1 时要 x≥7 才显著），`std=0` 的边界
问题也自动消失（恒定序列由分布决定显著性，不是由 std 决定）。

## 为什么手写而不用 scipy

scipy 会带来 numpy 依赖（镜像 +100MB）。这里只需要两个上尾概率，用 `math.lgamma`
算对数项、累加上尾和即可，精度对本用途（判断 p < 1e-3）足够。
"""

from __future__ import annotations

import math

#: 级数累加的最大项数（防止病态参数下死循环；未收敛时按"不显著"处理，宁漏不炸）
_MAX_TERMS = 20000
#: 泊松上尾求和精度：项小于这个比例就停
_EPS = 1e-18


def poisson_sf(k: float, lam: float) -> float:
    """泊松上尾 `P(X >= k)`，`X ~ Poisson(lam)`。

    `k` 允许是浮点（观测值可能是 3.0 这种），按 `ceil(k)` 处理。
    `lam <= 0` 时退化成"只要 k>0 就必然偏离"——由调用方决定要不要用，这里返回 0/1。
    """
    if k <= 0:
        return 1.0
    if lam <= 0:
        return 0.0
    x = math.ceil(k)  # math.ceil 已返回 int
    # log P(X = x) = -lam + x*ln(lam) - lgamma(x+1)
    log_term = -lam + x * math.log(lam) - math.lgamma(x + 1)
    if log_term > 700:  # 数值上溢保护：直接用对数累加
        return 0.0
    term = math.exp(log_term)
    total = 0.0
    for i in range(x, x + _MAX_TERMS):
        total += term
        if term <= total * _EPS:
            break
        # P(X=i+1) = P(X=i) * lam / (i+1)
        term *= lam / (i + 1)
    return min(1.0, total)


def nb_sf(k: float, lam: float, var: float) -> float:
    """负二项上尾 `P(X >= k)`（均值 `lam`、方差 `var > lam`），用于过分散的计数数据。

    参数化：`r = lam^2 / (var - lam)`、`p = r / (r + lam)`，此时
    `NB(r, p)` 的均值正好是 `lam`、方差是 `lam + lam^2/r = var`。

    级数在 `1-p` 接近 1（r 很小）时收敛慢；超过 `_MAX_TERMS` 仍未收敛就返回
    "不显著"（1.0）——宁可漏报也不制造误报。
    """
    if k <= 0:
        return 1.0
    if lam <= 0:
        return 0.0
    extra = var - lam
    if extra <= 0:
        return poisson_sf(k, lam)
    r = (lam * lam) / extra
    if r <= 0 or not math.isfinite(r):
        return poisson_sf(k, lam)
    p = r / (r + lam)
    if not (0.0 < p <= 1.0):
        return poisson_sf(k, lam)
    log_p = math.log(p)
    log_q = math.log1p(-p) if p < 1.0 else -math.inf
    x = math.ceil(k)  # math.ceil 已返回 int
    # log P(X=x) = lgamma(x+r) - lgamma(r) - lgamma(x+1) + r*ln p + x*ln(1-p)
    log_term = math.lgamma(x + r) - math.lgamma(r) - math.lgamma(x + 1) + r * log_p + x * log_q
    if not math.isfinite(log_term) or log_term > 700:
        return 0.0
    term = math.exp(log_term)
    total = 0.0
    for i in range(x, x + _MAX_TERMS):
        total += term
        if term <= total * _EPS:
            return min(1.0, total)
        # P(X=i+1)/P(X=i) = (i+r)/(i+1) * (1-p)
        term *= ((i + r) / (i + 1)) * (1.0 - p)
        if term == 0.0:
            return min(1.0, total)
    # 未收敛：不判异常（保守）
    return 1.0


def count_p_value(
    value: float,
    *,
    mean: float,
    var: float = 0.0,
    overdispersion_ratio: float = 2.0,
) -> float:
    """统一入口：按离散度自动在泊松与负二项之间选（`var > ratio*mean` → 负二项）。"""
    lam = max(0.0, float(mean))
    if lam <= 0:
        return 1.0 if value <= 0 else 0.0
    v = max(0.0, float(var))
    if v > overdispersion_ratio * lam:
        return nb_sf(value, lam, v)
    return poisson_sf(value, lam)


def bonferroni_alpha(alpha: float, tests: int) -> float:
    """多重比较校正：一次判定里做了 `tests` 个检验，单检验阈值要相应收紧。

    生产实测基数极大（3,345 个 IP × 3 特征 × 288 窗口/天），不做校正时
    `alpha=1e-3` 也会带来每天几千次假偏离。
    """
    if tests <= 1:
        return float(alpha)
    return float(alpha) / float(tests)
