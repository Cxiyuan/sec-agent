"""批 2（算法改造）的守卫：泊松/负二项检验、独立采样通道、LLR 后验、参数生效。

对应《XDR行为分析算法改造实施方案》里经复核**可落地**的部分，同时守住我们改动时
踩过的坑：多重比较校正、信号相关性、不引入 scipy 重依赖、限额闸门。
"""

from __future__ import annotations

import importlib
import math
import pathlib
from typing import Any

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _mod(name: str) -> Any:
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError:  # pragma: no cover - agent 栈没有 baseline 模块
        pytest.skip(f"该栈没有 {name}（属 NDR 侧）")


# ===== ① 泊松上尾：小均值天然保护、std=0 边界消失 =====


def test_poisson_tail_matches_known_values() -> None:
    """P(X>=x) 的数值要与手算/常识一致（lam=1.1 时 x=1 必然接近 1，x=7 已经很小）。"""
    p = _mod("app.baseline.poisson")
    assert p.poisson_sf(0, 1.1) == 1.0
    assert p.poisson_sf(1, 1.1) > 0.6
    assert p.poisson_sf(7, 1.1) < 1e-3
    # 大均值时尾部更尖：lam=50 时 x=50 大约 0.5
    assert 0.3 < p.poisson_sf(50, 50) < 0.7
    # 与解析式对照：P(X>=1) = 1 - e^-lam
    lam = 3.0
    assert abs(p.poisson_sf(1, lam) - (1 - math.exp(-lam))) < 1e-9


def test_poisson_protects_small_means() -> None:
    """均值 1.1 时 4 个目的 IP 不该算异常（旧的 2σ≈3.1 会报，这是主要误报源之一）。"""
    p = _mod("app.baseline.poisson")
    assert p.poisson_sf(4, 1.1) > 1e-2, "4 个目的 IP 在上尾看来还很常见"
    assert p.poisson_sf(7, 1.1) < 1e-3, "7 个才算显著"


def test_zero_variance_no_longer_fires_on_plus_one() -> None:
    """恒定基线（std=0）下"多 1 个连接"不能算偏离 —— 这是 32% 的键面广的误报形态。"""
    p = _mod("app.baseline.poisson")
    # 恒定 5：看到 6 很常见，看到 20 才异常
    assert p.count_p_value(6, mean=5, var=0) > 0.1
    assert p.count_p_value(20, mean=5, var=0) < 1e-3


def test_overdispersion_switches_to_negative_binomial() -> None:
    """方差远大于均值时走负二项，尾部更厚（同样观测值 p 更大 = 更不容易报）。"""
    p = _mod("app.baseline.poisson")
    poisson_p = p.count_p_value(30, mean=5, var=5)
    nb_p = p.count_p_value(30, mean=5, var=200)
    assert nb_p > poisson_p


def test_bonferroni_tightens_alpha() -> None:
    p = _mod("app.baseline.poisson")
    assert p.bonferroni_alpha(1e-3, 1) == 1e-3
    assert abs(p.bonferroni_alpha(1e-3, 5) - 2e-4) < 1e-12


def test_no_scipy_dependency() -> None:
    """上尾检验必须手写：scipy 会带来 numpy（镜像 +100MB），本项目零科学计算依赖。"""
    src = (ROOT / "ndr" / "backend" / "app" / "baseline" / "poisson.py").read_text(encoding="utf-8")
    # 只看**真实导入语句**：文档里提到"不引入 scipy"是说明，不是依赖
    code_lines = [
        line.strip() for line in src.splitlines() if line.strip().startswith(("import ", "from "))
    ]
    assert not [ln for ln in code_lines if "scipy" in ln or "numpy" in ln]
    pyproject = (ROOT / "ndr" / "backend" / "pyproject.toml").read_text(encoding="utf-8")
    for dep in ("scipy", "numpy", "scikit-learn"):
        assert dep not in pyproject, f"{dep} 不该进依赖"


# ===== ② 独立采样通道 =====


class FakeEntry:
    def __init__(self, src: str, dst: str = "", port: str = "") -> None:
        self.src_ip = src
        self.dst_ip = dst
        self.dst_port = port


def test_sampler_counts_every_event_not_just_rule_hits() -> None:
    """采样要覆盖**全量**事件：同一 IP 三条事件 → conn_count=3（与是否命中规则无关）。"""
    mod = _mod("app.baseline.sampler")
    s = mod.WindowSampler(window_seconds=300)
    for _ in range(3):
        s.observe(FakeEntry("10.0.0.1", "10.0.0.9", "443"), now=1000.0)
    s.observe(FakeEntry("10.0.0.2", "10.0.0.8", "80"), now=1001.0)
    assert s.due(now=1000.0) is False, "窗口未到期不出样"
    samples = s.pop_ready(now=1400.0)
    got = {x["src_ip"]: x for x in samples}
    assert got["10.0.0.1"]["conn_count"] == 3.0
    assert got["10.0.0.1"]["distinct_dst_ips"] == 1.0
    assert got["10.0.0.2"]["conn_count"] == 1.0
    assert s.pop_ready(now=1400.0) == [], "出样后要重置"


def test_sampler_caps_memory_for_proxies() -> None:
    """代理出口会碰几千个目的地址：集合必须封顶，并打 truncated 标记（不静默截断）。"""
    mod = _mod("app.baseline.sampler")
    s = mod.WindowSampler(window_seconds=1, max_distinct=5)
    for i in range(50):
        s.observe(FakeEntry("10.0.0.1", f"10.9.0.{i}"), now=1000.0)
    samples = s.pop_ready(now=1100.0)
    assert samples[0]["distinct_dst_ips"] == 5.0
    assert samples[0]["truncated"] is True


def test_sampler_skips_empty_src() -> None:
    mod = _mod("app.baseline.sampler")
    s = mod.WindowSampler(window_seconds=1)
    s.observe(FakeEntry(""), now=1000.0)
    s.observe(FakeEntry("-"), now=1000.0)
    assert s.pop_ready(now=1100.0) == []


# ===== ③ 学习通道：窗口样本进基线，且不再从摘要重复学习 =====


def test_engine_learns_from_window_samples() -> None:
    """`observe_window()` 把样本攒进待落库队列（学习通道），不改判异结果。"""
    engine_mod = _mod("app.baseline.engine")
    eng = engine_mod.BaselineEngine(client=None)
    eng.observe_window(
        {
            "src_ip": "10.0.0.1",
            "conn_count": 7.0,
            "distinct_dst_ports": 2.0,
            "distinct_dst_ips": 3.0,
        }
    )
    keys = set(eng._pending)
    assert "10.0.0.1:conn_count" in keys
    assert "10.0.0.1:distinct_dst_ips" in keys
    # 组先验一起学（池化用）
    assert any(k.startswith("grp:10.0.0.0/24:") for k in keys)


def test_group_prefix_families() -> None:
    engine_mod = _mod("app.baseline.engine")
    gp = engine_mod.group_prefix
    assert gp("10.1.2.3") == "10.1.2.0/24"
    assert gp("2409:1:2:3:4:5:6:7").startswith("2409:1:2:3")
    assert gp("") == "" and gp("-") == ""


def test_pooling_shrinks_sparse_entity_toward_group() -> None:
    """单观测实体要大幅向组先验收缩（这是"48.7% 只观测过 1 次"的解药）。"""
    engine_mod = _mod("app.baseline.engine")
    own = {"count": 1, "mean": 100.0, "m2": 0.0, "std": 0.0}
    group = {"count": 200, "mean": 5.0, "m2": 2000.0, "std": 3.17}
    mean, _var = engine_mod.pooled_lambda(own, group, k=20)
    assert mean < 15.0, "n=1 时组先验应占主导"
    own2 = {"count": 500, "mean": 100.0, "m2": 5000.0, "std": 3.16}
    mean2, _v2 = engine_mod.pooled_lambda(own2, group, k=20)
    assert mean2 > 90.0, "样本多了就该以自身为主"


# ===== ④ LLR 后验：分组去相关、可排序、真信号仍过线 =====


def test_llr_decorrelates_same_group_signals() -> None:
    """同组信号（都是"换设备"）只取最强的一条，不能叠加放大。"""
    prof = _mod("app.baseline.profile")
    only_ip = prof.posterior_of(["new_src_ip"])["posterior"]
    both = prof.posterior_of(["new_src_ip", "new_ua"])["posterior"]
    # new_ua 属 device 组、new_src_ip 属 network 组 → 跨组相加（应更大）
    assert both > only_ip
    # 同组的 cross_ip + new_src_ip 只取最大，不翻倍
    same = prof.posterior_of(["cross_ip", "new_src_ip"])
    assert same["llr"] <= prof.posterior_of(["cross_ip"])["llr"] + 1e-9


def test_llr_keeps_true_positive_signal() -> None:
    """跨 IP + 零成功爆破这种真信号必须远高于阈值。"""
    prof = _mod("app.baseline.profile")
    out = prof.posterior_of(["cross_ip", "fail_burst_hard"])
    assert out["posterior"] > 0.05


def test_llr_suppresses_benign_device_change() -> None:
    """换设备 + 新路径（OA 正常使用）必须低于阈值 —— 这是 36% 误报的形态。"""
    prof = _mod("app.baseline.profile")
    out = prof.posterior_of(["new_src_ip", "new_ua", "new_path"])
    assert out["posterior"] < 0.05


def test_posterior_is_ordered() -> None:
    """后验概率必须能排序：越强的证据组合分数越高（旧的加和分会顶到 1.0）。"""
    prof = _mod("app.baseline.profile")
    weak = prof.posterior_of(["new_ua"])["posterior"]
    mid = prof.posterior_of(["new_src_ip", "unusual_hour"])["posterior"]
    strong = prof.posterior_of(["cross_ip", "fail_burst_hard"])["posterior"]
    assert weak < mid < strong


# ===== ⑤ 参数与限额闸门 =====


def test_new_knobs_exist_and_are_clamped() -> None:
    """新增参数必须都在白名单里（界面可改），且脏值被夹紧。"""
    params = _mod("app.baseline.params")
    keys = {k.key for k in params.KNOBS}
    for key in (
        "baseline.scheme",
        "baseline.alpha",
        "baseline.learn_source",
        "baseline.pool_k",
        "baseline.deviation_cap_per_entity_hour",
        "baseline.deviation_cap_per_hour",
        "profile.scoring",
        "profile.prior_odds",
        "profile.posterior_threshold",
    ):
        assert key in keys, f"{key} 不在可调参数白名单里"
    assert params.scheme() in ("poisson", "zscore")
    assert params.learn_source() in ("window", "digest")
    assert params.scoring() in ("llr", "additive")


def test_deviation_cap_limits_flood() -> None:
    """限额闸门：单实体每小时超限后不再报（最后一道防误报刷屏的闸）。"""

    class FakeRedis:
        def __init__(self) -> None:
            self.data: dict[str, int] = {}

        def incr(self, key: str) -> int:
            self.data[key] = self.data.get(key, 0) + 1
            return self.data[key]

        def expire(self, key: str, ttl: int) -> bool:
            return True

    engine_mod = _mod("app.baseline.engine")
    eng = engine_mod.BaselineEngine(client=FakeRedis())
    cap = engine_mod.params.deviation_cap_per_entity_hour()
    allowed = sum(1 for _ in range(cap + 10) if eng._allow_deviation("10.0.0.1"))
    assert allowed == cap, f"单实体每小时最多 {cap} 次，实际放行 {allowed}"
