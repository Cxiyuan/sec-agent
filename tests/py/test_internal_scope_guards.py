"""C1 守卫：监控网段是唯一坐标系（候选/采样/资产基线/方向全部用 is_internal_ip）。

为什么单独立一个文件：口径错了不报错也不崩，只是悄悄把"别人的网段"当成自己的资产
—— 盲区任务、资产基线、外连基线、方向判定全跟着歪。这里用两个网段钉死行为：
配了 `10.1.1.0/24` 时，`10.9.9.9`（同样的私网、但不在监控网段里）**不许**出现在
任何一条主线里（observed_subjects 的原料 / 数值基线 / 资产台账 / 内网方向）。
"""

from __future__ import annotations

import importlib
from types import SimpleNamespace
from typing import Any

import pytest

NETS = ("10.1.1.0/24",)


@pytest.fixture
def nets(monkeypatch: pytest.MonkeyPatch) -> str:
    mod = importlib.import_module("app.iputil")
    monkeypatch.setattr(mod, "_net_texts", lambda: NETS)
    monkeypatch.setattr(mod, "_cache_at", 0.0, raising=False)
    # 其余模块（sampler 等）import 的是同一 mod 的函数对象，monkeypatch `_networks`
    # 才能保证它们走同一份网段注入
    monkeypatch.setattr(mod, "_networks", lambda: [__import__("ipaddress").ip_network(n) for n in NETS])
    assert mod.is_internal_ip("10.1.1.10") is True
    assert mod.is_internal_ip("10.9.9.9") is False
    assert mod.is_internal_ip("8.8.8.8") is False
    return "app.iputil"


def _event(
    src: str,
    dst: str,
    *,
    dst_port: Any = None,
    protocol: str = "",
    account: str = "",
    user: str = "",
    status_code: Any = None,
    event_type: str = "http_request",
    signature_id: str = "",
) -> SimpleNamespace:
    return SimpleNamespace(
        src_ip=src,
        dst_ip=dst,
        dst_port=dst_port,
        protocol=protocol,
        signature_id=signature_id,
        account=account,
        user=user,
        status_code=status_code,
        event_type=event_type,
    )


def test_candidates_register_only_in_scope_assets_and_accounts(
    nets: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """网段外私网不进资产/端口/账号（否则它会变成一条"从未分析"的盲区任务）。"""
    cand = importlib.import_module("app.analysis.candidates")
    subjects = importlib.import_module("app.analysis.subjects")
    monkeypatch.setattr(cand.params, "enabled", lambda: True)
    monkeypatch.setattr(cand.params, "candidate_kinds", lambda: {"novelty"})
    collector = cand.Collector()
    # 网段内被访问 → 应记资产 + 高危端口；账号来自网段内源 → 登记
    collector.observe(_event("10.1.1.10", "10.1.1.20", dst_port=22, account="alice"))
    # 网段外私网被访问 → **不**是资产；账号来自网段外源 → **不**登记
    collector.observe(_event("10.9.9.9", "10.1.1.20", dst_port=22, account="eviluser"))
    assets = collector.seen.get(subjects.KIND_ASSET, set())
    assert "10.1.1.20" in assets
    ports = collector.seen.get(subjects.KIND_PORT, set())
    assert "10.1.1.20:22" in ports
    accounts = collector.seen.get(subjects.KIND_ACCOUNT, set())
    assert "alice" in accounts
    assert "eviluser" not in accounts, "网段外源打的账号字典不能当'我们见过的新账号'登记"


def test_candidates_never_publish_out_of_scope_subject(nets: str) -> None:
    """10.9.9.9 作为被访问方不能进资产集合 —— 它是网段外，不是我们的资产。"""
    cand = importlib.import_module("app.analysis.candidates")
    subjects = importlib.import_module("app.analysis.subjects")
    collector = cand.Collector()
    collector.observe(_event("8.8.8.8", "10.9.9.9", dst_port=443))
    assert "10.9.9.9" not in collector.seen.get(subjects.KIND_ASSET, set())
    assert "10.9.9.9:443" not in collector.seen.get(subjects.KIND_PORT, set())


def test_sampler_baseline_only_for_in_scope_sources(
    nets: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """数值基线/外连采样只学监控网段内源；网段外源（含私网）只保留 404 探测统计。"""
    sampler_mod = importlib.import_module("app.baseline.sampler")
    sampler = sampler_mod.WindowSampler(window_seconds=300)
    sampler.observe(
        _event("10.1.1.10", "10.1.1.20", dst_port=22, event_type="conn_established"),
        now=1000.0,
    )
    sampler.observe(
        _event("10.9.9.9", "10.1.1.20", dst_port=80, status_code=404),
        now=1001.0,
    )
    sampler.observe(
        _event("10.1.1.10", "10.9.9.9", dst_port=8443, event_type="conn_established"),
        now=1002.0,
    )
    samples = sampler.pop_ready(now=1400.0)
    by_ip = {row["src_ip"]: row for row in samples}
    internal_row = by_ip.get("10.1.1.10") or {}
    assert internal_row.get("counts", internal_row.get("total", 1)) is not None
    not_in_scope = by_ip.get("10.9.9.9")
    assert not_in_scope is not None
    assert not_in_scope.get("skip_baseline") is True, "网段外源只留 404 探测，不建基线"
    eg_dts = internal_row.get("egress_dsts") or []
    assert "10.9.9.9" not in eg_dts, "网段外私网不是公网目的地，不算主动外连"


def test_asset_scope_uses_monitored_nets(nets: str) -> None:
    """资产台账的内外归属：网段外私网不是 internal（之前 is_private 口径会判成内网）。"""
    asset = importlib.import_module("app.baseline.asset")
    assert asset.scope_of_ip("10.1.1.10") == asset.SCOPE_INTERNAL
    assert asset.scope_of_ip("10.9.9.9") == asset.SCOPE_EXTERNAL
    assert asset.scope_of_ip("8.8.8.8") == asset.SCOPE_EXTERNAL
    # 非法/空/回环/非 IP 标识保持原口径（保守按内网，不把未知归「外部」）
    assert asset.scope_of_ip("127.0.0.1") == asset.SCOPE_INTERNAL
    assert asset.scope_of_ip("www.example.com") == asset.SCOPE_INTERNAL
    assert asset.scope_of_ip("") == asset.SCOPE_INTERNAL


def test_egress_baseline_only_from_in_scope_sources(
    nets: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """外连基线只记「网段内源 → 公网目的地」：网段外源连公网不是我们的外连。"""
    egress = importlib.import_module("app.baseline.egress")
    params = importlib.import_module("app.baseline.params")
    monkeypatch.setattr(params, "egress_enabled", lambda: True)
    out = egress.observe_window(
        [
            {
                "src_ip": "10.9.9.9",
                "egress_dsts": ["8.8.8.8"],
                "egress_domains": ["c2.example"],
                "egress_ports": ["8443"],
            },
        ]
    )
    assert out == {"new": 0, "rare": 0, "learned": 0}, "网段外源不得产出任何外连事实"
    # 目的不是公网（网段外私网目的地）同样不算外连
    out2 = egress.observe_window(
        [{"src_ip": "10.1.1.10", "egress_dsts": ["10.9.9.9"], "egress_domains": [], "egress_ports": []}]
    )
    assert out2["new"] == 0


def test_direction_of_follows_monitored_nets(nets: str) -> None:
    """方向判定（D1 口径）：网段外私网→监控网段是 out→in，不是 in→in。"""
    triage = importlib.import_module("app.triage_policy")
    # 监控网段 → 公网
    assert triage.direction_of("10.1.1.10", ["8.8.8.8"]) == triage.DIR_IN_TO_OUT
    # 公网 → 监控网段
    assert triage.direction_of("8.8.8.8", ["10.1.1.10"]) == triage.DIR_OUT_TO_IN
    # 监控网段 ↔ 监控网段
    assert triage.direction_of("10.1.1.10", ["10.1.1.20"]) == triage.DIR_IN_TO_IN
    # 网段外私网 → 监控网段：不是 in→in！它是"另一片内网来访问我们"
    assert triage.direction_of("10.9.9.9", ["10.1.1.10"]) == triage.DIR_OUT_TO_IN
    # 监控网段 → 网段外私网：离开监控范围按外向处理（宁可多分析，不因"它也是私网"而放进常规流量）
    assert triage.direction_of("10.1.1.10", ["10.9.9.9"]) == triage.DIR_IN_TO_OUT
    # 中继场景：真实客户端优先
    assert (
        triage.direction_of("10.1.1.10", ["10.1.1.20"], real_client_ips=["8.8.8.8"])
        == triage.DIR_OUT_TO_IN
    )
    # 缺目标信息：unknown（不猜方向）
    assert triage.direction_of("10.1.1.10", []) == "unknown"


def test_iputil_single_entry_is_the_only_internal_gauge(nets: str) -> None:
    """守卫：主线模块都从 app.iputil 拿口径，不许再自造"私网=内网"。"""
    from pathlib import Path

    root = Path(importlib.import_module("app.iputil").__file__).parent
    offenders: list[str] = []
    for rel in (
        "analysis/candidates.py",
        "baseline/sampler.py",
        "baseline/asset.py",
        "baseline/egress.py",
        "triage_policy.py",
    ):
        text = (root / rel).read_text(encoding="utf-8")
        if rel in ("baseline/egress.py", "baseline/sampler.py"):
            # 目的口径允许 is_public_ip（"是不是公网目的地"另有语义）
            continue
        if "is_private" in text:
            offenders.append(rel)
        if rel == "triage_policy.py" and "is_public_ip" in text:
            offenders.append(rel)
    assert not offenders, f"这些模块还在用别的口径判内网：{offenders}"
