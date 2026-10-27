"""这批升级的守卫：hint 富化、冷启动窗口、反例学习（抑制→排除规则）、工具档位。

来自 2026-10-26 架构评审的处理项：
- 旧摘要推送契约降级为回滚档（入口保留，语义以注释/文档为准）；
- 命中线索 hint 富化（客观元数据，省 agent 查询；绝不带严重度）；
- 冷启动窗口（基线重学期把"人人都新"的线索压到保留名额之下）；
- analyst 档补上 baseline_lookup / entity_profile（agent 从"没有尺子"到有尺子）；
- 抑制条目一键转人工排除规则草稿（反例学习）。
"""

from __future__ import annotations

import importlib
import inspect
from typing import Any

import pytest


def _mod(name: str) -> Any:
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError:  # pragma: no cover
        pytest.skip(f"该栈没有 {name}（属 NDR 侧）")


# ---------- ① hint 富化（只加客观字段，绝不碰严重度） ----------


def test_hit_hint_enriched_but_never_severity() -> None:
    cand = _mod("app.analysis.candidates")
    src = inspect.getsource(cand.enqueue_hit) + inspect.getsource(cand._hit_hint)
    for field in ("命中来源", "目的端口", "事件类型", "会话状态", "proxied"):
        assert field in src, f"hint 富化缺 {field}"
    assert 'get("rule_severity")' not in src, "hint 富化绝不读 rule_severity（判断权在智能体）"
    assert "取代性的判断词" not in src and "疑似攻击" not in src


def test_hit_hint_keeps_digest_out_of_wrong_fields() -> None:
    cand = _mod("app.analysis.candidates")
    hint = cand._hit_hint(
        {
            "rule": "ET SCAN",
            "src_ip": "10.0.0.5",
            "dst_ips": ["10.0.0.9", "10.0.0.10"],
            "count": 5,
            "dst_ports": [22, 80, 443],
            "event_types": ["alert"],
            "conn_states": ["ShR"],
            "proxied": True,
            "real_client_ips": ["1.2.3.4"],
            "rule_source": "suricata",
        },
        "ET SCAN",
        "ev:1",
        0.8,
        2,
    )
    assert hint["命中来源"] == "特征签名"
    assert hint["目的端口"] == ["22", "80", "443"]
    assert hint["会话状态"] == ["ShR"]
    assert hint["proxied"] is True and hint["真实客户端"] == ["1.2.3.4"]
    assert len(hint["reuse_identity"]) == 32
    same = cand._hit_reuse_identity(
        {"src_ip": "10.0.0.5", "dst_ips": ["10.0.0.10", "10.0.0.9"], "dst_ports": [443, 80, 22], "event_types": ["alert"]},
        "ET SCAN",
    )
    changed = cand._hit_reuse_identity(
        {"src_ip": "10.0.0.5", "dst_ips": ["10.0.0.11"], "dst_ports": [443, 80, 22], "event_types": ["alert"]},
        "ET SCAN",
    )
    assert hint["reuse_identity"] == same, "集合顺序与窗口计数不能改变同类事件身份"
    assert hint["reuse_identity"] != changed, "目标变化必须得到不同身份"
    for value in hint.values():
        if isinstance(value, str):
            assert "high" not in value.lower(), "不允许再把严重度词写进 hint"


# ---------- ② 冷启动窗口 ----------


class FakeRedis:
    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    def get(self, key: str) -> Any:
        return self.data.get(key)

    def setnx(self, key: str, value: Any) -> bool:
        if key in self.data:
            return False
        self.data[key] = str(value)
        return True


def test_cold_start_params_exist_and_clamped(monkeypatch: pytest.MonkeyPatch) -> None:
    params = _mod("app.analysis.params")
    keys = {k.key for k in params.KNOBS}
    for key in (
        "analysis.cold_start_hours",
        "analysis.cold_start_scale",
        "analysis.cold_start_strength_cap",
    ):
        assert key in keys, f"{key} 不在可调参数里"
    monkeypatch.setattr(params, "rc_get", lambda key, default=None: 999999)
    assert params.cold_start_scale() <= 10.0
    monkeypatch.setattr(params, "rc_get", lambda key, default=None: 5)
    assert params.cold_start_strength_cap() <= 1.0


def _stub_rc(hours: int, scale: float, cap: float):
    values = {
        "analysis.cold_start_hours": hours,
        "analysis.cold_start_scale": scale,
        "analysis.cold_start_strength_cap": cap,
    }
    return lambda key, default=None: values.get(key, default)


def test_cold_start_lifecycle_and_damping(monkeypatch: pytest.MonkeyPatch) -> None:
    cold = _mod("app.analysis.cold_start")
    params = _mod("app.analysis.params")
    client = FakeRedis()
    monkeypatch.setattr(params, "rc_get", _stub_rc(48, 2.0, 0.7))
    assert cold.active(client), "起点标记写入后默认 48h 内就是冷启动"
    assert cold.damped(0.95, client) <= 0.7, "冷启动期 novelty/coverage/structure 必须封顶"
    assert cold.damped(0.4, client) == 0.4
    monkeypatch.setattr(params, "rc_get", _stub_rc(0, 2.0, 0.7))
    assert not cold.active(client), "hours=0 = 关闭"
    assert cold.damped(0.95, client) == 0.95
    assert cold.interval_scale(client) == 1.0, "关闭时轮询间隔不变"
    # 降频倍数：时间推进 1h 仍在窗口内
    monkeypatch.setattr(params, "rc_get", _stub_rc(48, 2.0, 0.7))
    monkeypatch.setattr(cold.time, "time", lambda: (cold.started(client) or 0) + 3600)
    assert cold.interval_scale(client) == 2.0


def test_cold_start_only_caps_weak_kinds() -> None:
    cold = _mod("app.analysis.cold_start")
    assert cold.CAPPED_KINDS == frozenset({"novelty", "coverage", "structure"}), (
        "hit/shift 是真异常信号不能封顶（保留名额留给它们）"
    )


def test_runner_uses_cold_start_for_intervals() -> None:
    runner = _mod("app.detector.runner")
    src = inspect.getsource(runner._analysis_round)
    assert "cold_start.started" in src, "起点标记必须在分析机制启动时记录"
    assert "cold_start.interval_scale" in src, "coverage/retest 轮询要吃冷启动倍数"


# ---------- ③ analyst 档补尺子 ----------


def test_analyst_has_baseline_ruler_tools() -> None:
    server = _mod("app.mcp.server")
    analyst = set(server.build_server("analyst")._tool_manager._tools)
    for name in ("baseline_lookup", "entity_profile"):
        assert name in analyst, f"analyst 档缺取数底座工具：{name}"


# ---------- ④ 反例学习：抑制 → 人工排除规则 ----------


def test_to_exclusion_endpoint_registered() -> None:
    app = _mod("app.main").app
    paths = set(app.openapi()["paths"])
    assert "/api/suppressions/{item_id}/to-exclusion" in paths


def test_to_exclusion_defaults_to_disabled_draft() -> None:
    src = inspect.getsource(_mod("app.api.routes.suppressions").to_exclusion)
    assert "enabled=False" in src, "排除规则比抑制更重：只生成停用草稿，人审后启用"
    assert "match.rules" in src, "没有结构化条件的抑制条目不能转"
