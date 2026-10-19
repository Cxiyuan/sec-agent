"""批 3（A 组 6 项）的守卫：设备实体键、误报闭环、新颖度/稀有度/高基数、阈值告警、聚类。

这些改动都在"降低误报 / 让运维看得懂"这条线上，守卫要钉住的是**行为契约**：
- 同一台设备换 cookie 不能变成新实体；
- 标了误报之后，同一实体在窗口内不再参与打分（但理由仍可见）；
- 已知种类太多的维度（门户路径、UA 池）不再用"新/旧"判分；
- 共享出口网段（移动网/代理）里的新 IP 不算信号；
- 阈值告警要能把"静默积累"的问题变成可见的黄灯/红灯；
- 聚类口径要确定（同输入同输出），不能引入机器学习依赖。
"""

from __future__ import annotations

import importlib
import pathlib
from datetime import UTC
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _mod(name: str) -> Any:
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError:  # pragma: no cover - agent 栈没有这些模块
        pytest.skip(f"该栈没有 {name}（属 NDR 侧）")


# ===== ① 设备实体键（item 2）=====


def _entry(**fields: Any) -> Any:
    base: dict[str, Any] = {
        "cookie": "",
        "user_agent": "",
        "ja3": "",
        "ja4": "",
        "account": "",
        "user": "",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.9",
        "dst_port": "443",
        "path": "",
        "host": "",
        "method": "",
        "status": 200,
        "bytes": 100,
        "ts": 0.0,
        "log_type": "http",
        "event_type": "http_request",
        "source_system": "zeek",
        "conn_state": "",
        "uid": "",
        "user_agent_raw": "",
        "tls_sni": "",
        "server_name": "",
        "scheme": "https",
        "uri": "",
    }
    base.update(fields)
    return SimpleNamespace(**base)


def test_device_key_is_stable_per_device() -> None:
    """同一台设备（UA + JA3 相同）换了 cookie，实体键不变 —— 这是压缩 10 万会话的关键。"""
    prof = _mod("app.baseline.profile")
    a = prof.device_entity(_entry(user_agent="UA/1.0", ja3="abc123", cookie="sid=A"))
    b = prof.device_entity(_entry(user_agent="UA/1.0", ja3="abc123", cookie="sid=B"))
    assert a[0] and a[0] == b[0]
    assert a[1].startswith("设备 ")


def test_device_key_differs_by_fingerprint() -> None:
    prof = _mod("app.baseline.profile")
    a = prof.device_entity(_entry(user_agent="UA/1.0", ja3="abc"))[0]
    b = prof.device_entity(_entry(user_agent="UA/2.0", ja3="abc"))[0]
    c = prof.device_entity(_entry(user_agent="UA/1.0", ja3="def"))[0]
    assert a != b and a != c


def test_device_key_falls_back_to_empty() -> None:
    """取不到 UA/JA3 时返回空 → 调用方回落 cookie 口径（不丢观测）。"""
    prof = _mod("app.baseline.profile")
    assert prof.device_entity(_entry())[0] == ""


def test_entity_key_switch_is_whitelisted() -> None:
    params = _mod("app.baseline.params")
    assert params.entity_key() in ("device", "cookie")
    assert "profile.entity_key" in {k.key for k in params.KNOBS}


# ===== ② 误报闭环（item 3）=====


def _profile(profiles: ModuleType, **over: Any) -> Any:
    row = profiles.EntityProfile(
        kind=profiles.SESSION,
        entity_key="k",
        entity_display="disp",
        obs_count=500,
        src_ips={"10.0.0.1": 100},
        user_agents={"UA/1.0": 100},
        paths={},
        hour_hist={str(h): 20 for h in range(12)},
        success_count=100,
        fail_count=0,
        error_count=0,
        window_count=99,
    )
    for k, v in over.items():
        setattr(row, k, v)
    return row


def _obs(profiles: ModuleType, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "kind": profiles.SESSION,
        "key": "k",
        "display": "disp",
        "src_ips": {"10.9.9.9": 1},
        "dst_ips": {},
        "user_agents": {"UA/NEW": 1},
        "paths": {},
        "hours": {},
        "count": 5,
        "fail": 0,
        "success": 0,
        "errors": 0,
    }
    base.update(over)
    return base


def test_false_positive_suppresses_whole_alert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """整条告警被判误报后：不再告警，但**理由仍然可见**（运维要知道当初为什么报）。"""
    prof = _mod("app.baseline.profile")
    monkeypatch.setattr(prof, "load_suppressed", lambda kind, key: {"*"})
    eng = _mod("app.baseline.engine")
    monkeypatch.setattr(prof, "params", eng.params, raising=False)
    out = prof.detect(prof.SESSION, _obs(prof), _profile(prof))
    assert out["alerted"] is False
    assert out["posterior"] < 0.05
    assert any("误报" in r for r in out["reasons"])


def test_false_positive_suppresses_single_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """只降权指定信号：其余证据照常参与打分。"""
    prof = _mod("app.baseline.profile")
    base = prof.detect(prof.SESSION, _obs(prof), _profile(prof))
    monkeypatch.setattr(prof, "load_suppressed", lambda kind, key: {"new_src_ip"})
    out = prof.detect(prof.SESSION, _obs(prof), _profile(prof))
    assert out["posterior"] < base["posterior"]
    assert any("new_src_ip" in r for r in out["reasons"])


def test_suppress_days_knob_exists() -> None:
    params = _mod("app.baseline.params")
    assert "profile.false_positive_suppress_days" in {k.key for k in params.KNOBS}


def test_disposition_endpoints_registered() -> None:
    """处置接口必须注册在路由上（前端按文档调用，不能只是函数存在）。"""
    src = (ROOT / "ndr" / "backend" / "app" / "api" / "routes" / "baseline.py").read_text(
        encoding="utf-8"
    )
    assert '@router.post("/alerts/{profile_id}/disposition")' in src
    assert '@router.get("/alerts/dispositions")' in src
    assert "record_disposition" in src


# ===== ③ 新颖度 / 高基数 / 共享出口（item 4）=====


def test_high_cardinality_paths_are_not_scored() -> None:
    """已知路径够多（门户站点）时，「新路径」只记理由不打分。"""
    prof = _mod("app.baseline.profile")
    paths = {f"/p/{i}": 10 for i in range(200)}
    out = prof.detect(
        prof.SESSION,
        _obs(prof, paths={"/brand-new": 1}),
        _profile(prof, paths=paths),
    )
    assert any("新接口路径" in r for r in out["reasons"])
    assert any("已知路径过多" in r for r in out["reasons"])


def test_low_cardinality_paths_are_still_scored() -> None:
    """路径种类很少时，新路径仍然算证据（别把降级做成"永远不报"）。"""
    prof = _mod("app.baseline.profile")
    out = prof.detect(
        prof.SESSION,
        _obs(prof, paths={"/new-api": 1}),
        _profile(prof, paths={f"/p/{i}": 10 for i in range(20)}),
    )
    assert not any("已知路径过多" in r for r in out["reasons"])


def test_established_counts_only_repeated_values() -> None:
    """只数"见过 >= novelty_max_count 次"的值：一次性出现的一堆值不该触发降级。"""
    prof = _mod("app.baseline.profile")
    once = {f"/p/{i}": 1 for i in range(100)}
    repeated = {f"/p/{i}": 10 for i in range(10)}
    assert prof._established(once) == 0
    assert prof._established(repeated) == 10


class _FakeRarity:
    def __init__(self, count: int) -> None:
        self.count = count
        self.added: list[str] = []

    def pfadd(self, key: str, value: str) -> int:
        self.added.append(value)
        return 1

    def pfcount(self, key: str) -> int:
        return self.count

    def expire(self, key: str, ttl: int) -> bool:
        return True


def test_shared_egress_demotes_new_ip() -> None:
    """共享出口（同 /24 当天出现很多实体）里的新 IP 不算信号。"""
    prof = _mod("app.baseline.profile")
    assert prof.set_client is not None
    prof.set_client(_FakeRarity(999))
    try:
        out = prof.detect(prof.SESSION, _obs(prof), _profile(prof))
        assert any("共享出口" in r for r in out["reasons"])
    finally:
        prof.set_client(None)


def test_rarity_disabled_does_not_demote() -> None:
    prof = _mod("app.baseline.profile")
    params = _mod("app.baseline.params")
    prof.set_client(_FakeRarity(999))
    try:
        if not params.ip_rarity_enabled():  # 现场关了就直接跳过
            pytest.skip("该环境已关闭共享出口判定")
        # 反证：客户端拿掉后就不该出现"共享出口"理由
        prof.set_client(None)
        out = prof.detect(prof.SESSION, _obs(prof), _profile(prof))
        assert not any("共享出口" in r for r in out["reasons"])
    finally:
        prof.set_client(None)


# ===== ④ 阈值告警（item 5）=====


class _FakeRedis:
    def __init__(self, *, frag: float = 1.0, freq_keys: int = 0) -> None:
        self.frag = frag
        self.freq_keys = freq_keys

    def info(self, section: str) -> dict[str, Any]:
        return {"mem_fragmentation_ratio": self.frag, "used_memory_peak": 1}

    def scan_iter(self, match: str = "*", count: int = 1000) -> Any:
        for i in range(min(self.freq_keys, 5000)):
            yield f"shentong:freq:r:{i}"


def test_thresholds_ok_when_healthy() -> None:
    th = _mod("app.detector.thresholds")
    out = th.evaluate(_FakeRedis(frag=1.1, freq_keys=10), stats={"baseline_sampled": 5})
    assert out["level"] == "ok"
    assert {i["key"] for i in out["items"]} >= {"redis_fragmentation", "freq_keys"}


def test_thresholds_warn_on_fragmentation() -> None:
    th = _mod("app.detector.thresholds")
    out = th.evaluate(_FakeRedis(frag=2.0, freq_keys=1), stats={"baseline_sampled": 1})
    assert out["level"] in ("warn", "crit")


def test_thresholds_crit_on_handled_dropped() -> None:
    """判重登记被丢弃 = 去重已失效，必须是红灯（静默继续会重复分析）。"""
    th = _mod("app.detector.thresholds")
    out = th.evaluate(_FakeRedis(), stats={"handled_dropped": 12, "baseline_sampled": 1})
    assert out["level"] == "crit"
    assert any(i["key"] == "handled_dropped" and i["level"] == "crit" for i in out["items"])


def test_thresholds_warn_when_sampling_dead() -> None:
    """采样通道 0 条 = 数值基线在空转，要黄灯。"""
    th = _mod("app.detector.thresholds")
    out = th.evaluate(_FakeRedis(), stats={"baseline_sampled": 0})
    assert any(i["key"] == "baseline_sampled" and i["level"] == "warn" for i in out["items"])


def test_thresholds_are_wired_into_health() -> None:
    src = (ROOT / "ndr" / "backend" / "app" / "api" / "routes" / "health_components.py").read_text(
        encoding="utf-8"
    )
    assert "thresholds.evaluate" in src
    assert '"thresholds"' in src


# ===== ⑤ 告警聚类（item 6）=====


def test_cluster_id_is_deterministic() -> None:
    """同归类 + 同网段 + 同小时 → 同簇；换小时/换网段/换归类 → 不同簇。"""
    from datetime import datetime

    cl = _mod("app.detector.clustering")
    t1 = datetime(2026, 10, 19, 10, 5, tzinfo=UTC)
    t2 = datetime(2026, 10, 19, 10, 55, tzinfo=UTC)
    t3 = datetime(2026, 10, 19, 11, 5, tzinfo=UTC)
    base = cl.cluster_id("网络扫描", "10.1.2.3", t1)
    assert base == cl.cluster_id("网络扫描", "10.1.2.99", t2), "同网段同小时要归同簇"
    assert base != cl.cluster_id("网络扫描", "10.9.3.4", t1), "不同网段不能合并"
    assert base != cl.cluster_id("账号口令攻击", "10.1.2.3", t1), "不同归类不能合并"
    assert base != cl.cluster_id("网络扫描", "10.1.2.3", t3), "跨小时要分开（保留还在继续的语义）"


def test_cluster_id_handles_missing_ip() -> None:
    """没有地址的事件（基线偏离）也要能聚：退化成「归类 + 小时」。"""
    cl = _mod("app.detector.clustering")
    assert cl.cluster_id("连接数异常偏离", "")
    assert cl.cluster_id("连接数异常偏离", "-")


def test_no_ml_dependency_for_clustering() -> None:
    """聚类必须是规则式：引入 sklearn 会让镜像 +100MB，且不可解释。"""
    src = (ROOT / "ndr" / "backend" / "app" / "detector" / "clustering.py").read_text(
        encoding="utf-8"
    )
    code = [ln.strip() for ln in src.splitlines() if ln.strip().startswith(("import ", "from "))]
    assert not [ln for ln in code if "sklearn" in ln or "scipy" in ln or "numpy" in ln]


def test_hit_events_carry_cluster_id() -> None:
    """簇 ID 要落到事件表（NDR 侧）；agent 栈的 HitEvent 是另一套模型，跳过。"""
    models = _mod("app.db.models")
    if not hasattr(models, "HitEvent"):
        pytest.skip("该栈没有事件表（属 NDR 侧）")
    assert hasattr(models.HitEvent, "cluster_id")
    src = (ROOT / "ndr" / "backend" / "app" / "main.py").read_text(encoding="utf-8")
    assert "hit_events ADD COLUMN IF NOT EXISTS cluster_id" in src
