"""「最近命中」可见性 + 内网利用特征规则（2026-10 调研后新增）。

背景：摘要的唯一出口是「推给智能体」，现场没配推送地址时界面完全看不到检测器报了什么
（只有 undelivered 在涨）。所以检测器把摘要同时记一份到 Redis 环形列表，界面卡片读它 ——
**不依赖任何外部目标**。同一轮调研还发现：内网一台授权漏扫设备 24h 在 43 个内网目标上打
2,905 个端口、UA 带 Shellshock 载荷、路径是 /nacos/... /solr /manager/html，但没有任何规则
看「利用特征」——因此新增 `内置-内网漏洞利用探测`（扇出 ≥10 个内网目的 + 利用特征）。
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def recent(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("最近命中只在 NDR 侧（检测器交付侧）")
    return importlib.import_module("app.detector.recent")


@pytest.fixture(scope="module")
def route(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("检测器路由只存在于 NDR 侧")
    return importlib.import_module("app.api.routes.detector")


class _Pipe:
    def __init__(self, client: _Client) -> None:
        self.client = client

    def lpush(self, key: str, value: str) -> _Pipe:
        self.client.ops.append(("lpush", key, value))
        return self

    def ltrim(self, key: str, start: int, stop: int) -> _Pipe:
        self.client.ops.append(("ltrim", key, start, stop))
        return self

    def execute(self) -> list[Any]:
        self.client.ops.append(("execute",))
        return []


class _Client:
    def __init__(self, items: list[str] | None = None) -> None:
        self.ops: list[Any] = []
        self.items = items or []

    def pipeline(self) -> _Pipe:
        return _Pipe(self)

    def lrange(self, key: str, start: int, stop: int) -> list[str]:
        self.ops.append(("lrange", key, start, stop))
        return self.items


def _digest(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "src_ip": "10.1.2.66",
        "rule": "内置-内网漏洞利用探测",
        "rule_severity": "high",
        "rule_source": "builtin",
        "count": 42,
        "dst_ips": ["10.1.2.22", "10.1.2.24"],
        "dst_ports": ["8080", "8088"],
        "event_types": ["http_error"],
        "conn_states": ["SF"],
        "real_client_ips": [],
        "proxied": False,
        "first_seen": "2026-10-09T14:28:29+00:00",
        "last_seen": "2026-10-09T14:54:31+00:00",
        "excluded": False,
        "exclude_reason": "",
        "samples": [{"source": "es", "doc": {"huge": "doc"}}],
    }
    base.update(kw)
    return base


def test_compact_keeps_display_fields_and_drops_samples(recent: ModuleType) -> None:
    out = recent.compact(_digest())
    assert out["rule"] == "内置-内网漏洞利用探测"
    assert out["severity"] == "high"
    assert out["count"] == 42
    assert out["ts"] == "2026-10-09T14:54:31+00:00", "时间取最近一次命中"
    assert out["dst_ips"] == ["10.1.2.22", "10.1.2.24"]
    assert "samples" not in out, "样例文档不放进 Redis 环形记录（体积）"


def test_record_pushes_and_trims(recent: ModuleType) -> None:
    client = _Client()
    recent.record(client, _digest())
    kinds = [op[0] for op in client.ops]
    assert kinds == ["lpush", "ltrim", "execute"], "一次记录 = 入队 + 限长"
    pushed = next(op for op in client.ops if op[0] == "lpush")
    assert pushed[1] == recent.RECENT_KEY
    record = json.loads(pushed[2])
    assert record["rule"] == "内置-内网漏洞利用探测"
    trim = next(op for op in client.ops if op[0] == "ltrim")
    assert trim[2] == 0 and trim[3] == max(10, int(recent.settings.detector_recent_max)) - 1


def test_record_never_raises(recent: ModuleType) -> None:
    class _Boom:
        def pipeline(self) -> Any:
            raise RuntimeError("redis down")

    recent.record(_Boom(), _digest())  # 可见性是辅助能力，不能把检测主循环搞崩


def test_load_is_newest_first_and_tolerates_bad_rows(recent: ModuleType) -> None:
    client = _Client(
        items=[
            json.dumps({"rule": "b", "count": 2}),
            "{坏 JSON",
            json.dumps({"rule": "a", "count": 1}),
        ]
    )
    items = recent.load(client, 10)
    assert [i["rule"] for i in items] == ["b", "a"], "顺序就是 Redis 里的顺序（最新在前），坏行跳过"


def test_load_caps_limit(recent: ModuleType) -> None:
    """超大 limit 会被夹到 `detector_recent_max`（不能因为一个查询参数就把整条环形拉出来）。"""
    client = _Client(items=[])
    recent.load(client, 10**6)
    call = next(op for op in client.ops if op[0] == "lrange")
    assert call[3] == max(10, int(recent.settings.detector_recent_max)) - 1


def test_recent_endpoint_registered_exactly_once(route: ModuleType) -> None:
    """路由只能注册一次（本轮踩到：同名函数把前一个遮蔽掉，端点直接消失）。"""
    paths = [getattr(r, "path", "") for r in route.router.routes]
    assert paths.count("/api/detector/recent") == 1, f"/recent 应只注册一次，实际 {paths}"


def test_recent_endpoint_reads_redis(route: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    import redis as redis_mod

    client = _Client(items=[json.dumps({"rule": "内置-协议异常", "count": 3})])
    monkeypatch.setattr(redis_mod.Redis, "from_url", staticmethod(lambda *a, **k: client))
    out = route.detector_recent(None, limit=5)  # type: ignore[arg-type]
    assert out["count"] == 1 and out["items"][0]["rule"] == "内置-协议异常"


def test_internal_exploit_rule_shape(request: pytest.FixtureRequest) -> None:
    """新规则必须是「扇出 + 利用特征」：只对内网→内网、≥10 个不同内网目的才算。"""
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("这条内置规则只在 NDR 侧")
    builtin = importlib.import_module("app.rules.builtin")
    rule = next(r for r in builtin.BUILTIN_RULES if r["name"] == "内置-内网漏洞利用探测")
    cond = rule["conditions"]
    assert cond["mode"] == "count" and cond["key"] == ["src_ip"]
    assert cond["distinct"] == "dst_ip" and cond["min_distinct"] >= 10
    # 窗口是「扇出判定的观察期」，也是告警延迟：太长（如 6h）会让利用告警迟到，
    # 太短（<10min）会把正常批量运维也算进来 —— 30 分钟是实测后的折中
    assert 1800 <= cond["window"] <= 7200, f"窗口应在 30~120 分钟，实际 {cond['window']}"
    assert rule["severity"] == "high"
    flat = json.dumps(cond, ensure_ascii=False)
    assert "src_internal" in flat and "dst_internal" in flat, "只对内网横向判（内外有别）"


def test_internal_exploit_rule_matches_payloads(request: pytest.FixtureRequest) -> None:
    """Shellshock / Log4Shell 载荷头、Nacos/Solr/Tomcat 管理页要能命中；普通 UA 不能。"""
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("这条内置规则只在 NDR 侧")
    builtin = importlib.import_module("app.rules.builtin")
    engine = importlib.import_module("app.rules.engine")
    schemas = importlib.import_module("app.schemas")
    rule = next(r for r in builtin.BUILTIN_RULES if r["name"] == "内置-内网漏洞利用探测")

    def _hit(user_agent: str, uri_path: str) -> bool:
        entry = schemas.UnifiedLog(
            source_system="zeek",
            ts="2026-10-09T14:28:29+00:00",
            event_type="http_request",
            log_type="http",
            src_ip="10.1.2.66",
            dst_ip="10.1.2.22",
            dst_port=8080,
            user_agent=user_agent,
            uri_path=uri_path,
        )
        return engine.evaluate_conditions(rule["conditions"], entry)

    assert _hit("() { :; }; echo; echo test for CVE-$((2000+14))-6271;", "/")
    assert _hit("() { ignored; }; /bin/sleep 5;", "/")
    assert _hit("Mozilla/5.0", "/nacos/v1/cs/ops/data/removal"), "Nacos 利用端点"
    assert _hit("curl/7.68.0", "/solr/admin/cores"), "Solr 端点（大小写不敏感）"
    assert _hit("python-requests/2.23.0", "/manager/html"), "Tomcat 管理页"
    assert not _hit("Mozilla/5.0 (Windows NT 10.0)", "/index.html"), "正常浏览不该命中"

    # 公网来源不算（这条规则只管内网横向）
    external = schemas.UnifiedLog(
        source_system="zeek",
        ts="2026-10-09T14:28:29+00:00",
        event_type="http_request",
        log_type="http",
        src_ip="8.8.8.8",
        dst_ip="10.1.2.22",
        user_agent="() { :; }; /bin/sleep 5;",
        uri_path="/",
    )
    assert not engine.evaluate_conditions(rule["conditions"], external)


def test_compact_uses_real_client_when_proxied(recent: ModuleType) -> None:
    """中继链路：`src_ip` 是代理/WAF 自己，展示用的请求方必须取真实客户端（XFF）。

    实机依据（2026-10 用户反馈）：「多路径探测」命中里 `src_ip` 显示成 WAF 地址，
    而真实请求方在 XFF 里（如 113.0.87.111）—— 界面上把 WAF 当成了发起方。
    """
    out = recent.compact(
        _digest(src_ip="10.1.2.10", real_client_ips=["113.0.87.111"], proxied=True)
    )
    assert out["client"] == "113.0.87.111"
    assert out["client_source"] == "xff"
    assert out["via"] == "10.1.2.10", "要能看出这一跳经过了谁"
    assert out["src_ip"] == "10.1.2.10", "原始字段保留不动（聚合/去重仍用它）"


def test_compact_falls_back_to_src_when_direct(recent: ModuleType) -> None:
    """没有可信代理头（直连）时：请求方就是 src_ip，且不标「经 …」。"""
    out = recent.compact(_digest(src_ip="10.1.2.66", real_client_ips=[], proxied=False))
    assert out["client"] == "10.1.2.66"
    assert out["client_source"] == "src_ip"
    assert out["via"] == ""


def test_panel_shows_real_client_and_via() -> None:
    """界面守卫：源那一列显示真实请求方，并在经过中继时标注「经 …」。"""
    src = (ROOT / "ndr" / "frontend" / "components" / "status-panel.tsx").read_text(
        encoding="utf-8"
    )
    assert "row.client" in src, "源列必须优先显示真实请求 IP"
    assert "经 {row.via}" in src, "经过代理/中继时要在界面上说明"
