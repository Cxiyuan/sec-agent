"""规则路由（字段归属 → 求值范围）与两处静默失效的回归钉。

背景（2026-10 深度 QA，均由本文件守住）：

1. `app/rules/engine.py::_FIELD_TYPES` 原来只把 Web 字段挂到 ``("http",)``，而 Wazuh 告警
   同样会填 uri_path / query_string / method / body / status_code / user_agent / query
   （见 `app/ingestion/normalizer.py` 的 `normalize_wazuh`）—— 于是 14 条 Web/URL 内置规则
   在 Wazuh 告警上**永不求值**；只引用 `query` 的规则（开放重定向、URL 里的 token）
   也从不在 http 上跑。
2. `auth_scheme` 原来只从顶层 authorization 字段取，而 Zeek 的 http.log 没有这个字段
   （请求头在 `req_headers` 里，由 `zeek/site/shentong-httpheaders.zeek` 拼好）→
   内置「Token/JWT 异常使用」的 bearer/jwt 分支恒假。
"""

from __future__ import annotations

import importlib
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
import samples
from app.config import settings as real_settings
from app.ingestion.normalizer import normalize_zeek
from app.rules import builtin
from app.rules.engine import build_rule_index, evaluate_conditions, match_rule
from app.schemas import UnifiedLog


# 实时频次窗口只在 NDR 侧（agent 侧没有 detector：它分析摘要、不逐条看事件）。
# 惰性取模块（而不是 try/except 里 import 再置 None）—— 后者会让类型检查报「可空对象不可调用」。
def _load_freq_window() -> Any:
    try:
        return importlib.import_module("app.detector.frequency").FreqWindow
    except ImportError:  # pragma: no cover - agent 栈
        return None


_FreqWindow = _load_freq_window()
needs_freq = pytest.mark.skipif(_FreqWindow is None, reason="频次规则只在 NDR 侧")


def _rule(field: str, *, value: str = "x", op: str = "eq") -> dict:
    return {
        "name": f"t-{field}",
        "source": "test",
        "conditions": {"logic": "and", "rules": [{"field": field, "op": op, "value": value}]},
    }


def test_weird_name_routes_to_weird_only() -> None:
    """`weird_name` 只挂在 weird 日志上（其它类型恒空，不该被求值）。"""
    index = build_rule_index([_rule("weird_name")])
    assert [r["name"] for r in index["types"]["weird"]] == ["t-weird_name"]
    assert index["wild"] == []


def test_capture_anomaly_not_matched_by_protocol_anomaly_rule() -> None:
    """「协议异常」只管真正的协议异常，而且已加**同源频次门槛**（2026-10 实机实测）。

    两件事一起钉住：
    1. 归一化把采集类名字标成 `event_type=capture_anomaly`（见 normalizer._capture_weird），
       规则只认 `protocol_anomaly` —— 这类噪声不再占摘要额度；
    2. 该规则改成 `mode=count`（同源窗口内 ≥5 次）：摘要按「源 IP × 规则」分组，
       一次单发的怪象也会各占一条摘要 —— 实测残留的 ~52 个源每 5 分钟就吃掉 52~68 条额度。
    """
    rule = next(r for r in builtin.BUILTIN_RULES if r["name"] == "内置-协议异常")
    conditions = rule["conditions"]
    assert conditions["mode"] == "count"
    assert conditions["key"] == ["src_ip"]
    assert conditions["min_count"] >= 5
    assert conditions["rules"] == [{"field": "event_type", "op": "eq", "value": "protocol_anomaly"}]
    # count 模式不参与逐条匹配（由 frequency 窗口聚合触发）；采集类异常根本不在条件里
    capture = UnifiedLog(
        source_system="zeek",
        ts=datetime.now(UTC),
        event_type="capture_anomaly",
        log_type="weird",
        weird_name="possible_split_routing",
    )
    assert match_rule(rule, capture) is False


def test_web_fields_route_to_http_and_wazuh() -> None:
    index = build_rule_index([_rule("uri_path")])
    assert [r["name"] for r in index["types"]["http"]] == ["t-uri_path"]
    assert [r["name"] for r in index["types"]["wazuh"]] == ["t-uri_path"]
    assert index["wild"] == []


def test_all_wazuh_filled_web_fields_include_wazuh() -> None:
    """Wazuh 分支真正会填的 Web 字段，一个都不能漏掉 wazuh。"""
    for field in ("uri_path", "query_string", "method", "body", "status_code", "user_agent"):
        index = build_rule_index([_rule(field)])
        assert "wazuh" in index["types"], f"{field} 没挂到 wazuh"
        assert "http" in index["types"], f"{field} 没挂到 http"


def test_query_routes_to_dns_http_and_wazuh() -> None:
    """`query` 在 dns.log 里是域名，在 http / Wazuh 里是完整 URL，三边都要跑。"""
    index = build_rule_index([_rule("query")])
    for kind in ("dns", "http", "wazuh"):
        assert [r["name"] for r in index["types"][kind]] == ["t-query"]


def test_explicit_log_type_overrides_field_owner() -> None:
    rule = {
        "name": "t-dns",
        "conditions": {
            "logic": "and",
            "rules": [
                {"field": "log_type", "op": "eq", "value": "dns"},
                {"field": "uri_path", "op": "eq", "value": "x"},
            ],
        },
    }
    index = build_rule_index([rule])
    assert [r["name"] for r in index["types"]["dns"]] == ["t-dns"]
    assert "wazuh" not in index["types"]
    assert index["wild"] == []


def test_common_only_rule_is_wildcard() -> None:
    index = build_rule_index([_rule("src_ip")])
    assert [r["name"] for r in index["wild"]] == ["t-src_ip"]
    assert index["types"] == {}


def test_dead_field_names_no_longer_fake_http_ownership() -> None:
    """`host` / `referrer` 不是 UnifiedLog 的字段名（真名 hostname / referer）。

    老的 `_FIELD_TYPES` 给它们写了 ("http",)，会让只引用这些字段的规则被"只挂 http" ——
    既不在别的类型上求值、又永远匹配不上，属于静默死规则；现在它们落通配集合。
    """
    for field in ("host", "referrer"):
        index = build_rule_index([_rule(field)])
        assert index["wild"], field
        assert index["types"] == {}, field


def test_wazuh_web_attack_rule_covers_both_event_types() -> None:
    """Wazuh 的 Web 事件有两个值：`wazuh_web_attack`（规则组命中）与 `web_attack`
    （描述里带 sql/injection，见 `normalize_wazuh` 的 `_wazuh_event_type`）——规则要都覆盖。"""
    rule = next(r for r in builtin.BUILTIN_RULES if r["name"] == "内置-Web攻击（主机监控）")
    cond = rule["conditions"]["rules"][0]
    assert cond["op"] == "in"
    assert set(cond["value"]) == {"wazuh_web_attack", "web_attack"}


def test_auth_scheme_parsed_from_zeek_req_headers() -> None:
    doc = dict(samples.DOCS["http"])
    doc["zeek"] = {
        **doc["zeek"],
        "req_headers": (
            "Host: example.internal\r\n"
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig\r\n"
        ),
    }
    entry = normalize_zeek(doc)
    assert entry is not None
    assert entry.auth_scheme == "bearer"


def test_auth_scheme_silent_when_no_authorization_header() -> None:
    doc = dict(samples.DOCS["http"])
    doc["zeek"] = {**doc["zeek"], "req_headers": "Host: example.internal\r\n"}
    entry = normalize_zeek(doc)
    assert entry is not None
    assert entry.auth_scheme == ""


def test_baseline_observe_threshold_uses_window_not_cumulative(monkeypatch) -> None:
    """`BaselineEngine.observe` 的落库阈值必须看"距上次落库攒了多少"，不是累计值 ——
    否则累计越过 `baseline_max_observations` 之后，每条事件都会触发一次整批落库。"""
    # 基线引擎只在 NDR 栈里（智能体栈不做基线）——agent 栈跳过。
    baseline_engine = pytest.importorskip("app.baseline.engine")

    class _Settings:
        baseline_enabled = True
        profile_enabled = True
        baseline_max_observations = 1000  # 引擎里还有 max(1000, 配置) 的下限

    eng = baseline_engine.BaselineEngine()
    # 参数现在走 `params`（后台可改），补丁要打到它上，打 settings 已经无效了
    monkeypatch.setattr(baseline_engine.params, "baseline_enabled", lambda: True)
    monkeypatch.setattr(baseline_engine.params, "profile_enabled", lambda: True)
    monkeypatch.setattr(baseline_engine.params, "max_observations", lambda: 1000)
    flushes: list[int] = []

    def fake_flush() -> None:
        flushes.append(eng._obs_since_flush)
        eng._obs_since_flush = 0

    monkeypatch.setattr(eng, "flush", fake_flush)
    # 账号 + 会话各算一个实体：一条事件就 +2，600 次 = 1200 条观测。
    cookie_name = str(real_settings.session_cookie_names).split(",")[0].strip() or "PHPSESSID"
    entry = UnifiedLog(
        source_system="zeek",
        ts=datetime.now(UTC),
        event_type="http_request",
        log_type="http",
        account="alice",
        cookie=f"{cookie_name}=abc123def456",
    )
    for _ in range(600):
        eng.observe(entry)
    # 累计观测数照旧保留（界面上看的是它）：
    assert eng.stats["observed"] == 1200
    # 但只在攒够 1000 条时落了一次库，而不是越过阈值后每条都落（那会是 101 次）。
    assert len(flushes) == 1
    assert eng._obs_since_flush == 200


# ---------- 频次规则：扇出判定（2026-10 扫描规则改造）----------


class _FakeRedis:
    """够 `FreqWindow` 用的小号 Redis：ZSET（zadd/zremrangebyscore/zcard/expire）+ SET NX。"""

    def __init__(self) -> None:
        self.zsets: dict[str, dict[str, float]] = {}
        self.flags: dict[str, str] = {}

    def pipeline(self) -> Any:
        return _FakePipe(self)

    def zcard(self, key: str) -> int:
        return len(self.zsets.get(key) or {})

    def zadd(self, key: str, mapping: dict[str, float]) -> Any:
        # 频率窗口对 distinct 成员是直接 zadd 的（不走 pipeline），所以这里也要有。
        self.zsets.setdefault(key, {}).update(mapping)
        return len(mapping)

    def set(self, key: str, value: str, nx: bool = False, ex: int | None = None) -> Any:
        if nx and key in self.flags:
            return None
        self.flags[key] = value
        return True


class _FakePipe:
    def __init__(self, redis: _FakeRedis) -> None:
        self.r = redis

    def zremrangebyscore(self, key: str, _min: Any, max_score: float) -> Any:
        for member, score in list((self.r.zsets.get(key) or {}).items()):
            if score <= max_score:
                self.r.zsets[key].pop(member, None)
        return self

    def zadd(self, key: str, mapping: dict[str, float]) -> Any:
        self.r.zsets.setdefault(key, {}).update(mapping)
        return self

    def expire(self, *_a: Any, **_k: Any) -> Any:
        return self

    def execute(self) -> list[Any]:
        return []


def _conn_events(
    ports: list[int],
    *,
    conn_state: str = "S0",
    dst: str = "172.16.196.111",
    src: str = "172.16.199.50",
) -> list[UnifiedLog]:
    """造一组 conn 事件（走真归一化，连 event_type/虚拟字段一起验）。"""
    out: list[UnifiedLog] = []
    for i, port in enumerate(ports):
        doc = samples.envelope(
            {
                **samples.CONN,
                "id.orig_h": src,
                "id.orig_p": 40000 + i,
                "id.resp_h": dst,
                "id.resp_p": port,
                "conn_state": conn_state,
                "uid": f"C{i}",
            },
            "conn",
            "/logs/conn.log",
        )
        entry = normalize_zeek(doc)
        assert entry is not None
        out.append(entry)
    return out


def _builtin(name: str) -> dict:
    return next(r for r in builtin.BUILTIN_RULES if r["name"] == name)


def _http_events(cookie: str, ips: list[str]) -> list[UnifiedLog]:
    """造一组带 Cookie 头的 http 事件（走真归一化：session_id 也从这里算出来）。"""
    out: list[UnifiedLog] = []
    for i, ip in enumerate(ips):
        doc = samples.envelope(
            {
                **samples.HTTP,
                "id.orig_h": ip,
                "id.orig_p": 40000 + i,
                "cookie": cookie,
                "uid": f"H{i}",
            },
            "http",
            "/logs/http.log",
        )
        entry = normalize_zeek(doc)
        assert entry is not None
        out.append(entry)
    return out


def _fires(rule: dict, events: list[UnifiedLog]) -> bool:
    """按 runner 的口径判一轮：先过条件，再进频率窗口（与逐条规则的评审一致）。"""
    window = _FreqWindow(_FakeRedis(), 300, 300)
    cond = rule["conditions"]
    return any(window.observe(rule, e) for e in events if evaluate_conditions(cond, e))


@needs_freq
def test_session_rule_keys_on_session_id_not_whole_cookie() -> None:
    """「会话跨IP复用」按 session_id 判：真会话跨 IP 会中，常量 cookie 跨 IP 不再误报。

    2026-10 实测：整条 Cookie 头当键时，`Path=/`（应用造的常量 cookie）跨 2 个源 IP、
    `EPORTAL_COOKIE_PASSWORD=` 空值模板跨 164 个源 IP ⇒ 24h 337 条 critical 摘要零真命中。
    """
    rule = _builtin("内置-会话跨IP复用")
    # 同一个真会话 cookie 从两个源 IP 来 → 触发
    assert _fires(rule, _http_events("JSESSIONID=abc", ["172.16.199.1", "172.16.199.2"])) is True
    # 常量 cookie 跨 100 个源 IP → 不触发（session_id 为空 ⇒ 条件就不成立）
    many = [f"172.16.199.{i}" for i in range(1, 101)]
    assert _fires(rule, _http_events("Path=/; Path=/", many)) is False
    assert _fires(rule, _http_events("EPORTAL_COOKIE_PASSWORD=; X=1", many)) is False


@needs_freq
def test_fast_port_scan_fires_on_fanout_only() -> None:
    """扇出才告警：12 个不同目的端口会中；同样 3 个端口重试 300 次不会中。

    依据（2026-10 实测）：被退役的「扫描尝试连接」误报 ≈ 100% —— 近 15 分钟 92 个源里
    不同目的端口最多的只有 **3 个**；所以 ≥8 个不同端口这个门槛有 ~2.6× 余量。
    """
    rule = _builtin("内置-快速端口扫描")
    window = _FreqWindow(_FakeRedis(), 300, 300)
    fired = [window.observe(rule, entry) for entry in _conn_events(list(range(1, 13)))]
    assert any(fired), "12 个不同目的端口应当触发"

    retry = _FreqWindow(_FakeRedis(), 300, 300)
    hits = [retry.observe(rule, entry) for entry in _conn_events([80, 443, 8000] * 100)]
    assert not any(hits), "固定 3 个端口反复重试不该触发"


@needs_freq
def test_fast_port_scan_counts_rejected_not_established_resets() -> None:
    """失败判据 = 无回应（S0）+ RST 回应（REJ/RSTOS0/RSTRH）；**不含**已建立后的 RST。

    `RSTO`/`RSTR` 是「握手已建立、随后一方 RST 断开」= 正常业务断连（见 conn_states 表），
    把它们算进来会立刻引入新一批误报。
    """
    rule = _builtin("内置-快速端口扫描")
    cond = rule["conditions"]
    assert evaluate_conditions(cond, _conn_events([443])[0]) is True
    assert evaluate_conditions(cond, _conn_events([443], conn_state="REJ")[0]) is True
    assert evaluate_conditions(cond, _conn_events([443], conn_state="SF")[0]) is False
    assert evaluate_conditions(cond, _conn_events([443], conn_state="RSTO")[0]) is False

    # 收到 RST 的失败尝试同样计入扇出（补上「扫活主机关闭端口」的检出）
    window = _FreqWindow(_FakeRedis(), 300, 300)
    fired = [
        window.observe(rule, entry) for entry in _conn_events(list(range(1, 13)), conn_state="REJ")
    ]
    assert any(fired)


# ---------- 规则适用范围（network / host，2026-10 界面「检测规则」分组用）----------


def test_builtin_rule_scope_by_conditions() -> None:
    """内置规则的适用范围由**条件**判定：引用主机监控信号的是主机规则，其余算网络规则。

    界面「检测规则」按它分「网络（网络采集器）/ 主机（主机监控）」两组，检测器按它过滤
    （主机规则只在主机事件上求值，反之亦然）。少数条件里看不出侧向的认证/账号类规则
    在 `builtin._SCOPE_HOST_OVERRIDES` 里手工归主机（本部署由主机监控驱动）。
    """
    scope = builtin.rule_scope
    assert scope(_builtin("内置-主机文件完整性变更")) == "host"
    assert scope(_builtin("内置-主机策略违规")) == "host"
    assert scope(_builtin("内置-主机高危告警")) == "host"
    assert scope(_builtin("内置-弱TLS版本")) == "network"
    assert scope(_builtin("内置-命令注入特征")) == "network"
    assert scope(_builtin("内置-多路径探测(漏洞挖掘)")) == "network"
    # 条件里看不出侧向（brute_force / account），按覆盖表归主机
    for name in (
        "内置-暴力破解",
        "内置-主机登录失败",
        "内置-高频认证失败",
        "内置-撞库(同账号多源)",
    ):
        assert scope(_builtin(name)) == "host", name


@needs_freq
def test_detector_filters_rules_by_side() -> None:
    """检测器按事件来源过滤规则：主机事件只跑主机规则，网络事件只跑网络规则（缺 scope 按 network）。"""
    runner = importlib.import_module("app.detector.runner")
    z = UnifiedLog(
        source_system="zeek", ts=datetime.now(UTC), event_type="http_request", log_type="http"
    )
    w = UnifiedLog(
        source_system="wazuh",
        ts=datetime.now(UTC),
        event_type="wazuh_system_error",
        log_type="wazuh",
    )
    assert runner._entry_side(z) == "network"
    assert runner._entry_side(w) == "host"
    rules = [{"name": "n", "scope": "network"}, {"name": "h", "scope": "host"}, {"name": "d"}]
    assert [r["name"] for r in runner._same_side(rules, "network")] == ["n", "d"]
    assert [r["name"] for r in runner._same_side(rules, "host")] == ["h"]


@needs_freq
def test_rules_api_carries_scope() -> None:
    """规则接口带 scope：默认 network、非法值被拒、返回体里有它（界面靠它分组）。"""
    route = importlib.import_module("app.api.routes.rules")
    assert route.RuleIn(name="x").scope == "network"
    body = route.RuleIn(
        name="x",
        conditions={"rules": [{"field": "event_type", "op": "eq", "value": "http_request"}]},
        scope="bogus",
    )
    assert any(e["field"] == "scope" for e in route._validate(body))
    row = SimpleNamespace(
        id="1",
        name="x",
        description="",
        conditions={},
        severity="low",
        source="user",
        enabled=True,
        priority=100,
        scope="host",
    )
    assert route._rule_dict(row)["scope"] == "host"
