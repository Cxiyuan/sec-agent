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

from datetime import UTC, datetime

import pytest
import samples
from app.config import settings as real_settings
from app.ingestion.normalizer import normalize_zeek
from app.rules import builtin
from app.rules.engine import build_rule_index
from app.schemas import UnifiedLog


def _rule(field: str, *, value: str = "x", op: str = "eq") -> dict:
    return {
        "name": f"t-{field}",
        "source": "test",
        "conditions": {"logic": "and", "rules": [{"field": field, "op": op, "value": value}]},
    }


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
    monkeypatch.setattr(baseline_engine, "settings", _Settings())
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
