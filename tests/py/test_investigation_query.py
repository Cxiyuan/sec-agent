"""D 组修复的回归测试：调查工具 / MCP 查询层。

覆盖 QA 报告里 D 组的几条必修/应修，全部是**纯函数级**验证（不连 ES/Redis/PG）：

- `exists` 算子语义（必修1）：归一化给所有字符串字段默认空串，原生 `exists` 因此恒真；
  字符串字段的「存在」必须是「键在且值不是空串」；
- 回溯上限跟随**运行时**保留期（必修3）：`es_config.retention_days()` 而不是静态 settings；
- 跨来源取证不丢 Wazuh（必修2）：合并排序后截断，`by_source.returned` 与真实返回一致；
- 超时降级要真的能触发 + 错误文案区分「超时」与「ES 不可达」（应修4）；
- 网段过滤下推到 ES（应修5）：ip 字段用 CIDR term，text/keyword 用对齐 prefix；
- 结论枚举校验（应修6）与死代码删除的回归护栏（清理7）。

这些模块只在 NDR 侧存在（agent 侧有各自的同名副本），所以 `--stack=agent` 下整文件跳过。
"""

from __future__ import annotations

import importlib
from ipaddress import ip_network
from types import ModuleType
from typing import Any

import pytest

# 假 mapping：只放本文件用到的字段，口径与实机 `_field_caps` 一致
# （src_ip/dst_ip/ja4/qtype 实机是动态映射出来的 text，file_is_orig 是 boolean）。
_MAPPING = {
    "ja4": "text",
    "ja4.keyword": "keyword",
    "qtype": "text",
    "qtype.keyword": "keyword",
    "file_is_orig": "boolean",
    "src_ip": "text",
    "src_ip.keyword": "keyword",
    "dst_ip": "text",
    "dst_ip.keyword": "keyword",
}


@pytest.fixture(scope="module")
def mods(request: pytest.FixtureRequest) -> dict[str, ModuleType]:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("调查工具 / MCP 查询层只在 NDR 侧")
    return {
        "es_query": importlib.import_module("app.investigation.es_query"),
        "catalog": importlib.import_module("app.investigation.catalog"),
        "tools": importlib.import_module("app.investigation.tools"),
        "ndr_tools": importlib.import_module("app.mcp.ndr_tools"),
    }


@pytest.fixture
def fake_mapping(monkeypatch: pytest.MonkeyPatch, mods: dict[str, ModuleType]) -> None:
    """不连 ES：mapping 固定成 _MAPPING，索引名固定成运行时那一个。"""
    monkeypatch.setattr(mods["catalog"], "mapping_types", lambda index: dict(_MAPPING))
    monkeypatch.setattr(mods["es_query"], "index_pattern", lambda: "shentong-events-*")


# ---------- 必修1：exists = 「键在且值不是空串」 ----------


def test_exists_on_text_field_means_nonempty_keyword(
    mods: dict[str, ModuleType], fake_mapping: None
) -> None:
    clause = mods["es_query"].build_clause("ja4", {"exists": True})
    assert clause == {
        "bool": {
            "filter": [
                {"exists": {"field": "ja4"}},
                {
                    "bool": {
                        "must_not": {
                            "bool": {
                                "should": [{"term": {"ja4.keyword": ""}}],
                                "minimum_should_match": 1,
                            }
                        }
                    }
                },
            ]
        }
    }


def test_exists_false_is_the_negation(mods: dict[str, ModuleType], fake_mapping: None) -> None:
    positive = mods["es_query"].build_clause("ja4", {"exists": True})
    assert mods["es_query"].build_clause("ja4", {"exists": False}) == {
        "bool": {"must_not": positive}
    }


def test_exists_on_bool_field_stays_native(mods: dict[str, ModuleType], fake_mapping: None) -> None:
    """boolean 字段没有「空串」形态，仍走原生 exists（别把 .keyword 拼上去）。"""
    assert mods["es_query"].build_clause("file_is_orig", {"exists": True}) == {
        "exists": {"field": "file_is_orig"}
    }


def test_catalog_declares_file_is_orig_as_bool(mods: dict[str, ModuleType]) -> None:
    """目录声明成 bool，`_coerce` 的布尔支路才可达（以前声明 keyword → 整支死代码）。"""
    assert mods["catalog"].FIELDS["file_is_orig"]["kind"] == "bool"
    assert mods["es_query"]._coerce("file_is_orig", "true") is True
    assert mods["es_query"]._coerce("file_is_orig", "no") is False


def test_qtype_doc_says_numeric_code(mods: dict[str, ModuleType]) -> None:
    assert "数字码" in mods["catalog"].FIELDS["qtype"]["desc"]


# ---------- 必修3：回溯上限跟随运行时保留期 ----------


def test_max_lookback_days_follows_runtime_retention(
    monkeypatch: pytest.MonkeyPatch, mods: dict[str, ModuleType]
) -> None:
    es_query = mods["es_query"]
    monkeypatch.setattr(
        es_query.es_config,
        "current",
        lambda: {"es.retention_days": "90", "es.events_index": "shentong-events-*"},
    )
    assert es_query.max_lookback_days() == 90


def test_index_pattern_follows_runtime_config(
    monkeypatch: pytest.MonkeyPatch, mods: dict[str, ModuleType]
) -> None:
    es_query = mods["es_query"]
    monkeypatch.setattr(
        es_query.es_config,
        "current",
        lambda: {"es.events_index": "shentong-events-2026.*", "es.retention_days": "30"},
    )
    assert es_query.index_pattern() == "shentong-events-2026.*"


# ---------- 应修4：降级重试与错误文案 ----------


def test_with_degrade_retries_with_narrowed_window(mods: dict[str, ModuleType]) -> None:
    es_query = mods["es_query"]
    calls: list[tuple[Any, Any]] = []

    def run(start: Any, end: Any) -> dict[str, Any]:
        calls.append((start, end))
        if len(calls) == 1:
            raise RuntimeError("search_phase_execution_exception: timed out after 45s")
        return {"ok": True}

    resp, degraded = es_query._with_degrade(
        run, "2026-01-01T00:00:00+00:00", "2026-01-02T00:00:00+00:00"
    )
    assert resp == {"ok": True}
    assert degraded is True
    # 第二次必须拿到「对半后」的真实窗口——以前传的是原始入参（可能是 None），
    # _narrow(None, None) 原样返回 → 直接 raise，降级重试永远不发生。
    assert calls == [
        ("2026-01-01T00:00:00+00:00", "2026-01-02T00:00:00+00:00"),
        ("2026-01-01T12:00:00+00:00", "2026-01-02T00:00:00+00:00"),
    ]


def test_with_degrade_does_not_retry_hard_failure(mods: dict[str, ModuleType]) -> None:
    es_query = mods["es_query"]
    calls: list[tuple[Any, Any]] = []

    def run(start: Any, end: Any) -> dict[str, Any]:
        calls.append((start, end))
        raise RuntimeError("ConnectionError: connection refused")

    with pytest.raises(RuntimeError):
        es_query._with_degrade(run, "2026-01-01T00:00:00+00:00", "2026-01-02T00:00:00+00:00")
    assert len(calls) == 1


def test_failure_message_splits_timeout_from_hard_failure(mods: dict[str, ModuleType]) -> None:
    es_query = mods["es_query"]
    timeout = es_query._failure_message("查询", RuntimeError("timed out after 45s"))
    assert "超时" in timeout and "缩小时间窗" in timeout
    hard = es_query._failure_message("聚合", RuntimeError("ConnectionError: connection refused"))
    assert "不是超时" in hard and "缩小时间窗没用" in hard


# ---------- 必修（2026-10-03 实机发现）：request_timeout 必须是数字 ----------
# 实机现象：MCP 取证工具（search_events / aggregate_events / get_event）全部返回
# 「ES 查询超时…请缩小时间窗」，实际是 `request_timeout="45s"` 让 urllib3 抛
# ValueError（Timeout value connect was 45s…），查询根本没发出去。


def test_query_timeout_is_numeric(mods: dict[str, ModuleType]) -> None:
    es_query = mods["es_query"]
    value = es_query.query_timeout()
    assert isinstance(value, (int, float)) and not isinstance(value, bool)
    assert value >= 5


def test_search_passes_numeric_request_timeout(
    monkeypatch: pytest.MonkeyPatch, fake_mapping: None, mods: dict[str, ModuleType]
) -> None:
    es_query = mods["es_query"]
    seen: dict[str, Any] = {}

    class FakeEs:
        def search(self, **kwargs: Any) -> dict[str, Any]:
            seen.update(kwargs)
            return {"hits": {"hits": [], "total": {"value": 0}}}

    monkeypatch.setattr(es_query, "_es", lambda: FakeEs())
    out = es_query.search(
        "zeek", start="2026-01-01T00:00:00+00:00", end="2026-01-01T01:00:00+00:00"
    )
    assert out["hits"] == []
    assert isinstance(seen["request_timeout"], (int, float))
    assert not isinstance(seen["request_timeout"], bool)


def test_aggregate_passes_numeric_request_timeout(
    monkeypatch: pytest.MonkeyPatch, fake_mapping: None, mods: dict[str, ModuleType]
) -> None:
    es_query = mods["es_query"]
    seen: dict[str, Any] = {}

    class FakeEs:
        def search(self, **kwargs: Any) -> dict[str, Any]:
            seen.update(kwargs)
            return {"hits": {"hits": []}, "aggregations": {"buckets": {"buckets": []}}}

    monkeypatch.setattr(es_query, "_es", lambda: FakeEs())
    es_query.aggregate(
        "zeek", "src_ip", start="2026-01-01T00:00:00+00:00", end="2026-01-01T01:00:00+00:00"
    )
    assert isinstance(seen["request_timeout"], (int, float))


def test_is_timeout_ignores_parameter_errors(mods: dict[str, ModuleType]) -> None:
    es_query = mods["es_query"]
    bad = ValueError("Timeout value connect was 45s, but it must be an int, float or None.")
    assert es_query._is_timeout(bad) is False
    # 这条文案必须落到「不是超时」那一支，否则模型会一直原地缩小时间窗
    assert "不是超时" in es_query._failure_message("查询", bad)
    assert es_query._is_timeout(RuntimeError("search_phase_execution_exception: timed out")) is True


# ---------- 必修2：跨来源取证不丢 Wazuh ----------


def test_search_multi_keeps_wazuh_hits(
    monkeypatch: pytest.MonkeyPatch, mods: dict[str, ModuleType]
) -> None:
    es_query, tools = mods["es_query"], mods["tools"]

    def fake_search(source: str, **kwargs: Any) -> dict[str, Any]:
        rows = {
            "zeek": [
                {"ts": "2026-01-01T00:00:01+00:00", "source_system": "zeek"},
                {"ts": "2026-01-01T00:00:03+00:00", "source_system": "zeek"},
            ],
            "wazuh": [{"ts": "2026-01-01T00:00:02+00:00", "source_system": "wazuh"}],
        }[source]
        return {"hits": rows, "truncated": False, "index": "shentong-events-*"}

    monkeypatch.setattr(es_query, "search", fake_search)
    out = tools._search_multi(["zeek", "wazuh"], filters={}, limit=2)
    # 按时间倒序合并后截断：Wazuh 那条（00:00:02）必须留下，不能整段被 zeek 挤掉
    assert [h["source_system"] for h in out["hits"]] == ["zeek", "wazuh"]
    assert out["by_source"]["zeek"] == {
        "returned": 1,
        "fetched": 2,
        "truncated": False,
        "index": "shentong-events-*",
    }
    assert out["by_source"]["wazuh"]["returned"] == 1
    assert out["by_source"]["wazuh"]["fetched"] == 1
    assert out["fetched"] == 3
    assert out["truncated"] is True
    assert any("截掉 1 条" in note for note in out["notes"])


def test_search_multi_keeps_other_source_when_one_fails(
    monkeypatch: pytest.MonkeyPatch, mods: dict[str, ModuleType]
) -> None:
    es_query, tools = mods["es_query"], mods["tools"]

    def fake_search(source: str, **kwargs: Any) -> dict[str, Any]:
        if source == "wazuh":
            raise es_query.QueryError("索引不存在")
        return {
            "hits": [{"ts": "2026-01-01T00:00:01+00:00", "source_system": "zeek"}],
            "truncated": False,
            "index": "shentong-events-*",
        }

    monkeypatch.setattr(es_query, "search", fake_search)
    out = tools._search_multi(["zeek", "wazuh"], filters={}, limit=10)
    assert [h["source_system"] for h in out["hits"]] == ["zeek"]
    assert any("wazuh" in note for note in out["notes"])


# ---------- 应修5：网段过滤下推 ----------


def test_net_clauses_uses_cidr_terms_when_field_is_ip(
    monkeypatch: pytest.MonkeyPatch, mods: dict[str, ModuleType]
) -> None:
    monkeypatch.setattr(mods["catalog"], "es_type", lambda index, path: "ip")
    clauses, local = mods["ndr_tools"]._net_clauses(
        "idx", [ip_network("10.0.0.0/8"), ip_network("192.0.2.0/24")], ("src_ip", "dst_ip")
    )
    assert local == []
    assert clauses == [
        {
            "bool": {
                "should": [
                    {"terms": {"src_ip": ["10.0.0.0/8", "192.0.2.0/24"]}},
                    {"terms": {"dst_ip": ["10.0.0.0/8", "192.0.2.0/24"]}},
                ],
                "minimum_should_match": 1,
            }
        }
    ]


def test_net_clauses_prefix_for_aligned_text_field(
    monkeypatch: pytest.MonkeyPatch, mods: dict[str, ModuleType]
) -> None:
    monkeypatch.setattr(mods["catalog"], "es_type", lambda index, path: "text")
    clauses, local = mods["ndr_tools"]._net_clauses(
        "idx", [ip_network("192.0.2.0/24")], ("src_ip.keyword", "dst_ip.keyword")
    )
    assert local == []
    assert clauses == [
        {
            "bool": {
                "should": [
                    {"prefix": {"src_ip.keyword": "192.0.2."}},
                    {"prefix": {"dst_ip.keyword": "192.0.2."}},
                ],
                "minimum_should_match": 1,
            }
        }
    ]


def test_net_clauses_single_host_uses_exact_term(
    monkeypatch: pytest.MonkeyPatch, mods: dict[str, ModuleType]
) -> None:
    monkeypatch.setattr(mods["catalog"], "es_type", lambda index, path: "keyword")
    clauses, local = mods["ndr_tools"]._net_clauses(
        "idx", [ip_network("192.0.2.5/32")], ("src_ip.keyword", "dst_ip.keyword")
    )
    assert local == []
    assert clauses == [
        {
            "bool": {
                "should": [
                    {"term": {"src_ip.keyword": "192.0.2.5"}},
                    {"term": {"dst_ip.keyword": "192.0.2.5"}},
                ],
                "minimum_should_match": 1,
            }
        }
    ]


def test_net_clauses_unaligned_goes_local_only(
    monkeypatch: pytest.MonkeyPatch, mods: dict[str, ModuleType]
) -> None:
    monkeypatch.setattr(mods["catalog"], "es_type", lambda index, path: "text")
    clauses, local = mods["ndr_tools"]._net_clauses(
        "idx", [ip_network("172.16.0.0/12")], ("src_ip.keyword", "dst_ip.keyword")
    )
    assert clauses == []
    assert local == ["172.16.0.0/12"]


def test_es_path_uses_keyword_for_text_field(
    monkeypatch: pytest.MonkeyPatch, mods: dict[str, ModuleType]
) -> None:
    monkeypatch.setattr(mods["catalog"], "mapping_types", lambda index: dict(_MAPPING))
    assert mods["ndr_tools"]._es_path("idx", "src_ip") == "src_ip.keyword"
    assert mods["ndr_tools"]._es_path("idx", "file_is_orig") == "file_is_orig"


def test_es_index_follows_runtime_config(
    monkeypatch: pytest.MonkeyPatch, mods: dict[str, ModuleType]
) -> None:
    from app.ingestion import es_config

    monkeypatch.setattr(es_config, "current", lambda: {"es.events_index": "shentong-events-2026.*"})
    assert mods["ndr_tools"]._es_index() == "shentong-events-2026.*"


class _FakeEs:
    """只记下查询体、返回固定结果，用来验证 `fetch_window` 到底把什么下推给了 ES。"""

    def __init__(self, docs: list[dict[str, Any]]) -> None:
        self.docs = docs
        self.queries: list[dict[str, Any]] = []
        self.indexes: list[str] = []

    def count(self, index: str, query: dict[str, Any]) -> dict[str, Any]:
        self.indexes.append(index)
        self.queries.append(query)
        return {"count": len(self.docs)}

    def search(
        self, index: str, query: dict[str, Any], size: int, sort: list[dict[str, str]]
    ) -> dict[str, Any]:
        self.indexes.append(index)
        self.queries.append(query)
        return {
            "hits": {
                "hits": [
                    {"_index": index, "_id": str(i), "_source": doc}
                    for i, doc in enumerate(self.docs)
                ]
            }
        }


def test_fetch_window_pushes_nets_and_ips_down(
    monkeypatch: pytest.MonkeyPatch, mods: dict[str, ModuleType]
) -> None:
    from app.ingestion import es_client, es_config

    monkeypatch.setattr(mods["catalog"], "mapping_types", lambda index: dict(_MAPPING))
    monkeypatch.setattr(mods["catalog"], "es_type", lambda index, path: "text")
    monkeypatch.setattr(es_config, "current", lambda: {"es.events_index": "shentong-events-2026.*"})
    fake = _FakeEs([{"ts": "2026-01-01T00:00:01+00:00", "src_ip": "192.0.2.5"}])
    monkeypatch.setattr(es_client, "get_es", lambda: fake)

    out = mods["ndr_tools"]._fetch_window(
        {
            "start": "2026-01-01T00:00:00Z",
            "end": "2026-01-02T00:00:00Z",
            "nets": "192.0.2.0/24",
            "ips": "192.0.2.5",
            "limit": 5,
        }
    )
    assert out["index"] == "shentong-events-2026.*"  # 运行时索引，不是静态 settings
    assert out["nets_pushed_down"] is True
    assert out["returned"] == 1
    # 网段与 IP 都进了 ES 查询（而不是取回后本地过滤），路径是 keyword 路径
    filters = fake.queries[0]["bool"]["filter"]
    assert str({"prefix": {"src_ip.keyword": "192.0.2."}}) in str(filters)
    assert "src_ip.keyword" in str(filters)


def test_fetch_window_unaligned_nets_stay_local(
    monkeypatch: pytest.MonkeyPatch, mods: dict[str, ModuleType]
) -> None:
    from app.ingestion import es_client, es_config

    monkeypatch.setattr(mods["catalog"], "mapping_types", lambda index: dict(_MAPPING))
    monkeypatch.setattr(mods["catalog"], "es_type", lambda index, path: "text")
    monkeypatch.setattr(es_config, "current", lambda: {"es.events_index": "idx"})
    fake = _FakeEs([{"ts": "2026-01-01T00:00:01+00:00", "src_ip": "10.1.2.3"}])
    monkeypatch.setattr(es_client, "get_es", lambda: fake)

    out = mods["ndr_tools"]._fetch_window(
        {"start": "2026-01-01T00:00:00Z", "end": "2026-01-02T00:00:00Z", "nets": "172.16.0.0/12"}
    )
    assert out["nets_pushed_down"] is False
    assert out["returned"] == 0  # 下推不了 /12，靠本地过滤把 10.1.2.3 剔掉
    assert any("172.16.0.0/12" in note for note in out["notes"])


# ---------- 应修6：结论枚举校验 ----------


def test_enum_value_normalizes_aliases(mods: dict[str, ModuleType]) -> None:
    ndr_tools = mods["ndr_tools"]
    assert ndr_tools._enum_value(
        "高危",
        default="info",
        allowed=ndr_tools.SEVERITY_VALUES,
        aliases=ndr_tools._SEVERITY_ALIASES,
        label="severity",
    ) == ("high", "")
    assert ndr_tools._enum_value(
        "TRUE_POSITIVE",
        default="done",
        allowed=ndr_tools.STATUS_VALUES,
        aliases=ndr_tools._STATUS_ALIASES,
        label="status",
    ) == ("true_positive", "")
    assert ndr_tools._enum_value(
        "",
        default="info",
        allowed=ndr_tools.SEVERITY_VALUES,
        aliases=ndr_tools._SEVERITY_ALIASES,
        label="severity",
    ) == ("info", "")


def test_enum_value_rejects_unknown(mods: dict[str, ModuleType]) -> None:
    ndr_tools = mods["ndr_tools"]
    value, err = ndr_tools._enum_value(
        "maybe",
        default="done",
        allowed=ndr_tools.STATUS_VALUES,
        aliases=ndr_tools._STATUS_ALIASES,
        label="status",
    )
    assert value == ""
    assert "不认识" in err and "true_positive" in err


# ---------- 清理7：死代码删除的护栏 ----------


def test_dead_catalog_helpers_are_gone(mods: dict[str, ModuleType]) -> None:
    catalog = mods["catalog"]
    assert not hasattr(catalog, "field_names")
    assert not hasattr(catalog, "catalog_text")
    assert not hasattr(catalog, "spec")


def test_dead_query_and_tool_helpers_are_gone(mods: dict[str, ModuleType]) -> None:
    assert not hasattr(mods["es_query"], "count")
    assert not hasattr(mods["tools"], "tool_catalog_text")
    assert not hasattr(mods["tools"], "spec_for_api")
    assert not hasattr(mods["ndr_tools"], "tool_catalog_text")
    # 对外的工具注册表必须还在（智能体靠它调工具）
    assert "fetch_window" in mods["ndr_tools"].TOOLS
    assert "search_events" in mods["tools"].TOOLS
