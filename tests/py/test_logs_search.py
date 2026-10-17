"""日志检索接口的查询构造（`app/api/routes/logs.py`）。

只测**纯函数**部分（不连 ES）：时间窗、字段白名单、关键字全文检索的位置与组合方式。
这几条是"检索结果不对"的常见根因 —— 字段没打 `.keyword`（精确匹配失效）、
不在白名单的字段被拼进查询、关键字被塞进 filter（导致不能打分）等。
"""

from __future__ import annotations

import importlib
from types import ModuleType

import pytest


@pytest.fixture(scope="module")
def logs_mod(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("日志检索只在 NDR 侧")
    return importlib.import_module("app.api.routes.logs")


def test_query_has_time_window_and_filters(logs_mod: ModuleType) -> None:
    body = logs_mod._build_query(
        q="",
        minutes=60,
        text_filters={"src_ip": "10.1.2.3", "account": ""},
        num_filters={"dst_port": 443},
        log_type_extra="http",
    )
    bool_ = body["query"]["bool"]
    # 时间窗
    assert bool_["must"][0] == {"range": {"@timestamp": {"gte": "now-60m"}}}
    # 日志类型走 keyword 精确匹配
    assert {"term": {"log_type.keyword": "http"}} in bool_["must"]
    # 字符串字段按 .keyword 精确匹配；空值不上条件
    assert {"term": {"src_ip.keyword": "10.1.2.3"}} in bool_["filter"]
    assert all("account" not in str(cond) for cond in bool_["filter"])
    # 数值字段直接用字段名
    assert {"term": {"dst_port": 443}} in bool_["filter"]
    # 没有关键字就不加全文检索
    assert not any("multi_match" in str(cond) for cond in bool_["must"])


def test_keyword_search_goes_to_must_not_filter(logs_mod: ModuleType) -> None:
    """关键字必须放在 must（参与打分），放 filter 里就退化成"过滤"了。"""
    body = logs_mod._build_query(
        q="evil.example",
        minutes=15,
        text_filters={},
        num_filters={},
        log_type_extra="",
    )
    must = body["query"]["bool"]["must"]
    match = [cond for cond in must if "multi_match" in cond]
    assert len(match) == 1
    assert match[0]["multi_match"]["query"] == "evil.example"
    assert "hostname" in match[0]["multi_match"]["fields"]
    assert match[0]["multi_match"]["lenient"] is True


def test_unknown_field_is_ignored(logs_mod: ModuleType) -> None:
    """非白名单字段不能进查询（防止有人拼字段名）。"""
    body = logs_mod._build_query(
        q="",
        minutes=5,
        text_filters={"password": "x", "src_ip": "10.1.2.3"},
        num_filters={"not_a_field": 1},
        log_type_extra="",
    )
    filters = body["query"]["bool"]["filter"]
    assert {"term": {"src_ip.keyword": "10.1.2.3"}} in filters
    assert len(filters) == 1, "未知字段必须被丢掉"


def test_field_list_exposes_labels(logs_mod: ModuleType) -> None:
    """前端表单靠 `/fields` 拿字段清单：必须有 field + 中文 label。"""
    assert "src_ip" in logs_mod.TEXT_FIELDS
    assert logs_mod.TEXT_FIELDS["src_ip"]
    assert "dst_port" in logs_mod.NUM_FIELDS
    # 列表返回的字段集合要足够渲染表格（时间/类型/源/目的/摘要）
    for field in ("@timestamp", "log_type", "src_ip", "dst_ip", "summary"):
        assert field in logs_mod.LIST_SOURCE
