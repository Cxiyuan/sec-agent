"""Wazuh「接入状态」的 ES 读路径（``api/routes/wazuh.py:_ingest_stats``）回归测试。

这条路径是「API 通了但日志没进来」的唯一可见信号，所以它自己不能坏：

- **精确匹配/聚合必须走 keyword 路径**：``log_type``/``source_system`` 实机是 ``text``
  （动态映射另给一个 ``.keyword`` 副本）。对 text 主路径做 ``terms`` 聚合会被 ES 直接拒
  （``Fielddata is disabled on [log_type]``），界面就只剩「读 ES 失败」——2026-10 实机
  部署时就是这样：Wazuh 数据其实已经入库，面板却全 0 + 报错。
- **总数必须精确**：``size=0`` 的 search 默认 ``hits.total`` 超过 1 万只给下界（``gte``），
  界面会把下界当精确值显示，所以要求显式 ``track_total_hits=True``。
- ES 不可达时要回结构化错误，而不是把 500 抛给界面。

只在 NDR 栈跑（agent 侧没有这个路由），所以按同目录既有做法在 fixture 里 import。
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import Any

import pytest

# 实机 ``_field_caps`` 的口径：两个字段都是 text + .keyword 子字段
_MAPPING_TEXT = {
    "log_type": "text",
    "log_type.keyword": "keyword",
    "source_system": "text",
    "source_system.keyword": "keyword",
    "@timestamp": "date",
}
_MAPPING_KEYWORD = {
    "log_type": "keyword",
    "source_system": "keyword",
    "@timestamp": "date",
}

_ES_RESPONSE: dict[str, Any] = {
    "hits": {"total": {"value": 123, "relation": "eq"}},
    "aggregations": {
        "by_type": {
            "buckets": [
                {"key": "wazuh", "doc_count": 100},
                {"key": "wazuh_archive", "doc_count": 23},
            ]
        },
        "last": {"value_as_string": "2026-10-03T07:36:29.113Z"},
    },
}


@pytest.fixture(scope="module")
def mods(request: pytest.FixtureRequest) -> dict[str, ModuleType]:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("Wazuh 接入管理只在 NDR 侧")
    return {
        "wazuh": importlib.import_module("app.api.routes.wazuh"),
        "catalog": importlib.import_module("app.investigation.catalog"),
    }


class _StubEsConfig:
    def __init__(self, index: str = "shentong-events-*") -> None:
        self._index = index

    def current(self) -> dict[str, str]:
        return {"es.events_index": self._index}


class _RecordingEs:
    """记录 ``search`` 的实参，返回固定响应（或按要求抛错）。"""

    def __init__(self, response: dict[str, Any] | None = None, error: Exception | None = None):
        self.calls: list[dict[str, Any]] = []
        self._response = response if response is not None else _ES_RESPONSE
        self._error = error

    def search(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if self._error is not None:
            raise self._error
        return self._response

    # 汇总用到的字段路径 = 过滤条件里的 term 键 + 聚合字段
    @property
    def term_fields(self) -> list[str]:
        return list(self.calls[-1]["query"]["bool"]["filter"][0]["term"].keys())

    @property
    def agg_field(self) -> str:
        return str(self.calls[-1]["aggs"]["by_type"]["terms"]["field"])


def _prepare(
    mods: dict[str, ModuleType],
    monkeypatch: pytest.MonkeyPatch,
    mapping: dict[str, str],
    es: _RecordingEs,
) -> _RecordingEs:
    monkeypatch.setattr(mods["catalog"], "mapping_types", lambda index: dict(mapping))
    monkeypatch.setattr(mods["wazuh"], "es_config", _StubEsConfig())
    monkeypatch.setattr(mods["wazuh"], "get_es", lambda: es)
    return es


def test_ingest_stats_uses_keyword_paths(
    mods: dict[str, ModuleType], monkeypatch: pytest.MonkeyPatch
) -> None:
    """text 字段必须落到 ``.keyword``：否则 ES 报 fielddata，面板显示「读 ES 失败」。"""
    es = _prepare(mods, monkeypatch, _MAPPING_TEXT, _RecordingEs())

    out = mods["wazuh"]._ingest_stats()

    assert out["error"] == ""
    assert es.term_fields == ["source_system.keyword"]
    assert es.agg_field == "log_type.keyword"
    assert es.calls[-1]["track_total_hits"] is True
    assert out["total"] == 123
    assert out["alerts"] == 100
    assert out["archives"] == 23
    assert out["last_at"] == "2026-10-03T07:36:29.113Z"


def test_ingest_stats_keeps_bare_path_on_keyword_fields(
    mods: dict[str, ModuleType], monkeypatch: pytest.MonkeyPatch
) -> None:
    """字段本身就是 keyword 时不能硬拼 ``.keyword``（会静默空结果）。"""
    es = _prepare(mods, monkeypatch, _MAPPING_KEYWORD, _RecordingEs())

    out = mods["wazuh"]._ingest_stats()

    assert out["error"] == ""
    assert es.term_fields == ["source_system"]
    assert es.agg_field == "log_type"


def test_ingest_stats_survives_es_failure(
    mods: dict[str, ModuleType], monkeypatch: pytest.MonkeyPatch
) -> None:
    """ES 不可达：回结构化错误（界面能显示原因），不要把异常抛给路由。"""
    _prepare(mods, monkeypatch, _MAPPING_TEXT, _RecordingEs(error=RuntimeError("连接被拒")))

    out = mods["wazuh"]._ingest_stats()

    assert "连接被拒" in out["error"]
    assert out["total"] == 0 and out["alerts"] == 0
