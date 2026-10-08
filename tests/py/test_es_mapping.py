"""ES 事件索引映射契约：``raw`` 必须是「不解析」的 object，老索引要报警。

背景（2026-10 实机事故）：索引模板只管 settings、没有 mappings，``raw`` 走动态映射，
``raw.id`` 被先到的 Zeek conn 文档定成 object；此后所有「``raw.id`` 是字符串」的文档
被 Logstash 静默丢弃 —— Filebeat / Redis / 归一化三段都是好的，只有落库这一段丢数据。

``flattened`` 也躲不掉：8.15.3 实测单值超过 32,766 字节（一条 LLM 日志的
``raw.resp_body`` 32,771 字节）会整条 400，仍是静默丢数据的形状。所以最终选
``{type: object, enabled: false}``：不做解析 ⇒ 结构上不可能再被拒；原文仍在 ``_source`` 里。

这里的断言是防回归的"真源"：① ``raw`` 声明成不解析的 object；
② 模板真的把它下发了；③ 老索引（动态映射、或已建的 flattened）会被明确报警。

这些模块只在 NDR 侧存在，所以按同目录既有做法：**在 fixture 里 import**，
`--stack=agent` 下整文件跳过（模块顶层 import 会让 agent 轮次收集失败）。
"""

from __future__ import annotations

import importlib
import logging
from types import ModuleType
from typing import Any

import pytest


@pytest.fixture(scope="module")
def mods(request: pytest.FixtureRequest) -> dict[str, ModuleType]:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("ES 索引映射只在 NDR 侧")
    return {
        "es_admin": importlib.import_module("app.api.routes.es_admin"),
        "es_mapping": importlib.import_module("app.collector.es_mapping"),
        "normalizer": importlib.import_module("app.ingestion.normalizer"),
    }


class _FakeIndices:
    def __init__(self, mapping: object = None) -> None:
        self.template_calls: list[dict[str, object]] = []
        self.settings_calls: list[dict[str, object]] = []
        self._mapping = mapping or {}

    def put_index_template(self, **kwargs: object) -> None:
        self.template_calls.append(kwargs)

    def put_settings(self, **kwargs: object) -> None:
        self.settings_calls.append(kwargs)

    def get_mapping(self, index: str | None = None) -> object:
        return self._mapping


class _FakeIlm:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def put_lifecycle(self, **kwargs: object) -> None:
        self.calls.append(kwargs)


class _FakeEs:
    def __init__(self, mapping: object = None) -> None:
        self.indices = _FakeIndices(mapping)
        self.ilm = _FakeIlm()


def test_event_index_mappings_disable_raw_parsing(mods: dict[str, ModuleType]) -> None:
    """形状不统一的原文只声明 ``raw`` 不解析，别的字段交给动态映射。"""
    assert mods["es_mapping"].EVENT_INDEX_MAPPINGS == {
        "properties": {"raw": {"type": "object", "enabled": False}}
    }


def test_is_safe_raw_mapping(mods: dict[str, ModuleType]) -> None:
    """只有「object + enabled: false」算安全；flattened 与动态映射都不算。"""
    is_safe = mods["es_mapping"].is_safe_raw_mapping
    assert is_safe({"type": "object", "enabled": False}) is True
    assert is_safe({"type": "flattened"}) is False
    assert is_safe({"properties": {"id": {"type": "object"}}}) is False
    assert is_safe(None) is False
    assert is_safe({}) is False


def test_ensure_retention_ships_raw_mapping(
    mods: dict[str, ModuleType], monkeypatch: pytest.MonkeyPatch
) -> None:
    """``ensure_retention`` 必须把 mappings 一起下发（只下发 settings 就会重演事故）。"""
    es_admin = mods["es_admin"]
    fake = _FakeEs()
    monkeypatch.setattr(es_admin, "get_es", lambda: fake)

    es_admin.ensure_retention(days=30)

    assert fake.ilm.calls, "ILM 策略没下发"
    assert fake.indices.template_calls, "索引模板没下发"
    call = fake.indices.template_calls[0]
    assert call["name"] == "shentong-events"
    assert call["index_patterns"] == ["shentong-events-*"]
    assert call["priority"] == 500
    template = call["template"]
    assert isinstance(template, dict)
    assert template["mappings"] == mods["es_mapping"].EVENT_INDEX_MAPPINGS
    settings = template["settings"]
    assert isinstance(settings, dict)
    assert settings["auto_expand_replicas"] == "0-1"


def _warn(mods: dict[str, ModuleType], mapping: dict[str, Any]) -> None:
    mods["es_admin"]._warn_legacy_raw_mapping(_FakeEs(mapping), "shentong-events-*")


def test_legacy_raw_mapping_warns(
    mods: dict[str, ModuleType], caplog: pytest.LogCaptureFixture
) -> None:
    """老索引（``raw`` 已被动态映射成 object）要报警，且提示只能 reindex。"""
    legacy = {
        "shentong-events-2026.10.03": {
            "mappings": {"properties": {"raw": {"properties": {"id": {"type": "object"}}}}}
        }
    }
    with caplog.at_level(logging.WARNING, logger=mods["es_admin"].logger.name):
        _warn(mods, legacy)

    assert "shentong-events-2026.10.03" in caplog.text
    assert "reindex" in caplog.text


def test_flattened_index_still_warns(
    mods: dict[str, ModuleType], caplog: pytest.LogCaptureFixture
) -> None:
    """flattened 不是安全形状（单值 > 32766 字节仍整条丢），要照旧报警。"""
    flattened = {
        "shentong-events-2026.10.04": {"mappings": {"properties": {"raw": {"type": "flattened"}}}}
    }
    with caplog.at_level(logging.WARNING, logger=mods["es_admin"].logger.name):
        _warn(mods, flattened)

    assert "shentong-events-2026.10.04" in caplog.text
    assert "reindex" in caplog.text


def test_safe_raw_mapping_does_not_warn(
    mods: dict[str, ModuleType], caplog: pytest.LogCaptureFixture
) -> None:
    """新模板建出来的索引（``raw`` 不解析）不该再报警。"""
    fixed = {
        "shentong-events-2026.10.05": {
            "mappings": {"properties": {"raw": {"type": "object", "enabled": False}}}
        }
    }
    with caplog.at_level(logging.WARNING, logger=mods["es_admin"].logger.name):
        _warn(mods, fixed)

    assert "reindex" not in caplog.text
