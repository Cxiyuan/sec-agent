"""Wazuh 连接信息「只来自部署环境、用户不可配置」的回归测试。

背景：Wazuh 4.14 是**随本项目一起部署**的内置服务，地址/凭据在部署时就固定了
（``.env`` 的 ``WAZUH_API_*`` → 后台 ``ST_WAZUH_API_*``）。第 6 期把它做成了「凭据存
``SystemConfig.wazuh.params`` + 界面填地址/密码/测试连接」，于是同一个事实有两份来源，
界面写一个地址、实际连另一个地址也看不出来，部署完还得人工填一遍。

现在：``_cfg()`` 只读环境变量、不碰数据库；``GET /api/wazuh`` 没有配套的 ``PUT`` 写配置，
也没有 ``POST /test`` 试连接（探活信息本来就在 GET 的 ``status`` 里）；密码也不再以打码
形态回显（打码会泄漏首尾字符，而界面已经无处可填）。

这几条都是「不许回退」的约定，所以用「模块里已经没有旧入口」直接钉住。

只在 NDR 栈跑（agent 侧没有这个路由）。
"""

from __future__ import annotations

import importlib
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest


@pytest.fixture(scope="module")
def wazuh(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("Wazuh 接入管理只在 NDR 侧")
    return importlib.import_module("app.api.routes.wazuh")


def _stub_settings(**overrides: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "wazuh_api_url": "https://wazuh-manager:55000",
        "wazuh_api_user": "wazuh-wui",
        "wazuh_api_password": "s3cret",
        "wazuh_api_verify_tls": False,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_cfg_reads_only_settings(wazuh: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """``_cfg()`` 的四个字段全部来自 settings，且地址会补 scheme、去尾斜杠。"""
    monkeypatch.setattr(wazuh, "settings", _stub_settings(wazuh_api_url="wazuh-manager:55000/"))

    assert wazuh._cfg() == {
        "url": "https://wazuh-manager:55000",
        "user": "wazuh-wui",
        "password": "s3cret",
        "verify_tls": False,
    }


def test_cfg_keeps_empty_env_as_unconfigured(
    wazuh: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """环境没给地址/凭据时「未配置」要如实报出来，不能编一个本地默认值。"""
    monkeypatch.setattr(wazuh, "settings", _stub_settings(wazuh_api_url="", wazuh_api_password=""))

    public = wazuh._public(wazuh._cfg())

    assert public["configured"] is False
    assert public["password_set"] is False
    assert public["url"] == ""


def test_payload_is_env_backed_and_has_no_second_source(
    wazuh: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """整份 payload 不含 ``env``（没有「环境默认值 vs 界面保存值」两份来源）、不含打码密码。"""
    monkeypatch.setattr(wazuh, "settings", _stub_settings())
    monkeypatch.setattr(
        wazuh,
        "_probe",
        lambda cfg: {
            "reachable": True,
            "url": cfg["url"],
            "version": "v4.14.8",
            "cluster_enabled": False,
            "detail": "连通",
        },
    )
    monkeypatch.setattr(wazuh, "_api", lambda *a, **k: ({"data": {"affected_items": []}}, ""))
    monkeypatch.setattr(
        wazuh,
        "_ingest_stats",
        lambda: {
            "alerts": 1,
            "archives": 0,
            "total": 1,
            "last_at": None,
            "error": "",
        },
    )

    payload = wazuh._payload()

    assert payload["config"]["url"] == "https://wazuh-manager:55000"
    assert payload["config"]["user"] == "wazuh-wui"
    assert payload["config"]["password_set"] is True
    assert payload["config"]["configured"] is True
    assert "env" not in payload
    assert "password_masked" not in payload["config"]
    # 提示语要告诉运维「去哪儿改」——不是在这一页填
    assert "部署环境" in payload["hint"]


def test_config_storage_helpers_are_gone(wazuh: ModuleType) -> None:
    """旧的可配置路径（读库/合并/写库）必须彻底删除，避免被重新接上。"""
    for gone in ("_stored", "_merge", "_env_defaults", "WazuhConfigIn", "CONFIG_KEY", "mask"):
        assert not hasattr(wazuh, gone), f"{gone} 又回来了：连接信息不该再有第二个来源"


def test_config_endpoints_are_read_only(wazuh: ModuleType) -> None:
    """连接配置相关的写入口（``PUT /api/wazuh``、``POST /api/wazuh/test``）必须不存在。"""
    routes = {
        (method, route.path) for route in wazuh.router.routes for method in route.methods or set()
    }

    assert ("PUT", "/api/wazuh") not in routes
    assert ("POST", "/api/wazuh/test") not in routes
    # 只读入口与规则下发仍在
    assert ("GET", "/api/wazuh") in routes
    assert ("GET", "/api/wazuh/status") in routes
    assert ("GET", "/api/wazuh/agents") in routes
    assert ("GET", "/api/wazuh/rules") in routes
    assert ("POST", "/api/wazuh/rules") in routes
