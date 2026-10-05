"""ES 连接信息「只来自部署环境、用户不可配置」的回归测试。

背景：Elasticsearch 是**随 NDR 一起部署**的内置服务，地址/凭据在部署时就固定了
（``.env`` 的 ``ES_*`` → 后台 ``ST_ES_*``）。第 6 期把它做成了「连接信息存 ``SystemConfig``
（``es.url`` / ``es.username`` / ``es.password``）+ 界面填地址、填密码、点测试连接」，于是
同一个事实有两份来源：界面写一个地址、实际连另一个地址也看不出来。

现在：
- ``es_config.RUNTIME_KEYS`` 只剩**策略项**（索引族 + 保留天数），连接三项永远取
  ``settings.es_*``，库里的历史行不再被读；
- ``PUT /api/es/config`` 的 body 里没有连接字段，``POST /api/es/test`` 删除；
- 写侧（Logstash 管道的 ``elasticsearch { hosts => [...] }``）同样由部署环境拍定，
  参数行里不再存 ``es_host``，启动时自动对齐已生成的管道。

只在 NDR 栈跑（agent 侧没有这两个路由）。
"""

from __future__ import annotations

import importlib
from types import ModuleType, SimpleNamespace
from typing import Any, Self

import pytest


@pytest.fixture(scope="module")
def es_config(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("ES 运行时配置只在 NDR 侧")
    return importlib.import_module("app.ingestion.es_config")


@pytest.fixture(scope="module")
def es_admin(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("ES 管理路由只在 NDR 侧")
    return importlib.import_module("app.api.routes.es_admin")


@pytest.fixture(scope="module")
def logstash(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("Logstash 管道管理只在 NDR 侧")
    return importlib.import_module("app.api.routes.logstash")


class _Row:
    def __init__(self, key: str, value: Any) -> None:
        self.key = key
        self.value = value


class _FakeSession:
    """够 ``es_config._load()`` / ``logstash._save_params()`` 用的小号 Session。"""

    def __init__(self, rows: list[_Row] | None = None) -> None:
        self.rows = rows or []
        self.added: list[_Row] = []

    def scalars(self, stmt: Any) -> Any:
        # 按 SQL 里的 WHERE 过滤，而不是把库里所有行都倒出来：这样「_load 只查 RUNTIME_KEYS」
        # 这条约束才是真的被验证（把 .in_(RUNTIME_KEYS) 拿掉，库里的 es.url 行就会漏进来）。
        sql = str(stmt.compile(compile_kwargs={"literal_binds": True}))
        return SimpleNamespace(all=lambda: [r for r in self.rows if f"'{r.key}'" in sql])

    def get(self, _model: Any, _key: str) -> _Row | None:
        return None

    def add(self, row: _Row) -> None:
        self.added.append(row)

    def commit(self) -> None:
        return None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False


def test_connection_keys_are_not_runtime_configurable(es_config: ModuleType) -> None:
    """连接三项必须不在可覆盖名单里 —— 加回去就等于又开了一个配置口子。"""
    assert tuple(es_config.RUNTIME_KEYS) == ("es.events_index", "es.retention_days")
    for key in ("es.url", "es.username", "es.password"):
        assert key not in es_config.RUNTIME_KEYS


def test_load_ignores_stored_connection_rows(
    es_config: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """库里就算留着 es.url/username/password 覆盖值，也只认部署环境。"""
    rows = [
        _Row("es.url", {"value": "http://somebody-edited-in-ui:9200"}),
        _Row("es.username", {"value": "ui-user"}),
        _Row("es.password", {"value": "ui-pass"}),
        _Row("es.events_index", {"value": "custom-events-*"}),
        _Row("es.retention_days", {"value": "45"}),
    ]
    monkeypatch.setattr(es_config, "SessionLocal", lambda: _FakeSession(rows))
    monkeypatch.setattr(
        es_config,
        "settings",
        SimpleNamespace(
            es_url="http://elasticsearch:9200",
            es_user="env-user",
            es_password="env-pass",
            es_events_index="shentong-events-*",
            es_retention_days=30,
        ),
    )

    cfg = es_config._load()

    assert cfg["es.url"] == "http://elasticsearch:9200"
    assert cfg["es.username"] == "env-user"
    assert cfg["es.password"] == "env-pass"
    # 策略项仍然可以被后台覆盖
    assert cfg["es.events_index"] == "custom-events-*"
    assert cfg["es.retention_days"] == "45"
    # 读路径拿到的连接对（供 es_client 用）也来自环境
    assert es_config.auth_pair() == ("env-user", "env-pass")


def test_defaults_cover_all_keys_for_read_path(es_config: ModuleType) -> None:
    """`defaults()` 仍要给全五个键：`get_es()` 直接读 `current()["es.url"]`。"""
    cfg = es_config.defaults()

    assert set(cfg) == {
        "es.url",
        "es.username",
        "es.password",
        "es.events_index",
        "es.retention_days",
    }


def test_config_model_and_routes_have_no_connection_write_path(es_admin: ModuleType) -> None:
    """``EsConfigIn`` 只收策略项；连接配置的写入口（PUT 里的 url、POST /test）必须不存在。"""
    assert set(es_admin.EsConfigIn.model_fields) == {"events_index", "retention_days"}
    for gone in ("clear_password", "url", "username", "password"):
        assert gone not in es_admin.EsConfigIn.model_fields

    routes = {
        (method, route.path)
        for route in es_admin.router.routes
        for method in route.methods or set()
    }
    assert ("GET", "/api/es/config") in routes
    assert ("PUT", "/api/es/config") in routes
    assert ("GET", "/api/es/status") in routes
    assert ("POST", "/api/es/apply-retention") in routes
    assert ("POST", "/api/es/test") not in routes


def test_public_view_still_reports_where_it_connects(es_admin: ModuleType) -> None:
    """只读回显要能看出「现在连的是哪台」，但永不下发密码明文。"""
    view = es_admin._public(
        {
            "es.url": "http://elasticsearch:9200",
            "es.username": "elastic",
            "es.password": "s3cret",
            "es.events_index": "shentong-events-*",
        }
    )

    assert view["url"] == "http://elasticsearch:9200"
    assert view["username"] == "elastic"
    assert view["password_set"] is True
    assert "password" not in view
    assert not hasattr(es_admin, "_mask"), "_mask 已被只读的 _public 取代"


def test_logstash_params_pin_es_host_to_deployment(
    logstash: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """表单只能改索引族；ES 地址一律被部署环境覆盖，且不落库。"""
    assert set(logstash.ParamsIn.model_fields) == {"es_enabled", "events_index"}

    monkeypatch.setattr(
        logstash,
        "settings",
        SimpleNamespace(es_url="http://elasticsearch:9200", logstash_http_port=8080),
    )
    params = logstash._effective_params(
        {"es_enabled": True, "es_host": "http://old-host:9200", "events_index": "custom-*"}
    )
    assert params["es_host"] == "http://elasticsearch:9200"
    assert params["events_index"] == "custom-*"

    session = _FakeSession()
    logstash._save_params(session, params)  # pyright: ignore[reportArgumentType]
    stored = session.added[0].value["value"]
    assert "es_host" not in stored, "ES 地址是部署环境派生的，不该进库变成第二个来源"
    assert stored == {"es_enabled": True, "events_index": "custom-*"}


def _resync_fixture(
    logstash: ModuleType, monkeypatch: pytest.MonkeyPatch, es_url: str, file_text: str
) -> list[str]:
    written: list[str] = []
    monkeypatch.setattr(
        logstash,
        "settings",
        SimpleNamespace(
            es_url=es_url,
            logstash_http_port=8080,
            logstash_pipeline_conf="/tmp/logstash.conf",
        ),
    )
    monkeypatch.setattr(logstash, "read_pipeline", lambda: file_text)
    monkeypatch.setattr(logstash, "derived_from_generated_pipeline", lambda: True)
    monkeypatch.setattr(logstash, "write_pipeline", lambda text: written.append(text) or None)
    return written


def test_resync_es_host_follows_deployment_env(
    logstash: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """改过 .env 再重启：生成管道里的旧地址要自动对齐（写路径跟读路径一致）。"""
    template = importlib.import_module("app.collector.template")
    params = {"es_enabled": True, "events_index": "shentong-events-%{+yyyy.MM.dd}"}
    old_text = template.render({**params, "es_host": "http://old-es:9200"}, 8080)
    written = _resync_fixture(logstash, monkeypatch, "http://new-es:9200", old_text)

    action = logstash._resync_es_host(_FakeSession())

    assert action == "updated"
    assert len(written) == 1
    assert 'hosts => ["http://new-es:9200"]' in written[0]


def test_resync_es_host_is_noop_when_already_aligned(
    logstash: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    template = importlib.import_module("app.collector.template")
    params = {"es_enabled": True, "events_index": "shentong-events-%{+yyyy.MM.dd}"}
    text = template.render({**params, "es_host": "http://elasticsearch:9200"}, 8080)
    written = _resync_fixture(logstash, monkeypatch, "http://elasticsearch:9200", text)

    assert logstash._resync_es_host(_FakeSession()) is None
    assert written == []


def test_resync_es_host_never_clobbers_hand_edited_pipeline(
    logstash: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """手工改过（除地址外还有别的编辑）时只告警、不改写，避免覆盖人的改动。"""
    template = importlib.import_module("app.collector.template")
    params = {"es_enabled": True, "events_index": "shentong-events-%{+yyyy.MM.dd}"}
    old_text = template.render({**params, "es_host": "http://old-es:9200"}, 8080)
    hand_edited = old_text.replace("  # 无条件入库", "  # 人手加的注释：别覆盖我")
    written = _resync_fixture(logstash, monkeypatch, "http://new-es:9200", hand_edited)

    assert logstash._resync_es_host(_FakeSession()) == "manual-edit"
    assert written == []
