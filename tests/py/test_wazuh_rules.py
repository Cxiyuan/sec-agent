"""Wazuh 规则文件下发 + 生效校验（``api/routes/wazuh.py``）回归测试。

2026-10-03 实机（172.16.196.77，manager 4.14.8）下发第一条自定义规则时踩到两个坑，
两个都让「下发是否真的生效」这个结论不可信：

1. **回读原文那一步必失败**：``GET /rules/files/<name>?raw=true`` 回的是
   ``application/xml`` 原文，而 ``_api`` 无条件 ``resp.json()`` → 判成
   「Wazuh API 响应不是 JSON」，于是 ``verified`` 永远 false（规则其实已经生效）。
2. **生效条数会瞬时读到 0**：下发后立刻 ``GET /rules?filename=...`` 可能拿到 0 条，
   几秒后才看得见（manager 侧规则集扫描滞后；同一操作第二次又可能立刻可见）。
   读一次就把 0 当结论 = 把「已生效」判成「没生效」。

所以这里锁定三件事：``raw=True`` 走文本、生效条数带轮询、两处都满足才算 ``verified``。

只在 NDR 栈跑（agent 侧没有这个路由），按同目录既有做法在 fixture 里 import。
"""

from __future__ import annotations

import importlib
import json
from types import ModuleType, SimpleNamespace
from typing import Any, ClassVar, Self

import pytest

_RULE_TEXT = (
    "<!-- 深瞳：本地自定义告警规则（id 请用 100000-120000 区段） -->\n"
    '<group name="shentong,">\n'
    '  <rule id="100199" level="0">\n'
    "    <program_name>shentong-rule-push-probe</program_name>\n"
    "    <description>测试用</description>\n"
    "  </rule>\n"
    "</group>\n"
)


@pytest.fixture(scope="module")
def wazuh(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("Wazuh 接入管理只在 NDR 侧")
    return importlib.import_module("app.api.routes.wazuh")


# ---------- 假的 httpx：换掉模块里的 `httpx.Client`，不发真实请求 ----------


class _FakeResp:
    def __init__(self, status_code: int = 200, text: str = "", payload: Any = None) -> None:
        self.status_code = status_code
        self.text = text
        self._payload = payload

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("Expecting value: line 1 column 1 (char 0)")
        return self._payload

    @property
    def headers(self) -> dict[str, str]:
        return {"content-type": "application/json" if self._payload is not None else "text/plain"}


class _FakeClient:
    """按 URL 片段决定回什么：登录固定回 token，其余回注册好的响应。"""

    routes: ClassVar[list[tuple[str, _FakeResp]]] = []

    def __init__(self, **_kwargs: Any) -> None:
        pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False

    def post(self, url: str, **_kwargs: Any) -> _FakeResp:
        assert url.endswith("/security/user/authenticate")
        return _FakeResp(payload={"data": {"token": "t0k3n", "expires_at": 0}})

    def request(self, method: str, url: str, **_kwargs: Any) -> _FakeResp:
        for frag, resp in self.routes:
            if frag in url:
                return resp
        raise AssertionError(f"没有为 {method} {url} 准备响应")


def _stub_httpx(
    wazuh: ModuleType, monkeypatch: pytest.MonkeyPatch, routes: list[tuple[str, _FakeResp]]
) -> None:
    _FakeClient.routes = routes
    monkeypatch.setattr(wazuh, "httpx", SimpleNamespace(Client=_FakeClient))


_CFG = {
    "url": "https://wazuh-manager:55000",
    "user": "wazuh-wui",
    "password": "x",
    "verify_tls": False,
}


def test_api_raw_returns_text(wazuh: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """`raw=True`：XML 原文按文本返回，不能判成「不是 JSON」。"""
    xml = '<group name="shentong,"></group>\n'
    _stub_httpx(wazuh, monkeypatch, [("/rules/files/", _FakeResp(text=xml))])
    wazuh._token_cache.clear()

    data, err = wazuh._api(_CFG, "GET", "/rules/files/probe.xml", params={"raw": "true"}, raw=True)

    assert err == ""
    assert data == xml


def test_api_without_raw_still_reports_non_json(
    wazuh: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """不带 `raw` 时行为不变：非 JSON 仍然是结构化错误（不要静默当成文本）。"""
    _stub_httpx(wazuh, monkeypatch, [("/rules/files/", _FakeResp(text="<xml/>"))])
    wazuh._token_cache.clear()

    data, err = wazuh._api(_CFG, "GET", "/rules/files/probe.xml")

    assert data is None
    assert "不是 JSON" in err


# ---------- 生效条数：轮询 ----------


class _FakeClock:
    """假时钟：`sleep` 推进 `monotonic`，这样「轮询到超时」的分支也能在测试里终止。"""

    def __init__(self) -> None:
        self.now = 0.0
        self.slept = 0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds
        self.slept += 1


def _count_api(counts: list[int], calls: list[tuple[str, dict[str, Any]]]) -> Any:
    def fake(cfg: dict[str, Any], method: str, path: str, **kwargs: Any) -> tuple[Any, str]:
        calls.append((path, kwargs))
        n = counts[min(len(calls), len(counts)) - 1]
        return {"data": {"total_affected_items": n}}, ""

    return fake


def test_count_rules_polls_until_visible(
    wazuh: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """第一次读到 0 不算数：继续轮询，看到 1 条才返回。"""
    clock = _FakeClock()
    calls: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(wazuh, "time", clock)
    monkeypatch.setattr(wazuh, "_api", _count_api([0, 0, 1], calls))

    total, err = wazuh._count_rules(_CFG, "probe.xml", want=1, timeout=8.0)

    assert (total, err) == (1, "")
    assert len(calls) == 3
    assert all(path == "/rules" for path, _ in calls)
    assert calls[0][1]["params"] == {"filename": "probe.xml", "limit": 1}


def test_count_rules_gives_up_at_deadline(
    wazuh: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """一直看不见也不能死循环：到期按当前条数返回，由调用方判「校验不一致」。"""
    clock = _FakeClock()
    calls: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(wazuh, "time", clock)
    monkeypatch.setattr(wazuh, "_api", _count_api([0], calls))

    total, err = wazuh._count_rules(_CFG, "probe.xml", want=1, timeout=2.0)

    assert (total, err) == (0, "")
    assert clock.slept >= 4  # 0.5s 一次，2s 至少 4 次
    assert len(calls) == clock.slept + 1


# ---------- 下发 + 校验整条路 ----------


def _upload(
    wazuh: ModuleType, monkeypatch: pytest.MonkeyPatch, api: Any, **kwargs: Any
) -> dict[str, Any]:
    monkeypatch.setattr(wazuh, "_stored", lambda _db: {})
    monkeypatch.setattr(wazuh, "_api", api)
    body = wazuh.WazuhRuleIn(filename="probe.xml", text=_RULE_TEXT, **kwargs)
    out = wazuh.upload_rule_file(body=body, db=None, _=None)
    assert not hasattr(out, "status_code"), f"不该回错误响应：{getattr(out, 'body', out)}"
    assert isinstance(out, dict)
    return out


def test_upload_rule_file_verifies_after_poll(
    wazuh: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """端到端：上传成功 + 条数轮询到 1 + 原文一致 ⇒ verified=true。"""
    clock = _FakeClock()
    monkeypatch.setattr(wazuh, "time", clock)
    seen: list[tuple[str, str, dict[str, Any]]] = []

    def api(cfg: dict[str, Any], method: str, path: str, **kwargs: Any) -> tuple[Any, str]:
        seen.append((method, path, kwargs))
        if path == "/rules":
            n = 0 if len([s for s in seen if s[1] == "/rules"]) == 1 else 1
            return {"data": {"total_affected_items": n}}, ""
        if kwargs.get("raw"):
            return _RULE_TEXT, ""
        return {"data": {"affected_items": ["etc/rules/probe.xml"]}}, ""

    out = _upload(wazuh, monkeypatch, api)

    assert out["ok"] is True
    assert out["verified"] is True
    assert out["applied_rules"] == 1
    assert out["sent_rules"] == 1
    assert out["rule_ids"] == ["100199"]
    raw_calls = [s for s in seen if s[0] == "GET" and s[2].get("raw")]
    assert raw_calls, "回读原文必须显式带 raw=True"
    assert raw_calls[0][2]["params"] == {"raw": "true"}


def test_upload_rule_file_flags_content_mismatch(
    wazuh: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """manager 上的原文与发出的不一致 ⇒ verified=false，且说明里点出原因。"""

    def api(cfg: dict[str, Any], method: str, path: str, **kwargs: Any) -> tuple[Any, str]:
        if path == "/rules":
            return {"data": {"total_affected_items": 1}}, ""
        if kwargs.get("raw"):
            return '<group name="other,"></group>\n', ""
        return {"data": {"affected_items": []}}, ""

    out = _upload(wazuh, monkeypatch, api)

    assert out["verified"] is False
    assert out["applied_rules"] == 1
    assert "不一致" in out["detail"]


def test_upload_rule_file_survives_raw_read_failure(
    wazuh: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """原文读不到时：仍报「已上传 + 生效条数」，但明确指出回读原文失败。"""

    def api(cfg: dict[str, Any], method: str, path: str, **kwargs: Any) -> tuple[Any, str]:
        if path == "/rules":
            return {"data": {"total_affected_items": 1}}, ""
        if kwargs.get("raw"):
            return None, "Wazuh API 返回 HTTP 500：boom"
        return {"data": {"affected_items": []}}, ""

    out = _upload(wazuh, monkeypatch, api)

    assert out["ok"] is True
    assert out["verified"] is False
    assert out["applied_rules"] == 1
    assert "回读原文失败" in out["detail"]


def test_upload_rejects_bad_filename(wazuh: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """文件名只允许一层 .xml：目录穿越与嵌套路径必须在进 API 之前挡下。"""
    monkeypatch.setattr(wazuh, "_stored", lambda _db: {})
    called: list[str] = []
    monkeypatch.setattr(wazuh, "_api", lambda *a, **k: called.append(a[2]) or (None, ""))

    for bad in ("../evil.xml", "sub/dir.xml", "nope.txt", ""):
        body = wazuh.WazuhRuleIn(filename=bad, text=_RULE_TEXT, verify=True)
        out = wazuh.upload_rule_file(body=body, db=None, _=None)
        assert out.status_code == 400, bad
        assert json.loads(bytes(out.body))["conflict"] == "field_error"
    assert called == []
