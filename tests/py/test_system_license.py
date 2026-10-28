"""系统授权（项目组织身份）的守卫。

要钉住四件事：

1. **授权ID 可复现**：同一台机器永远同一个 8 位串；不同种子必须不同（不能撞成同一个项目）；
2. **派生来源优先级**：硬件 UUID → 系统安装标识 → 主机名兜底，且来源要能说清；
3. **它是身份不是密钥**：接口只回派生后的 ID 与来源，**不回原始机器码**；
4. **两边都带得上**：MCP 响应头 `x-ndr-auth-id`、`server_info` 工具、门铃载荷的 `project`
   —— 智能体才能逐次核对"这还是我绑定的那个项目吗"。
"""

from __future__ import annotations

import asyncio
import importlib
from typing import Any

import pytest

_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


def _mod(name: str) -> Any:
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError:  # pragma: no cover - agent 栈没有这些模块
        pytest.skip(f"该栈没有 {name}（属 NDR 侧）")


@pytest.fixture()
def lic() -> Any:
    module = _mod("app.system_license")
    module.reset_cache()
    yield module
    module.reset_cache()


# ===== ① 可复现的 8 位串 =====


def test_auth_id_is_eight_uppercase_alnum(lic: Any) -> None:
    for seed in ("", "abc", "99ba1c42-537b-a478-4d4a-b5767f2f6c11", "x" * 200):
        value = lic.encode_auth_id(seed)
        assert len(value) == 8, f"{seed!r} 生成的不是 8 位：{value}"
        assert set(value) <= _ALPHABET, f"{seed!r} 生成了字母数字之外的字符：{value}"


def test_auth_id_is_stable_per_seed(lic: Any) -> None:
    """同一台机器必须永远同一个 ID（重启、重建容器都不能变）。"""
    assert lic.encode_auth_id("machine-a") == lic.encode_auth_id("machine-a")
    assert lic.encode_auth_id("machine-a") != lic.encode_auth_id("machine-b")


# ===== ② 派生来源优先级 =====


def test_machine_code_prefers_hardware(lic: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    dmi = tmp_path / "product_uuid"
    dmi.write_text("hardware-uuid\n", encoding="utf-8")
    mid = tmp_path / "machine-id"
    mid.write_text("system-machine-id\n", encoding="utf-8")
    monkeypatch.setattr(lic, "_DMI_UUID", dmi)
    monkeypatch.setattr(lic, "_MACHINE_ID", mid)
    assert lic.machine_code() == ("hardware-uuid", "hardware")


def test_machine_code_falls_back_to_machine_id(
    lic: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    monkeypatch.setattr(lic, "_DMI_UUID", tmp_path / "missing")
    mid = tmp_path / "machine-id"
    mid.write_text("system-machine-id\n", encoding="utf-8")
    monkeypatch.setattr(lic, "_MACHINE_ID", mid)
    assert lic.machine_code() == ("system-machine-id", "machine-id")


def test_machine_code_falls_back_to_hostname(
    lic: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    monkeypatch.setattr(lic, "_DMI_UUID", tmp_path / "missing")
    monkeypatch.setattr(lic, "_MACHINE_ID", tmp_path / "missing")
    monkeypatch.setattr(lic.socket, "gethostname", lambda: "ndr-host")
    assert lic.machine_code() == ("ndr-host", "hostname")


def test_hostname_fallback_is_marked_unstable(
    lic: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """主机名兜底时界面要能提示"这不稳"（换主机名就换 ID）。"""
    monkeypatch.setattr(lic, "_DMI_UUID", tmp_path / "missing")
    monkeypatch.setattr(lic, "_MACHINE_ID", tmp_path / "missing")
    monkeypatch.setattr(lic.socket, "gethostname", lambda: "ndr-host")
    info = lic.license_info(refresh=True)
    assert info["source"] == "hostname"
    assert info["stable"] is False
    assert info["auth_id"] == lic.encode_auth_id("ndr-host")


# ===== ③ 接口只回派生后的身份 =====


def test_license_route_is_registered() -> None:
    app = _mod("app.main").app
    assert "/api/system/license" in set(app.openapi()["paths"])


def test_license_route_does_not_leak_machine_code(
    lic: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """接口只回 8 位 ID 与来源，不回原始机器码（没必要，也不该外泄硬件序列）。"""
    dmi = tmp_path / "product_uuid"
    dmi.write_text("super-secret-hardware-uuid\n", encoding="utf-8")
    monkeypatch.setattr(lic, "_DMI_UUID", dmi)
    monkeypatch.setattr(lic, "_MACHINE_ID", tmp_path / "missing")
    from app.api.routes.system_metrics import system_license

    out = system_license(_=None)  # type: ignore[arg-type]
    assert out["auth_id"] == lic.encode_auth_id("super-secret-hardware-uuid")
    assert "super-secret-hardware-uuid" not in str(out)
    assert out["stable"] is True


# ===== ④ 两边都带得上身份 =====


def test_mcp_response_carries_auth_id_header(lic: Any) -> None:
    """所有 MCP 响应（含 401/404）都要带 `x-ndr-auth-id`，智能体才能逐次核对。"""
    server = _mod("app.mcp.server")
    sent: list[dict[str, Any]] = []

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": b"{}"})

    async def receive() -> Any:
        return {"type": "http.request"}

    async def send(message: Any) -> None:
        sent.append(message)

    asyncio.run(
        server.ServerIdentityHeader(inner)(
            {"type": "http", "path": "/mcp", "headers": []}, receive, send
        )
    )
    headers = dict(sent[0]["headers"])
    assert headers[b"x-ndr-auth-id"] == lic.auth_id().encode()


def test_server_info_tool_returns_auth_id(lic: Any) -> None:
    tools = _mod("app.mcp.ndr_tools").TOOLS
    assert "server_info" in tools, "MCP 缺 server_info（绑定校验没地方读）"
    out = tools["server_info"]["run"]({})
    assert out["auth_id"] == lic.auth_id()
    assert out["source"]


def test_doorbell_carries_project_identity(lic: Any) -> None:
    """门铃要能带项目身份（多项目 agent 靠它路由），但仍不许带任何事件数据。"""
    import inspect

    queue_mod = _mod("app.analysis.queue")
    src = inspect.getsource(queue_mod.doorbell_payload)
    assert '"project": auth_id()' in src
    for forbidden in ("digest", "evidence", "severity", "src_ip", "samples"):
        assert forbidden not in src
