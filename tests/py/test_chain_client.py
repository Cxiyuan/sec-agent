"""攻击链还原里的「请求方是谁」：同一连接的旁证事件要能取回客户端（2026-10 用户提问驱动）。

用户看到 `未知请求IP → 10.1.2.11 → 10.1.2.10 → 10.1.2.30:80`，问为什么会有「未知」。
实测原因（.203 后跳、5 分钟窗口）：一次访问会有多条事件 —— `http`（带 Host/URI/XFF）与
`files`/`conn`/`weird`（同一 uid 的旁证，**不带代理头**）。后者单独还原就是「客户端为空」的空链。
抽查 34 个这样的 uid，**30 个**能从同 uid 的明文事件取回客户端（同 uid = 同一次访问，不是猜）。
"""

from __future__ import annotations

import importlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]

RELAY = "10.1.2.10"
ORIGIN = "10.1.2.20"
CLIENT = "10.3.1.2"
UID = "ChzH6k335ij3U9oZef"


@pytest.fixture
def chain(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("攻击链还原只在 NDR 侧")
    return importlib.import_module("app.api.routes.chain")


def _doc(**kw: Any) -> dict[str, Any]:
    """够链路还原用的事件（只带它读的字段）。默认是「.203 后跳」的旁证事件：没有代理头。"""
    base: dict[str, Any] = {
        "ts": "2026-10-09T15:04:05+00:00",
        "log_type": "files",
        "event_type": "file",
        "hop": "back",
        "src_ip": RELAY,
        "src_port": 34814,
        "dst_ip": ORIGIN,
        "dst_port": 80,
        "real_client_ip": None,
        "hostname": None,
        "uri_path": None,
        "uid": UID,
        "filename": "shell.jsp",
    }
    base.update(kw)
    return base


@pytest.fixture
def stub(chain: ModuleType, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """把链路还原的外部依赖都打桩（ES 取数 / 中继清单 / 拓扑边）。"""
    state: dict[str, Any] = {"docs": [], "edges": []}
    monkeypatch.setattr(chain, "_fetch", lambda start, end, size: (state["docs"], False))
    monkeypatch.setattr(chain, "_edges", lambda: (state["edges"], {}))
    monkeypatch.setattr(chain.relay_nodes, "configured", lambda: True)
    monkeypatch.setattr(chain.relay_nodes, "sides", dict)
    monkeypatch.setattr(chain.relay_nodes, "role_overrides", dict)
    monkeypatch.setattr(chain.relay_nodes, "side_override", lambda ip: "")
    return state


def _build(chain: ModuleType) -> dict[str, Any]:
    end = datetime(2026, 10, 9, 16, tzinfo=UTC)
    return chain._build(end - timedelta(minutes=60), end, ip="", host="", suspicious_only=False)


def test_peer_by_uid_keeps_client_and_host(chain: ModuleType) -> None:
    peers = chain._peer_by_uid(
        [
            _doc(log_type="files", filename="a.bin"),
            _doc(log_type="http", real_client_ip=CLIENT, hostname="portal.example.com"),
            _doc(log_type="conn", uid=""),  # 没有 uid 的事件不参与
        ]
    )
    assert peers[UID] == (CLIENT, "portal.example.com")


def test_chain_recovers_client_and_host_from_same_uid(
    chain: ModuleType, stub: dict[str, Any]
) -> None:
    """同一 uid 的旁证事件（files/conn/weird）要归到那条真实访问上，而不是单起一条空链。"""
    stub["docs"] = [
        # 旁证事件：没有代理头、没有 Host（原来会变成「未知请求IP → …」）
        _doc(log_type="files"),
        _doc(log_type="conn", dst_port=80),
        # 同一次访问的明文事件：带 XFF 与 Host
        _doc(
            log_type="http", real_client_ip=CLIENT, hostname="portal.example.com", uri_path="/x.jsp"
        ),
    ]
    data = _build(chain)
    assert len(data["chains"]) == 1, f"应合并成一条链，实际 {len(data['chains'])} 条"
    row = data["chains"][0]
    assert row["client"] == CLIENT
    assert row["client_source"] == "xff_same_uid"
    assert row["client_state"] == "known"
    assert row["origin"] == "portal.example.com" and row["origin_kind"] == "hostname"
    assert row["origin_source"] == "same_uid"
    assert row["facts"]["events"] == 3, "旁证事件仍要计入事实聚合（文件名等）"
    assert "shell.jsp" in row["facts"]["filenames"]
    assert row["segments"][0]["from"] == CLIENT, "链首应该是真实请求方"
    assert row["segments"][0]["to"] == RELAY


def test_chain_says_client_not_recorded_instead_of_unknown(
    chain: ModuleType, stub: dict[str, Any]
) -> None:
    """确实取不到请求方时：说「客户端未记录」并给原因，不写「未知请求IP」（那读起来像出错）。"""
    stub["docs"] = [_doc(log_type="files")]
    row = _build(chain)["chains"][0]
    assert row["client"] == ""
    assert row["client_state"] == "not_recorded"
    assert "不带代理头" in row["client_reason"]
    assert row["segments"][0]["from"] == chain.UNKNOWN_CLIENT


def test_chain_with_relay_path_marks_head_from_upstream(
    chain: ModuleType, stub: dict[str, Any]
) -> None:
    """有上游中继时链首是上游中继（用户看到的那条形状），请求方取回后不该再显示为空。"""
    stub["edges"] = [
        {"from": "10.1.2.11", "to": RELAY, "direct": 165473, "header": 3722, "confirmed": True}
    ]
    stub["docs"] = [
        _doc(log_type="files"),
        _doc(log_type="http", real_client_ip=CLIENT, hostname="portal.example.com"),
    ]
    row = _build(chain)["chains"][0]
    assert row["relay_path"] == ["10.1.2.11", RELAY]
    assert row["client"] == CLIENT


def test_page_does_not_say_unknown_client(request: pytest.FixtureRequest) -> None:
    """界面文案守卫：不再出现「未知请求IP」，改为「客户端未记录」+ 原因。"""
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("攻击链页只在 NDR 侧")
    src = (ROOT / "ndr" / "frontend" / "app" / "chain" / "page.tsx").read_text(
        encoding="utf-8"
    )
    assert "未知请求IP" not in src
    assert "客户端未记录" in src
    assert "client_reason" in src


def test_origin_shows_ip_primary(chain: ModuleType, stub: dict[str, Any]) -> None:
    """源站展示：**IP:端口 优先**，域名/Host 只作补充。

    实机依据（2026-10 用户反馈）：内网服务的 HTTP Host 是 `master:5000`，只显示它就看不出
    是哪台机器；`origin` 字段语义保持不变（分组、交智能体仍按域名/Host），另给 origin_ip。
    """
    stub["docs"] = [
        _doc(
            log_type="http",
            real_client_ip=CLIENT,
            hostname="master:5000",
            dst_ip="10.1.2.30",
            dst_port=5000,
        )
    ]
    row = _build(chain)["chains"][0]
    assert row["origin"] == "master:5000" and row["origin_kind"] == "hostname"
    assert row["origin_ip"] == "10.1.2.30:5000", "展示用的源站必须是 IP:端口"
    assert row["segments"][-1]["to"] == "10.1.2.30:5000", "链路图最后一段也显示 IP"


def test_chain_page_shows_origin_ip_first() -> None:
    """界面守卫：源站优先用 origin_ip 渲染（域名作括号补充）。"""
    src = (ROOT / "ndr" / "frontend" / "app" / "chain" / "page.tsx").read_text(
        encoding="utf-8"
    )
    assert "origin_ip" in src and "originLabel" in src
