"""命中事件（PG 唯一事件 ID + 详情证据 + 忽略/白名单）—— 2026-10 用户要求。

三个要点各自钉一条：
1. **目的要成对**：摘要里 `dst_ips` / `dst_ports` 是两个独立列表，界面上拼成
   「IP : 端口/端口/端口」看不出谁配谁（用户反馈）—— 落库时从样例事件取真实配对；
2. **唯一事件 ID**：每条命中一行、主键即 ID（关联分析的锚点），详情里要显示；
3. **详情要有证据**：样例事件的关键字段（时间/类型/URI/UA/状态码/账号…）。
"""

from __future__ import annotations

import importlib
from types import SimpleNamespace
from typing import Any

import pytest

ROOT_PATHS = ("tests/py",)


@pytest.fixture(scope="module")
def hits(request: pytest.FixtureRequest) -> Any:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("命中事件只在 NDR 侧")
    return importlib.import_module("app.detector.hits")


@pytest.fixture(scope="module")
def route(request: pytest.FixtureRequest) -> Any:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("检测器路由只存在于 NDR 侧")
    return importlib.import_module("app.api.routes.detector")


def _digest(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "src_ip": "10.1.2.10",
        "real_client_ips": ["113.0.87.111"],
        "proxied": True,
        "rule": "内置-多路径探测(漏洞挖掘)",
        "rule_severity": "high",
        "rule_source": "builtin",
        "count": 3,
        "dst_ips": ["10.1.2.20", "10.1.2.21"],
        "dst_ports": ["46220", "60384"],
        "event_types": ["http_error"],
        "conn_states": ["SF"],
        "first_seen": "2026-10-12T00:20:00+00:00",
        "last_seen": "2026-10-12T00:26:22+00:00",
        "samples": [
            {
                "source": "es",
                "doc": {
                    "dst_ip": "10.1.2.20",
                    "dst_port": 46220,
                    "log_type": "http",
                    "uri_path": "/a",
                    "status_code": 404,
                    "uid": "C1",
                    "raw_extra": "x",
                },
            },
            {
                "source": "es",
                "doc": {
                    "dst_ip": "10.1.2.21",
                    "dst_port": 60384,
                    "log_type": "http",
                    "uri_path": "/b",
                    "status_code": 403,
                },
            },
        ],
    }
    base.update(kw)
    return base


def test_pairs_are_paired_not_cross_joined(hits: Any) -> None:
    """目的必须是**真实配对**，不能把两个列表拼成 `IP : 端口/端口`。"""
    pairs = hits._pairs(_digest())
    assert pairs == ["10.1.2.20:46220", "10.1.2.21:60384"]
    assert "10.1.2.20:60384" not in pairs, "不能出现交叉组合"


def test_pairs_fall_back_when_no_samples(hits: Any) -> None:
    pairs = hits._pairs(_digest(samples=[], dst_ips=["10.1.2.99"], dst_ports=["80", "443"]))
    assert pairs == ["10.1.2.99:80", "10.1.2.99:443"]


def test_evidence_keeps_key_fields_and_drops_blob(hits: Any) -> None:
    ev = hits._evidence(_digest())
    assert len(ev) == 2
    assert ev[0]["uri_path"] == "/a" and ev[0]["status_code"] == 404
    assert ev[0]["source"] == "es"
    assert ev[0]["other_fields"] == ["raw_extra"], "关键字段之外的字段只列名、不落值"


def test_save_writes_unique_id_and_paired_dst(hits: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """落库：返回唯一事件 ID，且 client/via/目的配对都写对。"""
    captured: dict[str, Any] = {}

    class _DB:
        def add(self, row: Any) -> None:
            captured["row"] = row
            row.id = "11111111-2222-3333-4444-555555555555"

        def commit(self) -> None:
            captured["committed"] = True

        def __enter__(self) -> Any:
            return self

        def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool:
            return False

    monkeypatch.setattr(hits, "SessionLocal", lambda: _DB())
    hit_id = hits.save_from_digest(_digest())
    row = captured["row"]
    assert hit_id == "11111111-2222-3333-4444-555555555555"
    assert captured.get("committed") is True
    assert row.dst_pairs == ["10.1.2.20:46220", "10.1.2.21:60384"]
    assert row.client == "113.0.87.111", "展示用请求方取真实客户端"
    assert row.via == "10.1.2.10", "中继链路上要记住这一跳经过谁"
    assert row.client_source == "xff"
    assert row.ignored in (None, False), "新建事件默认未忽略（列默认值在落库时生效）"
    assert row.evidence and row.evidence[0]["uri_path"] == "/a"


def test_save_never_raises(hits: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """落库失败不该影响检测投递（返回空串）。"""

    def _boom() -> Any:
        raise RuntimeError("pg down")

    monkeypatch.setattr(hits, "SessionLocal", _boom)
    assert hits.save_from_digest(_digest()) == ""


def test_hit_endpoints_registered_once(route: Any) -> None:
    paths = [getattr(r, "path", "") for r in route.router.routes]
    for want in (
        "/api/detector/hits",
        "/api/detector/hits/{hit_id}",
        "/api/detector/hits/{hit_id}/ignore",
        "/api/detector/hits/{hit_id}/whitelist",
    ):
        assert paths.count(want) == 1, f"{want} 应只注册一次，实际 {paths}"


def test_ignore_marks_row(hits: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    row = SimpleNamespace(id="abc", ignored=False, ignored_at=None, ignored_reason="")

    class _DB:
        def get(self, _model: Any, _key: str) -> Any:
            return row

        def commit(self) -> None:
            row.committed = True

        def __enter__(self) -> Any:
            return self

        def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool:
            return False

    monkeypatch.setattr(hits, "SessionLocal", lambda: _DB())
    out = hits.mark_ignored("abc", reason="误报")
    assert out["ok"] is True and row.ignored is True and row.ignored_reason == "误报"


def test_panel_shows_pairs_id_and_detail() -> None:
    """界面守卫：目的按 `IP:端口` 成对显示、列表有事件 ID 列、有详情按钮与弹窗动作。"""
    src = (
        importlib.import_module("pathlib").Path(__file__).resolve().parents[2]
        / "ndr"
        / "frontend"
        / "components"
        / "status-panel.tsx"
    ).read_text(encoding="utf-8")
    assert "dst_pairs" in src, "目的要用成对字段渲染"
    assert 'row.dst_ips.join("、")' not in src, "不能再用「IP : 端口/端口」那种拼法"
    assert "row.id.slice(0, 8)" in src, "列表要有事件 ID"
    assert "详情" in src and "加入白名单" in src and "忽略这条" in src
    assert "/api/detector/hits" in src


def test_evidence_extracts_suricata_signature(hits: Any) -> None:
    """签名命中的证据要能看出**是哪条签名**（Suricata 原始 EVE 把签名放在嵌套 alert 里）。

    实测背景：某条命中只显示「内置-签名命中(高危)」，看不出是 Cobalt Strike JA3S 还是别的 ——
    因为证据取的是顶层字段，而签名在 `alert.signature` / `alert.signature_id` 里。
    """
    digest = _digest(
        samples=[
            {
                "source": "suricata",
                "doc": {
                    "event_type": "alert",
                    "src_ip": "20.1.1.1",
                    "dest_ip": "10.1.2.59",
                    "dest_port": 64881,
                    "app_proto": "tls",
                    "alert": {
                        "signature": "检测到 Cobalt Strike Server JA3S 特征",
                        "signature_id": 1000371,
                        "category": "Unknown Classtype",
                        "severity": 1,
                        "metadata": {"threat_type": ["C2"]},
                    },
                },
            }
        ],
        dst_ips=["10.1.2.59"],
        dst_ports=["64881"],
    )
    ev = hits._evidence(digest)[0]
    assert ev["signature"] == "检测到 Cobalt Strike Server JA3S 特征"
    assert ev["signature_id"] == 1000371
    assert ev["signature_category"] == "Unknown Classtype"
    assert ev["signature_severity"] == 1
    assert ev["signature_threat_type"] == ["C2"]
    assert ev["app_proto"] == "tls"
    assert hits._pairs(digest) == ["10.1.2.59:64881"], "EVE 用 dest_ip/dest_port，也要能配对"
