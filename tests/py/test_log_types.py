"""日志类型分类（``app/ingestion/log_types.py``）的判定矩阵。

这一层是"哪些流进检测"的唯一入口，判错的两个方向都有代价：
漏判 → 运维日志进检测、污染画像；错判 → 真事件被当运维丢掉。
"""

from __future__ import annotations

import pytest
from app.ingestion import log_types
from app.schemas import UnifiedLog


@pytest.mark.parametrize(
    ("raw", "want"),
    [
        ("conn", "conn"),
        ("CONN", "conn"),
        (" conn ", "conn"),
        ("conn.log", "conn"),
        ("conn.2026-10-01.log", "conn"),
        ("conn.14-00-00.log", "conn"),
        ("/logs/conn.log", "conn"),
        ("/logs/2026-10-01/conn.log", "conn"),
        ("packet_filter.log", "packet_filter"),
        ("", ""),
        ("   ", ""),
    ],
)
def test_canonical_log_type(raw: str, want: str) -> None:
    assert log_types.canonical_log_type(raw) == want


@pytest.mark.parametrize(
    ("name", "want"),
    [
        ("conn", "event"),
        ("http", "event"),
        ("x509", "event"),
        ("weird", "event"),
        ("smtp", "event"),
        ("ssh", "event"),
        ("notice", "event"),
        ("ntp", "ops"),
        ("packet_filter", "ops"),
        ("reporter", "ops"),
        ("stats", "ops"),
        ("ja4ssh", "ops"),
        ("ja4d", "ops"),
        ("ja3sfp", "unknown"),  # 名单外的新流
        ("tlsfp", "unknown"),
        ("", "unknown"),
    ],
)
def test_classify(name: str, want: str) -> None:
    assert log_types.classify(name) == want


@pytest.mark.parametrize(
    ("name", "want"), [("conn", True), ("stats", True), ("ja3sfp", False), ("", False)]
)
def test_is_known(name: str, want: bool) -> None:
    assert log_types.is_known(name) is want


def _entry(**kw: object) -> UnifiedLog:
    base: dict[str, object] = {
        "source_system": "zeek",
        "ts": 1790912698.490834,
        "log_type": "conn",
        "event_type": "flow",
    }
    base.update(kw)
    return UnifiedLog(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("log_type", "want"),
    [
        ("conn", True),
        ("http", True),
        ("ntp", False),
        ("stats", False),
        ("ja3sfp", False),
        ("", False),
    ],
)
def test_is_detectable_zeek(log_type: str, want: bool) -> None:
    assert log_types.is_detectable(_entry(log_type=log_type)) is want


def test_wazuh_never_gated() -> None:
    """Wazuh 线不受这个闸门约束（它有自己的一套：归档只入库、告警进检测）。"""
    entry = _entry(source_system="wazuh", log_type="ntp")  # 就算类型名撞上运维类
    assert log_types.classify_entry(entry) == log_types.EVENT
    assert log_types.is_detectable(entry) is True
