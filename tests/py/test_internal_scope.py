"""内外网判定口径守卫（2026-10 与 Zeek 原生日志对账后统一）。

**标准答案**：Zeek 的 `conn.log` 自带 `local_orig` / `local_resp`，由 `Site::local_nets`
（= 我们下发的 `monitored_nets`，与采集 BPF、检测器 scope 过滤同源）算出。
所以「内网」必须等于「落在监控网段内」，**不是**「非公网」：

| 地址 | Zeek（现场实测，地址已泛化） | 旧口径（非公网即内网） | 新口径 |
|---|---|---|---|
| 监控网段内的私网主机 | local=True | 内网 ✓ | 内网 ✓ |
| 私网但**不在**监控网段（如另一段 10/8） | local=False | **内网 ✗（误报内网横向）** | 非内网 ✓ |
| 公网地址 | local=False | 非内网 ✓ | 非内网 ✓ |

现场 250 条 conn 样本里旧口径有 64 次侧判定分歧（约 13%），本文件钉住修复后的行为。
（测试用通用网段，不写任何部署环境特有的地址。）
"""

from __future__ import annotations

import importlib
import ipaddress
from typing import Any

import pytest

#: 通用监控网段（模拟"只监控其中一小段"）
NETS = ("10.1.1.0/24", "10.2.0.0/24")
INSIDE = ("10.1.1.10", "10.1.1.20", "10.2.0.30")
#: 私网但**不在**监控网段内（Zeek 会说 local=False）
OUTSIDE_PRIVATE = ("10.9.9.9", "172.16.5.5", "192.168.9.9")
PUBLIC = ("8.8.8.8", "1.1.1.1")


@pytest.fixture
def helper(monkeypatch: pytest.MonkeyPatch) -> Any:
    """两个栈各自的 is_internal_ip（NDR 在 app.iputil，agent 在 app.tools.context）。"""
    try:
        mod = importlib.import_module("app.iputil")
        monkeypatch.setattr(mod, "_net_texts", lambda: NETS)
    except ModuleNotFoundError:  # agent 栈
        mod = importlib.import_module("app.tools.context")
        monkeypatch.setattr(
            mod, "_monitored_networks", lambda: [ipaddress.ip_network(n) for n in NETS]
        )
    monkeypatch.setattr(mod, "_cache_at", 0.0, raising=False)
    monkeypatch.setattr(mod, "_nets_at", 0.0, raising=False)
    return mod


def _entry(ip: str, dst: str = "8.8.8.8") -> Any:
    schemas = importlib.import_module("app.schemas")
    return schemas.UnifiedLog(
        source_system="zeek",
        ts="2026-10-11T13:00:00+00:00",
        event_type="http_request",
        log_type="http",
        src_ip=ip,
        dst_ip=dst,
    )


def test_inside_monitored_nets_is_internal(helper: Any) -> None:
    for ip in INSIDE:
        assert helper.is_internal_ip(ip) is True, f"{ip} 在监控网段内，应判内网"


def test_private_but_outside_monitored_nets_is_not_internal(helper: Any) -> None:
    """本次修复的核心：监控范围外的私网地址**不算内网**（Zeek 也说 local=False）。"""
    for ip in OUTSIDE_PRIVATE:
        assert helper.is_internal_ip(ip) is False, f"{ip} 不在监控网段内，不该算内网"


def test_public_is_not_internal(helper: Any) -> None:
    for ip in PUBLIC:
        assert helper.is_internal_ip(ip) is False


def test_falls_back_to_non_public_when_no_nets(monkeypatch: pytest.MonkeyPatch) -> None:
    """一条网段都没配时回落到老行为（非公网即内网）—— 不凭空把地址判成外网。"""
    try:
        mod = importlib.import_module("app.iputil")
        monkeypatch.setattr(mod, "_net_texts", lambda: ())
    except ModuleNotFoundError:
        mod = importlib.import_module("app.tools.context")
        monkeypatch.setattr(mod, "_monitored_networks", list)
    monkeypatch.setattr(mod, "_cache_at", 0.0, raising=False)
    monkeypatch.setattr(mod, "_nets_at", 0.0, raising=False)
    assert mod.is_internal_ip("10.9.9.9") is True
    assert mod.is_internal_ip("8.8.8.8") is False


def test_rule_virtual_fields_follow_monitored_nets(monkeypatch: pytest.MonkeyPatch) -> None:
    """规则里的 src_internal / dst_internal 必须走同一口径（内外有别类判据靠它）。"""
    engine = importlib.import_module("app.rules.engine")
    monkeypatch.setattr(engine, "is_internal_ip", lambda ip: str(ip).startswith("10.1.1."))
    cond = {"logic": "and", "rules": [{"field": "src_internal", "op": "eq", "value": True}]}
    assert engine.evaluate_conditions(cond, _entry("10.1.1.10")) is True
    assert engine.evaluate_conditions(cond, _entry("10.9.9.9")) is False


def test_external_stays_public_only() -> None:
    """x_external 仍只看「公网地址」：监控范围外的私网既不算内网也不算外网（不互补）。"""
    engine = importlib.import_module("app.rules.engine")
    cond = {"logic": "and", "rules": [{"field": "dst_external", "op": "eq", "value": True}]}
    for dst, want in (("8.8.8.8", True), ("10.9.9.9", False), ("10.1.1.10", False)):
        assert engine.evaluate_conditions(cond, _entry("10.1.1.10", dst)) is want, dst
