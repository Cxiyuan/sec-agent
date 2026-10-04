"""监听网卡清单：下拉里只允许出现**物理网卡**（`api/routes/zeek.py::_read_interfaces`）。

为什么单列一条：采集器容器是 host 网络，能看到宿主机全部网卡（docker0 / br-* / veth* /
tun0 / lo 全在里面），直接塞给前端会让人选错。判定优先级：

1. 采集器写下的 `physical`（sysfs 的 `/sys/class/net/<n>/device` 是否存在 —— 只有 host
   网络的采集器容器看得到宿主全部网卡的 sysfs，后端容器看不到）；
2. 名字模式兜底（旧镜像还没写 `physical` 字段时，也要把虚拟网卡挡掉）。

只跑 NDR 栈（采集器管理接口只在 NDR 侧）。
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


@pytest.fixture(scope="module")
def zeek_route(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("采集器管理接口只在 NDR 侧")
    return importlib.import_module("app.api.routes.zeek")


def _write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, items: list[dict[str, Any]]) -> Path:
    settings = importlib.import_module("app.config").settings
    path = tmp_path / "interfaces.json"
    path.write_text(json.dumps(items), encoding="utf-8")
    monkeypatch.setattr(settings, "zeek_interfaces_json", str(path), raising=False)
    return path


def _names(zeek_route: ModuleType) -> list[str]:
    return [str(item["name"]) for item in zeek_route._read_interfaces()]


def test_no_hardcoded_nic_name_in_product_code() -> None:
    """产品代码里不得给网卡名写死默认值（2026-10 硬编码审计）。

    网卡名是**客户环境**的东西（ens192 / ens224 / eth0 … 每家不一样）：写死一个名字，
    换台机器就是错的。正确做法是留空 + 采集器自动探测第一块物理网卡（`auto_iface`）。
    """
    import re

    root = Path(__file__).resolve().parents[2]
    entrypoint = (root / "ndr/zeek/entrypoint.sh").read_text(encoding="utf-8")
    # 自动探测必须在，且默认值来自探测结果
    assert "auto_iface()" in entrypoint
    assert 'IFACE_DEFAULT="${IFACE_ENV:-$(auto_iface)}"' in entrypoint
    # 任何地方都不允许出现「ZEEK_IFACE 的非空兜底值」
    for name in ("ndr/zeek/entrypoint.sh", "ndr/docker-compose.yml", "ndr/docker-compose.deploy.yml"):
        text = (root / name).read_text(encoding="utf-8")
        bad = re.findall(r"\$\{ZEEK_IFACE:-[^}]+\}", text)
        assert bad == [], f"{name} 里还有写死的网卡默认值：{bad}"
    # 后端配置同样不能写死（空 = 由采集器自动探测）
    assert 'zeek_interface: str = ""' in (root / "ndr/backend/app/config.py").read_text(
        encoding="utf-8"
    )


def test_keeps_only_physical_when_flag_present(
    zeek_route: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(
        tmp_path,
        monkeypatch,
        [
            {"name": "ens160", "state": "up", "mtu": 1500, "physical": True},
            {"name": "ens192", "state": "up", "mtu": 1500, "physical": True},
            {"name": "docker0", "state": "down", "mtu": 1500, "physical": False},
            {"name": "veth3dd3530", "state": "up", "mtu": 1500, "physical": False},
            {"name": "br-2130867d369f", "state": "up", "mtu": 1500, "physical": False},
            {"name": "tun0", "state": "unknown", "mtu": 1360, "physical": False},
        ],
    )
    assert _names(zeek_route) == ["ens160", "ens192"]


def test_falls_back_to_name_pattern_for_legacy_entries(
    zeek_route: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """旧镜像写的 interfaces.json 没有 physical 字段，也要把虚拟网卡挡掉。"""
    _write(
        tmp_path,
        monkeypatch,
        [
            {"name": "ens160", "state": "up", "mtu": 1500},
            {"name": "lo", "state": "unknown", "mtu": 65536},
            {"name": "docker0", "state": "down", "mtu": 1500},
            {"name": "vethabc123", "state": "up", "mtu": 1500},
            {"name": "br-abcdef123456", "state": "up", "mtu": 1500},
            {"name": "wg0", "state": "unknown", "mtu": 1420},
            {"name": "Tailscale0", "state": "unknown", "mtu": 1280},
        ],
    )
    assert _names(zeek_route) == ["ens160"]
    # 名字模式忽略大小写：Tailscale0 / TUN0 这类大写变体也要挡掉


def test_missing_file_returns_empty(
    zeek_route: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = importlib.import_module("app.config").settings
    monkeypatch.setattr(
        settings, "zeek_interfaces_json", str(tmp_path / "nope.json"), raising=False
    )
    assert zeek_route._read_interfaces() == []


def test_broken_json_returns_empty(
    zeek_route: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = importlib.import_module("app.config").settings
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(settings, "zeek_interfaces_json", str(path), raising=False)
    assert zeek_route._read_interfaces() == []


def test_entrypoint_marks_physical_by_sysfs() -> None:
    """采集器入口必须按 sysfs 写 physical 字段（后端只做过滤，不做探测）。"""
    script = (
        Path(__file__).resolve().parents[2] / "ndr" / "zeek" / "entrypoint.sh"
    ).read_text(encoding="utf-8")
    assert '[ -e "$dev/device" ]' in script, "write_interfaces 没有按 sysfs 判定物理网卡"
    assert '"physical":%s' in script, "interfaces.json 没有写 physical 字段"
