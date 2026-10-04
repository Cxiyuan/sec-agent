"""部署编排的端口暴露面（``ndr/docker-compose.deploy.yml``）。

红线：**无鉴权/弱鉴权**的口不能发布到 ``0.0.0.0``。

- ES 无鉴权（xpack.security 关着）、Postgres 弱口令、Redis 默认无密码；
- Logstash 8080 是 ``json_lines`` 输入且无鉴权 —— 谁都能往 ES 里灌数据
  （2026-10-04 实机实测：8080/9600 发布在 0.0.0.0）。

这些都只给**容器网络**用（归一化服务 POST logstash:8080、后端读 logstash:9600、
backend 连 postgres/redis/es），宿主机排查走 ``127.0.0.1`` 就够，不需要对外发布。
Redis 是唯一例外（智能体线路可能要连），但**默认值必须是回环**，放开要显式改
``REDIS_BIND``。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
DEPLOY_COMPOSE_PATH = ROOT / "ndr" / "docker-compose.deploy.yml"

#: 这些服务的端口必须绑回环（或以回环为默认值）。
LOOPBACK_ONLY = ("elasticsearch", "postgres", "redis", "logstash")


@pytest.fixture(scope="module")
def services() -> dict[str, Any]:
    data = yaml.safe_load(DEPLOY_COMPOSE_PATH.read_text(encoding="utf-8"))
    return data["services"]


def _ports(services: dict[str, Any], name: str) -> list[str]:
    raw = services[name].get("ports") or []
    return [str(p) for p in raw]


@pytest.mark.parametrize("name", LOOPBACK_ONLY)
def test_no_public_bind(services: dict[str, Any], name: str) -> None:
    for port in _ports(services, name):
        # 短语法 "host:container"；不带 host 部分的裸 "8080:8080" 等于发布到 0.0.0.0
        parts = port.split(":")
        assert len(parts) >= 3, f"{name} 的端口 {port!r} 没写 host 绑定，会发布到 0.0.0.0"
        assert parts[0] != "0.0.0.0", f"{name} 的端口 {port!r} 发布到了 0.0.0.0"


@pytest.mark.parametrize("name", ["elasticsearch", "postgres", "logstash"])
def test_sensitive_services_bind_loopback(services: dict[str, Any], name: str) -> None:
    """ES / Postgres / Logstash 没有跨机需求，必须写死 127.0.0.1。"""
    for port in _ports(services, name):
        assert port.startswith("127.0.0.1:"), f"{name} 的端口 {port!r} 不是回环绑定"


def test_redis_bind_defaults_to_loopback(services: dict[str, Any]) -> None:
    """Redis 允许跨机（智能体线路），但默认必须是回环，放开要显式设 REDIS_BIND。"""
    ports = _ports(services, "redis")
    assert ports, "redis 没有发布端口？跨机智能体线路要连它"
    assert any("${REDIS_BIND:-127.0.0.1}" in p for p in ports), ports
