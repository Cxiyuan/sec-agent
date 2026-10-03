"""MCP 令牌的到期口径（``ndr/backend/app/api/routes/mcp.py``）——纯逻辑，不碰数据库。

为什么单独一个文件：到期/轮换是这次新加的能力（QA 报告「MCP 令牌无过期、不可轮换」），
而 ``tests/py/`` 下原本没有任何 MCP 路由测试。写库路径（轮换、写 ``expires_at``）需要
PostgreSQL，靠 ``ndr/backend/app/main.py`` 的 ``_MIGRATIONS`` 给老库补列，这里只钉住
「取值校验」和「到期时间算得对」这两条纯函数契约，接口本身的行为由集成部署验证。
"""

from __future__ import annotations

import importlib
from datetime import UTC, datetime, timedelta
from types import ModuleType

import pytest


@pytest.fixture(scope="module")
def mcp_route(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("MCP 管理接口只在 NDR 侧")
    return importlib.import_module("app.api.routes.mcp")


def test_max_token_days_is_ten_years(mcp_route: ModuleType) -> None:
    # 上限是「永久」的实用等价物，不是安全边界；改了要同步 mcp.py 的报错文案。
    assert mcp_route.MAX_TOKEN_DAYS == 3650


def test_token_in_defaults_to_never_expire(mcp_route: ModuleType) -> None:
    # 不传 = 永不过期：既有令牌与既有调用方都不会因为这次改动突然失效。
    assert mcp_route.TokenIn(name="agent").expires_in_days is None
    assert mcp_route.TokenExpiryIn().expires_in_days is None


@pytest.mark.parametrize("days", [None, 1, 30, 3650])
def test_bad_days_accepts_none_and_valid_range(mcp_route: ModuleType, days: int | None) -> None:
    assert mcp_route._bad_days(days) is False


@pytest.mark.parametrize("days", [0, -1, 3651, 10**6])
def test_bad_days_rejects_out_of_range(mcp_route: ModuleType, days: int) -> None:
    assert mcp_route._bad_days(days) is True


def test_expires_at_is_timezone_aware_and_exact(mcp_route: ModuleType) -> None:
    now = datetime.now(UTC)
    got = mcp_route._expires_at(2)

    assert got.tzinfo is not None, "库里存的是带时区的时间，不能拿 naive datetime 比较"
    assert (
        now + timedelta(days=2) - timedelta(seconds=5)
        <= got
        <= now + timedelta(days=2) + timedelta(seconds=5)
    )
