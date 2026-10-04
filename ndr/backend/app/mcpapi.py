"""NDR 后端侧的 MCP 专用门面：MCP 只准依赖这一个文件，不许穿透到内部子系统。

`app/mcp/` 是独立的 MCP 服务进程，但它和 Web 后端共用同一个 `app` 包，导入没有任何物理
隔离。以前 `app/mcp/` 直接 import `app.db` / `app.ingestion` / `app.detector` /
`app.investigation` / `app.baseline` / `app.workers`，内部实现一改就要跟着改 MCP 层，
边界名存实亡（见 `docs/ndr-redesign.md` §8 第 5 条）。

这个模块就是那道边界：内部依赖全部收敛到这里，对外只暴露 MCP 真正需要的那几件能力。
**它只做转发与收敛，不含业务逻辑** —— 想改内部实现时只改调用点，`app/mcp/` 不用动。

边界由 `tests/py/test_mcp_boundary.py` 用 AST 静态守住：`app/mcp/` 下的任何文件都不许出现
`app.db` / `app.ingestion` / `app.detector` / `app.investigation` / `app.baseline` /
`app.rules` / `app.collector` / `app.api` / `app.workers` 这类内部导入，只能 import
`app.config`、`app.mcp.*` 与 `app.mcpapi` 本身。
"""

from __future__ import annotations

from typing import Any

from app.baseline import profile as _profile, stats as _stats
from app.db.base import SessionLocal as session_factory
from app.db.models import (
    ConclusionRecord,
    ExclusionFilter,
    IngestFilter,
    McpToken,
    Rule,
)
from app.detector import health as _health
from app.ingestion import es_client as _es_client, es_config as _es_config, scope as _scope
from app.investigation import catalog, tools as es_tools
from app.workers.log import get_logger

__all__ = [
    "ConclusionRecord",
    "ExclusionFilter",
    "IngestFilter",
    "McpToken",
    "Rule",
    "build_networks",
    "catalog",
    "detector_health",
    "es_client",
    "es_config",
    "es_tools",
    "get_logger",
    "in_scope",
    "list_profiles",
    "monitored_nets",
    "networks_status",
    "session_factory",
    "stats_lookup",
    "top_anomalies",
]

# 下面所有转发都走「模块属性」而不是「导入期绑定的函数对象」：原 `app/mcp/` 里的懒导入
# 在调用时才取模块属性，测试的 monkeypatch 才能生效；门面必须保住同一份可替换性，否则
# 只是把依赖搬了个家、却静默改变了行为。

# ---------- ES 客户端与运行时配置 ----------


def es_client() -> Any:
    """取 ES 客户端（连接信息取自运行时配置，客户端按连接三要素缓存复用）。"""
    return _es_client.get_es()


def es_config() -> dict[str, str]:
    """当前生效的 ES 运行时配置（DB 覆盖 env，带 30 秒 TTL 缓存）。"""
    return _es_config.current()


# ---------- 网段与 scope ----------


def build_networks(cidrs: list[str]) -> list[Any]:
    """把 CIDR / 单 IP 字符串解析成 ip_network 列表（非法的丢弃，返回空表）。"""
    return _es_client.build_networks(cidrs)


def in_scope(ip_value: Any, nets: list[Any]) -> bool:
    """判断 IP 是否落在给定网段集合内（内网判定的唯一依据）。"""
    return _es_client.in_scope(ip_value, nets)


def monitored_nets() -> list[str]:
    """当前监控网段清单（去重保序；读库出错返回空表）。"""
    return _scope.monitored_nets()


def networks_status() -> dict[str, int | bool]:
    """网段配置状态：`{"configured": bool, "count": int}`。"""
    return _scope.networks_status()


# ---------- 字段目录 / 取证工具 / 基线 ----------
# `catalog` 与 `es_tools` 直接以模块形态转出：前者的字段路径解析、后者的工具注册表都
# 是 MCP 直接遍历的接口，包一层函数反而多一层无意义的转发。


def stats_lookup(ip: str = "", key: str = "", limit: int = 50) -> dict[str, Any]:
    """查数值基线：某源 IP 的长期均值 / 标准差 / 样本数与是否过观测期。"""
    return _stats.lookup(ip=ip, key=key, limit=limit)


def list_profiles(
    *,
    kind: str | None = None,
    keys: list[str] | None = None,
    min_risk: float = 0.0,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """查账号 / 会话画像（跨窗口长期基线），可按实体键指名或只看过阈值的异常。"""
    return _profile.list_profiles(kind=kind, keys=keys, min_risk=min_risk, limit=limit, offset=offset)


def top_anomalies(limit: int = 10) -> dict[str, Any]:
    """按风险分取 TOP 异常画像。"""
    return _profile.top_anomalies(limit)


# ---------- 检测器健康与日志 ----------


def detector_health(client: Any) -> dict[str, Any]:
    """检测器依赖的 Redis 体检（内存占用 / 上限 / 淘汰策略）。

    传入调用方已有的 redis 客户端，与检测器读的是同一份口径；不在这里新建连接。
    """
    return _health.redis_memory(client)


# `get_logger` 直接以 import 形态转出（MCP 各模块用它建自己的 logger）。
