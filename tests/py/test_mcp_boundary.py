"""MCP 边界守卫：`app/mcp/` 只准依赖 `app.mcpapi`，不许穿透到后端内部子系统。

背景（`docs/ndr-redesign.md` §8 第 5 条）：MCP 服务进程与 Web 后端共用同一个 `app` 包，
导入没有任何物理隔离，很容易「顺手」`from app.db.models import ...` 把内部实现焊进 MCP 层。
这里用 AST 静态解析守住边界（不依赖运行时导入），`app/mcpapi.py` 是唯一被允许收敛这些
内部依赖的门面。

`--stack=agent` 下整文件跳过（agent 侧没有 `app/mcpapi`；与 `test_es_mapping.py` 同一做法）。
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_MCP_DIR = ROOT / "ndr" / "backend" / "app" / "mcp"
_MCPAPI = ROOT / "ndr" / "backend" / "app" / "mcpapi.py"

# `app/mcp/` 下禁止出现的内部子系统前缀（`app.mcpapi` / `app.mcp.*` / `app.config` 除外）。
# 前半是子包，后半是直接挂在 `app` 下的内部模块 —— 一并列全，新增内部包时这里也要补。
FORBIDDEN_PREFIXES = (
    "app.api",
    "app.baseline",
    "app.collector",
    "app.db",
    "app.detector",
    "app.ingestion",
    "app.investigation",
    "app.rules",
    "app.workers",
    "app.iputil",
    "app.main",
    "app.runtime_config",
    "app.schemas",
    "app.selfcheck",
    "app.triage_policy",
)

# 允许的 `app.*` 导入（白名单，比黑名单更强：以后新加的内部包也会被拦下）。
ALLOWED_PREFIXES = ("app.config", "app.mcp", "app.mcpapi")

# 门面必须对 MCP 暴露的能力（少一个就说明某处调用点又绕回内部模块了）。
REQUIRED_API = (
    # ES 客户端与运行时配置
    "es_client",
    "es_config",
    # 网段与 scope
    "build_networks",
    "in_scope",
    "monitored_nets",
    "networks_status",
    # 字段目录 / 取证工具 / 基线
    "catalog",
    "es_tools",
    "stats_lookup",
    "list_profiles",
    "top_anomalies",
    # 检测器健康与日志
    "detector_health",
    "get_logger",
    # DB
    "session_factory",
    "McpToken",
    "ConclusionRecord",
    "ExclusionFilter",
    "IngestFilter",
    "Rule",
)


@pytest.fixture(scope="module", autouse=True)
def _ndr_only(request: pytest.FixtureRequest) -> None:
    """这两条边界只在 NDR 侧存在；agent 栈直接跳过整文件。"""
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("MCP 边界只在 NDR 侧（agent 没有 app/mcpapi）")


@pytest.fixture(scope="module")
def mcp_dir() -> Path:
    assert _MCP_DIR.is_dir(), f"找不到 MCP 目录：{_MCP_DIR}"
    return _MCP_DIR


def _resolve_relative(module: str | None, level: int) -> str:
    """把相对导入还原成绝对模块名（被解析的文件都在 `app/mcp/` 下）。"""
    if level == 0:
        return module or ""
    base = "app.mcp"
    for _ in range(level - 1):
        base = base.rsplit(".", 1)[0]
    return f"{base}.{module}" if module else base


def _iter_app_imports(path: Path) -> list[tuple[int, str]]:
    """收集文件里所有以 `app.` 开头的导入（行号, 绝对模块名）。

    同时展开 `from app import mcpapi` 这种别名，避免它绕过前缀检查。
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("app."):
                    found.append((node.lineno, alias.name))
        elif isinstance(node, ast.ImportFrom):
            base = _resolve_relative(node.module, node.level)
            if base.startswith("app."):
                found.append((node.lineno, base))
            for alias in node.names:
                full = f"{base}.{alias.name}" if base else alias.name
                if full.startswith("app."):
                    found.append((node.lineno, full))
    return found


def _hits(name: str, prefixes: tuple[str, ...]) -> bool:
    return any(name == p or name.startswith(p + ".") for p in prefixes)


def test_no_backend_internal_imports(mcp_dir: Path) -> None:
    """黑名单：`app/mcp/` 下任何文件都不许直接 import 后端内部子系统。"""
    violations = [
        f"{path.name}:{lineno} 导入了内部模块 {name}"
        for path in sorted(mcp_dir.glob("*.py"))
        for lineno, name in _iter_app_imports(path)
        if _hits(name, FORBIDDEN_PREFIXES)
    ]
    assert not violations, (
        "app/mcp/ 必须经由 app.mcpapi，禁止直接依赖后端内部子系统：\n" + "\n".join(violations)
    )


def test_only_allowed_app_imports(mcp_dir: Path) -> None:
    """白名单：`app/mcp/` 只准 import `app.config` / `app.mcp.*` / `app.mcpapi`。"""
    violations = [
        f"{path.name}:{lineno} 导入了未授权的模块 {name}"
        for path in sorted(mcp_dir.glob("*.py"))
        for lineno, name in _iter_app_imports(path)
        if not _hits(name, ALLOWED_PREFIXES)
    ]
    assert not violations, (
        "app/mcp/ 只允许 import app.config / app.mcp.* / app.mcpapi：\n" + "\n".join(violations)
    )


def test_mcpapi_exists_and_is_importable() -> None:
    """门面本身存在且能正常导入（它才是允许依赖内部子系统的那一层）。"""
    assert _MCPAPI.is_file(), f"缺少门面模块：{_MCPAPI}"
    mod = importlib.import_module("app.mcpapi")
    assert Path(mod.__file__ or "").resolve() == _MCPAPI.resolve()


def test_mcp_layer_imports_the_facade(mcp_dir: Path) -> None:
    """防止门面被架空：`app/mcp/` 至少有一个文件真的 import 了 `app.mcpapi`。"""
    users = [
        path.name
        for path in sorted(mcp_dir.glob("*.py"))
        if any(
            name == "app.mcpapi" or name.startswith("app.mcpapi.")
            for _, name in _iter_app_imports(path)
        )
    ]
    assert users, "app/mcp/ 下没有任何文件 import app.mcpapi：门面被架空了"


def test_mcpapi_exposes_required_api() -> None:
    """门面对外暴露的能力齐全（签名不检查，只保证调用点依赖的名字都在）。"""
    mod = importlib.import_module("app.mcpapi")
    missing = [name for name in REQUIRED_API if not hasattr(mod, name)]
    assert not missing, f"app.mcpapi 缺少 MCP 需要的能力：{missing}"
