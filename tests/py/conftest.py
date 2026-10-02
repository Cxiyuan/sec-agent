"""pytest 配置：一次只绑一个栈（ndr / agent），用 ``--stack`` 选择。

两个栈的后端包都叫 ``app``（``ndr/backend/app``、``agent/backend/app``），同一个进程里
没法同时 import。所以分工是：

- 断言**某一个栈**行为的测试：用 ``--stack`` 指定，CI 里两个栈各跑一遍；
- 断言**两侧一致**的测试：用子进程分别加载（见 ``test_stack_consistency.py``）。

用法::

    .venv/bin/pytest tests/py --stack=ndr
    .venv/bin/pytest tests/py --stack=agent
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]  # 仓库根
STACKS = ("ndr", "agent")


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--stack",
        action="store",
        default="ndr",
        choices=STACKS,
        help="要测的栈（默认 ndr；CI 里 ndr / agent 各跑一遍）",
    )


def pytest_configure(config: pytest.Config) -> None:
    stack = str(config.getoption("--stack"))
    backend = ROOT / stack / "backend"
    if not (backend / "app").is_dir():
        raise pytest.UsageError(f"找不到后端包：{backend}/app")
    # 放在最前面，确保 `import app` 命中的是被测栈
    sys.path.insert(0, str(backend))


@pytest.fixture(scope="session")
def stack(request: pytest.FixtureRequest) -> str:
    return str(request.config.getoption("--stack"))


@pytest.fixture(scope="session")
def backend_dir(stack: str) -> Path:
    return ROOT / stack / "backend"
