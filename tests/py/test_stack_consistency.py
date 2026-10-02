"""两侧（NDR / 智能体）归一化结果必须逐字一致。

两侧各持一份 ``ingestion/normalizer.py``（约定：字段名、截断、类型判定都必须一致），
这个测试是那句约定的守门人：**只改一侧**会在这里炸。

实现上用子进程分别加载两个栈（两个包都叫 ``app``，同进程无法共存），
把每个样本的归一化结果 dump 成 JSON 再比。
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import samples

ROOT = Path(__file__).resolve().parents[2]
RUNNER = Path(__file__).with_name("_dump_entries.py")

# 允许两侧不同的字段（目前为空：两侧 UnifiedLog 字段必须完全一致）。
# 真需要加时写明原因，并同步 docs/ndr-collect-plan.md 的"智能体对等适配"。
ALLOWED_FIELD_DIFF: set[str] = set()


def _dump(side: str) -> dict[str, dict[str, object]]:
    proc = subprocess.run(
        [sys.executable, str(RUNNER), str(ROOT), side],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        pytest.fail(f"[{side}] 归一化子进程失败：\n{proc.stdout}\n{proc.stderr}")
    return json.loads(proc.stdout)


@pytest.fixture(scope="module")
def dumps() -> dict[str, dict[str, dict[str, object]]]:
    return {"ndr": _dump("ndr"), "agent": _dump("agent")}


def test_same_samples(dumps: dict) -> None:
    assert sorted(dumps["ndr"]) == sorted(dumps["agent"])


def test_field_sets_match(dumps: dict) -> None:
    for name in sorted(dumps["ndr"]):
        ndr_fields = set(dumps["ndr"][name]["fields"])
        agent_fields = set(dumps["agent"][name]["fields"])
        diff = ndr_fields ^ agent_fields
        assert diff <= ALLOWED_FIELD_DIFF, (
            f"{name}: UnifiedLog 字段两侧不一致 {sorted(diff)}"
            "（改了一侧忘改另一侧；确实要有意区分就加进 ALLOWED_FIELD_DIFF）"
        )


@pytest.mark.parametrize("name", sorted(samples.DOCS))
def test_values_match(name: str, dumps: dict) -> None:
    ndr = dumps["ndr"][name]["values"]
    agent = dumps["agent"][name]["values"]
    assert ndr is not None, f"{name}: NDR 侧归一化返回 None"
    assert agent is not None, f"{name}: 智能体侧归一化返回 None"
    for key in sorted(set(ndr) | set(agent)):
        assert ndr.get(key) == agent.get(key), (
            f"{name}.{key} 两侧不一致：ndr={ndr.get(key)!r} agent={agent.get(key)!r}"
        )
