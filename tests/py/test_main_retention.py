"""启动时下发 ES 保留期/模板的日志口径（``ndr/backend/app/main.py``）。

只跑 NDR 栈。钉住的是**噪音**问题，不是下发本身：

- 稳态下每 5 分钟的幂等复查**不应**记 info（否则一条「第 N 次尝试下发成功」每 5 分钟
  刷一次，N 一直涨，看着像一直在重试 —— 2026-10-04 实机实测就是这样）；
- 失败后重试成功要记一条 info，并带真实重试次数；
- 一直失败仍只在第 ``_ES_SETUP_ATTEMPTS`` 次记一条 warning（既有行为，不回归）。
"""

from __future__ import annotations

import importlib
import logging
from typing import Any

import pytest


class _StopLoop(Exception):
    """在 monkeypatch 的 sleep 里抛出，用来跳出 ``_push_es_retention`` 的死循环。"""


@pytest.fixture(scope="module")
def main_mod(request: pytest.FixtureRequest) -> Any:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("启动线程只在 NDR 侧")
    return importlib.import_module("app.main")


def _run_loop(
    main_mod: Any,
    monkeypatch: pytest.MonkeyPatch,
    outcome: list[Exception | None],
) -> list[float]:
    """跑 `_push_es_retention`，按 `outcome` 逐轮决定 ensure 成功还是失败。

    `outcome[i]` 为 None = 成功；为异常 = 失败。跑完 `outcome` 后下一轮 sleep 抛
    ``_StopLoop`` 结束循环。返回各轮 sleep 的秒数。
    """
    calls = {"n": 0}
    slept: list[float] = []

    def fake_ensure(*_a: Any, **_k: Any) -> None:
        idx = calls["n"]
        calls["n"] += 1
        if idx < len(outcome) and outcome[idx] is not None:
            raise outcome[idx]  # type: ignore[misc]

    def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
        if calls["n"] >= len(outcome):
            raise _StopLoop

    # `_push_es_retention` 在函数体内 `from app.api.routes.es_admin import ensure_retention`，
    # 所以打补丁要打在源模块上。
    es_admin = importlib.import_module("app.api.routes.es_admin")
    monkeypatch.setattr(es_admin, "ensure_retention", fake_ensure)
    monkeypatch.setattr(main_mod.time, "sleep", fake_sleep)
    main_mod._push_es_retention()  # 死循环，由 fake_sleep 抛 _StopLoop 结束
    return slept


def test_steady_state_recheck_is_not_info(
    main_mod: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """稳态：一次成功下发后，周期复查不应再记 info。"""
    with caplog.at_level(logging.DEBUG, logger="app.main"), pytest.raises(_StopLoop):
        _run_loop(main_mod, monkeypatch, [None])
    records = [r for r in caplog.records if r.name == "app.main"]
    assert not [r for r in records if r.levelno == logging.INFO], records
    assert [r for r in records if r.levelno == logging.DEBUG]


def test_success_after_failures_logs_once_with_attempt_count(
    main_mod: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """失败两次后成功：记一条 info，说明是第几次尝试、前几次失败；不用含糊的旧措辞。"""
    err = RuntimeError("es down")
    with caplog.at_level(logging.INFO, logger="app.main"), pytest.raises(_StopLoop):
        _run_loop(main_mod, monkeypatch, [err, err, None])
    msgs = [r.getMessage() for r in caplog.records if r.name == "app.main"]
    infos = [m for m in msgs if "下发成功" in m]
    assert len(infos) == 1, msgs
    assert "第 3 次尝试下发成功" in infos[0] and "前 2 次失败" in infos[0], infos


def test_persistent_failure_warns_once_at_attempt_threshold(
    main_mod: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """一直失败：只在第 `_ES_SETUP_ATTEMPTS` 次记一条 warning，之后再失败不再刷。"""
    attempts = main_mod._ES_SETUP_ATTEMPTS
    with caplog.at_level(logging.WARNING, logger="app.main"), pytest.raises(_StopLoop):
        _run_loop(main_mod, monkeypatch, [RuntimeError("es down")] * (attempts + 3))
    warnings = [r for r in caplog.records if r.name == "app.main" and r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert f"重试 {attempts} 次未成功" in warnings[0].getMessage()
