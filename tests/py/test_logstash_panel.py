"""界面展示的「管道是否生效」要与真实状态一致（2026-10 审计）。

实机：库里从没存过参数（`logstash.params` 缺失），部署里的管道文件却与当前模板不一致
（文件里还留着已移除的 Wazuh 说明注释）—— 旧实现把这种情况也显示成「当前管道为自定义内容」，
让人看不出「模板已更新、文件过时」。现在两个标记分开给，界面按标记说不同的话。
"""

from __future__ import annotations

import importlib
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def logstash_mod(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("Logstash 采集配置只在 NDR 侧")
    return importlib.import_module("app.api.routes.logstash")


def _payload(
    logstash_mod: ModuleType, monkeypatch: pytest.MonkeyPatch, *, stored: Any, text: str
) -> dict[str, Any]:
    monkeypatch.setattr(logstash_mod, "_stored_params", lambda db: stored)
    monkeypatch.setattr(logstash_mod, "read_pipeline", lambda: text)
    monkeypatch.setattr(logstash_mod, "_file_updated_at", lambda: "")
    monkeypatch.setattr(logstash_mod, "_runtime_status", dict)
    monkeypatch.setattr(logstash_mod, "_queue_depth", lambda: 0)
    return logstash_mod.get_logstash(None, None)  # type: ignore[arg-type]


def test_flags_split_custom_content_from_stale_template(
    logstash_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    rendered = logstash_mod.template.render(
        logstash_mod._effective_params(None), logstash_mod.settings.logstash_http_port
    )
    # ① 文件 == 模板、库里没参数 → 已生效，不需要任何提醒
    ok = _payload(logstash_mod, monkeypatch, stored=None, text=rendered)
    assert ok["params_applied"] is True
    assert ok["params_stored"] is False
    # ② 文件 != 模板、库里没参数 → 模板过时/手工改过，**不是**「自定义内容」
    stale = _payload(logstash_mod, monkeypatch, stored=None, text=rendered + "\n# 手工加的一行\n")
    assert stale["params_applied"] is False
    assert stale["params_stored"] is False
    # ③ 文件 != 模板、库里有参数 → 真·自定义内容
    custom = _payload(
        logstash_mod,
        monkeypatch,
        stored={"es_enabled": True},
        text=rendered + "\n# 自定义\n",
    )
    assert custom["params_applied"] is False
    assert custom["params_stored"] is True


def test_panel_uses_both_flags() -> None:
    """前端两个标记都要用上：只说「自定义内容」会把「模板已更新」误报成用户自定义。"""
    src = (ROOT / "ndr" / "frontend" / "components" / "logstash-panel.tsx").read_text(
        encoding="utf-8"
    )
    assert "params_stored" in src
    assert "默认模板不一致" in src


def test_template_has_no_removed_product_name() -> None:
    """模板里不能再出现已移除的组件名（实机管道的过时注释就是这么来的）。"""
    src = (ROOT / "ndr" / "backend" / "app" / "collector" / "template.py").read_text(
        encoding="utf-8"
    )
    assert "Wazuh" not in src and "wazuh" not in src
