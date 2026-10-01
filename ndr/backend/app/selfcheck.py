"""启动自检（NDR 侧）：把「会静默失败」的配置问题在启动时暴露出来。"""

from __future__ import annotations

from app.workers.log import get_logger

log = get_logger(__name__)


def run_startup_selfcheck() -> None:
    """校验内置规则正则，问题以 WARNING 打印（不阻断启动）。"""
    from app.rules.builtin import BUILTIN_RULES
    from app.rules.engine import validate_rule_regexes

    for rule in BUILTIN_RULES:
        for msg in validate_rule_regexes(rule):
            log.warning("内置规则「%s」自检：%s", rule.get("name"), msg)
