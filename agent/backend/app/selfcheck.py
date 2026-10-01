"""启动自检：把「会静默失败」的配置问题在启动时暴露出来。

历史教训：提示词模板里多写了一个占位符（`{src_port}`）但调用点没传，
`str.format` 抛 KeyError 被上层 except 吞掉 → 「研判降噪」整层静默失效。
这类问题不看日志根本发现不了，所以启动时主动校验。
"""

from __future__ import annotations

import re

from app.workers.log import get_logger

log = get_logger(__name__)

_PLACEHOLDER_RE = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


def verify_prompts() -> list[str]:
    """校验所有提示词模板：花括号成对 + 可用占位符自身格式化。"""
    from app.models import prompts as prompt_module

    problems: list[str] = []
    for name in dir(prompt_module):
        if not name.isupper():
            continue
        template = getattr(prompt_module, name)
        if not isinstance(template, str) or not template:
            continue

        placeholders = set(_PLACEHOLDER_RE.findall(template))
        if not placeholders:
            # 无占位符的模板（如 SYSTEM 提示里的 JSON 示例）不做花括号校验，
            # 它们从不用 .format()，字面 { } 是示例内容
            continue

        residue = _PLACEHOLDER_RE.sub("", template)
        if "{" in residue or "}" in residue:
            problems.append(f"{name}: 存在不成对或非法的花括号")
            continue

        try:
            template.format(**{key: "" for key in placeholders})
        except (KeyError, IndexError, ValueError) as exc:
            problems.append(f"{name}: 格式化失败（{exc}）")
    return problems


def verify_skills() -> list[str]:
    """校验内置技能：事件类型/工具非空，工具名必须存在（防「指向不存在工具」的死技能）。"""
    from app.skills import BUILTIN_SKILLS
    from app.tools import tool_names

    known = set(tool_names())
    problems: list[str] = []
    for skill in BUILTIN_SKILLS:
        if not skill.get("event_types"):
            problems.append(f"{skill.get('name')}: 未声明事件类型，永远不会被路由命中")
        for tool in skill.get("tools") or []:
            if tool not in known:
                problems.append(f"{skill.get('name')}: 引用了不存在的工具 {tool}")
    return problems


def run_startup_selfcheck() -> None:
    """执行全部启动自检，问题以 WARNING 打印（不阻断启动）。"""
    from app.rules.builtin import BUILTIN_RULES
    from app.rules.engine import validate_rule_regexes

    for name in verify_prompts():
        log.warning("提示词自检：%s", name)

    for skill in verify_skills():
        log.warning("技能自检：%s", skill)

    for rule in BUILTIN_RULES:
        for msg in validate_rule_regexes(rule):
            log.warning("内置规则「%s」自检：%s", rule.get("name"), msg)
