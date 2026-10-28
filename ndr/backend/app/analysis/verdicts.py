"""结论与判定的**统一词表**（verdict / status）。

为什么要单独一个模块：同一套结论词汇以前有三处各写一份 ——
`record_conclusion` 的 `status`、`complete_task` 的 `verdict`、界面展示映射。
三处各自维护必然漂移（我们已在中文映射、会话 id 提取上各踩过一次），
所以这里做**唯一事实来源**：值、中文别名、校验函数都只写一遍。

两种用途共用同一份别名表，但**允许集合不同**：
- 写回事件的 `status` 允许流程态 `pending` / `done`；
- 任务判定的 `verdict` 只允许结论态（`done` 不是判定，`pending` 表示"还没判"）。
"""

from __future__ import annotations

from typing import Any

#: 结论态（判定结果）：智能体对"这是什么"的答复
VERDICT_VALUES: tuple[str, ...] = (
    "true_positive",
    "false_positive",
    "benign",
    "suspicious",
    "inconclusive",
)

#: 写回事件用的状态：判定态 + 流程态（界面那条结论列表要能表达"在跑/已完成"）
STATUS_VALUES: tuple[str, ...] = VERDICT_VALUES + ("pending", "done")

#: 中文与简写别名：模型经常用中文写，界面也直接用中文展示
VALUE_ALIASES: dict[str, str] = {
    "true_positive": "true_positive",
    "truepositive": "true_positive",
    "tp": "true_positive",
    "真阳性": "true_positive",
    "确认攻击": "true_positive",
    "攻击": "true_positive",
    "真实事件": "true_positive",
    "false_positive": "false_positive",
    "falsepositive": "false_positive",
    "fp": "false_positive",
    "误报": "false_positive",
    "误判": "false_positive",
    "benign": "benign",
    "正常": "benign",
    "无害": "benign",
    "suspicious": "suspicious",
    "可疑": "suspicious",
    "inconclusive": "inconclusive",
    "不确定": "inconclusive",
    "待定": "inconclusive",
    "pending": "pending",
    "在跑": "pending",
    "待完成": "pending",
    "done": "done",
    "完成": "done",
    "已完成": "done",
}


#: 中文展示名（界面直接用；与 VALUE_ALIASES 里的主标签一致，单一来源）
DISPLAY_LABELS: dict[str, str] = {
    "true_positive": "确认攻击",
    "false_positive": "误报",
    "benign": "正常",
    "suspicious": "可疑",
    "inconclusive": "无法定性",
    "pending": "分析中",
    "done": "已完成",
}


def label_of(value: str) -> str:
    """结论态 → 中文展示名；未知值原样返回（不吞掉脏值，界面能看出来）。"""
    key = str(value or "").strip().lower()
    return DISPLAY_LABELS.get(key, str(value or ""))


def clean_value(
    raw: Any,
    *,
    default: str,
    allowed: tuple[str, ...],
    label: str,
) -> tuple[str, str]:
    """归一化枚举值，返回 `(规范值, 错误信息)`；错误信息为空表示通过。

    错误信息里**必须列出可选值**：模型看到可选值才能自我纠正，
    只回一句"参数不合法"会让它反复试同一个错。
    """
    text = str(raw or "").strip()
    if not text:
        return default, ""
    value = VALUE_ALIASES.get(text.lower())
    if value is None or value not in allowed:
        return "", f"{label} 不认识：{text!r}。只能填：{'、'.join(allowed)}（中文别名也认）"
    return value, ""


def clean_verdict(raw: Any, *, label: str = "verdict") -> tuple[str, str]:
    """任务判定：只接受结论态（`pending`/`done` 属于流程态，不算判定）。"""
    return clean_value(raw, default="", allowed=VERDICT_VALUES, label=label)


def clean_status(raw: Any, *, default: str = "done", label: str = "status") -> tuple[str, str]:
    """事件结论状态：结论态 + 流程态都接受。"""
    return clean_value(raw, default=default, allowed=STATUS_VALUES, label=label)


#: **终态原因**：一次分析是怎么结束的。
#: 为什么它与 verdict 分开：verdict 说的是"结论是什么"，terminal_reason 说的是
#: "这个结论是怎么来的"。只看 verdict 时 `inconclusive` 分不清「查了但没有证据」和
#: 「预算用尽/超时根本没查完」，前者说明线索质量差、后者说明预算不够，
#: 处置方式完全相反（调线索 vs 调预算），所以必须分开记。
TERMINAL_REASONS: tuple[str, ...] = (
    "concluded",
    "budget_exhausted",
    "tool_error",
    "timeout",
    "aborted",
)

#: 终态原因的中文别名（与 verdict 一样，模型写中文也认）
TERMINAL_ALIASES: dict[str, str] = {
    "结论达成": "concluded",
    "查清": "concluded",
    "已结论": "concluded",
    "预算耗尽": "budget_exhausted",
    "超预算": "budget_exhausted",
    "配额用尽": "budget_exhausted",
    "工具失败": "tool_error",
    "取数失败": "tool_error",
    "超时": "timeout",
    "会话超时": "timeout",
    "被中断": "aborted",
    "中断": "aborted",
    "放弃": "aborted",
}


def clean_terminal_reason(
    raw: Any, *, default: str = "concluded", label: str = "terminal_reason"
) -> tuple[str, str]:
    """归一化终态原因；脏值**报错而不是兜底**（兜底会让统计悄悄失真）。"""
    text = str(raw or "").strip()
    if not text:
        return default, ""
    value = TERMINAL_ALIASES.get(text.lower()) or TERMINAL_ALIASES.get(text)
    if value is None and text.lower() in TERMINAL_REASONS:
        value = text.lower()
    if value is None:
        return "", (
            f"{label} 不认识：{text!r}。只能填：{'、'.join(TERMINAL_REASONS)}（中文别名也认）"
        )
    return value, ""
