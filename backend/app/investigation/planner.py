"""有界自主调查循环：模型规划 → 执行只读取证工具 → 证据校验 → 观察回填 → 下一步。

为什么是「有界」而不是放任自主：本项目的事件流是持续压力（20 次/分），调查体一旦
发散就会烧钱拖时间。所以四类预算全部硬生效（步数/查询/模型调用/墙钟），任一触顶
立刻停并在已有结论上产出部分结果——绝不"再试一次看看"。

上下文控制：每步观察压缩到 ~1500 字符，只有最近 K 步保留完整观察，更早的折叠成一行。
否则 8 步之后提示词会被工具结果撑爆，既贵又容易让模型跑偏。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from app.config import settings
from app.investigation import catalog, es_query, pg_query, schema, tools
from app.models import prompts
from app.models.llm import deep_invoke_json
from app.workers.log import get_logger

log = get_logger(__name__)

# 记录类工具不消耗查询预算（它们不访问数据源）
FREE_TOOLS = {"record_finding", "note_gap"}
MAX_INVALID_REPLIES = 2


def _safe_int(value: Any, default: int = 0) -> int:
    """安全转 int（案件/接口给的值可能是字符串或脏值，不该让整轮调查崩掉）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@dataclass
class Budget:
    """一次调查的预算与消耗（落库供审计）。"""

    max_steps: int = 8
    max_queries: int = 12
    max_llm_calls: int = 6
    timeout_seconds: int = 240
    started: float = field(default_factory=time.monotonic)
    steps: int = 0
    queries: int = 0
    llm_calls: int = 0
    tokens_est: int = 0
    stop_reason: str = ""

    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.started

    def elapsed_ms(self) -> int:
        return _safe_int(self.elapsed_seconds() * 1000)

    def exhausted(self) -> str:
        if self.steps >= self.max_steps:
            return f"步数达到上限 {self.max_steps}"
        if self.queries >= self.max_queries:
            return f"查询次数达到上限 {self.max_queries}"
        if self.llm_calls >= self.max_llm_calls:
            return f"模型调用达到上限 {self.max_llm_calls}"
        if self.elapsed_seconds() >= self.timeout_seconds:
            return f"耗时达到上限 {self.timeout_seconds}s"
        return ""

    def dump(self) -> dict[str, Any]:
        return {
            "steps": self.steps,
            "queries": self.queries,
            "llm_calls": self.llm_calls,
            "tokens_est": self.tokens_est,
            "elapsed_ms": self.elapsed_ms(),
            "limits": {
                "max_steps": self.max_steps,
                "max_queries": self.max_queries,
                "max_llm_calls": self.max_llm_calls,
                "timeout_seconds": self.timeout_seconds,
            },
            "stop_reason": self.stop_reason,
        }


def _estimate_tokens(*texts: str) -> int:
    """粗略估算 token（中文≈1 字 1 token，英文≈4 字符 1 token）——只用于成本可见性。"""
    chars = sum(len(t or "") for t in texts)
    return _safe_int(chars / 1.8)


def _clip_json(value: Any, limit: int) -> str:
    try:
        text = json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        text = str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + f"…(截断，共 {len(text)} 字符)"


def _compact_observation(name: str, result: dict[str, Any]) -> str:
    """把工具结果压成紧凑观察（保留计数与关键条目，丢掉体积大的明细）。"""
    limit = max(300, settings.investigation_observation_chars)
    payload = dict(result)
    if isinstance(payload.get("hits"), list):
        hits = payload.pop("hits")
        payload["hits_sample"] = hits[:5]
        payload["hits_total"] = len(hits)
    if isinstance(payload.get("buckets"), list) and len(payload["buckets"]) > 10:
        payload["buckets"] = payload["buckets"][:10]
    if isinstance(payload.get("by_source"), dict):
        for value in payload["by_source"].values():
            if isinstance(value, dict) and isinstance(value.get("buckets"), list):
                value["buckets"] = value["buckets"][:8]
            if isinstance(value, dict):
                for sub in value.values():
                    if isinstance(sub, dict) and isinstance(sub.get("buckets"), list):
                        sub["buckets"] = sub["buckets"][:8]
    if isinstance(payload.get("item"), dict):
        payload["item"] = {k: v for k, v in payload["item"].items() if k != "raw"}
    return _clip_json(payload, limit)


def _transcript(history: list[dict[str, Any]], *, keep_full: int) -> str:
    """渲染步骤记录：最近 keep_full 步给完整观察，更早的折叠成一行。"""
    lines: list[str] = []
    total = len(history)
    for idx, item in enumerate(history):
        step = idx + 1
        head = f"步骤{step} 动作 {item.get('action')}"
        if item.get("params"):
            head += f" 参数 {_clip_json(item['params'], 300)}"
        if total - idx <= keep_full:
            lines.append(f"{head}\n  观察：{item.get('observation') or '（空）'}")
        else:
            lines.append(f"{head} → {item.get('brief') or '（已折叠）'}")
    return "\n".join(lines) if lines else "（尚未执行任何步骤）"


def _brief(action: str, result: dict[str, Any]) -> str:
    if isinstance(result.get("error"), str):
        return f"出错：{str(result['error'])[:120]}"
    for key in ("returned", "found", "fetched", "recorded", "gaps"):
        if key in result:
            return f"{key}={result[key]}"
    if isinstance(result.get("buckets"), list):
        return f"分桶 {len(result['buckets'])} 个"
    return "已返回"


def _case_context(
    case: dict[str, Any],
    *,
    events: dict[str, list[dict[str, Any]]],
    history: list[dict[str, Any]],
    kind: str = "auto",
    instruction: str = "",
    finalize: bool = False,
) -> dict[str, str]:
    """组装案件背景（成员事件、历史组、资产）——全部来自 PG，不消耗 ES 查询。"""
    fps = list(case.get("group_fingerprints") or [])
    flat_events: list[dict[str, Any]] = []
    for fp in fps:
        flat_events.extend(events.get(fp) or [])
    flat_events.sort(key=lambda e: str(e.get("ts") or ""))
    ips = sorted(
        {
            *(str(x) for x in (case.get("src_ips") or [])),
            *(str(x) for x in (case.get("dst_ips") or [])),
        }
    )
    assets = pg_query.assets_by_ips(ips)
    group_hist = pg_query.group_history(
        sorted({str(x) for x in (case.get("keys") or {}).get("ip") or []})
        or [str(x) for x in (case.get("src_ips") or [])],
        days=settings.investigation_max_lookback_days,
        limit=20,
    )
    return {
        "case_key": str(case.get("attacker_key") or "unknown"),
        "severity": str(case.get("severity") or "unknown"),
        "group_count": str(case.get("group_count") or len(fps)),
        "event_count": str(case.get("event_count") or len(flat_events)),
        "first_seen": str(case.get("first_seen") or "-"),
        "last_seen": str(case.get("last_seen") or "-"),
        "keys": _clip_json(case.get("keys") or {}, 800),
        "src_ips": _clip_json(case.get("src_ips") or [], 400),
        "dst_ips": _clip_json(case.get("dst_ips") or [], 400),
        "events": _clip_json(flat_events[:40], 3000),
        "history": _clip_json(group_hist, 2000),
        "assets": _clip_json(assets[:20], 1500),
        "tools": tools.tool_catalog_text(),
        "fields": "\n\n".join(
            catalog.catalog_text(kind, es_query.index_pattern(kind))
            for kind in catalog.default_sources()
        ),
        "transcript": _transcript(
            history, keep_full=max(1, settings.investigation_keep_observations)
        ),
        "task": _task_text(kind, instruction, finalize),
    }


def _task_text(kind: str, instruction: str, finalize: bool = False) -> str:
    if finalize:
        # 为什么单开一句：实测上限 6 时调查**全部**撞限就停——模型一直在查，
        # 没机会输出结论，于是 path/gaps/IOC 全空。把最后一次专门留给收束。
        return (
            "⏰ **预算即将用尽：这是最后一次机会**。必须立即输出 action=finish，"
            "把已确认的阶段（record_finding 记过的、或本轮已核实的事实）、已取到的证据引用、"
            "以及还没查清的点（gaps）全部整理出来。宁可结论留缺口，也不要再发起新查询。"
        )
    if kind == "followup" and instruction:
        return (
            f"这是**追问轮**：分析师要求「{instruction}」。"
            "优先回答该要求，仍按同一证据纪律记录阶段与缺口。"
        )
    if kind == "manual" and instruction:
        return (
            f"人工发起的调查，附加要求：「{instruction}」。先看历史与已确认事实，再做针对性取证。"
        )
    return (
        "自动调查：还原该攻击者的**完整攻击路径**（入口 → 立足 → 横向 → 外泄）。"
        "优先确认：怎么进来的、在哪里立足、横向到哪些机器、有没有数据外泄。"
    )


def _build_prompt(ctx: dict[str, str]) -> str:
    return prompts.INVESTIGATION_USER.format(**ctx)


def run(
    case: dict[str, Any],
    *,
    kind: str = "auto",
    instruction: str = "",
    scope_cidrs: list[str] | None = None,
) -> tuple[schema.InvestigationResult, tools.ToolCtx, Budget, list[dict[str, Any]]]:
    """执行一轮调查，返回 (结果, 工具上下文, 预算, 查询轨迹)。"""
    budget = Budget(
        max_steps=max(1, settings.investigation_max_steps),
        max_queries=max(1, settings.investigation_max_queries),
        max_llm_calls=max(1, settings.investigation_max_llm_calls),
        timeout_seconds=max(30, settings.investigation_timeout_seconds),
    )
    ctx = tools.ToolCtx(case=case, scope_cidrs=list(scope_cidrs or []))
    events = pg_query.group_events(list(case.get("group_fingerprints") or []))
    history: list[dict[str, Any]] = []
    trail: list[dict[str, Any]] = []
    invalid_replies = 0

    while True:
        reason = budget.exhausted()
        if reason:
            budget.stop_reason = reason
            break

        # 最后一次调用专用于收束结论（否则预算会被查询吃光、产出为空）
        finalize = budget.llm_calls >= budget.max_llm_calls - 1
        try:
            prompt = _build_prompt(
                _case_context(
                    case,
                    events=events,
                    history=history,
                    kind=kind,
                    instruction=instruction,
                    finalize=finalize,
                )
            )
        except KeyError as exc:  # 提示词占位符与调用点不一致 → 明确报错而不是静默
            budget.stop_reason = f"提示词占位符缺失：{exc}"
            break
        if len(prompt) > settings.investigation_max_prompt_chars:
            prompt = prompt[: settings.investigation_max_prompt_chars] + "\n…（上下文过长已截断）"

        try:
            reply = deep_invoke_json(prompts.INVESTIGATION_SYSTEM, prompt)
        except Exception as exc:  # noqa: BLE001
            budget.stop_reason = f"模型调用失败：{exc}"
            break
        budget.llm_calls += 1
        budget.tokens_est += _estimate_tokens(
            prompts.INVESTIGATION_SYSTEM, prompt, _clip_json(reply, 2000)
        )

        action = str((reply or {}).get("action") or "").strip()
        params = (reply or {}).get("params")
        if action == "finish":
            budget.stop_reason = budget.stop_reason or "模型给出最终结论"
            return (
                schema.validate_result(
                    {**(params if isinstance(params, dict) else {}), "kind": kind},
                    valid_refs=ctx.valid_refs,
                    findings=ctx.findings,
                    gaps=ctx.gaps,
                    base={
                        "case_id": str(case.get("id") or ""),
                        "round": _safe_int(case.get("round")),
                        "kind": kind,
                    },
                ),
                ctx,
                budget,
                trail,
            )
        if not action:
            invalid_replies += 1
            history.append(
                {
                    "action": "（无效输出）",
                    "params": {},
                    "observation": '没有解析出 action 字段。请严格输出 JSON：{"action":"…","params":{…}}',
                    "brief": "无效输出",
                }
            )
            if invalid_replies >= MAX_INVALID_REPLIES:
                budget.stop_reason = "模型连续输出无效 JSON"
                break
            continue

        budget.steps += 1
        if action not in FREE_TOOLS:
            budget.queries += 1
        started = time.monotonic()
        result = tools.execute(action, params, ctx)
        elapsed = _safe_int((time.monotonic() - started) * 1000)
        observation = _compact_observation(action, result)
        history.append(
            {
                "action": action,
                "params": params if isinstance(params, dict) else {},
                "observation": observation,
                "brief": _brief(action, result),
            }
        )
        trail.append(
            {
                "step": budget.steps,
                "tool": action,
                "params": params if isinstance(params, dict) else {},
                "result_count": result.get("returned")
                or result.get("found")
                or result.get("fetched"),
                "error": result.get("error"),
                "ms": elapsed,
            }
        )

    # 预算耗尽/失败：用已记录的内容产出部分结果（不留空手）
    if not ctx.findings and not ctx.gaps:
        # 显式记缺口：否则界面与报告上就是"什么都没有"，看不出是没查到还是没跑
        ctx.gaps.append(
            {
                "missing": "未记录可验证的攻击阶段",
                "why": budget.stop_reason or "调查未产生可落库的结论",
                "next_action": (
                    "可提高「模型调用上限」（系统配置 → 自主取证调查，即时生效），"
                    "或人工下发追问指令（指定时间范围 / 重点 IP）"
                ),
            }
        )
    partial = schema.validate_result(
        {
            "kind": kind,
            "status": "budget_exhausted" if budget.stop_reason else "partial",
            "summary": f"调查未完成：{budget.stop_reason or '未知原因'}；已完成 {budget.steps} 步取证。",
        },
        valid_refs=ctx.valid_refs,
        findings=ctx.findings,
        gaps=ctx.gaps,
        base={
            "case_id": str(case.get("id") or ""),
            "round": _safe_int(case.get("round")),
            "kind": kind,
        },
    )
    partial.status = (
        "budget_exhausted"
        if budget.stop_reason.startswith(("步数", "查询", "模型调用", "耗时"))
        else "partial"
    )
    return partial, ctx, budget, trail


def build_group_context(
    case: dict[str, Any], *, kind: str = "auto", instruction: str = ""
) -> dict[str, Any]:
    """给服务层/报告用的紧凑案件上下文（含事件与历史，避免重复查库）。"""
    events = pg_query.group_events(list(case.get("group_fingerprints") or []))
    return {
        "events": events,
        "context": _case_context(
            case, events=events, history=[], kind=kind, instruction=instruction
        ),
    }


def empty_result(case_id: str, reason: str) -> schema.InvestigationResult:
    """失败占位结果（保证界面与报告永远有结构可渲染）。"""
    result = schema.InvestigationResult(case_id=case_id, status="failed", summary=reason[:500])
    result.confidence = 0.0
    return result
