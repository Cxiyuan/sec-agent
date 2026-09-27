"""有界自主调查循环：模型规划 → 执行只读取证工具 → 证据校验 → 观察回填 → 下一步。

为什么是「有界」而不是放任自主：本项目的事件流是持续压力（20 次/分），调查体一旦
发散就会烧钱拖时间。所以四类预算全部硬生效（步数/查询/模型调用/墙钟），任一触顶
立刻停并在已有结论上产出部分结果——绝不"再试一次看看"。

上下文控制：每步观察压缩到 ~1500 字符，只有最近 K 步保留完整观察，更早的折叠成一行。
否则 8 步之后提示词会被工具结果撑爆，既贵又容易让模型跑偏。
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from app.config import settings
from app.investigation import catalog, es_query, pg_query, schema, tools
from app.models import prompts
from app.models.llm import invoke_json_diag
from app.workers.log import get_logger

log = get_logger(__name__)

# 记录类工具不消耗查询预算（它们不访问数据源）
FREE_TOOLS = {"record_finding", "note_gap"}


def _invalid_limit() -> int:
    """允许连续几次输出无法解析（任意一次有效动作即归零）。"""
    return max(1, _safe_int(settings.investigation_invalid_json_limit, 4))


def _no_progress_limit() -> int:
    """连续多少步没新证据就判定无进展、强制收束。"""
    return max(2, _safe_int(settings.investigation_no_progress_steps, 4))


def _repeat_limit() -> int:
    """同一动作+参数重复多少次就强制收束。"""
    return max(2, _safe_int(settings.investigation_repeat_action_limit, 3))


def _action_signature(action: str, params: Any) -> str:
    """动作指纹（动作名 + 归一化参数），用于识别重复查询。"""
    try:
        blob = json.dumps(params or {}, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        blob = str(params)
    return hashlib.sha256(f"{action}|{blob}".encode()).hexdigest()[:16]


def _safe_int(value: Any, default: int = 0) -> int:
    """安全转 int（案件/接口给的值可能是字符串或脏值，不该让整轮调查崩掉）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@dataclass
class Budget:
    """一次调查的预算与消耗（落库供审计）。

    **软预算不是主停条件**：只要还在产出新证据就允许延长（受 ``max_extensions`` 与硬上限约束），
    主停条件是模型自己输出 ``finish``。原因：线上实测撞软上限就停会让整轮产出空结论，
    而模型往往再走两步就能收束。
    """

    max_steps: int = 8
    max_queries: int = 12
    max_llm_calls: int = 6
    timeout_seconds: int = 240
    max_steps_hard: int = 60
    max_llm_calls_hard: int = 24
    extend_steps: int = 8
    extend_llm_calls: int = 4
    extend_queries: int = 12
    max_extensions: int = 6
    started: float = field(default_factory=time.monotonic)
    steps: int = 0
    queries: int = 0
    llm_calls: int = 0
    tokens_est: int = 0
    stop_reason: str = ""
    stop_kind: str = ""  # model_finish|steps|llm_calls|queries|timeout|hard_limit|invalid_json|no_progress|repeat|model_error|prompt_error
    # 护栏与异常计数（都要落库可查：中止/降级绝不静默）
    invalid_json: int = 0
    no_progress_hits: int = 0
    repeat_hits: int = 0
    salvaged: int = 0
    extensions: int = 0

    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.started

    def elapsed_ms(self) -> int:
        return _safe_int(self.elapsed_seconds() * 1000)

    def exhausted(self) -> str:
        """当前是否已触顶 → 可读原因（未触顶返回空串）。"""
        if self.steps >= self.max_steps_hard:
            return f"步数达到绝对上限 {self.max_steps_hard}"
        if self.llm_calls >= self.max_llm_calls_hard:
            return f"模型调用达到绝对上限 {self.max_llm_calls_hard}"
        if self.queries >= self.max_queries:
            return f"查询次数达到上限 {self.max_queries}"
        if self.steps >= self.max_steps:
            return f"步数达到上限 {self.max_steps}"
        if self.llm_calls >= self.max_llm_calls:
            return f"模型调用达到上限 {self.max_llm_calls}"
        if self.elapsed_seconds() >= self.timeout_seconds:
            return f"耗时达到上限 {self.timeout_seconds}s"
        return ""

    def kind_of(self, reason: str) -> str:
        """可读原因 → 机器可读分类（用于状态映射与统计）。"""
        if "绝对上限" in reason:
            return "hard_limit"
        if "耗时" in reason:
            return "timeout"
        if "查询次数" in reason:
            return "queries"
        if "步数" in reason:
            return "steps"
        if "模型调用" in reason:
            return "llm_calls"
        return "unknown"

    def maybe_extend(self, *, progress: bool) -> str:
        """有进展时延长软预算（受 max_extensions 与硬上限约束）；返回可读说明。"""
        if not progress or self.extensions >= self.max_extensions:
            return ""
        extended: list[str] = []
        if self.steps >= self.max_steps and self.steps < self.max_steps_hard:
            self.max_steps = min(self.max_steps_hard, self.steps + max(1, self.extend_steps))
            extended.append(f"步数→{self.max_steps}")
        if self.llm_calls >= self.max_llm_calls and self.llm_calls < self.max_llm_calls_hard:
            self.max_llm_calls = min(
                self.max_llm_calls_hard, self.llm_calls + max(1, self.extend_llm_calls)
            )
            extended.append(f"模型调用→{self.max_llm_calls}")
        if self.queries >= self.max_queries:
            self.max_queries += max(1, self.extend_queries)
            extended.append(f"查询→{self.max_queries}")
        if not extended:
            return ""
        self.extensions += 1
        return "有进展，延长预算：" + "、".join(extended)

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
                "max_steps_hard": self.max_steps_hard,
                "max_llm_calls_hard": self.max_llm_calls_hard,
                "timeout_seconds": self.timeout_seconds,
                "extensions": self.extensions,
            },
            "stop_reason": self.stop_reason,
            "stop_kind": self.stop_kind,
            "invalid_json": self.invalid_json,
            "no_progress_hits": self.no_progress_hits,
            "repeat_hits": self.repeat_hits,
            "salvaged": self.salvaged,
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
        max_steps_hard=max(
            max(1, settings.investigation_max_steps), settings.investigation_max_steps_hard
        ),
        max_llm_calls_hard=max(
            max(1, settings.investigation_max_llm_calls), settings.investigation_max_llm_calls_hard
        ),
        max_extensions=max(0, _safe_int(settings.investigation_max_extensions, 6)),
    )
    ctx = tools.ToolCtx(case=case, scope_cidrs=list(scope_cidrs or []))
    events = pg_query.group_events(list(case.get("group_fingerprints") or []))
    history: list[dict[str, Any]] = []
    trail: list[dict[str, Any]] = []
    invalid_streak = 0  # 连续无效输出（任意一次有效动作即归零）
    stall_steps = 0  # 连续无进展步数
    repeats: Counter[str] = Counter()
    refs_seen = len(ctx.valid_refs)
    findings_seen = len(ctx.findings)
    last_brief = ""
    force_finalize = False  # 护栏触发后：下一次调用必须是收束

    while True:
        # 有进展就延长软预算（“不限制轮次”的落地方式）；无进展则按现有预算判断触顶
        extended = budget.maybe_extend(progress=stall_steps == 0 and budget.steps > 0)
        if extended:
            log.info(
                "调查有进展，%s（案件 %s）", extended, case.get("attacker_key") or case.get("id")
            )
        reason = budget.exhausted()
        if reason:
            budget.stop_reason = reason
            budget.stop_kind = budget.kind_of(reason)
            break

        # 最后一次调用专用于收束结论（否则预算会被查询吃光、产出为空）
        finalize = force_finalize or budget.llm_calls >= budget.max_llm_calls - 1
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
            reply, diag = invoke_json_diag(prompts.INVESTIGATION_SYSTEM, prompt, role="deep")
        except Exception as exc:  # noqa: BLE001
            budget.stop_reason = f"模型调用失败：{exc}"
            budget.stop_kind = "model_error"
            break
        budget.llm_calls += 1
        budget.tokens_est += _estimate_tokens(
            prompts.INVESTIGATION_SYSTEM, prompt, _clip_json(reply, 2000)
        )

        action = str((reply or {}).get("action") or "").strip()
        params = (reply or {}).get("params")
        if action == "finish":
            budget.stop_reason = budget.stop_reason or "模型给出最终结论"
            budget.stop_kind = budget.stop_kind or "model_finish"
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
            # 自纠正：把“为什么解析失败 + 你自己的原文片段”回灌，而不是只说一句“请输出 JSON”
            invalid_streak += 1
            budget.invalid_json += 1
            history.append(
                {
                    "action": "（无效输出）",
                    "params": {},
                    "observation": (
                        f"你上一条输出无法作为动作执行：{diag or '缺少 action 字段'}。"
                        '请只输出一个 JSON 对象：{"action": "工具名", "params": {…}}。'
                    ),
                    "brief": "无效输出（已提示自纠正）",
                }
            )
            if invalid_streak >= _invalid_limit():
                budget.stop_reason = f"模型连续 {invalid_streak} 次输出无效 JSON"
                budget.stop_kind = "invalid_json"
                break
            continue

        # 有效动作：连续无效计数归零（修掉“累计 2 次就判死整轮”的旧 bug）
        invalid_streak = 0
        force_finalize = False
        budget.steps += 1
        if action not in FREE_TOOLS:
            budget.queries += 1
        started = time.monotonic()
        result = tools.execute(action, params, ctx)
        elapsed = _safe_int((time.monotonic() - started) * 1000)
        observation = _compact_observation(action, result)
        brief = _brief(action, result)
        history.append(
            {
                "action": action,
                "params": params if isinstance(params, dict) else {},
                "observation": observation,
                "brief": brief,
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

        # ---- 防死循环护栏 1：同一动作 + 相同参数重复 ----
        sig = _action_signature(action, params)
        repeats[sig] += 1
        if repeats[sig] >= _repeat_limit():
            budget.repeat_hits += 1
            force_finalize = True
            history.append(
                {
                    "action": "（护栏：重复动作）",
                    "params": {},
                    "observation": (
                        f"同一动作已执行 {repeats[sig]} 次（{action}），同样参数的查询结果不会变。"
                        "不要再重复查：请换一个完全不同的取证角度，或直接输出 action=finish 收束。"
                    ),
                    "brief": "重复动作护栏",
                }
            )
        elif repeats[sig] == 2:
            history.append(
                {
                    "action": "（提示：重复动作）",
                    "params": {},
                    "observation": f"{action} 与相同参数已经执行过一次，请换角度或收束。",
                    "brief": "重复动作提示",
                }
            )

        # ---- 防死循环护栏 2：无进展（没新证据引用、没新阶段、结果摘要也没变）----
        refs_now, findings_now = len(ctx.valid_refs), len(ctx.findings)
        progressed = (
            refs_now > refs_seen
            or findings_now > findings_seen
            or (brief != last_brief and not result.get("error"))
        )
        refs_seen, findings_seen, last_brief = refs_now, findings_now, brief
        if progressed:
            stall_steps = 0
        else:
            stall_steps += 1
            if stall_steps >= _no_progress_limit():
                budget.no_progress_hits += 1
                force_finalize = True
                history.append(
                    {
                        "action": "（护栏：无进展）",
                        "params": {},
                        "observation": (
                            f"连续 {stall_steps} 步没取到新证据（证据引用 {refs_now} 条、"
                            f"已记录阶段 {findings_now} 条）。不要再查同类数据：直接输出 "
                            "action=finish，把已确认的写进 path，把查不到的写进 gaps。"
                        ),
                        "brief": "无进展护栏",
                    }
                )

    # 非正常结束：先尝试一次“只出结论”调用，再退到部分结果（不留空手）
    salvaged = _salvage(case, ctx, budget, kind=kind, trail=trail)
    if salvaged is not None:
        return salvaged, ctx, budget, trail

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
        if budget.stop_kind in ("steps", "llm_calls", "queries", "timeout", "hard_limit")
        else "partial"
    )
    return partial, ctx, budget, trail


def _salvage(
    case: dict[str, Any],
    ctx: tools.ToolCtx,
    budget: Budget,
    *,
    kind: str,
    trail: list[dict[str, Any]],
) -> schema.InvestigationResult | None:
    """一次「只出结论」调用：预算耗尽/被护栏拦住时，把已取证内容整理成结论。

    只允许 1 次、默认走 flash（省成本）；失败返回 None，由调用方落部分结果 + 显式缺口。
    这样“模型不听话”不再等于“整轮白跑”（线上实测 8/18 轮就是白跑）。
    """
    if not settings.investigation_salvage_enabled:
        return None
    if budget.llm_calls >= budget.max_llm_calls_hard:
        return None
    role = "deep" if str(settings.investigation_salvage_model or "").lower() == "deep" else "flash"
    try:
        prompt = prompts.INVESTIGATION_SALVAGE_USER.format(
            case_key=str(case.get("attacker_key") or "unknown"),
            severity=str(case.get("severity") or "unknown"),
            group_count=str(case.get("group_count") or 0),
            event_count=str(case.get("event_count") or 0),
            reason=budget.stop_reason or "未知原因",
            findings=_clip_json(ctx.findings, 3000),
            gaps=_clip_json(ctx.gaps, 1500),
            trail=_clip_json(trail[-12:], 2500),
            refs=_clip_json(sorted(ctx.valid_refs)[:60], 2000),
        )
        reply, diag = invoke_json_diag(prompts.INVESTIGATION_SALVAGE_SYSTEM, prompt, role=role)
    except Exception as exc:  # noqa: BLE001
        log.warning("收束调用失败（退回部分结果）: %s", exc)
        return None
    budget.llm_calls += 1
    if diag or not reply:
        log.warning("收束输出仍无法解析（退回部分结果）：%s", diag or "空输出")
        return None
    budget.salvaged = 1
    log.info("收束调用成功（模型 %s，中止原因 %s）", role, budget.stop_reason or "-")
    # 收束如果也没取出阶段，必须显式记缺口：否则又是“静默空结论”（本项目禁止的行为）
    if not reply.get("path") and not ctx.gaps:
        ctx.gaps.append(
            {
                "missing": "未记录可验证的攻击阶段",
                "why": budget.stop_reason or "调查被中止，且本轮未取到足够证据",
                "next_action": (
                    "可提高「模型调用上限」或「查询次数上限」（系统配置 → 自主取证调查，"
                    "即时生效），或人工下发追问指令（指定时间范围 / 重点 IP）"
                ),
            }
        )
    result = schema.validate_result(
        {
            **reply,
            "kind": kind,
            "status": "partial",
            "summary": str(reply.get("summary") or "").strip()
            or f"调查未完成（{budget.stop_reason or '未知原因'}），已按已取证内容收束。",
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
    # validate_result 不读取 payload 里的 status（它只用自身默认值）→ 显式落“部分结果”
    result.status = "partial"
    return result


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
