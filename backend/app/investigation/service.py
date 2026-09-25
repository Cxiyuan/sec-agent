"""一轮自主调查的编排：加锁 → 建轮次 → 跑循环 → 落库 → 兼容写入 → 生成取证报告。

为什么要单实例锁：同一案件可能被"自动触发 + 人工点按钮 + 重试"同时派发，重复调查既
烧钱又会把两轮结果互相覆盖。Redis SETNX 挡住并发；Redis 不可用时**放行**（宁可重复
调查，也不要因为锁服务挂掉就永远不调查）。
"""

from __future__ import annotations

from typing import Any, Literal

from app.config import settings
from app.investigation import cases, export, planner, schema
from app.workers.log import get_logger

log = get_logger(__name__)

RoundKind = Literal["auto", "manual", "followup"]


def dispatch(case_id: str, *, kind: RoundKind = "auto", instruction: str = "") -> dict[str, Any]:
    """派发一轮调查（进 investigation 队列，不阻塞实时链路）。"""
    case = cases.get_case(case_id)
    if case is None:
        return {"ok": False, "error": "案件不存在"}
    if not settings.investigation_enabled:
        return {"ok": False, "error": "自主调查未开启（系统配置 investigation_enabled）"}
    if case.get("status") == "closed":
        return {"ok": False, "error": "案件已关闭，先重新打开再调查"}
    from app.workers.celery_app import celery_app

    celery_app.send_task(
        "analysis.investigate_case",
        args=[case_id],
        kwargs={"kind": kind, "instruction": instruction},
        queue="investigation",
    )
    cases.mark_dispatched(case_id)
    log.info("已派发案件调查：%s（%s）", case_id, kind)
    return {"ok": True, "case_id": case_id, "kind": kind, "queued": True}


def investigate(case_id: str, *, kind: RoundKind = "auto", instruction: str = "") -> dict[str, Any]:
    """同步执行一轮调查（Celery 任务体 / 本机自测入口）。"""
    case = cases.get_case(case_id)
    if case is None:
        return {"ok": False, "error": "案件不存在"}
    if not cases.acquire_lock(case_id):
        return {"ok": False, "error": "该案件正在调查中，已跳过本次"}
    started = cases.start_round(case_id, kind=kind, instruction=instruction)
    if started is None:
        cases.release_lock(case_id)
        return {"ok": False, "error": "案件不存在"}
    round_no, inv_id = started
    case["round"] = round_no
    try:
        scope = _scope_cidrs()
        result, ctx, budget, trail = planner.run(
            case, kind=kind, instruction=instruction, scope_cidrs=scope
        )
        payload = _payload(result, budget=budget, trail=trail, raw_evidence=ctx.raw_evidence)
        status = result.status if result.status in schema.STATUSES else "partial"
        cases.finish_round(
            inv_id,
            result=payload,
            budget=budget.dump(),
            trail=trail,
            status=status,
            error=budget.stop_reason if status != "succeeded" else "",
        )
        cases.apply_result(case_id, payload, status=status)
        _publish(case_id, payload, status=status)
        report = None
        if payload.get("path"):
            report = export.generate_report(case_id)
        log.info(
            "案件 %s 第 %d 轮调查完成：状态 %s，阶段 %d，缺口 %d，预算 %s",
            case_id,
            round_no,
            status,
            len(payload.get("path") or []),
            len(payload.get("gaps") or []),
            budget.dump().get("stop_reason") or "-",
        )
        return {
            "ok": True,
            "case_id": case_id,
            "round": round_no,
            "status": status,
            "stages": [p.get("stage") for p in payload.get("path") or []],
            "confidence": payload.get("confidence"),
            "gaps": len(payload.get("gaps") or []),
            "budget": budget.dump(),
            "report": report,
        }
    except Exception as exc:
        log.exception("案件 %s 调查失败", case_id)
        failure = planner.empty_result(case_id, f"调查异常：{exc}")
        payload = _payload(failure, budget=planner.Budget(), trail=[], raw_evidence=[])
        cases.finish_round(inv_id, result=payload, budget={}, trail=[], status="failed", error=str(exc))
        cases.apply_result(case_id, payload, status="failed")
        return {"ok": False, "case_id": case_id, "round": round_no, "error": str(exc)}
    finally:
        cases.release_lock(case_id)


def _payload(
    result: schema.InvestigationResult,
    *,
    budget: planner.Budget,
    trail: list[dict[str, Any]],
    raw_evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    """调查结果 → 落库载荷（**超集**：既含完整路径，也含旧界面依赖的 stages）。"""
    chain = schema.to_group_attack_chain(result)
    payload: dict[str, Any] = {
        **result.model_dump(),
        **chain,
        "query_trail": trail,
        "budget": budget.dump(),
        "raw_evidence": raw_evidence[: max(1, settings.investigation_raw_evidence_max)],
        "attacker_profile": schema.to_group_profile(result),
        "dropped": result.dropped,
    }
    return payload


def _scope_cidrs() -> list[str]:
    try:
        from app.ingestion.scope import enabled_cidrs

        return list(enabled_cidrs())
    except Exception as exc:  # noqa: BLE001
        log.warning("读取分析网段失败（调查仍继续）: %s", exc)
        return []


def _publish(case_id: str, payload: dict[str, Any], *, status: str) -> None:
    from app.workers.pubsub import publish

    publish(
        "shentong:events",
        {
            "type": "case_investigated",
            "case_id": case_id,
            "attacker_key": payload.get("attacker_key"),
            "status": status,
            "confidence": payload.get("confidence"),
            "stages": [p.get("stage") for p in (payload.get("path") or []) if isinstance(p, dict)],
            "gaps": len(payload.get("gaps") or []),
        },
    )
