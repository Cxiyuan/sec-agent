"""调查结论回写 NDR（走 MCP 的 ``record_conclusion``）。

**为什么要有这个模块**：NDR 后台「智能体对接」页有一块「写回结论」面板，读的是 NDR 库里的
结论表；而那张表**只有** MCP 的 ``record_conclusion`` 会写。智能体侧从来没有人调它，
于是面板永远是空的、``get_event`` 也永远查不到结论（2026-10 MCP QA）。

**为什么用确定性代码而不是给模型一个工具**：让模型"记得"在收尾时写回，就会变成有时写
有时不写；调查链路的收尾点是确定的（``service.investigate``），在那里按案件的事件组指纹
逐条回写最可靠。同一指纹重复回写只会覆盖（NDR 侧 ``dedup_key`` = 指纹）。

回写是**旁路**：MCP 没配、NDR 不可达、写被拒都只记日志，绝不影响本轮调查结果。
"""

from __future__ import annotations

from typing import Any

from app.investigation import mcp_client
from app.workers.log import get_logger

log = get_logger(__name__)

#: 一次最多回写多少个事件组。案件可能并了几十个组，回写是审计/展示用途，
#: 按上限截断并在 detail 里说明实际组数，不把一次收尾变成几十次网络调用。
MAX_GROUPS = 20

#: 判定「有攻击链且置信度够」的门槛：低于它只写 suspicious，不写 true_positive
_CONFIRM_CONFIDENCE = 0.6


def verdict_of(payload: dict[str, Any]) -> str:
    """调查结果 → NDR 结论状态（只输出 NDR 认的值，见 ndr_tools.STATUS_VALUES）。"""
    status = str(payload.get("status") or "")
    if status == "failed":
        return "pending"
    if status != "succeeded":
        # partial / budget_exhausted：结论未跑完，别当成定论
        return "inconclusive"
    if payload.get("contradiction"):
        # 声称高级行为却缺结构化证据 → 不给定论（防把幻觉写进 NDR）
        return "inconclusive"
    if not (payload.get("path") or []):
        return "inconclusive"
    try:
        confidence = float(payload.get("confidence") or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    return "true_positive" if confidence >= _CONFIRM_CONFIDENCE else "suspicious"


def _summary(payload: dict[str, Any], status: str, groups: int, written: int) -> str:
    """结论正文：模型的总结 + 攻击链 + 缺口/置信度/状态，给 NDR 列表直接显示。"""
    stages = [str((item or {}).get("stage") or "") for item in (payload.get("path") or [])]
    parts = [str(payload.get("summary") or "").strip()]
    stages = [s for s in stages if s]
    if stages:
        parts.append("攻击链：" + " → ".join(stages))
    gaps = len(payload.get("gaps") or [])
    if gaps:
        parts.append(f"证据缺口 {gaps} 条")
    if payload.get("degraded"):
        parts.append("取证不完整（degraded）")
    if payload.get("confidence") is not None:
        parts.append(f"置信度 {payload.get('confidence')}")
    parts.append(f"调查状态 {status}")
    if groups > written:
        parts.append(f"（案件共 {groups} 个事件组，这里回写了前 {written} 个）")
    return "；".join(p for p in parts if p)[:2000]


def record_conclusion(case: dict[str, Any], payload: dict[str, Any], status: str) -> int:
    """把这一轮结论按事件组指纹回写 NDR，返回成功条数。**绝不抛异常**。"""
    if not mcp_client.enabled():
        return 0
    fingerprints = [str(x).strip() for x in (case.get("group_fingerprints") or [])]
    fingerprints = [f for f in fingerprints if f]
    if not fingerprints:
        # 没有事件组指纹 = 没有可以挂结论的 NDR 事件（例如人工建的空案件）
        return 0
    targets = fingerprints[:MAX_GROUPS]
    summary = _summary(payload, status, len(fingerprints), len(targets))
    detail = {
        "source": "agent-investigation",
        "case_id": case.get("id"),
        "display_id": case.get("display_id"),
        "round": payload.get("round"),
        "confidence": payload.get("confidence"),
        "stages": [s for s in ((item or {}).get("stage") for item in (payload.get("path") or []))],
        "gaps": len(payload.get("gaps") or []),
        "degraded": bool(payload.get("degraded")),
        "contradiction": bool(payload.get("contradiction")),
    }
    verdict = verdict_of(payload)
    severity = str(case.get("severity") or "info")
    written = 0
    for fingerprint in targets:
        try:
            result = mcp_client.call(
                "record_conclusion",
                {
                    "summary": summary,
                    "fingerprint": fingerprint,
                    "status": verdict,
                    "severity": severity,
                    "detail": detail,
                    "thread_id": str(case.get("id") or ""),
                },
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("回写 NDR 结论失败（%s）：%s", fingerprint, exc)
            continue
        if isinstance(result, dict) and result.get("error"):
            log.warning("回写 NDR 结论被拒（%s）：%s", fingerprint, result.get("error"))
            continue
        written += 1
    if written:
        log.info(
            "已回写 %d/%d 条结论到 NDR（案件 %s，判定 %s）",
            written,
            len(fingerprints),
            case.get("display_id") or case.get("id"),
            verdict,
        )
    return written
