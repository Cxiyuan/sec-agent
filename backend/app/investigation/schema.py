"""调查结果结构与校验。

核心纪律（反幻觉）：
- 每条结论必须挂**已被本轮查询证实过**的证据引用；全无效的条目直接丢弃；
- 置信度由证据覆盖率封顶（证据不足时不允许出现"高置信度"）；
- 规模全部有上限，落库结构永远可渲染（前端与报告不需要防御性代码）。
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

# 阶段词表：与 deep_analysis.KILLCHAIN_STAGES 对齐（报告与界面共用）
STAGES: tuple[str, ...] = ("侦察", "入侵", "立足", "横向", "外泄")
ROLES: tuple[str, ...] = ("入口", "落脚", "横向", "目标", "未知")
IOC_TYPES: tuple[str, ...] = ("ip", "domain", "hash", "url")
# 轮次状态：succeeded=完整完成；partial/budget_exhausted=预算或数据受限的部分结果；failed=失败
STATUSES: tuple[str, ...] = ("running", "succeeded", "partial", "budget_exhausted", "failed")

MAX_PATH = 12
MAX_TIMELINE = 200
MAX_IOCS = 60
MAX_LATERAL = 30
MAX_EXFIL = 30
MAX_ASSETS = 40
MAX_GAPS = 20


class PathStage(BaseModel):
    stage: str
    description: str = ""
    start: str | None = None
    end: str | None = None
    assets: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class TimelineItem(BaseModel):
    ts: str | None = None
    type: str = ""
    src: str = ""
    dst: str = ""
    summary: str = ""
    ref: str = ""


class LateralItem(BaseModel):
    src: str = ""
    dst: str = ""
    method: str = ""
    evidence_refs: list[str] = Field(default_factory=list)


class ExfilItem(BaseModel):
    dst: str = ""
    bytes: int = 0
    evidence_refs: list[str] = Field(default_factory=list)


class IocItem(BaseModel):
    type: str = "ip"
    value: str = ""
    intel: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[str] = Field(default_factory=list)


class AssetImpact(BaseModel):
    ip: str = ""
    asset: str = ""
    importance: str = ""
    role: str = "未知"


class GapItem(BaseModel):
    missing: str = ""
    why: str = ""
    next_action: str = ""


class InvestigationResult(BaseModel):
    """一轮调查的最终产出（落 case_investigations.result 与 attacker_cases.investigation）。"""

    version: int = 1
    case_id: str = ""
    round: int = 0
    kind: str = "auto"
    status: str = "succeeded"  # succeeded|partial|budget_exhausted|failed
    attacker: dict[str, Any] = Field(default_factory=dict)
    path: list[PathStage] = Field(default_factory=list)
    timeline: list[TimelineItem] = Field(default_factory=list)
    lateral: list[LateralItem] = Field(default_factory=list)
    exfil: list[ExfilItem] = Field(default_factory=list)
    iocs: list[IocItem] = Field(default_factory=list)
    assets_impacted: list[AssetImpact] = Field(default_factory=list)
    gaps: list[GapItem] = Field(default_factory=list)
    confidence: float = 0.0
    summary: str = ""
    query_trail: list[dict[str, Any]] = Field(default_factory=list)
    budget: dict[str, Any] = Field(default_factory=dict)
    dropped: list[str] = Field(default_factory=list)  # 因证据不足被丢弃的条目（可审计）

    @field_validator("confidence")
    @classmethod
    def _clamp_confidence(cls, value: float) -> float:
        try:
            return max(0.0, min(float(value), 1.0))
        except (TypeError, ValueError):
            return 0.0


def _as_str_list(value: Any, limit: int = 20) -> list[str]:
    if isinstance(value, (str, int, float)):
        return [str(value)][:limit]
    if isinstance(value, list):
        return [str(x) for x in value][:limit]
    return []


def _refs(value: Any, valid: set[str]) -> list[str]:
    """只保留有效引用（无效引用会让结论站不住脚，宁缺毋滥）。"""
    return [r for r in _as_str_list(value, 30) if r in valid]


def _int_or_zero(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return 0


def _merge_stages(items: list[PathStage]) -> list[PathStage]:
    """同一阶段只留一条：合并证据/资产/时间（模型既逐步 record_finding、又在 finish 里重写一遍时很常见）。

    为什么必须合并：路径是「阶段序列」，同一阶段出现两次会让报告与时间线看起来像
    攻击发生了两次；而两处描述往往互补（一处有资产、一处有证据）。
    """
    merged: dict[str, PathStage] = {}
    order: list[str] = []
    for stage in items:
        key = stage.stage
        if key not in merged:
            merged[key] = stage
            order.append(key)
            continue
        base = merged[key]
        if len(stage.description) > len(base.description):
            base.description = stage.description
        base.assets = sorted({*base.assets, *stage.assets})[:20]
        base.evidence_refs = sorted({*base.evidence_refs, *stage.evidence_refs})[:30]
        for attr in ("start", "end"):
            current, new = getattr(base, attr), getattr(stage, attr)
            if not new:
                continue
            if (
                current is None
                or (attr == "start" and new < current)
                or (attr == "end" and new > current)
            ):
                setattr(base, attr, new)
    return [merged[key] for key in order]


def _sanitize_path(items: Any, valid: set[str], dropped: list[str]) -> list[PathStage]:
    out: list[PathStage] = []
    for raw in items if isinstance(items, list) else []:
        if not isinstance(raw, dict):
            continue
        stage = str(raw.get("stage") or "").strip()
        if stage not in STAGES:
            dropped.append(f"未知阶段 {stage!r}")
            continue
        refs = _refs(raw.get("evidence_refs"), valid)
        if not refs:
            # 与固定深度分析同策略：无证据的阶段不保留
            dropped.append(f"阶段「{stage}」无有效证据，已丢弃")
            continue
        out.append(
            PathStage(
                stage=stage,
                description=str(raw.get("description") or "")[:600],
                start=str(raw["start"]) if raw.get("start") else None,
                end=str(raw["end"]) if raw.get("end") else None,
                assets=_as_str_list(raw.get("assets"), 20),
                evidence_refs=refs,
            )
        )
        if len(out) >= MAX_PATH:
            break
    return _merge_stages(out)


def _sanitize_items(
    items: Any, model: type[BaseModel], ref_field: list[str], valid: set[str], limit: int, dropped: list[str], label: str
) -> list[Any]:
    out: list[Any] = []
    for raw in items if isinstance(items, list) else []:
        if not isinstance(raw, dict):
            continue
        refs = _refs(raw.get("evidence_refs"), valid)
        if not refs:
            dropped.append(f"{label} 条目无有效证据，已丢弃")
            continue
        data = dict(raw)
        data["evidence_refs"] = refs
        for key in ref_field:
            data.pop(key, None)
        try:
            out.append(model(**data))
        except Exception:  # noqa: BLE001
            dropped.append(f"{label} 条目结构非法，已丢弃")
        if len(out) >= limit:
            break
    return out


def validate_result(
    raw: Any,
    *,
    valid_refs: set[str],
    findings: list[dict[str, Any]] | None = None,
    gaps: list[dict[str, Any]] | None = None,
    base: dict[str, Any] | None = None,
) -> InvestigationResult:
    """把模型输出规整成可落库结构：丢无效条目 + 置信度封顶 + 规模截断。

    ``findings``（record_finding 逐步记录的结果）优先于 ``finish`` 里的一次性描述：
    前者是"边查边记"，证据经过即时校验；后者留作补充。
    """
    payload = raw if isinstance(raw, dict) else {}
    dropped: list[str] = []
    result = InvestigationResult(**{**(base or {}), "version": 1})

    # 阶段：以 record_finding 为主（即时校验过），finish.path 作为补充
    path_raw: list[dict[str, Any]] = []
    for item in findings or []:
        if isinstance(item, dict):
            path_raw.append(
                {
                    "stage": item.get("stage"),
                    "description": item.get("description"),
                    "assets": item.get("assets"),
                    "evidence_refs": item.get("evidence_refs"),
                    "start": item.get("time_start"),
                    "end": item.get("time_end"),
                }
            )
    extra = payload.get("path")
    if isinstance(extra, list):
        path_raw.extend([x for x in extra if isinstance(x, dict)])
    result.path = _sanitize_path(path_raw, valid_refs, dropped)

    result.timeline = [
        item
        for item in (
            TimelineItem(
                ts=str(x["ts"]) if isinstance(x, dict) and x.get("ts") else None,
                type=str((x or {}).get("type") or "")[:64],
                src=str((x or {}).get("src") or "")[:64],
                dst=str((x or {}).get("dst") or "")[:64],
                summary=str((x or {}).get("summary") or "")[:300],
                ref=str((x or {}).get("ref") or ""),
            )
            for x in (payload.get("timeline") or [])
            if isinstance(x, dict)
        )
        if item.ref in valid_refs or not item.ref
    ][:MAX_TIMELINE]

    result.lateral = _sanitize_items(
        payload.get("lateral"), LateralItem, ["from"], valid_refs, MAX_LATERAL, dropped, "横向移动"
    )
    result.exfil = _sanitize_items(
        payload.get("exfil"), ExfilItem, [], valid_refs, MAX_EXFIL, dropped, "外泄"
    )
    for item in result.exfil:
        item.bytes = _int_or_zero(getattr(item, "bytes", 0))

    iocs_raw = payload.get("iocs")
    iocs_src = iocs_raw if isinstance(iocs_raw, list) else []
    iocs: list[IocItem] = []
    for raw_ioc in iocs_src:
        if not isinstance(raw_ioc, dict):
            continue
        itype = str(raw_ioc.get("type") or "ip").lower()
        value = str(raw_ioc.get("value") or "").strip()
        refs = _refs(raw_ioc.get("evidence_refs"), valid_refs)
        if not value or not refs:
            if value:
                dropped.append(f"IOC {value} 无有效证据，已丢弃")
            continue
        intel_raw = raw_ioc.get("intel")
        iocs.append(
            IocItem(
                type=itype if itype in IOC_TYPES else "ip",
                value=value[:256],
                intel=intel_raw if isinstance(intel_raw, dict) else {},
                evidence_refs=refs,
            )
        )
        if len(iocs) >= MAX_IOCS:
            break
    result.iocs = iocs

    assets_raw = payload.get("assets_impacted")
    assets_src = assets_raw if isinstance(assets_raw, list) else []
    assets: list[AssetImpact] = []
    for raw_asset in assets_src:
        if not isinstance(raw_asset, dict):
            continue
        role = str(raw_asset.get("role") or "未知")
        assets.append(
            AssetImpact(
                ip=str(raw_asset.get("ip") or "")[:64],
                asset=str(raw_asset.get("asset") or "")[:128],
                importance=str(raw_asset.get("importance") or "")[:16],
                role=role if role in ROLES else "未知",
            )
        )
        if len(assets) >= MAX_ASSETS:
            break
    result.assets_impacted = assets

    merged_gaps: list[GapItem] = []
    for item in (gaps or []) + list(payload.get("gaps") or []):
        if not isinstance(item, dict):
            continue
        merged_gaps.append(
            GapItem(
                missing=str(item.get("missing") or "")[:300],
                why=str(item.get("why") or "")[:300],
                next_action=str(item.get("next_action") or "")[:300],
            )
        )
        if len(merged_gaps) >= MAX_GAPS:
            break
    result.gaps = merged_gaps

    attacker_raw = payload.get("attacker")
    result.attacker = attacker_raw if isinstance(attacker_raw, dict) else {}
    result.summary = str(payload.get("summary") or "")[:2000]
    result.confidence = payload.get("confidence") or 0.0

    # 置信度封顶：证据链不完整时不允许出现"高置信度"
    #   - 有阶段因无证据被丢弃 → 上限 0.6
    #   - 覆盖率 < 50% → 上限 0.5
    #   - 一个阶段都没留下 → 上限 0.4
    if result.path:
        claimed = len([x for x in (payload.get("path") or []) if isinstance(x, dict)])
        covered = len(result.path)
        total_claimed = max(claimed, covered)
        if covered < total_claimed:
            result.confidence = min(result.confidence, 0.6)
            dropped.append(
                f"证据链不完整：声称 {total_claimed} 个阶段、{covered} 个有证据 → 置信度上限 0.6"
            )
        if covered / total_claimed < 0.5:
            result.confidence = min(result.confidence, 0.5)
    else:
        result.confidence = min(result.confidence, 0.4)
    result.dropped = dropped[:40]
    return result


def to_group_attack_chain(result: InvestigationResult) -> dict[str, Any]:
    """转成 ``event_groups.attack_chain`` 的**超集**结构。

    保留原有的 ``stages[].evidence[{id,type,src,dst,summary}]`` 形状（旧界面/报告/定级
    不用改），额外带上完整路径、IOC、缺口 —— 增量字段缺失时前端与模板自动跳过。
    """
    stages = [
        {
            "stage": st.stage,
            "description": st.description,
            "evidence": [{"id": ref, "type": "ref", "src": "", "dst": "", "summary": ref} for ref in st.evidence_refs],
        }
        for st in result.path
    ]
    return {
        "stages": stages,
        "summary": result.summary,
        "confidence": result.confidence,
        "case_id": result.case_id,
        "path": [st.model_dump() for st in result.path],
        "timeline": [item.model_dump() for item in result.timeline],
        "lateral": [item.model_dump() for item in result.lateral],
        "exfil": [item.model_dump() for item in result.exfil],
        "iocs": [item.model_dump() for item in result.iocs],
        "assets_impacted": [item.model_dump() for item in result.assets_impacted],
        "gaps": [item.model_dump() for item in result.gaps],
        "status": result.status,
    }


def to_group_profile(result: InvestigationResult) -> dict[str, Any]:
    """转成 ``event_groups.profile`` 的既有形状 {basic, behavior}。"""
    basic = result.attacker.get("basic") if isinstance(result.attacker.get("basic"), dict) else {}
    behavior = (
        result.attacker.get("behavior") if isinstance(result.attacker.get("behavior"), dict) else {}
    )
    if not basic and not behavior:
        basic = {"src_ips": _as_str_list(result.attacker.get("src_ips"), 20)}
        behavior = {"ttps": _as_str_list(result.attacker.get("ttps"), 20)}
    return {"basic": basic, "behavior": behavior, "case_id": result.case_id}
