"""LangGraph 分析节点实现。"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy.orm import Session

from app import runtime_config
from app.agents.memory import (
    cleanup as memory_cleanup,
    memory_text,
    recall as recall_memory,
    write_group,
    write_run,
)
from app.agents.metrics import merge_aggregates
from app.agents.persistence import (
    get_enabled_rules,
    get_enabled_skills,
    save_business_context,
    save_groups,
    save_report,
    set_groups_pending,
    update_group_analysis,
    update_group_lookback,
    update_group_memory_hits,
    update_group_profile_hits,
    update_group_skill_hits,
)
from app.agents.prefilter import known_asset_ip_set, prefilter
from app.agents.profile import (
    cleanup as profile_cleanup,
    profile_text,
    recall_entities,
    update_profiles,
    window_observations,
)
from app.agents.state import AgentState
from app.config import settings
from app.db.base import SessionLocal
from app.db.models import SystemConfig
from app.detector.handled import doc_hash
from app.edge_config import edge_thinking_for, edge_thinking_merge
from app.ingestion import exclusion
from app.ingestion.dedup import dedup_logs
from app.ingestion.es_client import fetch_window_logs
from app.ingestion.normalizer import normalize
from app.ingestion.scope import enabled_cidrs
from app.models import prompts
from app.models.llm import edge_invoke_json, flash_invoke_json, flash_invoke_text
from app.rag.context import build_business_context, context_text_for_group
from app.rules.engine import is_count_rule, match_count_rule, match_rule
from app.schemas import EventGroup, SuspiciousEvent, UnifiedLog
from app.tools import execute
from app.tools.context import ToolContext, is_public_ip
from app.workers.log import get_logger

log = get_logger(__name__)

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _now() -> datetime:
    return datetime.now(UTC)


def _config(db: Session, key: str, default: Any) -> Any:
    row = db.get(SystemConfig, key)
    if row and row.value is not None:
        return row.value.get("value", default)
    return default


def _safe_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int) -> int:
    """安全转 int（含 inf/nan 溢出防护）。"""
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


# ---------- 节点 1：拉取 + 规范化 + 去重 ----------


def _handled_registry() -> Any | None:
    """已处理文档登记（供兜底补漏）；Redis 不可用时返回 None（降级为全量分析）。"""
    try:
        import redis

        from app.detector.handled import HandledRegistry

        client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        client.ping()
        return HandledRegistry(client, settings.detector_handled_key, settings.detector_handled_ttl)
    except Exception as exc:  # noqa: BLE001
        log.warning("读取已处理登记失败，兜底将按全量分析: %s", exc)
        return None


def ingest_node(state: AgentState) -> dict[str, Any]:
    start = state.get("window_start") or (
        _now() - timedelta(minutes=settings.analysis_window_minutes)
    )
    end = state.get("window_end") or start + timedelta(minutes=settings.analysis_window_minutes)

    # 只拉取「源或目的 IP 落在启用分析网段内」的日志
    cidrs = enabled_cidrs()
    fetched = fetch_window_logs(start, end, cidrs)

    # 兜底补漏：跳过检测器已处理过的文档（否则会与实时链路重复出组/出报告）
    kept_docs = fetched.logs
    skipped_handled = 0
    if settings.detector_enabled and kept_docs:
        registry = _handled_registry()
        if registry is not None:
            hashes = [doc_hash(doc) for _, doc in kept_docs]
            flags = registry.filter_unhandled(hashes)
            kept_docs = [d for d, keep in zip(kept_docs, flags, strict=False) if keep]
            skipped_handled = len(flags) - len(kept_docs)

    logs: list[UnifiedLog] = []
    for source, doc in kept_docs:
        norm = normalize(source, doc)
        if norm is not None:
            logs.append(norm)
    logs = dedup_logs(logs, settings.analysis_window_minutes)

    run_meta: dict[str, Any] = {
        "scope_cidrs": cidrs,
        "scope_count": len(cidrs),
        "fetch_mode": fetched.mode,
        "fetched_raw": fetched.total,
        "truncated": fetched.truncated,
        "notes": fetched.notes,
        "skipped_handled": skipped_handled,
        "skipped": "no_scope" if fetched.mode == "no_scope" else None,
    }
    log.info(
        "窗口 %s ~ %s 拉取 %d 条（模式 %s，网段 %d 个），补漏跳过 %d 条，去重后 %d 条",
        start,
        end,
        fetched.total,
        fetched.mode,
        len(cidrs),
        skipped_handled,
        len(logs),
    )
    return {
        "window_start": start,
        "window_end": end,
        "raw_logs": logs,
        "run_meta": run_meta,
    }


# ---------- 节点 2：研判降噪（四层漏斗 + 兜底预筛） ----------


def _edge_review(entry: UnifiedLog, rule_label: str) -> tuple[float, bool, str]:
    """边缘模型审查降噪：返回 (score, is_suspicious, reason)。"""
    user_prompt = prompts.TRIAGE_USER.format(
        event_type=entry.event_type,
        source_system=entry.source_system,
        src_ip=entry.src_ip or "-",
        src_port=entry.src_port if entry.src_port is not None else "-",
        dst_ip=entry.dst_ip or "-",
        dst_port=entry.dst_port if entry.dst_port is not None else "-",
        protocol=entry.protocol,
        hit_rule=rule_label,
        summary=entry.summary,
        raw=json.dumps(entry.raw, ensure_ascii=False, default=str)[:1500],
    )
    try:
        result = edge_invoke_json(
            prompts.TRIAGE_SYSTEM, user_prompt, thinking=edge_thinking_for(entry.event_type)
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("边缘模型研判失败，默认视为可疑: %s", exc)
        result = {"is_suspicious": True, "score": 0.6, "reason": "边缘模型不可用"}
    return (
        _safe_float(result.get("score"), 0.5),
        bool(result.get("is_suspicious", True)),
        str(result.get("reason", "")),
    )


def _excluded_reason_text(name: str) -> str:
    """被排除事件的理由文本（详情页直接展示）。"""
    return f"已排除过滤「{name}」命中，跳过模型分析"[:500]


def _edge_concurrency() -> int:
    """批内并发度（后台可调，默认 8）。

    服务器实测（2026-09-25 预热后）：并发 1 → ~5 次/分，4 → 17，8 → 23，16 → 26.5。
    CPU 上合批是唯一的吞吐杠杆（多请求共享同一次权重读取），所以并发度直接决定吞吐。
    上限 16 对齐服务器槽位（--parallel 16），再多只会排队。
    """
    try:
        workers = int(
            runtime_config.get("edge_review_concurrency", settings.edge_review_concurrency)
        )
    except (TypeError, ValueError):
        workers = settings.edge_review_concurrency
    return max(1, min(workers, 16))


def _parallel_map(fn: Callable[[Any], Any], items: list[Any], prefix: str) -> list[Any]:
    """批内并发（线程池）；返回顺序与输入严格一致。

    边缘模型调用是同步阻塞的 HTTP 请求，用线程池即可。workers=1 或只有 1 条时
    退化为串行（省线程开销）。
    """
    if not items:
        return []
    workers = min(_edge_concurrency(), len(items))
    if workers <= 1:
        return [fn(item) for item in items]
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix=prefix) as pool:
        return list(pool.map(fn, items))


def edge_review_many(items: list[tuple[UnifiedLog, str]]) -> list[tuple[float, bool, str]]:
    """并发调边缘模型做降噪；返回顺序与输入严格一致。

    单条失败已在 _edge_review 内部兜底（返回“可疑”），不会拖垮整批。
    """
    return _parallel_map(lambda item: _edge_review(item[0], item[1]), list(items), "edge-review")


def _digest_aggregate(
    digest: dict[str, Any],
    count: int,
    rule: str,
    dst_ips: list[Any],
    dst_ports: list[Any],
) -> dict[str, Any]:
    """将聚合规模写进数据模型（不再只活在文本里）：次数/目标/端口/首末时间。"""
    return {
        "hits": count,
        "rules": {rule: count},
        "dst_ips": [str(x) for x in dst_ips][:50],
        "dst_ports": [str(x) for x in dst_ports][:50],
        "first_seen": digest.get("first_seen"),
        "last_seen": digest.get("last_seen"),
    }


def triage_node(state: AgentState) -> dict[str, Any]:
    """四层漏斗：逐条规则 → 频率规则 → 边缘模型审查 → 兜底预筛（防漏报）。"""
    logs = state.get("raw_logs", [])
    with SessionLocal() as db:
        rules = get_enabled_rules(db)

    per_log_rules = [r for r in rules if not is_count_rule(r)]
    count_rules = [r for r in rules if is_count_rule(r)]

    suspicious: list[SuspiciousEvent] = []
    handled: set[str] = set()
    rule_hits = count_hits = fallback_hits = excluded_hits = 0

    # 第 1/2 层：先做纯本地判定（谁命中了哪条规则），把要花模型的攒起来一次性并发研判。
    # 批内 N 条 = N 并发而非 N 次串行（实测服务器：8 并发 23 次/分 vs 串行 ~5 次/分）。
    hits: list[tuple[str, UnifiedLog, dict[str, Any], str]] = []  # (层, 事件, 规则, 附加说明)
    for entry in logs:
        hit = next((r for r in per_log_rules if match_rule(r, entry)), None)
        if hit is None:
            continue
        handled.add(entry.fingerprint())
        hits.append(("rule", entry, hit, ""))

    for rule in count_rules:
        for key, matched in match_count_rule(rule, logs):
            if not matched:
                continue
            rep = max(matched, key=lambda x: x.ts)
            for m in matched:
                handled.add(m.fingerprint())
            hits.append(("count", rep, rule, f"{key} × {len(matched)} 次"))

    # 第 3 层：排除过滤（本地判定，零成本）→ 边缘模型研判（并发）
    # 排除命中的事件仍进事件组（可查、可回溯），只是不进入模型分析
    decisions: list[SuspiciousEvent | None] = [None] * len(hits)
    pending: list[tuple[int, str]] = []  # (decisions 下标, 规则名)
    for idx, (_tier, entry, rule, _extra) in enumerate(hits):
        excluded_reason = exclusion.check_filter(
            entry,
            rule_name=str(rule.get("name") or ""),
            rule_source=str(rule.get("source") or ""),
            rule_severity=str(rule.get("severity") or ""),
        )
        if excluded_reason:
            excluded_hits += 1
            exclusion.record_hit(excluded_reason, entry, rule_name=str(rule.get("name") or ""))
            decisions[idx] = SuspiciousEvent(
                log=entry,
                hit_rule=rule["name"],
                rule_source=rule["source"],
                edge_score=0.0,
                edge_reason=_excluded_reason_text(excluded_reason),
                excluded=True,
                exclude_reason=excluded_reason,
            )
        else:
            pending.append((idx, str(rule.get("name") or "规则命中")))

    results = edge_review_many([(hits[i][1], label) for i, label in pending])
    for (idx, _label), (score, ok, reason) in zip(pending, results, strict=False):
        if not ok:
            continue
        tier, entry, rule, extra = hits[idx]
        decisions[idx] = SuspiciousEvent(
            log=entry,
            hit_rule=rule["name"],
            rule_source=rule["source"],
            edge_score=score,
            edge_reason=(f"{extra}｜{reason}" if extra else reason)[:500],
        )
        if tier == "count":
            count_hits += 1
        else:
            rule_hits += 1
    suspicious.extend(ev for ev in decisions if ev is not None)

    # 第 4 层：兜底预筛——规则漏掉的高风险行为，交边缘模型复筛（防漏报）
    missed = [entry for entry in logs if entry.fingerprint() not in handled]
    candidates = prefilter(
        missed,
        scope_cidrs=(state.get("run_meta") or {}).get("scope_cidrs") or [],
        known_asset_ips=known_asset_ip_set(),
    )
    cand_decisions: list[SuspiciousEvent | None] = [None] * len(candidates)
    cand_pending: list[tuple[int, str]] = []  # (cand_decisions 下标, 标签)
    for idx, cand in enumerate(candidates):
        label = f"兜底预筛（{'；'.join(cand.reasons)}）"
        excluded_reason = exclusion.check_filter(
            cand.log,
            rule_name="兜底预筛",
            rule_source="builtin",
            rule_severity=cand.log.severity,
        )
        if excluded_reason:
            excluded_hits += 1
            exclusion.record_hit(excluded_reason, cand.log, rule_name="兜底预筛")
            cand_decisions[idx] = SuspiciousEvent(
                log=cand.log,
                hit_rule="兜底预筛",
                rule_source="builtin",
                edge_score=0.0,
                edge_reason=_excluded_reason_text(excluded_reason),
                excluded=True,
                exclude_reason=excluded_reason,
            )
        else:
            cand_pending.append((idx, label))

    cand_results = edge_review_many([(candidates[i].log, label) for i, label in cand_pending])
    for (idx, _label), (score, ok, reason) in zip(cand_pending, cand_results, strict=False):
        if not ok:
            continue
        cand = candidates[idx]
        fallback_hits += 1
        cand_decisions[idx] = SuspiciousEvent(
            log=cand.log,
            hit_rule="兜底预筛",
            rule_source="builtin",
            edge_score=max(score, cand.score),
            edge_reason=f"启发式 {cand.score}：{'；'.join(cand.reasons)}｜{reason}"[:500],
        )
    suspicious.extend(ev for ev in cand_decisions if ev is not None)

    log.info(
        "研判降噪：%d 条 → 可疑 %d（逐条规则 %d / 频率 %d / 兜底 %d / 排除 %d）；"
        "规则漏掉 %d 条，兜底候选 %d 条",
        len(logs),
        len(suspicious),
        rule_hits,
        count_hits,
        fallback_hits,
        excluded_hits,
        len(missed),
        len(candidates),
    )
    return {"suspicious_events": suspicious}


# ---------- 节点 2.5：实时入口（检测器投递的聚合摘要）----------


def realtime_triage_node(state: AgentState) -> dict[str, Any]:
    """实时链路入口：把检测器投递的聚合摘要转成可疑事件并做边缘降噪。

    与 triage_node 的区别：规则匹配已在检测器完成，这里只做
    「摘要 → 可疑事件」转换 + 边缘模型降噪（量已按短窗聚合，成本可控）。
    聚合规模（次数/目标数/端口）写进 summary 与 edge_reason，供后续
    报告与定级看到真实规模。
    """
    raw_digests = state.get("digests")
    digests: list[dict[str, Any]] = raw_digests if isinstance(raw_digests, list) else []
    decisions: list[SuspiciousEvent | None] = [None] * len(digests)
    pending: list[tuple[int, UnifiedLog, str, dict[str, Any], str, Literal["user", "builtin"]]] = []
    # 元素：(下标, 事件, 标签, 聚合规模, 规则名, 规则来源)
    reviewed = 0
    excluded_n = 0
    for idx, d in enumerate(digests):
        if not isinstance(d, dict):
            continue
        rule = str(d.get("rule") or "实时检测")
        count = _safe_int(d.get("count"), 1)
        raw_dst_ips = d.get("dst_ips")
        dst_ips: list[Any] = raw_dst_ips if isinstance(raw_dst_ips, list) else []
        raw_dst_ports = d.get("dst_ports")
        dst_ports: list[Any] = raw_dst_ports if isinstance(raw_dst_ports, list) else []
        label = f"{rule}（实时聚合 {count} 次"
        if dst_ips:
            label += f" / {len(dst_ips)} 个目标"
        if dst_ports:
            label += f" / 端口 {','.join(str(p) for p in dst_ports[:6])}"
        label += "）"

        raw_samples = d.get("samples")
        samples: list[Any] = raw_samples if isinstance(raw_samples, list) else []
        sample = next((s for s in samples if isinstance(s, dict)), None)
        if sample is None:
            continue
        log_source = str(sample.get("source") or "zeek")
        raw_doc = sample.get("doc")
        if not isinstance(raw_doc, dict):
            continue
        entry = normalize(log_source, raw_doc)
        if entry is None:
            continue

        # 聚合规模带进 summary（会进入定级/报告提示词与界面）
        entry.summary = f"[实时聚合 ×{count}] {entry.summary}"[:500]
        excluded_reason = str(d.get("exclude_reason") or "")
        if excluded_reason:
            # 排除过滤命中：不调边缘模型（省调用），事件照常进组供界面查看
            excluded_n += 1
            decisions[idx] = SuspiciousEvent(
                log=entry,
                hit_rule=rule,
                rule_source="user" if d.get("rule_source") == "user" else "builtin",
                edge_score=0.0,
                edge_reason=f"{label}｜{_excluded_reason_text(excluded_reason)}"[:500],
                excluded=True,
                exclude_reason=excluded_reason,
                aggregate=_digest_aggregate(d, count, rule, dst_ips, dst_ports),
            )
        else:
            pending.append(
                (
                    idx,
                    entry,
                    label,
                    _digest_aggregate(d, count, rule, dst_ips, dst_ports),
                    rule,
                    "user" if d.get("rule_source") == "user" else "builtin",
                )
            )

    # 边缘研判：批内并发（实测服务器 8 并发 23 次/分，串行仅 ~5 次/分）
    results = edge_review_many([(entry, label) for _i, entry, label, _a, _r, _s in pending])
    for (idx, entry, label, agg, rule, rule_source), (score, ok, reason) in zip(
        pending, results, strict=False
    ):
        reviewed += 1
        if not ok:
            continue
        decisions[idx] = SuspiciousEvent(
            log=entry,
            hit_rule=rule,
            rule_source=rule_source,
            edge_score=score,
            edge_reason=f"{label}｜{reason}"[:500],
            aggregate=agg,
        )
    suspicious = [ev for ev in decisions if ev is not None]

    log.info(
        "实时研判：摘要 %d 条 → 边缘研判 %d 条（排除跳过 %d）→ 可疑 %d 条",
        len(digests),
        reviewed,
        excluded_n,
        len(suspicious),
    )
    # 窗口取摘要的真实首末时间（原来是 now，导致事件组窗口长度为 0 秒）
    firsts = sorted(s for s in (str(d.get("first_seen") or "") for d in digests) if s)
    lasts = sorted(s for s in (str(d.get("last_seen") or "") for d in digests) if s)
    win_start = _parse_dt(firsts[0]) if firsts else None
    win_end = _parse_dt(lasts[-1]) if lasts else None
    return {
        "suspicious_events": suspicious,
        "window_start": win_start or state.get("window_start") or _now(),
        "window_end": win_end or state.get("window_end") or _now(),
    }


# ---------- 节点 3：多源关联（归组） ----------


def _parse_dt(value: Any) -> datetime | None:
    """宽松解析 ISO 时间字符串（失败返回 None）。"""
    if isinstance(value, datetime):
        return value
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _merge_aggregates(items: list[dict[str, Any]]) -> dict[str, Any]:
    """合并多个摘要/事件的聚合规模 → 组级规模（实现在 metrics，供多处共用）。"""
    return merge_aggregates(list(items))


def _group_fingerprint(ips: set[str], start: datetime, excluded: bool = False) -> str:
    """事件组指纹：IP 集合 + **时间桶**（默认 30 分钟，见 group_bucket_minutes）。

    原来按“分钟”取整 → 持续攻击每个窗口/每批都会生成新组与新报告（界面被刷屏）。
    改为按可配时间桶：同一对象在桶内复用同一个组（事件累加、窗口前移）。

    excluded=True 走独立命名空间：被排除的事件不能和正常事件合并成同一个组，
    否则整组会被拉去跑模型，“跳过模型”就失效了。
    """
    bucket_minutes = max(1, _safe_int(settings.group_bucket_minutes, 30))
    minutes = _safe_int(start.timestamp() // 60, 0)
    bucket = (minutes // bucket_minutes) * bucket_minutes
    key = ("ex|" if excluded else "") + "|".join(sorted(ips)) + "|" + str(bucket)
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def _build_groups(
    events: list[SuspiciousEvent],
    window_start: datetime,
    window_end: datetime,
    *,
    excluded: bool,
) -> list[EventGroup]:
    """按 IP（源或目的）做确定性 union-find 归组（排除组用独立指纹命名空间）。"""
    if not events:
        return []
    parent: dict[int, int] = {i: i for i in range(len(events))}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    ip_to_idx: dict[str, list[int]] = {}
    for i, ev in enumerate(events):
        for ip in (ev.log.src_ip, ev.log.dst_ip):
            if ip:
                ip_to_idx.setdefault(ip, []).append(i)

    for idxs in ip_to_idx.values():
        for i in range(1, len(idxs)):
            union(idxs[0], idxs[i])

    buckets: dict[int, list[SuspiciousEvent]] = {}
    for i, ev in enumerate(events):
        buckets.setdefault(find(i), []).append(ev)

    groups: list[EventGroup] = []
    for bucket_events in buckets.values():
        src_ips = sorted({e.log.src_ip for e in bucket_events if e.log.src_ip})
        dst_ips = sorted({e.log.dst_ip for e in bucket_events if e.log.dst_ip})
        score = max((e.edge_score for e in bucket_events), default=0.0)
        fp = _group_fingerprint(set(src_ips) | set(dst_ips), window_start, excluded=excluded)
        groups.append(
            EventGroup(
                fingerprint=fp,
                src_ips=src_ips,
                dst_ips=dst_ips,
                window_start=window_start,
                window_end=window_end,
                events=bucket_events,
                triage_score=score,
                escalate=False,
                aggregate=_merge_aggregates([e.aggregate for e in bucket_events]),
                excluded=excluded,
            )
        )
    return groups


def correlate_node(state: AgentState) -> dict[str, Any]:
    events = state.get("suspicious_events", [])
    window_start = state.get("window_start") or _now()
    window_end = state.get("window_end") or window_start

    # 排除事件独立成组：既保证“跳过模型”确实省下调用，也避免噪声污染正常组的规模与定级
    groups = _build_groups(
        [ev for ev in events if not ev.excluded], window_start, window_end, excluded=False
    )
    excluded_groups = _build_groups(
        [ev for ev in events if ev.excluded], window_start, window_end, excluded=True
    )

    # 语义关联（补充）：对高分组之间用边缘模型判断是否同一次攻击（限流）；排除组不参与
    groups = _semantic_merge(groups)
    groups.extend(excluded_groups)

    # 升级判定（阈值打分）；排除组不升级（不跑深度分析）
    with SessionLocal() as db:
        threshold = _safe_float(
            _config(db, "escalate_score_threshold", settings.escalate_score_threshold),
            settings.escalate_score_threshold,
        )
    for g in groups:
        g.escalate = (not g.excluded) and g.triage_score >= threshold

    # 持久化事件组，供后台/驾驶舱即时可见
    save_groups(groups, state.get("thread_id", ""))
    log.info(
        "关联归组：%d 个事件组（其中已排除 %d 个），升级 %d 个",
        len(groups),
        len(excluded_groups),
        sum(1 for g in groups if g.escalate),
    )
    return {"groups": groups}


def _semantic_merge(groups: list[EventGroup], max_calls: int = 20) -> list[EventGroup]:
    """边缘模型语义关联：高分且无共享 IP 的组，判断是否同一次攻击。

    用并查集合并，避免两个坑：
    - 索引错位：之前 merged 记的是 high 子列表下标，却拿去过滤 groups，会误删低分组；
    - 传递合并丢事件：A 并 B、B 并 C 时，C 的事件挂在将被删除的 B 上而丢失。
    """
    if len(groups) < 2:
        return groups
    high_idx = [i for i, g in enumerate(groups) if g.triage_score >= 0.5]
    if len(high_idx) < 2:
        return groups
    n = len(high_idx)
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    # 先把候选对全部筛出来（高分 + 无共享 IP），再并发问模型；合并仍按原顺序应用。
    # 为什么要并发：这一步用的是 thinking 模式（单次 16~29s），串行 20 次 = 5 分钟以上。
    pairs: list[tuple[int, int]] = []
    for p in range(n):
        for q in range(p + 1, n):
            if len(pairs) >= max_calls:
                break
            a, b = groups[high_idx[p]], groups[high_idx[q]]
            if set(a.src_ips) & set(b.src_ips) or set(a.dst_ips) & set(b.dst_ips):
                continue
            pairs.append((p, q))

    def ask(pair: tuple[int, int]) -> tuple[int, int, bool]:
        p, q = pair
        a, b = groups[high_idx[p]], groups[high_idx[q]]
        try:
            r = edge_invoke_json(
                prompts.GROUP_SEMANTIC_SYSTEM,
                prompts.GROUP_SEMANTIC_USER.format(
                    event_a=json.dumps([e.log.summary for e in a.events[:5]], ensure_ascii=False),
                    event_b=json.dumps([e.log.summary for e in b.events[:5]], ensure_ascii=False),
                ),
                thinking=edge_thinking_merge(),
            )
            return p, q, bool(r.get("same_attack"))
        except Exception as exc:  # noqa: BLE001
            log.warning("语义关联失败: %s", exc)
            return p, q, False

    # pool.map 保序 → 并查集的合并顺序与串行版一致（对已同组的对做 union 本就是空操作，语义等价）
    for p, q, same_attack in _parallel_map(ask, pairs, "edge-merge"):
        if same_attack:
            union(p, q)

    # 按根聚合：根组吸收同组其它组的事件 / IP / 分数，只删除被吸收的组
    buckets: dict[int, list[int]] = {}
    for p in range(n):
        buckets.setdefault(find(p), []).append(high_idx[p])
    remove: set[int] = set()
    for members in buckets.values():
        if len(members) <= 1:
            continue
        base = groups[members[0]]
        for gi in members[1:]:
            other = groups[gi]
            base.events.extend(other.events)
            base.src_ips = sorted(set(base.src_ips) | set(other.src_ips))
            base.dst_ips = sorted(set(base.dst_ips) | set(other.dst_ips))
            base.triage_score = max(base.triage_score, other.triage_score)
            remove.add(gi)
    if remove:
        groups = [g for i, g in enumerate(groups) if i not in remove]
    return groups


# ---------- 节点 3.5：资产背景富化（RAG） ----------


def asset_enrich_node(state: AgentState) -> dict[str, Any]:
    """对每个事件组的局域网 IP 做混合检索，生成业务背景。"""
    groups = state.get("groups", [])
    contexts: dict[str, dict[str, Any]] = {}
    for g in groups:
        if g.excluded:
            continue  # 被排除的组不查业务背景（省检索），事件本身仍可在界面查看
        query = " ".join(e.log.summary for e in g.events[:10] if e.log.summary)
        try:
            ctx = build_business_context(g.src_ips, g.dst_ips, query)
        except Exception as exc:  # noqa: BLE001
            log.warning("资产背景检索失败 %s: %s", g.fingerprint, exc)
            ctx = {"lan_ips": [], "assets": [], "knowledge": [], "text": ""}
        contexts[g.fingerprint] = ctx
        g.business_context = ctx
    if contexts:
        save_business_context(contexts)
        log.info("资产背景富化：%d 个事件组", len(contexts))
    return {"business_context": contexts}


# ---------- 节点 3.6：历史记忆召回（比对 + 持续性） ----------


def _group_asset_ids(state: AgentState, fingerprint: str) -> list[str]:
    ctx = (state.get("business_context") or {}).get(fingerprint) or {}
    return [str(a["id"]) for a in (ctx.get("assets") or []) if a.get("id")]


def memory_recall_node(state: AgentState) -> dict[str, Any]:
    """按组召回历史记忆 + 持续性统计，写入 state.memory 与 event_groups.memory_hits。"""
    groups = state.get("groups", [])
    recalled: dict[str, dict[str, Any]] = {}
    for g in groups:
        if g.excluded:
            continue  # 被排除的组不查历史记忆（省一次检索）
        info = recall_memory(
            sorted(set(g.src_ips + g.dst_ips)),
            _group_asset_ids(state, g.fingerprint),
            g.fingerprint,
        )
        recalled[g.fingerprint] = info
        update_group_memory_hits(g.fingerprint, info)
    persistent = sum(1 for v in recalled.values() if (v.get("persistence") or {}).get("persistent"))
    log.info("历史记忆召回：%d 组，其中持续性 %d 组", len(recalled), persistent)
    return {"memory": recalled}


# ---------- 节点 3.65：账号/会话画像比对（跨窗口长期基线） ----------


def _profile_text_for_group(state: AgentState, fingerprint: str) -> str:
    info = ((state.get("profile") or {}).get("by_group") or {}).get(fingerprint)
    return profile_text(info)


def profile_recall_node(state: AgentState) -> dict[str, Any]:
    """对全窗口日志做账号/会话画像比对；异常按涉及 IP 归属到事件组。"""
    if not settings.profile_enabled:
        return {"profile": {"entities": [], "anomalies": [], "by_group": {}}}

    info = recall_entities(state.get("raw_logs", []))
    entities = info.get("entities") or []
    threshold = settings.profile_risk_threshold

    by_group: dict[str, dict[str, Any]] = {}
    for g in state.get("groups", []):
        if g.excluded:
            continue  # 画像异常只挂到正常组（排除组不展示、不落库）
        group_ips = set(g.src_ips + g.dst_ips)
        related = [e for e in entities if group_ips & set(e.get("src_ips") or [])]
        payload = {
            "entities": related,
            "anomalies": [e for e in related if e.get("risk", 0) >= threshold],
        }
        by_group[g.fingerprint] = payload
        update_group_profile_hits(g.fingerprint, payload)

    log.info(
        "账号/会话画像：异常 %d 条（高风险 %d）", len(entities), len(info.get("anomalies") or [])
    )
    return {"profile": {**info, "by_group": by_group}}


# ---------- 节点 3.66：技能路由 + 工具执行 ----------


def _build_tool_context(g: EventGroup) -> ToolContext:
    """从事件组聚合工具输入（IP / 文本 / URL / 域名 / 请求体）。"""
    src_ips = g.src_ips or []
    dst_ips = g.dst_ips or []
    all_ips = [ip for ip in src_ips + dst_ips if ip]
    external_ips = [ip for ip in all_ips if is_public_ip(ip)]
    parts: list[str] = []
    urls: list[str] = []
    domains: list[str] = []
    qs: list[str] = []
    bodies: list[str] = []
    for ev in g.events:
        lg = ev.log
        for text in (lg.summary, lg.uri_path, lg.query_string, lg.body):
            if text:
                parts.append(str(text))
        if lg.query_string:
            qs.append(str(lg.query_string))
        if lg.body:
            bodies.append(str(lg.body))
        if lg.uri_path:
            host = lg.dst_ip or lg.hostname
            if host:
                urls.append(f"http://{host}{lg.uri_path}")
        if lg.event_type == "dns_query" and lg.query:
            domains.append(str(lg.query))
    return ToolContext(
        src_ips=src_ips,
        dst_ips=dst_ips,
        external_ips=external_ips,
        text="\n".join(parts)[:20000],
        urls=urls[:20],
        domains=domains[:20],
        query_strings=qs[:10],
        bodies=bodies[:10],
    )


def skill_context_text(g: EventGroup, skill_context: dict[str, Any]) -> str:
    """把命中技能的 SOP + 工具结果拼成提示词文本（无命中则回「无专属技能」）。"""
    info = skill_context.get(g.fingerprint) or {}
    skills = info.get("skills") or []
    if not skills:
        return "（无专属技能）"
    tool_results = info.get("tool_results") or {}
    blocks: list[str] = []
    for s in skills:
        sop = (s.get("sop") or "").strip()[: settings.skill_sop_max_chars]
        block = [f"【技能：{s['name']}】", sop]
        for tool_name in s.get("tools") or []:
            result = tool_results.get(tool_name)
            if result:
                rendered = json.dumps(result, ensure_ascii=False, default=str)[:1500]
                block.append(f"[工具 {tool_name} 结果]\n{rendered}")
        blocks.append("\n".join(block))
    return "\n\n".join(blocks)


def skill_enrich_node(state: AgentState) -> dict[str, Any]:
    """按事件类型路由技能，确定性执行其工具，产出技能上下文。"""
    if not settings.skill_enabled:
        return {"skill_context": {}}
    groups = state.get("groups", [])
    if not groups:
        return {"skill_context": {}}
    with SessionLocal() as db:
        skills = get_enabled_skills(db)
    if not skills:
        return {"skill_context": {}}

    contexts: dict[str, dict[str, Any]] = {}
    for g in groups:
        if g.excluded:
            continue  # 被排除的组不走技能与工具（含情报查询/主动探测，最该省的部分）
        event_types = {ev.log.event_type for ev in g.events}
        matched = [s for s in skills if set(s["event_types"]) & event_types]
        matched = matched[: settings.skill_max_per_group]
        ctx = _build_tool_context(g)
        tool_results: dict[str, Any] = {}
        for skill in matched:
            for tool_name in skill["tools"]:
                if tool_name not in tool_results:
                    tool_results[tool_name] = execute(tool_name, ctx)
        payload = {
            "skills": [
                {
                    "name": s["name"],
                    "description": s["description"],
                    "sop": s["sop"],
                    "tools": s["tools"],
                }
                for s in matched
            ],
            "tool_results": tool_results,
        }
        contexts[g.fingerprint] = payload
        update_group_skill_hits(g.fingerprint, payload)

    hit = sum(1 for c in contexts.values() if c["skills"])
    log.info("技能路由：%d/%d 组命中技能", hit, len(contexts))
    return {"skill_context": contexts}


# ---------- 节点 3.7：回溯决策与历史行为（LLM 决定时长，后端封顶） ----------


def _decide_lookback(
    g: EventGroup, ctx: dict[str, Any], memory_info: dict[str, Any]
) -> dict[str, Any]:
    prompt = prompts.LOOKBACK_USER.format(
        group_summary=json.dumps(
            {
                "src_ips": g.src_ips,
                "dst_ips": g.dst_ips,
                "event_count": len(g.events),
                "triage_score": round(g.triage_score, 3),
                "hit_rules": sorted({e.hit_rule for e in g.events if e.hit_rule}),
                "event_types": sorted({e.log.event_type for e in g.events}),
            },
            ensure_ascii=False,
        ),
        business_context=str(ctx.get("text") or "（无）"),
        memory=memory_text(memory_info),
    )
    try:
        return flash_invoke_json(prompts.LOOKBACK_SYSTEM, prompt)
    except Exception as exc:  # noqa: BLE001
        log.warning("回溯决策失败，默认不回溯: %s", exc)
        return {"hours": 0, "reason": "回溯决策失败"}


def _rule_hit_events(
    raw_logs: list[tuple[str, dict[str, Any]]], ips: list[str]
) -> list[UnifiedLog]:
    """回溯阶段只跑规则引擎（不调边缘模型，控成本）。"""
    with SessionLocal() as db:
        rules = get_enabled_rules(db)
    ip_set = set(ips)
    out: list[UnifiedLog] = []
    for source, doc in raw_logs:
        norm = normalize(source, doc)
        if norm is None:
            continue
        if norm.src_ip not in ip_set and norm.dst_ip not in ip_set:
            continue
        hit = next((r for r in rules if match_rule(r, norm)), None)
        if hit is None:
            continue
        # 排除过滤同样作用于回溯：否则被排除的噪声会从“历史行为”里复活
        if exclusion.check_filter(
            norm,
            rule_name=str(hit.get("name") or ""),
            rule_source=str(hit.get("source") or ""),
            rule_severity=str(hit.get("severity") or ""),
        ):
            continue
        out.append(norm)
    out.sort(key=lambda x: x.ts)
    return out[: settings.lookback_max_events]


def _history_summary(
    start: datetime,
    end: datetime,
    events: list[UnifiedLog],
    fetched_total: int,
    notes: list[str],
) -> str:
    head = f"回溯窗口 {start:%Y-%m-%d %H:%M} ~ {end:%Y-%m-%d %H:%M}：拉取 {fetched_total} 条"
    if not events:
        return head + "，未发现命中规则的历史事件"
    types: dict[str, int] = {}
    for e in events:
        types[e.event_type] = types.get(e.event_type, 0) + 1
    dst_ips = {e.dst_ip for e in events if e.dst_ip}
    dst_ports = {e.dst_port for e in events if e.dst_port}
    lines = [
        head,
        f"命中规则事件 {len(events)} 条",
        "类型分布：" + "，".join(f"{k}×{v}" for k, v in sorted(types.items(), key=lambda x: -x[1])),
        f"首次 {events[0].ts:%Y-%m-%d %H:%M}，最近 {events[-1].ts:%Y-%m-%d %H:%M}",
        f"涉及目的 IP {len(dst_ips)} 个、目的端口 {len(dst_ports)} 个",
    ]
    if notes:
        lines.append("拉取说明：" + "；".join(notes[:3]))
    return "\n".join(lines)


def lookback_node(state: AgentState) -> dict[str, Any]:
    """对升级组：LLM 决定回溯时长 → 按网段拉取历史日志 → 规则筛事件 → 生成历史行为摘要。"""
    groups = [g for g in state.get("groups", []) if g.escalate]
    ctx_map = state.get("business_context") or {}
    mem_map = state.get("memory") or {}
    cidrs = (state.get("run_meta") or {}).get("scope_cidrs") or enabled_cidrs()

    results: dict[str, dict[str, Any]] = {}
    for g in groups:
        decision = _decide_lookback(
            g, ctx_map.get(g.fingerprint) or {}, mem_map.get(g.fingerprint) or {}
        )
        hours = _safe_int(_safe_float(decision.get("hours"), 0), 0)
        hours = max(0, min(hours, settings.lookback_max_days * 24))
        entry: dict[str, Any] = {
            "hours": hours,
            "reason": str(decision.get("reason") or ""),
            "log_count": 0,
            "event_count": 0,
            "summary": "",
        }
        if hours > 0 and cidrs:
            end = _now()
            start = end - timedelta(hours=hours)
            fetched = fetch_window_logs(start, end, cidrs, max_logs=settings.lookback_max_logs)
            events = _rule_hit_events(fetched.logs, sorted(set(g.src_ips + g.dst_ips)))
            entry["log_count"] = fetched.total
            entry["event_count"] = len(events)
            entry["summary"] = _history_summary(start, end, events, fetched.total, fetched.notes)
        else:
            entry["summary"] = "未回溯（LLM 判定无需回溯或未配置分析网段）"
        results[g.fingerprint] = entry
        update_group_lookback(g.fingerprint, entry)

    if results:
        log.info(
            "回溯决策：%d 组，实际回溯 %d 组",
            len(results),
            sum(1 for v in results.values() if v["hours"] > 0),
        )
    return {"lookback": results}


# ---------- 节点 4：云端深度分析（子图，见 deep_analysis.py） ----------

# ---------- 节点 5：定级 ----------


def _rule_severity(g: EventGroup) -> str:
    """组内命中规则的最高严重度（不含模型判断，可作回退与排除组定级）。"""
    out = "info"
    for ev in g.events:
        sev = ev.log.severity
        if sev in SEVERITY_RANK and SEVERITY_RANK[sev] > SEVERITY_RANK[out]:
            out = sev
    return out


def severity_node(state: AgentState) -> dict[str, Any]:
    groups = state.get("groups", [])
    analyses = state.get("analyses", {})
    for g in groups:
        rule_severity = _rule_severity(g)
        if g.excluded:
            # 被排除的组不调云端定级：按规则严重度落库即可（界面仍可查）
            update_group_analysis(g.fingerprint, severity=rule_severity)
            g.severity = rule_severity  # type: ignore[assignment]
            continue
        chain = (analyses.get(g.fingerprint) or {}).get("attack_chain", {})
        profile = (analyses.get(g.fingerprint) or {}).get("profile", {})
        context_text = context_text_for_group(
            g, state.get("business_context", {}).get(g.fingerprint)
        )
        memory_blob = memory_text((state.get("memory") or {}).get(g.fingerprint) or {})
        lookback_blob = str(
            ((state.get("lookback") or {}).get(g.fingerprint) or {}).get("summary") or "（无回溯）"
        )
        profile_blob = _profile_text_for_group(state, g.fingerprint)
        try:
            r = flash_invoke_json(
                prompts.SEVERITY_SYSTEM,
                prompts.SEVERITY_USER.format(
                    chain=json.dumps(chain, ensure_ascii=False, default=str),
                    profile=json.dumps(profile, ensure_ascii=False, default=str),
                    rule_severity=rule_severity,
                    business_context=context_text,
                    memory=memory_blob,
                    lookback=lookback_blob,
                    entity_profile=profile_blob,
                    skill=skill_context_text(g, state.get("skill_context") or {}),
                ),
            )
            severity = r.get("severity", rule_severity)
        except Exception as exc:  # noqa: BLE001
            log.warning("云端定级失败，回退规则定级: %s", exc)
            severity = rule_severity
        if severity not in SEVERITY_RANK:
            severity = rule_severity
        update_group_analysis(g.fingerprint, severity=severity)
        g.severity = severity  # type: ignore[assignment]
    return {"groups": groups}


# ---------- HITL 节点 ----------


def hitl_node(state: AgentState) -> dict[str, Any]:
    from langgraph.types import interrupt

    with SessionLocal() as db:
        enabled = bool(_config(db, "hitl_enabled", settings.hitl_enabled))
        min_sev = str(_config(db, "hitl_min_severity", settings.hitl_min_severity))

    groups = state.get("groups", [])
    pending = [
        g
        for g in groups
        if not g.excluded
        and (g.severity or "info") in SEVERITY_RANK
        and SEVERITY_RANK[g.severity or "info"] >= SEVERITY_RANK.get(min_sev, 3)
    ]

    if not enabled or not pending:
        return {}

    set_groups_pending([g.fingerprint for g in pending])
    decision = interrupt(
        {
            "message": "存在高危事件，等待人工确认",
            "pending": [
                {
                    "fingerprint": g.fingerprint,
                    "severity": g.severity,
                    "src_ips": g.src_ips,
                    "dst_ips": g.dst_ips,
                }
                for g in pending
            ],
        }
    )
    confirmations = decision.get("confirmations", {}) if isinstance(decision, dict) else {}
    return {"confirmations": confirmations}


# ---------- 节点 6：处置建议 ----------


def response_node(state: AgentState) -> dict[str, Any]:
    groups = state.get("groups", [])
    analyses = state.get("analyses", {})
    confirmations = state.get("confirmations", {})
    for g in groups:
        if g.excluded:
            continue  # 被排除的组不等人工确认、不做处置建议
        if confirmations.get(g.fingerprint) == "dismiss":
            update_group_analysis(g.fingerprint, status="dismissed")
            continue
        chain = (analyses.get(g.fingerprint) or {}).get("attack_chain", {})
        profile = (analyses.get(g.fingerprint) or {}).get("profile", {})
        context_text = context_text_for_group(
            g, state.get("business_context", {}).get(g.fingerprint)
        )
        try:
            r = flash_invoke_json(
                prompts.RESPONSE_SYSTEM,
                prompts.RESPONSE_USER.format(
                    severity=g.severity,
                    chain=json.dumps(chain, ensure_ascii=False, default=str),
                    profile=json.dumps(profile, ensure_ascii=False, default=str),
                    business_context=context_text,
                    skill=skill_context_text(g, state.get("skill_context") or {}),
                ),
            )
            suggestions = r.get("suggestions", [])
        except Exception as exc:  # noqa: BLE001
            log.warning("处置建议生成失败: %s", exc)
            suggestions = [
                {"category": "incident_response", "action": "人工复核", "detail": "模型不可用"}
            ]
        update_group_analysis(g.fingerprint, response_suggestions=suggestions)
    return {}


# ---------- 节点 7：报告输出 ----------


def _report_body(g: Any, analysis: dict[str, Any]) -> str:
    """用 flash 生成报告正文；失败返回空串（不阻断报告生成）。"""
    try:
        overview = {
            "src_ips": g.src_ips,
            "dst_ips": g.dst_ips,
            "severity": g.severity,
            "event_count": len(g.events),
            "window_start": g.window_start.isoformat() if g.window_start else None,
            "window_end": g.window_end.isoformat() if g.window_end else None,
        }
        return flash_invoke_text(
            prompts.REPORT_SYSTEM,
            prompts.REPORT_USER.format(
                overview=json.dumps(overview, ensure_ascii=False, default=str),
                chain=json.dumps(analysis.get("attack_chain", {}), ensure_ascii=False, default=str),
                profile=json.dumps(analysis.get("profile", {}), ensure_ascii=False, default=str),
                suggestions=json.dumps(
                    g.response_suggestions or [], ensure_ascii=False, default=str
                ),
            ),
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("报告正文生成失败（不影响报告输出）: %s", exc)
        return ""


def report_node(state: AgentState) -> dict[str, Any]:
    from app.reports.render import render_report

    groups = state.get("groups", [])
    analyses = state.get("analyses", {})
    confirmations = state.get("confirmations", {})
    with SessionLocal() as db:
        min_sev = str(_config(db, "report_min_severity", settings.report_min_severity))

    summary = {"total_groups": len(groups), "reports": 0}
    for g in groups:
        if g.excluded:
            continue  # 被排除的组不出报告（不出报告也就不调报告模型）
        if confirmations.get(g.fingerprint) == "dismiss":
            continue
        sev = g.severity or "info"
        if SEVERITY_RANK.get(sev, 0) < SEVERITY_RANK.get(min_sev, 2):
            continue
        analysis = analyses.get(g.fingerprint) or {}
        try:
            body = _report_body(g, analysis)
            html, pdf_path = render_report(g, analysis, body)
            save_report(g.fingerprint, f"安全事件报告 - {sev}", sev, html, pdf_path)
            summary["reports"] += 1
        except Exception as exc:  # noqa: BLE001
            log.warning("报告生成失败 %s: %s", g.fingerprint, exc)

    log.info("报告输出：%s", summary)
    return {"run_summary": summary}


# ---------- 节点 8：分析记忆写入 ----------


def _group_memory_summary(
    g: EventGroup, analysis: dict[str, Any], persistence: dict[str, Any]
) -> str:
    chain = analysis.get("attack_chain") or {}
    stages = "→".join(str(s.get("stage", "")) for s in (chain.get("stages") or []))
    parts = [f"定级 {g.severity or 'info'}"]
    if stages:
        parts.append(f"攻击链 {stages}")
    if chain.get("summary"):
        parts.append(str(chain["summary"])[:120])
    if persistence.get("persistent"):
        parts.append(
            f"持续性（{persistence.get('window_days')}天内 {persistence.get('count')} 次）"
        )
    parts.append(f"涉及 IP {len(set(g.src_ips + g.dst_ips))} 个")
    return "；".join(parts)


def _run_memory_summary(state: AgentState) -> str:
    meta = state.get("run_meta") or {}
    if meta.get("skipped") == "no_scope":
        return "本轮跳过：" + "；".join(meta.get("notes") or ["未配置分析网段"])
    reports = (state.get("run_summary") or {}).get("reports", 0)
    return (
        f"窗口拉取 {meta.get('fetched_raw', 0)} 条（{meta.get('fetch_mode')}），"
        f"去重 {len(state.get('raw_logs') or [])} 条，"
        f"可疑事件 {len(state.get('suspicious_events') or [])} 条，"
        f"事件组 {len(state.get('groups') or [])} 个，报告 {reports} 份"
    )


def memory_write_node(state: AgentState) -> dict[str, Any]:
    """写入对象级 + 轮次级分析记忆，并机会式清理过期记忆。"""
    groups = state.get("groups", [])
    analyses = state.get("analyses") or {}
    mem_map = state.get("memory") or {}
    look_map = state.get("lookback") or {}

    for g in groups:
        if g.excluded:
            continue  # 被排除的噪声不进分析记忆（否则污染后续研判）
        analysis = analyses.get(g.fingerprint) or {}
        persistence = (mem_map.get(g.fingerprint) or {}).get("persistence") or {}
        write_group(
            fingerprint=g.fingerprint,
            window_start=g.window_start,
            window_end=g.window_end,
            ips=sorted(set(g.src_ips + g.dst_ips)),
            asset_ids=_group_asset_ids(state, g.fingerprint),
            severity=g.severity,
            summary=_group_memory_summary(g, analysis, persistence),
            detail={
                "attack_chain": analysis.get("attack_chain"),
                "lookback": look_map.get(g.fingerprint),
                "persistent": bool(persistence.get("persistent")),
            },
        )

    write_run(
        thread_id=state.get("thread_id", ""),
        window_start=state.get("window_start"),
        window_end=state.get("window_end"),
        ips=sorted({ip for g in groups for ip in (g.src_ips + g.dst_ips)})[:500],
        summary=_run_memory_summary(state),
        detail={
            "run_meta": state.get("run_meta") or {},
            "groups": len(groups),
            "reports": (state.get("run_summary") or {}).get("reports", 0),
        },
    )
    deleted = memory_cleanup()
    log.info(
        "分析记忆写入：对象 %d 条；清理 run=%d group=%d",
        len(groups),
        deleted["run"],
        deleted["group"],
    )
    return {}


# ---------- 节点 9：账号/会话画像基线更新 ----------


def profile_update_node(state: AgentState) -> dict[str, Any]:
    """用本窗口观测增量更新画像基线，回写异常风险分，并清理长期无观测画像。"""
    if not settings.profile_enabled:
        return {}
    observations = window_observations(state.get("raw_logs", []))
    # 把 profile_recall 算出的异常风险一并回写，驾驶舱 TOP / 排序才会生效
    info = state.get("profile") or {}
    risks = {f"{e.get('kind')}|{e.get('key')}": e for e in (info.get("entities") or [])}
    result = update_profiles(observations, risks)
    deleted = profile_cleanup()
    log.info(
        "画像基线更新：实体 %d（新增 %d / 更新 %d）；清理过期 %d",
        len(observations),
        result["created"],
        result["updated"],
        deleted["deleted"],
    )
    return {}


# ---------- 条件路由 ----------


def escalate_route(state: AgentState) -> str:
    groups = state.get("groups", [])
    return "deep" if any(g.escalate for g in groups) else "skip"


def hitl_route(state: AgentState) -> str:
    from langgraph.types import interrupt  # noqa: F401  (仅占位说明)

    with SessionLocal() as db:
        enabled = bool(_config(db, "hitl_enabled", settings.hitl_enabled))
    if not enabled:
        return "pass"
    groups = state.get("groups", [])
    with SessionLocal() as db:
        min_sev = str(_config(db, "hitl_min_severity", settings.hitl_min_severity))
    for g in groups:
        sev = g.severity or "info"
        if g.excluded:
            continue  # 被排除的组不触发人工确认
        if SEVERITY_RANK.get(sev, 0) >= SEVERITY_RANK.get(min_sev, 3):
            return "confirm"
    return "pass"
