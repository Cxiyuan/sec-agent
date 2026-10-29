"""客观线索队列：入队（去重/容量/合并）、原子领取（不设额度/并发上限）、结论回收。

三个不可妥协的点：

1. **不静默丢**：队列满时要么与同族合并计数（`merged`）、要么按强度替换（`superseded`）、
   要么计数后丢弃（`dropped_overflow`）—— 三个数都进 Redis 统计，界面能看见；
2. **NDR 不限制领取额度或并发**：领取多少、多久领一次由智能体自己决定；
3. **领取必须原子**：多令牌/多次长轮询同时抢同一任务会重复分析。用 PG
   `SELECT ... FOR UPDATE SKIP LOCKED` + 同事务改状态，抢不到的自动跳过而不是等待。
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError

from app.analysis import anchors as anchors_mod, digests as digests_mod, feedback, params
from app.analysis.verdicts import VERDICT_VALUES, clean_terminal_reason, clean_verdict
from app.db.base import SessionLocal
from app.db.models import (
    AnalysisResult,
    AnalysisTask,
    ConclusionRecord,
    EgressAllow,
    HitEvent,
    Observation,
)
from app.workers.log import get_logger

#: 等价于 3.11 的 `datetime.UTC`（本仓库 requires-python >=3.11）；用别名写法
#: 免得按旧语法解析的静态检查工具报「unknown import symbol」。
UTC = timezone.utc

log = get_logger(__name__)

STATS_KEY = "shentong:analysis:stats"
# 保持旧 Redis 键名，让已有的门铃状态自然过期；此处只存队列水位和门铃去抖标记。
_DOORBELL_PREFIX = "shentong:analysis:claim"
_STATE_COUNTER = {
    "pending": "enqueued",
    "deferred": "deferred",
    "claimed": "claimed",
    "done": "done",
    "stuck": "stuck",
    "expired": "expired",
}


def dedupe_key(
    kind: str, subject_kind: str, subject: str, feature: str, now: datetime | None = None
) -> str:
    """去重键：同现象 + 同时间桶只有一条（桶宽按类型分，避免"每窗口一条"刷满队列）。

    `hit`/`shift`/`structure` 按 `analysis.dedupe_bucket_minutes`（默认 60 分钟）、
    `coverage` 按天（盲区一天提醒一次足够）。

    **`novelty` 不带时间桶**（一次性事件）："这个对象是新面孔"这件事只发生一次，
    不该每个小时再派一遍工 —— 线上就是这么把队列灌满的（同一个资产每小时一条，
    几千个资产轮着来，真正该看的规则命中被挤在后面）。
    同一个现象后来的出现只累加 `coalesced` 计数；现象变强时 `enqueue` 会把它重新排队。
    """
    if kind == "novelty":
        return f"{kind}|{subject_kind}:{subject}|{feature or '-'}|once"
    ts = now or datetime.now(UTC)
    # 盲区一天提醒一次就够；其余按 `analysis.dedupe_bucket_minutes`（默认 60 分钟）
    bucket_minutes = 1440 if kind == "coverage" else max(5, params.dedupe_bucket_minutes())
    floor = ts.replace(minute=0, second=0, microsecond=0)
    if bucket_minutes >= 1440:
        floor = floor.replace(hour=0)
    index = int((ts - floor).total_seconds() // (60 * bucket_minutes))
    return f"{kind}|{subject_kind}:{subject}|{feature or '-'}|{floor:%Y%m%d%H}#{index}"


# ---------- 统计（Redis，跨重启可查；写失败只 debug，不影响主流程） ----------


def bump(client: Any, field: str, count: int = 1) -> None:
    if client is None or count <= 0:
        return
    try:
        client.hincrby(STATS_KEY, field, count)
    except Exception as exc:  # noqa: BLE001
        log.debug("写分析统计失败: %s", exc)


def read_stats(client: Any) -> dict[str, int]:
    if client is None:
        return {}
    try:
        raw = client.hgetall(STATS_KEY) or {}
    except Exception as exc:  # noqa: BLE001
        log.debug("读分析统计失败: %s", exc)
        return {}
    out: dict[str, int] = {}
    for key, value in raw.items():
        name = key.decode() if isinstance(key, bytes) else str(key)
        try:
            out[name] = int(value)
        except (TypeError, ValueError):
            out[name] = 0
    return out


# ---------- 入队 ----------


def enqueue(
    *,
    kind: str,
    subject_kind: str,
    subject: str,
    strength: float,
    hint: dict[str, Any] | None = None,
    feature: str = "",
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    parent_id: str = "",
    depth: int = 0,
    client: Any = None,
    force: bool = False,
) -> str:
    """线索入队。返回状态串（`new` / `merged` / `superseded` / `dropped` / `skipped` / `error`）。

    满了怎么办：新线索强度**高于**队列里最低强度的 pending 就把那条挤出去（标 `expired`
    + `superseded` 计数），否则合并到同族或计数丢弃 —— 三条路都留痕。

    `force=True` = 不受 `analysis.candidate_kinds` 开关约束。给**运维类待办**用
    （例如"你之前提交的抑制没生效，请收窄后重提"）—— 那不是检测线索，
    不该被"生成哪些线索"的旋钮关掉。
    """
    if not params.enabled() or (not force and kind not in params.candidate_kinds()):
        return "skipped"
    try:
        strength = max(0.0, min(1.0, float(strength)))
    except (TypeError, ValueError):
        strength = 0.0  # 脏强度按最低处理（宁可排后面，也不要抛异常丢掉线索）
    key = dedupe_key(kind, subject_kind, subject, feature)
    now = datetime.now(UTC)
    try:
        with SessionLocal() as db:
            existing = db.scalars(
                select(AnalysisTask).where(AnalysisTask.dedupe_key == key)
            ).first()
            if existing is not None:
                # 同族合并：不新增行，累加计数并把强度抬到两者较大者（现象变强要能升级）
                existing.coalesced = int(existing.coalesced or 0) + 1
                if strength > float(existing.strength or 0):
                    existing.strength = strength
                    existing.priority = round(strength * 100)
                    # 过期的同族线索被更强的现象"复活"，重新排队
                    if existing.state in ("expired", "done"):
                        existing.state = "pending"
                        existing.note = "同现象再次出现，已重新排队"
                elif kind == "novelty" and existing.state == "expired":
                    # 一次性现象（首见）被挤出队列（容量挤掉/超期）时，只要它还在
                    # 新面孔窗口内就重新排一次 —— 否则这个对象就再也不会被看了。
                    # 能走到这里说明它已经跨窗口反复出现（调用方过滤过一次性对象）。
                    existing.state = "pending"
                    existing.note = "同现象再次出现，已重新排队"
                existing.updated_at = now
                db.commit()
                bump(client, "merged")
                return "merged"

            pending = int(
                db.scalar(
                    select(func.count())
                    .select_from(AnalysisTask)
                    .where(AnalysisTask.state.in_(("pending", "deferred")))
                )
                or 0
            )
            if pending >= params.queue_capacity():
                weakest = db.scalars(
                    select(AnalysisTask)
                    .where(AnalysisTask.state == "pending")
                    .order_by(AnalysisTask.priority.asc(), AnalysisTask.created_at.asc())
                    .limit(1)
                ).first()
                if weakest is None or float(weakest.strength or 0) >= strength:
                    bump(client, "dropped_overflow")
                    return "dropped"
                weakest.state = "expired"
                weakest.note = f"被更强线索挤掉（{kind}/{subject}）"
                bump(client, "superseded")

            row = AnalysisTask(
                dedupe_key=key,
                kind=kind,
                strength=strength,
                priority=round(strength * 100),
                subject_kind=subject_kind,
                subject=subject,
                window_start=window_start,
                window_end=window_end,
                hint=hint or {},
                state="pending",
                parent_id=parent_id,
                depth=depth,
            )
            db.add(row)
            try:
                db.commit()
            except IntegrityError:
                # 并发下同一 dedupe_key 同时入队：唯一约束兜底，本条按"已合并"处理
                db.rollback()
                bump(client, "merged")
                return "merged"
            db.refresh(row)
            bump(client, "enqueued")
            return "new"
    except Exception as exc:  # noqa: BLE001 — 生成线索失败绝不能影响检测
        log.warning("线索入队失败（%s/%s）：%s", kind, subject, exc)
        bump(client, "candidate_error")
        return "error"


# ---------- 领取（原子，不限制额度/并发） ----------


def _pick(
    db: Any, want: int, *, min_strength: float, cap: float, kinds: set[str]
) -> list[AnalysisTask]:
    """按优先级取一批可领取任务（`SKIP LOCKED` 保证并发下不重复领取）。"""
    if want <= 0:
        return []
    now = datetime.now(UTC)
    conds: list[Any] = [
        or_(
            # 待派工的随时可领。
            AnalysisTask.state == "pending",
            # **延后到期才可领**：`defer_task` 写的「下次可领时间」必须真的算数。
            # 以前这里把 deferred 与 pending 一视同仁，延后形同虚设：同一条线索
            # 被领走→没交回→延后→立刻又被领走，反复重跑，白烧模型调用。
            (AnalysisTask.state == "deferred")
            & or_(AnalysisTask.lease_until.is_(None), AnalysisTask.lease_until <= now),
            # 领了没交回的：租约过期才回收（次数超限判 stuck 在 sweep 里）。
            (AnalysisTask.state == "claimed") & (AnalysisTask.lease_until < now),
        ),
        AnalysisTask.strength >= min_strength,
        AnalysisTask.strength < cap,
    ]
    if kinds:
        conds.append(AnalysisTask.kind.in_(sorted(kinds)))
    stmt = (
        select(AnalysisTask)
        .where(*conds)
        # 公平：等待越久越容易被捞起，加成封顶 20 分（与强度同一量纲，100 分制）。
        # 没有它，队列会被"几分钟前的高分线索"长期占住，冷门对象永远等不到。
        .order_by(
            (
                AnalysisTask.priority
                + func.least(
                    func.extract("epoch", func.now() - AnalysisTask.created_at) / 3600.0 * 2.0,
                    20.0,
                )
            ).desc(),
            AnalysisTask.created_at.asc(),
        )
        .limit(want)
        .with_for_update(skip_locked=True)
    )
    return list(db.scalars(stmt).all())


def claim_tasks(
    client: Any,
    *,
    token: str,
    limit: int = 0,
    kinds: set[str] | None = None,
    min_strength: float = 0.0,
) -> dict[str, Any]:
    """原子领取请求数量的任务；不按令牌、小时或并发数限制领取。"""
    want = max(1, min(int(limit or 1), 20))
    picked_kinds = set(kinds or ()) & set(params.KINDS)
    now = datetime.now(UTC)
    lease = timedelta(seconds=params.lease_seconds())
    taken: list[AnalysisTask] = []
    try:
        with SessionLocal() as db:
            taken = _pick(
                db,
                want,
                min_strength=min_strength,
                cap=1.01,
                kinds=picked_kinds,
            )
            if not taken:
                db.rollback()
                return {"tasks": [], "reason": "queue_empty"}
            ids = [str(t.id) for t in taken]
            db.execute(
                update(AnalysisTask)
                .where(AnalysisTask.id.in_(ids))
                .values(
                    state="claimed",
                    claimed_by=token[:64],
                    lease_until=now + lease,
                    attempts=AnalysisTask.attempts + 1,
                    updated_at=now,
                )
            )
            db.commit()
            # 回执在会话内拍平：commit 后 ORM 属性过期，会话内访问会自动刷新，
            # 但出了 with 块就是 detached 实例，一访问就崩（线上 claim_tasks
            # 每领必抛 "Instance not bound to a Session"、闭环整条挂掉，就是这里）。
            out = [_task_dict(t, claimed=True) for t in taken]
    except Exception as exc:  # noqa: BLE001
        log.warning("领取任务失败：%s", exc)
        return {"error": f"领取失败：{str(exc)[:160]}"}

    bump(client, "claimed", len(taken))

    return {"tasks": out, "watermark": now.isoformat(), "scope": _scope_payload()}


def _scope_payload() -> dict[str, Any]:
    """监控网段（C3，2026-10-29）：任务主体是"监控网段内资产"，agent 必须有坐标系。

    未配置时明确说明内网判定退化成"非公网即内网"（Zeek 侧不过滤）——
    不能假装网段已配置，否则 agent 会把未监控私网当成自己的资产。
    """
    try:
        from app.ingestion import scope as scope_mod

        nets = [str(x) for x in (scope_mod.monitored_nets() or [])][:200]
    except Exception:  # noqa: BLE001 — 读不到网段按"未配置"如实说明
        nets = []
    return {
        "configured": bool(nets),
        "monitored_nets": nets,
        "note": (
            "分析对象以监控网段内的 IP 资产为主；外部 IP 只作为对端/线索。"
            if nets
            else "未配置监控网段：内网判定退化为「非公网即内网」，Zeek 侧也不按网段过滤，内外方向结论要打折"
        ),
    }


# ---------- 交回 / 延后 ----------


def _event_id_of(task: AnalysisTask) -> str:
    """任务对应的**命中事件 ID**（hint 里带的；只有 hit 线索有）。"""
    hint = task.hint if isinstance(task.hint, dict) else {}
    return str(hint.get("事件ID") or hint.get("event_id") or "").strip()[:64]


def _mirror_event_conclusion(
    db: Any,
    task: AnalysisTask,
    *,
    event_id: str,
    verdict: str,
    summary: str,
    findings: dict[str, Any] | None,
    confidence: float,
    terminal_reason: str,
) -> bool:
    """任务级结论 → **事件级结论镜像**（事件列表的 `agent_*` 字段靠它）。

    为什么需要：智能体只调 `complete_task`（analyst 档没有 `record_conclusion`），
    而事件列表按事件 ID 读结论（`conclusion_records.dedup_key = hit_events.id`）。
    没有这份镜像，界面上永远看不到"这条事件智能体已经判过了" —— 判定权转移只落在
    任务队列里，事件列表还是空的。

    失败只告警，不影响任务完成（交回是硬要求，镜像是展示）。
    """
    if event_id == "" or summary.strip() == "":
        return False
    try:
        now = datetime.now(UTC)
        rec = db.execute(
            select(ConclusionRecord).where(ConclusionRecord.dedup_key == event_id)
        ).scalar_one_or_none()
        if rec is None:
            rec = ConclusionRecord(dedup_key=event_id, created_at=now)
            db.add(rec)
        detail: dict[str, Any] = dict(findings or {}) if isinstance(findings, dict) else {}
        detail.update(
            {
                "task_id": str(task.id),
                "confidence": max(0.0, min(1.0, float(confidence or 0))),
                "terminal_reason": str(terminal_reason or ""),
            }
        )
        rec.event_id = event_id
        rec.status = str(verdict or "")[:32]
        # 任务级结论没有"严重度"这一维（智能体不编严重度）：留空，界面回退看结论态
        rec.severity = ""
        rec.summary = str(summary)[:4000]
        rec.detail = detail
        rec.updated_at = now
        db.commit()
        return True
    except Exception as exc:  # noqa: BLE001 — 镜像失败不能影响任务交回
        db.rollback()
        log.warning("写事件级结论镜像失败（任务 %s / 事件 %s）：%s", task.id, event_id, exc)
        return False


def complete_task(
    client: Any,
    task_id: str,
    *,
    verdict: str,
    summary: str = "",
    confidence: float = 0.0,
    findings: dict[str, Any] | None = None,
    evidence_refs: list[str] | None = None,
    tools_used: int = 0,
    duration_ms: int = 0,
    terminal_reason: str = "",
    anchors: list[dict[str, Any]] | None = None,
    token: str = "",
) -> dict[str, Any]:
    """交回结论：写 `analysis_results` 并把任务置 `done`。

    `anchors` 把结论挂到具体资产上（多对多）：一条"这台是反向代理"的结论
    必须能影响它后面的那些后端，否则下次分析还得从头查。

    `terminal_reason` 记"这次是怎么结束的"：`inconclusive` 到底是"查了没证据"
    还是"预算用光根本没查完"，处置方式完全不同（调线索 vs 调预算）。
    """
    # 校验全部前置（fail-closed 且在任何 I/O 之前）：脏值不允许写进库，
    # 否则统计会悄悄失真，而且事后无法区分是模型写错还是系统记错。
    normalized, verdict_error = clean_verdict(verdict)
    if verdict_error:
        return {"error": verdict_error, "field": "verdict"}
    verdict = normalized
    reason, reason_error = clean_terminal_reason(terminal_reason)
    if reason_error:
        return {"error": reason_error, "field": "terminal_reason"}
    anchor_pairs, anchor_errors = anchors_mod.clean_anchors(anchors)
    if anchor_errors:
        return {"error": "；".join(anchor_errors[:5]), "field": "anchors", "field_errors": anchor_errors}
    with SessionLocal() as db:
        row = db.get(AnalysisTask, str(task_id or "").strip())
        if row is None:
            return {"error": "任务不存在"}
        now = datetime.now(UTC)
        db.add(
            AnalysisResult(
                task_id=str(row.id),
                kind=row.kind,
                subject_kind=row.subject_kind,
                subject=row.subject,
                verdict=verdict,
                confidence=max(0.0, min(1.0, float(confidence or 0))),
                summary=str(summary or "")[:4000],
                findings=findings or {},
                evidence_refs=[str(x)[:200] for x in (evidence_refs or [])][:20],
                tools_used=max(0, int(tools_used or 0)),
                duration_ms=max(0, int(duration_ms or 0)),
                terminal_reason=reason,
                claimed_by=(token or row.claimed_by or "")[:64],
            )
        )
        db.flush()  # 先拿到新结论行的主键，锚点要挂在它上面
        result_row = db.scalars(
            select(AnalysisResult).order_by(AnalysisResult.created_at.desc()).limit(1)
        ).first()
        anchored = 0
        if result_row is not None and anchor_pairs:
            anchored = anchors_mod.write_anchors(
                db,
                result_id=str(result_row.id),
                task_id=str(row.id),
                pairs=anchor_pairs,
            )
        event_id = _event_id_of(row)
        row.state = "done"
        row.lease_until = None
        row.updated_at = now
        # 分析过要记账：覆盖率与 staleness 分量都靠它。
        # **轻量初筛关单不算**（2026-10-29 架构整改 A3）：2B 小模型只看 hint 没有真取证，
        # 它关单 ≤ 覆盖率就会虚高（把"其实没看"记成"看过了"），还会压低 staleness 派工分量。
        # 结论仍完整留档（findings.triaged_by=light 在控制台可见、抽检可比对），只是不记账。
        if str((findings or {}).get("triaged_by") or "") != "light":
            _mark_analyzed(db, row.subject_kind, row.subject, now)
        else:
            bump(client, "light_triaged")
        db.commit()
        # 事件级结论镜像：命中线索关联到具体事件时同步写一份（失败不影响交回）
        _mirror_event_conclusion(
            db,
            row,
            event_id=event_id,
            verdict=verdict,
            summary=str(summary or ""),
            findings=findings,
            confidence=float(confidence or 0),
            terminal_reason=reason,
        )
        db.refresh(row)
        bump(client, "done")
        # 提交后 ORM 属性会过期，要在这里就把后面要用的三个值取出来
        done_id = str(row.id)
        task_kind = str(row.kind or "")
        task_subject = str(row.subject or "")
    # 反馈学习（会话已关，不占事务）：
    # - 新分析结论一进库就作废系数缓存；真阳性会触发误抑制回弹；
    # - 复用结论只是把旧判断写到新任务作审计，**不是新证据**，不能再次训练反馈，
    #   尤其不能因为复用旧 true_positive 就误撤一条后来新增的抑制。
    reused_from = str((findings or {}).get("reused_from") or "").strip()
    light_triaged = str((findings or {}).get("triaged_by") or "") == "light"
    rebound = 0
    if not reused_from and not light_triaged:
        # 初筛关单同理：2B 小模型只看 hint，它的 benign/false_positive 不是取证结论，
        # 不许拿来训练反馈系数（否则一次初筛误判就会机床化后续的派工强度）。
        rebound = int(feedback.note_verdict(task_kind, task_subject, verdict).get("rebound") or 0)
    if rebound:
        bump(client, "suppression_rebound", rebound)
    return {
        "ok": True,
        "task_id": done_id,
        "task_state": "done",
        "verdict": verdict,
        "terminal_reason": reason,
        "anchors": anchored,
        "suppression_rebound": rebound,
    }


# 词表唯一来源是 `analysis.verdicts`（与 record_conclusion 共用，中文别名同样接受）
VERDICTS = VERDICT_VALUES


def defer_task(
    client: Any, task_id: str, *, reason: str = "", retry_after_seconds: int = 3600, token: str = ""
) -> dict[str, Any]:
    """延后重排（数据还没入齐、或现在不想深挖）。不算失败，但必须释放租约。"""
    delay = max(60, min(int(retry_after_seconds or 3600), 7 * 24 * 3600))
    with SessionLocal() as db:
        row = db.get(AnalysisTask, str(task_id or "").strip())
        if row is None:
            return {"error": "任务不存在"}
        now = datetime.now(UTC)
        row.state = "deferred"
        row.lease_until = now + timedelta(seconds=delay)  # 到期前不再可领
        row.note = str(reason or "")[:200]
        row.updated_at = now
        if token:
            row.claimed_by = token[:64]
        db.commit()
        bump(client, "deferred")
        return {"ok": True, "state": row.state, "next_due_at": row.lease_until.isoformat()}


# ---------- 清理与统计 ----------


def sweep(client: Any) -> dict[str, int]:
    """回收：过租约未交回的重新排队（超次数则 stuck）、过老的 pending 置 expired。"""
    now = datetime.now(UTC)
    stuck_after = params.stuck_after_attempts()
    expired = 0
    reclaimed = 0
    stuck = 0
    with SessionLocal() as db:
        stale = db.scalars(
            select(AnalysisTask).where(
                AnalysisTask.state == "claimed",
                AnalysisTask.lease_until.is_not(None),
                AnalysisTask.lease_until < now,
            )
        ).all()
        for row in stale:
            if int(row.attempts or 0) >= stuck_after:
                row.state = "stuck"
                row.note = f"连续 {row.attempts} 次领取未交回结论，已停止派发"
                row.lease_until = None
                stuck += 1
            else:
                row.state = "pending"
                row.note = "租约到期自动回收"
                row.lease_until = None
                reclaimed += 1
        # 首见线索单独一条更短的 TTL：它的价值随时间快速衰减（"这台机器上周是新的"
        # 对今天的判断没有意义），而且历史积压会把 observation/hit 饿死。
        novelty_cutoff = now - timedelta(hours=12)
        novelty_result = db.execute(
            update(AnalysisTask)
            .where(
                AnalysisTask.kind == "novelty",
                AnalysisTask.state.in_(("pending", "deferred")),
                AnalysisTask.created_at < novelty_cutoff,
            )
            .values(state="expired", note="首见线索超过 12 小时未分析，已过期", updated_at=now)
        )
        expired += int(getattr(novelty_result, "rowcount", 0) or 0)
        cutoff = now - timedelta(hours=params.pending_ttl_hours())
        result = db.execute(
            update(AnalysisTask)
            .where(
                AnalysisTask.state.in_(("pending", "deferred")),
                AnalysisTask.created_at < cutoff,
            )
            .values(state="expired", note="超过有效期未领取", updated_at=now)
        )
        expired += int(getattr(result, "rowcount", 0) or 0)
        db.commit()
    bump(client, "expired", expired)
    bump(client, "reclaimed", reclaimed)
    bump(client, "stuck", stuck)
    return {"expired": expired, "reclaimed": reclaimed, "stuck": stuck}


def _task_dict(row: AnalysisTask, *, claimed: bool = False) -> dict[str, Any]:
    hint = dict(row.hint or {})
    # C2（2026-10-29）：任务主体统一成「监控网段内资产」视角 —— 把主体/受影响资产/对端
    # 提成任务的一等字段，界面与智能体不用再从中文 hint 里各猜一套。
    principal_hint = hint.get("主体资产")
    principal = str(principal_hint.get("value") or "") if isinstance(principal_hint, dict) else ""
    affected_raw = hint.get("受影响资产") or []
    affected = [
        {"kind": str(x.get("kind") or ""), "value": str(x.get("value") or "")}
        for x in (affected_raw if isinstance(affected_raw, list) else [])
        if isinstance(x, dict) and str(x.get("value") or "").strip()
    ][:20]
    peers_raw = hint.get("对端") or []
    peers = [str(x) for x in (peers_raw if isinstance(peers_raw, list) else [])][:20]
    return {
        "id": str(row.id),
        "kind": row.kind,
        "strength": round(float(row.strength or 0), 3),
        "priority": int(row.priority or 0),
        "subject_kind": row.subject_kind,
        "subject": row.subject,
        # 主体资产（监控网段内）；缺省时就是任务主体本身（observation/coverage 已是资产视角）
        "principal_asset": principal or str(row.subject or ""),
        "affected_assets": affected,
        "direction": str(hint.get("方向") or ""),
        "peers": peers,
        # 现象特征（命中=规则名、偏移=指标名……）：智能体侧的同类结论复用靠它
        # 区分"同一台机器上的不同规则"，不参与任何判定。
        "feature": _feature_of(
            row.dedupe_key, row.kind, row.subject_kind, row.subject
        ),
        "window_start": row.window_start.isoformat() if row.window_start else "",
        "window_end": row.window_end.isoformat() if row.window_end else "",
        "hint": hint,
        "coalesced": int(row.coalesced or 0),
        "attempts": int(row.attempts or 0),
        "depth": int(row.depth or 0),
        "parent_id": row.parent_id or "",
        "state": row.state,
        "lease_until": row.lease_until.isoformat() if (claimed and row.lease_until) else "",
        "created_at": row.created_at.isoformat() if row.created_at else "",
    }


def _feature_of(dedupe_key: str, kind: str, subject_kind: str, subject: str) -> str:
    """从去重键里取出现象特征：`kind|subject_kind:subject|feature|时间桶`。

    按任务字段匹配前缀，再从右侧拆掉时间桶；这样 feature 可含 `|`，subject
    也不靠固定下标解析。形状不符（老数据/手写行）时返回空串，智能体会跳过复用。
    """
    key = str(dedupe_key or "")
    prefix = f"{kind}|{subject_kind}:{subject}|"
    if not key.startswith(prefix):
        return ""
    feature, separator, bucket = key[len(prefix):].rpartition("|")
    if not separator or "#" not in bucket:
        return ""
    return "" if feature == "-" else feature


def _mark_analyzed(db: Any, subject_kind: str, subject: str, now: datetime) -> None:
    """把"这个对象被分析过"记进 observed_subjects（覆盖率与 staleness 的数据源）。"""
    from app.analysis.subjects import mark_analyzed

    mark_analyzed(db, subject_kind, subject, now)


def stats(client: Any) -> dict[str, Any]:
    """队列总览（界面与智能体读同一份队列状况）。

    **成本口径只算真分析**：同类现象复用交回的行会写 `findings.reused_from`，
    它的 `tools_used/duration_ms` 是 0（根本没起会话）。把它算进平均会把成本
    拉低，看起来像"智能体变便宜了"，其实是同一件事被重复交回。
    所以：`results_total`（累计结论）与结论分布都只算真分析，复用次数单列
    `reused_total`。
    """
    now = datetime.now(UTC)
    # 复用行：findings 里带 reused_from（JSONB 判键，走 ? 操作符）
    real = ~AnalysisResult.findings.has_key("reused_from")  # noqa: W601 — JSONB，不是 dict
    with SessionLocal() as db:
        by_state = {
            str(state or ""): int(count)
            for state, count in db.execute(
                select(AnalysisTask.state, func.count())
                .select_from(AnalysisTask)
                .group_by(AnalysisTask.state)
            ).all()
        }
        by_kind = [
            {"kind": str(kind or ""), "count": int(count)}
            for kind, count in db.execute(
                select(AnalysisTask.kind, func.count())
                .where(AnalysisTask.state.in_(("pending", "deferred")))
                .group_by(AnalysisTask.kind)
                .order_by(func.count().desc())
            ).all()
        ]
        by_verdict = [
            {"verdict": str(v or ""), "count": int(c)}
            for v, c in db.execute(
                select(AnalysisResult.verdict, func.count())
                .where(real)
                .group_by(AnalysisResult.verdict)
                .order_by(func.count().desc())
            ).all()
        ]
        avg_tools = db.scalar(select(func.avg(AnalysisResult.tools_used)).where(real)) or 0
        avg_ms = db.scalar(select(func.avg(AnalysisResult.duration_ms)).where(real)) or 0
        done_total = db.scalar(select(func.count()).select_from(AnalysisResult).where(real)) or 0
        reused_total = (
            db.scalar(select(func.count()).select_from(AnalysisResult).where(~real)) or 0
        )
        # 指标看板（Phase 3，2026-10-29）：方向分布 / 资产主体比例 / 基线事实量 / 自动白名单数
        week_ago = now - timedelta(days=7)
        by_direction = [
            {"direction": str(direction or "unknown"), "count": int(count)}
            for direction, count in db.execute(
                select(HitEvent.direction, func.count())
                .where(HitEvent.created_at >= week_ago)
                .group_by(HitEvent.direction)
                .order_by(func.count().desc())
            ).all()
        ]
        by_subject_kind = [
            {"subject_kind": str(subject_kind or ""), "count": int(count)}
            for subject_kind, count in db.execute(
                select(AnalysisTask.subject_kind, func.count())
                .where(AnalysisTask.created_at >= week_ago)
                .group_by(AnalysisTask.subject_kind)
                .order_by(func.count().desc())
            ).all()
        ]
        facts_24h = [
            {"kind": str(kind or ""), "count": int(count)}
            for kind, count in db.execute(
                select(Observation.kind, func.count())
                .where(Observation.last_seen >= now - timedelta(hours=24))
                .group_by(Observation.kind)
                .order_by(func.count().desc())
            ).all()
        ]
        auto_allow_total = (
            db.scalar(
                select(func.count())
                .select_from(EgressAllow)
                .where(EgressAllow.source == "learned")
            )
            or 0
        )
    return {
        "enabled": params.enabled(),
        "by_state": by_state,
        "pending": int(by_state.get("pending", 0)),
        "deferred": int(by_state.get("deferred", 0)),
        "claimed": int(by_state.get("claimed", 0)),
        "stuck": int(by_state.get("stuck", 0)),
        "by_kind": by_kind,
        "by_verdict": by_verdict,
        "results_total": int(done_total),
        # 同类现象复用交回的次数（0 token 的那部分，成本口径里单列）
        "reused_total": int(reused_total),
        "avg_tools_used": round(float(avg_tools or 0), 2),
        "avg_duration_ms": int(avg_ms or 0),
        "counters": read_stats(client),
        "metrics": {
            # 方向分布（近 7 天命中事件）：out→in / in→out / in→in / out→out / unknown
            "by_direction": by_direction,
            # 任务主体类型分布（近 7 天）：asset 占比越高 = 主体资产化越到位
            "by_subject_kind": by_subject_kind,
            # 基线事实量（近 24 小时，按 kind）
            "observations_24h": facts_24h,
            # 自动进白名单的条目数（egress.auto_allow 关着时不再增长）
            "auto_allow_total": int(auto_allow_total),
        },
        "queue_policy": {
            "lease_seconds": params.lease_seconds(),
            "queue_capacity": params.queue_capacity(),
            "pending_ttl_hours": params.pending_ttl_hours(),
        },
        "generated_at": now.isoformat(),
    }


def list_tasks(
    *,
    state: str = "",
    kind: str = "",
    subject: str = "",
    q: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """界面浏览队列（按优先级降序；同分先进先出）。"""
    cap = max(1, min(int(limit or 50), 200))
    start = max(0, int(offset or 0))
    conds: list[Any] = []
    if state:
        conds.append(AnalysisTask.state == state)
    if kind:
        conds.append(AnalysisTask.kind == kind)
    if subject:
        conds.append(AnalysisTask.subject == subject)
    if (q or "").strip():
        needle = f"%{str(q).strip()}%"
        conds.append(AnalysisTask.subject.ilike(needle) | AnalysisTask.note.ilike(needle))
    try:
        with SessionLocal() as db:
            total = int(
                db.scalar(select(func.count()).select_from(AnalysisTask).where(*conds)) or 0
            )
            rows = db.scalars(
                select(AnalysisTask)
                .where(*conds)
                .order_by(AnalysisTask.priority.desc(), AnalysisTask.created_at.desc())
                .limit(cap)
                .offset(start)
            ).all()
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读任务队列失败：{exc}", "items": [], "total": 0}
    return {
        "total": total,
        "returned": len(rows),
        "items": [_task_dict(r) for r in rows],
    }


def task_detail(task_id: str) -> dict[str, Any]:
    """任务详情 + 该对象的历史结论（智能体与界面都靠它判断"是不是分析过"）。"""
    with SessionLocal() as db:
        row = db.get(AnalysisTask, str(task_id or "").strip())
        if row is None:
            return {"error": "任务不存在"}
        out = _task_dict(row)
        results = list(
            db.scalars(
                select(AnalysisResult)
                .where(AnalysisResult.task_id == str(row.id))
                .order_by(AnalysisResult.created_at.desc())
                .limit(10)
            ).all()
        )
        # B2：复用要回放「上次这条结论挂了哪些资产」——锚点按 result_id 查回
        anchors_of = anchors_mod.assets_of_results([str(r.id) for r in results])
        out["results"] = [
            {
                "verdict": r.verdict,
                "terminal_reason": r.terminal_reason,
                "confidence": r.confidence,
                "summary": r.summary,
                # B6：一句话建议（_complete_task 落在 findings["recommendation"]），
                # 提升成结果行的一等字段，界面/复用回放不用再翻 findings
                "recommendation": str((r.findings or {}).get("recommendation") or ""),
                # 智能体侧要留档一份结论（控制台不再直连各 NDR 的 PG），
                # 所以把 findings / 证据引用 / 锚点一并回给它；都是它自己交回来的内容。
                "findings": dict(r.findings or {}),
                "evidence_refs": list(r.evidence_refs or []),
                "anchors": anchors_of.get(str(r.id), []),
                "tools_used": r.tools_used,
                "duration_ms": r.duration_ms,
                "claimed_by": r.claimed_by,
                "created_at": r.created_at.isoformat() if r.created_at else "",
            }
            for r in results
        ]
        return out


def next_watermark(client: Any) -> str:
    """给门铃用的水位线：队列里最新一条线索的时间（不含任何数据）。"""
    try:
        with SessionLocal() as db:
            newest = db.scalar(select(func.max(AnalysisTask.created_at)))
    except Exception:  # noqa: BLE001
        newest = None
    return (newest or datetime.now(UTC)).isoformat()


def doorbell_payload(client: Any) -> dict[str, Any]:
    """门铃载荷：**只有队列状况 + 本 NDR 的项目身份，不含任何事件数据**。

    红线：含事件数据就又回到"被动解释器"。`project` 是授权ID（8 位身份串），
    用于多项目 agent 把门铃路由到正确的项目；它不含任何流量内容。
    """
    from app.system_license import auth_id

    with SessionLocal() as db:
        rows = db.execute(
            select(AnalysisTask.kind, func.count(), func.max(AnalysisTask.strength))
            .where(AnalysisTask.state.in_(("pending", "deferred")))
            .group_by(AnalysisTask.kind)
        ).all()
    queue_len = sum(int(r[1] or 0) for r in rows)
    top = max(rows, key=lambda r: float(r[2] or 0), default=None)
    return {
        # 项目组织身份（授权ID）：多项目 agent 靠它路由；不是密钥
        "project": auth_id(),
        "queue_len": queue_len,
        "top_kind": str(top[0]) if top else "",
        "max_strength": round(float(top[2] or 0), 3) if top else 0.0,
        "watermark": next_watermark(client),
        "ts": datetime.now(UTC).isoformat(),
    }


def should_ring(client: Any, payload: dict[str, Any]) -> bool:
    """要不要按门铃：队列从空变非空立即一次；其余按冷却合并。"""
    if not params.doorbell_enabled():
        return False
    cooldown = params.doorbell_cooldown()
    try:
        if int(payload.get("queue_len") or 0) <= 0:
            return False
        # 空→非空跃迁：不看冷却，直接叫醒（这是"最该快"的一次）
        last_len = client.get(f"{_DOORBELL_PREFIX}:qlen")
        jumped = last_len is None or int(last_len or 0) <= 0
        client.set(f"{_DOORBELL_PREFIX}:qlen", int(payload.get("queue_len") or 0))
        if jumped:
            client.delete(f"{_DOORBELL_PREFIX}:bell")
        if cooldown > 0:
            got = client.set(f"{_DOORBELL_PREFIX}:bell", "1", nx=True, ex=cooldown)
            if not got and not jumped:
                return False
        return True
    except Exception as exc:  # noqa: BLE001 — 算不出来就按"发一次"处理，宁多不漏
        log.debug("门铃判定失败（照发）：%s", exc)
        return True


def add_followups(
    client: Any,
    parent_id: str,
    items: list[dict[str, Any]],
    *,
    token: str = "",
) -> dict[str, Any]:
    """智能体在交回结论时追加"还要看什么"（追问链）。

    两条硬上限（否则任务会自我繁殖，成本上限形同虚设）：
    - `analysis.followup_max_per_task`：一次最多派生几条；
    - `analysis.followup_depth`：超过深度直接**拒绝并说明原因**（不静默丢）。
    """
    limit = params.followup_max_per_task()
    max_depth = params.followup_depth()
    wanted = [i for i in (items or []) if isinstance(i, dict)][: max(0, limit)]
    if not wanted:
        return {"accepted": 0, "rejected": len(items or [])}
    with SessionLocal() as db:
        parent = db.get(AnalysisTask, str(parent_id or "").strip())
        if parent is None:
            return {"accepted": 0, "rejected": len(wanted), "reason": "父任务不存在"}
        depth = int(parent.depth or 0) + 1
        if depth > max_depth:
            return {
                "accepted": 0,
                "rejected": len(wanted),
                "reason": f"追问深度已达上限 {max_depth}（analysis.followup_depth），不再派生",
            }
        accepted = 0
        rejected = 0
        for item in wanted:
            kind = str(item.get("kind") or "hit").strip()[:16]
            if kind not in params.KINDS:
                rejected += 1
                continue
            subject_kind = str(item.get("subject_kind") or parent.subject_kind or "ip").strip()[:16]
            subject = str(item.get("subject") or parent.subject or "").strip()[:128]
            if not subject:
                rejected += 1
                continue
            strength = item.get("strength")
            result = enqueue(
                kind=kind,
                subject_kind=subject_kind,
                subject=subject,
                strength=float(strength) if isinstance(strength, (int, float)) else 0.5,
                hint=dict(item.get("hint") or {}) if isinstance(item.get("hint"), dict) else {},
                feature=str(item.get("feature") or "followup")[:64],
                window_start=parent.window_start,
                window_end=parent.window_end,
                parent_id=str(parent.id),
                depth=depth,
                client=client,
            )
            if result in ("new", "merged"):
                accepted += 1
            else:
                rejected += 1
        bump(client, "followup_accepted", accepted)
        return {
            "accepted": accepted,
            "rejected": rejected,
            "depth": depth,
            "max_depth": max_depth,
            "claimed_by": token[:64],
        }


def manual_task(
    client: Any,
    *,
    subject_kind: str,
    subject: str,
    note: str = "",
    kind: str = "hit",
    strength: float = 0.6,
) -> dict[str, Any]:
    """人工派工：运维"我就想看看这台"直接进队列（不插队、走同一套容量与去重）。"""
    result = enqueue(
        kind=kind if kind in params.KINDS else "hit",
        subject_kind=subject_kind or "ip",
        subject=subject,
        strength=strength,
        feature="manual",
        hint={"事实": "人工派工", "备注": note[:500], "客观强度": strength},
        client=client,
    )
    return {"ok": result in ("new", "merged"), "result": result, "subject": subject}


def recent_results(
    *,
    subject: str = "",
    kind: str = "",
    verdict: str = "",
    limit: int = 20,
    detail: bool = False,
    via_asset: bool = False,
) -> dict[str, Any]:
    """按对象查**历史结论**（智能体自主规划前必读）。

    为什么必须有：新架构里智能体不再被推送喂着，很容易"同一个对象反复分析"；
    能不能省预算，取决于它开工前先问一句"这台看过没有、看过几次、结论是什么"。

    三种视图（对应 artex 的 cold-digest + anchors）：
    - **概览**（默认）：先给冷摘要（每个对象一行、带次数与结论分布），再给最近未摘要的明细。
      这样返回量**恒定大小**，不会随历史线性膨胀；
    - **下钻**（`detail=True`）：连已摘要的原始行一起给，用来查"具体某次怎么判的"；
    - **按资产反查**（`via_asset=True`）：把锚到同一批资产的结论也带出来 ——
      一条"这台是反向代理"的结论因此能作用到它后面的后端主机。
    """
    cap = max(1, min(int(limit or 20), 100))
    subject_text = str(subject or "").strip()
    conds: list[Any] = []
    if subject_text:
        conds.append(AnalysisResult.subject == subject_text[:128])
    if (kind or "").strip():
        conds.append(AnalysisResult.kind == str(kind).strip()[:16])
    if (verdict or "").strip():
        conds.append(AnalysisResult.verdict == str(verdict).strip()[:24])
    if not detail:
        # 已折叠进摘要的老行不进概览（行还在，detail=true 才拉）
        conds.append(AnalysisResult.digested_at.is_(None))

    digests: list[dict[str, Any]] = []
    if not detail and params.digest_enabled():
        digests = digests_mod.get_digests(subject=subject_text, limit=cap)

    try:
        with SessionLocal() as db:
            rows = db.scalars(
                select(AnalysisResult)
                .where(*conds)
                .order_by(AnalysisResult.created_at.desc())
                .limit(cap)
            ).all()
            total = int(
                db.scalar(select(func.count()).select_from(AnalysisResult).where(*conds)) or 0
            )
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读历史结论失败：{exc}", "items": [], "total": 0}

    row_list = list(rows)
    items = [_result_dict(r, with_detail=detail) for r in row_list]

    if via_asset:
        pairs = _anchor_pairs_for(subject_text, row_list)
        if pairs:
            try:
                extra = anchors_mod.results_for_assets(pairs, limit=cap)
            except Exception as exc:  # noqa: BLE001
                return {
                    "error": f"按资产反查结论失败：{exc}",
                    "items": items,
                    "digests": digests,
                    "total": total,
                }
            seen_ids = {str(r.id) for r in rows}
            for result_row, via in extra:
                if str(result_row.id) in seen_ids:
                    continue
                payload = _result_dict(result_row, with_detail=detail)
                payload["via"] = via
                items.append(payload)
                seen_ids.add(str(result_row.id))

    return {
        "total": total,
        "returned": len(items),
        "subjects_seen": sorted({str(r.subject) for r in row_list if r.subject}),
        "digests": digests,
        "items": items,
        "note": (
            "digests 是折叠后的历史概览（恒定大小）；items 是最近未折叠的明细。"
            "要看已折叠的原始判定用 detail=true。"
        ),
    }


def _anchor_pairs_for(subject_text: str, rows: Sequence[AnalysisResult]) -> list[tuple[str, str]]:
    """要反查哪些资产：显式 subject（当它是 IP）+ 本批结果自己挂的锚点。"""
    pairs: list[tuple[str, str]] = []
    if subject_text:
        normalized = anchors_mod.normalize_ip(subject_text)
        if normalized:
            pairs.append(("ip", normalized))
    ids = [str(r.id) for r in rows]
    if ids:
        for assets in anchors_mod.assets_of_results(ids).values():
            for asset in assets:
                pair = (str(asset.get("kind") or ""), str(asset.get("value") or ""))
                if pair[0] and pair[1] and pair not in pairs:
                    pairs.append(pair)
    return pairs[:20]


def reused_from(row: AnalysisResult) -> str:
    """这条结论是不是「同类现象复用」交回的？是则返回原任务的 ID。

    复用交回不烧 token（没起会话），所以成本统计要把它剔出去、界面要标成
    「复用」—— 否则"累计结论"会把同一件事重复计数，平均工具数也被 0 值拉低。
    """
    findings = row.findings or {}
    if not isinstance(findings, dict):
        return ""
    return str(findings.get("reused_from") or "").strip()


def _result_dict(row: AnalysisResult, *, with_detail: bool = False) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "task_id": row.task_id,
        "kind": row.kind,
        "subject": row.subject,
        "subject_kind": row.subject_kind,
        "verdict": row.verdict,
        "confidence": row.confidence,
        "summary": row.summary[:600],
        "tools_used": row.tools_used,
        "duration_ms": row.duration_ms,
        "terminal_reason": str(row.terminal_reason or ""),
        "claimed_by": row.claimed_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
    if with_detail:
        payload["evidence_refs"] = list(row.evidence_refs or [])
        payload["findings"] = dict(row.findings or {})
        payload["digested_at"] = row.digested_at.isoformat() if row.digested_at else None
    return payload
