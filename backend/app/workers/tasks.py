"""分析任务：实时摘要分析（事件驱动）+ 水位驱动的定时兜底。"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import select

from app.agents.runner import get_graph
from app.config import settings
from app.detector.analyzed import AnalyzedRegistry, digest_age
from app.workers.celery_app import celery_app
from app.workers.log import get_logger

log = get_logger(__name__)


@celery_app.task(name="analysis.analyze_digests")
def analyze_digests(digests: list[dict]) -> dict:
    """实时链路：分析检测器投递的一批聚合摘要（一次图运行处理一批）。

    入口先做一次「超龄过滤」：投递侧已有同样的检查，但 Celery 开了 ``acks_late``，
    worker 被杀时 broker 会把**同一个任务消息原样重投**（带着当初那批摘要），
    这条路径完全绕过了投递侧 —— 部署实测过：11:00 的摘要在 14:09 被重跑，
    产出窗口很旧的事件组。
    """
    digests, expired = _drop_stale_digests(digests)
    if expired:
        _count_digests_expired(expired)
    if not digests:
        return {"summary": {"total_groups": 0, "reports": 0}, "digests": 0, "expired": expired}

    # 「被杀-重投」防护：acks_late 下 worker 被杀会把同一批摘要原样重投，
    # 如果这批每次都跑不完（长任务/模型卡住），就会无限循环、且什么都不产出。
    redeliveries = _redelivery_count(digests)
    limit = max(1, _redis_int(settings.analysis_max_redeliveries, 2))
    if redeliveries > limit:
        _count_dropped("task_abandoned", len(digests))
        log.warning(
            "同一批摘要已重投 %d 次（超上限 %d），放弃本批并计入 dropped.task_abandoned",
            redeliveries,
            limit,
        )
        return {"abandoned": len(digests), "redeliveries": redeliveries}

    now = datetime.now(UTC)
    thread_id = str(uuid.uuid4())
    initial = {
        "thread_id": thread_id,
        "digests": digests,
        "window_start": now,
        "window_end": now,
    }
    try:
        result = get_graph().invoke(initial, {"configurable": {"thread_id": thread_id}})
        # 分析完结标记：必须落在图正常返回之后（异常则保持“在途”，等 TTL 到期后可重投）
        AnalyzedRegistry().mark_done(digests, thread_id)
        _dispatch_cases(result.get("groups") or [])
        return {
            "thread_id": thread_id,
            "digests": len(digests),
            "summary": result.get("run_summary", {}),
        }
    except SoftTimeLimitExceeded:
        # 软超时：明确记录，而不是等硬超时把 worker 杀掉（杀掉后 acks_late 会重投同一批）
        log.warning("软超时中断：本批分析未跑完（digests=%d）", len(digests))
        _count_task_failed(len(digests))
        return {"thread_id": thread_id, "digests": len(digests), "error": "软超时中断"}
    except Exception:
        log.exception("实时分析任务失败")
        _count_task_failed(len(digests))
        return {"thread_id": thread_id, "digests": len(digests), "error": "实时分析任务失败"}


def _redis_int(value: Any, default: int) -> int:
    """安全转 int（配置可能来自后台，可能是字符串/脏值）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _digest_batch_key(digests: list[dict[str, Any]]) -> str:
    """这批摘要的稳定指纹（识别“同一批被反复重投”）。"""
    parts = sorted(
        str(d.get("fingerprint") or f"{d.get('src_ip')}|{d.get('rule')}") for d in digests
    )
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def _redelivery_count(digests: list[dict[str, Any]]) -> int:
    """这批摘要被投递的次数（Redis 计数，TTL 6h）；Redis 不可用时返回 1（放行）。"""
    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        key = f"shentong:analysis:redeliveries:{_digest_batch_key(digests)}"
        count = int(client.incr(key))
        client.expire(key, 6 * 3600)
        return count
    except Exception as exc:  # noqa: BLE001
        log.debug("重投计数失败（按首次处理）: %s", exc)
        return 1


def _count_dropped(reason: str, count: int) -> None:
    """把异常丢弃计入统一丢弃哈希（可查、不静默）。"""
    if count <= 0:
        return
    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        client.hincrby(settings.detector_drop_key, reason, int(count))
        client.hset(
            settings.detector_drop_key, "last_dropped_at", datetime.now(UTC).isoformat()
        )
        client.expire(settings.detector_drop_key, 30 * 24 * 3600)
    except Exception as exc:  # noqa: BLE001
        log.debug("写入丢弃计数失败: %s", exc)


def _count_task_failed(count: int) -> None:
    """记录“投递了但分析失败”的摘要数（原来只有一行日志，看不出来是否在漏分析）。"""
    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        client.hincrby(settings.detector_task_failed_key, "failed", count)
        client.hset(
            settings.detector_task_failed_key,
            "last_failed_at",
            datetime.now(UTC).isoformat(),
        )
        client.expire(settings.detector_task_failed_key, 30 * 24 * 3600)
    except Exception as exc:  # noqa: BLE001
        log.debug("写入分析失败计数失败: %s", exc)


def _drop_stale_digests(digests: list[dict]) -> tuple[list[dict], int]:
    """丢掉超龄摘要，返回 (保留的摘要, 丢掉的数量)。

    判据与投递侧同一个（analyzed.digest_age，取 last_seen 事件时间）。
    """
    max_age = settings.detector_digest_max_age_seconds
    if max_age <= 0:
        return digests, 0
    kept = [d for d in digests if digest_age(d) <= max_age]
    expired = len(digests) - len(kept)
    if expired:
        log.warning(
            "跳过 %d 条超龄摘要（>%d 秒）：多为 worker 重启后 acks_late 重投递的旧消息，不再进入分析",
            expired,
            max_age,
        )
    return kept, expired


def _count_digests_expired(count: int) -> None:
    """超龄丢弃计数：与检测器共用同一哈希（字段区分来源，接口上一眼能看到）。"""
    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        client.hincrby(settings.detector_drop_key, "expired_task", count)
        client.hset(settings.detector_drop_key, "last_dropped_at", datetime.now(UTC).isoformat())
        client.expire(settings.detector_drop_key, 30 * 24 * 3600)
    except Exception as exc:  # noqa: BLE001
        log.debug("写入超龄丢弃计数失败: %s", exc)


def _read_watermark() -> datetime | None:
    """读取兜底水位（存 PostgreSQL，跨重启可靠）。"""
    from app.db.base import SessionLocal
    from app.db.models import SystemConfig

    try:
        with SessionLocal() as db:
            row = db.get(SystemConfig, settings.fallback_watermark_key)
        raw = (row.value or {}).get("value") if row is not None else None
    except Exception as exc:  # noqa: BLE001
        log.warning("读取兜底水位失败: %s", exc)
        return None
    if not raw:
        return None
    try:
        ts = datetime.fromisoformat(str(raw))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def _write_watermark(ts: datetime) -> None:
    from app.db.base import SessionLocal
    from app.db.models import SystemConfig

    try:
        with SessionLocal() as db:
            row = db.get(SystemConfig, settings.fallback_watermark_key)
            if row is None:
                row = SystemConfig(key=settings.fallback_watermark_key, value={})
                db.add(row)
            row.value = {"value": ts.isoformat()}
            db.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("写入兜底水位失败: %s", exc)


@celery_app.task(name="analysis.run_window")
def run_analysis_window() -> dict:
    """定时兜底：窗口 = [水位, now]，只补检测器没处理过的日志。

    为什么用水位而不是固定窗口：服务整体停机数小时后，固定窗口会让停机期间
    的漏报永远补不回来；水位驱动则恢复后一次性补齐（带最大回补上限）。
    """
    now = datetime.now(UTC)
    # 顺手清理过期的去重指纹（inflight 超时 / done 超保留期）——每轮兜底跑一次，无需额外调度
    removed = AnalyzedRegistry().cleanup()
    if removed:
        log.info("清理过期去重指纹 %d 条", removed)
    # 右边界后退 lag：给检测器留出先处理这批日志的时间，避开与实时链路的重叠竞态
    end = now - timedelta(seconds=max(0, settings.fallback_lag_seconds))
    # 无水位时的首次窗口：取一个 beat 间隔（而不是分析窗口），语义上兜底一次覆盖一个调度周期
    start = _read_watermark() or (
        end - timedelta(minutes=max(1, settings.analysis_interval_minutes))
    )
    max_backfill = timedelta(hours=settings.fallback_max_backfill_hours)
    if end - start > max_backfill:
        log.warning(
            "兜底窗口 %s 超过最大回补 %d 小时，已截断",
            start.isoformat(),
            settings.fallback_max_backfill_hours,
        )
        start = end - max_backfill
    if end <= start:
        # 空窗口（例：刚跑过手动任务、或 beat 间隔小于 lag）：不动水位，直接跳过
        log.info("兜底窗口为空（%s ~ %s），本轮跳过", start.isoformat(), end.isoformat())
        return {"skipped": "empty_window"}

    thread_id = str(uuid.uuid4())
    initial = {"window_start": start, "window_end": end, "thread_id": thread_id}
    try:
        result = get_graph().invoke(initial, {"configurable": {"thread_id": thread_id}})
    except Exception:
        log.exception("兜底分析任务失败（水位不前移，下轮重试同一窗口）")
        return {"thread_id": thread_id, "error": "兜底分析任务失败"}
    # 水位只推进到实际覆盖到的右边界（不是 now），保证下轮不重叠、不断层
    _write_watermark(end)
    _dispatch_cases(result.get("groups") or [])
    return {"thread_id": thread_id, "summary": result.get("run_summary", {})}


# ---------- 自主取证调查（攻击者跨组案件）----------


def _group_ref(group: Any) -> dict:
    """把升级事件组压成案件归集引用（键抽取在此完成，任务端只做归集）。"""
    from app.investigation.cases import group_ref

    events = list(getattr(group, "events", None) or [])
    return group_ref(
        fingerprint=str(getattr(group, "fingerprint", "")),
        src_ips=list(getattr(group, "src_ips", None) or []),
        dst_ips=list(getattr(group, "dst_ips", None) or []),
        severity=getattr(group, "severity", None),
        event_types=sorted({str(e.log.event_type) for e in events}),
        texts=[str(e.log.summary) for e in events][:20],
        raws=[e.log.raw for e in events][:20],
        event_count=len(events),
        first_seen=getattr(group, "window_start", None),
        last_seen=getattr(group, "window_end", None),
    )


def _dispatch_cases(groups: list[Any]) -> None:
    """图跑完后：把**升级组**投给案件归集（独立队列，不阻塞实时链路）。

    为什么放在图之后而不是图里：调查是跨组、跨时间的异步长任务（最多几分钟），
    放进图里会拖长实时分析并占用实时 worker。
    """
    refs: list[dict] = []
    for group in groups or []:
        if not getattr(group, "escalate", False) or getattr(group, "excluded", False):
            continue
        try:
            refs.append(_group_ref(group))
        except Exception as exc:  # noqa: BLE001
            log.warning("案件归集引用抽取失败（跳过该组）: %s", exc)
    if not refs:
        return
    try:
        # 用 send_task 按名字投递（不依赖任务对象的 .apply_async，类型检查也更干净）
        celery_app.send_task("analysis.build_cases", args=[refs], queue="investigation")
    except Exception as exc:  # noqa: BLE001
        # 归集失败不能影响主分析链路（图已经跑完了）
        log.warning("案件归集任务投递失败: %s", exc)


@celery_app.task(name="analysis.build_cases")
def build_cases(refs: list[dict]) -> dict:
    """案件归集：把升级事件组挂到案件，并对需要调查的案件派发调查任务。"""
    from app.investigation import cases as case_service, service as investigation_service

    try:
        outcome = case_service.upsert_from_groups(refs)
    except Exception:
        log.exception("案件归集失败")
        return {"error": "案件归集失败"}
    dispatched = 0
    for item in outcome.get("dispatch") or []:
        result = investigation_service.dispatch(str(item.get("case_id")), kind="auto")
        if result.get("ok"):
            dispatched += 1
    log.info(
        "案件归集：新建 %s / 挂载 %s / 跳过 %s / 派发调查 %d",
        outcome.get("created"),
        outcome.get("linked"),
        outcome.get("skipped"),
        dispatched,
    )
    return {**outcome, "dispatched": dispatched}


@celery_app.task(name="analysis.investigate_case")
def investigate_case(case_id: str, kind: str = "auto", instruction: str = "") -> dict:
    """执行一轮自主取证调查（investigation 队列，独立 worker）。"""
    from app.investigation.service import investigate

    return investigate(case_id, kind=kind, instruction=instruction)  # type: ignore[arg-type]


@celery_app.task(name="analysis.retry_failed_cases")
def retry_failed_cases() -> dict:
    """失败案件自动重试（受单案每日轮次上限与冷却约束，不会无限烧钱）。"""
    from app.db.base import SessionLocal
    from app.db.models import AttackerCase
    from app.investigation import cases as case_service, service as investigation_service

    retried = 0
    with SessionLocal() as db:
        rows = (
            db.execute(select(AttackerCase).where(AttackerCase.status == "failed").limit(10))
            .scalars()
            .all()
        )
        candidates = [(row.id, case_service.should_investigate(row, is_new=False)) for row in rows]
    for case_id, (ok, _reason) in candidates:
        if not ok:
            continue
        if investigation_service.dispatch(case_id, kind="auto").get("ok"):
            retried += 1
    return {"failed_cases": len(candidates), "retried": retried}


class IndexFailedError(Exception):
    """向量化失败，用于触发 Celery 重试。"""


@celery_app.task(name="analysis.rebuild_cases")
def rebuild_cases(
    run_id: str,
    *,
    limit: int | None = None,
    hours: int | None = None,
    dispatch_after: bool = False,
) -> dict:
    """存量全量重建（手动触发，不进 beat）：按新规则重算键与归并，旧案件置 superseded。

    重建只动案件与组上的指针列（不改事件、不改图），并落 rebuild_runs 支持回滚。
    默认**不自动派发**新调查：旧结论随旧案件退场，避免批量烧模型预算。
    """
    from app.investigation import rebuild as rebuild_service

    try:
        return rebuild_service.apply(
            run_id=run_id, limit=limit, hours=hours, dispatch_after=dispatch_after
        )
    except Exception as exc:
        log.exception("重建失败（run %s）", run_id)
        from app.db.base import SessionLocal
        from app.db.models import RebuildRun

        with SessionLocal() as db:
            row = db.get(RebuildRun, run_id)
            if row is not None:
                row.status = "failed"
                row.counts = {"error": str(exc)[:500]}
                db.commit()
        raise


@celery_app.task(name="analysis.reap_stuck_groups")
def reap_stuck_groups() -> dict:
    """把长时间停在 analyzing 的事件组标成「分析未收敛（analyze_failed）」。

    为什么必须有这个任务：Redis 内存打满时（noeviction）Celery 写结果全部失败、任务崩溃，
    事件组永远停在 analyzing，而**表面上没有任何提示** —— 线上真实发生过，持续 4 小时 39 分
    没出报告，直到人工翻库才发现。分析不收敛必须自己叫出来、并在界面上看得见。
    """
    try:
        limit = max(1, int(settings.analysis_stuck_minutes))
    except (TypeError, ValueError):
        limit = 30
    cutoff = datetime.now(UTC) - timedelta(minutes=limit)
    from app.db.base import SessionLocal
    from app.db.models import EventGroup

    reaped = 0
    finished = 0
    with SessionLocal() as db:
        rows = (
            db.execute(
                select(EventGroup).where(
                    EventGroup.status == "analyzing", EventGroup.created_at < cutoff
                )
            )
            .scalars()
            .all()
        )
        for row in rows:
            # 有分析结果（级别/攻击链）说明图已经跑完，只是没出报告 → 记「已分析」；
            # 真没结果的才算「未收敛」，否则会把正常完成误报成事故
            if row.severity or row.attack_chain:
                row.status = "analyzed"
                finished += 1
            else:
                row.status = "analyze_failed"
                reaped += 1
        if reaped or finished:
            db.commit()
    if reaped:
        log.warning(
            "分析未收敛：%d 个事件组停在 analyzing 超过 %d 分钟且无任何分析结果，已标记 analyze_failed"
            "（常见原因：Redis 写失败 / worker 崩溃 / 模型不可达）",
            reaped,
            limit,
        )
    if finished:
        log.info("补落终态：%d 个组已分析完成但无报告，标记为 analyzed", finished)
    return {"reaped": reaped, "finished": finished, "stuck_minutes": limit}


@celery_app.task(name="analysis.shelve_stale_cases")
def shelve_stale_cases() -> dict:
    """自动关闭「零轮次且长期无新增」的案件（空壳治理的兜底）。

    背景：建案不看调查门槛，info 级也会建案，实测 25 个新案件里 20 个是零轮次空壳。
    现在低于门槛的建案即置 shelved（列表默认隐藏），超过天数无新增则自动 closed——
    归档而非删除：跨时间聚合仍保留，达标信号到来时 _attach 会自动复活。
    """
    try:
        days = max(1, int(settings.case_stale_close_days))
    except (TypeError, ValueError):
        days = 7
    cutoff = datetime.now(UTC) - timedelta(days=days)
    from sqlalchemy import func

    from app.db.base import SessionLocal
    from app.db.models import AttackerCase
    from app.investigation import cases as case_service

    closed = 0
    shelved = 0
    with SessionLocal() as db:
        # 第一步：存量归档——低于门槛且零轮次的 open 案件先置 shelved（列表默认隐藏）。
        # 为什么要管存量：新逻辑只管新建；不补这一步，历史空壳会一直挂在列表上
        # （实测 103 个 / 占 63%）。
        rows_zero = (
            db.execute(
                select(AttackerCase).where(
                    AttackerCase.status == "open", AttackerCase.rounds_total == 0
                )
            )
            .scalars()
            .all()
        )
        for row in rows_zero:
            if not case_service.qualifies_severity(row.severity):
                row.status = "shelved"
                shelved += 1
        if shelved:
            db.commit()
            log.info("存量空壳归档：%d 个零轮次且低于门槛的案件置为 shelved", shelved)

        # 第二步：长期无新增的零轮次案件自动关闭（归档而非删除）
        rows = (
            db.execute(
                select(AttackerCase).where(
                    AttackerCase.status.in_(["open", "shelved"]),
                    AttackerCase.rounds_total == 0,
                    func.coalesce(AttackerCase.last_seen, AttackerCase.created_at) < cutoff,
                )
            )
            .scalars()
            .all()
        )
        for row in rows:
            row.status = "closed"
            row.last_error = f"长期无新增且未达调查门槛，超过 {days} 天自动关闭"
            closed += 1
        if closed:
            db.commit()
    if closed:
        log.info("自动关闭零轮次空壳案件 %d 个（超过 %d 天无新增）", closed, days)
    return {"closed": closed, "shelved": shelved, "stale_days": days}


@celery_app.task(
    name="rag.index_asset",
    autoretry_for=(IndexFailedError,),
    retry_backoff=True,
    max_retries=3,
)
def index_asset_task(asset_id: str) -> bool:
    """向量化单个资产。"""
    from app.rag.indexer import index_asset

    if not index_asset(asset_id):
        raise IndexFailedError(asset_id)
    return True


@celery_app.task(
    name="rag.index_document",
    autoretry_for=(IndexFailedError,),
    retry_backoff=True,
    max_retries=3,
)
def index_document_task(doc_id: str) -> bool:
    """向量化单个文档（正文已存库）。"""
    from app.db.base import SessionLocal
    from app.db.models import Document
    from app.rag.indexer import index_document

    with SessionLocal() as db:
        d = db.get(Document, doc_id)
        text = d.content if d is not None else ""
        db.expunge_all()
    if not text.strip():
        return False
    if not index_document(doc_id, text):
        raise IndexFailedError(doc_id)
    return True


@celery_app.task(
    name="rag.index_topology",
    autoretry_for=(IndexFailedError,),
    retry_backoff=True,
    max_retries=3,
)
def index_topology_task(topology_id: str) -> bool:
    """向量化一张拓扑图。"""
    from app.rag.indexer import index_topology

    if not index_topology(topology_id):
        raise IndexFailedError(topology_id)
    return True
