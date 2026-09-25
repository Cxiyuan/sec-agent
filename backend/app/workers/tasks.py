"""分析任务：实时摘要分析（事件驱动）+ 水位驱动的定时兜底。"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from app.agents.runner import get_graph
from app.config import settings
from app.detector.analyzed import AnalyzedRegistry
from app.workers.celery_app import celery_app
from app.workers.log import get_logger

log = get_logger(__name__)


@celery_app.task(name="analysis.analyze_digests")
def analyze_digests(digests: list[dict]) -> dict:
    """实时链路：分析检测器投递的一批聚合摘要（一次图运行处理一批）。"""
    if not digests:
        return {"summary": {"total_groups": 0, "reports": 0}, "digests": 0}
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
    except Exception:
        log.exception("实时分析任务失败")
        _count_task_failed(len(digests))
        return {"thread_id": thread_id, "digests": len(digests), "error": "实时分析任务失败"}


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
