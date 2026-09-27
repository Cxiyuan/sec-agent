"""Celery 应用 + Beat 定时调度。"""

from __future__ import annotations

from celery import Celery

from app.config import settings

celery_app = Celery(
    "shentong",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone=settings.timezone,
    enable_utc=True,
    task_track_started=True,
    # 结果只用于排障：默认保留 24h 会让 celery-task-meta-* 无限堆积（实测 5000+ 键）
    result_expires=3600,
    # 任务被 worker 崩溃/超时中断时不丢：消息保持未确认，会重新投递
    task_acks_late=True,
    # 一次只预取 1 个：长任务（分析耗时几分钟）不应把后续任务锁在 worker 本地，
    # 否则 broker 队列显示为空，积压看不见
    worker_prefetch_multiplier=1,
    # 硬/软超时：防止卡住的图（如 HITL 长时间等人）把 worker 占死。
    # 注意：HITL 等待若超过硬超时，任务会被中断；图状态仍在 checkpointer 里，
    # 人工确认接口会用 resume_graph 继续。
    task_time_limit=1800,
    task_soft_time_limit=1500,
    # 队列隔离：自主调查很慢（单轮最多 240s，带多步模型调用），绝不能让它与实时分析抢 worker，
    # 否则检测器投递的摘要会在队列里排队、超过 "摘要最长安存" 被白丢。
    task_default_queue="celery",
    task_routes={
        "analysis.build_cases": {"queue": "investigation"},
        "analysis.investigate_case": {"queue": "investigation"},
        "analysis.retry_failed_cases": {"queue": "investigation"},
        # 水位兑底扫描很慢（实测单次 >1200s）——绝不能和实时分析抢同一个 worker：
        # prefetch=1 时它会把 worker 占死，实时摘要全部排不进来（真实停摆根因）。
        "analysis.run_window": {"queue": "investigation"},
        # 重建是长事务（逐组重算），绝不能跟实时分析挤同一个 worker：
        # 实测被实时分析“预取槽”卡住几十分钟没跑（prefetch=1）。走空闲的 investigation 队列。
        "analysis.rebuild_cases": {"queue": "investigation"},
    },
    beat_schedule={
        "run-analysis-every-interval": {
            "task": "analysis.run_window",
            "schedule": settings.analysis_interval_minutes * 60.0,
        },
        # 失败案件的自动重试（受单案每日轮次上限约束，不会无限烧钱）
        "retry-failed-investigations": {
            "task": "analysis.retry_failed_cases",
            "schedule": 600.0,
        },
        # 分析不收敛的兜底：把停在 analyzing 太久的组标成 analyze_failed（事故可见性）
        "reap-stuck-groups": {
            "task": "analysis.reap_stuck_groups",
            "schedule": 300.0,
        },
        # 空壳案件治理：零轮次且长期无新增 → 自动关闭（列表默认已隐藏）
        "shelve-stale-cases": {
            "task": "analysis.shelve_stale_cases",
            "schedule": 3600.0,
        },
    },
)
