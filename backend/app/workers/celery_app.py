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
    beat_schedule={
        "run-analysis-every-interval": {
            "task": "analysis.run_window",
            "schedule": settings.analysis_interval_minutes * 60.0,
        }
    },
)
