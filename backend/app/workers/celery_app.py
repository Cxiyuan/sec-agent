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
    beat_schedule={
        "run-analysis-every-interval": {
            "task": "analysis.run_window",
            "schedule": settings.analysis_interval_minutes * 60.0,
        }
    },
)
