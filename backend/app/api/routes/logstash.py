"""Logstash 采集管道管理：后台界面维护「参数表单」或「管道全文」。

沿用 Zeek 的模式：后端只写**共享卷配置文件**，Logstash 靠 config.reload.automatic
自动重载（约 10 秒生效）—— 不接触 docker socket、不重启容器。
每次保存前备份上一版，界面可一键回滚。
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.collector import template
from app.config import settings
from app.db.base import get_db
from app.db.models import SystemConfig, User
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/logstash", tags=["logstash"])

PARAMS_KEY = "logstash.params"


class ParamsIn(BaseModel):
    """常用参数（表单）。"""

    es_enabled: bool = True
    es_host: str = template.DEFAULT_ES_HOST
    zeek_index: str = template.DEFAULT_ZEEK_INDEX
    wazuh_index: str = template.DEFAULT_WAZUH_INDEX
    redis_enabled: bool = True
    redis_host: str = template.DEFAULT_REDIS_HOST
    redis_port: int = template.DEFAULT_REDIS_PORT
    redis_db: int = template.DEFAULT_REDIS_DB
    redis_key: str = template.DEFAULT_REDIS_KEY


class PipelineIn(BaseModel):
    """管道全文（高级）。"""

    text: str


# ---------- 共享卷读写 ----------


def read_pipeline() -> str:
    try:
        with open(settings.logstash_pipeline_conf, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def write_pipeline(text: str) -> str | None:
    """备份上一版 → 原子写。成功返回 None，失败返回错误说明。"""
    path = settings.logstash_pipeline_conf
    current = read_pipeline()
    if current.strip():
        try:
            with open(settings.logstash_pipeline_backup, "w", encoding="utf-8") as fh:
                fh.write(current)
        except OSError as exc:
            log.warning("备份上一版管道失败（继续写入）: %s", exc)
    tmp = f"{path}.tmp"
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except OSError as exc:
        return str(exc)
    return None


def seed_if_missing() -> bool:
    """首次部署时播种默认管道（卷内无文件才写）。"""
    if not settings.logstash_seed_on_startup:
        return False
    if read_pipeline().strip():
        return False
    text = template.render(template.default_params(settings.es_url, settings.redis_url))
    err = write_pipeline(text)
    if err:
        log.warning("播种默认 Logstash 管道失败: %s", err)
        return False
    log.info("已播种默认 Logstash 管道 → %s", settings.logstash_pipeline_conf)
    return True


# ---------- 参数持久化 ----------


def _defaults() -> dict[str, Any]:
    return template.default_params(settings.es_url, settings.redis_url)


def _stored_params(db: Session) -> dict[str, Any] | None:
    row = db.get(SystemConfig, PARAMS_KEY)
    value = (row.value or {}).get("value") if row is not None else None
    return value if isinstance(value, dict) else None


def _save_params(db: Session, params: dict[str, Any]) -> None:
    row = db.get(SystemConfig, PARAMS_KEY)
    if row is None:
        row = SystemConfig(key=PARAMS_KEY, value={})
        db.add(row)
    row.value = {"value": params}
    db.commit()


# ---------- 运行状态 ----------


def _runtime_status() -> dict[str, Any]:
    """读 Logstash HTTP API（9600）拿存活、吞吐与重载统计。"""
    try:
        resp = httpx.get(f"{settings.logstash_api_url.rstrip('/')}/_node/stats", timeout=5.0)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        return {"alive": False, "error": str(exc)[:200]}

    raw_reloads = data.get("reloads")
    reloads = raw_reloads if isinstance(raw_reloads, dict) else {}
    raw_pipelines = data.get("pipelines")
    pipelines = raw_pipelines if isinstance(raw_pipelines, dict) else {}
    raw_main = pipelines.get("main")
    main = raw_main if isinstance(raw_main, dict) else {}
    raw_events = main.get("events")
    events = raw_events if isinstance(raw_events, dict) else {}
    return {
        "alive": True,
        "reloads_successes": reloads.get("successes"),
        "reloads_failures": reloads.get("failures"),
        "events_in": events.get("in"),
        "events_filtered": events.get("filtered"),
        "events_out": events.get("out"),
    }


def _queue_depth() -> int | None:
    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        return int(client.llen(settings.detector_raw_queue))
    except Exception as exc:  # noqa: BLE001
        log.debug("读取旁路队列长度失败: %s", exc)
        return None


def _file_updated_at() -> str | None:
    try:
        ts = os.path.getmtime(settings.logstash_pipeline_conf)
    except OSError:
        return None
    return datetime.fromtimestamp(ts, tz=UTC).isoformat()


# ---------- 路由 ----------


@router.get("")
def get_logstash(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    text = read_pipeline()
    stored = _stored_params(db)
    params = {**_defaults(), **(stored or {})}
    rendered = template.render(params, settings.logstash_beats_port)
    return {
        "params": params,
        "params_applied": bool(stored) and text.strip() == rendered.strip(),
        "pipeline": text,
        "default_pipeline": rendered,
        "config_path": settings.logstash_pipeline_conf,
        "backup_path": settings.logstash_pipeline_backup,
        "updated_at": _file_updated_at(),
        "beats": {
            "port": settings.logstash_beats_port,
            "hint": f"把 Zeek/Wazuh 的输出指向本机 {settings.logstash_beats_port} 端口（beats 协议）",
        },
        "logstash": _runtime_status(),
        "queue_depth": _queue_depth(),
    }


@router.post("/preview")
def preview(
    body: ParamsIn,
    _: Annotated[User, Depends(get_current_user)],
):
    """按参数渲染管道全文（不落盘，供界面确认后再保存）。"""
    return {"pipeline": template.render(body.model_dump(), settings.logstash_beats_port)}


@router.put("/params")
def save_params(
    body: ParamsIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """保存表单参数：渲染全文并下发（会覆盖「全文编辑」的内容）。"""
    params = body.model_dump()
    if not params["es_enabled"] and not params["redis_enabled"]:
        return JSONResponse(
            status_code=400,
            content={
                "conflict": "field_error",
                "detail": "至少启用一个输出（Elasticsearch 或 Redis 旁路）",
            },
        )
    text = template.render(params, settings.logstash_beats_port)
    err = write_pipeline(text)
    if err:
        return JSONResponse(
            status_code=400,
            content={
                "conflict": "write_failed",
                "detail": f"写入管道失败：{err}（请确认 logstash-pipeline 共享卷已挂载）",
            },
        )
    _save_params(db, params)
    return {
        "ok": True,
        "pipeline": text,
        "note": "已下发；Logstash 约 10 秒内自动重载。注意：参数保存会覆盖「全文编辑」的内容。",
    }


@router.put("/pipeline")
def save_pipeline(
    body: PipelineIn,
    _: Annotated[User, Depends(get_current_user)],
):
    """保存管道全文（保存前做静态校验）。"""
    problems = template.validate_pipeline(body.text, settings.logstash_pipeline_max_chars)
    if problems:
        return JSONResponse(
            status_code=400,
            content={
                "conflict": "field_error",
                "detail": problems[0],
                "field_errors": [{"field": "pipeline", "msg": p} for p in problems],
            },
        )
    err = write_pipeline(body.text)
    if err:
        return JSONResponse(
            status_code=400,
            content={"conflict": "write_failed", "detail": f"写入管道失败：{err}"},
        )
    return {"ok": True, "note": "已下发；Logstash 约 10 秒内自动重载。"}


@router.post("/rollback")
def rollback(_: Annotated[User, Depends(get_current_user)]):
    """回滚到上一版（保存前自动备份的那份）。"""
    try:
        with open(settings.logstash_pipeline_backup, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return JSONResponse(
            status_code=400,
            content={"conflict": "no_backup", "detail": "没有可回滚的上一版"},
        )
    problems = template.validate_pipeline(text, settings.logstash_pipeline_max_chars)
    if problems:
        return JSONResponse(
            status_code=400,
            content={"conflict": "field_error", "detail": f"备份内容不合法：{problems[0]}"},
        )
    # 直接把备份写回（不再覆盖备份本身）
    path = settings.logstash_pipeline_conf
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except OSError as exc:
        return JSONResponse(
            status_code=400, content={"conflict": "write_failed", "detail": str(exc)}
        )
    return {"ok": True, "pipeline": text, "note": "已回滚到上一版，等待 Logstash 重载。"}
