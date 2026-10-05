"""Logstash 采集管道管理：后台界面维护「参数表单」或「管道全文」。

沿用 Zeek 的模式：后端只写**共享卷配置文件**，Logstash 靠 config.reload.automatic
自动重载（约 10 秒生效）—— 不接触 docker socket、不重启容器。
每次保存前备份上一版，界面可一键回滚。
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.collector import template
from app.config import settings
from app.db.base import SessionLocal, get_db
from app.db.models import SystemConfig, User
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/logstash", tags=["logstash"])

PARAMS_KEY = "logstash.params"

# 生成管道里 ES 地址那一行（对齐部署环境时用来读当前值；只认双引号写法，
# 与 `template.render()` 输出一致）。
_HOSTS_RE = re.compile(r'hosts\s*=>\s*\["([^"]*)"\]')


class ParamsIn(BaseModel):
    """常用参数（表单）。**ES 地址不在这里** —— 连接信息由部署环境固定（`ST_ES_URL`）。"""

    es_enabled: bool = True
    events_index: str = template.DEFAULT_EVENTS_INDEX


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
    # 保存前也清一次：管道目录里冒出别的文件就会把管道变成两份拼接
    remove_foreign_configs()
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


def remove_foreign_configs() -> list[str]:
    """把管道目录里**不属于我们**的文件删掉，返回被删的文件名。

    为什么必须删（而不仅仅是改名停用）：Logstash 把管道目录里**所有文件**都当配置读，
    **不看扩展名**。实测启动日志的 ``pipeline.sources`` 里同时列出了
    ``logstash.conf``、``logstash.conf.disabled``、``pipeline.conf.disabled`` ——
    改名为 .disabled 根本拦不住它。而官方镜像自带
    ``/usr/share/logstash/pipeline/logstash.conf``（示例管道：beats + ES + stdout），
    当我们把共享卷挂到那个目录时 Docker 会把它拷进卷里，于是同一个管道里出现两个
    beats 输入抢 5044 端口（第二个每 7 秒报 "Address already in use" 后重启），
    并且全量事件被额外 stdout 一遍刷爆容器日志。

    不变式：**管道目录里永远只能有 logstash.conf 一个文件**（包括备份文件也不能放这里）。
    """
    managed = Path(settings.logstash_pipeline_conf)
    removed: list[str] = []
    try:
        entries = [p for p in sorted(managed.parent.iterdir()) if p.is_file()]
    except OSError as exc:
        log.warning("扫描 Logstash 管道目录失败: %s", exc)
        return removed
    for entry in entries:
        if entry.name == managed.name:
            continue
        try:
            size = entry.stat().st_size
            entry.unlink()
            removed.append(f"{entry.name}({size}B)")
        except OSError as exc:
            log.warning("删除多余管道文件失败 %s: %s", entry, exc)
    if removed:
        log.warning(
            "管道目录里存在多余文件并已删除（Logstash 会把目录里所有文件拼成一个管道，"
            "不看扩展名；否则会出现两个 beats 抢 5044 端口）：%s",
            removed,
        )
    return removed


_HEADER_MARK = template.HEADER.splitlines()[0]


def _looks_managed(text: str) -> bool:
    """卷里的 logstash.conf 是不是**本系统下发的**管道（而不是官方镜像自带的示例管道）。

    为什么不能只看「文件非空」：官方镜像自带
    ``/usr/share/logstash/pipeline/logstash.conf``（示例管道：beats → stdout），
    而 compose 把共享卷**挂在镜像的默认管道目录**上；**命名卷首次挂载时 Docker 会把镜像
    那个目录的内容拷进卷**。于是全新部署时「卷里已有非空文件」并不代表用户配过管道。

    判定依据：我们渲染的管道一定带 `template.HEADER` 首行；用户走「全文编辑」保存的版本
    也必定含 `elasticsearch` 输出（`template.validate_pipeline` 强制）。示例管道两者皆无。
    """
    return _HEADER_MARK in text or "elasticsearch" in text


def derived_from_generated_pipeline() -> bool:
    """卷里的管道是不是**我们渲染出来的那份**（带模板头部标记）。

    比 `_looks_managed` 严：手工「全文编辑」保存的版本也算「本系统的管道」，但它可能被人
    改过，自动重渲染会把人的改动覆盖掉。只有带生成标记时才敢自动改写（写之前
    `write_pipeline` 还会备份上一版，界面可一键回滚）。
    """
    return _HEADER_MARK in read_pipeline()


def _resync_es_host(db: Session) -> str | None:
    """把**生成管道**里的 ES 地址对齐到部署环境，返回动作说明（None = 没动）。

    为什么需要它：读路径（`es_config`）永远取部署环境的 `ST_ES_URL`，写路径的地址却烧在
    管道文件的 `elasticsearch { hosts => [...] }` 里。改过 `.env` 再重启后，两边不一致就会
    出现「采集有数但界面查不到」的假故障。连接信息既然不再由界面配置，这里就必须跟部署
    环境自动对齐（第 6 期是「界面改地址 → 同步管道」，那条链已随配置 UI 一起删除）。

    只在**能确认文件就是我们渲染出来的那一份**时才改写：从文件里取出当前的 hosts，用它
    重渲染一遍；与文件逐字相同说明除地址外没有别的编辑 → 安全改写。否则只告警不动手
    （人手工编辑过的管道不能被自动流程覆盖）。地址本来就一致时什么都不做。
    """
    if not derived_from_generated_pipeline():
        return None
    text = read_pipeline()
    match = _HOSTS_RE.search(text)
    if match is None:
        log.warning("生成管道里找不到 elasticsearch hosts 行，跳过 ES 地址对齐")
        return "no-hosts"
    current_host = match.group(1)
    target_host = settings.es_url
    if current_host == target_host:
        return None
    params = _effective_params(_stored_params(db))
    if template.render(
        {**params, "es_host": current_host}, settings.logstash_http_port
    ).strip() != (text.strip()):
        log.warning(
            "生成管道里除 ES 地址外还有人工编辑（文件 %s 用 %s，部署环境是 %s），"
            "不自动改写；要跟随部署环境请在「采集 → Logstash 管道」保存一次参数",
            settings.logstash_pipeline_conf,
            current_host,
            target_host,
        )
        return "manual-edit"
    err = write_pipeline(template.render(params, settings.logstash_http_port))
    if err:
        log.warning("对齐管道 ES 地址失败：%s", err)
        return "write-failed"
    log.info(
        "已把 Logstash 管道的 ES 地址对齐到部署环境：%s → %s（约 10 秒自动重载）",
        current_host,
        target_host,
    )
    return "updated"


def seed_if_missing() -> bool:
    """首次部署时播种默认管道（卷内没有本系统的管道才写）。

    **开关语义**：`logstash_seed_on_startup=False` 只关掉「写默认管道」这一步；
    `remove_foreign_configs()` 的无条件清理不受它影响 —— 那是管道目录的**不变式**
    （目录里多一个文件，Logstash 就会把两份管道拼在一起，出现两个 beats 输入抢端口），
    属保护动作而不是播种内容。要连清理一起关就只能改造这个模块，不建议。
    关掉它同时也关掉 ES 地址对齐（那也是一次自动写入）。
    """
    # 不管是否播种，先把多余文件清掉（否则会和我们的管道拼接生效）
    remove_foreign_configs()
    if not settings.logstash_seed_on_startup:
        return False
    current = read_pipeline()
    if current.strip() and _looks_managed(current):
        # 已经是我们下发的管道：只做地址对齐（改过 .env 后不用人工去界面重存一次）
        with SessionLocal() as db:
            _resync_es_host(db)
        return False
    if current.strip():
        # 2026-10 实机部署踩到：不覆盖它就永远跑镜像示例管道（8080 没有 http 输入、
        # 也没有 ES 输出），归一化服务入库全是 [Errno 111] Connection refused。
        log.warning(
            "卷内 %s 不是本系统下发的管道（多为镜像自带示例管道），已覆盖为默认管道",
            settings.logstash_pipeline_conf,
        )
    text = template.render(template.default_params(settings.es_url), settings.logstash_http_port)
    err = write_pipeline(text)
    if err:
        log.warning("播种默认 Logstash 管道失败: %s", err)
        return False
    log.info("已播种默认 Logstash 管道 → %s", settings.logstash_pipeline_conf)
    return True


# ---------- 参数持久化 ----------


def _defaults() -> dict[str, Any]:
    return template.default_params(settings.es_url)


def _stored_params(db: Session) -> dict[str, Any] | None:
    row = db.get(SystemConfig, PARAMS_KEY)
    value = (row.value or {}).get("value") if row is not None else None
    return value if isinstance(value, dict) else None


def _effective_params(stored: dict[str, Any] | None) -> dict[str, Any]:
    """合并「库里的参数」与部署环境；**ES 地址永远由部署环境最后拍定**。

    库里可能留着历史的 `es_host`（第 6 期界面可改地址时写下的），这里一律忽略：连接信息
    只有一个来源（`.env` 的 `ST_ES_URL`），否则会出现「界面写了一个地址、实际连的是另一个」。
    """
    return {**_defaults(), **(stored or {}), "es_host": settings.es_url}


def _save_params(db: Session, params: dict[str, Any]) -> None:
    """只落可改的两项；ES 地址是部署环境派生的，不进库（读了也会被覆盖）。"""
    stored = {k: v for k, v in params.items() if k != "es_host"}
    row = db.get(SystemConfig, PARAMS_KEY)
    if row is None:
        row = SystemConfig(key=PARAMS_KEY, value={})
        db.add(row)
    row.value = {"value": stored}
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


def pipeline_runtime() -> dict[str, Any]:
    """Logstash 运行状态（总览页的组件灯也用它，避免两处各写一遍探测）。"""
    return _runtime_status()


def _queue_depth() -> int | None:
    """待归一化的积压（Filebeat 写进采集队列、还没被归一化服务取走的条数）。"""
    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        return int(client.llen(settings.collector_collect_queue))  # pyright: ignore[reportArgumentType]  # redis-py 同步返回被注为 Awaitable[T] | T
    except Exception as exc:  # noqa: BLE001
        log.debug("读取采集队列长度失败: %s", exc)
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
    params = _effective_params(stored)
    rendered = template.render(params, settings.logstash_http_port)
    return {
        "params": params,
        "params_applied": bool(stored) and text.strip() == rendered.strip(),
        "pipeline": text,
        "default_pipeline": rendered,
        "config_path": settings.logstash_pipeline_conf,
        "backup_path": settings.logstash_pipeline_backup,
        "updated_at": _file_updated_at(),
        "http": {
            "port": settings.logstash_http_port,
            "hint": (
                f"归一化服务把拍平后的文档 POST 到本机 {settings.logstash_http_port} 端口"
                "（http 输入，JSON）。原始日志不经过这里，走 Redis 采集队列。"
            ),
        },
        "logstash": _runtime_status(),
        "queue_depth": _queue_depth(),
    }


@router.post("/preview")
def preview(
    body: ParamsIn,
    _: Annotated[User, Depends(get_current_user)],
):
    """按参数渲染管道全文（不落盘，供界面确认后再保存）。ES 地址取部署环境。"""
    params = _effective_params(body.model_dump())
    return {"pipeline": template.render(params, settings.logstash_http_port)}


@router.put("/params")
def save_params(
    body: ParamsIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """保存表单参数：渲染全文并下发（会覆盖「全文编辑」的内容）。

    ES 地址不在表单里 —— 它由 `_effective_params()` 用部署环境拍定。
    """
    params = _effective_params(body.model_dump())
    if not params["es_enabled"]:
        return JSONResponse(
            status_code=400,
            content={
                "conflict": "field_error",
                "detail": (
                    "必须启用 Elasticsearch 输出：归一化后的日志只有这一个去处"
                    "（Redis 采集队列在下游的归一化服务里写，不由本管道负责）"
                ),
            },
        )
    text = template.render(params, settings.logstash_http_port)
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
