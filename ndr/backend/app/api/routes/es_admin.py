"""ES 管理：连接配置 / 保留期（ILM）/ 状态展示。

- 连接与保留期存 `system_config`（DB 覆盖 env），改动即时生效（缓存失效）
- 保留期通过 ILM 策略 + 索引模板下发（幂等），让 ES 自动 rollover 与删除
- 保留期硬下限 = 管线回溯封顶（`ST_LOOKBACK_MAX_DAYS`），否则回溯会无数据
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.config import settings
from app.db.base import get_db
from app.db.models import SystemConfig, User
from app.ingestion import es_config
from app.ingestion.es_client import get_es

router = APIRouter(prefix="/api/es", tags=["es"])

logger = logging.getLogger(__name__)

# 可被后台覆盖的键名单一来源 = `app.ingestion.es_config.RUNTIME_KEYS`
# （这里原先有一份复制出来的 `CONFIG_KEYS`，谁都没读，已删；加键请改 es_config）。

# 默认索引模板：模式 -> 模板名（归一化后只有一族索引）
TEMPLATES = {
    "shentong-events-*": "shentong-events",
}


class EsConfigIn(BaseModel):
    url: str | None = None
    username: str | None = None
    #: 不传（null）= 保留原值；传空串 = **清空**（与 Wazuh 配置同一口径：空串在
    #: `es_config` 里等于「没有覆盖」，所以清空必须表现为删掉那行覆盖值）。
    password: str | None = None
    #: 与「传空串」等价，供明确表达意图用（界面上「清空密码」勾选它或发空串都行）
    clear_password: bool = False
    events_index: str | None = None
    retention_days: int | None = None


class RetentionIn(BaseModel):
    retention_days: int


def _mask(cfg: dict[str, str]) -> dict[str, Any]:
    """返回给前端时对密码脱敏。"""
    return {
        "url": cfg.get("es.url", ""),
        "username": cfg.get("es.username", ""),
        "password_set": bool(cfg.get("es.password")),
        "events_index": cfg.get("es.events_index", ""),
        "retention_days": es_config.retention_days(),
        "retention_min_days": settings.lookback_max_days,
        "ilm_policy": settings.es_ilm_policy,
    }


@router.get("/config")
def get_config(_: Annotated[User, Depends(get_current_user)]):
    return _mask(es_config.current())


def _sync_logstash_es_host(db: Session, cfg: dict[str, str]) -> dict[str, Any]:
    """把 ES 连接地址同步进 Logstash 管道参数（实现见 `logstash.sync_es_endpoint`）。

    为什么要同步：写路径（Logstash 的 `elasticsearch { hosts => [...] }`）与读路径
    （`es_config.current()`）各存一份地址，只改一边就会出现「采集有数但界面查不到」
    或反过来的假故障。
    """
    from app.api.routes.logstash import sync_es_endpoint

    try:
        return sync_es_endpoint(db, str(cfg.get("es.url") or ""))
    except Exception as exc:  # noqa: BLE001
        logger.warning("同步 Logstash 管道的 ES 地址失败：%s", exc)
        return {"action": "error", "detail": str(exc)[:200]}


@router.put("/config")
def update_config(
    body: EsConfigIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    # 保留期校验：不得小于回溯封顶
    if body.retention_days is not None:
        if body.retention_days < settings.lookback_max_days:
            return JSONResponse(
                status_code=400,
                content={
                    "conflict": "field_error",
                    "detail": (
                        f"保留期不得小于 {settings.lookback_max_days} 天"
                        "（管线回溯封顶，过短会导致回溯无数据）"
                    ),
                },
            )
        if body.retention_days > 3650:
            return JSONResponse(
                status_code=400,
                content={"conflict": "field_error", "detail": "保留期不得大于 3650 天"},
            )

    pairs = {
        "es.url": body.url,
        "es.username": body.username,
        "es.password": body.password,
        "es.events_index": body.events_index,
        "es.retention_days": (
            str(body.retention_days) if body.retention_days is not None else None
        ),
    }
    changed: set[str] = set()
    for key, value in pairs.items():
        if value is None:
            continue
        if key == "es.password" and value == "":
            continue  # 空串=清空，交给下面的 clear_password 分支（避免写一行空值自相矛盾）
        row = db.get(SystemConfig, key)
        if row is None:
            row = SystemConfig(key=key, value={})
            db.add(row)
        row.value = {"value": value}
        changed.add(key)
    if body.clear_password or body.password == "":
        # 删掉覆盖值 → 回落到环境变量默认。传空串做不到「保留」的语义：es_config 读的
        # 时候把空值当作「没有覆盖」，所以「清空」必须表现为删行。
        row = db.get(SystemConfig, "es.password")
        if row is not None:
            db.delete(row)
        changed.add("es.password")
    db.commit()
    es_config.invalidate()
    # 注：原先这里还清一次「IP 字段类型 30 分钟缓存」（es_schema.clear_cache），
    # 但那条链（es_schema.get_ip_fields）全仓没有调用点，属死代码，一并删掉这次调用；
    # 若将来恢复该缓存，改配置后必须重新在这里失效。
    cfg_now = es_config.current()
    out: dict[str, Any] = dict(_mask(cfg_now))
    out["changed"] = sorted(changed)
    if "es.url" in changed:
        out["logstash"] = _sync_logstash_es_host(db, cfg_now)
    if "es.events_index" in changed:
        out["logstash_index_hint"] = (
            "这里改的是**查询**索引模式（如 shentong-events-*）；写侧按天滚动的索引名"
            "（shentong-events-%{+yyyy.MM.dd}）在「采集 → Logstash 管道」里配，不会自动跟着改。"
        )
    return out


@router.post("/test")
def test_connection(
    _: Annotated[User, Depends(get_current_user)],
    body: EsConfigIn | None = None,
):
    """连通性测试；传 body 时先测传入的连接（不落库）。"""
    try:
        if body and body.url:
            from elasticsearch import Elasticsearch

            # 界面拿不到已存密码（GET /config 只回 password_set），所以 body 里没带密码时
            # 回落库里/env 的现值，否则「不改密码只点测试」会假报鉴权失败。
            password = body.password or str(es_config.current().get("es.password") or "")
            auth = (body.username, password) if body.username else None
            probe = Elasticsearch(
                body.url,
                basic_auth=auth,
                verify_certs=settings.es_verify_certs,
                request_timeout=10,
            )
        else:
            probe = get_es()
        info = probe.info()
        return {
            "ok": True,
            "cluster_name": info.get("cluster_name"),
            "version": (info.get("version") or {}).get("number"),
        }
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            status_code=400,
            content={"conflict": "es_unreachable", "detail": f"连接 ES 失败：{exc}"},
        )


@router.get("/status")
def status(_: Annotated[User, Depends(get_current_user)]):
    """集群健康 + 索引列表 + ILM 策略状态。"""
    try:
        es = get_es()
        health = es.cluster.health()
        cfg = es_config.current()
        cat = es.cat.indices(
            format="json",
            h="index,docs.count,store.size,creation.date.string",
            bytes="b",
            s="index",
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            status_code=400,
            content={"conflict": "es_unreachable", "detail": f"读取 ES 状态失败：{exc}"},
        )

    patterns = ((cfg.get("es.events_index") or "shentong-events-*").replace("*", ""),)
    indices = [
        {
            "index": row.get("index"),
            "docs": row.get("docs.count"),
            "store": row.get("store.size"),
            "created": row.get("creation.date.string"),
        }
        for row in cat
        if isinstance(row, dict) and any(str(row.get("index", "")).startswith(p) for p in patterns)
    ]

    ilm: dict[str, Any] = {
        "policy": settings.es_ilm_policy,
        "retention_days": es_config.retention_days(),
    }
    try:
        policy = es.ilm.get_lifecycle(name=settings.es_ilm_policy)
        ilm["exists"] = True
        ilm["version"] = policy.get(settings.es_ilm_policy, {}).get("version")
    except Exception:  # noqa: BLE001
        ilm["exists"] = False

    return {
        "health": {
            "status": health.get("status"),
            "cluster_name": health.get("cluster_name"),
            "nodes": health.get("number_of_nodes"),
        },
        "indices": indices,
        "ilm": ilm,
    }


def _ilm_policy(days: int) -> dict[str, Any]:
    return {
        "policy": {
            "phases": {
                "hot": {"min_age": "0ms", "actions": {}},
                "delete": {
                    "min_age": f"{days}d",
                    "actions": {"delete": {"delete_searchable_snapshot": True}},
                },
            }
        }
    }


def ensure_retention(days: int | None = None) -> None:
    """幂等下发 ILM 策略与事件索引模板（启动时调用；失败由调用方决定是否吞掉）。

    模板里**副本数按 `auto_expand_replicas: "0-1"` 下发**：Logstash 输出用的是
    `manage_template => false`，索引由 ES 自动创建，单节点集群会拿到默认的
    `number_of_replicas: 1` —— 副本永远分配不出去，集群健康恒为 yellow
    （2026-10 实机部署踩到）。`0-1` 让 ES 自己按节点数伸缩：单节点 = 0 副本（green），
    多节点 = 1 副本（有冗余），比硬写死 0 更稳。模板只影响之后新建的索引，所以这里
    顺手把**已经存在**的同类索引也改成同一口径（模板缺失期间建出来的索引仍是 1 副本，
    会一直 yellow；改成 0 副本 + `0-1` 后 ES 会把多出来的副本撤掉，集群回 green）。
    """
    real_days = days if days is not None else es_config.retention_days()
    real_days = max(real_days, settings.lookback_max_days)
    es = get_es()
    es.ilm.put_lifecycle(
        name=settings.es_ilm_policy, policy=_ilm_policy(real_days)["policy"]
    )
    for pattern, name in TEMPLATES.items():
        es.indices.put_index_template(
            name=name,
            index_patterns=[pattern],
            template={
                "settings": {
                    "index.lifecycle.name": settings.es_ilm_policy,
                    "number_of_replicas": 0,
                    "auto_expand_replicas": "0-1",
                }
            },
            priority=500,
        )
    # 已存在的索引也拉回同一口径（幂等）。一个都没匹配上时 ES 报 index_not_found，
    # 属正常情况，忽略即可。
    for pattern in TEMPLATES:
        try:
            es.indices.put_settings(
                index=pattern,
                settings={
                    "index": {
                        "number_of_replicas": 0,
                        "auto_expand_replicas": "0-1",
                    }
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("回正已存在索引的副本设置失败（%s）：%s", pattern, exc)


@router.post("/apply-retention")
def apply_retention(
    _: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    body: RetentionIn | None = None,
):
    """按保留期下发 ILM 策略与索引模板（幂等）。未传则用当前配置。"""
    days = body.retention_days if body else es_config.retention_days()
    if days < settings.lookback_max_days:
        return JSONResponse(
            status_code=400,
            content={
                "conflict": "field_error",
                "detail": f"保留期不得小于 {settings.lookback_max_days} 天（管线回溯封顶）",
            },
        )

    try:
        ensure_retention(days)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            status_code=400,
            content={"conflict": "es_error", "detail": f"下发 ILM/模板失败：{exc}"},
        )

    # 同时把保留期写入配置，保持一致
    if body is not None:
        row = db.get(SystemConfig, "es.retention_days")
        if row is None:
            row = SystemConfig(key="es.retention_days", value={})
            db.add(row)
        row.value = {"value": str(days)}
        db.commit()
        es_config.invalidate()

    return {
        "ok": True,
        "retention_days": days,
        "policy": settings.es_ilm_policy,
        "templates": list(TEMPLATES.values()),
    }
