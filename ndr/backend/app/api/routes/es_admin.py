"""ES 管理：接入状态 / 索引族与保留期（ILM）/ 集群状态展示。

- **连接信息（地址/用户名/密码）不可由用户配置**：Elasticsearch 随 NDR 一起部署，连接信息
  由部署环境固定（`.env` 的 `ES_*` → 后台的 `ST_ES_*`，见 `app/config.py`）。本模块只读它，
  不写库、也没有保存接口 —— 同一事实两份来源会出现「界面写了一个地址、实际连的是另一个」。
  库里的历史 `es.url` / `es.username` / `es.password` 行不再被读（可以安全删除）。
- 只有**策略项**（索引族 `es.events_index`、保留天数 `es.retention_days`）可改，存
  `system_config`（DB 覆盖 env），改动即时生效（缓存失效）
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
from app.collector.es_mapping import EVENT_INDEX_MAPPINGS, is_safe_raw_mapping
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
    """可改的只有**策略项**；连接信息由部署环境固定，这里没有对应字段。"""

    events_index: str | None = None
    retention_days: int | None = None


class RetentionIn(BaseModel):
    retention_days: int


def _public(cfg: dict[str, str]) -> dict[str, Any]:
    """返回给前端的只读视图：连接信息用于**显示**（确认连的是哪台），不可写。

    密码只回 `password_set` 布尔（永不下发明文）；连接值来自部署环境，所以「打码」这件事
    本身就失去了意义 —— 没有用户填进来的值需要遮。
    """
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
    return _public(es_config.current())


@router.put("/config")
def update_config(
    body: EsConfigIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """改索引族 / 保留天数。连接信息不在 body 里 —— 想改连接只能改部署环境再重启后端。"""
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
        "es.events_index": body.events_index,
        "es.retention_days": (
            str(body.retention_days) if body.retention_days is not None else None
        ),
    }
    changed: set[str] = set()
    for key, value in pairs.items():
        if value is None:
            continue
        row = db.get(SystemConfig, key)
        if row is None:
            row = SystemConfig(key=key, value={})
            db.add(row)
        row.value = {"value": value}
        changed.add(key)
    db.commit()
    es_config.invalidate()
    # 注：原先这里还清一次「IP 字段类型 30 分钟缓存」（es_schema.clear_cache），
    # 但那条链（es_schema.get_ip_fields）全仓没有调用点，属死代码，一并删掉这次调用；
    # 若将来恢复该缓存，改配置后必须重新在这里失效。
    out: dict[str, Any] = dict(_public(es_config.current()))
    out["changed"] = sorted(changed)
    if "es.events_index" in changed:
        out["logstash_index_hint"] = (
            "这里改的是**查询**索引模式（如 shentong-events-*）；写侧按天滚动的索引名"
            "（shentong-events-%{+yyyy.MM.dd}）由后端按部署环境生成，不跟着查询模式变。"
        )
    return out


@router.get("/status")
def status(_: Annotated[User, Depends(get_current_user)]):
    """集群健康 + 索引列表 + ILM 策略状态（读路径的连通性就体现在这里）。"""
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


def _warn_legacy_raw_mapping(es: Any, pattern: str) -> None:
    """老索引的 ``raw`` 还不是安全映射时报警（索引模板只管之后新建的索引）。

    这类索引里 ``raw.id`` 已被动态映射定成 object，之后凡是「``raw.id`` 是字符串」的文档
    （Wazuh 告警、Zeek ocsp）都会被 ES 判 ``document_parsing_exception`` 整条 400 丢弃
    （见 `app/collector/es_mapping.py` 的事故说明）。``flattened`` 也不安全：单值超过
    32,766 字节仍会整条丢弃。**字段类型不能原地改**——8.15.3 实测三条路都不通：
    ``dynamic: false`` 只对未映射字段生效（``raw.id`` 已映射，照样 400）、``enabled`` 不允许
    改已存在的 object、``ignore_malformed`` 在 object 上不支持。所以这里只报警，不动数据；
    要修只能 reindex 到新映射（模板里的 ``raw: {type: object, enabled: false}``）。
    """
    mapping = es.indices.get_mapping(index=pattern)
    for index, body in (mapping or {}).items():
        props = (body.get("mappings") or {}).get("properties") or {}
        if not is_safe_raw_mapping(props.get("raw")):
            logger.warning(
                "索引 %s 的 raw 仍是动态/flattened 映射（raw.id 已被定成 object）：raw.id 为字符串"
                "的文档（Wazuh 告警、Zeek ocsp）与单值超过 32766 字节的文档会被 ES 丢弃；"
                "需 reindex 到新模板的映射",
                index,
            )


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
                },
                # `raw` 声明成 {type: object, enabled: false}：它是各来源原文，形状不统一
                # （`raw.id` 在 Zeek conn 是对象、在 Zeek ocsp 与 Wazuh 告警是字符串），动态映射
                # 会把先到的形状定死、之后整条文档被 ES 判 400 丢弃（2026-10 实机：全部 Wazuh
                # 告警 + 2024 条 ocsp 静默丢失）；`flattened` 也躲不掉（单值 > 32766 字节仍整条丢）。
                # 理由与实测见 `app/collector/es_mapping.py`。
                "mappings": EVENT_INDEX_MAPPINGS,
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
        try:
            _warn_legacy_raw_mapping(es, pattern)
        except Exception as exc:  # noqa: BLE001
            logger.debug("检查已存在索引的 raw 映射失败（%s）：%s", pattern, exc)


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
