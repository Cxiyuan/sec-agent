"""降噪过滤（入库前）管理：命中则事件不投检测器，但仍然进 Elasticsearch。

与 `/api/exclusions`（排除过滤）的分工：
- **这里**决定「值得进检测器吗」——作用在归一化之后、规则之前，省的是检测器与模型的成本；
- 排除过滤决定「值得花钱分析吗」——作用在规则命中之后。

为什么必须能试运行：过滤是最容易「配错就静默漏报」的一类开关。所以保存前过三道校验
（空条件 / 字段白名单 / 正则），并且可以不落库先干跑一次看会挡掉什么。
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.base import get_db
from app.db.models import IngestFilter, User
from app.ingestion import ingest_filter
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/ingest-filters", tags=["ingest-filters"])

OPERATORS = ["eq", "ne", "contains", "regex", "gt", "gte", "lt", "lte", "in", "exists"]

# 给界面「示例」按钮用的现成条件（都是最常见的噪声，改一下就能用）
EXAMPLES: list[dict[str, Any]] = [
    {
        "name": "内网互扫不进检测器",
        "description": "内网到内网的扫描尝试（漏洞扫描器 / 资产测绘的日常噪声）",
        "conditions": {
            "rules": [
                {"field": "src_internal", "op": "eq", "value": True},
                {"field": "dst_internal", "op": "eq", "value": True},
                {"field": "event_type", "op": "eq", "value": "scan_attempt"},
            ]
        },
    },
    {
        "name": "监控探活 UA",
        "description": "带监控/拨测客户端 UA 的 HTTP 请求",
        "conditions": {"rules": [{"field": "user_agent", "op": "contains", "value": "Zabbix"}]},
    },
    {
        "name": "心跳域名查询",
        "description": "固定心跳域名的 DNS 查询（把域名换成自己的）",
        "conditions": {"rules": [{"field": "query", "op": "eq", "value": "telemetry.example.com"}]},
    },
]


class IngestFilterIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = ""
    conditions: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    priority: int = 100


class DryRunIn(BaseModel):
    conditions: dict[str, Any] = Field(default_factory=dict)
    hours: int = 0
    limit: int = 0


def _dict(
    row: IngestFilter, counts: dict[str, int], samples: dict[str, list[dict[str, Any]]]
) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "conditions": row.conditions or {},
        "enabled": row.enabled,
        "priority": row.priority,
        "hit_count": int(counts.get(row.name, 0)),
        "samples": samples.get(row.name, []),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def _validate(payload: IngestFilterIn) -> None:
    errors = ingest_filter.validate_conditions(payload.conditions)
    if errors:
        raise HTTPException(status_code=400, detail="；".join(errors))


def _get(db: Session, filter_id: str) -> IngestFilter:
    row = db.execute(select(IngestFilter).where(IngestFilter.id == filter_id)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="降噪过滤不存在")
    return row


def _check_name_free(db: Session, name: str, exclude_id: str | None = None) -> None:
    row = db.execute(select(IngestFilter).where(IngestFilter.name == name)).scalar_one_or_none()
    if row is not None and row.id != exclude_id:
        raise HTTPException(status_code=409, detail="同名降噪过滤已存在")


@router.get("")
def list_filters(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    rows = db.execute(select(IngestFilter).order_by(IngestFilter.priority)).scalars().all()
    stats = ingest_filter.get_stats()
    counts = stats.get("counts", {})
    samples = ingest_filter.get_samples()
    return {
        "total": len(rows),
        "items": [_dict(r, counts, samples) for r in rows],
        "last_hit_at": stats.get("last_hit_at"),
    }


@router.get("/fields")
def list_fields(_: Annotated[User, Depends(get_current_user)]):
    """条件可用字段与运算符（供界面条件编辑器）。"""
    return {
        "fields": sorted(ingest_filter.allowed_fields()),
        "address_fields": list(ingest_filter.ADDRESS_FIELDS),
        "content_fields": list(ingest_filter.CONTENT_FIELDS),
        "direction_fields": ["src_internal", "dst_internal", "src_external", "dst_external"],
        "operators": OPERATORS,
        "examples": EXAMPLES,
        "hint": "命中的事件仍然进 Elasticsearch（界面查得到），只是不产生告警。",
    }


@router.get("/stats")
def get_stats(_: Annotated[User, Depends(get_current_user)]):
    """命中统计与最近样例：用来回答「我配的降噪到底挡掉了什么」。"""
    return {**ingest_filter.get_stats(), "samples": ingest_filter.get_samples()}


@router.post("/dry-run")
def dry_run(
    payload: DryRunIn,
    _: Annotated[User, Depends(get_current_user)],
):
    """试运行：拿最近的历史事件跑一遍条件，看会挡掉多少、长什么样（不落库）。"""
    result = ingest_filter.dry_run(payload.conditions, hours=payload.hours, limit=payload.limit)
    if result.get("error"):
        raise HTTPException(status_code=400, detail=str(result["error"]))
    return result


@router.post("")
def create_filter(
    payload: IngestFilterIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    _validate(payload)
    _check_name_free(db, payload.name)
    row = IngestFilter(
        name=payload.name,
        description=payload.description,
        conditions=payload.conditions,
        enabled=payload.enabled,
        priority=payload.priority,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    ingest_filter.invalidate_cache()
    log.info("新增降噪过滤：%s（启用 %s）", row.name, row.enabled)
    return _dict(row, {}, {})


@router.put("/{filter_id}")
def update_filter(
    filter_id: str,
    payload: IngestFilterIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    row = _get(db, filter_id)
    _validate(payload)
    _check_name_free(db, payload.name, exclude_id=row.id)
    row.name = payload.name
    row.description = payload.description
    row.conditions = payload.conditions
    row.enabled = payload.enabled
    row.priority = payload.priority
    db.commit()
    db.refresh(row)
    ingest_filter.invalidate_cache()
    log.info("更新降噪过滤：%s（启用 %s）", row.name, row.enabled)
    return _dict(row, {}, {})


@router.delete("/{filter_id}")
def delete_filter(
    filter_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    row = _get(db, filter_id)
    name = row.name
    db.delete(row)
    db.commit()
    ingest_filter.invalidate_cache()
    log.info("删除降噪过滤：%s", name)
    return {"ok": True}
