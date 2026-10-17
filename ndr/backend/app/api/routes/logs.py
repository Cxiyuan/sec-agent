"""日志检索（分析中心 → 日志检索）：按**归一化后的字段**查 ES，点一条看完整详情。

为什么单独一个端点（不复用 `es_admin`）：
- `es_admin` 是"运维视角"（集群健康、索引、模板），不按业务字段检索；
- 这里要的是**分析视角**：时间窗 + 关键字 + 几个常用字段过滤 + 分页，
  字段清单与归一化结构（`app/schemas.py::UnifiedLog`）对齐，前端不用猜字段名。

安全：只做**只读**查询（`_search` / `_doc`），不接受任何写操作；所有过滤字段走白名单，
不把用户输入拼进查询字符串（ES 查询体是 JSON 对象，天然的注入面很小，但字段名仍要白名单）。
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.deps import get_current_user
from app.config import settings
from app.db.models import User
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/logs", tags=["logs"])

#: 可检索的字符串字段（归一化后的名字 → 中文标签）。要加字段就加这里，前端自动出现输入框。
TEXT_FIELDS: dict[str, str] = {
    "log_type": "日志类型",
    "event_type": "事件类型",
    "src_ip": "源 IP",
    "dst_ip": "目的 IP",
    "account": "账号",
    "proxy_user": "代理认证账号",
    "hostname": "主机名 / 域名",
    "method": "HTTP 方法",
    "uri_path": "接口路径",
    "protocol": "协议",
    "user_agent": "User-Agent",
    "severity": "严重度",
    "hop": "中继位置",
    "source_file": "采集文件",
    "community_id": "Community ID",
    "signature": "签名名",
    "query": "查询 / URI",
}

#: 数值字段（term 精确匹配）
NUM_FIELDS: dict[str, str] = {
    "dst_port": "目的端口",
    "src_port": "源端口",
    "status_code": "状态码",
}

#: 全文检索命中的字段（顺序 = ES 的打分权重来源；body/resp_body 放后面，避免长正文压过关键字段）
FULLTEXT_FIELDS: tuple[str, ...] = (
    "query",
    "uri_path",
    "hostname",
    "account",
    "summary",
    "user_agent",
    "signature",
    "src_ip",
    "dst_ip",
    "body",
    "resp_body",
)

#: 列表里带的字段（详情走 `/doc/{id}`，列表不带 raw，省带宽）
LIST_SOURCE: tuple[str, ...] = (
    "@timestamp",
    "ts",
    "log_type",
    "event_type",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "hostname",
    "account",
    "status_code",
    "method",
    "uri_path",
    "bytes_out",
    "bytes_in",
    "conn_state",
    "summary",
    "signature",
    "severity",
    "hop",
)

MAX_SIZE = 200


def _es() -> Any:
    from app.ingestion.es_client import get_es

    return get_es()


def _index() -> str:
    return settings.es_events_index


def _keyword(field: str) -> str:
    """字符串字段统一打 `.keyword`（映射里是 text+keyword，精确匹配必须走 keyword）。"""
    return f"{field}.keyword"


@router.get("/fields")
def log_fields(_: Annotated[User, Depends(get_current_user)]) -> dict[str, Any]:
    """检索表单用的字段清单（前端据此渲染输入框，不写死字段名）。"""
    return {
        "text": [{"field": k, "label": v} for k, v in TEXT_FIELDS.items()],
        "num": [{"field": k, "label": v} for k, v in NUM_FIELDS.items()],
        "index": _index(),
    }


def _build_query(
    *,
    q: str,
    minutes: int,
    text_filters: dict[str, str],
    num_filters: dict[str, int],
    log_type_extra: str,
) -> dict[str, Any]:
    must: list[dict[str, Any]] = [
        {"range": {"@timestamp": {"gte": f"now-{max(1, minutes)}m"}}},
    ]
    if (log_type_extra or "").strip():
        must.append({"term": {_keyword("log_type"): log_type_extra.strip()}})
    filters: list[dict[str, Any]] = []
    for field, value in text_filters.items():
        if field not in TEXT_FIELDS or not str(value or "").strip():
            continue
        filters.append({"term": {_keyword(field): str(value).strip()}})
    for field, value in num_filters.items():
        if field not in NUM_FIELDS or value is None:
            continue
        filters.append({"term": {field: int(value)}})

    body: dict[str, Any] = {
        "query": {"bool": {"must": must, "filter": filters}},
    }
    text = (q or "").strip()
    if text:
        body["query"]["bool"]["must"].append(
            {
                "multi_match": {
                    "query": text,
                    "fields": list(FULLTEXT_FIELDS),
                    "type": "best_fields",
                    "lenient": True,
                }
            }
        )
    return body


@router.get("/search")
def search_logs(
    _: Annotated[User, Depends(get_current_user)],
    q: str = "",
    log_type: str = "",
    src_ip: str = "",
    dst_ip: str = "",
    account: str = "",
    hostname: str = "",
    event_type: str = "",
    method: str = "",
    uri_path: str = "",
    src_port: int | None = None,
    dst_port: int | None = None,
    status_code: int | None = None,
    minutes: int = Query(default=60, ge=1, le=60 * 24 * 30),
    size: int = Query(default=50, ge=1, le=MAX_SIZE),
    offset: int = Query(default=0, ge=0),
    order: str = Query(default="desc", pattern="^(desc|asc)$"),
) -> dict[str, Any]:
    """按归一化字段检索日志（时间窗 + 关键字 + 常用字段过滤 + 分页）。"""
    text_filters = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "account": account,
        "hostname": hostname,
        "event_type": event_type,
        "method": method,
        "uri_path": uri_path,
    }
    num_filters: dict[str, int] = {}
    if src_port is not None:
        num_filters["src_port"] = src_port
    if dst_port is not None:
        num_filters["dst_port"] = dst_port
    if status_code is not None:
        num_filters["status_code"] = status_code

    body = _build_query(
        q=q,
        minutes=minutes,
        text_filters=text_filters,
        num_filters=num_filters,
        log_type_extra=log_type,
    )
    body.update(
        {
            "size": size,
            "from": offset,
            "sort": [{"@timestamp": {"order": order}}],
            "_source": list(LIST_SOURCE),
            "aggs": {
                # 结果分布：一眼看出这批结果里是什么日志（点一下就能按类型再筛）
                "log_types": {"terms": {"field": _keyword("log_type"), "size": 20}},
                "top_src": {"terms": {"field": _keyword("src_ip"), "size": 10}},
                "top_dst": {"terms": {"field": _keyword("dst_ip"), "size": 10}},
            },
            "track_total_hits": True,
        }
    )
    try:
        resp = _es().search(index=_index(), body=body)
    except Exception as exc:
        log.warning("日志检索失败: %s", exc)
        raise HTTPException(status_code=503, detail=f"ES 查询失败：{exc}") from exc

    aggs = resp.get("aggregations") or {}
    return {
        "total": int((resp.get("hits") or {}).get("total", {}).get("value") or 0),
        "took_ms": int(resp.get("took") or 0),
        "items": [
            {"id": h.get("_id"), "index": h.get("_index"), "doc": h.get("_source") or {}}
            for h in ((resp.get("hits") or {}).get("hits") or [])
        ],
        "log_types": [
            {"value": b.get("key"), "count": b.get("doc_count")}
            for b in (((aggs.get("log_types") or {}).get("buckets")) or [])
        ],
        "top_src": [
            {"value": b.get("key"), "count": b.get("doc_count")}
            for b in (((aggs.get("top_src") or {}).get("buckets")) or [])
        ],
        "top_dst": [
            {"value": b.get("key"), "count": b.get("doc_count")}
            for b in (((aggs.get("top_dst") or {}).get("buckets")) or [])
        ],
        "minutes": minutes,
        "size": size,
        "offset": offset,
    }


@router.get("/doc/{doc_id}")
def log_doc(
    doc_id: str,
    _: Annotated[User, Depends(get_current_user)],
    index: str = "",
) -> dict[str, Any]:
    """取单条日志的**完整**内容（右侧详情抽屉用）。"""
    target = (index or "").strip() or _index()
    try:
        resp = _es().get(index=target, id=doc_id)
    except Exception as exc:
        log.warning("取日志详情失败: %s", exc)
        raise HTTPException(status_code=404, detail=f"取不到该日志：{exc}") from exc
    return {
        "id": resp.get("_id"),
        "index": resp.get("_index"),
        "doc": resp.get("_source") or {},
    }
