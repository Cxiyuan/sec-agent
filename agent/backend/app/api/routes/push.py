"""接收端点（第 5 期）：NDR 检测器经 HTTP 把聚合摘要推进来。

与原来的 Redis 队列 + ``app.consumer`` 相比，回执从「队列消费掉」变成 **HTTP 2xx**：
NDR 侧收到 2xx 就算送到、否则落回自己的持久队列重发。本端点的职责是：

1. **鉴权**：NDR 在「智能体推送」里配的令牌（``ST_PUSH_TOKEN``，两侧必须一致）。
2. **判重**：按「事件组指纹 + 时间桶」判。指纹算法与图里落库用同一份
   （``app.digest.group_fingerprint``），所以：
   - 库里已有同指纹的组（上一次已经分析过）→ **只累加 ``event_count``，不跑图**；
   - 库里没有、但 Redis 里已有桶内占位（同一桶的第一批还在跑）→ 跳过，不重复跑图；
   - 都没有 → 占位 + 交给 Celery 跑图。
3. **立即返回 2xx**：真正的分析在 Celery worker 里跑（分钟级），请求不能等它。

为什么判重要放在这里、而不是像以前那样放 NDR 侧：跨库拆分后「已分析过没有」这件事
只有智能体自己知道（结论、报告都在它的库里）。NDR 侧那份 ``AnalyzedRegistry``
因此退役（见 docs/ndr-redesign.md 第 5 期）。
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Annotated, Any

import redis
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.db.base import get_db
from app.db.models import EventGroup
from app.digest import bucket_minutes, digest_ips, group_fingerprint
from app.workers.celery_app import celery_app
from app.workers.log import get_logger

#: 等价于 3.11 的 `datetime.UTC`（本仓库 requires-python >=3.11）；用别名写法
#: 免得按旧语法解析的静态检查工具报「unknown import symbol」。
UTC = timezone.utc

log = get_logger(__name__)

router = APIRouter(prefix="/api/push", tags=["push"])


class PushItem(BaseModel):
    """一条推送：NDR 侧生成的事件 ID + 摘要指纹，外加摘要本体。"""

    event_id: str = ""
    fingerprint: str = ""  # NDR 侧的摘要级指纹（rule|src_ip|时间桶），仅用于日志/排障
    digest: dict[str, Any]


class PushIn(BaseModel):
    items: list[PushItem] = Field(min_length=1)


class PushResult(BaseModel):
    received: int
    accepted: int  # 新进图（交给 Celery）
    merged: int  # 库里已有同指纹的组：只累加计数
    inflight: int  # 同桶内已在跑：跳过
    group_fingerprints: list[str]
    hint: str


def require_push_token(authorization: Annotated[str | None, Header()] = None) -> None:
    """推送鉴权：``Authorization: Bearer <ST_PUSH_TOKEN>``（常数时间比较）。"""
    expect = (settings.push_token or "").strip()
    if not expect:
        # 没配令牌就一律拒绝：这是「没配好」，不是「客户端错」，用 503 让 NDR 侧看得懂
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="服务端未配置推送令牌（ST_PUSH_TOKEN），拒绝所有推送",
        )
    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    if not token or not secrets.compare_digest(token, expect):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="推送令牌不正确")


def _claim(fingerprint: str) -> bool:
    """桶内占位（Redis SET NX）：同一指纹在桶宽内只允许跑一次图。

    Redis 不可用时返回 True（放行）—— 宁可多跑一次分析，也不要因为判重组件挂了而漏报。
    """
    client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    ttl = max(60, bucket_minutes() * 60 * 2)
    key = f"{settings.push_dedup_key}:{fingerprint}"
    created = client.set(key, "1", nx=True, ex=ttl)
    return bool(created)


def _digest_count(digest: dict[str, Any]) -> int:
    """这条摘要代表的事件次数（检测器聚合次数，拿不到按 1）。"""
    try:
        return max(1, int(digest.get("count") or 1))
    except (TypeError, ValueError):
        return 1


@router.get("/ping")
def ping(_: Annotated[None, Depends(require_push_token)]) -> dict[str, Any]:
    """连通性自检：NDR 侧「测试连接」按钮用，不产生任何副作用。"""
    return {"ok": True, "service": settings.app_name, "dedup_window_minutes": bucket_minutes()}


@router.post("/digests")
def receive_digests(
    payload: PushIn,
    _: Annotated[None, Depends(require_push_token)],
    db: Annotated[Session, Depends(get_db)],
) -> PushResult:
    """接收一批摘要：判重 → 占位 → 交 Celery 跑图；立即可回 2xx。"""
    if len(payload.items) > max(1, settings.push_max_items):
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"单次推送最多 {settings.push_max_items} 条摘要",
        )

    now = datetime.now(UTC)
    accepted: list[dict[str, Any]] = []
    fingerprints: list[str] = []
    merged = inflight = 0

    for item in payload.items:
        digest = item.digest
        ips = digest_ips(digest)
        if not ips:
            # 连 IP 都没有的摘要算不出组指纹，直接当重复丢掉（图里也归不了组）
            inflight += 1
            log.warning("推送的摘要没有源/目的 IP，跳过：event_id=%s", item.event_id)
            continue
        fingerprint = group_fingerprint(ips, now)
        fingerprints.append(fingerprint)

        row = db.execute(
            select(EventGroup).where(EventGroup.fingerprint == fingerprint)
        ).scalar_one_or_none()
        if row is not None:
            # 已分析过（或正在分析）：只累加规模，不再跑一遍模型、不再出第二份报告
            row.event_count = (row.event_count or 0) + _digest_count(digest)
            if row.window_end is None or now > row.window_end:
                row.window_end = now
            merged += 1
            continue

        try:
            claimed = _claim(fingerprint)
        except Exception as exc:  # noqa: BLE001
            log.warning("判重占位失败（按未重复处理，照常投递）: %s", exc)
            claimed = True
        if not claimed:
            inflight += 1
            continue
        accepted.append(digest)

    if merged:
        db.commit()

    if accepted:
        # 交给 Celery worker（分钟级任务，不能占着 HTTP 请求）。
        # 用 send_task 按名字投递：API 进程不必 import 整个任务模块（图/模型那一大坨）。
        celery_app.send_task("analysis.analyze_digests", args=[accepted])

    if merged or inflight:
        log.info(
            "推送接收：收到 %d / 新进图 %d / 累计入已有组 %d / 桶内在跑跳过 %d",
            len(payload.items),
            len(accepted),
            merged,
            inflight,
        )
    return PushResult(
        received=len(payload.items),
        accepted=len(accepted),
        merged=merged,
        inflight=inflight,
        group_fingerprints=fingerprints,
        hint=(
            "accepted=已交给分析（2xx 即回执，掉了会由 NDR 重发）；"
            "merged=同一攻击的重复推送，只累加计数、不产生第二份报告"
        ),
    )
