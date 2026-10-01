"""第 5 期：检测器把聚合摘要经 **HTTP** 推给智能体（取代 Redis 队列交接）。

交接契约的变化（两侧必须一起升级）：

- 旧（已退役）：``LPUSH shentong:events:dispatch`` → 智能体 ``app.consumer``（BRPOPLPUSH）跑图，
  跑完回传 ``shentong:analyzed:done`` 当回执。两侧均已删除 ``consumer`` / ``AnalyzedRegistry``；
  该 LPUSH 分支只在本模块开关关闭时作为兼容通道保留。
- 新：``POST {地址}`` 带 ``Authorization: Bearer {令牌}``，**收到 2xx 即成功**（响应就是回执）。
  推送失败落本模块的持久重试队列（``shentong:events:pushretry``），由检测循环后台重发。

为什么要把回执从「队列消费掉」换成「HTTP 2xx」：跨库拆分后「这个指纹分析过没有」只有
智能体自己知道（结论、报告都在它的库里）。NDR 侧那份 ``AnalyzedRegistry`` 闸门因此退役
（见 ``docs/ndr-redesign.md`` 第 5 期），判重落到智能体接收端点。

配置存 ``system_config``（键 ``agent_push.params``），环境变量只作默认值：
地址形如 ``http://agent:8000/api/push/digests``；**地址留空 = 不推送**，仍走旧队列路径
（升级时先配好再切，不会两头都断）。
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.db.base import SessionLocal
from app.db.models import SystemConfig
from app.detector.fingerprint import digest_fingerprint
from app.detector.queue import ReliableQueue
from app.workers.log import get_logger

log = get_logger(__name__)

CONFIG_KEY = "agent_push.params"

# 状态计数写这个 Redis 哈希（界面读它显示「已送 / 失败 / 待重发」）
_STATS_TTL = 30 * 24 * 3600


def env_defaults() -> dict[str, Any]:
    """环境变量给的默认配置（库里没存过就用它）。"""
    return {
        "url": (settings.agent_push_url or "").strip(),
        "token": settings.agent_push_token or "",
        "enabled": bool(settings.agent_push_enabled),
        "timeout_seconds": float(settings.agent_push_timeout_seconds or 10.0),
        "max_per_push": int(settings.agent_push_max_per_push or 200),
    }


def _to_bool(value: Any, default: bool) -> bool:
    """宽松转 bool：库里若被人手写成 ``"false"``/``"0"``/``"no"``，别当成 True。"""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    raw = str(value).strip().lower()
    if raw in ("", "0", "false", "no", "off", "null", "none"):
        return False
    if raw in ("1", "true", "yes", "on"):
        return True
    return default


def _merge(raw: Any) -> dict[str, Any]:
    cfg = env_defaults()
    if isinstance(raw, dict):
        for key in ("url", "token", "enabled", "timeout_seconds", "max_per_push"):
            if key in raw and raw[key] is not None:
                cfg[key] = raw[key]
    cfg["url"] = str(cfg["url"] or "").strip()
    cfg["token"] = str(cfg["token"] or "")
    cfg["enabled"] = _to_bool(cfg["enabled"], True)
    try:
        cfg["timeout_seconds"] = max(1.0, float(cfg["timeout_seconds"]))
    except (TypeError, ValueError):
        cfg["timeout_seconds"] = 10.0
    try:
        cfg["max_per_push"] = max(1, int(cfg["max_per_push"]))
    except (TypeError, ValueError):
        cfg["max_per_push"] = 200
    return cfg


def load_config(db: Session | None = None) -> dict[str, Any]:
    """读配置：库里存过以库为准，否则用环境变量；读库异常也回退环境变量（fail-open）。"""

    def _read(session: Session) -> dict[str, Any]:
        row = session.get(SystemConfig, CONFIG_KEY)
        value = (row.value or {}).get("value") if row is not None else None
        return _merge(value)

    if db is not None:
        try:
            return _read(db)
        except Exception as exc:  # noqa: BLE001
            log.warning("读智能体推送配置失败，用环境变量默认值: %s", exc)
            return env_defaults()
    try:
        with SessionLocal() as session:
            return _read(session)
    except Exception as exc:  # noqa: BLE001
        log.warning("读智能体推送配置失败，用环境变量默认值: %s", exc)
        return env_defaults()


def save_config(db: Session, params: dict[str, Any]) -> dict[str, Any]:
    """存配置（整份覆盖 ``agent_push.params``）。"""
    row = db.get(SystemConfig, CONFIG_KEY)
    if row is None:
        row = SystemConfig(key=CONFIG_KEY, value={})
        db.add(row)
    row.value = {"value": params, "updated_at": datetime.now(UTC).isoformat()}
    db.commit()
    return load_config(db)


def is_on(cfg: dict[str, Any]) -> bool:
    """真正生效的判据：开关打开 **且** 配了地址（只开开关不填地址等于没配）。"""
    return bool(cfg.get("enabled")) and bool(str(cfg.get("url") or "").strip())


def ping_url(url: str) -> str:
    """由推送地址推出连通性自检地址（``/api/push/digests`` → ``/api/push/ping``）。"""
    base = str(url or "").strip()
    if base.endswith("/digests"):
        return f"{base[: -len('/digests')]}/ping"
    return f"{base.rstrip('/')}/ping"


def mask_token(token: str) -> str:
    """界面回显用：只露头尾，避免整串令牌进前端/日志。"""
    raw = str(token or "")
    if not raw:
        return ""
    if len(raw) <= 8:
        return "*" * len(raw)
    return f"{raw[:4]}{'*' * 6}{raw[-2:]}"


def build_items(digests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """推送载荷：每条摘要配一个事件 ID（UUID）与摘要指纹（指纹给智能体日志用）。"""
    return [
        {
            "event_id": str(uuid.uuid4()),
            "fingerprint": digest_fingerprint(d) or "",
            "digest": d,
        }
        for d in digests
    ]


def push_batch(cfg: dict[str, Any], digests: list[dict[str, Any]], *, timeout: float = 0.0) -> tuple[bool, str]:
    """推一批摘要：2xx 即成功。返回 (是否成功, 失败说明)。"""
    url = str(cfg.get("url") or "").strip()
    if not url:
        return False, "未配置推送地址"
    headers = {"Content-Type": "application/json"}
    token = str(cfg.get("token") or "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    limit = timeout or float(cfg.get("timeout_seconds") or 10.0)
    try:
        resp = httpx.post(
            url,
            json={"items": build_items(digests)},
            headers=headers,
            timeout=limit,
        )
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)[:200]
    if 200 <= resp.status_code < 300:
        return True, ""
    return False, f"HTTP {resp.status_code}: {resp.text[:200]}"


def ping(cfg: dict[str, Any], override_url: str = "") -> tuple[bool, str]:
    """连通性自检：``GET {ping_url}`` 带令牌。"""
    url = ping_url(override_url or str(cfg.get("url") or ""))
    headers: dict[str, str] = {}
    token = str(cfg.get("token") or "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = httpx.get(url, headers=headers, timeout=float(cfg.get("timeout_seconds") or 10.0))
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)[:200]
    if 200 <= resp.status_code < 300:
        return True, resp.text[:200]
    return False, f"HTTP {resp.status_code}: {resp.text[:200]}"


# ---------- 状态计数（Redis，界面读） ----------


def record(client: Any, kind: str, count: int, error: str = "") -> None:
    """记一笔推送状态。kind: sent / queued / retried / retry_failed。"""
    if count <= 0:
        return
    now = datetime.now(UTC).isoformat()
    try:
        key = settings.detector_push_stats_key
        client.hincrby(key, kind, count)
        if kind in ("sent", "retried"):
            client.hset(key, mapping={"last_success_at": now})
        else:
            client.hset(key, mapping={"last_error": error[:300], "last_error_at": now})
        client.expire(key, _STATS_TTL)
    except Exception as exc:  # noqa: BLE001
        log.debug("写推送状态失败: %s", exc)


def status(client: Any) -> dict[str, Any]:
    """把 Redis 里的计数与队列深度整理成界面能直接显示的一份状态。"""
    out: dict[str, Any] = {
        "sent": 0,
        "queued": 0,
        "retried": 0,
        "retry_failed": 0,
        "last_success_at": "",
        "last_error_at": "",
        "last_error": "",
        "queue_depth": 0,
        "processing_depth": 0,
    }
    try:
        raw = client.hgetall(settings.detector_push_stats_key) or {}
        for key in ("sent", "queued", "retried", "retry_failed"):
            try:
                out[key] = int(raw.get(key) or 0)
            except (TypeError, ValueError):
                out[key] = 0
        for key in ("last_success_at", "last_error_at", "last_error"):
            out[key] = str(raw.get(key) or "")
        out["queue_depth"] = int(client.llen(settings.detector_push_retry_queue))
        out["processing_depth"] = int(client.llen(settings.detector_push_processing_queue))
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)[:200]
    return out


# ---------- 投递与重发 ----------


def _enqueue_retry(client: Any, digests: list[dict[str, Any]]) -> bool:
    """推送失败的摘要落持久重试队列（成功返回 True；Redis 也挂了返回 False）。"""
    payload = json.dumps(digests, ensure_ascii=False, default=str)
    try:
        client.lpush(settings.detector_push_retry_queue, payload)
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("推送失败且落重试队列也失败（摘要将放回检测队列）: %s", exc)
        return False


def deliver(client: Any, digests: list[dict[str, Any]], stats: dict[str, int]) -> tuple[str, str]:
    """把一批摘要推给智能体。

    返回 ``(结果, 说明)``，结果取值：
    - ``off``：没配地址/关了开关 → 调用方走旧的 Redis 队列路径
    - ``pushed``：全部推成功（2xx）
    - ``queued``：部分/全部失败，但失败的都已落持久重试队列 → 调用方可以安全 ack
    - ``lost``：失败且落重试队列也失败 → 调用方必须把摘要放回检测队列
    """
    cfg = load_config()
    if not is_on(cfg):
        return "off", "未配置推送地址或已关闭"
    size = max(1, int(cfg.get("max_per_push") or 200))
    pushed = queued = lost = 0
    last_error = ""
    for start in range(0, len(digests), size):
        chunk = digests[start : start + size]
        ok, err = push_batch(cfg, chunk)
        if ok:
            pushed += len(chunk)
            continue
        last_error = err
        if _enqueue_retry(client, chunk):
            queued += len(chunk)
        else:
            lost += len(chunk)
    if pushed:
        record(client, "sent", pushed)
    if queued:
        record(client, "queued", queued, last_error)
    if lost:
        stats["push_lost"] = stats.get("push_lost", 0) + lost
    if queued:
        stats["push_queued"] = stats.get("push_queued", 0) + queued
    if pushed and not queued and not lost:
        return "pushed", ""
    if lost:
        return "lost", last_error
    return "queued", last_error


def retry_pending(
    client: Any,
    stats: dict[str, int],
    *,
    limit: int = 0,
    log_result: bool = True,
) -> dict[str, int]:
    """后台重发：把重试队列里的批再推一次，成功出队、失败放回队尾（下轮再试）。

    一次调用最多试 ``limit``（默认 ``detector_push_retry_max_per_round``）批；
    遇到失败就停（多半是智能体整体不可达，继续试只是空转烧 Redis）。
    启动时 ``recover()`` 把上次没确认的批回灌队列，所以进程被杀不会丢。
    """
    out = {"tried": 0, "sent": 0, "failed": 0}
    cfg = load_config()
    if not is_on(cfg):
        return out
    q = ReliableQueue(
        client,
        settings.detector_push_retry_queue,
        settings.detector_push_processing_queue,
    )
    try:
        q.recover()
    except Exception as exc:  # noqa: BLE001
        log.warning("回灌推送重试队列失败: %s", exc)
        return out
    cap = limit or max(1, int(settings.detector_push_retry_max_per_round))
    while out["tried"] < cap:
        payload = q.try_consume()
        if payload is None:
            break
        out["tried"] += 1
        try:
            digests = json.loads(payload)
        except (TypeError, ValueError):
            q.ack(payload)
            continue
        if not isinstance(digests, list) or not digests:
            q.ack(payload)
            continue
        batch = [d for d in digests if isinstance(d, dict)]
        if not batch:
            q.ack(payload)
            continue
        ok, err = push_batch(cfg, batch)
        if ok:
            q.ack(payload)
            out["sent"] += len(batch)
            record(client, "retried", len(batch))
            continue
        q.requeue(payload)
        out["failed"] += len(batch)
        record(client, "retry_failed", len(batch), err)
        break
    if out["sent"]:
        stats["push_retried"] = stats.get("push_retried", 0) + out["sent"]
    if out["tried"] and log_result:
        log.info(
            "推送重发：试了 %d 批，成功 %d 条，失败 %d 条（队列剩 %d 批）",
            out["tried"],
            out["sent"],
            out["failed"],
            status(client).get("queue_depth", 0),
        )
    return out
