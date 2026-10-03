"""第 5 期：检测器把聚合摘要经 **HTTP** 推给智能体（取代 Redis 队列交接）。

交接契约的变化（两侧必须一起升级）：

- 旧（已退役）：``LPUSH shentong:events:dispatch`` → 智能体 ``app.consumer``（BRPOPLPUSH）跑图，
  跑完回传 ``shentong:analyzed:done`` 当回执。两侧均已删除 ``consumer`` / ``AnalyzedRegistry``；
  **本侧也不再写这个队列**——「没配地址 / 开关关闭」时摘要记入 ``undelivered`` 计数并告警，
  不再假称「已投递」（那个队列已经没有消费者，写进去只会让统计看起来成功）。
- 新：``POST {地址}`` 带 ``Authorization: Bearer {令牌}``，**收到 2xx 即成功**（响应就是回执）。
  推送失败落本模块的持久重试队列（``shentong:events:pushretry``），由检测循环后台重发。
  重试队列有硬上限；重发区分两类失败：**整体不可达**（连接失败/超时/5xx）→ 放回队尾并结束本轮
  （智能体整体不可达时空转没意义），**单批永久失败**（如持续 4xx 的坏批）→ 延后到队尾之后，
  连试 ``_RETRY_MAX_ATTEMPTS`` 次仍失败即判 ``lost``（计数可查，不再永久堵在队首）。

为什么要把回执从「队列消费掉」换成「HTTP 2xx」：跨库拆分后「这个指纹分析过没有」只有
智能体自己知道（结论、报告都在它的库里）。NDR 侧那份 ``AnalyzedRegistry`` 闸门因此退役
（见 ``docs/ndr-redesign.md`` 第 5 期），判重落到智能体接收端点。

配置存 ``system_config``（键 ``agent_push.params``），环境变量只作默认值：
地址形如 ``http://agent:8000/api/push/digests``；**地址留空 = 不推送**：摘要不再投递，
落到 ``undelivered`` 计数（在 ``/api/agent-push`` 状态与检测器 dropped 里都能看到），
不会假装成功、也不会再写那条已退役的 Redis 队列。
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

# 重试队列硬上限（批数）：智能体长期不可达时防止 Redis 被撑满。
# 为什么先放模块常量：``config.py`` 不在本轮修复的改动范围内；要变成可调配置项，就在
# config.py 增 ``detector_push_retry_queue_max`` 再引用它。超限时丢**最老**的批并计
# ``retry_dropped``（丢的是最旧的待重发批，保留最新的）。
_RETRY_QUEUE_MAX = 2000

# 单批「永久失败」（如持续 4xx 的坏批）最多试几次：超过即判 ``lost``（计数 + 丢弃），
# 不再让它一直堵在队首拖死后面的健康批。整体不可达（网络错/5xx）不走这条路。
_RETRY_MAX_ATTEMPTS = 5

# 重发串行锁：检测循环与 ``/api/agent-push/retry`` 共用同一条重发路径；没锁时两边会同时
# 从 processing 队里抢同一批，同一批摘要被推两次。
_LOCK_KEY = "shentong:events:pushretry:lock"
_LOCK_TTL = 120

# 重试载荷格式版本：v2 形如 ``{"v":2,"digests":[...],"attempts":N}``；
# 兼容期还要能读旧格式（裸列表 ``[...]``，视作 attempts=0）。
_PAYLOAD_V = 2


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
    """记一笔推送状态。kind: sent / queued / retried / retry_failed / retry_lost /
    retry_dropped / undelivered（后四者也写 last_error，便于界面直接看到原因）。"""
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
    """把 Redis 里的计数与队列深度整理成界面能直接显示的一份状态。

    除 ``queue_depth``/``processing_depth``/``retry_backlog_batches`` 外，
    其余计数（``sent``/``queued``/``retried``/``retry_failed``/``retry_lost``/
    ``retry_dropped``/``undelivered``）都是**自 Redis 计数以来的累计值**，不是当下积压：
    要显示「还堆着多少」请用 ``retry_backlog_batches``（= queue_depth + processing_depth）。
    """
    out: dict[str, Any] = {
        "sent": 0,
        "queued": 0,
        "retried": 0,
        "retry_failed": 0,
        "retry_lost": 0,
        "retry_dropped": 0,
        "undelivered": 0,
        "last_success_at": "",
        "last_error_at": "",
        "last_error": "",
        "queue_depth": 0,
        "processing_depth": 0,
        "retry_backlog_batches": 0,
    }
    try:
        raw = client.hgetall(settings.detector_push_stats_key) or {}
        counters = (
            "sent",
            "queued",
            "retried",
            "retry_failed",
            "retry_lost",
            "retry_dropped",
            "undelivered",
        )
        for key in counters:
            try:
                out[key] = int(raw.get(key) or 0)
            except (TypeError, ValueError):
                out[key] = 0
        for key in ("last_success_at", "last_error_at", "last_error"):
            out[key] = str(raw.get(key) or "")
        out["queue_depth"] = int(client.llen(settings.detector_push_retry_queue))
        out["processing_depth"] = int(client.llen(settings.detector_push_processing_queue))
        out["retry_backlog_batches"] = int(out["queue_depth"]) + int(out["processing_depth"])
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)[:200]
    return out


# ---------- 投递与重发 ----------


def _pack(digests: list[dict[str, Any]], *, attempts: int = 0, last_error: str = "") -> str:
    """重试队列的载荷（v2）：带上尝试次数，好区分「整体不可达」与「坏批」。"""
    return json.dumps(
        {
            "v": _PAYLOAD_V,
            "digests": digests,
            "attempts": max(0, int(attempts)),
            "last_error": str(last_error or "")[:200],
        },
        ensure_ascii=False,
        default=str,
    )


def _unpack(payload: str) -> tuple[list[dict[str, Any]], int, str]:
    """解析重试载荷，兼容旧格式（裸列表视作 attempts=0）；解析不出来返回空列表。"""
    try:
        raw = json.loads(payload)
    except (TypeError, ValueError):
        return [], 0, ""
    if isinstance(raw, dict):
        digests = raw.get("digests")
        try:
            attempts = int(raw.get("attempts") or 0)
        except (TypeError, ValueError):
            attempts = 0
        err = str(raw.get("last_error") or "")
    else:
        digests, attempts, err = raw, 0, ""
    if not isinstance(digests, list):
        return [], 0, ""
    return [d for d in digests if isinstance(d, dict)], max(0, attempts), err


def _is_transient(err: str) -> bool:
    """失败是「智能体整体不可达」还是「这一批永久失败」。

    - 连接失败/超时/HTTP 5xx/408/429 → 整体不可达（放回队尾，结束本轮，下轮再试）
    - HTTP 4xx（地址配错、鉴权失败、载荷被拒）→ 这一批永久失败，延后并计次，别堵住队首
    """
    raw = str(err or "").strip()
    if not raw.upper().startswith("HTTP "):
        return True
    try:
        code = int(raw.split()[1].rstrip(":"))
    except (IndexError, ValueError):
        return True
    if code in (408, 429):
        return True
    return code >= 500


def _trim_retry_queue(client: Any, cap: int | None = None) -> int:
    """把重试队列裁到上限（LPUSH 头部是最新：保留最新、丢最老），返回被丢掉的批数。"""
    limit = max(1, int(_RETRY_QUEUE_MAX if cap is None else cap))
    try:
        depth = int(client.llen(settings.detector_push_retry_queue))
        if depth <= limit:
            return 0
        client.ltrim(settings.detector_push_retry_queue, 0, limit - 1)
        return depth - limit
    except Exception as exc:  # noqa: BLE001
        log.debug("裁剪推送重试队列失败: %s", exc)
        return 0


def _acquire_drain_lock(client: Any) -> str:
    """抢「谁在重发」的锁：抢到返回持有令牌，没抢到返回空串。"""
    token = uuid.uuid4().hex
    try:
        if client.set(_LOCK_KEY, token, nx=True, ex=_LOCK_TTL):
            return token
    except Exception as exc:  # noqa: BLE001
        log.debug("抢重发锁失败（按没抢到处理）: %s", exc)
    return ""


def _release_drain_lock(client: Any, token: str) -> None:
    """只释放自己的锁（令牌对得上才删，避免删掉别人的）。"""
    if not token:
        return
    try:
        if client.get(_LOCK_KEY) == token:
            client.delete(_LOCK_KEY)
    except Exception as exc:  # noqa: BLE001
        log.debug("释放重发锁失败: %s", exc)


def _enqueue_retry(
    client: Any,
    digests: list[dict[str, Any]],
    *,
    error: str = "",
    stats: dict[str, int] | None = None,
) -> bool:
    """推送失败的摘要落持久重试队列（成功返回 True；Redis 也挂了返回 False）。

    队列有硬上限：超限时丢最老的批（``ltrim 0..cap-1``，LPUSH 头部是最新），并计
    ``retry_dropped``——「有摘要再也不会被重发」这件事必须在界面上看得见。
    """
    payload = _pack(digests, last_error=error)
    try:
        client.lpush(settings.detector_push_retry_queue, payload)
    except Exception as exc:  # noqa: BLE001
        log.warning("推送失败且落重试队列也失败（摘要将放回检测队列）: %s", exc)
        return False
    dropped = _trim_retry_queue(client)
    if dropped:
        record(client, "retry_dropped", dropped, "重试队列超上限，丢弃最老的待重发批")
        if stats is not None:
            stats["push_lost"] = stats.get("push_lost", 0) + dropped
    return True


def recover_pending(client: Any) -> int:
    """启动时把上次没确认的重发批从 processing 回灌队列（进程被杀不丢摘要）。

    只在主循环开始前调一次：``retry_pending()`` 不再隐含 ``recover()``——原来是每轮都回灌，
    会和 ``/api/agent-push/retry`` 抢同一批 processing，同一批摘要被推两次。
    """
    q = ReliableQueue(
        client,
        settings.detector_push_retry_queue,
        settings.detector_push_processing_queue,
    )
    try:
        return int(q.recover() or 0)
    except Exception as exc:  # noqa: BLE001
        log.warning("回灌推送重试队列失败: %s", exc)
        return 0


def deliver(client: Any, digests: list[dict[str, Any]], stats: dict[str, int]) -> tuple[str, str]:
    """把一批摘要推给智能体。

    返回 ``(结果, 说明)``，结果取值：
    - ``off``：没配地址/关了开关 → **没投递**：调用方必须记 ``undelivered`` 并告警，
      不能再写那条已退役的 ``shentong:events:dispatch``（没有消费者，写进去只是假成功）
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
        if _enqueue_retry(client, chunk, error=err, stats=stats):
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
) -> dict[str, Any]:
    """后台重发：把重试队列里的批再推一次。

    一次调用最多试 ``limit``（默认 ``detector_push_retry_max_per_round``）批。失败分两类：

    - **整体不可达**（连接失败/超时/5xx/408/429）：该批放回队尾并**结束本轮**——继续试只是
      空转烧 Redis（``docs/ndr-redesign.md`` 第 5 期定的行为）；
    - **单批永久失败**（持续 4xx）：把它挪到「最新」一端并累加尝试次数，让后面的健康批先走；
      试满 ``_RETRY_MAX_ATTEMPTS`` 次仍失败就判 ``lost``（计数 + 丢弃），不再永久堵队首。

    整轮重发用 Redis 锁串行化：检测循环与 ``/api/agent-push/retry`` 不会再抢同一批 processing。
    启动回灌改成显式 ``recover_pending()``，这里不再每轮隐式 ``recover()``。

    返回 ``{"tried","sent","failed","lost","locked"}``（locked=True 表示别的重发正在进行）。
    """
    out: dict[str, Any] = {"tried": 0, "sent": 0, "failed": 0, "lost": 0, "locked": False}
    cfg = load_config()
    if not is_on(cfg):
        return out
    token = _acquire_drain_lock(client)
    if not token:
        out["locked"] = True
        return out
    try:
        q = ReliableQueue(
            client,
            settings.detector_push_retry_queue,
            settings.detector_push_processing_queue,
        )
        cap = limit or max(1, int(settings.detector_push_retry_max_per_round))
        deferred: set[str] = set()
        while out["tried"] < int(cap):
            payload = q.try_consume()
            if payload is None:
                break
            if payload in deferred:
                # 本轮已经试过它一次（挪到最新端后又被取到）→ 队列里没有别的可试了
                q.requeue(payload)
                break
            batch, attempts, _last_error = _unpack(payload)
            if not batch:
                q.ack(payload)
                continue
            out["tried"] += 1
            ok, err = push_batch(cfg, batch)
            if ok:
                q.ack(payload)
                out["sent"] += len(batch)
                record(client, "retried", len(batch))
                continue
            if _is_transient(err):
                q.requeue(payload)
                out["failed"] += len(batch)
                record(client, "retry_failed", len(batch), err)
                break
            attempts += 1
            if attempts >= max(1, int(_RETRY_MAX_ATTEMPTS)):
                q.ack(payload)
                out["lost"] += len(batch)
                record(client, "retry_lost", len(batch), f"连续 {attempts} 次永久失败：{err}")
                stats["push_lost"] = stats.get("push_lost", 0) + len(batch)
                continue
            packed = _pack(batch, attempts=attempts, last_error=err)
            q.push(packed)  # 挪到「最新」一端：后面的健康批先走，不堵队首
            q.ack(payload)
            deferred.add(packed)
            out["failed"] += len(batch)
            record(client, "retry_failed", len(batch), err)
    finally:
        _release_drain_lock(client, token)
    if out["sent"]:
        stats["push_retried"] = stats.get("push_retried", 0) + int(out["sent"])
    if out["tried"] and log_result:
        log.info(
            "推送重发：试了 %d 批，成功 %d 条，失败 %d 条，判丢 %d 条（队列剩 %d 批）",
            out["tried"],
            out["sent"],
            out["failed"],
            out["lost"],
            status(client).get("queue_depth", 0),
        )
    return out
