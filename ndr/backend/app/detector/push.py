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
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
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


def push_batch(
    cfg: dict[str, Any], digests: list[dict[str, Any]], *, timeout: float = 0.0
) -> tuple[bool, str]:
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
        "spool_batches": 0,
        "spool_bytes": 0,
        "spool_oldest_age": 0,
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
        out.update(spool_stats())
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
            # 入队时间：老化判据（队列里待超过 detector_push_age_seconds 就落磁盘缓存）
            "queued_at": _spool_now_iso(),
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


# ---------- 摘要老化与磁盘缓存 ----------
# 2026-10 用户口径：摘要在队列里最多待 5 分钟。超时（推送不成功、或智能体没连上）就从 Redis
# 挪到**磁盘缓存**，别再占 Redis 内存；等智能体能正常响应（任一批推送成功）后，从磁盘按**先
# 后顺序**补推，推成功即从缓存里删掉。这样：内存有界、磁盘上不丢、智能体恢复后自动补齐。
_SPOOL_NAME = "push-spool.jsonl"
# 老化扫描的节流（秒）：扫描要 lrange 整个重试队列，不能每条命中都扫
_SPOOL_SWEEP_INTERVAL = 30.0
_last_spool_sweep = 0.0


def _spool_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _spool_path() -> Path:
    return Path(str(settings.detector_push_spool_dir)) / _SPOOL_NAME


def _spool_append(payload: str) -> bool:
    """把一批摘要追加到磁盘缓存。返回是否写成功（写不进去就留在队列里，不做静默丢弃）。"""
    path = _spool_path()
    line = json.dumps(
        {"spooled_at": _spool_now_iso(), "payload": payload}, ensure_ascii=False, default=str
    )
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        limit = max(1, int(settings.detector_push_spool_max_mb)) * 1024 * 1024
        if path.exists() and path.stat().st_size + len(line.encode("utf-8")) > limit:
            log.warning(
                "磁盘缓存已满（%s MB），摘要保留在队列中", settings.detector_push_spool_max_mb
            )
            return False
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return True
    except OSError as exc:
        log.warning("摘要落磁盘缓存失败: %s", exc)
        return False


def _spool_read() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    try:
        path = _spool_path()
        if not path.exists():
            return rows
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except ValueError:
                    continue
                if isinstance(raw, dict) and raw.get("payload"):
                    rows.append(
                        {
                            "spooled_at": str(raw.get("spooled_at") or ""),
                            "payload": str(raw["payload"]),
                        }
                    )
    except OSError as exc:
        log.debug("读磁盘缓存失败: %s", exc)
    return rows


def _spool_write(rows: list[dict[str, str]]) -> None:
    """重写磁盘缓存（只剩还没补推成功的行）；空了就删文件。"""
    path = _spool_path()
    try:
        if not rows:
            path.unlink(missing_ok=True)
            return
        tmp = path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
        tmp.replace(path)
    except OSError as exc:
        log.warning("重写磁盘缓存失败: %s", exc)


# 磁盘缓存的规模缓存：键=路径，值=((mtime, size), 批数, 最早入缓存时间戳)。
# 为什么缓存：`status()` 会被健康检查/界面反复调用，而缓存文件可能涨到很大；
# 只要 mtime/size 没变就直接复用，避免每次把整个文件读一遍。
_spool_stat_cache: dict[str, tuple[tuple[float, int], int, float]] = {}


def spool_stats() -> dict[str, Any]:
    """磁盘缓存的当下规模（界面/体检要能看到“还有多少没补推”）。"""
    out: dict[str, Any] = {"spool_batches": 0, "spool_bytes": 0, "spool_oldest_age": 0}
    path = _spool_path()
    try:
        st = path.stat()
    except OSError:
        _spool_stat_cache.pop(str(path), None)
        return out
    key = (st.st_mtime, st.st_size)
    cached = _spool_stat_cache.get(str(path))
    if cached is not None and cached[0] == key:
        batches, oldest_ts = cached[1], cached[2]
    else:
        rows = _spool_read()
        batches = len(rows)
        oldest_ts = 0.0
        if rows:
            try:
                oldest_ts = datetime.fromisoformat(rows[0].get("spooled_at") or "").timestamp()
            except (TypeError, ValueError):
                oldest_ts = 0.0
        _spool_stat_cache[str(path)] = (key, batches, oldest_ts)
    out["spool_batches"] = batches
    out["spool_bytes"] = int(st.st_size)
    if batches and oldest_ts:
        out["spool_oldest_age"] = max(0, int(time.time() - oldest_ts))
    return out


def _queued_ts(payload: str) -> float | None:
    """载荷的入队时间戳；老载荷没有这个字段（返回 None，按“已超龄”处理）。"""
    try:
        raw = json.loads(payload)
    except (TypeError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    stamp = raw.get("queued_at")
    if not stamp:
        return None
    try:
        return datetime.fromisoformat(str(stamp)).timestamp()
    except (TypeError, ValueError):
        return None


def age_out_to_spool(client: Any, stats: dict[str, int], *, force: bool = False) -> int:
    """把在队列里待超过老化时间的摘要挪到磁盘缓存，返回挪走的批数。

    只挪「推送不成功或智能体连不上」而堆在队列里的那些；正常几秒内就送出去的批不受影响。
    """
    global _last_spool_sweep
    now = time.time()
    if not force and now - _last_spool_sweep < _SPOOL_SWEEP_INTERVAL:
        return 0
    _last_spool_sweep = now
    cutoff = now - max(30, int(settings.detector_push_age_seconds or 300))
    moved = 0
    try:
        payloads = list(client.lrange(settings.detector_push_retry_queue, 0, -1))
    except Exception as exc:  # noqa: BLE001
        log.debug("老化扫描读队列失败: %s", exc)
        return 0
    for payload in payloads:
        stamp = _queued_ts(str(payload))
        if stamp is not None and stamp >= cutoff:
            continue  # 还没超龄
        if not _spool_append(str(payload)):
            continue  # 磁盘写不进去就留在队列里（宁可占内存，也不静默丢）
        try:
            client.lrem(settings.detector_push_retry_queue, 1, payload)
        except Exception as exc:  # noqa: BLE001
            log.debug("从队列移出超龄批失败: %s", exc)
            break
        moved += 1
    if moved:
        record(client, "aged_to_spool", moved, "超龄摘要转入磁盘缓存")
        stats["push_spooled"] = stats.get("push_spooled", 0) + moved
        log.info(
            "摘要老化：%d 批转入磁盘缓存（队列剩 %d 批）",
            moved,
            status(client).get("queue_depth", 0),
        )
    return moved


def replay_spool(client: Any, stats: dict[str, int], *, limit: int = 0) -> dict[str, int]:
    """智能体确认可达后，把磁盘缓存里的摘要按序补推；成功的行删掉，第一批失败就停。

    返回 ``{"sent": n}``。只在**推送真的成功过**之后调用——失败就继续留在磁盘上等下次。
    单轮最多补推 ``limit`` 批（默认取 ``detector_push_retry_max_per_round``）：补推是在检测
    循环里同步做的，缓存厚的时候不能一轮全推完，否则把检测循环卡住。
    """
    out = {"sent": 0}
    cfg = load_config()
    if not is_on(cfg):
        return out
    rows = _spool_read()
    if not rows:
        return out
    default_cap = max(1, int(settings.detector_push_retry_max_per_round or 50))
    cap = int(limit) if int(limit) > 0 else min(default_cap, len(rows))
    consumed = 0
    for row in rows[:cap]:
        batch, _attempts, _err = _unpack(row["payload"])
        if not batch:
            consumed += 1  # 坏行直接跳过并清掉
            continue
        ok, err = push_batch(cfg, batch)
        if not ok:
            log.info("磁盘缓存补推失败，继续留在磁盘等下次：%s", err)
            break
        consumed += 1
        out["sent"] += len(batch)
        record(client, "spool_sent", len(batch))
    if consumed:
        _spool_write(rows[consumed:])
    if out["sent"]:
        stats["push_spool_sent"] = stats.get("push_spool_sent", 0) + int(out["sent"])
        log.info("磁盘缓存补推成功 %d 条摘要（缓存还剩 %d 批）", out["sent"], len(rows) - consumed)
    return out


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
        # 这一批送成功了 ⇒ 判定「智能体可达」：先把磁盘缓存里积压的摘要按序补推
        replay_spool(client, stats)
    # 队列里待太久的摘要挪到磁盘（每 30 秒最多扫一次）
    age_out_to_spool(client, stats)
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
    age_out_to_spool(client, stats)
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
        replay_spool(client, stats)
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
