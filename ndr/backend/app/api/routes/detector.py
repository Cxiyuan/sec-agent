"""检测器运行状态：队列深度、投递速率、丢弃计数。

目的：让「事件被丢弃 / 未进入分析」可见（此前只写一行统计日志，无法查询、无告警）。
数据全部从 Redis 读，不依赖检测器进程存活。
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from app import triage_policy
from app.api.deps import get_current_user
from app.config import settings
from app.db.models import User
from app.detector import health
from app.detector.runner import FAILED_KEY, PAUSED_KEY, rate_bucket
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/detector", tags=["detector"])


def _window_estimate(d_delivered: float, interval: float, window_seconds: float) -> float | None:
    """把「最近一个统计区间的投递增量」折算成请求窗口内的投递量（QA 应修 4）。

    这是 coverage 量纲对齐的核心：ES 侧数的是窗口内文档，分子也必须是窗口内增量。
    ``interval<=0``（快照缺字段/旧格式）返回 None，让上层明确「算不出来」而不是拿 0 去比。
    """
    if interval <= 0:
        return None
    return max(0.0, float(d_delivered)) * (float(window_seconds) / float(interval))


def _snapshot_stale(snapshot_age: float | None, interval: float) -> bool:
    """统计快照是否已过期：超过两个统计区间、且至少 900 秒没更新。"""
    if interval <= 0 or snapshot_age is None:
        return False
    return snapshot_age > max(2 * interval, 900.0)


@router.get("/coverage")
def detector_coverage(
    _: Annotated[User, Depends(get_current_user)],
    minutes: int = 60,
):
    """漏报兑底率：窗口内「已投递摘要数」vs 窗口内 ES 命中文档数（含丢弃计数）。

    语义：比率 <1 是正常的（策略跳过、聚合归并都会减少落库事件），看的是**趋势突变**
    （比率骤降 = 大批事件没进分析），所以同时返回容量性丢弃计数供对照。

    量纲必须一致（QA 应修 4）：ES 侧是「窗口内」计数，分子也必须是窗口内增量。原来分子取
    `shentong:detector:rates` 里的**累计** delivered —— 实机出现
    `delivered_total=5 / es_docs=55251 → ratio 0.0 / warn=true` 的恒假警。
    现在用最近一个统计区间的 `d_delivered` 折算出窗口增量；快照过期就明确标注、不下判警。
    """
    from datetime import UTC, datetime, timedelta

    from app.config import settings

    window_minutes = max(5, min(int(minutes or 60), 1440))
    since = datetime.now(UTC) - timedelta(minutes=window_minutes)
    window_seconds = window_minutes * 60.0
    out: dict[str, Any] = {"minutes": minutes, "since": since.isoformat()}
    # 已投递摘要数（ndr 视角的"进入分析"计数；事件组/案件口径在 agent 侧）
    delivered_total = 0
    d_delivered = 0.0
    interval = 0.0
    snapshot_age: float | None = None
    try:
        import redis as _redis

        _c = _redis.Redis.from_url(settings.redis_url, decode_responses=True)
        snap = _c.hgetall("shentong:detector:rates")
        if isinstance(snap, dict):
            delivered_total = int(float(snap.get("delivered") or 0))
            d_delivered = float(snap.get("d_delivered") or 0)
            interval = float(snap.get("interval_seconds") or 0)
            if snap.get("ts"):
                try:
                    snapshot_age = datetime.now(UTC).timestamp() - float(snap["ts"])
                except (TypeError, ValueError):
                    snapshot_age = None
    except Exception:  # noqa: BLE001
        # Redis 不可用时回退 0（与 log.py 的 fail-open 回退同一套风格）
        delivered_total = 0
    out["delivered_total"] = delivered_total
    out["delivered_interval"] = int(d_delivered)
    out["interval_seconds"] = round(interval, 1) if interval > 0 else None
    out["snapshot_age_seconds"] = round(snapshot_age, 1) if snapshot_age is not None else None
    # 快照超过两个统计周期（且至少 900s）没更新 → 检测器可能已停，计数不可信
    stale = _snapshot_stale(snapshot_age, interval)
    out["stale"] = stale
    delivered_window = _window_estimate(d_delivered, interval, window_seconds)
    out["delivered_window_est"] = (
        round(delivered_window, 1) if delivered_window is not None else None
    )
    es_docs: int | None = None
    try:
        from app.ingestion import es_config
        from app.ingestion.es_client import get_es

        cfg = es_config.current()
        pattern = str(cfg.get("es.events_index") or settings.es_events_index)
        resp = get_es().count(
            index=pattern,
            query={"range": {"@timestamp": {"gte": since.isoformat()}}},
        )
        es_docs = int(resp.get("count") or 0)
    except Exception as exc:  # noqa: BLE001
        out["es_error"] = str(exc)[:200]
    out["es_docs"] = es_docs
    if es_docs and delivered_window is not None and not stale:
        ratio = float(delivered_window) / float(es_docs)
        out["coverage_ratio"] = round(ratio, 3)
        out["warn"] = ratio < float(settings.detector_coverage_warn_ratio)
    elif stale:
        # 快照过期时旧口径会算出 ratio≈0 的假警，这里明确说「不判警」而不是发一个假告警
        out["coverage_ratio"] = None
        out["warn"] = False
        out["warn_reason"] = (
            f"检测器统计快照已过期（{out['snapshot_age_seconds']}s 未更新），投递计数不可信，不判警"
        )
    else:
        out["coverage_ratio"] = None
        out["warn"] = False
    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        out["dropped"] = client.hgetall(settings.detector_drop_key)
    except Exception as exc:  # noqa: BLE001
        out["dropped_error"] = str(exc)[:200]
    return out


@router.get("/rate")
def detector_rate(
    _: Annotated[User, Depends(get_current_user)],
    minutes: int = 10,
):
    """五段速率：入队 / 扫描 / 命中 / 投递 / 分析（哪一段窄，一眼可见）。

    健康形态：入队 ≈ 扫描 > 命中 > 投递 ≈ 分析。
    入队速率用守恒关系推算：入队 ≈ 扫描 + 被裁剪（进了队但没被消费掉的事件）。
    不含队列自身增长——接口拿不到上一时刻的队列深度做基线，所以这是**下界**估计，
    不是原来注释里说的完整守恒（QA 应修 4 顺带修正的注释与实现不符）。
    """
    from datetime import UTC, datetime

    from app.config import settings

    out: dict[str, Any] = {}
    snap: dict[Any, Any] = {}
    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        raw = client.hgetall("shentong:detector:rates")
        snap = dict(raw) if isinstance(raw, dict) else {}
        out["queue_raw"] = int(client.llen(settings.detector_raw_queue) or 0)  # pyright: ignore[reportArgumentType]  # redis-py 同步返回被注为 Awaitable[T] | T
        out["queue_digest"] = int(client.llen(settings.detector_digest_queue) or 0)  # pyright: ignore[reportArgumentType]  # redis-py 同步返回被注为 Awaitable[T] | T
        out["agent_capacity_per_min"] = int(settings.detector_max_digests_per_minute)
    except Exception as exc:  # noqa: BLE001
        out["redis_error"] = str(exc)[:200]

    def _num(key: str) -> float:
        try:
            return float(snap.get(key) or 0)
        except (TypeError, ValueError):
            return 0.0

    window = max(1.0, _num("ts") and (datetime.now(UTC).timestamp() - _num("ts")) or 0.0)
    if window > 0 and snap:
        out["window_seconds"] = round(window, 1)
        out["scanned_per_sec"] = round(_num("scanned") / window, 1)
        out["hits_per_min"] = round(_num("hit") / window * 60.0, 1)
        out["digests_per_min"] = round(_num("digest") / window * 60.0, 1)
        out["delivered_per_min"] = round(_num("delivered") / window * 60.0, 1)
        out["raw_trimmed_total"] = int(_num("raw_trimmed"))
        out["limit_saturated"] = int(_num("limit_saturated"))
        out["requeued_total"] = int(_num("requeued"))
        # 静默降级/丢失的累计口径（未投递 / 处理失败 / 聚合满丢弃），必须可查
        out["undelivered_total"] = int(_num("undelivered"))
        out["failed_total"] = int(_num("failed"))
        out["agg_full_total"] = int(_num("agg_full"))
        # 入队速率（下界）：扫描 + 被裁剪（这些事件入过队但没被消费）
        out["ingest_per_sec_est"] = round(
            float(out["scanned_per_sec"]) + _num("raw_trimmed") / window, 1
        )
    # 覆盖修正：用「区间增量 ÷ 区间秒数」算速率。
    # 原来用 ts-vs-now 反推窗口，检测器重启/刷新周期内窗口失真，曾算出
    # delivered_per_min=471（上限只有 20）这种不可能值。
    interval = _num("interval_seconds") or 0.0
    if interval > 0 and "d_scanned" in snap:

        def _delta2(key: str) -> float:
            try:
                return float(snap.get(key) or 0)
            except (TypeError, ValueError):
                return 0.0

        out["interval_seconds"] = round(interval, 1)
        out["scanned_per_sec"] = round(_delta2("d_scanned") / interval, 1)
        out["hits_per_min"] = round(_delta2("d_hit") / interval * 60.0, 1)
        out["digests_per_min"] = round(_delta2("d_digest") / interval * 60.0, 1)
        out["delivered_per_min"] = round(_delta2("d_delivered") / interval * 60.0, 1)
        out["raw_trimmed_in_interval"] = int(_delta2("d_raw_trimmed"))
        out["ingest_per_sec_est"] = round(
            _delta2("d_scanned") / interval + _delta2("d_raw_trimmed") / interval, 1
        )
    if snap.get("ts"):
        try:
            out["snapshot_age_seconds"] = round(
                datetime.now(UTC).timestamp() - float(snap["ts"]), 1
            )
        except (TypeError, ValueError):
            pass
    if out.get("delivered_per_min") is not None and out.get("agent_capacity_per_min"):
        out["over_capacity"] = out["delivered_per_min"] > float(out["agent_capacity_per_min"])

    # 突发与 SLA 可见性（H3）：队列占用比 / 最后裁剪 / 兜底滞后（SLA 实测值）
    try:
        import json as _json

        import redis as _redis

        _c = _redis.Redis.from_url(settings.redis_url, decode_responses=True)
        cap = max(1, int(settings.detector_raw_queue_max))
        out["queue_raw_pct"] = round(min(100.0, float(out.get("queue_raw") or 0) * 100.0 / cap), 1)
        raw_wins = _c.lrange("shentong:trimmed:windows", 0, 4)
        parsed_wins: list[dict[str, Any]] = []
        for item in raw_wins if isinstance(raw_wins, list) else []:
            try:
                parsed_wins.append(_json.loads(item))
            except (TypeError, ValueError):
                continue
        out["trimmed_windows"] = parsed_wins
        out["last_trimmed_at"] = parsed_wins[0].get("at") if parsed_wins else None
    except Exception as exc:  # noqa: BLE001
        out["trim_error"] = str(exc)[:200]
    out["note"] = "入队≈扫描>命中>投递≈分析 为健康；最小的一段即瓶颈"
    return out


@router.get("/stats")
def get_stats(_: Annotated[User, Depends(get_current_user)]):
    out: dict[str, Any] = {
        "enabled": settings.detector_enabled,
        "queue_raw": None,
        "queue_digest": None,
        "queue_processing": None,
        # 处理失败被隔离的消息数（QA 必修 2）：原来这种消息被静默 ack 丢掉，看不见
        "queue_failed": None,
        # 配置里 detector_enabled=false 时检测器真的停了没有（QA 应修 5）：
        # 过去界面显示"检测关闭"而进程照常消费/推送，现在以这个 Redis 标记为准
        "paused": False,
        "paused_since": None,
        "delivered_this_minute": None,
        "rate_limit_per_minute": settings.detector_max_digests_per_minute,
        "queue_max": settings.detector_queue_max,
        "digest_max_age_seconds": settings.detector_digest_max_age_seconds,
        "dropped": {},
        "last_dropped_at": None,
        # 选主状态：谁在消费（另一个实例在待命热备）
        "leader": None,
        # 判重（第 5 期起）在智能体侧：NDR 只在检测器内做聚合与投递，重复推送由
        # 接收端按事件组指纹吸收（已分析过只累加计数、桶内在跑跳过）。
        # 这里保留形状给界面展示现状；skipped_total 是闸门退役前累计的历史值。
        "dedup": {
            "enabled": False,
            "note": "判重已下放到智能体（按事件组指纹）",
            "inflight_ttl_seconds": 0,
            "skipped_total": 0,
            "last_skipped_at": None,
            "inflight": 0,
            "done": 0,
        },
        # 投递了但分析失败（原来只有一行日志，看不出来是否在漏分析）
        "task_failed": {"failed_total": 0, "last_failed_at": None},
        # 误报治理：策略跳过的数量与最后时间（内网常规流量等）——降噪必须可见
        "policy": {"internal_routine": 0, "last_at": None},
    }
    try:
        import redis

        client: Any = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        out["queue_raw"] = int(client.llen(settings.detector_raw_queue))
        out["queue_digest"] = int(client.llen(settings.detector_digest_queue))
        out["queue_processing"] = int(client.llen(settings.detector_processing_queue))
        out["queue_failed"] = int(client.llen(FAILED_KEY))
        paused_raw = client.get(PAUSED_KEY)
        out["paused"] = bool(paused_raw)
        out["paused_since"] = str(paused_raw) if paused_raw else None
        out["delivered_this_minute"] = int(client.get(rate_bucket()) or 0)
        dropped = client.hgetall(settings.detector_drop_key)
        raw_dropped = dropped if isinstance(dropped, dict) else {}
        out["dropped"] = {
            key: int(val)
            for key, val in raw_dropped.items()
            if key != "last_dropped_at" and str(val).isdigit()
        }
        out["last_dropped_at"] = raw_dropped.get("last_dropped_at")
        holder = client.get(settings.detector_leader_key)
        out["leader"] = {
            "holder": str(holder) if holder else None,
            "ttl_seconds": max(0, int(client.ttl(settings.detector_leader_key) or 0)),
        }
        # 历史值：闸门退役前累计的「省下重复分析」条数（不再增长，仅供对照）
        dedup_raw = client.hgetall(settings.detector_dedup_key)
        dedup_stats = dedup_raw if isinstance(dedup_raw, dict) else {}
        out["dedup"].update(
            {
                "skipped_total": int(dedup_stats.get("skipped") or 0),
                "last_skipped_at": dedup_stats.get("last_skipped_at"),
            }
        )
        failed_raw = client.hgetall(settings.detector_task_failed_key)
        failed_stats = failed_raw if isinstance(failed_raw, dict) else {}
        out["task_failed"].update(
            {
                "failed_total": int(failed_stats.get("failed") or 0),
                "last_failed_at": failed_stats.get("last_failed_at"),
            }
        )
        policy_raw = client.hgetall(triage_policy.POLICY_STATS_KEY)
        policy_stats = policy_raw if isinstance(policy_raw, dict) else {}
        out["policy"] = {
            "internal_routine": int(policy_stats.get("internal_routine") or 0),
            "last_at": policy_stats.get("last_at"),
        }
        # Redis 体检：内存吃满会让整条分析链静默卡死（真实事故），必须一眼可见
        mem = health.redis_memory(client)
        out["redis"] = mem
        out["redis_warn"] = (
            bool(mem.get("max")) and mem.get("perc", 0) >= settings.redis_memory_warn_perc
        )
        try:
            out["handled_skipped"] = int(
                client.get(f"{settings.detector_handled_key}:skipped") or 0
            )
        except (TypeError, ValueError):
            out["handled_skipped"] = 0
    except Exception as exc:  # noqa: BLE001
        log.warning("读取检测器状态失败: %s", exc)
        out["error"] = str(exc)[:200]
    return out
