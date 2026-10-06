"""检测器主循环：消费归一化队列 → 网段过滤 → 规则（逐条+滑窗频率）
→ 短窗聚合 → 攒批投递给智能体分析。

文档由采集侧归一化服务拍平后投进队列（`shentong:events:raw`）；检测器只做
判定与聚合，不再重复归一化（队列里若还压着原始文档，会自动回退归一化）。
替代原来「智能体每 N 分钟主动拉 ES 全量」的入口；智能体只处理被提炼过的
聚合摘要，不再自己捞数据。
"""

from __future__ import annotations

import atexit
import json
import signal
import time
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from app import triage_policy
from app.baseline.engine import BaselineEngine
from app.config import settings
from app.db.base import SessionLocal
from app.detector import health, push
from app.detector.aggregate import Aggregator
from app.detector.fingerprint import digest_age
from app.detector.frequency import FreqWindow
from app.detector.handled import HandledRegistry, doc_hash
from app.detector.history import (
    append as history_append,
    extract_interval_rules,
    mark_digest,
    severity_deltas,
)
from app.detector.leader import Leader
from app.detector.queue import ReliableQueue, make_blocking_client
from app.detector.relay_pairing import RelayDedup
from app.detector.relay_roles import RelayRoleDetector
from app.ingestion import exclusion, log_types
from app.ingestion.es_client import build_networks, in_scope
from app.ingestion.normalizer import normalize, source_of
from app.ingestion.scope import monitored_nets
from app.rules.engine import (
    build_rule_index,
    evaluate_conditions,
    is_count_rule,
    match_rule,
    rules_for_log_type,
    whitelisted,
)
from app.rules.service import get_enabled_rules
from app.schemas import UnifiedLog
from app.workers.log import get_logger

log = get_logger(__name__)

_RATE_KEY = "shentong:detector:delivered"
_BACKLOG_WARN = 50_000
_THROTTLE_LOG_INTERVAL = 60  # 限流/丢弃告警最小间隔（秒），避免刷屏
_last_throttle_log = 0.0
_last_drop_log = 0.0

# 处理失败的消息落到这个隔离队列（有上限，可人工捞回）。
# 原来 except 之后无条件 ack：单条异常即永久丢，且不计任何错误计数（QA 必修 2）。
# 为什么先放模块常量：``config.py`` 不在本轮修复的改动范围内；要做成配置项，
# 就在 config.py 增 ``detector_failed_queue`` / ``detector_failed_max`` 再引用。
FAILED_KEY = "shentong:detector:failed"
_FAILED_MAX = 1000
_FAILED_TTL = 7 * 24 * 3600

# detector_enabled=false 时写这个键（带 TTL）：让「界面说检测已关闭」与
# 「检测器真的没在消费」能在 Redis 里核对（QA 应修 5）。
PAUSED_KEY = "shentong:detector:paused"
_PAUSED_TTL = 300


def _to_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def rate_bucket() -> str:
    """当前分钟桶的键（固定窗口限流计数）。"""
    return f"{_RATE_KEY}:{_to_int(time.time() // 60, 0)}"


def _load_rules() -> dict[str, list[dict[str, Any]]]:
    with SessionLocal() as db:
        rules = get_enabled_rules(db)
    return {
        "per_event": [r for r in rules if not is_count_rule(r)],
        "count": [r for r in rules if is_count_rule(r)],
    }


def _load_scopes() -> list[Any]:
    return build_networks(monitored_nets())


def _with_index(rules: dict[str, Any]) -> dict[str, Any]:
    """给规则表挂上 log_type 索引（幂等，只在规则加载时调用一次）。"""
    if "index" not in rules:
        rules["index"] = build_rule_index(list(rules.get("per_event") or []))
    return rules


def _source_of(doc: dict[str, Any]) -> str:
    """判定日志来源（实现见 `app.ingestion.normalizer.source_of`）。"""
    return source_of(doc)


# 已归一化文档的判别标记：这三个字段同时在场就认为采集侧已经拍平过
_NORMALIZED_MARKERS = ("source_system", "event_type", "raw")


def _to_entry(source: str, doc: dict[str, Any]) -> UnifiedLog | None:
    """拿到归一化后的 entry。

    采集侧的归一化服务已经把文档拍平过一遍，检测器再拍一次纯属浪费 CPU；
    但队列里可能还压着升级前遗留的原始文档（或人工重放的旧数据），
    所以保留「现场归一化」这条兜底路径。
    """
    if all(key in doc for key in _NORMALIZED_MARKERS):
        try:
            return UnifiedLog.model_validate(doc)
        except Exception:  # noqa: BLE001
            log.debug("队列文档带归一化标记但校验失败，按原始文档重新归一化")
    return normalize(source, doc)


def _entry_in_scope(entry: UnifiedLog, nets: list[Any]) -> bool:
    """按归一化后的 src_ip / dst_ip 判网段：任一落在网段内即算监控范围内。

    例外：Wazuh（主机监控）事件不受范围闸门约束 —— 主机监控只收本单位 agent，用 IP 判范围
    对主机侧没有意义（近 6h 1,981 条 Wazuh 告警里带 src_ip 的 0 条，全在这道闸门被丢，
    5 条主机规则 24h 零摘要）。这与日志类型闸门的口径一致：log_types.classify_entry 对
    Wazuh 一律按事件类处理、不套 Zeek 的运维类闸门（见 app/ingestion/log_types.py）。
    """
    if entry.source_system == "wazuh":
        return True
    return in_scope(entry.src_ip, nets) or in_scope(entry.dst_ip, nets)


def run() -> None:
    """常驻循环（由 docker compose 的 detector 服务拉起）。"""
    # 阻塞取队列的客户端：socket 读超时必须大于阻塞超时，否则空队列会抛
    # redis.exceptions.TimeoutError 打崩循环（见 app/detector/queue.py 说明）
    client: Any = make_blocking_client(settings.redis_url, settings.detector_poll_timeout)
    raw_q = ReliableQueue(client, settings.detector_raw_queue, settings.detector_processing_queue)
    digest_q = ReliableQueue(
        client,
        settings.detector_digest_queue,
        f"{settings.detector_digest_queue}:processing",
    )

    handled = HandledRegistry(client, settings.detector_handled_key, settings.detector_handled_ttl)
    freq = FreqWindow(client, settings.freq_window_seconds, settings.freq_cooldown_seconds)
    agg = Aggregator(client, settings.detector_agg_seconds, settings.detector_agg_max_keys)
    # 基线（第 8 期）：数值 2σ 按摘要算、账号/会话画像逐条观测，算完随摘要打标给智能体
    engine = BaselineEngine(client)
    # 中继角色推算：按实际流量自动判定清单里的地址是「反代/WAF」还是「内网 DNS 转发器」，
    # 周期回写 PG（界面只读展示）；见 detector/relay_roles.py
    relay_roles = RelayRoleDetector()
    # 中继去重：保留**有明文内容**的那一侧（2026-10 实机实测：WAF 的客户端侧是 TLS 无 SNI，
    # 只有源站侧有 Host/URI/请求体）；侧向由 relay_roles 按实测内容算，可界面手动覆盖。
    # 见 detector/relay_pairing.py
    relay_dedup = RelayDedup(side_of=relay_roles.side_of)
    # 判重（第 5 期起）在智能体侧：只有它知道某个事件组分析过没有。本侧只负责投递。
    # 多实例选主：只有持锁实例消费队列（其余待命热备），故障后租约到期自动接管
    leader = Leader(client)
    elected = False  # 本次持有租约期间是否已做过启动回灌

    def _on_term(_signum: int, _frame: Any) -> None:
        raise SystemExit(0)  # 让退出路径（atexit）能执行让位

    signal.signal(signal.SIGTERM, _on_term)
    atexit.register(leader.release)
    # 续约走独立线程、按墙上时钟：主循环一轮要消费上千条消息，单轮可能远超租约 TTL，
    # 靠「回到循环顶部再续约」会在一轮超时后被别的实例抢主（QA 应修 7）。
    leader.start_auto_renew()

    rules = _with_index(_load_rules())
    scopes = _load_scopes()
    last_rule_load = time.time()
    last_scope_load = last_rule_load

    stats: Counter[str] = Counter()
    last_flush = time.time()
    last_stats = time.time()
    # 速率快照的上一采样点（用于算"本区间增量"，避免用 ts 反推导致失真）
    rate_prev: dict[str, float] = {
        "ts": last_stats,
        "scanned": 0.0,
        "hit": 0.0,
        "digest": 0.0,
        "delivered": 0.0,
        "raw_trimmed": 0.0,
    }
    log.info(
        "检测器启动：逐条规则 %d 条 / 频率规则 %d 条 / 监控网段 %d 个 / 聚合窗口 %ds",
        len(rules["per_event"]),
        len(rules["count"]),
        len(scopes),
        settings.detector_agg_seconds,
    )

    paused_logged = False
    while True:
        if not settings.detector_enabled:
            # 配置里关掉了：不消费 / 不聚合 / 不投递。原来只有 MCP 与状态端点读这个开关，
            # 界面显示「检测关闭」但循环照常消费推送（QA 应修 5）。
            if not paused_logged:
                log.warning(
                    "检测器已按配置关闭（detector_enabled=false）：不消费队列、不投递摘要；"
                    "置回 true 自动恢复"
                )
                paused_logged = True
            if leader.is_leader:
                leader.release()  # 关闭期间不占租约，让别的实例（若启用）接手
                elected = False
            _mark_paused(client)
            time.sleep(1.0)
            continue
        if paused_logged:
            log.info("检测器已重新启用（detector_enabled=true），恢复消费")
            paused_logged = False
            _clear_paused(client)
        if not leader.try_acquire():
            # 非持锁实例：待命热备，不消费 / 不聚合 / 不投递
            if elected and not leader.is_leader:
                log.warning("检测器已失去主身份，转为待命")
                elected = False
            time.sleep(leader.renew_seconds)
            continue
        if not elected:
            elected = True
            # 每次当选只做一次：回灌上次未确认的消息（避免反复回灌正在处理的项）
            raw_q.recover()
            digest_q.recover()
            # 推送重试队列的回灌也只在当选时做一次（原来每轮都调，会和手动重发抢同一批）
            push.recover_pending(client)
            backlog, _ = raw_q.depth()
            if backlog > _BACKLOG_WARN:
                log.warning(
                    "raw 队列积压 %d 条（常见原因：采集侧重读了历史日志），将按速率护栏逐步消化",
                    backlog,
                )

        now = time.time()
        if now - last_rule_load >= 60:  # 规则可能被后台改动
            rules = _with_index(_load_rules())
            last_rule_load = now
        if now - last_scope_load >= settings.detector_scope_refresh_seconds:
            scopes = _load_scopes()
            last_scope_load = now

        # 批量消费：一次循环处理一批（固定开销只在每批一次），提升扫描吞吐
        for payload in raw_q.consume_many(
            settings.detector_consume_batch, settings.detector_poll_timeout
        ):
            try:
                _handle(
                    payload,
                    rules,
                    scopes,
                    freq,
                    agg,
                    handled,
                    stats,
                    engine,
                    relay_roles,
                    relay_dedup,
                )
            except Exception:
                # 原来这里 except 后无条件 ack：单条异常即永久丢且不计错误（QA 必修 2）。
                # 现在转入隔离队列（有上限、可捞回）并计入 dropped.handle_failed。
                log.exception("处理队列消息失败，转入失败队列 %s（不再静默确认丢弃）", FAILED_KEY)
                _quarantine(client, payload, stats)
            finally:
                raw_q.ack(payload)

        # 聚合窗口到期 → 摘要入投递队列（持久化，崩溃可恢复）
        for digest in agg.pop_due():
            # 基线打标（第 8 期）：2σ 偏离 + 账号/会话画像异常随摘要一起推给智能体；
            # 被排除的摘要不参与基线（它本来就不进分析，学进去只会污染基线）
            if not digest.get("excluded"):
                digest["baseline"] = engine.annotate(digest)
            _apply_routine_policy(digest, client, stats)
            digest_q.push(json.dumps(digest, ensure_ascii=False))
            stats["digest"] += 1
            # 历史采样的原料：按严重度累计 + 按规则计本区间数（进下一次统计块的采样点）
            mark_digest(stats, digest)
        # 基线落库：画像观测 + 数值统计攒到这里一次性写（节奏由 baseline_flush_seconds 控制）
        engine.maybe_flush()

        # raw 队列持续封顶：采集速率（实测几万条/分钟）远高于检测器处理能力，
        # 不封顶就会把 Redis 撑满 → noeviction 拒写 → 检测器与 Celery 全线卡死（真实事故）。
        # 保留最新的（LPUSH 头部最新）；丢掉的计入 dropped.raw_trimmed（可查、不静默）。
        _trim_queue(
            raw_q, client, stats, limit=settings.detector_raw_queue_max, reason="raw_trimmed"
        )

        # 攒批：凑够 N 条或等待超时即处理一次
        # 注意：即使被限流也要走 _flush —— 否则连「清理超龄」都做不了，队列只增不减
        pending_raw, _ = digest_q.depth()
        if pending_raw and (
            pending_raw >= settings.detector_batch_max
            or time.time() - last_flush >= settings.detector_batch_seconds
        ):
            _flush(digest_q, client, stats)
            _trim_queue(digest_q, client, stats)
            last_flush = time.time()

        # 第 5 期：把上次推送失败、落在持久重试队列里的摘要在后台重发
        # （放在这里而不是另起线程：检测循环本来就是分钟级节奏，够用且不引入并发）
        push.retry_pending(client, stats)
        # 中继角色推算回写（与统计块同节奏；写失败只记警告，不影响检测）
        relay_roles.maybe_flush()
        # 中继去重计数也写进基线心跳（同一把 Redis 键）：「行为分析」页要展示，不静默
        try:
            client.hset(
                settings.baseline_stats_key,
                mapping={key: int(value) for key, value in relay_dedup.counts.items()},
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("中继去重计数写入 Redis 失败: %s", exc)

        if time.time() - last_stats >= settings.detector_stats_log_seconds:
            q_raw, q_proc = raw_q.depth()
            # Redis 体检：内存吃满 → noeviction 拒写 → 全链路静默卡死（真实事故，必须提前叫）
            mem = health.redis_memory(client)
            if mem.get("max") and mem.get("perc", 0) >= settings.redis_memory_warn_perc:
                log.warning(
                    "%s —— 超过 maxmemory 后 Redis 会拒绝所有写命令，分析链路会整体卡死；"
                    "请用 redis-cli --bigkeys 找大键（历史事故键：shentong:handled:docs）",
                    health.describe(mem),
                )
            if handled.skipped:
                try:
                    client.set(f"{settings.detector_handled_key}:skipped", handled.skipped)
                except Exception as exc:  # noqa: BLE001
                    log.debug("登记丢弃计数写入失败: %s", exc)
            log.info(
                "检测器统计（主实例 %s）：扫描 %d / 命中 %d / 频率触发 %d / 重复跳过 %d / 排除 %d / 摘要 %d "
                "/ 投递 %d / 未投递 %d / 处理失败 %d / 聚合满丢弃 %d / 限流 %d / 回队 %d "
                "/ 丢弃(超龄 %d / 裁剪 %d / raw裁剪 %d) "
                "/ 策略跳过(内网常规 %d) / 类型跳过(运维 %d / 未知 %d) / 登记丢弃 %d "
                "| 队列 raw=%d processing=%d 失败=%d | 聚合中 %d | %s",
                leader.me,
                stats["scanned"],
                stats["hit"],
                stats["freq_hit"],
                stats["duplicate"],
                stats["excluded"],
                stats["digest"],
                stats["delivered"],
                stats["dropped_undelivered"],
                stats["dropped_handle_failed"],
                stats["dropped_agg_full"],
                stats["throttled"],
                stats["requeued"],
                stats["dropped_expired"],
                stats["dropped_trimmed"],
                stats["dropped_raw_trimmed"],
                stats["policy_internal_routine"],
                stats["ops_skipped"],
                stats["unknown_skipped"],
                handled.skipped,
                q_raw,
                q_proc,
                _failed_depth(client),
                agg.pending(),
                health.describe(mem),
            )
            # 速率快照落库（G4）：写入"本区间增量 + 区间秒数"，端点据此精确算速率
            now_ts = time.time()
            interval = max(0.1, now_ts - rate_prev["ts"])
            try:
                client.hset(
                    "shentong:detector:rates",
                    mapping={
                        "ts": str(now_ts),
                        "interval_seconds": str(interval),
                        "d_scanned": str(stats["scanned"] - rate_prev["scanned"]),
                        "d_hit": str(stats["hit"] - rate_prev["hit"]),
                        "d_digest": str(stats["digest"] - rate_prev["digest"]),
                        "d_delivered": str(stats["delivered"] - rate_prev["delivered"]),
                        "d_raw_trimmed": str(
                            stats["dropped_raw_trimmed"] - rate_prev["raw_trimmed"]
                        ),
                        "scanned": str(stats["scanned"]),
                        "hit": str(stats["hit"]),
                        "freq_hit": str(stats["freq_hit"]),
                        "digest": str(stats["digest"]),
                        "delivered": str(stats["delivered"]),
                        "undelivered": str(stats["dropped_undelivered"]),
                        "failed": str(stats["dropped_handle_failed"]),
                        "agg_full": str(stats["dropped_agg_full"]),
                        "raw_trimmed": str(stats["dropped_raw_trimmed"]),
                        "limit_saturated": str(stats["limit_saturated"]),
                        "requeued": str(stats["requeued"]),
                    },
                )
            except Exception as exc:  # noqa: BLE001
                log.debug("写入速率快照失败: %s", exc)
            # 历史采样（总览页的 24h 趋势与威胁事件图都吃这一份）：一条 = 一个统计区间。
            # 必须在 `rate_prev.update` **之前**算增量，否则拿到的全是 0。
            sample: dict[str, Any] = {
                "ts": now_ts,
                "interval_seconds": interval,
                "d_scanned": stats["scanned"] - rate_prev["scanned"],
                "d_hit": stats["hit"] - rate_prev["hit"],
                "d_digest": stats["digest"] - rate_prev["digest"],
                "d_delivered": stats["delivered"] - rate_prev["delivered"],
                "d_raw_trimmed": stats["dropped_raw_trimmed"] - rate_prev["raw_trimmed"],
                # 按严重度、按规则的区间增量（威胁事件图用）
                **severity_deltas(stats, rate_prev),
                "by_rule": extract_interval_rules(stats),
                "scanned": stats["scanned"],
                "hit": stats["hit"],
                "digest": stats["digest"],
                "delivered": stats["delivered"],
                "undelivered": stats["dropped_undelivered"],
                "failed": stats["dropped_handle_failed"],
                "agg_full": stats["dropped_agg_full"],
                "raw_trimmed": stats["dropped_raw_trimmed"],
                "limit_saturated": stats["limit_saturated"],
                "requeued": stats["requeued"],
                # 队列与内存是**采样瞬时值**（不是区间平均），图上要注明
                "queue_raw": q_raw,
                "queue_processing": q_proc,
                "queue_failed": _failed_depth(client),
                "agg_pending": agg.pending(),
                "redis_perc": mem.get("perc"),
            }
            history_append(
                client,
                sample,
                key=settings.detector_history_key,
                max_items=settings.detector_history_max,
            )
            rate_prev.update(
                {
                    "ts": now_ts,
                    "scanned": stats["scanned"],
                    "hit": stats["hit"],
                    "digest": stats["digest"],
                    "delivered": stats["delivered"],
                    "raw_trimmed": stats["dropped_raw_trimmed"],
                }
            )
            last_stats = now_ts


def _apply_routine_policy(digest: dict[str, Any], client: Any, stats: Counter[str]) -> None:
    """分级放行：把「内网常规流量」打标（事件仍落库可查，只是不跑模型、不出报告）。

    为什么判定放在**聚合结果定稿之后**（而不是每条命中时）：目标数与连接状态要积累完
    才知道；而且排除位参与聚合键，逐条判定会把同一 (源,规则) 拆成两个桶，反而更乱。
    """
    if digest.get("excluded"):
        return  # 已被排除过滤器命中，不重复判定
    direction = triage_policy.direction_of(
        digest.get("src_ip"), digest.get("dst_ips"), digest.get("real_client_ips")
    )
    reason = triage_policy.internal_routine_reason(
        direction=direction,
        rule_severity=digest.get("rule_severity"),
        dst_count=len(digest.get("dst_ips") or []),
        success=triage_policy.has_success(digest.get("event_types"), digest.get("conn_states")),
        # 规则名参与白名单判定：名单外/取不到名字 → 不跳（fail-open，防漏报）
        rule_name=str(digest.get("rule") or ""),
    )
    if not reason:
        return
    digest["excluded"] = True
    digest["exclude_reason"] = reason
    digest["direction"] = direction
    stats["policy_internal_routine"] += 1
    triage_policy.count_skip(client, "internal_routine")


def _sleep_to_next_minute(now: float | None = None) -> float:
    """短睡一会儿再回来看投递额度（额度按分钟桶重置）。

    只睡最多 5 秒：这是「等额度」而不是「睡到边界」——限流期间主循环还要保持可中断
    （信号/退出、规则重载），下一轮回到这里继续等，直到跨过分钟边界。
    """
    current = time.time() if now is None else now
    wait = 60.0 - (current % 60.0)
    wait = max(0.2, min(5.0, wait))
    time.sleep(wait)
    return wait


def _rate_remaining(client: Any) -> int:
    """本分钟还剩多少投递额度（cap<=0 表示不限）。"""
    cap = settings.detector_max_digests_per_minute
    if cap <= 0:
        return 1 << 30
    return max(0, cap - _to_int(client.get(rate_bucket()), 0))


def _failed_depth(client: Any) -> int:
    """隔离队列当前深度（统计日志用；取不到就报 0）。"""
    try:
        return int(client.llen(FAILED_KEY))
    except Exception as exc:  # noqa: BLE001
        log.debug("读取失败队列深度失败: %s", exc)
        return 0


def _quarantine(client: Any, payload: str, stats: Counter[str]) -> None:
    """把处理失败的消息挪进隔离队列（有上限、有 TTL、可人工捞回），并计入丢弃统计。

    原来 except 之后无条件 ack = 单条异常永久丢、且没有任何计数（QA 必修 2）。
    队列满时丢最老的：宁可留下最近的现场。
    """
    _drop(client, "handle_failed", 1, stats)
    try:
        client.lpush(FAILED_KEY, payload)
        client.ltrim(FAILED_KEY, 0, _FAILED_MAX - 1)
        client.expire(FAILED_KEY, _FAILED_TTL)
    except Exception as exc:  # noqa: BLE001
        log.debug("写入失败队列 %s 失败: %s", FAILED_KEY, exc)


def _mark_paused(client: Any) -> None:
    """打「检测器被配置关闭」的标记（带 TTL，反复续期直到重新启用）。"""
    try:
        client.set(PAUSED_KEY, datetime.now(UTC).isoformat(), ex=_PAUSED_TTL)
    except Exception as exc:  # noqa: BLE001
        log.debug("写检测器暂停标记失败: %s", exc)


def _clear_paused(client: Any) -> None:
    """清「检测器被配置关闭」的标记。"""
    try:
        client.delete(PAUSED_KEY)
    except Exception as exc:  # noqa: BLE001
        log.debug("清检测器暂停标记失败: %s", exc)


def _drop(client: Any, reason: str, count: int, stats: Counter[str]) -> None:
    """记录被丢弃的摘要，避免「静默漏分析」。

    原因：expired（超龄未及分析）/ trimmed（队列超上限裁掉最老的）/
    raw_trimmed（raw 队列超上限）/ handle_failed（处理异常，已转隔离队列）/
    undelivered（没配推送地址，摘要没投出去）/ agg_full（聚合态满，命中未聚合）。
    计数写 Redis（跨重启可查），并限频告警。
    """
    global _last_drop_log
    if count <= 0:
        return
    stats[f"dropped_{reason}"] += count
    try:
        client.hincrby(settings.detector_drop_key, reason, count)
        client.hset(settings.detector_drop_key, "last_dropped_at", datetime.now(UTC).isoformat())
        client.expire(settings.detector_drop_key, 30 * 24 * 3600)
    except Exception as exc:  # noqa: BLE001
        log.debug("写入丢弃计数失败: %s", exc)
    now = time.time()
    if now - _last_drop_log >= _THROTTLE_LOG_INTERVAL:
        _last_drop_log = now
        log.warning(
            "有摘要被丢弃（%s）本进程累计 %d 条 —— 说明分析能力跟不上产出，这些事件不会进入分析",
            reason,
            stats[f"dropped_{reason}"],
        )


#: 摘要严重度排序：投递额度不够时先保高价值摘要（评审 P1）。
_DIGEST_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _severity_rank(digest: dict[str, Any]) -> int:
    """摘要的严重度排序值（缺值/脏值算 0）。"""
    return _DIGEST_SEVERITY_RANK.get(str(digest.get("rule_severity") or "").strip().lower(), 0)


def _cap_per_rule(
    client: Any, items: list[tuple[str, dict[str, Any]]], stats: Counter[str]
) -> tuple[list[tuple[str, dict[str, Any]]], list[str]]:
    """按规则名限速：每分钟每条规则最多投多少条摘要。

    返回 (保留项, 需 ack 的丢弃 payload)。丢弃**不静默**：写 dropped.rule_capped。
    `cap<=0`、规则名为空或 Redis 不可用时一律放行（fail-open，宁可多投不静默丢）。
    """
    cap = settings.detector_max_digests_per_rule_minute
    if cap <= 0:
        return items, []
    kept: list[tuple[str, dict[str, Any]]] = []
    dropped: list[str] = []
    bucket = rate_bucket()
    for payload, digest in items:
        rule = str(digest.get("rule") or "")
        if not rule:
            kept.append((payload, digest))
            continue
        try:
            key = f"{settings.detector_rule_cap_key}:{bucket}:{rule}"
            used = int(client.incr(key))
            if used == 1:
                client.expire(key, 180)
        except Exception as exc:  # noqa: BLE001
            log.debug("规则级限速计数失败（按放行处理）: %s", exc)
            kept.append((payload, digest))
            continue
        if used <= cap:
            kept.append((payload, digest))
        else:
            _drop(client, "rule_capped", 1, stats)
            dropped.append(payload)
    return kept, dropped


def _digest_age(entry: dict[str, Any]) -> float:
    """摘要已存在秒数（取 last_seen；解析失败返回 0 视为新鲜）。

    实现放在 ``detector.fingerprint.digest_age``：任务侧（workers.tasks）也要用同一个判据。
    """
    return digest_age(entry)


def _flush(
    q: ReliableQueue,
    client: Any,
    stats: Counter[str],
) -> None:
    """弹出并处理一批摘要：超龄丢弃 → 按速率额度投递，超出的放回队尾。

    要点：
    - **丢弃不受投递限额约束**：否则限流时连清理都做不了，队列只增不减
    - **严格按剩余额度投递**：不再出现「已用 59 + 整批 50 = 109」的超发
    - 投递失败的摘要立即放回队列（原来会卡在 processing 里直到重启）
    - 超龄摘要丢弃时落 Redis 计数 + 告警，不再是静默丢失
    - **判重在智能体侧**（第 5 期）：本侧不再查库去重，重复推送由接收端按
      事件组指纹吸收（已分析过只累加计数、桶内在跑直接跳过），故这里不设闸门
    """
    global _last_throttle_log
    budget = _rate_remaining(client)
    if budget <= 0:
        # 额度耗尽：**不再空转**（原来会把整批取出再放回队尾 —— 实测回队 15 万次白烧）
        stats["limit_saturated"] += 1
        _sleep_to_next_minute()
        return
    max_age = settings.detector_digest_max_age_seconds
    items: list[tuple[str, dict[str, Any]]] = []
    expired = 0
    for _ in range(settings.detector_max_per_batch):
        payload = q.try_consume()
        if payload is None:
            break
        try:
            digest = json.loads(payload)
        except (TypeError, ValueError):
            q.ack(payload)
            continue
        if not isinstance(digest, dict):
            q.ack(payload)
            continue
        if max_age > 0 and _digest_age(digest) > max_age:
            q.ack(payload)
            expired += 1
            continue
        items.append((payload, digest))

    # 单规则每分钟上限：per-event 噪声规则（例：横向移动管理端口）能几分钟吃满总额度，
    # 把高价值摘要挤到超龄丢弃（评审 P1）。超限的计入 dropped.rule_capped 后 ack。
    items, capped = _cap_per_rule(client, items, stats)
    for payload in capped:
        q.ack(payload)
    # 按剩余额度投递：超出的放回队尾（下轮优先）。
    # **先按严重度降序**：额度长期不够时先保高价值摘要，而不是让 FIFO 把扫描噪声
    # 排在勒索告警前面（评审 P1）。
    items.sort(key=lambda item: _severity_rank(item[1]), reverse=True)
    surplus = [payload for payload, _ in items[budget:]]
    items = items[:budget]
    for payload in surplus:
        q.requeue(payload)
    if surplus:
        stats["requeued"] += len(surplus)
        stats["throttled"] += 1
        now = time.time()
        if now - _last_throttle_log >= _THROTTLE_LOG_INTERVAL:
            _last_throttle_log = now
            log.warning(
                "投递额度已用完（%d 条/分钟），%d 条摘要放回队列下轮再投",
                settings.detector_max_digests_per_minute,
                len(surplus),
            )
    if expired:
        _drop(client, "expired", expired, stats)
    if not items:
        return

    # 交接契约（第 5 期）：优先 **HTTP 推**给智能体（2xx 即回执）；
    # 没配地址/关了开关 → 不再写已退役的 shentong:events:dispatch（全仓无消费者），
    # 明确记为「未投递」；推送失败 → 落持久重试队列后台重发。
    # 三种情况下「批」的语义不变：一批 = 一次图运行 = 一次跨摘要关联归组。
    digests = [d for _, d in items]
    outcome, detail = push.deliver(client, digests, stats)
    if outcome == "off":
        # 没有可投递的去处：摘要不会进入分析，必须让它可见（dropped.undelivered +
        # /api/agent-push 的 undelivered 计数），绝不能计成 delivered（QA 必修 1）。
        _drop(client, "undelivered", len(items), stats)
        push.record(client, "undelivered", len(items), detail or "未配置推送地址或已关闭")
        for payload, _ in items:
            q.ack(payload)
        return
    elif outcome == "lost":
        # 推送失败、重试队列也写不进去（Redis 挂了）：摘要放回检测队列，绝不静默丢
        log.warning("推送失败且无法落重试队列（%s），%d 条摘要放回队尾", detail, len(items))
        for payload, _ in items:
            q.requeue(payload)
        return
    elif outcome == "pushed":
        log.info("已推送 %d 条聚合摘要给智能体（HTTP 2xx 即回执）", len(items))
    else:
        log.warning("推送失败（%s），%d 条摘要已落重试队列待重发", detail, len(items))
    for payload, _ in items:
        q.ack(payload)
    stats["delivered"] += len(items)
    bkey = rate_bucket()
    client.incrby(bkey, len(items))
    client.expire(bkey, 120)


def _trim_queue(
    q: ReliableQueue,
    client: Any,
    stats: Counter[str],
    *,
    limit: int | None = None,
    reason: str = "trimmed",
) -> None:
    """队列超上限时保最新、裁最旧（LPUSH 头部最新，故裁尾部），保证积压有界。"""
    cap = settings.detector_queue_max if limit is None else limit
    if cap <= 0:
        return
    depth, _ = q.depth()
    if depth <= cap:
        return
    try:
        client.ltrim(q.raw, 0, cap - 1)
    except Exception as exc:  # noqa: BLE001
        log.debug("裁剪队列 %s 失败: %s", q.raw, exc)
        return
    _drop(client, reason, depth - cap, stats)
    if reason == "raw_trimmed":
        # 记录裁剪时段（H1）：兜底按水位扫 ES 会补回这些日志，这里留下面证供对账
        try:
            import json as _json
            from datetime import UTC as _UTC, datetime as _dt

            client.lpush(
                "shentong:trimmed:windows",
                _json.dumps(
                    {
                        "at": _dt.now(_UTC).isoformat(),
                        "dropped": int(depth - cap),
                        "queue_depth": int(depth),
                        "cap": int(cap),
                    },
                    ensure_ascii=False,
                ),
            )
            client.ltrim("shentong:trimmed:windows", 0, 49)
            client.expire("shentong:trimmed:windows", 7 * 24 * 3600)
        except Exception as exc:  # noqa: BLE001
            log.debug("记录裁剪时段失败: %s", exc)


def _handle(
    payload: str,
    rules: dict[str, list[dict[str, Any]]],
    scopes: list[Any],
    freq: FreqWindow,
    agg: Aggregator,
    handled: HandledRegistry,
    stats: Counter[str],
    engine: BaselineEngine,
    relay_roles: RelayRoleDetector,
    relay_dedup: RelayDedup,
) -> None:
    """处理单条队列消息。"""
    try:
        doc = json.loads(payload)
    except (TypeError, ValueError):
        stats["bad_message"] += 1
        return
    if not isinstance(doc, dict):
        stats["bad_message"] += 1
        return

    source = _source_of(doc)
    digest_key = doc_hash(doc)
    # 输入去重：采集侧重试/重放会造成同一文档重复投递，会让聚合次数虚高、产生重复摘要
    if handled.is_handled(digest_key):
        stats["duplicate"] += 1
        return
    handled.mark_many([digest_key])  # 无论是否命中都登记：兜底只补“检测器没看到的”

    # ② 归一化 + 网段过滤前置：不在监控网段 → 直接丢弃（只计数，不写 PG；ES 仍保留全量）
    entry = _to_entry(source, doc)
    if entry is None:
        stats["normalize_failed"] += 1
        return
    # ②b 日志类型闸门（批 1）：运维类（ntp/packet_filter/reporter/stats/ja4ssh/ja4d）与
    #     白名单外的未知类型不进检测（ES 里仍有全量事实）。兜底放在检测器这一侧，是因为
    #     队列里可能还压着升级前的旧文档或人工重放数据，归一化服务那道闸门管不到它们。
    if not log_types.is_detectable(entry):
        stats[f"{log_types.classify_entry(entry)}_skipped"] += 1
        return
    if scopes and not _entry_in_scope(entry, scopes):
        stats["out_of_scope"] += 1
        stats["prefiltered_scope"] += 1
        return
    stats["scanned"] += 1

    # ④ 中继角色证据（只看清单内的地址；http/ssl → 反代，dns → DNS 转发）
    #    放在排除过滤器之前：角色反映的是「这类协议是否经过该中继」，与用户过滤无关。
    relay_roles.observe(entry)
    # ⑤ 中继去重（同样在用户过滤之前判定）：保留前跳、丢掉后跳；
    #    若从未见过该中继的前跳（抓包点只在源站侧），后跳照常处理，不丢数据。
    if relay_dedup.decide(entry) == "drop":
        stats["relay_deduped"] += 1
        return

    # ③ 用户自定义排除过滤器前置：命中即丢弃（只计数；ES 仍保留全量）
    #    为什么要前置：这些日志"注定不会被分析"，放在规则之后跑纯属浪费扫描吞吐。
    pre_name = exclusion.check_filter(entry)
    if pre_name:
        stats["prefiltered_exclusion"] += 1
        exclusion.record_hit(pre_name, entry)
        return

    # ④ 基线观测（第 8 期）：账号/会话画像按「在监控网段内、未被排除」的事件持续学习。
    #    放在规则之前：画像是长期行为基线，不该只学命中规则的那部分日志。
    engine.observe(entry)

    # ⑤ 只跑与本期日志类型相关的规则（+ 通配规则）；rules_evaluated 用于量化提速
    candidates = rules_for_log_type(rules.get("index"), entry.log_type) or list(rules["per_event"])
    stats["rules_evaluated"] += len(candidates)
    hit = next((r for r in candidates if match_rule(r, entry)), None)
    if hit is not None:
        stats["hit"] += 1
        _aggregate(
            agg, entry, hit, entry.raw, source, stats=stats, **_exclusion_of(entry, hit, stats)
        )

    # 注意：命中逐条规则后**必须继续**评估频率规则。
    # 若在此 return，内置逐条规则（如“扫描尝试连接”匹配所有 scan_attempt）会把
    # 频率规则“饿死”——18 条频率规则几乎永不触发（现场统计：9065 次命中仅触发 14 次）。
    for rule in rules["count"]:
        cond = rule.get("conditions") or {}
        if whitelisted(cond, entry) or not evaluate_conditions(cond, entry):
            continue
        if freq.observe(rule, entry):
            stats["freq_hit"] += 1
            _aggregate(
                agg,
                entry,
                rule,
                entry.raw,
                source,
                stats=stats,
                **_exclusion_of(entry, rule, stats),
            )


def _exclusion_of(entry: Any, rule: dict[str, Any], stats: Counter[str]) -> dict[str, Any]:
    """规则命中后判一次排除过滤，命中则返回 {excluded, exclude_reason}。

    检查点必须在“规则命中之后”：条件要能引用命中规则元数据（规则名/来源/严重度），
    这是“关掉某条规则的全部噪声”的关键；代价只是规则匹配照跑（极廉价）。
    求值异常在 exclusion 内部按“未命中”处理（fail-open，宁可多分析不漏报）。
    """
    rule_name = str(rule.get("name") or "")
    name = exclusion.check_filter(
        entry,
        rule_name=rule_name,
        rule_source=str(rule.get("source") or ""),
        rule_severity=str(rule.get("severity") or ""),
    )
    if not name:
        return {}
    stats["excluded"] += 1
    exclusion.record_hit(name, entry, rule_name=rule_name)
    return {"excluded": True, "exclude_reason": name}


def _aggregate(
    agg: Aggregator,
    entry: Any,
    rule: dict[str, Any],
    raw_doc: dict[str, Any],
    source: str,
    *,
    stats: Counter[str],
    excluded: bool = False,
    exclude_reason: str = "",
) -> None:
    """投递一条摘要样本。

    `raw_doc` 必须是**原始文档**（`entry.raw`）而不是拍平后的字段：智能体侧会拿它
    再跑一次 `normalize()` 做证据展示（`agent/backend/app/agents/nodes.py`）。
    `stats` 只用来统计「聚合态满导致本条命中没被聚合」——这属于静默降级，必须可见（QA 应修 6）。
    """
    added = agg.add(
        # 源 IP 缺失时用 "-"（未知）归并；不能用 dst_ip 代替——那是目标，语义错位
        src_ip=str(entry.src_ip or "-"),
        rule=str(rule.get("name") or ""),
        severity=str(rule.get("severity") or "medium"),
        source=str(rule.get("source") or "builtin"),
        entry=entry,
        raw_doc=raw_doc,
        log_source=source,
        excluded=excluded,
        exclude_reason=exclude_reason,
    )
    if not added:
        # 聚合态数量达上限，本条命中被直接丢弃（聚合器侧同时写 dropped.agg_full）
        stats["dropped_agg_full"] += 1
