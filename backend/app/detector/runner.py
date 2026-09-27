"""检测器主循环：消费旁路队列 → 归一化 → 网段过滤 → 规则（逐条+滑窗频率）
→ 短窗聚合 → 攒批投递给智能体分析。

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

import redis

from app.agents import triage_policy
from app.agents.persistence import get_enabled_rules
from app.config import settings
from app.db.base import SessionLocal
from app.detector import health
from app.detector.aggregate import Aggregator
from app.detector.analyzed import AnalyzedRegistry, digest_age, digest_fingerprint
from app.detector.frequency import FreqWindow
from app.detector.handled import HandledRegistry, doc_hash
from app.detector.leader import Leader
from app.detector.queue import ReliableQueue
from app.ingestion import exclusion
from app.ingestion.es_client import build_networks, doc_in_scope
from app.ingestion.es_schema import configured_fields
from app.ingestion.normalizer import normalize
from app.ingestion.scope import enabled_cidrs
from app.rules.engine import evaluate_conditions, is_count_rule, match_rule, whitelisted
from app.workers.log import get_logger

log = get_logger(__name__)

_SOURCES = ("zeek", "wazuh")
_RATE_KEY = "shentong:detector:delivered"
_BACKLOG_WARN = 50_000
_THROTTLE_LOG_INTERVAL = 60  # 限流/丢弃告警最小间隔（秒），避免刷屏
_last_throttle_log = 0.0
_last_drop_log = 0.0


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
    return build_networks(enabled_cidrs())


def _source_of(doc: dict[str, Any]) -> str:
    """判定日志来源。

    优先看显式标记 source_system（Zeek 的 Filebeat / Logstash 过滤器会补）；
    缺失时做兜底嗅探——否则一本 Zeek 文档会被当成 Wazuh 解析，
    导致 event_type 全错、规则静默不命中（隐性漏检）。
    """
    raw = str(doc.get("source_system") or "").strip().lower()
    if raw in _SOURCES:
        return raw
    if "log_type" in doc or isinstance(doc.get("zeek"), dict):
        return "zeek"
    return "wazuh"


def run() -> None:
    """常驻循环（由 docker compose 的 detector 服务拉起）。"""
    client: Any = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    raw_q = ReliableQueue(client, settings.detector_raw_queue, settings.detector_processing_queue)
    digest_q = ReliableQueue(
        client,
        settings.detector_digest_queue,
        f"{settings.detector_digest_queue}:processing",
    )

    handled = HandledRegistry(client, settings.detector_handled_key, settings.detector_handled_ttl)
    freq = FreqWindow(client, settings.freq_window_seconds, settings.freq_cooldown_seconds)
    agg = Aggregator(client, settings.detector_agg_seconds, settings.detector_agg_max_keys)
    # 投递前去重闸门（按「规则|源IP|时间桶」指纹查库，已分析过的不再重复投）
    analyzed = AnalyzedRegistry()
    # 多实例选主：只有持锁实例消费队列（其余待命热备），故障后租约到期自动接管
    leader = Leader(client)
    elected = False  # 本次持有租约期间是否已做过启动回灌

    def _on_term(_signum: int, _frame: Any) -> None:
        raise SystemExit(0)  # 让退出路径（atexit）能执行让位

    signal.signal(signal.SIGTERM, _on_term)
    atexit.register(leader.release)

    rules = _load_rules()
    scopes = _load_scopes()
    last_rule_load = time.time()
    last_scope_load = last_rule_load

    stats: Counter[str] = Counter()
    last_flush = time.time()
    last_stats = time.time()
    log.info(
        "检测器启动：逐条规则 %d 条 / 频率规则 %d 条 / 分析网段 %d 个 / 聚合窗口 %ds",
        len(rules["per_event"]),
        len(rules["count"]),
        len(scopes),
        settings.detector_agg_seconds,
    )
    if analyzed.enabled:
        removed = analyzed.cleanup()
        log.info(
            "投递前去重：开启（在途 TTL %ds / 完结保留 %d 天），启动清理过期指纹 %d 条",
            analyzed.ttl,
            analyzed.retention_days,
            removed,
        )

    while True:
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
            backlog, _ = raw_q.depth()
            if backlog > _BACKLOG_WARN:
                log.warning(
                    "raw 队列积压 %d 条（常见原因：采集侧重读了历史日志），将按速率护栏逐步消化",
                    backlog,
                )

        now = time.time()
        if now - last_rule_load >= 60:  # 规则可能被后台改动
            rules = _load_rules()
            last_rule_load = now
        if now - last_scope_load >= settings.detector_scope_refresh_seconds:
            scopes = _load_scopes()
            last_scope_load = now

        # 批量消费：一次循环处理一批（固定开销只在每批一次），提升扫描吞吐
        consumed_any = False
        for payload in raw_q.consume_many(
            settings.detector_consume_batch, settings.detector_poll_timeout
        ):
            consumed_any = True
            try:
                _handle(payload, rules, scopes, freq, agg, handled, stats)
            except Exception:
                log.exception("处理队列消息失败（已确认，避免卡死队列）")
            finally:
                raw_q.ack(payload)
        _ = consumed_any

        # 聚合窗口到期 → 摘要入投递队列（持久化，崩溃可恢复）
        for digest in agg.pop_due():
            _apply_routine_policy(digest, client, stats)
            digest_q.push(json.dumps(digest, ensure_ascii=False))
            stats["digest"] += 1

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
            _flush(digest_q, client, stats, analyzed)
            _trim_queue(digest_q, client, stats)
            last_flush = time.time()

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
                "/ 投递 %d / 去重跳过 %d / 限流 %d / 回队 %d / 丢弃(超龄 %d / 裁剪 %d / raw裁剪 %d) "
                "/ 策略跳过(内网常规 %d) / 登记丢弃 %d "
                "| 队列 raw=%d processing=%d | 聚合中 %d | %s",
                leader.me,
                stats["scanned"],
                stats["hit"],
                stats["freq_hit"],
                stats["duplicate"],
                stats["excluded"],
                stats["digest"],
                stats["delivered"],
                stats["dedup_skipped"],
                stats["throttled"],
                stats["requeued"],
                stats["dropped_expired"],
                stats["dropped_trimmed"],
                stats["dropped_raw_trimmed"],
                stats["policy_internal_routine"],
                handled.skipped,
                q_raw,
                q_proc,
                agg.pending(),
                health.describe(mem),
            )
            # 速率快照落库（G4）：五段速率靠两个采样点的差值计算，面板/接口都能读
            try:
                client.hset(
                    "shentong:detector:rates",
                    mapping={
                        "ts": time.time(),
                        "scanned": stats["scanned"],
                        "hit": stats["hit"],
                        "freq_hit": stats["freq_hit"],
                        "digest": stats["digest"],
                        "delivered": stats["delivered"],
                        "raw_trimmed": stats["dropped_raw_trimmed"],
                        "limit_saturated": stats["limit_saturated"],
                        "requeued": stats["requeued"],
                    },
                )
            except Exception as exc:  # noqa: BLE001
                log.debug("写入速率快照失败: %s", exc)
            last_stats = time.time()


def _apply_routine_policy(digest: dict[str, Any], client: Any, stats: Counter[str]) -> None:
    """分级放行：把「内网常规流量」打标（事件仍落库可查，只是不跑模型、不出报告）。

    为什么判定放在**聚合结果定稿之后**（而不是每条命中时）：目标数与连接状态要积累完
    才知道；而且排除位参与聚合键，逐条判定会把同一 (源,规则) 拆成两个桶，反而更乱。
    """
    if digest.get("excluded"):
        return  # 已被排除过滤器命中，不重复判定
    direction = triage_policy.direction_of(digest.get("src_ip"), digest.get("dst_ips"))
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
    """睡到下一个分钟桶边界（投递额度按分钟重置）；最多睡 5 秒保持响应。"""
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


def _drop(client: Any, reason: str, count: int, stats: Counter[str]) -> None:
    """记录被丢弃的摘要，避免「静默漏分析」。

    原因：expired（超龄未及分析）/ trimmed（队列超上限裁掉最老的）。
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


def _digest_age(entry: dict[str, Any]) -> float:
    """摘要已存在秒数（取 last_seen；解析失败返回 0 视为新鲜）。

    实现放在 ``analyzed.digest_age``：任务侧（workers.tasks）也要用同一个判据。
    """
    return digest_age(entry)


def _flush(
    q: ReliableQueue,
    client: Any,
    stats: Counter[str],
    analyzed: AnalyzedRegistry | None = None,
) -> None:
    """弹出并处理一批摘要：超龄丢弃 → 投递前去重 → 按速率额度投递，超出的放回队尾。

    要点：
    - **丢弃不受投递限额约束**：否则限流时连清理都做不了，队列只增不减
    - **去重在限额之前**：被去重的不占投递额度
    - **严格按剩余额度投递**：不再出现「已用 59 + 整批 50 = 109」的超发
    - 投递失败的摘要立即放回队列（原来会卡在 processing 里直到重启）
    - 超龄摘要丢弃时落 Redis 计数 + 告警，不再是静默丢失
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

    # 投递前去重（在限额之前）：被去重的不占投递额度，也不该再跑一遍 LLM 尾部
    items, dedup_skipped = _apply_dedup(q, items, analyzed)
    if dedup_skipped:
        stats["dedup_skipped"] += dedup_skipped
        _count_dedup(client, dedup_skipped)

    # 严格按剩余额度投递：超出的放回队尾（下轮优先）
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

    from app.workers.celery_app import celery_app

    try:
        celery_app.send_task("analysis.analyze_digests", args=[[d for _, d in items]])
    except Exception as exc:  # noqa: BLE001
        log.warning("投递分析任务失败，摘要放回队列待重试: %s", exc)
        for payload, _ in items:
            q.requeue(payload)
        return
    for payload, _ in items:
        q.ack(payload)
    if analyzed is not None and analyzed.enabled:
        # 登记“在途”：投递到分析完结之间的窗口也必须拦住重复投递
        analyzed.mark_inflight([(d, fp) for _, d in items if (fp := digest_fingerprint(d))])
    stats["delivered"] += len(items)
    bkey = rate_bucket()
    client.incrby(bkey, len(items))
    client.expire(bkey, 120)
    log.info("已投递 %d 条聚合摘要给智能体分析", len(items))


def _analyzed_label(analyzed: AnalyzedRegistry | None) -> str:
    """统计日志里的去重状态标记（关闭时不刷无用信息）。"""
    return "开" if analyzed is not None and analyzed.enabled else "关"


def _count_dedup(client: Any, count: int) -> None:
    """记录被去重拦下的摘要数（写 Redis，跨重启可查，供 /api/detector/stats 展示）。"""
    try:
        client.hincrby(settings.detector_dedup_key, "skipped", count)
        client.hset(settings.detector_dedup_key, "last_skipped_at", datetime.now(UTC).isoformat())
        client.expire(settings.detector_dedup_key, 30 * 24 * 3600)
    except Exception as exc:  # noqa: BLE001
        log.debug("写入去重计数失败: %s", exc)


def _apply_dedup(
    q: ReliableQueue,
    items: list[tuple[str, dict[str, Any]]],
    analyzed: AnalyzedRegistry | None,
) -> tuple[list[tuple[str, dict[str, Any]]], int]:
    """按指纹去重：已分析/在途未过期的摘要直接 ack（不再投递），返回 (待投递, 跳过数)。

    指纹算不出来（缺规则名/首末时间）的摘要照常投递，不能因为算不出指纹就丢事件；
    同批内指纹重复的只留第一条（同一桶内可能弹出多份同键摘要）。
    """
    if analyzed is None or not analyzed.enabled or not items:
        return items, 0
    kept_fps = {fp for _, fp in analyzed.filter_new([d for _, d in items])}
    deliver: list[tuple[str, dict[str, Any]]] = []
    seen: set[str] = set()
    skipped = 0
    for payload, digest in items:
        fp = digest_fingerprint(digest)
        if fp is not None and (fp not in kept_fps or fp in seen):
            q.ack(payload)
            skipped += 1
            continue
        if fp is not None:
            seen.add(fp)
        deliver.append((payload, digest))
    if skipped:
        log.info("投递前去重：本批 %d 条中 %d 条已分析/在途，跳过", len(items), skipped)
    return deliver, skipped


def _trim_queue(
    q: ReliableQueue,
    client: Any,
    stats: Counter[str],
    *,
    limit: int | None = None,
    reason: str = "trimmed",
) -> None:
    """队列超上限时裁掉最老的（LPUSH 新→旧，故裁尾部），保证积压有界。"""
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


def _handle(
    payload: str,
    rules: dict[str, list[dict[str, Any]]],
    scopes: list[Any],
    freq: FreqWindow,
    agg: Aggregator,
    handled: HandledRegistry,
    stats: Counter[str],
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

    if scopes and not doc_in_scope(doc, configured_fields(source), scopes):
        stats["out_of_scope"] += 1
        return

    entry = normalize(source, doc)
    if entry is None:
        stats["normalize_failed"] += 1
        return
    stats["scanned"] += 1

    hit = next((r for r in rules["per_event"] if match_rule(r, entry)), None)
    if hit is not None:
        stats["hit"] += 1
        _aggregate(agg, entry, hit, doc, source, **_exclusion_of(entry, hit, stats))

    # 注意：命中逐条规则后**必须继续**评估频率规则。
    # 若在此 return，内置逐条规则（如“扫描尝试连接”匹配所有 scan_attempt）会把
    # 频率规则“饿死”——18 条频率规则几乎永不触发（现场统计：9065 次命中仅触发 14 次）。
    for rule in rules["count"]:
        cond = rule.get("conditions") or {}
        if whitelisted(cond, entry) or not evaluate_conditions(cond, entry):
            continue
        if freq.observe(rule, entry):
            stats["freq_hit"] += 1
            _aggregate(agg, entry, rule, doc, source, **_exclusion_of(entry, rule, stats))


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
    doc: dict[str, Any],
    source: str,
    *,
    excluded: bool = False,
    exclude_reason: str = "",
) -> None:
    agg.add(
        # 源 IP 缺失时用 "-"（未知）归并；不能用 dst_ip 代替——那是目标，语义错位
        src_ip=str(entry.src_ip or "-"),
        rule=str(rule.get("name") or ""),
        severity=str(rule.get("severity") or "medium"),
        source=str(rule.get("source") or "builtin"),
        entry=entry,
        raw_doc=doc,
        log_source=source,
        excluded=excluded,
        exclude_reason=exclude_reason,
    )
