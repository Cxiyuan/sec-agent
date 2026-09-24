"""检测器主循环：消费旁路队列 → 归一化 → 网段过滤 → 规则（逐条+滑窗频率）
→ 短窗聚合 → 攒批投递给智能体分析。

替代原来「智能体每 N 分钟主动拉 ES 全量」的入口；智能体只处理被提炼过的
聚合摘要，不再自己捞数据。
"""

from __future__ import annotations

import json
import time
from collections import Counter
from datetime import UTC, datetime
from typing import Any

import redis

from app.agents.persistence import get_enabled_rules
from app.config import settings
from app.db.base import SessionLocal
from app.detector.aggregate import Aggregator
from app.detector.frequency import FreqWindow
from app.detector.handled import HandledRegistry, doc_hash
from app.detector.queue import ReliableQueue
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
    raw_q.recover()
    digest_q.recover()
    backlog, _ = raw_q.depth()
    if backlog > _BACKLOG_WARN:
        log.warning(
            "raw 队列积压 %d 条（常见原因：采集侧重读了历史日志），将按速率护栏逐步消化",
            backlog,
        )

    handled = HandledRegistry(client, settings.detector_handled_key, settings.detector_handled_ttl)
    freq = FreqWindow(client, settings.freq_window_seconds, settings.freq_cooldown_seconds)
    agg = Aggregator(client, settings.detector_agg_seconds, settings.detector_agg_max_keys)

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

    while True:
        now = time.time()
        if now - last_rule_load >= 60:  # 规则可能被后台改动
            rules = _load_rules()
            last_rule_load = now
        if now - last_scope_load >= settings.detector_scope_refresh_seconds:
            scopes = _load_scopes()
            last_scope_load = now

        payload = raw_q.consume(settings.detector_poll_timeout)
        if payload:
            try:
                _handle(payload, rules, scopes, freq, agg, handled, stats)
            except Exception:
                log.exception("处理队列消息失败（已确认，避免卡死队列）")
            finally:
                raw_q.ack(payload)

        # 聚合窗口到期 → 摘要入投递队列（持久化，崩溃可恢复）
        for digest in agg.pop_due():
            digest_q.push(json.dumps(digest, ensure_ascii=False))
            stats["digest"] += 1

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

        if time.time() - last_stats >= settings.detector_stats_log_seconds:
            q_raw, q_proc = raw_q.depth()
            log.info(
                "检测器统计：扫描 %d / 命中 %d / 频率触发 %d / 重复跳过 %d / 摘要 %d / 投递 %d "
                "/ 限流 %d / 回队 %d / 丢弃(超龄 %d / 裁剪 %d) "
                "| 队列 raw=%d processing=%d | 聚合中 %d",
                stats["scanned"],
                stats["hit"],
                stats["freq_hit"],
                stats["duplicate"],
                stats["digest"],
                stats["delivered"],
                stats["throttled"],
                stats["requeued"],
                stats["dropped_expired"],
                stats["dropped_trimmed"],
                q_raw,
                q_proc,
                agg.pending(),
            )
            last_stats = time.time()


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
    """摘要已存在秒数（取 last_seen；解析失败返回 0 视为新鲜）。"""
    raw = entry.get("last_seen")
    if not raw:
        return 0.0
    try:
        seen = datetime.fromisoformat(str(raw))
    except ValueError:
        return 0.0
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=UTC)
    return max(0.0, (datetime.now(UTC) - seen).total_seconds())


def _flush(q: ReliableQueue, client: Any, stats: Counter[str]) -> None:
    """弹出并处理一批摘要：超龄丢弃 + 按速率额度投递，超出的放回队尾。

    要点（修复两处逻辑漏洞）：
    - **丢弃不受投递限额约束**：否则限流时连清理都做不了，队列只增不减
    - **严格按剩余额度投递**：不再出现「已用 59 + 整批 50 = 109」的超发
    - 投递失败的摘要立即放回队列（原来会卡在 processing 里直到重启）
    - 超龄摘要丢弃时落 Redis 计数 + 告警，不再是静默丢失
    """
    global _last_throttle_log
    budget = _rate_remaining(client)
    max_age = settings.detector_digest_max_age_seconds
    items: list[tuple[str, dict[str, Any]]] = []
    surplus: list[str] = []
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
        if len(items) >= budget:
            surplus.append(payload)  # 额度用完：放回队尾，下轮优先
            continue
        items.append((payload, digest))

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
    stats["delivered"] += len(items)
    bkey = rate_bucket()
    client.incrby(bkey, len(items))
    client.expire(bkey, 120)
    log.info("已投递 %d 条聚合摘要给智能体分析", len(items))


def _trim_queue(q: ReliableQueue, client: Any, stats: Counter[str]) -> None:
    """队列超上限时裁掉最老的（LPUSH 新→旧，故裁尾部），保证积压有界。"""
    limit = settings.detector_queue_max
    if limit <= 0:
        return
    depth, _ = q.depth()
    if depth <= limit:
        return
    try:
        client.ltrim(q.raw, 0, limit - 1)
    except Exception as exc:  # noqa: BLE001
        log.debug("裁剪摘要队列失败: %s", exc)
        return
    _drop(client, "trimmed", depth - limit, stats)


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
        _aggregate(agg, entry, hit, doc, source)

    # 注意：命中逐条规则后**必须继续**评估频率规则。
    # 若在此 return，内置逐条规则（如“扫描尝试连接”匹配所有 scan_attempt）会把
    # 频率规则“饿死”——18 条频率规则几乎永不触发（现场统计：9065 次命中仅触发 14 次）。
    for rule in rules["count"]:
        cond = rule.get("conditions") or {}
        if whitelisted(cond, entry) or not evaluate_conditions(cond, entry):
            continue
        if freq.observe(rule, entry):
            stats["freq_hit"] += 1
            _aggregate(agg, entry, rule, doc, source)


def _aggregate(
    agg: Aggregator,
    entry: Any,
    rule: dict[str, Any],
    doc: dict[str, Any],
    source: str,
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
    )
