"""检测器主循环：消费旁路队列 → 归一化 → 网段过滤 → 规则（逐条+滑窗频率）
→ 短窗聚合 → 攒批投递给智能体分析。

替代原来「智能体每 N 分钟主动拉 ES 全量」的入口；智能体只处理被提炼过的
聚合摘要，不再自己捞数据。
"""

from __future__ import annotations

import json
import time
from collections import Counter
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
_THROTTLE_LOG_INTERVAL = 60  # 限流告警最小间隔（秒），避免刷屏
_last_throttle_log = 0.0


def _to_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _rate_bucket() -> str:
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
    raw = str(doc.get("source_system") or "").strip().lower()
    return raw if raw in _SOURCES else "wazuh"


def run() -> None:
    """常驻循环（由 docker compose 的 detector 服务拉起）。"""
    client: Any = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    raw_q = ReliableQueue(
        client, settings.detector_raw_queue, settings.detector_processing_queue
    )
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

        # 攒批：凑够 N 条或等待超时即触发一次分析
        pending_raw, _ = digest_q.depth()
        if pending_raw and (
            pending_raw >= settings.detector_batch_max
            or time.time() - last_flush >= settings.detector_batch_seconds
        ):
            if _rate_allow(client, stats):
                _flush(digest_q, client, stats)
            last_flush = time.time()

        if time.time() - last_stats >= settings.detector_stats_log_seconds:
            q_raw, q_proc = raw_q.depth()
            log.info(
                "检测器统计：扫描 %d / 命中 %d / 频率触发 %d / 摘要 %d / 投递 %d / 限流 %d "
                "| 队列 raw=%d processing=%d | 聚合中 %d",
                stats["scanned"],
                stats["hit"],
                stats["freq_hit"],
                stats["digest"],
                stats["delivered"],
                stats["throttled"],
                q_raw,
                q_proc,
                agg.pending(),
            )
            last_stats = time.time()


def _rate_allow(client: Any, stats: Counter[str]) -> bool:
    """投递速率护欄：固定分钟窗内不超上限。超限则本轮不投（摘要留在队列，不丢）。"""
    global _last_throttle_log
    cap = settings.detector_max_digests_per_minute
    if cap <= 0:
        return True
    bkey = _rate_bucket()
    if _to_int(client.get(bkey), 0) >= cap:
        stats["throttled"] += 1
        now = time.time()
        if now - _last_throttle_log >= _THROTTLE_LOG_INTERVAL:
            _last_throttle_log = now
            log.warning(
                "投递速率达上限 %d 条/分钟，摘要暂留队列（累计限流 %d 次）",
                cap,
                stats["throttled"],
            )
        return False
    return True


def _flush(q: ReliableQueue, client: Any, stats: Counter[str]) -> None:
    """取一批摘要投递给 Celery；投递成功才确认（失败留队列重试）。"""
    items: list[tuple[str, dict[str, Any]]] = []
    for _ in range(settings.detector_max_per_batch):
        payload = q.try_consume()
        if payload is None:
            break
        try:
            digest = json.loads(payload)
        except (TypeError, ValueError):
            q.ack(payload)
            continue
        if isinstance(digest, dict):
            items.append((payload, digest))
        else:
            q.ack(payload)
    if not items:
        return

    from app.workers.celery_app import celery_app

    try:
        celery_app.send_task("analysis.analyze_digests", args=[[d for _, d in items]])
    except Exception as exc:  # noqa: BLE001
        log.warning("投递分析任务失败，摘要保留在队列待重试: %s", exc)
        return
    for payload, _ in items:
        q.ack(payload)
    stats["delivered"] += len(items)
    bkey = _rate_bucket()
    client.incrby(bkey, len(items))
    client.expire(bkey, 120)
    log.info("已投递 %d 条聚合摘要给智能体分析", len(items))


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
        return

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
        src_ip=str(entry.src_ip or entry.dst_ip or "-"),
        rule=str(rule.get("name") or ""),
        severity=str(rule.get("severity") or "medium"),
        source=str(rule.get("source") or "builtin"),
        entry=entry,
        raw_doc=doc,
        log_source=source,
    )
