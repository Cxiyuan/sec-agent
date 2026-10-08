"""采集侧归一化服务：原始日志 → 统一结构 → 检测器队列 + Elasticsearch。

为什么要单独一个服务：改造前 Logstash 把原始文档原样写进 ES（Zeek 落在 `zeek.*`、
只做一次、只在这里做：

      └ RPOPLPUSH（从右端取 = 最新优先）--> shentong:events:collect:processing
          ├ 降噪过滤（命中 → 跳过①，②照走）
          ├ ① LPUSH 归一化文档 --> shentong:events:raw（检测器 BRPOPLPUSH 从右端取最旧
          │     = 先进先出；这条队列是我们自产自销，方向与采集口相反是对的）
          ├ ② POST 归一化文档  --> Logstash http(:8080) → ES（2xx 才算入库成功）
          └ 坏消息（JSON 坏了 / 归一化失败）--> shentong:events:dead（死信，有上限）

队列方向以实机为准（2026-10 复核）：Filebeat 的 redis output 在 `datatype: list` 时用的是
**RPUSH**（官方文档明写），我们又是 RPOPLPUSH 从右端取 —— 左端最旧、右端最新，消费的是
最新那批。`_trim_queue()` 的裁剪方向必须与之一致（积压时丢最旧），否则丢的正是「攻击当下」
的事件（改造前就是这个写反的 bug）。

**降噪过滤**（`app/ingestion/ingest_filter.py`）在这里判定，而不是写成 Logstash 的
`drop`：原始日志已经不经过 Logstash，而 ES 只由这里写入 —— 用 `drop` 会连 ES 那份一起
丢掉，直接违反「ES 落全量」。命中过滤的事件**只是不投检测器**，照样入库。

投递顺序刻意是「先入检测器队列，再 POST 入库」：
  ① 检测是实时车道，不该被 ES/Logstash 的抖动拖住；
  ② POST 失败就把本批**放回队尾**重试（`recover()` 只兜底进程崩溃留下的残留）；
     重试造成的重复文档由检测器侧的 `handled` 注册表（按文档哈希）挡住，不会重复告警。

入口：`python -m app.collector.normalizer_service`（由 compose 的 normalizer 服务拉起）。
"""

from __future__ import annotations

import json
import signal
import time
from collections import Counter
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.config import settings
from app.detector.queue import ReliableQueue, make_blocking_client
from app.ingestion import ingest_filter, log_types
from app.ingestion.normalizer import normalize, source_of
from app.schemas import UnifiedLog
from app.workers.log import get_logger

log = get_logger(__name__)

#: 坏消息（JSON 坏了 / 归一化失败）的死信队列：LPUSH 进、LTRIM 保最新，防止永远好不了的
#: 消息把队列撑爆；原文整条留着，方便事后捞出来重放或定位。
#: 这两个值暂用模块内常量（配置项在 app/config.py，属 E 组白名单）；若要提成配置项，
#: 建议命名 `ST_COLLECTOR_DEAD_LETTER_QUEUE` / `ST_COLLECTOR_DEAD_LETTER_MAX`。
_DEAD_LETTER_KEY = "shentong:events:dead"
_DEAD_LETTER_MAX = 10000

#: 坏消息的持久计数（Redis hash，按原因分桶）：进程内 `stats` 每轮日志后就地清零，
#: 界面/巡检看不到历史，累计值写这里——`HGETALL shentong:collector:stats` 就能看。
_COLLECTOR_STATS_KEY = "shentong:collector:stats"


# ---------- 辅助 ----------


def _target_url() -> str:
    """Logstash http 输入地址（主机名复用 `logstash_api_url` 的配置）。

    刻意不新增一个「入库地址」配置项：Logstash 的监控 API 与 http 输入是同一个容器，
    分成两个配置只会多一个写歪的机会（主机名不一致时最难查）。端口必须分开是因为
    9600 是监控 API、8080 才是 http 输入。
    """
    parts = urlsplit(settings.logstash_api_url)
    host = parts.hostname or "logstash"
    return f"{parts.scheme or 'http'}://{host}:{settings.logstash_http_port}/"


def _payload(entry: Any) -> dict[str, Any]:
    """归一化文档的线上形态：去掉空值（ES 里少一堆 null 字段，也省带宽）。"""
    data = entry.model_dump(mode="json")
    return {k: v for k, v in data.items() if v is not None}


def _ndjson(payloads: list[dict[str, Any]]) -> bytes:
    """一批文档压成 NDJSON（Logstash 侧用 json_lines 编解码器拆回多条事件）。"""
    body = "\n".join(json.dumps(p, ensure_ascii=False) for p in payloads)
    return (body + "\n").encode("utf-8")


def _record_dead(client: Any, item: str, reason: str, stats: Counter[str]) -> None:
    """坏消息进死信队列 + 持久计数（尽最大努力，绝不把常驻循环带崩）。

    改造前这类消息是**直接确认掉、只在进程内记个数**：日志一刷就再也查不到，ES 里也没有，
    等于静默丢事件（违反「ES 是全量事实源」）。现在原文整条进 `_DEAD_LETTER_KEY`，累计条数
    进 `_COLLECTOR_STATS_KEY`，日志里还会报积压。

    Redis 写失败只告警不上抛：调用方紧接着要 ack 这条消息，异常传出去会让循环退出。这种
    极端情况（Redis 连不上）下 ack 同样会失败，消息会留在 processing 里等下次启动回灌，
    不会静默消失。
    """
    stats[f"dead_{reason}"] += 1
    record = {
        "at": datetime.now(UTC).isoformat(),
        "reason": reason,
        "payload": item,
    }
    try:
        client.lpush(_DEAD_LETTER_KEY, json.dumps(record, ensure_ascii=False))
        client.ltrim(_DEAD_LETTER_KEY, 0, _DEAD_LETTER_MAX - 1)
        client.hincrby(_COLLECTOR_STATS_KEY, f"dead_{reason}", 1)
    except Exception as exc:  # noqa: BLE001
        log.warning("写入死信队列失败（%s）：%s", reason, exc)


def _dead_letter_depth(client: Any) -> int:
    """死信队列当前积压；读不到返回 -1（只用于日志，不参与控制流）。"""
    try:
        return int(client.llen(_DEAD_LETTER_KEY))
    except Exception:  # noqa: BLE001
        return -1


def _split(
    items: list[str], stats: Counter[str]
) -> tuple[list[tuple[str, UnifiedLog]], list[tuple[str, str]]]:
    """把队列消息分成 (能归一化的, 永远好不了的)。

    后一类不能一直留在队列里重试（一条坏消息会把整条链路卡死），所以调用方会确认掉它们；
    但确认之前先写死信队列并计数（见 `_record_dead`），做到「不丢 + 可观测」。

    返回的坏消息带原因（`bad_json` / `normalize_failed`），死信记录与计数都按原因分桶。

    这里刻意返回 **UnifiedLog**（而不是线上形态的 dict）：降噪过滤要按字段求值，而每条
    文档的 `model_dump` 只该做一次（在调用方合并成一次循环）。
    """
    good: list[tuple[str, UnifiedLog]] = []
    bad: list[tuple[str, str]] = []
    for item in items:
        try:
            doc = json.loads(item)
        except (TypeError, ValueError):
            stats["bad_json"] += 1
            bad.append((item, "bad_json"))
            continue
        if not isinstance(doc, dict):
            stats["bad_json"] += 1
            bad.append((item, "bad_json"))
            continue
        entry = normalize(source_of(doc), doc)
        if entry is None:
            stats["normalize_failed"] += 1
            bad.append((item, "normalize_failed"))
            continue
        good.append((item, entry))
    return good, bad


def _post(client: httpx.Client, url: str, payloads: list[dict[str, Any]]) -> bool:
    """把一批归一化文档 POST 给 Logstash，返回是否成功入库。

    Logstash 的 http 输入在积压时回 429、队列堵住时可能直接把请求拖到超时
    （官方文档明说这两种行为）。两类都按「没成功」处理：调用方会把本批放回队尾
    重试，绝不误确认。
    """
    body = _ndjson(payloads)
    attempts = max(1, settings.collector_post_retries)
    for attempt in range(1, attempts + 1):
        try:
            resp = client.post(url, content=body, headers={"Content-Type": "application/json"})
            if 200 <= resp.status_code < 300:
                return True
            log.warning(
                "Logstash 入库失败（HTTP %s），第 %d/%d 次", resp.status_code, attempt, attempts
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("Logstash 入库异常，第 %d/%d 次：%s", attempt, attempts, exc)
        if attempt < attempts:
            time.sleep(settings.collector_retry_backoff_seconds * attempt)
    return False


def _trim_queue(client: Any, key: str, limit: int) -> int:
    """队列封顶：超出就裁掉**最旧**的，保留最新。

    方向依据（2026-10 实机 `redis-cli monitor` 抓到活流量 + Filebeat 官方文档）：Filebeat
    的 redis output 在 `datatype: list` 时用 **RPUSH**，我们又是 RPOPLPUSH 从右端取 ——
    左端最旧、右端最新。改造前这里是 `ltrim(key, 0, limit - 1)`（保最旧、砍最新），积压时
    丢掉的正好是「攻击当下」的最新事件，而日志还写着「已裁掉最旧的」。
    """
    if limit <= 0:
        return 0
    try:
        size = int(client.llen(key))
    except Exception as exc:  # noqa: BLE001
        log.debug("读取采集队列长度失败: %s", exc)
        return 0
    if size <= limit:
        return 0
    dropped = size - limit
    try:
        client.ltrim(key, -limit, -1)
    except Exception as exc:  # noqa: BLE001
        log.warning("裁剪采集队列失败: %s", exc)
        return 0
    log.warning("采集队列超过上限 %d，已裁掉最旧的 %d 条", limit, dropped)
    return dropped


def _maybe_log(stats: Counter[str], last: float, queue: ReliableQueue, client: Any) -> float:
    """周期性汇报（每 `collector_stats_log_seconds` 一次，不刷屏）。"""
    now = time.monotonic()
    if now - last < settings.collector_stats_log_seconds:
        return last
    raw_depth, processing = queue.depth()
    if stats or raw_depth or processing:
        log.info(
            "归一化服务：入库 %d 条 / 降噪挡下 %d 条 / 原始日志只入库 %d 条 / 类型闸门只入库 %d 条"
            " / 待重试 %d 条 / 坏消息 %d 条（已进死信，积压 %d 条） / 积压 %d 条（处理中 %d 条）",
            stats.get("delivered", 0),
            stats.get("filtered", 0),
            stats.get("archive_es_only", 0),
            stats.get("ops_es_only", 0) + stats.get("unknown_es_only", 0),
            stats.get("deferred", 0),
            stats.get("bad_json", 0) + stats.get("normalize_failed", 0),
            _dead_letter_depth(client),
            raw_depth,
            processing,
        )
    stats.clear()
    return now


# ---------- 主循环 ----------


def run() -> None:
    """常驻循环（由 compose 的 normalizer 服务拉起）。"""
    # 阻塞取队列的客户端：socket 读超时必须大于阻塞超时，否则空队列会抛
    # redis.exceptions.TimeoutError 打崩循环（见 app/detector/queue.py 说明）
    client: Any = make_blocking_client(settings.redis_url, settings.collector_poll_timeout)
    queue = ReliableQueue(
        client, settings.collector_collect_queue, settings.collector_processing_queue
    )
    recovered = queue.recover()
    if recovered:
        log.info("回灌上次未确认的采集消息 %d 条", recovered)
    _trim_queue(client, settings.collector_collect_queue, settings.collector_queue_max)

    url = _target_url()
    stats: Counter[str] = Counter()
    last_log = time.monotonic()
    log.info(
        "归一化服务启动：%s → 检测器 %s / Logstash %s",
        settings.collector_collect_queue,
        settings.detector_raw_queue,
        url,
    )

    with httpx.Client(timeout=settings.collector_post_timeout_seconds) as http:
        # 本进程内已投给检测器的原文：入库失败重试时不再重复投（否则 Logstash 一挂，
        # 检测器队列会被同一批数据翻倍灌，而这正是最不该再添乱的时候）。
        pushed: set[str] = set()
        while True:
            items = queue.consume_many(
                settings.collector_consume_batch, settings.collector_poll_timeout
            )
            if not items:
                last_log = _maybe_log(stats, last_log, queue, client)
                _trim_queue(client, settings.collector_collect_queue, settings.collector_queue_max)
                continue

            good, bad = _split(items, stats)
            # 坏消息：先把原文写进死信队列并计数，再确认掉。确认是为了不卡住链路——
            # 留在 processing 等 recover 只会在下次启动时又冒出来，永远处理不掉。
            for item, reason in bad:
                _record_dead(client, item, reason, stats)
                queue.ack(item)

            if good:
                # ① 分流：降噪命中的不投检测器，但**照样入库**（ES 必须是全量事实源）
                payloads: list[tuple[str, dict[str, Any]]] = []
                kept: list[tuple[str, dict[str, Any]]] = []
                for item, entry in good:
                    payload = _payload(entry)
                    payloads.append((item, payload))
                    name = ingest_filter.match(entry)
                    if name:
                        stats["filtered"] += 1
                        ingest_filter.record_hit(name, entry)
                    elif not log_types.is_detectable(entry):
                        # 日志类型闸门（批 1）：运维类（ntp/packet_filter/reporter/stats/ja4ssh/ja4d）
                        # 与白名单外的未知类型只入库当证据——进了检测只会污染画像与规则命中率。
                        # 名单外的类型没有静默丢：ES 里 log_type 保留原名且 log_type_known=False，
                        # 用 log_type.keyword 聚合就能看出"多了哪条流"。
                        cls = log_types.classify_entry(entry)
                        stats[f"{cls}_es_only"] += 1
                    else:
                        kept.append((item, payload))

                # ② 喂检测器：检测是实时车道，成败与入库无关
                for item, payload in kept:
                    if item in pushed:
                        continue
                    client.lpush(
                        settings.detector_raw_queue, json.dumps(payload, ensure_ascii=False)
                    )
                    pushed.add(item)
                # ③ 入库：全量（含被降噪挡下的），2xx 才确认；失败就放回队尾重试
                if _post(http, url, [p for _, p in payloads]):
                    for item, _ in payloads:
                        queue.ack(item)
                        pushed.discard(item)
                    stats["delivered"] += len(payloads)
                else:
                    stats["deferred"] += len(payloads)
                    # 为什么不用「留在 processing 等下轮 recover」：recover 只在启动时跑一次，
                    # Logstash 一挂积压就会一直躺在 processing 里直到进程重启。放回队尾才是
                    # 真正的重试。顺序要倒着 rpush（本批是从 raw 右端弹出来的，最早的在
                    # items[0]），这样下一轮先处理最老的那条。
                    for item, _ in reversed(payloads):
                        queue.requeue(item)
                    time.sleep(settings.collector_retry_backoff_seconds)

            last_log = _maybe_log(stats, last_log, queue, client)
            _trim_queue(client, settings.collector_collect_queue, settings.collector_queue_max)


def _stop(signum: int, _frame: Any) -> None:
    """停止前不做任何确认：留在 processing 的消息下次启动会被回灌。"""
    log.info("收到信号 %s，正在停止归一化服务（未确认的消息下次启动会回灌）", signum)
    raise KeyboardInterrupt


def main() -> None:
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        run()
    except KeyboardInterrupt:
        log.info("归一化服务已停止")


if __name__ == "__main__":
    main()
