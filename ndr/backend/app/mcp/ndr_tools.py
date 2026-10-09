"""NDR 自己的调查工具：事件、规则、检测器状态、网段、排除过滤、结论写回、基线。

与 `app/investigation/tools.py` 那 10 个「查 ES」的工具不同，这些查的是 **NDR 自身的
运行状态与配置** —— 智能体在别处（案件库、资产、情报、记忆）拿不到，只能问 NDR。

统一签名 `run(params: dict) -> dict`，**没有 ctx**：这些是无状态纯函数，参数进、结果出。
MCP 层拿到结果后统一转成 JSON 文本给模型。
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any

import redis
from sqlalchemy import select

from app.config import settings
from app.mcpapi import (
    ConclusionRecord,
    ExclusionFilter,
    IngestFilter,
    Rule,
    build_networks,
    catalog,
    detector_health,
    es_client,
    es_config,
    in_scope,
    is_valid_fuid,
    list_profiles,
    lookup_extract,
    monitored_nets,
    networks_status,
    resolve_extract_path,
    session_factory,
    stats_lookup,
    top_anomalies,
)


def _client() -> Any:
    """Redis 客户端。

    返回类型刻意写成 `Any`：redis-py 把同步命令的返回注解成 `Awaitable[T] | T`，
    不这么写每处调用都要挂 `# pyright: ignore`（`api/routes/detector.py` 里就是那么干的）。
    """
    return redis.Redis.from_url(settings.redis_url, decode_responses=True)


def _hint(client: Any, key: str, field: str, default: int = 0) -> int:
    try:
        return int(client.hget(key, field) or default)
    except (TypeError, ValueError, redis.RedisError):
        return default


def _hstr(client: Any, key: str, field: str) -> str:
    try:
        return str(client.hget(key, field) or "")
    except (TypeError, redis.RedisError):
        return ""


def _llen(client: Any, key: str) -> int:
    try:
        return int(client.llen(key) or 0)
    except (TypeError, ValueError, redis.RedisError):
        return 0


# ---------- get_event ----------


def _get_event(args: dict[str, Any]) -> dict[str, Any]:
    """按事件ID 或指纹取「这条事件已经有哪些结论」。"""
    event_id = str(args.get("event_id") or "").strip()[:64]
    fingerprint = str(args.get("fingerprint") or "").strip()[:64]
    if not event_id and not fingerprint:
        return {"error": "event_id 与 fingerprint 至少给一个（推送载荷里都带着）"}

    out: dict[str, Any] = {"event_id": event_id, "fingerprint": fingerprint}
    with session_factory() as db:
        rows: list[ConclusionRecord] = []
        if fingerprint:
            rows = list(
                db.execute(
                    select(ConclusionRecord)
                    .where(ConclusionRecord.fingerprint == fingerprint)
                    .order_by(ConclusionRecord.updated_at.desc())
                    .limit(settings.mcp_max_rows)
                )
                .scalars()
                .all()
            )
        if not rows and event_id:
            rows = list(
                db.execute(
                    select(ConclusionRecord)
                    .where(ConclusionRecord.event_id == event_id)
                    .order_by(ConclusionRecord.updated_at.desc())
                    .limit(settings.mcp_max_rows)
                )
                .scalars()
                .all()
            )
        out["conclusions"] = [
            {
                "id": str(r.id),
                "dedup_key": r.dedup_key,
                "event_id": r.event_id,
                "fingerprint": r.fingerprint,
                "thread_id": r.thread_id,
                "status": r.status,
                "severity": r.severity,
                "summary": r.summary,
                "detail": r.detail or {},
                "updated_at": r.updated_at.isoformat() if r.updated_at else "",
            }
            for r in rows
        ]

        if fingerprint:
            # 第 5 期起判重下放到智能体（按事件组指纹），NDR 侧**不再记录投递指纹**，
            # 所以这里没有"被投递过什么"可返回。以前它返回一个只有 note 的 dispatch 块，
            # 看着像有数据实则恒空（2026-10 MCP QA）：改为一句顶层说明，不再放假结构。
            out["delivery_note"] = (
                "NDR 侧不记录投递指纹（判重在智能体侧按事件组指纹做）；"
                "投递/分析状态请看智能体的分析记录。本工具只回结论。"
            )

    if not out["conclusions"]:
        out["note"] = "没有这条事件的结论：ID 可能不对，或结论已过保留期被清掉。"
    return out


# ---------- get_rule ----------


def _get_rule(args: dict[str, Any]) -> dict[str, Any]:
    """按规则名或规则 ID 取规则原文（智能体判断「这条摘要为什么被判可疑」时的依据）。"""
    name = str(args.get("name") or "").strip()[:128]
    rule_id = str(args.get("rule_id") or "").strip()[:64]
    if not name and not rule_id:
        return {"error": "name 与 rule_id 至少给一个"}
    with session_factory() as db:
        row = None
        if rule_id:
            row = db.get(Rule, rule_id)
        if row is None and name:
            row = db.execute(select(Rule).where(Rule.name == name)).scalar_one_or_none()
        if row is None:
            return {"error": f"没有找到规则 {name or rule_id}（规则名要完全一致）"}
        return {
            "id": str(row.id),
            "name": row.name,
            "description": row.description,
            "severity": row.severity,
            "source": row.source,
            "enabled": bool(row.enabled),
            "priority": int(row.priority or 0),
            "conditions": row.conditions or {},
        }


# ---------- detector_status ----------


def _detector_status(args: dict[str, Any]) -> dict[str, Any]:
    """检测器现在的状态：队列积压、吞吐、丢弃/去重/失败计数、主从、内存。

    字段口径与 `api/routes/detector.py` 完全一致（同一个 `shentong:detector:rates` 哈希），
    这样界面看到和智能体看到的不会出现两套数字。
    """
    client = _client()
    raw = settings.detector_raw_queue
    digest = settings.detector_digest_queue
    processing = settings.detector_processing_queue
    interval = _hint(client, "shentong:detector:rates", "interval_seconds", 60)
    interval = max(1, interval)

    def per_min(field: str) -> float:
        # 速率用「区间增量 ÷ 区间秒数」反推：直接拿累计值除以运行时长会算出
        # 远超理论上限的数字（route 里有注释记过这个坑）。
        delta = _hint(client, "shentong:detector:rates", f"d_{field}")
        return round(delta * 60.0 / interval, 2)

    status: dict[str, Any] = {
        "queues": {
            "raw": _llen(client, raw),
            "digest": _llen(client, digest),
            "processing": _llen(client, processing),
            "raw_limit": settings.detector_raw_queue_max,
        },
        "rates_per_minute": {
            "scanned": per_min("scanned"),
            "hit": per_min("hit"),
            "digest": per_min("digest"),
            "delivered": per_min("delivered"),
            "digest_limit": settings.detector_max_digests_per_minute,
        },
        "cumulative": {
            "scanned": _hint(client, "shentong:detector:rates", "scanned"),
            "hit": _hint(client, "shentong:detector:rates", "hit"),
            "digest": _hint(client, "shentong:detector:rates", "digest"),
            "delivered": _hint(client, "shentong:detector:rates", "delivered"),
            "raw_trimmed": _hint(client, "shentong:detector:rates", "raw_trimmed"),
            "requeued": _hint(client, "shentong:detector:rates", "requeued"),
        },
        "dropped": {
            "count": _hint(client, settings.detector_drop_key, "dropped"),
            "last_at": _hstr(client, settings.detector_drop_key, "last_dropped_at"),
        },
        "task_failed": {
            "failed": _hint(client, settings.detector_task_failed_key, "failed"),
            "last_at": _hstr(client, settings.detector_task_failed_key, "last_failed_at"),
        },
    }

    # 选主：只有持锁的那个实例在跑检测，判断「检测器是不是活着」看这里
    try:
        ttl = int(client.ttl(settings.detector_leader_key))
        holder = str(client.get(settings.detector_leader_key) or "")
    except (TypeError, ValueError, redis.RedisError):
        ttl, holder = -2, ""
    status["leader"] = {
        "active": ttl > 0,
        "holder": holder,
        "ttl_seconds": ttl,
    }

    # Redis 内存：NDR 历史上被队列打满过一次，这个数字要能直接看到
    try:
        status["redis_memory"] = detector_health(client)
    except Exception as exc:  # noqa: BLE001
        status["redis_memory"] = {"error": str(exc)}

    # 判重闸门（第 5 期）已退役：投递状态与去重都在智能体侧，NDR 只报投递与丢弃计数
    status["dedup"] = {"enabled": False, "note": "判重已下放到智能体（按事件组指纹）"}

    status["enabled"] = bool(settings.detector_enabled)
    return status


# ---------- list_networks ----------


def _list_networks(args: dict[str, Any]) -> dict[str, Any]:
    """监控网段清单（判定「内网/外网」的依据，也是 Zeek 抓包过滤的条件）。"""
    nets = monitored_nets()
    state = networks_status()
    return {
        "networks": nets,
        "count": len(nets),
        "configured": bool(state.get("configured")),
        "hint": "清单为空时 Zeek 不过滤（抓全部）；内网判定也跟着失效，描述流量时要说明这一点。",
    }


# ---------- list_filters ----------


def _list_filters(args: dict[str, Any]) -> dict[str, Any]:
    """两道过滤闸门的清单：入库前降噪（不投检测器）与排除过滤（跳过分析）。

    为什么要一起给智能体看：这两类配置都会让「某条事件没有告警」，如果智能体不知道
    它们的存在，就容易把「被过滤掉」误读成「本来就没事」——漏报的锅不能扣在配置头上。
    """
    with session_factory() as db:
        rows = (
            db.execute(
                select(ExclusionFilter).order_by(ExclusionFilter.priority, ExclusionFilter.name)
            )
            .scalars()
            .all()
        )
        exclusion = [
            {
                "id": str(r.id),
                "name": r.name,
                "description": r.description,
                "enabled": bool(r.enabled),
                "priority": int(r.priority or 0),
                "conditions": r.conditions or {},
            }
            for r in rows
        ]
        rows = (
            db.execute(select(IngestFilter).order_by(IngestFilter.priority, IngestFilter.name))
            .scalars()
            .all()
        )
        ingest = [
            {
                "id": str(r.id),
                "name": r.name,
                "description": r.description,
                "enabled": bool(r.enabled),
                "priority": int(r.priority or 0),
                "conditions": r.conditions or {},
            }
            for r in rows
        ]
    return {
        "filters": exclusion,
        "ingest_filters": ingest,
        "hint": (
            "两道闸门：`ingest_filters` 命中 = 事件进 ES 但**没进检测器**（所以没有告警）；"
            "`filters` 命中 = 进了检测器但跳过了分析。两类都不产生结论，"
            "别把「被过滤」当成「没有异常」。"
        ),
    }


# ---------- record_conclusion ----------

# 结论状态 / 定级的枚举。以前是把模型给的原字符串截断直接落库，于是库里既有
# "true_positive" 又有 "高危"、还有拼错的词，界面按状态统计/过滤全不准。这里改成
# 「先归一化、再校验」：认识的值统一成规范写法入库，不认识的值报错并列出可选值，
# 让模型自我纠正（与工具集其它参数的 fail-closed 纪律一致）。
STATUS_VALUES = (
    "true_positive",
    "false_positive",
    "benign",
    "suspicious",
    "inconclusive",
    "pending",
    "done",
)
SEVERITY_VALUES = ("info", "low", "medium", "high", "critical")
_STATUS_ALIASES = {
    "true_positive": "true_positive",
    "truepositive": "true_positive",
    "tp": "true_positive",
    "真阳性": "true_positive",
    "确认攻击": "true_positive",
    "攻击": "true_positive",
    "false_positive": "false_positive",
    "falsepositive": "false_positive",
    "fp": "false_positive",
    "误报": "false_positive",
    "误判": "false_positive",
    "benign": "benign",
    "正常": "benign",
    "白名单": "benign",
    "无异常": "benign",
    "suspicious": "suspicious",
    "可疑": "suspicious",
    "存疑": "suspicious",
    "inconclusive": "inconclusive",
    "待定": "inconclusive",
    "不确定": "inconclusive",
    "未定": "inconclusive",
    "pending": "pending",
    "处理中": "pending",
    "待处理": "pending",
    "进行中": "pending",
    "done": "done",
    "完成": "done",
    "结案": "done",
    "已结案": "done",
    "已处理": "done",
}
_SEVERITY_ALIASES = {
    "info": "info",
    "信息": "info",
    "提示": "info",
    "low": "low",
    "低": "low",
    "低危": "low",
    "medium": "medium",
    "中": "medium",
    "中危": "medium",
    "moderate": "medium",
    "high": "high",
    "高": "high",
    "高危": "high",
    "critical": "critical",
    "严重": "critical",
    "紧急": "critical",
}


def _enum_value(
    raw: Any,
    *,
    default: str,
    allowed: tuple[str, ...],
    aliases: dict[str, str],
    label: str,
) -> tuple[str, str]:
    """归一化一个枚举参数，返回 ``(规范值, 错误信息)``；空值用默认值，错误信息为空表示通过。"""
    text = str(raw or "").strip()
    if not text:
        return default, ""
    value = aliases.get(text.lower())
    if value is None:
        return "", f"{label} 不认识：{text!r}。只能填：{'、'.join(allowed)}（中文别名也认）"
    return value, ""


def _record_conclusion(args: dict[str, Any]) -> dict[str, Any]:
    """把调查结论写回 NDR（界面可见）。

    **同一事件只留一份**：`dedup_key` = 事件ID（没有就用指纹），再来一次覆盖旧的。
    这里不判重、不拦重复告警 —— 判重的权威在智能体侧，这里只是审计与展示用的副本。
    """
    summary = str(args.get("summary") or "").strip()
    if not summary:
        return {"error": "summary 必填：写清结论本身，界面列表主要看它"}
    event_id = str(args.get("event_id") or "").strip()[:64]
    fingerprint = str(args.get("fingerprint") or "").strip()[:64]
    dedup_key = (event_id or fingerprint)[:64]
    if not dedup_key:
        return {"error": "event_id 与 fingerprint 至少给一个，用它作为结论的归属键"}

    detail = args.get("detail")
    if not isinstance(detail, dict):
        detail = {"text": detail} if detail not in (None, "") else {}

    status, err = _enum_value(
        args.get("status"),
        default="done",
        allowed=STATUS_VALUES,
        aliases=_STATUS_ALIASES,
        label="status",
    )
    if err:
        return {"error": err}
    severity, err = _enum_value(
        args.get("severity"),
        default="info",
        allowed=SEVERITY_VALUES,
        aliases=_SEVERITY_ALIASES,
        label="severity",
    )
    if err:
        return {"error": err}

    now = datetime.now(UTC)
    with session_factory() as db:
        row = db.execute(
            select(ConclusionRecord).where(ConclusionRecord.dedup_key == dedup_key)
        ).scalar_one_or_none()
        created = row is None
        if row is None:
            row = ConclusionRecord(dedup_key=dedup_key, created_at=now)
            db.add(row)
        row.event_id = event_id or row.event_id or ""
        row.fingerprint = fingerprint or row.fingerprint or ""
        row.thread_id = str(args.get("thread_id") or row.thread_id or "")[:64]
        row.status = status[:32]
        row.severity = severity[:16]
        row.summary = summary
        row.detail = detail
        row.updated_at = now
        db.commit()
        row_id = str(row.id)

    return {
        "ok": True,
        "id": row_id,
        "created": created,
        "dedup_key": dedup_key,
        "note": "已写入 NDR；同一事件再次写回会覆盖这一条。" if not created else "已写入 NDR。",
    }


# ---------- fetch_window ----------

# 一次最多交回的条目数。回溯是「把窗口内的东西整批拿走去跑规则」，比查几条要重得多，
# 所以单独给一个更大的上限（智能体自己还有 lookback_max_logs 封顶）。
WINDOW_MAX = 5000


def _str_list(value: Any, cap: int = 200) -> list[str]:
    if isinstance(value, str):
        items = [p.strip() for p in value.replace(",", "\n").splitlines()]
    elif isinstance(value, (list, tuple)):
        items = [str(v).strip() for v in value]
    else:
        items = []
    return [i for i in items if i][:cap]


def _es_index() -> str:
    """当前**运行时**事件索引族。

    后台「系统配置」里 `es.events_index` 是可改的（`ndr/backend/app/ingestion/es_config.py`），
    只读静态 `settings.es_events_index` 会出现「采集已写进新索引族、这里还在查老的」——
    表现为「明明有数据却查不到」。静态值只作兜底。
    """
    return str(es_config().get("es.events_index") or settings.es_events_index)


def _es_path(index: str, field: str) -> str:
    """统一字段名 → ES 精确匹配路径（text 字段必须走 `.keyword`）。"""
    paths = catalog.term_paths(index, catalog.resolve(field) or field)
    return paths[0] if paths else field


def _octet_prefix(net: Any) -> str | None:
    """按字节对齐的 IPv4 网段（/8 /16 /24）→ keyword 前缀串，其他返回 None。

    ``str(network_address)`` 在非对齐网段上会给出「网络地址」而非调用方原串（例如
    10.1.2.5/24 → 10.1.2.0），拿它做前缀会多匹配，所以只接受对齐网段。
    """
    if getattr(net, "version", 0) != 4 or net.prefixlen not in (8, 16, 24):
        return None
    octets = str(net.network_address).split(".")
    return ".".join(octets[: net.prefixlen // 8]) + "."


def _net_clauses(
    index: str, networks: list[Any], paths: tuple[str, str]
) -> tuple[list[dict[str, Any]], list[str]]:
    """把网段尽量下推到 ES，返回 ``(子句列表, 只能取回后本地过滤的网段字符串)``。

    字段是 ES `ip` 类型时用 CIDR term（原生支持）；否则 text/keyword 只能：
    - `/8 /16 /24` 这类按字节对齐的网段 → `prefix`（实测可用）；
    - 单个地址（/32、/128）→ 精确 `term`；
    - 其余（如 /12、/20）→ 下推一定不准，交给调用点本地过滤并在 note 里说明。
    """
    if catalog.es_type(index, "src_ip") == "ip":
        cidrs = [str(n) for n in networks]
        return (
            [
                {
                    "bool": {
                        "should": [{"terms": {paths[0]: cidrs}}, {"terms": {paths[1]: cidrs}}],
                        "minimum_should_match": 1,
                    }
                }
            ],
            [],
        )

    should: list[dict[str, Any]] = []
    local_only: list[str] = []
    for net in networks:
        prefix = _octet_prefix(net)
        if prefix is not None:
            should.extend([{"prefix": {paths[0]: prefix}}, {"prefix": {paths[1]: prefix}}])
        elif net.prefixlen == net.max_prefixlen:
            host = str(net.network_address)
            should.extend([{"term": {paths[0]: host}}, {"term": {paths[1]: host}}])
        else:
            local_only.append(str(net))
    if not should:
        return [], local_only
    # 多个网段是「或」：用 should + minimum_should_match=1 合并成一条子句。
    return [{"bool": {"should": should, "minimum_should_match": 1}}], local_only


def _fetch_window(args: dict[str, Any]) -> dict[str, Any]:
    """按时间窗（可再按网段/IP）整批取回事件条目，交给调用方自己筛。

    与 `search_events` 的分工：那个是「查几条看看」，返回的是摘要字段；
    这个是「把窗口里的条目交出来」，返回完整条目（含 `raw` 原文），条数由调用方限。
    典型用途是回溯：拉历史窗口 → 调用方自己跑规则 → 看这组 IP 以前干过什么。

    每条带 `ref`（`es:<索引>/<文档id>`），可直接当证据引用。
    """
    start = str(args.get("start") or "").strip()
    end = str(args.get("end") or "").strip()
    if not start or not end:
        return {"error": "start 与 end 必填（ISO 时间，如 2026-02-14T00:00:00Z）"}
    try:
        limit = int(args.get("limit") or WINDOW_MAX)
    except (TypeError, ValueError):
        limit = WINDOW_MAX
    limit = max(1, min(limit, WINDOW_MAX))
    ips = _str_list(args.get("ips"))
    nets = build_networks(_str_list(args.get("nets")))

    # 索引取运行时配置：后台「系统配置」能改 es.events_index，只读静态 settings 会
    # 出现「采集写进新索引族、这个工具还在查老的」。（静态值仍作兜底。）
    index = _es_index()
    src_path, dst_path = _es_path(index, "src_ip"), _es_path(index, "dst_ip")

    conditions: list[dict[str, Any]] = [{"range": {"@timestamp": {"gte": start, "lt": end}}}]
    if ips:
        # 指定了 IP 就用它收窄——这正是调用方本来要做的事，放在 ES 侧做省得白拉一堆。
        # 路径必须是 keyword 路径：src_ip 实机是 text（动态映射），对主路径做 terms
        # 只在“分词后恰好留住整串”时才匹配，属于会静默丢结果的坑。
        conditions.append(
            {
                "bool": {
                    "should": [
                        {"terms": {src_path: ips}},
                        {"terms": {dst_path: ips}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        )

    nets_pushed = False
    local_only_nets: list[str] = []
    if nets:
        pushable, local_only_nets = _net_clauses(index, nets, (src_path, dst_path))
        nets_pushed = not local_only_nets
        conditions.extend(pushable)

    query: dict[str, Any] = {"bool": {"filter": conditions}}

    es = es_client()
    try:
        total = int(es.count(index=index, query=query).get("count") or 0)
        resp = es.search(
            index=index,
            query=query,
            size=limit,
            sort=[{"@timestamp": "asc"}],
        )
    except Exception as exc:  # noqa: BLE001
        return {"error": f"取事件窗口失败：{exc}"}

    logs: list[dict[str, Any]] = []
    for hit in resp.get("hits", {}).get("hits", []) or []:
        doc = hit.get("_source") or {}
        if nets and not (in_scope(doc.get("src_ip"), nets) or in_scope(doc.get("dst_ip"), nets)):
            continue
        logs.append({"ref": f"es:{hit.get('_index')}/{hit.get('_id')}", **doc})

    notes: list[str] = []
    if total > len(logs):
        notes.append(f"窗口内共 {total} 条，本次只取回 {len(logs)} 条（按时间从早到晚）")
    if not ips and not nets:
        notes.append("未限定网段/ IP：这是整段时间窗的全量条目")
    if local_only_nets:
        # 下推不了的那部分网段只能取回后本地过滤 —— total 是「下推条件」的计数，
        # 不含这部分，必须说清楚，否则调用方会拿 total 当「返回条数的上限」用。
        notes.append(
            "以下网段无法下推到 ES（字段不是 ip 类型且网段不按字节对齐），"
            f"只在取回后本地过滤：{', '.join(local_only_nets)}；"
            "total 是下推条件下的条数（不含这部分）。"
        )
    return {
        "window": {"start": start, "end": end},
        "index": index,
        "total": total,
        "returned": len(logs),
        "nets_pushed_down": bool(nets) and nets_pushed,
        "logs": logs,
        "notes": notes,
    }


# ---------- baseline_lookup / entity_profile（第 8 期：基线落在 NDR 侧） ----------

BASELINE_MAX = 200
PROFILE_MAX = 50
# 提取件内容：默认回 64 KiB、硬上限 1 MiB（回的是文本，必须封顶，
# 否则一份大文件就能把模型上下文吃光）。要完整文件用 Web 下载入口。
FILE_DEFAULT_BYTES = 65536
FILE_MAX_BYTES = 1048576
_FEATURE_EXAMPLE = "conn_count"


def _cap_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(n, high))


def _baseline_lookup(args: dict[str, Any]) -> dict[str, Any]:
    """查数值基线：某个源 IP 的长期均值/标准差/样本数，以及是否过了观测期。

    三个维度（key 形如 `10.0.0.5:conn_count`）：连接数、不同目的端口数、不同目的 IP 数。
    """
    ip = str(args.get("ip") or "").strip()
    key = str(args.get("key") or "").strip()
    result = stats_lookup(ip=ip, key=key, limit=_cap_int(args.get("limit"), 50, 1, BASELINE_MAX))
    if "error" in result:
        return result
    result["note"] = (
        f"观测期 {settings.baseline_observe_days} 天内的维度 warmed=false，不参与判定；"
        "「没报偏离」不等于正常。判据是 当前值 > mean + "
        f"{settings.baseline_zscore}σ，NDR 只在摘要里打标，定性由智能体做。"
    )
    return result


def _entity_profile(args: dict[str, Any]) -> dict[str, Any]:
    """查账号/会话画像（跨窗口长期基线），可按实体键指名或只看过阈值异常。"""
    kind_raw = str(args.get("kind") or "").strip().lower()
    kind = kind_raw if kind_raw in ("account", "session") else None
    keys = _str_list(args.get("keys"))
    limit = _cap_int(args.get("limit"), 20, 1, PROFILE_MAX)
    try:
        min_risk = max(0.0, min(float(args.get("min_risk") or 0.0), 1.0))
    except (TypeError, ValueError):
        min_risk = 0.0
    if keys:
        result = list_profiles(kind=kind, keys=keys, min_risk=min_risk, limit=limit)
    elif args.get("anomalies_only"):
        result = top_anomalies(limit)
    else:
        result = list_profiles(kind=kind, min_risk=min_risk, limit=limit)
    if "error" in result:
        return result
    result["threshold"] = settings.profile_risk_threshold
    result["note"] = (
        "风险分是加权累加：新源 IP +0.35（v6 只在 /64 前缀也新时算，隐私地址轮换不算）、"
        "新 UA +0.2（非常用时段 +0.15，需画像满 "
        f"{settings.profile_hour_min_age_hours} 小时且见过 ≥{settings.profile_hour_min_coverage} 个时段）、"
        f"新接口路径 +0.25（只算接口形态，已知 ≥{settings.profile_path_min_known} 条才判）、"
        "同族跨 ≥2 个 IP +0.45（v4+v6 双栈不算会话劫持）、"
        "认证失败突增分档：≥5 且多于成功 +0.25 / ≥10 +0.35 / ≥20 且零成功 +0.6（这类基本是脚本在撞，单条即达阈值）；"
        f"达到 {settings.profile_risk_threshold} 才算异常，冷启动（观测不足）不算。"
        "风险分是「当前窗口」的值：本轮无异常会归零并清空，risk_at 是判定时间。"
    )
    return result


# ---------- file_content（提取件内容，采集面批 4） ----------


def _file_content(args: dict[str, Any]) -> dict[str, Any]:
    """取提取件的内容（有界）或元数据。

    为什么需要它：文件提取与下载通道只在 NDR 的 Web API 上（要管理员 JWT），智能体拿不到，
    于是「模型知道有个文件、却看不到文件内容」——采集面做了提取、分析面用不上（2026-10 MCP QA）。
    这里用与下载路由**完全相同**的校验（fuid 格式 + `lookup_extract` + `resolve_extract_path`），
    只把不可变的字节按有界长度回给模型。
    """
    fuid = str(args.get("fuid") or "").strip()
    if not is_valid_fuid(fuid):
        return {"error": "fuid 格式不合法（形如 Fx8HnP1AbCdEfGhIjK，8~64 位 URL 安全字符）"}
    encoding = str(args.get("encoding") or "base64").strip().lower()
    if encoding not in ("text", "base64"):
        return {"error": "encoding 只能是 text 或 base64"}
    try:
        want = int(args.get("max_bytes") or FILE_DEFAULT_BYTES)
    except (TypeError, ValueError):
        want = FILE_DEFAULT_BYTES
    want = max(1, min(want, FILE_MAX_BYTES))

    try:
        doc = lookup_extract(fuid)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"查事件库失败：{exc}"}
    if not doc:
        return {
            "error": f"没有 fuid={fuid} 的提取件（来源不是 HTTP/FTP 明文，或未开启提取、已被清理）"
        }
    path = resolve_extract_path(str(doc.get("extracted") or ""))
    if path is None:
        return {"error": "提取件字段未通过路径校验（拒绝读取）"}
    try:
        if not path.is_file():
            return {
                "error": "提取件已被清理（非白名单类型或超出容量上限，见 zeek/extract_cleanup.py）"
            }
        size = path.stat().st_size
        with path.open("rb") as fh:
            blob = fh.read(want)
    except OSError as exc:
        return {"error": f"读取提取件失败：{exc}"}

    out: dict[str, Any] = {
        "fuid": fuid,
        "filename": str(doc.get("filename") or ""),
        "mime_type": str(doc.get("mime_type") or ""),
        "size_on_disk": size,
        "es_extracted_size": doc.get("extracted_size"),
        "es_extracted_cutoff": bool(doc.get("extracted_cutoff")),
        "read_bytes": len(blob),
        "truncated": size > len(blob),
        "max_bytes": want,
        # 二进制本体不可能全塞进模型上下文：要完整文件得走这个下载入口（需 NDR 登录）
        "download": f"/api/files/{fuid}",
    }
    if encoding == "text":
        out["encoding"] = "text"
        out["content"] = blob.decode("utf-8", errors="replace")
    else:
        out["encoding"] = "base64"
        out["content_base64"] = base64.b64encode(blob).decode("ascii")
    if out["truncated"]:
        out["note"] = (
            f"只读了前 {len(blob)} 字节（文件共 {size} 字节）；需要更多请调大 max_bytes"
            f"（上限 {FILE_MAX_BYTES}），或走 download 取完整文件。"
        )
    return out


# ---------- 注册表 ----------

TOOLS: dict[str, dict[str, Any]] = {
    "get_event": {
        "run": _get_event,
        "desc": "按事件ID/指纹取这条事件已有的结论（推送载荷里带着这两个 ID）",
        "params": {"event_id": "事件ID", "fingerprint": "指纹（二者至少给一个）"},
    },
    "get_rule": {
        "run": _get_rule,
        "desc": "取检测规则原文（判断摘要为什么被判可疑）",
        "params": {"name": "规则名（完全一致）", "rule_id": "规则 ID"},
    },
    "detector_status": {
        "run": _detector_status,
        "desc": "检测器运行状态：队列积压、吞吐、丢弃/去重/失败计数、主从、Redis 内存",
        "params": {},
    },
    "list_networks": {
        "run": _list_networks,
        "desc": "监控网段清单（内网判定依据）",
        "params": {},
    },
    "list_filters": {
        "run": _list_filters,
        "desc": "两道过滤闸门清单：入库前降噪（不投检测器）与排除过滤（跳过分析）",
        "params": {},
    },
    "fetch_window": {
        "run": _fetch_window,
        "desc": "按时间窗整批取回事件条目（可限定网段/IP，含原文），用于回溯：自己跑规则看历史行为",
        "params": {
            "start": "起点（ISO 时间）",
            "end": "终点（ISO 时间）",
            "nets": "网段清单（数组或逗号分隔，可省）",
            "ips": "IP 清单（数组或逗号分隔，可省；给了就用它收窄）",
            "limit": f"最多取回条数（默认与上限都是 {WINDOW_MAX}）",
        },
    },
    "record_conclusion": {
        "run": _record_conclusion,
        "desc": "把调查结论写回 NDR（界面可见；同一事件只留一份，重复写会覆盖）",
        "params": {
            "summary": "结论正文（必填）",
            "event_id": "事件ID",
            "fingerprint": "指纹",
            "status": f"结论状态（可省，默认 done；可选：{'、'.join(STATUS_VALUES)}；中文别名也认）",
            "severity": f"定级（可省，默认 info；可选：{'、'.join(SEVERITY_VALUES)}；中文别名也认）",
            "detail": "对象：证据、处置建议等",
            "thread_id": "分析线程 ID",
        },
    },
    "baseline_lookup": {
        "run": _baseline_lookup,
        "desc": (
            "查数值基线：某个源 IP 的连接数/目的端口数/目的 IP 数的长期均值与标准差，"
            "以及是否过了观测期（判断「这条摘要是不是真的偏离常态」的依据）"
        ),
        "params": {
            "ip": "源 IP（查它的全部维度）",
            "key": f"完整维度键（形如 10.0.0.5:{_FEATURE_EXAMPLE}）",
            "limit": f"最多返回条数（默认 50，上限 {BASELINE_MAX}）",
        },
    },
    "entity_profile": {
        "run": _entity_profile,
        "desc": (
            "查账号/会话画像（跨窗口长期基线）：常用源 IP/UA/路径/时段、成功失败计数、"
            "风险分与异常理由；也能只看过阈值的异常"
        ),
        "params": {
            "kind": "account 或 session（可省，省了两种都查）",
            "keys": "实体键清单（数组或逗号分隔，可省；给了就指名查）",
            "min_risk": "只看风险 ≥ 这个值（0~1）",
            "anomalies_only": "只要过阈值的异常（true/false）",
            "limit": f"最多返回条数（默认 20，上限 {PROFILE_MAX}）",
        },
    },
    "file_content": {
        "run": _file_content,
        "desc": (
            "取提取件（Zeek 落盘的明文文件）的**内容或元数据**：按 fuid 取回有界字节；"
            "文本用 encoding=text、二进制用 base64；只要元数据（大小/类型/是否被截断）就调小 max_bytes=1"
        ),
        "params": {
            "fuid": "文件 id（事件里的 extracted/fuid 字段）",
            "encoding": "text 或 base64（默认 base64）",
            "max_bytes": f"最多读多少字节（默认 {FILE_DEFAULT_BYTES}，上限 {FILE_MAX_BYTES}）",
        },
    },
}


def tool_names() -> list[str]:
    return sorted(TOOLS)


def dispatch(name: str, params: dict[str, Any]) -> dict[str, Any]:
    """按工具名分派到对应实现；错误一律转成结构化结果（模型自我纠正，不炸掉整次调用）。

    叫 `dispatch` 而不是 `execute`：它分派的是调查工具，与任何 SQL/子进程端点无关；
    名字里带 execute 还会被静态扫描当成动态执行端点（实际参数是工具名）。
    """
    spec = TOOLS.get(name)
    if spec is None:
        return {"error": f"未知工具 {name}。可用工具：{', '.join(tool_names())}"}
    try:
        result = spec["run"](params)
        return result if isinstance(result, dict) else {"result": result}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"工具执行失败：{exc}"}
