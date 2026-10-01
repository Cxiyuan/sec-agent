"""NDR 自己的调查工具：事件、规则、检测器状态、网段、排除过滤、结论写回。

与 `app/investigation/tools.py` 那 10 个「查 ES」的工具不同，这些查的是 **NDR 自身的
运行状态与配置** —— 智能体在别处（案件库、资产、情报、记忆）拿不到，只能问 NDR。

统一签名 `run(params: dict) -> dict`，**没有 ctx**：这些是无状态纯函数，参数进、结果出。
MCP 层拿到结果后统一转成 JSON 文本给模型。
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import redis
from sqlalchemy import select

from app.config import settings
from app.db.base import SessionLocal
from app.db.models import ConclusionRecord, ExclusionFilter, IngestFilter, Rule
from app.ingestion.es_client import build_networks, in_scope
from app.ingestion.scope import monitored_nets, networks_status


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
    """按事件ID 或指纹取「这条事件被投递过什么、后来得出了什么结论」。"""
    event_id = str(args.get("event_id") or "").strip()[:64]
    fingerprint = str(args.get("fingerprint") or "").strip()[:64]
    if not event_id and not fingerprint:
        return {"error": "event_id 与 fingerprint 至少给一个（推送载荷里都带着）"}

    out: dict[str, Any] = {"event_id": event_id, "fingerprint": fingerprint}
    with SessionLocal() as db:
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
            # 第 5 期起判重下放到智能体（按事件组指纹），NDR 侧不再记录投递指纹；
            # 这里只说明「投递状态要去智能体那边看」，不再假装有本侧记录。
            out["dispatch"] = {
                "fingerprint": fingerprint,
                "note": "NDR 侧已不记录投递指纹（判重在智能体侧按事件组指纹做）；"
                "投递/分析状态请看智能体的分析记录与结论。",
            }

    if not out["conclusions"] and "dispatch" not in out:
        out["note"] = "没有这条事件的投递记录与结论：ID 可能不对，或已过保留期被清掉了。"
    return out


# ---------- get_rule ----------


def _get_rule(args: dict[str, Any]) -> dict[str, Any]:
    """按规则名或规则 ID 取规则原文（智能体判断「这条摘要为什么被判可疑」时的依据）。"""
    name = str(args.get("name") or "").strip()[:128]
    rule_id = str(args.get("rule_id") or "").strip()[:64]
    if not name and not rule_id:
        return {"error": "name 与 rule_id 至少给一个"}
    with SessionLocal() as db:
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
        "dedup": {
            "skipped": _hint(client, settings.detector_dedup_key, "skipped"),
            "last_at": _hstr(client, settings.detector_dedup_key, "last_skipped_at"),
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
        from app.detector import health

        status["redis_memory"] = health.redis_memory(client)
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
    with SessionLocal() as db:
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

    now = datetime.now(UTC)
    with SessionLocal() as db:
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
        row.status = str(args.get("status") or "done").strip()[:32]
        row.severity = str(args.get("severity") or "info").strip()[:16]
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

    boolean: dict[str, Any] = {"filter": [{"range": {"@timestamp": {"gte": start, "lt": end}}}]}
    if ips:
        # 指定了 IP 就用它收窄——这正是调用方本来要做的事，放在 ES 侧做省得白拉一堆
        boolean["should"] = [{"terms": {"src_ip": ips}}, {"terms": {"dst_ip": ips}}]
        boolean["minimum_should_match"] = 1
    query: dict[str, Any] = {"bool": boolean}

    from app.ingestion.es_client import get_es

    es = get_es()
    index = settings.es_events_index
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
    return {
        "window": {"start": start, "end": end},
        "total": total,
        "returned": len(logs),
        "logs": logs,
        "notes": notes,
    }


# ---------- 注册表 ----------

TOOLS: dict[str, dict[str, Any]] = {
    "get_event": {
        "run": _get_event,
        "desc": "按事件ID/指纹取这条事件被投递过什么、已有哪些结论（推送载荷里带着这两个 ID）",
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
            "status": "结论状态（真阳性/误报/待定…）",
            "severity": "定级",
            "detail": "对象：证据、处置建议等",
            "thread_id": "分析线程 ID",
        },
    },
}


def tool_names() -> list[str]:
    return sorted(TOOLS)


def tool_catalog_text(*, max_chars: int = 2600) -> str:
    """给模型看的工具清单（与 ES 侧工具同一格式）。"""
    lines: list[str] = []
    for name in sorted(TOOLS):
        spec = TOOLS[name]
        params = spec.get("params") or {}
        arg_text = ", ".join(f"{k}: {v}" for k, v in params.items()) or "无参数"
        lines.append(f"- {name}（{arg_text}）：{spec['desc']}")
    return "\n".join(lines)[:max_chars]


def execute(name: str, params: dict[str, Any]) -> dict[str, Any]:
    """执行工具；错误一律转成结构化结果（模型自我纠正，不炸掉整次调用）。"""
    spec = TOOLS.get(name)
    if spec is None:
        return {"error": f"未知工具 {name}。可用工具：{', '.join(tool_names())}"}
    try:
        result = spec["run"](params)
        return result if isinstance(result, dict) else {"result": result}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"工具执行失败：{exc}"}
