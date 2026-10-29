"""命中事件（PG）：唯一事件 ID + 详情证据 + 忽略 / 白名单。

设计要点（2026-10 用户要求）：

- **唯一 ID 落在 PG 主键上**：每条命中在摘要定型时写一行，`id` 就是整个系统的唯一事件 ID，
  用于关联分析（忽略、白名单、交智能体、人工追溯都引用它）；
- **目的写「IP:端口」成对**：摘要里 `dst_ips` / `dst_ports` 是两个独立列表，界面上拼成
  「IP : 端口/端口/端口」会让人看不出谁配谁（用户反馈）——这里从样例事件里取**真实配对**；
- **证据存关键字段**：够展示与判断，又不把 PG 撑爆；完整原始文档仍在 ES（按 `uid` 可回查）。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

#: `datetime.UTC` 是 3.11 才有的别名（本项目 requires-python >=3.11），这里取等价写法：
#: 行为完全相同，但不会让按旧语法解析的静态检查工具报「unknown import symbol」。
UTC = timezone.utc
from typing import Any

from sqlalchemy import String, case, cast, func, or_, select

from app.analysis import verdicts as verdicts_mod
from app.db.base import SessionLocal
from app.db.models import AnalysisTask, ConclusionRecord, HitEvent
from app.detector import clustering
from app.ingestion.log_types import EVENT_TYPE_LABELS
from app.workers.log import get_logger

log = get_logger(__name__)

#: 详情里展示多少条样例事件
_MAX_EVIDENCE = 5
#: 单条证据保留多少字段（其余字段名仅列出来，避免界面信息过载）
_EVIDENCE_FIELDS = (
    "ts",
    "log_type",
    "event_type",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "real_client_ip",
    "hop",
    "hostname",
    "uri_path",
    "query_string",
    "method",
    "status_code",
    "user_agent",
    "referer",
    "account",
    "session_id",
    "query",
    "qtype",
    "conn_state",
    "protocol",
    "community_id",
    "signature",
    "signature_id",
    "signature_severity",
    "filename",
    "md5",
    "summary",
    "uid",
    # 签名引擎（Suricata EVE）的字段名
    "dest_ip",
    "dest_port",
    "app_proto",
    "direction",
    "timestamp",  # Suricata EVE 的时间字段（顶层叫 timestamp，不是 ts）
    "flow_id",
    # 「因为什么内容被命中」——正文/查询串/请求头（会截断）
    "body",
    "resp_body",
    "query_string",
    "req_headers",
    "content_type",
    "payload_printable",
    # TLS 指纹：JA3/JA3S/JA4 类规则的**判定依据本身就是这几串哈希**（载荷是二进制，看不出问题）
    "ja3",
    "ja3s",
    "ja4",
    "tls_version",
    "cert_issuer",
)

#: 证据里**不重复输出**的字段（2026-10 用户要求）：这些在详情里已经有专门的位置 ——
#: 源/目的地址在「请求方/目的」、时间在「首次/最近」、类型在「事件类型」、
#: log_type/flow_id/alert_action/community_id 属实现细节，放在事件内容里只会干扰阅读。
_HIDDEN_IN_EVIDENCE = frozenset(
    {
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "dest_ip",
        "dest_port",
        "flow_id",
        "log_type",
        "event_type",
        "timestamp",
        "alert_action",
        "community_id",
    }
)

#: 证据去重的身份字段（同一次事件的两份文档这些字段一致，只有时间戳不同）
_EVIDENCE_ID_FIELDS = (
    "uid",
    "community_id",
    "flow_id",
    "event_type",
    "signature_id",
    "src_ip",
    "dst_ip",
    "dst_port",
    "uri_path",
)

#: 会被截断的长文本字段（用户反馈「证据看不出因为什么内容被命中」）
_TRUNCATE_FIELDS = ("body", "resp_body", "req_headers", "query_string", "payload_printable")
#: 单个长文本最多留多少字符（够判断，又不会把界面撑爆）
_MAX_TEXT = 400
#: 嵌套块里要提上来的字段（Suricata EVE 把 http/tls 信息放在子对象里）
_NESTED_BLOCKS = ("http", "tls")


def _iso(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))  # py3.11+ 认 Z
    except (TypeError, ValueError):
        return None


def _pairs(digest: dict[str, Any]) -> list[str]:
    """从样例事件里取**真实配对**的 `IP:端口`（拿不到才回落到两个列表的简单拼接）。"""
    pairs: list[str] = []
    for sample in digest.get("samples") or []:
        doc = (sample or {}).get("doc") if isinstance(sample, dict) else None
        if not isinstance(doc, dict):
            continue
        # Suricata 原始 EVE 用 dest_ip/dest_port（不是 dst_ip/dst_port）——不认这个别名就配不上对
        ip = str(doc.get("dst_ip") or doc.get("dest_ip") or "").strip()
        port = doc.get("dst_port") or doc.get("dest_port")
        if not ip:
            continue
        item = f"{ip}:{port}" if port else ip
        if item not in pairs:
            pairs.append(item)
    if pairs:
        return pairs[:20]
    ips = [str(x) for x in (digest.get("dst_ips") or []) if str(x or "").strip()]
    ports = [str(x) for x in (digest.get("dst_ports") or []) if str(x or "").strip()]
    if len(ips) == 1:
        return [f"{ips[0]}:{p}" if p else ips[0] for p in ports] or ips
    return ips[:20]


def _truncate(value: Any) -> Any:
    """长文本截断（保留长度提示），其余原样。"""
    if isinstance(value, str) and len(value) > _MAX_TEXT:
        return value[:_MAX_TEXT] + f"…（已截断，原长 {len(value)}）"
    return value


def _matched_content(doc: dict[str, Any], item: dict[str, Any]) -> None:
    """把「因为什么内容被命中」提上来：Suricata 的 http/tls 子对象 + 长文本截断。"""
    for block_name in _NESTED_BLOCKS:
        block = doc.get(block_name)
        if not isinstance(block, dict):
            continue
        for key, value in block.items():
            if value in (None, "", [], {}):
                continue
            if isinstance(value, (str, int, float, bool)):
                item[f"{block_name}.{key}"] = _truncate(value)
            elif isinstance(value, list) and all(isinstance(v, (str, int, float)) for v in value):
                item[f"{block_name}.{key}"] = [_truncate(v) for v in value]
    for key in _TRUNCATE_FIELDS:
        if key in item:
            item[key] = _truncate(item[key])


def _evidence_key(ev: dict[str, Any]) -> str:
    """证据条目的去重键（同一次事件的两份文档 @timestamp 不同，但身份字段一致）。"""
    key = "|".join(str(ev.get(k) or "") for k in _EVIDENCE_ID_FIELDS)
    if key.strip("|"):
        return key
    return repr(sorted((k, str(v)) for k, v in ev.items() if k != "other_fields"))


def dedupe_evidence(items: list[Any]) -> list[dict[str, Any]]:
    """对已入库的证据再按事件身份去重（旧记录是写入时定格的，读时兜一层）。"""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ev in items or []:
        if not isinstance(ev, dict):
            continue
        key = _evidence_key(ev)
        if key in seen:
            continue
        seen.add(key)
        out.append(ev)
    return out


def _evidence(digest: dict[str, Any]) -> list[dict[str, Any]]:
    """样例事件 → 关键字段（丢空值、控制体积、长文本截断、**按事件去重**）。

    为什么要去重（2026-10 用户反馈）：同一条事件可能被采集侧重复投递（Filebeat 重投/重放），
    两份文档的 `@timestamp` 略有差异 ⇒ 输入去重的哈希不同 ⇒ 都被聚合进同一条命中 ⇒
    详情里就出现两条**内容完全一样**的"事件内容"。这里按事件身份去重，界面上只留一条。
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for sample in (digest.get("samples") or [])[: _MAX_EVIDENCE * 2]:
        doc = (sample or {}).get("doc") if isinstance(sample, dict) else None
        if not isinstance(doc, dict):
            continue
        item = {
            k: doc.get(k)
            for k in _EVIDENCE_FIELDS
            if k not in _HIDDEN_IN_EVIDENCE and doc.get(k) not in (None, "", [], {})
        }
        if isinstance(sample, dict) and sample.get("source"):
            item["source"] = sample["source"]
        # 签名引擎的告警在原始 EVE 里是嵌套的 alert 对象（signature/signature_id/category/
        # severity/metadata.threat_type）——不提上来，详情里就看不出「命中了哪条签名」
        # （实测：只显示"签名命中(高危)"，看不出是 Cobalt Strike JA3S 还是别的）。
        # 去重键：优先用能唯一标识「一次事件」的字段；都没有就退回内容本身
        key = "|".join(str(doc.get(k) or "") for k in _EVIDENCE_ID_FIELDS)
        if not key.strip("|"):
            key = repr(sorted((k, str(v)) for k, v in item.items() if k != "other_fields"))
        if key in seen:
            continue
        seen.add(key)
        alert = doc.get("alert")
        if isinstance(alert, dict):
            for src_key, dst_key in (
                ("signature", "signature"),
                ("signature_id", "signature_id"),
                ("category", "signature_category"),
                ("severity", "signature_severity"),
                ("action", "alert_action"),
            ):
                if alert.get(src_key) not in (None, "", [], {}):
                    item[dst_key] = alert[src_key]
            meta = alert.get("metadata")
            if isinstance(meta, dict) and meta.get("threat_type"):
                item["signature_threat_type"] = meta["threat_type"]
        for key in ("app_proto", "direction"):
            if doc.get(key) not in (None, "", [], {}):
                item[key] = doc[key]
        _matched_content(doc, item)
        for key in list(item):
            if key in _HIDDEN_IN_EVIDENCE or key.startswith(("http.dest", "http.src")):
                item.pop(key, None)
        # 其余字段名列出来（便于知道还能查什么），不落值
        extra = sorted(set(doc) - set(_EVIDENCE_FIELDS))
        if extra:
            item["other_fields"] = extra[:40]
        out.append(item)
    return out


#: 列表场景 `agent_summary` 截断到多少字符（全文在详情里看）
_AGENT_SUMMARY_MAX = 200


def _conclusion_keys_of(row: HitEvent) -> list[str]:
    """hit 行 → 结论归属键候选（与 `mcp/ndr_tools._record_conclusion` 的 dedup_key 同规则）。

    `dedup_key = (event_id or fingerprint)[:64]`：对命中事件而言 event_id 就是本表主键
    `id`（智能体经 `search_hits` 拿到的就是它）。`HitEvent` 没有 fingerprint 列
    （指纹只活在摘要/EventGroup 层），所以候选键就一个；智能体只按指纹记结论时
    匹配不上，界面按「无结论」处理（字段为 null）。
    """
    event_id = str(row.id or "").strip()[:64]
    return [event_id] if event_id else []


def _agent_conclusion_map(rows: list[HitEvent]) -> dict[str, ConclusionRecord]:
    """一次 `IN` 批量取本页命中的智能体结论，映射 ``dedup_key → 记录``。

    为什么批量：每行单独查一次就是 N+1（一页 200 条 = 200 次 SQL）。
    `dedup_key` 唯一且 hit 主键唯一，一个 hit 至多命中一条记录，不会串行。
    读失败按「无结论」处理（返回空表），不能因为结论表挂了把整个事件列表拖垮。
    """
    keys: list[str] = []
    for row in rows:
        for key in _conclusion_keys_of(row):
            if key and key not in keys:
                keys.append(key)
    if not keys:
        return {}
    try:
        with SessionLocal() as db:
            records = list(
                db.scalars(
                    select(ConclusionRecord).where(ConclusionRecord.dedup_key.in_(keys))
                ).all()
            )
    except Exception as exc:  # noqa: BLE001 — 结论读失败只丢结论字段，不影响事件本身
        log.warning("读智能体结论失败: %s", exc)
        return {}
    return {r.dedup_key: r for r in records}


def _agent_fields(rec: ConclusionRecord | None, *, detail: bool = False) -> dict[str, Any]:
    """一条 ConclusionRecord → 平铺的 `agent_*` 字段（无记录全 null）。"""
    if rec is None:
        fields: dict[str, Any] = {
            "agent_status": None,
            "agent_severity": None,
            "agent_summary": None,
            "agent_updated_at": None,
        }
        if detail:
            fields["agent_detail"] = None
            fields["agent_thread_id"] = None
        return fields
    summary = str(rec.summary or "")
    if len(summary) > _AGENT_SUMMARY_MAX:
        summary = summary[:_AGENT_SUMMARY_MAX] + "…"
    fields = {
        "agent_status": str(rec.status or ""),
        "agent_severity": str(rec.severity or "") or None,
        "agent_summary": summary or None,
        "agent_updated_at": rec.updated_at.isoformat() if rec.updated_at else None,
    }
    if detail:
        fields["agent_detail"] = dict(rec.detail or {}) if isinstance(rec.detail, dict) else {}
        fields["agent_thread_id"] = str(rec.thread_id or "") or None
    return fields


#: 智能体**尚未返回结论**的特殊筛选值（没有结论记录）
AGENT_STATUS_UNANALYZED = "unanalyzed"

#: `agent_status` 允许的筛选值：结论词表 + 流程态 + unanalyzed
AGENT_FILTER_STATUSES: frozenset[str] = frozenset(
    (*verdicts_mod.STATUS_VALUES, AGENT_STATUS_UNANALYZED)
)

#: 派工任务态 → 前端能用的四档（`pending/deferred`=排队、`claimed`=分析中、`done`、`stuck/expired`=失败）
AGENT_TASK_BUCKETS: dict[str, tuple[str, ...]] = {
    "queued": ("pending", "deferred"),
    "claimed": ("claimed",),
    "done": ("done",),
    "failed": ("stuck", "expired"),
}

#: 列表筛选允许的任务态（含「没有派工任务」）
AGENT_TASK_STATES: frozenset[str] = frozenset(("none", *AGENT_TASK_BUCKETS))

#: 桶 → 中文（前端直接显示；这里描述的是流程，与结论态分开）
AGENT_TASK_STATE_LABELS: dict[str, str] = {
    "none": "未派工",
    "queued": "排队中",
    "claimed": "分析中",
    "done": "已完成",
    "failed": "已失败",
}

#: 结论态排序：聚合簇时「真阳性优先，其次可疑/无法定性/误报」
_AGENT_STATUS_RANK: dict[str, int] = {
    "true_positive": 5,
    "suspicious": 4,
    "inconclusive": 3,
    "pending": 2,
    "false_positive": 1,
    "benign": 1,
    "done": 1,
}

#: 严重度排序（簇聚合用）
_SEVERITY_RANK: dict[str, int] = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _agent_status_condition(agent_status: str) -> Any | None:
    """`agent_status` 筛选 → SQL 条件（纯函数，不碰数据库）。

    支持**逗号分隔多值**（OR），例如事件中心默认的 `true_positive,suspicious`
    （= 智能体确认为可疑/威胁）。`unanalyzed` 可以单独用，也可以和具体状态混用
    （混用时 = 有这些结论 **或** 还没结论）。未识别的值忽略；全脏值不加条件。
    """
    wanted = {
        item.strip().lower()
        for item in str(agent_status or "").split(",")
        if item.strip() != ""
    }
    values = {item for item in wanted if item in AGENT_FILTER_STATUSES}
    if not values:
        return None

    def confirmed() -> Any:
        return select(ConclusionRecord.dedup_key).where(
            # hit 主键是 UUID、结论键是 VARCHAR(64)：SQL 侧必须显式转文本再比
            ConclusionRecord.dedup_key == cast(HitEvent.id, String),
            ConclusionRecord.status.in_(values - {AGENT_STATUS_UNANALYZED}),
        ).exists()

    def unanalyzed() -> Any:
        return ~select(ConclusionRecord.dedup_key).where(
            ConclusionRecord.dedup_key == cast(HitEvent.id, String)
        ).exists()

    statuses = values - {AGENT_STATUS_UNANALYZED}
    if not statuses:
        return unanalyzed()
    if AGENT_STATUS_UNANALYZED in values:
        return or_(confirmed(), unanalyzed())
    return confirmed()


def _agent_task_state_condition(agent_task_state: str) -> Any | None:
    """`agent_task_state` 筛选 → SQL 条件（纯函数）。

    派工任务与命中事件的关联键：`analysis_tasks.hint->>'事件ID'`（与 claim_tasks
    下发的 hint 同源）。一次 EXISTS 子查询，不逐行查。
    """
    value = str(agent_task_state or "").strip().lower()
    if value == "" or value not in AGENT_TASK_STATES:
        return None
    exists = select(AnalysisTask.id).where(
        AnalysisTask.kind == "hit",
        AnalysisTask.hint["事件ID"].astext == cast(HitEvent.id, String),
    )
    if value == "none":
        return ~exists.exists()
    return exists.where(AnalysisTask.state.in_(AGENT_TASK_BUCKETS[value])).exists()


def _agent_task_bucket(state: str) -> str:
    """任务状态 → 四档桶。"""
    value = str(state or "").strip()
    if value == "":
        return "none"
    for bucket, states in AGENT_TASK_BUCKETS.items():
        if value in states:
            return bucket
    return "failed"


def _agent_task_map(rows: list[HitEvent]) -> dict[str, AnalysisTask]:
    """一次 `IN` 批量取本页事件对应的派工任务（`hint.事件ID → 最新一条`）。

    读失败按「没有任务」处理：事件列表不能因为任务表挂了就打不开。
    """
    ids = [str(row.id) for row in rows if str(row.id or "").strip()]
    if not ids:
        return {}
    try:
        with SessionLocal() as db:
            tasks = list(
                db.scalars(
                    select(AnalysisTask)
                    .where(
                        AnalysisTask.kind == "hit",
                        AnalysisTask.hint["事件ID"].astext.in_(ids),
                    )
                    .order_by(AnalysisTask.created_at.desc())
                ).all()
            )
    except Exception as exc:  # noqa: BLE001 — 任务读失败只丢任务字段，不影响事件本身
        log.warning("读派工任务失败: %s", exc)
        return {}
    out: dict[str, AnalysisTask] = {}
    for task in tasks:
        hint = task.hint if isinstance(task.hint, dict) else {}
        event_id = str(hint.get("事件ID") or "")
        if event_id and event_id not in out:
            out[event_id] = task
    return out


def _agent_task_fields(
    task: AnalysisTask | None,
    conclusion: ConclusionRecord | None,
    *,
    detail: bool = False,
) -> dict[str, Any]:
    """一条派工任务 → 平铺的 `agent_task_*` 字段（无任务时 `agent_task_state=none`）。"""
    if task is None:
        fields: dict[str, Any] = {"agent_task_state": "none", "agent_task_id": ""}
        if detail:
            fields["agent_task"] = None
        return fields
    bucket = _agent_task_bucket(task.state)
    fields: dict[str, Any] = {
        "agent_task_state": bucket,
        "agent_task_id": str(task.id),
    }
    if detail:
        claimed_at = ""
        if str(task.state or "") == "claimed" and task.updated_at is not None:
            claimed_at = task.updated_at.isoformat()
        fields["agent_task"] = {
            "task_id": str(task.id),
            "state": str(task.state or ""),
            "bucket": bucket,
            "claimed_by": str(task.claimed_by or ""),
            "verdict": str(conclusion.status or "") if conclusion is not None else "",
            "claimed_at": claimed_at,
        }
    return fields


def _rows_to_dict(rows: list[HitEvent], *, detail: bool = False) -> list[dict[str, Any]]:
    conclusions = _agent_conclusion_map(rows)
    tasks = _agent_task_map(rows)
    out: list[dict[str, Any]] = []
    for row in rows:
        item: dict[str, Any] = {
            "id": row.id,
            "created_at": row.created_at.isoformat() if row.created_at else "",
            "first_seen": row.first_seen.isoformat() if row.first_seen else "",
            "last_seen": row.last_seen.isoformat() if row.last_seen else "",
            "rule": row.rule,
            # 来源类别（特征匹配 / 行为分析 / 基线偏离）——界面按这三类展示，不再提采集器名字
            "source_kind": getattr(row, "source_kind", "") or "behavior_analysis",
            # 告警簇（归类 + 网段 + 小时）：界面按簇折叠时用，单条也能看到自己属于哪一簇
            "cluster_id": getattr(row, "cluster_id", "") or "",
            "source_label": SOURCE_LABELS.get(
                getattr(row, "source_kind", "") or "behavior_analysis", "行为分析"
            ),
            "severity": row.rule_severity,
            "source": row.rule_source,
            "src_ip": row.src_ip,
            "client": row.client or row.src_ip,
            "client_source": row.client_source or "src_ip",
            "via": row.via,
            "proxied": bool(row.proxied),
            "count": int(row.count or 0),
            "dst_pairs": list(row.dst_pairs or []),
            "dst_ips": list(row.dst_ips or []),
            "dst_ports": list(row.dst_ports or []),
            "event_types": list(row.event_types or []),
            # 中文名并列返回：前端不用自己维护映射表（原来是直接显示 `signature_hit`）
            "event_type_labels": [
                EVENT_TYPE_LABELS.get(str(x), str(x)) for x in (row.event_types or [])
            ],
            "conn_states": list(row.conn_states or []),
            "log_types": list(row.log_types or []),
            "real_client_ips": list(row.real_client_ips or []),
            # 方向（D1）：out→in / in→out / in→in / out→out / unknown
            "direction": getattr(row, "direction", "") or "",
            "ignored": bool(row.ignored),
            "ignored_at": row.ignored_at.isoformat() if row.ignored_at else "",
            "ignored_reason": row.ignored_reason or "",
            "whitelist_id": row.whitelist_id or "",
            # 智能体分析结论（判定权威来源；无记录为 null，界面回退显示 NDR 初判）
            **_agent_fields(
                next((conclusions.get(k) for k in _conclusion_keys_of(row) if k in conclusions), None),
                detail=detail,
            ),
            **_agent_task_fields(
                next((tasks.get(k) for k in _conclusion_keys_of(row) if k in tasks), None),
                next((conclusions.get(k) for k in _conclusion_keys_of(row) if k in conclusions), None),
                detail=detail,
            ),
        }
        if detail:
            # 读时再去一次重：老记录的证据是写入时定格的，可能有同事件的重复文档
            item["evidence"] = dedupe_evidence(list(row.evidence or []))
        out.append(item)
    return out


#: 事件来源类别（**不体现采集器名字**，用户口径 2026-10）：
#: feature_match=特征匹配（签名引擎）/ behavior_analysis=行为分析（流量规则）/ baseline_deviation=基线偏离
SOURCE_LABELS: dict[str, str] = {
    "feature_match": "特征匹配",
    "behavior_analysis": "行为分析",
    "baseline_deviation": "基线偏离",
}

#: 签名引擎的 classtype → **具体安全事件归类**（界面直接展示这个，不再显示「签名命中」这种笼统说法）
SIGNATURE_CATEGORY_LABELS: dict[str, str] = {
    "web-application-attack": "Web 应用攻击",
    "attempted-admin": "权限提升尝试",
    "attempted-user": "账号口令攻击",
    "trojan-activity": "木马与后门活动",
    "network-scan": "网络扫描",
    "attempted-recon": "侦察探测",
    "attempted-dos": "拒绝服务攻击",
    "denial-of-service": "拒绝服务攻击",
    "policy-violation": "策略违规",
    "non-standard-protocol": "非标准协议通信",
    "suspicious-filename-detect": "可疑文件投递",
    "suspicious-login": "可疑登录",
    "misc-attack": "其它攻击行为",
    "misc-activity": "其它可疑活动",
    "shellcode-detect": "Shellcode 执行",
    "exploit-kit": "漏洞利用工具",
    "default-login-attempt": "默认口令尝试",
    "web-application-activity": "Web 应用探测",
    "string-detect": "可疑字符串",
    "unusual-client-port-connection": "非常规客户端端口",
    "protocol-command-decode": "协议命令解析异常",
    "icmp-event": "ICMP 事件",
    "tcp-connection": "TCP 连接事件",
}

#: Suricata 的 `alert.category` 是**人话文本**（classification.config 里的名字），
#: 上面那张表用的是 classtype 短名。这里把文本映射回短名，两种写法都能命中。
#: 实测库里就是文本形态（`Detection of a Network Scan` / `Attempted Administrator
#: Privilege Gain` …），不映射的话事件标题只能落到兜底文案。
SIGNATURE_CATEGORY_ALIASES: dict[str, str] = {
    "detection of a network scan": "network-scan",
    "attempted administrator privilege gain": "attempted-admin",
    "successful administrator privilege gain": "attempted-admin",
    "attempted user privilege gain": "attempted-user",
    "successful user privilege gain": "attempted-user",
    "unsuccessful user privilege gain": "attempted-user",
    "a network trojan was detected": "trojan-activity",
    "attempted information leak": "attempted-recon",
    "successful information leak": "attempted-recon",
    "attempted denial of service": "attempted-dos",
    "denial of service attack": "denial-of-service",
    "misc activity": "misc-activity",
    "misc attack": "misc-attack",
    "web application attack": "web-application-attack",
    "access to a potentially vulnerable web application": "web-application-activity",
    "potential corporate privacy violation": "policy-violation",
    "a suspicious filename was detected": "suspicious-filename-detect",
    "an attempted login using a suspicious username was detected": "suspicious-login",
    "attempt to login by a default username and password": "default-login-attempt",
    "detection of a non-standard protocol or event": "non-standard-protocol",
    "executable code was detected": "shellcode-detect",
    "a suspicious string was detected": "string-detect",
    "a client was using an unusual port": "unusual-client-port-connection",
    "generic protocol command decode": "protocol-command-decode",
    "generic icmp event": "icmp-event",
    "a tcp connection was detected": "tcp-connection",
}


#: 一条事件的签名线索只存在于**聚合态样本**里（摘要顶层只有规则名/计数）：
#: 样本是 `{"source": …, "doc": <原始文档>}`，签名引擎的原始文档把签名放在嵌套 `alert` 对象里。
#: 取不到就会退化成「签名命中(高危)」这种笼统标题 —— 实测线上就是这个现象（2026-10）。
def _sig_fields(item: dict[str, Any]) -> tuple[str, str, str]:
    """从任意一层对象里取 (签名归类, 签名名, 签名 ID)；嵌套 ``alert`` 也认。"""
    category = str(item.get("signature_category") or "").strip()
    signature = str(item.get("signature") or "").strip()
    sig_id = str(item.get("signature_id") or "").strip()
    alert = item.get("alert")
    if isinstance(alert, dict):
        category = category or str(alert.get("category") or "").strip()
        signature = signature or str(alert.get("signature") or "").strip()
        sig_id = sig_id or str(alert.get("signature_id") or "").strip()
    return category, signature, sig_id


def signature_hint(digest: dict[str, Any]) -> tuple[str, str, str]:
    """摘要 → 样本 → 样本内原始文档 → 证据，逐层找签名线索。"""
    category, signature, sig_id = _sig_fields(digest)
    if category or signature or sig_id:
        return category, signature, sig_id
    for sample in digest.get("samples") or []:
        if not isinstance(sample, dict):
            continue
        category, signature, sig_id = _sig_fields(sample)
        if not (category or signature or sig_id):
            doc = sample.get("doc")
            if isinstance(doc, dict):
                category, signature, sig_id = _sig_fields(doc)
        if category or signature or sig_id:
            return category, signature, sig_id
    for item in digest.get("evidence") or []:
        if isinstance(item, dict):
            category, signature, sig_id = _sig_fields(item)
            if category or signature or sig_id:
                return category, signature, sig_id
    return "", "", ""


#: 这些归类**不含具体信息**（签名引擎把抓不准的都归到 Misc activity）。
#: 有签名名时优先用签名名，界面上「sliver https debian」比「其它可疑活动」有用得多。
_GENERIC_TITLES: set[str] = {"其它可疑活动", "其它攻击行为", "可疑活动"}


def signature_category_label(category: str) -> str:
    """classtype（短名或人话文本）→ 中文安全事件归类；认不出返回空串。"""
    raw = " ".join(str(category or "").strip().lower().split())
    if not raw:
        return ""
    slug = SIGNATURE_CATEGORY_ALIASES.get(raw) or raw.replace(" ", "-").replace("_", "-")
    return SIGNATURE_CATEGORY_LABELS.get(slug, "")


def _title_from_signature(signature: str) -> str:
    """没有归类时用**签名名本身**当标题（比「其它可疑活动」具体得多）。

    签名名形如 `[扫描-07] UDP 端口扫描 - 出向高频`：去掉方括号编号前缀后直接展示。
    """
    text = str(signature or "").strip()
    if text.startswith("[") and "]" in text:
        text = text.split("]", 1)[1].strip()
    text = " ".join(text.split())
    return text[:40]


def source_kind_of(digest: dict[str, Any]) -> str:
    """判断这条命中属于哪类来源（三类之一）。"""
    _category, signature, sig_id = signature_hint(digest)
    if signature or sig_id:
        return "feature_match"
    if str(digest.get("kind") or "") in ("account", "session") or digest.get("baseline"):
        return "baseline_deviation"
    return "behavior_analysis"


def event_title_of(digest: dict[str, Any], source_kind: str) -> str:
    """命中事件在界面上显示的**安全事件归类**（具体，不笼统）。"""
    if source_kind == "feature_match":
        category, signature, _sig_id = signature_hint(digest)
        mapped = signature_category_label(category)
        title = _title_from_signature(signature)
        # 笼统归类（「其它可疑活动」/「其它攻击行为」）不如签名名有信息量：
        # 实测 Suricata 自带把大量签名归到 Misc activity，而签名名叫
        # 「sliver https debian」—— 界面上后者才能看出是什么事。
        if mapped and (mapped not in _GENERIC_TITLES or not title):
            return mapped
        if title:
            return title
        return "其它可疑活动"
    return str(digest.get("rule") or "未归类事件")


def event_types_of(digest: dict[str, Any], source_kind: str, title: str) -> list[str]:
    """事件的**类型**（界面直接显示）：具体归类，不是内部码。

    用户口径（2026-10）：事件类型要能看出"这是什么事件"——
    `signature_hit` / `baseline_deviation` 这类内部码不展示。

    - 特征匹配：取签名归类（Web 应用攻击 / 网络扫描 / 账号口令攻击…），认不出才退回标题；
    - 行为分析：类型就是规则名（大流量外传、内网慢速横向…）；
    - 基线偏离：类型就是偏离维度（连接数异常偏离…）。
    """
    if source_kind == "feature_match":
        category, _signature, _sid = signature_hint(digest)
        label = signature_category_label(category)
        return [label or title or "其它可疑活动"]
    return [title or "未归类事件"]


def save_from_digest(digest: dict[str, Any]) -> str:
    """摘要定型 → 写一行命中事件，返回**唯一事件 ID**（写失败返回空串，不打断检测）。"""
    reals = [str(x) for x in (digest.get("real_client_ips") or []) if str(x or "").strip()]
    src = str(digest.get("src_ip") or "")
    pairs = _pairs(digest)
    try:
        with SessionLocal() as db:
            title = event_title_of(digest, source_kind_of(digest))
            row = HitEvent(
                first_seen=_iso(digest.get("first_seen")),
                last_seen=_iso(digest.get("last_seen")),
                # 事件标题 = **具体安全事件归类**（签名命中不再显示成「签名命中(高危)」）
                rule=title,
                source_kind=source_kind_of(digest),
                # 告警簇：同一归类 + 同一网段 + 同一小时归为一件事（一次扫描命中几十个 IP 时靠它折叠）
                cluster_id=clustering.cluster_id(
                    title, src or (reals[0] if reals else ""), _iso(digest.get("last_seen"))
                ),
                rule_severity=str(
                    digest.get("rule_severity") or digest.get("severity") or "medium"
                ),
                rule_source=str(digest.get("rule_source") or digest.get("source") or "builtin"),
                src_ip=src,
                client=reals[0] if reals else src,
                client_source="xff" if reals else "src_ip",
                via=src if reals and src and src != reals[0] else "",
                proxied=bool(digest.get("proxied")),
                count=int(digest.get("count") or 0),
                dst_pairs=pairs,
                dst_ips=[str(x) for x in (digest.get("dst_ips") or [])],
                dst_ports=[str(x) for x in (digest.get("dst_ports") or [])],
                # 事件类型 = 具体归类（中文），不存 signature_hit 这类内部码
                event_types=event_types_of(digest, source_kind_of(digest), title),
                conn_states=[str(x) for x in (digest.get("conn_states") or [])],
                log_types=sorted(
                    {
                        str(s.get("source") or "")
                        for s in (digest.get("samples") or [])
                        if isinstance(s, dict)
                    }
                    - {""}
                ),
                real_client_ips=reals,
                # 方向在聚合定型时由 runner 统一算好放进 digest（D1）：这里只落库
                direction=str(digest.get("direction") or ""),
                evidence=_evidence(digest),
            )
            db.add(row)
            db.commit()
            return str(row.id)
    except Exception as exc:  # noqa: BLE001 — 落库失败不该影响检测投递
        log.warning("写命中事件失败: %s", exc)
        return ""


#: 画像判据 → 事件归类名（界面直接显示，不写「基线偏离」这种笼统说法）
_REASON_LABELS: tuple[tuple[str, str], ...] = (
    ("新源 IP", "新来源地址"),
    ("新 User-Agent", "新客户端指纹"),
    ("新接口路径", "新接口访问"),
    ("非常用时段", "非常用时段活动"),
    ("会话跨", "会话可能被劫持"),
    ("错误响应突增", "错误响应激增"),
    ("认证失败突增", "认证失败激增"),
)


def _reason_label(reason: str) -> str:
    for key, label in _REASON_LABELS:
        if str(reason).startswith(key):
            return label
    return "行为基线偏离"


#: 事件类型列里出现过的**内部码**（这些才是"事件类型显示英文"的根源）。
#: 老行直接存了 `signature_hit` / `baseline_deviation` 这类码，现在要换成具体归类。
_LEGACY_TYPE_CODES: frozenset[str] = frozenset(
    {"feature_match", "behavior_analysis", "baseline_deviation", "signature_hit"}
    | set(EVENT_TYPE_LABELS)
)

#: 已废弃的"包装规则"名：`签名命中(高危)` 这类不是检测逻辑，界面上不该出现。
_LEGACY_RULE_PREFIXES: tuple[str, ...] = ("签名命中",)


def _concrete_title(row: Any) -> str:
    """老行 → 具体事件归类（签名行从证据里的签名归类推回来）。"""
    rule = str(row.rule or "").strip()
    if not rule.startswith(_LEGACY_RULE_PREFIXES):
        return rule
    for item in row.evidence or []:
        if not isinstance(item, dict):
            continue
        label = signature_category_label(str(item.get("signature_category") or ""))
        if label:
            return label
        fallback = _title_from_signature(str(item.get("signature") or ""))
        if fallback:
            return fallback
    return "其它可疑活动"


def backfill_event_labels() -> int:
    """把**老数据**的事件标题/事件类型改成具体归类（幂等，启动时跑一次）。

    为什么要有：事件类型这一列早期存的是 `signature_hit` / `baseline_deviation`
    这类内部码，标题是「签名命中(高危)」这种包装规则名 —— 界面照抄就全成了英文/笼统说法。
    新写入已经改成具体归类（见 `event_types_of`），但历史行不会自己变，所以要回填。
    返回改了多少行（日志里可审计）。
    """
    fixed = 0
    try:
        with SessionLocal() as db:
            rows = db.execute(select(HitEvent)).scalars().all()
            for row in rows:
                old_rule = str(row.rule or "")
                old_types = [str(x) for x in (row.event_types or [])]
                title = _concrete_title(row)
                new_types = [title if t in _LEGACY_TYPE_CODES else t for t in old_types]
                if not new_types:
                    new_types = [title or "其它可疑活动"]
                if title == old_rule and new_types == old_types:
                    continue
                row.rule = title or old_rule
                row.event_types = new_types
                if title != old_rule:
                    row.cluster_id = clustering.cluster_id(
                        row.rule,
                        str(row.client or row.src_ip or ""),
                        row.last_seen,  # 传 datetime（cluster_id 自己按小时取桶）
                    )
                fixed += 1
            db.commit()
    except Exception as exc:  # noqa: BLE001 — 回填失败不能挡住启动
        log.warning("回填事件归类失败：%s", exc)
        return fixed
    if fixed:
        log.info("事件归类回填：%d 行从内部码/包装规则名改为具体归类", fixed)
    return fixed


def _hit_conditions(
    *,
    include_ignored: bool = False,
    source_kind: str = "",
    minutes: int = 0,
    severity: str = "",
    rule: str = "",
    ip: str = "",
    q: str = "",
    cluster_id: str = "",
    agent_status: str = "",
    agent_task_state: str = "",
) -> list[Any]:
    """把过滤条件翻译成 SQLAlchemy 条件（**纯函数**，可单测，不碰数据库）。

    事件中心的筛选项就落在这里：时间范围 / 三类来源 / 严重度 / 事件归类 / IP / 关键字。
    """
    # 显式 Any：条件里既有 BinaryExpression（is_()）又有 ColumnElement（== / like），
    # 让 pyright 别按第一个元素的类型推断整个 list。
    conds: list[Any] = []
    if not include_ignored:
        conds.append(HitEvent.ignored.is_(False))
    kind = str(source_kind or "").strip()
    if kind in SOURCE_LABELS:
        conds.append(HitEvent.source_kind == kind)
    # 智能体口径（判定权转移后的主口径）：结论态筛选 + 派工任务态筛选
    for condition in (
        _agent_status_condition(agent_status),
        _agent_task_state_condition(agent_task_state),
    ):
        if condition is not None:
            conds.append(condition)
    sev = str(severity or "").strip().lower()
    if sev:
        conds.append(HitEvent.rule_severity == sev)
    if minutes and int(minutes) > 0:
        since = datetime.now(UTC) - timedelta(minutes=int(minutes))
        # 用 last_seen（事件最近发生时间）筛：比 created_at 更贴近"这半小时发生的事"
        conds.append(func.coalesce(HitEvent.last_seen, HitEvent.created_at) >= since)
    rule_text = str(rule or "").strip()
    if rule_text:
        conds.append(HitEvent.rule.ilike(f"%{rule_text}%"))
    cluster_text = str(cluster_id or "").strip()
    if cluster_text:
        # 簇是聚类算出来的标识；界面「按簇展开」点进来就看这一簇的全部事件
        conds.append(HitEvent.cluster_id == cluster_text)
    ip_text = str(ip or "").strip()
    if ip_text:
        like = f"%{ip_text}%"
        conds.append(
            or_(
                HitEvent.src_ip.ilike(like),
                HitEvent.client.ilike(like),
                HitEvent.via.ilike(like),
                cast(HitEvent.dst_ips, String).ilike(like),
            )
        )
    keyword = str(q or "").strip()
    if keyword:
        like = f"%{keyword}%"
        conds.append(
            or_(
                HitEvent.rule.ilike(like),
                HitEvent.src_ip.ilike(like),
                HitEvent.client.ilike(like),
                HitEvent.via.ilike(like),
                cast(HitEvent.evidence, String).ilike(like),
            )
        )
    return conds


def list_hits(
    *,
    limit: int = 50,
    offset: int = 0,
    include_ignored: bool = False,
    source_kind: str = "",
    minutes: int = 0,
    severity: str = "",
    rule: str = "",
    ip: str = "",
    q: str = "",
    cluster_id: str = "",
    sort: str = "recent",
    agent_status: str = "",
    agent_task_state: str = "",
) -> dict[str, Any]:
    """命中事件列表（默认最近在前）。

    支持事件中心需要的筛选：`minutes`（时间范围）、`source_kind`（三类来源）、
    `severity`、`rule`（事件归类子串）、`ip`（请求方/客户端/中继/目的）、`q`（跨字段关键字）。
    `sort`：`recent`=最近发生在前（默认）/ `oldest` / `count`=按命中次数。
    """
    cap = max(1, min(int(limit or 50), 200))
    start = max(0, int(offset or 0))
    conds = _hit_conditions(
        include_ignored=include_ignored,
        source_kind=source_kind,
        minutes=minutes,
        severity=severity,
        rule=rule,
        ip=ip,
        q=q,
        cluster_id=cluster_id,
        agent_status=agent_status,
        agent_task_state=agent_task_state,
    )
    order_by = {
        "oldest": func.coalesce(HitEvent.last_seen, HitEvent.created_at).asc(),
        "count": HitEvent.count.desc(),
    }.get(
        str(sort or "recent").strip(), func.coalesce(HitEvent.last_seen, HitEvent.created_at).desc()
    )
    try:
        with SessionLocal() as db:
            total = int(db.scalar(select(func.count()).select_from(HitEvent).where(*conds)) or 0)
            rows = list(
                db.scalars(
                    select(HitEvent).where(*conds).order_by(order_by).limit(cap).offset(start)
                ).all()
            )
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读命中事件失败：{exc}", "items": [], "total": 0}
    return {"items": _rows_to_dict(rows), "total": total, "returned": len(rows)}


def hits_stats(*, minutes: int = 1440) -> dict[str, Any]:
    """事件中心首页要的聚合：检测器口径 + **智能体结论口径**两套并存。

    检测器口径（原有，保持不动）：`total` / `by_source_kind` / `by_severity` / `top_rules` / `trend`。
    智能体口径（2026-10 判定权转移后新增）：
    - `by_agent_status[]`：按结论态分组（`unanalyzed` = 结论表里没有记录），各桶之和 = `total`；
    - `agent_pending_total`：智能体**尚未返回结论**的事件数（运营一眼看积压）。
    两套口径并存、字段名区分开，不改写原有字段（历史对比不断裂）。
    """
    window = max(1, int(minutes or 1440))
    since = datetime.now(UTC) - timedelta(minutes=window)
    bucket_seconds = 3600 if window >= 360 else 600  # ≤6 小时按 10 分钟分桶，否则按小时
    try:
        with SessionLocal() as db:
            base = [
                func.coalesce(HitEvent.last_seen, HitEvent.created_at) >= since,
                HitEvent.ignored.is_(False),
            ]
            total = int(db.scalar(select(func.count()).select_from(HitEvent).where(*base)) or 0)
            ignored = int(
                db.scalar(
                    select(func.count())
                    .select_from(HitEvent)
                    .where(
                        func.coalesce(HitEvent.last_seen, HitEvent.created_at) >= since,
                        HitEvent.ignored.is_(True),
                    )
                )
                or 0
            )

            def group_by(column: Any) -> list[dict[str, Any]]:
                stmt = (
                    select(column, func.count())
                    .where(*base)
                    .group_by(column)
                    .order_by(func.count().desc())
                )
                rows = list(db.execute(stmt).all())
                return [
                    {
                        "key": str(row[0] or ""),
                        "label": SOURCE_LABELS.get(str(row[0] or ""), str(row[0] or "")),
                        "count": int(row[1] or 0),
                    }
                    for row in rows
                ]

            by_kind = group_by(HitEvent.source_kind)
            by_severity = group_by(HitEvent.rule_severity)
            rule_stmt = (
                select(HitEvent.rule, func.count())
                .where(*base)
                .group_by(HitEvent.rule)
                .order_by(func.count().desc())
                .limit(10)
            )
            by_rule = [
                {"rule": str(row[0] or ""), "count": int(row[1] or 0)}
                for row in list(db.execute(rule_stmt).all())
            ]
            # 趋势：按时间分桶（供折线图）
            ts = func.coalesce(HitEvent.last_seen, HitEvent.created_at)
            trend_stmt = select(ts, func.count()).where(*base).group_by(ts).order_by(ts)
            trend_rows = list(db.execute(trend_stmt).all())
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读命中事件统计失败：{exc}", "total": 0}

    # 智能体口径：一次 left join 分组（结论表为空/异常 → 空桶 + pending 未知，不影响检测器口径）
    by_agent_status: list[dict[str, Any]] = []
    agent_pending_total: int | None = None
    agent_confirmed_total = 0
    try:
        with SessionLocal() as db:
            agent_rows = list(
                db.execute(
                    select(ConclusionRecord.status, func.count())
                    .select_from(HitEvent)
                    .outerjoin(
                        ConclusionRecord,
                        ConclusionRecord.dedup_key == cast(HitEvent.id, String),
                    )
                    .where(
                        func.coalesce(HitEvent.last_seen, HitEvent.created_at) >= since,
                        HitEvent.ignored.is_(False),
                    )
                    .group_by(ConclusionRecord.status)
                ).all()
            )
        counts: dict[str, int] = {}
        for row in agent_rows:
            key = str(row[0] or AGENT_STATUS_UNANALYZED)
            counts[key] = counts.get(key, 0) + int(row[1] or 0)
        by_agent_status = [
            {
                "key": key,
                "label": verdicts_mod.label_of(key) if key != AGENT_STATUS_UNANALYZED else "未分析",
                "count": count,
            }
            for key, count in sorted(counts.items(), key=lambda kv: -kv[1])
        ]
        agent_pending_total = int(counts.get(AGENT_STATUS_UNANALYZED, 0))
        # 事件中心「智能体确认」口径：可疑 + 威胁（不含误报/正常/待定/未分析）
        agent_confirmed_total = int(counts.get("true_positive", 0)) + int(counts.get("suspicious", 0))
    except Exception as exc:  # noqa: BLE001 — 结论口径读失败不能拖垮检测器口径
        log.warning("读智能体结论统计失败: %s", exc)

    buckets: dict[str, int] = {}
    for row in trend_rows:
        ts_value = row[0]
        count = int(row[1] or 0)
        if ts_value is None:
            continue
        moment = (
            ts_value if isinstance(ts_value, datetime) else datetime.fromisoformat(str(ts_value))
        )
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        epoch = int(moment.timestamp()) // bucket_seconds * bucket_seconds
        key = datetime.fromtimestamp(epoch, UTC).isoformat().replace("+00:00", "Z")
        buckets[key] = buckets.get(key, 0) + int(count)
    return {
        "minutes": window,
        "bucket_seconds": bucket_seconds,
        "total": total,
        "ignored": ignored,
        "by_source_kind": by_kind,
        "by_severity": by_severity,
        # 智能体口径（与上面检测器口径并存；字段名区分开，不做覆盖）
        "by_agent_status": by_agent_status,
        "agent_pending_total": agent_pending_total,
        "agent_confirmed_total": agent_confirmed_total,
        "top_rules": by_rule,
        "trend": [{"ts": k, "count": v} for k, v in sorted(buckets.items())],
    }


def _empty_cluster_agent() -> dict[str, Any]:
    """没有结论时的簇级 agent 字段（与列表的 null 语义一致）。"""
    return {
        "agent_status": None,
        "agent_status_label": None,
        "agent_severity": None,
        "agent_analyzed": 0,
        "agent_pending": 0,
        "agent_true_positive": 0,
    }


def _cluster_agent_stats(
    cluster_ids: list[str], *, since: datetime, include_ignored: bool
) -> dict[str, dict[str, Any]]:
    """一个簇内所有事件各取结论后聚合：真阳性优先、严重度取最高、并给出已分析/未分析计数。

    为什么在库侧做：一簇可能有几十上百条事件，逐条回查结论就是 N+1；
    这里一条 group by（cluster_id, status, severity）就够。
    读失败返回空表（簇列表照常显示，只是没有 agent_* 字段）。
    """
    ids = [cid for cid in cluster_ids if cid]
    if not ids:
        return {}
    conds: list[Any] = [
        HitEvent.cluster_id.in_(ids),
        func.coalesce(HitEvent.last_seen, HitEvent.created_at) >= since,
    ]
    if not include_ignored:
        conds.append(HitEvent.ignored.is_(False))
    try:
        with SessionLocal() as db:
            rows = list(
                db.execute(
                    select(
                        HitEvent.cluster_id,
                        ConclusionRecord.status,
                        ConclusionRecord.severity,
                        func.count(),
                    )
                    .select_from(HitEvent)
                    .outerjoin(
                        ConclusionRecord,
                        ConclusionRecord.dedup_key == cast(HitEvent.id, String),
                    )
                    .where(*conds)
                    .group_by(HitEvent.cluster_id, ConclusionRecord.status, ConclusionRecord.severity)
                ).all()
            )
    except Exception as exc:  # noqa: BLE001 — 簇的结论读失败不影响簇本身
        log.warning("读告警簇结论失败: %s", exc)
        return {}
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        cid = str(row[0] or "")
        if cid == "":
            continue
        status = str(row[1] or "")
        severity = str(row[2] or "")
        count = int(row[3] or 0)
        acc = out.setdefault(cid, {
            "agent_status": "",
            "agent_status_label": "",
            "agent_severity": "",
            "agent_analyzed": 0,
            "agent_pending": 0,
            "agent_true_positive": 0,
            "_status_rank": 0,
            "_severity_rank": 0,
        })
        if status == "":
            acc["agent_pending"] += count
            continue
        acc["agent_analyzed"] += count
        rank = _AGENT_STATUS_RANK.get(status, 0)
        if rank > int(acc["_status_rank"] or 0):
            acc["_status_rank"] = rank
            acc["agent_status"] = status
            acc["agent_status_label"] = verdicts_mod.label_of(status)
        sev_rank = _SEVERITY_RANK.get(severity, 0)
        if sev_rank > int(acc["_severity_rank"] or 0):
            acc["_severity_rank"] = sev_rank
            acc["agent_severity"] = severity
        if status == "true_positive":
            acc["agent_true_positive"] += count
    for acc in out.values():
        if int(acc["agent_analyzed"] or 0) == 0:
            acc["agent_status"] = None
            acc["agent_status_label"] = None
        acc["agent_severity"] = acc["agent_severity"] or None
        acc.pop("_status_rank", None)
        acc.pop("_severity_rank", None)
    return out


def clusters(
    *,
    minutes: int = 1440,
    limit: int = 20,
    include_ignored: bool = False,
    source_kind: str = "",
) -> dict[str, Any]:
    """**告警簇**：把同一件事下的几十条事件折成一行（事件中心「按簇看」用）。

    一簇 = 同一事件归类 + 同一网段（v4 /24、v6 /64）+ 同一小时（见 `detector/clustering.py`）。
    为什么不在前端折叠：前端只能对**已加载的那一页**折叠，跨页/跨时间的同一件事折不起来；
    聚合放在库侧才能给出"这件事总共命中多少次、涉及多少个地址、最新到什么时候"。
    """
    window = max(1, int(minutes or 1440))
    cap = max(1, min(int(limit or 20), 200))
    since = datetime.now(UTC) - timedelta(minutes=window)
    ts = func.coalesce(HitEvent.last_seen, HitEvent.created_at)
    conds: list[Any] = [ts >= since]
    if not include_ignored:
        conds.append(HitEvent.ignored.is_(False))
    kind = str(source_kind or "").strip()
    if kind in SOURCE_LABELS:
        conds.append(HitEvent.source_kind == kind)
    # 迁移前写入的老事件没有簇 ID（列默认空串）：如果不过滤，它们会合成一个虚假的巨型簇
    conds.append(HitEvent.cluster_id.is_not(None))
    conds.append(HitEvent.cluster_id != "")
    # 严重度取「本簇里最高的一级」：簇里有高危就整体按高危看（运维先看重的）
    sev_rank = case(
        (HitEvent.rule_severity == "high", 3),
        (HitEvent.rule_severity == "medium", 2),
        else_=1,
    )
    sev_label = {3: "high", 2: "medium", 1: "low"}
    try:
        with SessionLocal() as db:
            stmt = (
                select(
                    HitEvent.cluster_id,
                    func.min(HitEvent.rule),
                    func.min(HitEvent.src_ip),
                    func.min(ts),
                    func.max(ts),
                    func.count(),
                    func.coalesce(func.sum(HitEvent.count), 0),
                    func.count(func.distinct(HitEvent.src_ip)),
                    func.count(func.distinct(HitEvent.client)),
                    func.max(sev_rank),
                    func.min(HitEvent.source_kind),
                )
                .where(*conds)
                .group_by(HitEvent.cluster_id)
                .order_by(func.max(ts).desc())
                .limit(cap)
            )
            rows = list(db.execute(stmt).all())
            total_clusters = int(
                db.scalar(
                    select(func.count(func.distinct(HitEvent.cluster_id)))
                    .select_from(HitEvent)
                    .where(*conds)
                )
                or 0
            )
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读告警簇失败：{exc}", "items": [], "total": 0}

    # 智能体口径：本页每个簇的成员事件各取结论后聚合（与列表同一套关联键，一次 group by）
    agent_by_cluster = _cluster_agent_stats(
        [str(row[0] or "") for row in rows], since=since, include_ignored=include_ignored
    )

    items: list[dict[str, Any]] = []
    for row in rows:
        cid = str(row[0] or "")
        rule = str(row[1] or "")
        sample_ip = str(row[2] or "")
        first = row[3] if isinstance(row[3], datetime) else None
        last = row[4] if isinstance(row[4], datetime) else None
        src_kind = str(row[10] or "behavior_analysis")
        items.append(
            {
                "cluster_id": cid,
                "label": clustering.cluster_label(rule, sample_ip, last),
                "rule": rule,
                "net": clustering.net_of(sample_ip),
                "hour": clustering.hour_of(last),
                "source_kind": src_kind,
                "source_label": SOURCE_LABELS.get(src_kind, "行为分析"),
                "severity": sev_label.get(int(row[9] or 1), "low"),
                "events": int(row[5] or 0),
                "count": int(row[6] or 0),
                "src_ips": int(row[7] or 0),
                "clients": int(row[8] or 0),
                "first_seen": first.isoformat() if first else "",
                "last_seen": last.isoformat() if last else "",
                # 智能体结论口径（簇内聚合；与列表视图同一套 agent_* 命名）
                **agent_by_cluster.get(cid, _empty_cluster_agent()),
            }
        )
    return {
        "minutes": window,
        "total": total_clusters,
        "items": items,
        "returned": len(items),
    }


def get_hit(hit_id: str) -> dict[str, Any]:
    """单条命中事件（含证据）。"""
    try:
        with SessionLocal() as db:
            row = db.get(HitEvent, str(hit_id or "").strip())
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读命中事件失败：{exc}"}
    if row is None:
        return {"error": "事件不存在"}
    return _rows_to_dict([row], detail=True)[0]


def mark_ignored(hit_id: str, *, reason: str = "") -> dict[str, Any]:
    """忽略这条事件（行保留、可撤回）。"""
    try:
        with SessionLocal() as db:
            row = db.get(HitEvent, str(hit_id or "").strip())
            if row is None:
                return {"error": "事件不存在"}
            row.ignored = True
            row.ignored_at = datetime.now(UTC)
            row.ignored_reason = str(reason or "")[:200]
            db.commit()
            return {"ok": True, "id": row.id, "ignored": True}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"忽略失败：{exc}"}


def attach_whitelist(hit_id: str, filter_id: str) -> None:
    """记下这条事件生成了哪个白名单（留痕）。"""
    try:
        with SessionLocal() as db:
            row = db.get(HitEvent, str(hit_id or "").strip())
            if row is None:
                return
            row.whitelist_id = str(filter_id or "")[:64]
            row.ignored = True
            row.ignored_at = datetime.now(UTC)
            row.ignored_reason = f"已加白名单（{filter_id}）"
            db.commit()
    except Exception as exc:  # noqa: BLE001
        log.debug("记录白名单关联失败: %s", exc)
