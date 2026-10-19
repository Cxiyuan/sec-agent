"""命中事件（PG）：唯一事件 ID + 详情证据 + 忽略 / 白名单。

设计要点（2026-10 用户要求）：

- **唯一 ID 落在 PG 主键上**：每条命中在摘要定型时写一行，`id` 就是整个系统的唯一事件 ID，
  用于关联分析（忽略、白名单、交智能体、人工追溯都引用它）；
- **目的写「IP:端口」成对**：摘要里 `dst_ips` / `dst_ports` 是两个独立列表，界面上拼成
  「IP : 端口/端口/端口」会让人看不出谁配谁（用户反馈）——这里从样例事件里取**真实配对**；
- **证据存关键字段**：够展示与判断，又不把 PG 撑爆；完整原始文档仍在 ES（按 `uid` 可回查）。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import String, cast, func, or_, select

from app.db.base import SessionLocal
from app.db.models import HitEvent
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


def _rows_to_dict(rows: list[HitEvent], *, detail: bool = False) -> list[dict[str, Any]]:
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
            "conn_states": list(row.conn_states or []),
            "log_types": list(row.log_types or []),
            "real_client_ips": list(row.real_client_ips or []),
            "ignored": bool(row.ignored),
            "ignored_at": row.ignored_at.isoformat() if row.ignored_at else "",
            "ignored_reason": row.ignored_reason or "",
            "whitelist_id": row.whitelist_id or "",
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
}


def source_kind_of(digest: dict[str, Any]) -> str:
    """判断这条命中属于哪类来源（三类之一）。"""
    if str(digest.get("signature") or "").strip() or str(digest.get("signature_id") or "").strip():
        return "feature_match"
    if str(digest.get("kind") or "") in ("account", "session") or digest.get("baseline"):
        return "baseline_deviation"
    return "behavior_analysis"


def event_title_of(digest: dict[str, Any], source_kind: str) -> str:
    """命中事件在界面上显示的**安全事件归类**（具体，不笼统）。"""
    if source_kind == "feature_match":
        category = str(digest.get("signature_category") or "").strip().lower()
        mapped = SIGNATURE_CATEGORY_LABELS.get(category)
        if mapped:
            return mapped
        if str(digest.get("signature") or "").strip():
            return "其它可疑活动"
    return str(digest.get("rule") or "未归类事件")


def save_from_digest(digest: dict[str, Any]) -> str:
    """摘要定型 → 写一行命中事件，返回**唯一事件 ID**（写失败返回空串，不打断检测）。"""
    reals = [str(x) for x in (digest.get("real_client_ips") or []) if str(x or "").strip()]
    src = str(digest.get("src_ip") or "")
    pairs = _pairs(digest)
    try:
        with SessionLocal() as db:
            row = HitEvent(
                first_seen=_iso(digest.get("first_seen")),
                last_seen=_iso(digest.get("last_seen")),
                # 事件标题 = **具体安全事件归类**（签名命中不再显示成「签名命中(高危)」）
                rule=event_title_of(digest, source_kind_of(digest)),
                source_kind=source_kind_of(digest),
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
                event_types=[str(x) for x in (digest.get("event_types") or [])],
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

#: 数值基线特征 → 事件归类名
_FEATURE_LABELS: dict[str, str] = {
    "conn_count": "连接数异常偏离",
    "distinct_dst_ports": "目的端口数异常偏离",
    "distinct_dst_ips": "目的地址数异常偏离",
}


def _reason_label(reason: str) -> str:
    for key, label in _REASON_LABELS:
        if str(reason).startswith(key):
            return label
    return "行为基线偏离"


def _severity_of_risk(risk: float) -> str:
    if risk >= 0.75:
        return "high"
    if risk >= 0.45:
        return "medium"
    return "low"


def save_baseline_deviations(digest: dict[str, Any], baseline: dict[str, Any]) -> list[str]:
    """把本轮**基线偏离**（画像异常 + 数值 2σ 偏离）写成命中事件，返回事件 ID 列表。

    为什么要有（2026-10 用户口径）：命中事件的数据来源分三类 —— 特征匹配 / 行为分析 /
    **基线偏离**。前两类早就在落库（规则命中），基线偏离只打进摘要标签、没有独立事件，
    第三类在库里就是空的。这里补齐，和规则命中同一张表（`hit_events`）、同一套唯一事件 ID。
    """
    if not baseline:
        return []
    created: list[str] = []
    first = _iso(digest.get("first_seen"))
    last = _iso(digest.get("last_seen"))
    try:
        with SessionLocal() as db:
            # ① 画像异常（账号 / 会话）
            for item in baseline.get("profiles") or []:
                reasons = [str(x) for x in (item.get("reasons") or [])]
                if not reasons:
                    continue
                risk = float(item.get("risk") or 0.0)
                row = HitEvent(
                    first_seen=first,
                    last_seen=last,
                    rule=_reason_label(reasons[0]),
                    rule_severity=_severity_of_risk(risk),
                    rule_source="baseline",
                    source_kind="baseline_deviation",
                    src_ip=str((item.get("src_ips") or [""])[0] or ""),
                    count=int(item.get("count") or 0),
                    dst_ips=[str(x) for x in (item.get("dst_ips") or [])][:20],
                    evidence=[
                        {
                            "实体类型": "账号" if str(item.get("kind")) == "account" else "会话",
                            "实体": str(item.get("display") or item.get("key") or ""),
                            "风险分": round(risk, 3),
                            "判定理由": reasons,
                            "历史观测次数": int(item.get("obs_count") or 0),
                        }
                    ],
                )
                db.add(row)
                db.flush()
                created.append(str(row.id))
            # ② 数值基线（2σ 偏离）
            for item in baseline.get("numeric") or []:
                feature = str(item.get("feature") or "")
                row = HitEvent(
                    first_seen=first,
                    last_seen=last,
                    rule=_FEATURE_LABELS.get(feature, "数值基线偏离"),
                    rule_severity="high",
                    rule_source="baseline",
                    source_kind="baseline_deviation",
                    src_ip=str(item.get("src_ip") or ""),
                    count=1,
                    evidence=[
                        {
                            "特征": _FEATURE_LABELS.get(feature, feature),
                            "本窗口值": item.get("value"),
                            "历史均值": item.get("mean"),
                            "标准差": item.get("std"),
                            "偏离倍数": item.get("z"),
                        }
                    ],
                )
                db.add(row)
                db.flush()
                created.append(str(row.id))
            db.commit()
    except Exception as exc:  # noqa: BLE001 — 基线事件写失败不能挡住检测
        log.warning("基线偏离事件落库失败：%s", exc)
        return created
    return created


def _hit_conditions(
    *,
    include_ignored: bool = False,
    source_kind: str = "",
    minutes: int = 0,
    severity: str = "",
    rule: str = "",
    ip: str = "",
    q: str = "",
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
    sort: str = "recent",
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
    )
    order_by = {
        "oldest": func.coalesce(HitEvent.last_seen, HitEvent.created_at).asc(),
        "count": HitEvent.count.desc(),
    }.get(str(sort or "recent").strip(), func.coalesce(HitEvent.last_seen, HitEvent.created_at).desc())
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
    """事件中心首页要的聚合：总量、按三类来源、按严重度、按事件归类、按小时趋势。

    一次 SQL 拿完（group by 三次 + 时间分桶），前端直接画卡片和折线，不用自己聚合。
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
                    .where(func.coalesce(HitEvent.last_seen, HitEvent.created_at) >= since,
                           HitEvent.ignored.is_(True))
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

    buckets: dict[str, int] = {}
    for row in trend_rows:
        ts_value = row[0]
        count = int(row[1] or 0)
        if ts_value is None:
            continue
        moment = ts_value if isinstance(ts_value, datetime) else datetime.fromisoformat(str(ts_value))
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
        "top_rules": by_rule,
        "trend": [{"ts": k, "count": v} for k, v in sorted(buckets.items())],
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
