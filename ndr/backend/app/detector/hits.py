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

from app.db.base import SessionLocal
from app.db.models import HitEvent
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
                    cluster_id=clustering.cluster_id(
                        _reason_label(reasons[0]),
                        str((item.get("src_ips") or [""])[0] or ""),
                        last,
                    ),
                    rule_severity=_severity_of_risk(risk),
                    rule_source="baseline",
                    source_kind="baseline_deviation",
                    src_ip=str((item.get("src_ips") or [""])[0] or ""),
                    # 基线事件不来自日志文档，但要给「事件类型」一个值，否则界面显示"无"
                    # 事件类型 = 具体告警归类（如「连接数异常偏离」），不写内部码
                    event_types=[_reason_label(reasons[0])],
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
                    cluster_id=clustering.cluster_id(
                        _FEATURE_LABELS.get(feature, "数值基线偏离"),
                        str(item.get("src_ip") or ""),
                        last,
                    ),
                    rule_severity="high",
                    rule_source="baseline",
                    source_kind="baseline_deviation",
                    src_ip=str(item.get("src_ip") or ""),
                    # 基线事件不来自日志文档，但要给「事件类型」一个值，否则界面显示"无"
                    event_types=[_FEATURE_LABELS.get(feature, "数值基线偏离")],
                    count=1,
                    evidence=[
                        {
                            "特征": _FEATURE_LABELS.get(feature, feature),
                            "本窗口值": item.get("value"),
                            "历史均值": item.get("mean"),
                            "标准差": item.get("std"),
                            # 钳制过（原始 std 为 0 或极小）时带上原始值，证据可追溯
                            "原始标准差": item.get("std_raw"),
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
        "top_rules": by_rule,
        "trend": [{"ts": k, "count": v} for k, v in sorted(buckets.items())],
    }


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
