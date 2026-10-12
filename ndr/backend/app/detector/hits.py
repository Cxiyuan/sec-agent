"""命中事件（PG）：唯一事件 ID + 详情证据 + 忽略 / 白名单。

设计要点（2026-10 用户要求）：

- **唯一 ID 落在 PG 主键上**：每条命中在摘要定型时写一行，`id` 就是整个系统的唯一事件 ID，
  用于关联分析（忽略、白名单、交智能体、人工追溯都引用它）；
- **目的写「IP:端口」成对**：摘要里 `dst_ips` / `dst_ports` 是两个独立列表，界面上拼成
  「IP : 端口/端口/端口」会让人看不出谁配谁（用户反馈）——这里从样例事件里取**真实配对**；
- **证据存关键字段**：够展示与判断，又不把 PG 撑爆；完整原始文档仍在 ES（按 `uid` 可回查）。
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select

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
    # 「因为什么内容被命中」——正文/查询串/请求头（会截断）
    "body",
    "resp_body",
    "query_string",
    "req_headers",
    "content_type",
    "payload_printable",
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


def _evidence(digest: dict[str, Any]) -> list[dict[str, Any]]:
    """样例事件 → 关键字段（丢空值，控制体积；长文本截断）。"""
    out: list[dict[str, Any]] = []
    for sample in (digest.get("samples") or [])[:_MAX_EVIDENCE]:
        doc = (sample or {}).get("doc") if isinstance(sample, dict) else None
        if not isinstance(doc, dict):
            continue
        item = {k: doc.get(k) for k in _EVIDENCE_FIELDS if doc.get(k) not in (None, "", [], {})}
        if isinstance(sample, dict) and sample.get("source"):
            item["source"] = sample["source"]
        # 签名引擎的告警在原始 EVE 里是嵌套的 alert 对象（signature/signature_id/category/
        # severity/metadata.threat_type）——不提上来，详情里就看不出「命中了哪条签名」
        # （实测：只显示"内置-签名命中(高危)"，看不出是 Cobalt Strike JA3S 还是别的）。
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
            item["evidence"] = list(row.evidence or [])
        out.append(item)
    return out


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
                rule=str(digest.get("rule") or ""),
                rule_severity=str(digest.get("rule_severity") or digest.get("severity") or "medium"),
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
                log_types=sorted({str(s.get("source") or "") for s in (digest.get("samples") or []) if isinstance(s, dict)} - {""}),
                real_client_ips=reals,
                evidence=_evidence(digest),
            )
            db.add(row)
            db.commit()
            return str(row.id)
    except Exception as exc:  # noqa: BLE001 — 落库失败不该影响检测投递
        log.warning("写命中事件失败: %s", exc)
        return ""


def list_hits(
    *, limit: int = 50, offset: int = 0, include_ignored: bool = False
) -> dict[str, Any]:
    """命中事件列表（最新在前）。默认不含已忽略的。"""
    cap = max(1, min(int(limit or 50), 200))
    start = max(0, int(offset or 0))
    try:
        with SessionLocal() as db:
            conds = [] if include_ignored else [HitEvent.ignored.is_(False)]
            total = int(
                db.scalar(select(func.count()).select_from(HitEvent).where(*conds)) or 0
            )
            rows = list(
                db.scalars(
                    select(HitEvent)
                    .where(*conds)
                    .order_by(HitEvent.created_at.desc())
                    .limit(cap)
                    .offset(start)
                ).all()
            )
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读命中事件失败：{exc}", "items": [], "total": 0}
    return {"items": _rows_to_dict(rows), "total": total, "returned": len(rows)}


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
