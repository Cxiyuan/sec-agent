"""攻击链还原：把每次请求还原成「真实请求IP →（中继…）→ 源站」+ 事实聚合 + 交智能体。

口径（用户 2026-10）：

- **只还原真正进了检测的那些事件**（即通过中继去重的那些），与检测器/画像看到的完全一致；
- **真实请求IP**：可信代理头带来的 `real_client_ip`（直连对端在中继清单里才认）优先，
  无中继时就是 `src_ip`；**没有转发中继/跳板时就是「真实请求IP → 源站IP」两段**；
- **中继路径**：由「监控网段」页的中继上下级拓扑（`zeek.relay_topology`）推导，逐段标注证据来源
  （直连观测 / 代理头证据 / 纯拓扑推导）——可靠性要能核验，不猜；
- **动作分析**：只用 ES 事实（命中签名与 SID、事件类型、状态码、上传文件、DNS、时间线）。
  我们自研规则的命中明细在智能体侧，所以「交给智能体」时把本链事实一并送出。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.config import settings
from app.db.base import get_db
from app.db.models import User
from app.detector import push as digest_push
from app.ingestion import es_config, relay_nodes
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/chains", tags=["chains"])

#: 参与链路还原的日志类型：有请求语义的（含加密握手，用来判中继角色/侧向）+ 签名引擎命中 + 文件
_CHAIN_LOG_TYPES = ("http", "http2", "smtp", "dns", "ssl", "suricata", "files")
#: 拉回来的字段（够还原链路与动作，不拉 raw）
_SOURCE_INCLUDES = (
    "ts",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "real_client_ip",
    "hop",
    "log_type",
    "event_type",
    "hostname",
    "uri_path",
    "query_string",
    "method",
    "status_code",
    "user_agent",
    "referer",
    "signature",
    "signature_id",
    "signature_category",
    "signature_severity",
    "filename",
    "md5",
    "sha256",
    "query",
    "qtype",
    "community_id",
    "uid",
    "bytes_out",
    "bytes_in",
    "summary",
    "body",
    "resp_body",
    "account",
)
#: 「可疑」的可解释代理口径（页面上的开关用它筛；分级结论仍由智能体侧给）
_SUSPICIOUS_EVENT_TYPES = frozenset(
    {
        "http_upload",
        "http_login",
        "http_error",
        "scan_attempt",
        "rejected_connection",
        "protocol_anomaly",
        "tls_anomaly",
        "dns_anomaly",
        "signature_hit",
        "web_attack",
        "capture_anomaly",
    }
)
_MAX_MINUTES = 24 * 60
_SAMPLE_CHARS = 2000


class DispatchIn(BaseModel):
    """把某条链路交给智能体深挖。"""

    client: str = ""
    origin: str = ""
    path: list[str] = Field(default_factory=list)
    minutes: int = 60
    from_ts: str = ""
    to_ts: str = ""
    note: str = ""


# ---------- 时间窗与取数 ----------


def _window(minutes: int, from_ts: str, to_ts: str) -> tuple[datetime, datetime]:
    end = datetime.now(UTC)
    start = end - timedelta(minutes=max(1, min(int(minutes or 60), _MAX_MINUTES)))
    if from_ts:
        try:
            start = datetime.fromisoformat(from_ts)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="from 不是合法时间") from exc
    if to_ts:
        try:
            end = datetime.fromisoformat(to_ts)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="to 不是合法时间") from exc
    return start, end


def _fetch(start: datetime, end: datetime, size: int) -> tuple[list[dict[str, Any]], bool]:
    """按时间窗取事件（受 `chain_max_events` 上限约束）。返回 (文档, 是否被截断)。"""
    from app.ingestion.es_client import get_es

    pattern = str(es_config.current().get("es.events_index") or settings.es_events_index)
    limit = max(1, min(int(size), int(settings.chain_max_events)))
    query = {
        "bool": {
            "filter": [
                {"range": {"ts": {"gte": start.isoformat(), "lte": end.isoformat()}}},
                {"terms": {"log_type.keyword": list(_CHAIN_LOG_TYPES)}},
            ]
        }
    }
    resp = get_es().search(
        index=pattern,
        size=limit,
        query=query,
        sort=[{"ts": "desc"}],
        source_includes=list(_SOURCE_INCLUDES),
    )
    hits = [h.get("_source") or {} for h in ((resp.get("hits") or {}).get("hits") or [])]
    total = int(((resp.get("hits") or {}).get("total") or {}).get("value") or len(hits))
    return hits, total > len(hits)


# ---------- 链路还原 ----------


def _side_of(ip: str) -> str:
    return relay_nodes.side_override(ip) or relay_nodes.SIDE_AUTO


def _kept(doc: dict[str, Any]) -> bool:
    """这条事件是否**通过了中继去重**（即检测器/画像真正看到的那一批）。

    与 `detector/relay_pairing.py::decide()` 同一口径的静态近似：
    - `direct` 一律保留；
    - `front`：该中继的内容在客户端侧才保留（否则客户端那跳没有可读内容，丢掉）；
    - `back`：该中继的内容在源站侧就保留；
    - `relay_internal`：只有「发送方那侧就是源站侧」且本跳带明文内容时才留。
    （去重里还有「未见前跳则保留后跳」的兜底，属抓包单侧场景，这里按可见性无法静态判断，
    所以对 back 一律按保留处理 —— 宁可多还原一条，也不漏。）
    """
    hop = str(doc.get("hop") or "direct")
    if hop == "direct":
        return True
    relay = str(doc.get("dst_ip") or "") if hop == "front" else str(doc.get("src_ip") or "")
    side = _side_of(relay)
    if hop == "front":
        return side != relay_nodes.SIDE_BACK
    if hop == "back":
        return side != relay_nodes.SIDE_FRONT
    if hop == "relay_internal":
        return side == relay_nodes.SIDE_BACK and str(doc.get("log_type") or "") in {
            "http",
            "http2",
            "smtp",
            "dns",
        }
    return True


def _edges() -> tuple[list[dict[str, Any]], dict[str, int]]:
    """已确认且**未被环打断**的边 + 层级。

    必须排除 `cycle_broken` 里的边：拓扑检测到 A→B 与 B→A 共存时会打断较弱的一条，
    链路推导要尊重这个结论，否则会沿着被打断的那条边往回走，链路上出现重复中继
    （实机踩到：`… → [.214, .203, .214] → 源站`）。
    """
    topo = relay_nodes.topology()
    broken = {
        f"{pair[0]}|{pair[1]}"
        for pair in (topo.get("cycle_broken") or [])
        if isinstance(pair, list) and len(pair) >= 2
    }
    edges = [
        e
        for e in (topo.get("edges") or [])
        if isinstance(e, dict) and f"{e.get('from')}|{e.get('to')}" not in broken
    ]
    levels = {str(k): int(v) for k, v in (topo.get("levels") or {}).items()}
    return edges, levels


def _upstream_path(
    relay: str, edges: list[dict[str, Any]]
) -> tuple[list[str], list[dict[str, Any]]]:
    """从该中继沿「已确认的边」向**上游**走到入口，返回 (上游中继序列, 每段证据)。"""
    confirmed = [e for e in edges if e.get("confirmed")]
    path: list[str] = []
    evidence: list[dict[str, Any]] = []
    current = relay
    for _ in range(8):  # 深度上限，防环
        parents = [e for e in confirmed if str(e.get("to")) == current]
        if not parents:
            break
        # 证据最强的那条作为上级（多条时取计数大的）
        parent = max(parents, key=lambda e: int(e.get("direct") or 0) + int(e.get("header") or 0))
        up = str(parent.get("from"))
        if up in path or up == relay:
            break
        path.append(up)
        evidence.append(
            {
                "from": up,
                "to": current,
                "direct": int(parent.get("direct") or 0),
                "header": int(parent.get("header") or 0),
                "confirmed": True,
                "stale": bool(parent.get("stale")),
            }
        )
        current = up
    path.reverse()
    evidence.reverse()
    return path, evidence


def _downstream_path(relay: str, edges: list[dict[str, Any]]) -> list[str]:
    confirmed = [e for e in edges if e.get("confirmed")]
    out: list[str] = []
    current = relay
    for _ in range(8):
        children = [e for e in confirmed if str(e.get("from")) == current]
        if not children:
            break
        child = max(children, key=lambda e: int(e.get("direct") or 0) + int(e.get("header") or 0))
        down = str(child.get("to"))
        if down in out or down == relay:
            break
        out.append(down)
        current = down
    return out


def _is_suspicious(doc: dict[str, Any]) -> bool:
    if str(doc.get("log_type") or "") == "suricata":
        return True
    if str(doc.get("event_type") or "") in _SUSPICIOUS_EVENT_TYPES:
        return True
    status = doc.get("status_code")
    if isinstance(status, int) and status >= 400:
        return True
    return bool(str(doc.get("filename") or "").strip())


def _chain_of(doc: dict[str, Any], edges: list[dict[str, Any]]) -> dict[str, Any] | None:
    """把一条事件规约成链路要素；不是「保留的观测事件」就返回 None。"""
    if not _kept(doc):
        return None
    hop = str(doc.get("hop") or "direct")
    src = str(doc.get("src_ip") or "")
    dst = str(doc.get("dst_ip") or "")
    client = str(doc.get("real_client_ip") or "")
    client_source = "xff" if client else ""
    relay = ""
    if hop == "direct":
        client = client or src
        client_source = client_source or "src_ip"
    elif hop == "front":
        relay = dst
        client = client or src
        client_source = client_source or "src_ip"
    elif hop in ("back", "relay_internal"):
        relay = src
        client = client or ""
    upstream, evidence = _upstream_path(relay, edges) if relay else ([], [])
    downstream = _downstream_path(relay, edges) if relay else []
    relay_path = [*upstream, *([relay] if relay else []), *downstream]
    # 源站：本跳目的就是源站（direct / back）；front 那一跳的目的还是中继，源站要由下游补
    origin = ""
    origin_kind = ""
    if hop in ("direct", "back", "relay_internal"):
        origin = str(doc.get("hostname") or "")
        if not origin:
            port = doc.get("dst_port")
            origin = f"{dst}:{port}" if dst and port else dst
        origin_kind = "hostname" if doc.get("hostname") else "ip"
    elif hop == "front":
        origin = str(doc.get("hostname") or "")
        origin_kind = "hostname" if origin else ""
    return {
        "client": client,
        "client_source": client_source or "",
        "relay": relay,
        "relay_path": relay_path,
        "relay_evidence": evidence,
        "origin": origin,
        "origin_kind": origin_kind,
        "hop": hop,
    }


def _facts(items: list[dict[str, Any]]) -> dict[str, Any]:
    from collections import Counter

    event_types: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    signatures: Counter[str] = Counter()
    files: Counter[str] = Counter()
    dns: Counter[str] = Counter()
    paths: Counter[str] = Counter()
    methods: Counter[str] = Counter()
    logs: Counter[str] = Counter()
    clients: set[str] = set()
    for d in items:
        event_types[str(d.get("event_type") or "")] += 1
        logs[str(d.get("log_type") or "")] += 1
        if isinstance(d.get("status_code"), int):
            statuses[str(d["status_code"])] += 1
        if d.get("signature"):
            sig = f"{d.get('signature')}（SID {d.get('signature_id') or '-'}"
            sig += f" / {d.get('signature_category')}）" if d.get("signature_category") else "）"
            signatures[sig] += 1
        if d.get("filename"):
            files[str(d["filename"])] += 1
        if d.get("query") and str(d.get("log_type")) == "dns":
            dns[str(d["query"])] += 1
        if d.get("uri_path"):
            paths[str(d["uri_path"])] += 1
        if d.get("method"):
            methods[str(d["method"])] += 1
        if d.get("real_client_ip"):
            clients.add(str(d["real_client_ip"]))
        elif d.get("src_ip"):
            clients.add(str(d["src_ip"]))
    stamps = sorted(str(d.get("ts") or "") for d in items if d.get("ts"))
    return {
        "events": len(items),
        "log_types": dict(logs.most_common()),
        "event_types": dict(event_types.most_common()),
        "status_codes": dict(statuses.most_common()),
        "signatures": dict(signatures.most_common(10)),
        "filenames": dict(files.most_common(10)),
        "dns_queries": dict(dns.most_common(10)),
        "top_paths": dict(paths.most_common(10)),
        "methods": dict(methods.most_common()),
        "clients": sorted(clients)[:40],
        "first_seen": stamps[0] if stamps else "",
        "last_seen": stamps[-1] if stamps else "",
    }


def _build(
    start: datetime, end: datetime, *, ip: str, host: str, suspicious_only: bool
) -> dict[str, Any]:
    docs, truncated = _fetch(start, end, settings.chain_max_events)
    edges, levels = _edges()
    buckets: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]] = {}
    for doc in docs:
        chain = _chain_of(doc, edges)
        if chain is None:
            continue
        if ip and ip not in {
            chain["client"],
            chain["relay"],
            str(doc.get("src_ip") or ""),
            str(doc.get("dst_ip") or ""),
            str(doc.get("real_client_ip") or ""),
        }:
            continue
        if host and host.lower() not in f"{chain['origin']} {doc.get('hostname') or ''}".lower():
            continue
        if suspicious_only and not _is_suspicious(doc):
            continue
        key = (chain["client"], chain["origin"], tuple(chain["relay_path"]))
        bucket = buckets.setdefault(
            key, {"chain": chain, "items": [], "suspicious": False, "levels": levels}
        )
        bucket["items"].append(doc)
        bucket["suspicious"] = bool(bucket["suspicious"] or _is_suspicious(doc))
    chains: list[dict[str, Any]] = []
    for (client, origin, path), bucket in buckets.items():
        facts = _facts(bucket["items"])
        chain = bucket["chain"]
        # 每条链的逐段证据：入口段用第一段边的证据，本跳用 relay_evidence
        segs: list[dict[str, Any]] = []
        if not path:
            segs.append({"from": client or "?", "to": origin or "?", "kind": "direct"})
        else:
            prev = client or "?"
            for idx, node in enumerate(path):
                ev = next((e for e in chain["relay_evidence"] if e["to"] == node), None)
                segs.append(
                    {
                        "from": prev,
                        "to": node,
                        "kind": "edge"
                        if ev
                        else ("anchor" if node == chain["relay"] else "derived"),
                        "direct": int((ev or {}).get("direct") or 0),
                        "header": int((ev or {}).get("header") or 0),
                        "confirmed": bool((ev or {}).get("confirmed", idx == len(path) - 1)),
                    }
                )
                prev = node
            segs.append({"from": prev, "to": origin or "（源站，本跳不可见）", "kind": "origin"})
        chains.append(
            {
                "client": client,
                "client_source": chain["client_source"],
                "origin": origin,
                "origin_kind": chain["origin_kind"],
                "relay_path": list(path),
                "segments": segs,
                "suspicious": bool(bucket["suspicious"]),
                "facts": facts,
                "hop": chain["hop"],
            }
        )
    chains.sort(key=lambda c: (-int(c["facts"]["events"]), c["client"]))
    return {
        "window": {"from": start.isoformat(), "to": end.isoformat()},
        "relays": {
            "configured": relay_nodes.configured(),
            "sides": relay_nodes.sides(),
            "role_overrides": relay_nodes.role_overrides(),
            "levels": levels,
        },
        "chains": chains[: max(1, int(settings.chain_max_chains))],
        "scanned": len(docs),
        "truncated": truncated or len(chains) > int(settings.chain_max_chains),
        "suspicious_only": suspicious_only,
    }


# ---------- 接口 ----------


@router.get("")
def list_chains(
    _: Annotated[User, Depends(get_current_user)],
    minutes: int = 60,
    from_ts: str = "",
    to_ts: str = "",
    ip: str = "",
    host: str = "",
    suspicious_only: bool = True,
) -> dict[str, Any]:
    """时间窗内的链路清单：真实请求IP →（中继…）→ 源站 + 事实规模。

    `suspicious_only=true`（默认）只留「可疑」链路（签名命中/可疑事件类型/4xx-5xx/带上传），
    这是**可解释的代理口径**，不是分级结论（分级由智能体侧给）。
    """
    start, end = _window(minutes, from_ts, to_ts)
    return _build(start, end, ip=ip.strip(), host=host.strip(), suspicious_only=suspicious_only)


@router.get("/detail")
def chain_detail(
    _: Annotated[User, Depends(get_current_user)],
    client: str = "",
    origin: str = "",
    minutes: int = 60,
    from_ts: str = "",
    to_ts: str = "",
) -> dict[str, Any]:
    """单条链路的明细：逐段证据 + 动作事实 + 关键样本（正文按落库口径截断）。"""
    start, end = _window(minutes, from_ts, to_ts)
    data = _build(start, end, ip=client.strip(), host=origin.strip(), suspicious_only=False)
    match = next(
        (
            c
            for c in data["chains"]
            if (not client or c["client"] == client) and (not origin or c["origin"] == origin)
        ),
        None,
    )
    if match is None:
        raise HTTPException(status_code=404, detail="该时间窗内没有匹配的链路")
    # 样本：挑最可疑的几条（签名命中 > 上传 > 其它），正文按落库口径截断
    docs, _truncated = _fetch(start, end, settings.chain_max_events)
    picked: list[dict[str, Any]] = []
    for doc in docs:
        chain = _chain_of(doc, _edges()[0])
        if chain is None:
            continue
        if (client and chain["client"] != client) or (origin and chain["origin"] != origin):
            continue
        if not _is_suspicious(doc):
            continue
        picked.append(
            {
                "ts": doc.get("ts"),
                "log_type": doc.get("log_type"),
                "event_type": doc.get("event_type"),
                "src_ip": doc.get("src_ip"),
                "real_client_ip": doc.get("real_client_ip"),
                "dst_ip": doc.get("dst_ip"),
                "method": doc.get("method"),
                "hostname": doc.get("hostname"),
                "uri_path": doc.get("uri_path"),
                "query_string": doc.get("query_string"),
                "status_code": doc.get("status_code"),
                "signature": doc.get("signature"),
                "signature_id": doc.get("signature_id"),
                "filename": doc.get("filename"),
                "community_id": doc.get("community_id"),
                "body": str(doc.get("body") or "")[:_SAMPLE_CHARS],
                "resp_body": str(doc.get("resp_body") or "")[:_SAMPLE_CHARS],
            }
        )
        if len(picked) >= 5:
            break
    return {"chain": match, "samples": picked}


@router.post("/dispatch")
def dispatch_chain(
    body: DispatchIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """把这条链路交给智能体深挖：打包成一条摘要，走既有的推送通道（含失败重试）。"""
    start, end = _window(body.minutes, body.from_ts, body.to_ts)
    data = _build(
        start, end, ip=body.client.strip(), host=body.origin.strip(), suspicious_only=False
    )
    match = next(
        (
            c
            for c in data["chains"]
            if (not body.client or c["client"] == body.client)
            and (not body.origin or c["origin"] == body.origin)
        ),
        None,
    )
    if match is None:
        raise HTTPException(status_code=404, detail="该时间窗内没有匹配的链路")
    client = str(match.get("client") or "")
    if not client:
        raise HTTPException(status_code=400, detail="该链路没有可归因的请求 IP，无法交给智能体")

    cfg = digest_push.load_config(db)
    if not str(cfg.get("url") or "").strip():
        raise HTTPException(
            status_code=400,
            detail="尚未配置智能体推送地址与令牌：请先在「智能体对接」页配置后再交分析",
        )
    docs, _truncated = _fetch(start, end, 200)
    samples = [
        {"source": "chain", "doc": doc}
        for doc in docs
        if (chain := _chain_of(doc, _edges()[0])) is not None and chain["client"] == client
    ][:10]
    digest = {
        "rule": "攻击链还原（人工提交）",
        "severity": "medium",
        "source": "manual_chain",
        "src_ip": client,
        "dst_ips": [match["origin"]] if match.get("origin") else [],
        "real_client_ips": [client],
        "event_types": sorted((match["facts"].get("event_types") or {}).keys()),
        "count": int(match["facts"].get("events") or 1),
        "first_seen": match["facts"].get("first_seen") or start.isoformat(),
        "last_seen": match["facts"].get("last_seen") or end.isoformat(),
        "note": body.note,
        "aggregate": {
            "chain": {
                "client": client,
                "relay_path": match.get("relay_path") or [],
                "origin": match.get("origin") or "",
                "segments": match.get("segments") or [],
                "facts": match.get("facts") or {},
            }
        },
        "samples": samples,
    }
    ok, err = digest_push.push_batch(cfg, [digest])
    log.info("攻击链交智能体：client=%s origin=%s 成功=%s", client, match.get("origin"), ok)
    if not ok:
        return {"delivered": False, "queued": False, "error": err[:200], "client": client}
    return {"delivered": True, "queued": False, "error": "", "client": client}
