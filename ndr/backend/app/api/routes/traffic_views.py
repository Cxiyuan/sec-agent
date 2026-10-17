"""可视化流量（分析中心）：三个视角按 **IP** 聚合 —— 对外业务 / 横向 / 外连。

三个视角的区别只看「谁是主语、谁是对方、谁是内网」：

| 视角 | 主语 | 对方 | 含义 |
|---|---|---|---|
| outbound（对外业务流量） | 监控网段内的**资产**（dst） | 公网客户端（src） | 公网请求进来的业务访问 |
| lateral（横向访问流量） | 内网主机（src） | 内网主机（dst） | 网段内部的连接（横向移动视角） |
| egress（外连流量） | 内网主机（src） | 公网目标（dst） | 网段主动访问出去 |

实现要点：
- **内外网判定**用 `scope.monitored_nets()`（与采集/检测同一份配置），在 Python 侧过滤 ——
  不去猜 ES 的 `ip` 类型映射，也不把网段写死进查询。
- 一个 ES 聚合拿完一屏数据：`terms(主语 IP)` + 子聚合（流量、端点数、端口 TOP、日志类型、
  主机名、最近活跃）。端点数用 `cardinality`（ES 精确计数，precision_threshold 上限内）。
- 「地域 TOP5」需要 GeoIP 库：本部署没有 → 返回空数组并带 `geo_available=false`，
  前端显示"未配置 GeoIP"。库到位后只要填 `_regions()` 就能出数据，接口形状不用改。
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

from app.api.deps import get_current_user
from app.config import settings
from app.db.models import User
from app.ingestion import scope as scope_mod
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/traffic", tags=["traffic"])

VIEWS = ("outbound", "lateral", "egress")

#: 端口 → 应用名（TOP10 里显示"应用名（端口，流量）"用）。查不到就用 `端口/协议`。
PORT_APP: dict[int, str] = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS/TLS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP-Sub",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2181: "ZooKeeper",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5672: "AMQP",
    5900: "VNC",
    6379: "Redis",
    3000: "HTTP-Dev",
    4500: "IPsec-NAT-T",
    5000: "HTTP-Alt",
    5601: "Kibana",
    6443: "K8s-API",
    7001: "WebLogic",
    7002: "WebLogic-SSL",
    8000: "HTTP-Alt",
    8001: "HTTP-Alt",
    8008: "HTTP-Alt",
    8009: "AJP",
    8080: "HTTP-Proxy",
    8081: "HTTP-Alt",
    8088: "HTTP-Alt",
    8090: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9000: "HTTP-Alt",
    9090: "HTTP-Alt",
    9092: "Kafka",
    9200: "Elasticsearch",
    9443: "HTTPS-Alt",
    11211: "Memcached",
    12321: "P2P/下载",
    27017: "MongoDB",
}


def app_of(port: Any, protocol: Any = "") -> str:
    """端口 → 应用名；没有映射就回落 `端口/协议`。"""
    try:
        num = int(port)
    except (TypeError, ValueError):
        return str(protocol or "其它")
    name = PORT_APP.get(num)
    if name:
        return name
    proto = str(protocol or "").lower()
    return f"{num}/{proto}" if proto else str(num)


def _nets() -> list[ipaddress._BaseNetwork]:
    out: list[ipaddress._BaseNetwork] = []
    for text in scope_mod.monitored_nets():
        try:
            out.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            continue
    return out


def _in(ip: str, nets: Iterable[ipaddress._BaseNetwork]) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return any(addr in net for net in nets if net.version == addr.version)


def _clean_hostname(hostname: str, ip: str) -> str:
    """主机名清洗：Zeek 有时把 `IP:端口` 写进 host 字段（没有域名的连接），那不是主机名。"""
    text = str(hostname or "").strip()
    if not text:
        return ""
    bare = text.rsplit(":", 1)[0] if text.count(":") == 1 else text
    if bare == ip or text.startswith(ip):
        return ""
    return text[:255]


def _geo_available() -> bool:
    """地理库是否可用（配了路径且能打开）。"""
    try:
        from app import geoip

        return bool(geoip.resolve("1.1.1.1")) and geoip.resolve("1.1.1.1") != "未知"
    except Exception:  # noqa: BLE001
        return False


def _es() -> Any:
    from app.ingestion.es_client import get_es

    return get_es()


def shard_problem(resp: Any) -> str:
    """分片失败的可见化：ES 有分片报错时仍可能返回 200 与空结果。

    2026-10 实机踩过：聚合脚本在"缺字段"的文档上抛错 → 1 个分片失败 → `hits.total=0`、
    buckets 为空，界面上就变成"没有流量"，根因完全看不见。这里把失败原因提出来。
    """
    shards = (resp or {}).get("_shards") or {}
    failed = int(shards.get("failed") or 0)
    if not failed:
        return ""
    reason = ""
    failures = shards.get("failures") or []
    if failures:
        first = failures[0].get("reason") or {}
        kind = str(first.get("type") or "").strip()
        detail = str(first.get("reason") or "").strip()
        reason = f"{kind}: {detail}" if kind and detail else (kind or detail)[:160]
    return f"{failed} 个分片查询失败（{reason or '原因未知'}），结果可能不完整"


def _terms(key: str, size: int) -> dict[str, Any]:
    return {"terms": {"field": f"{key}.keyword", "size": size}}


def _subject_field(view: str) -> str:
    # 对外业务：主语是被访问的资产（dst）；横向与外连：主语是发起方（src）
    return "dst_ip" if view == "outbound" else "src_ip"


def _peer_field(view: str) -> str:
    return "src_ip" if view == "outbound" else "dst_ip"


def _port_field(view: str) -> str:
    # 对外业务看"被访问端口"（资产暴露面）；横向/外连看对端端口
    return "dst_port"


def _regions_from_peers(peers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """对端 IP 列表 → 地域 TOP5（次数 = 该地域出现的不同 IP 数）。

    地理库是**可选**能力（`settings.geoip_db` 指向 .mmdb 才生效）：
    没配库时统一返回 `[{"region": "未知", "count": N}]`，前端照常显示「未知」并说明原因 ——
    不假装有数据。
    """
    if not peers:
        return []
    counts = {str(p.get("ip") or ""): 1 for p in peers if p.get("ip")}
    try:
        from app import geoip

        return geoip.region_counts(counts, top=5)
    except Exception as exc:  # noqa: BLE001 — 地理库坏了不能挡住流量页
        log.warning("地域统计失败：%s", exc)
        return []


def _pair_body(*, minutes: int, size: int) -> dict[str, Any]:
    """按 **(源 IP, 目的 IP) 对** 聚合。

    为什么必须按对聚合：三个视角的分母不同 ——
    对外业务看"公网→资产"，横向看"内网→内网"，外连看"内网→公网"。
    如果只在 Python 里过滤"显示出来的对端"，主语的**总流量仍是全方向合计**，
    横向与外连就会长得一模一样（2026-10 QA 实测到的错）。
    按对聚出来后，每一对都能判方向，再按视角归类，数字才对。
    """
    return {
        "size": 0,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": f"now-{max(1, minutes)}m"}}}],
                "must_not": [{"terms": {"log_type.keyword": ["analyzer", "stats", "metrics"]}}],
            }
        },
        "aggs": {
            "pairs": {
                "composite": {
                    "size": size,
                    "sources": [
                        {"s": {"terms": {"field": "src_ip.keyword"}}},
                        {"d": {"terms": {"field": "dst_ip.keyword"}}},
                    ],
                },
                "aggs": {
                    "bo": {"sum": {"field": "bytes_out"}},
                    "bi": {"sum": {"field": "bytes_in"}},
                    "docs": {"value_count": {"field": "@timestamp"}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "hostname": {"terms": {"field": "hostname.keyword", "size": 1}},
                    "ports": {
                        "terms": {"field": "dst_port", "size": 10, "order": {"bo": "desc"}},
                        "aggs": {"bo": {"sum": {"field": "bytes_out"}}, "bi": {"sum": {"field": "bytes_in"}}},
                    },
                },
            }
        },
    }


def _classify(view: str, src: str, dst: str, nets: list[ipaddress._BaseNetwork]) -> bool:
    """这一对是否属于该视角（视角 = 主语内外 × 对端内外 的组合）。"""
    s_in = _in(src, nets) if nets else True
    d_in = _in(dst, nets) if nets else True
    if view == "outbound":
        return d_in and not s_in  # 公网 → 内网资产
    if view == "lateral":
        return s_in and d_in  # 内网 ↔ 内网
    return s_in and not d_in  # 内网 → 公网


def shape_pairs(resp: Any, *, view: str, limit: int) -> dict[str, Any]:
    """(源,目的) 对 → 每台主机的行（按视角选主语）。"""
    nets = _nets()
    buckets = (((resp.get("aggregations") or {}).get("pairs") or {}).get("buckets")) or []
    agg: dict[str, dict[str, Any]] = {}
    kept_pairs = 0
    for bucket in buckets:
        key = bucket.get("key") or {}
        src = str(key.get("s") or "")
        dst = str(key.get("d") or "")
        if not src or not dst or not _classify(view, src, dst, nets):
            continue
        kept_pairs += 1
        subject = dst if view == "outbound" else src
        peer = src if view == "outbound" else dst
        row = agg.get(subject)
        if row is None:
            row = agg[subject] = {
                "ip": subject,
                "hostname": "",
                "bytes_out": 0,
                "bytes_in": 0,
                "conns": 0,
                "peers": 0,
                "peer_set": set(),
                "ports": {},
                "peers_top": {},
                "last_seen": "",
            }
        row["bytes_out"] += int((bucket.get("bo") or {}).get("value") or 0)
        row["bytes_in"] += int((bucket.get("bi") or {}).get("value") or 0)
        row["conns"] += int((bucket.get("docs") or {}).get("value") or 0)
        last = (bucket.get("last_seen") or {}).get("value_as_string") or ""
        row["last_seen"] = max(row["last_seen"], last)
        hosts = ((bucket.get("hostname") or {}).get("buckets")) or []
        # 主机名只从"对外业务"视角取（那时它才是被访问资产的域名）；
        # 横向/外连视角里 hostname 是"客户端访问过的域名"，不是这台主机自己的名字。
        if hosts and view == "outbound" and not row["hostname"]:
            row["hostname"] = _clean_hostname(str(hosts[0].get("key") or ""), subject)
        row["peer_set"].add(peer)
        for pb in (((bucket.get("ports") or {}).get("buckets")) or []):
            port = pb.get("key")
            slot = row["ports"].setdefault(
                port, {"port": port, "app": app_of(port), "bytes": 0}
            )
            slot["bytes"] += int((pb.get("bo") or {}).get("value") or 0) + int(
                (pb.get("bi") or {}).get("value") or 0
            )
        pb_slot = row["peers_top"].setdefault(peer, {"ip": peer, "hostname": "", "bytes": 0})
        pb_slot["bytes"] += int((bucket.get("bo") or {}).get("value") or 0) + int(
            (bucket.get("bi") or {}).get("value") or 0
        )

    rows: list[dict[str, Any]] = []
    for row in agg.values():
        ports = sorted(row["ports"].values(), key=lambda x: -int(x["bytes"]))[:10]
        peers = sorted(row["peers_top"].values(), key=lambda x: -int(x["bytes"]))[:10]
        rows.append(
            {
                "ip": row["ip"],
                "hostname": row["hostname"],
                "bytes_out": row["bytes_out"],
                "bytes_in": row["bytes_in"],
                "bytes_total": row["bytes_out"] + row["bytes_in"],
                "conns": row["conns"],
                "peers": len(row["peer_set"]),
                "ports": ports,
                "peers_top": peers,
                "log_types": [],
                "last_seen": row["last_seen"],
                "regions": _regions_from_peers(peers),
            }
        )
    rows.sort(key=lambda r: -int(r["bytes_total"]))
    return {
        "items": rows[:limit],
        "scanned_pairs": len(buckets),
        "kept_pairs": kept_pairs,
        "filtered_out": len(buckets) - kept_pairs,
        "geo_available": _geo_available(),
        "note": ""
        if _geo_available()
        else "「地区」需要离线地理库（部署时用 ST_GEOIP_DB 指向 .mmdb），当前显示「未知」",
        "monitored_nets": [str(n) for n in nets],
    }


@router.get("/ips")
def traffic_ips(
    _: Annotated[User, Depends(get_current_user)],
    view: str = Query(default="outbound"),
    minutes: int = Query(default=60, ge=1, le=60 * 24 * 7),
    limit: int = Query(default=100, ge=1, le=300),
) -> dict[str, Any]:
    """按 IP 出三个视角的流量明细（对外业务 / 横向 / 外连）。"""
    if view not in VIEWS:
        view = "outbound"
    body = _pair_body(minutes=minutes, size=min(5000, max(limit * 40, 500)))
    try:
        resp = _es().search(index=settings.es_events_index, body=body)
    except Exception as exc:  # noqa: BLE001
        log.warning("流量聚合失败: %s", exc)
        return {"items": [], "error": f"ES 查询失败：{exc}", "view": view, "minutes": minutes}
    out = shape_pairs(resp, view=view, limit=limit)
    out.update({"view": view, "minutes": minutes, "warning": shard_problem(resp)})
    return out


@router.get("/peers")
def traffic_peers(
    _: Annotated[User, Depends(get_current_user)],
    ip: str,
    view: str = Query(default="lateral"),
    minutes: int = Query(default=60, ge=1, le=60 * 24 * 7),
    limit: int = Query(default=40, ge=1, le=100),
) -> dict[str, Any]:
    """某个 IP 与对端的连接（右侧抽屉里的拓扑用）。"""
    if view not in VIEWS:
        view = "outbound"
    subject = _subject_field(view)
    peer = _peer_field(view)
    nets = _nets()
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{max(1, minutes)}m"}}},
                    {"term": {f"{subject}.keyword": ip}},
                ]
            }
        },
        "aggs": {
            "peers": {
                "terms": {"field": f"{peer}.keyword", "size": limit, "order": {"bytes_in": "desc"}},
                "aggs": {
                    "bytes_out": {"sum": {"field": "bytes_out"}},
                    "bytes_in": {"sum": {"field": "bytes_in"}},
                    "hostname": {"terms": {"field": "hostname.keyword", "size": 1}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                },
            }
        },
    }
    try:
        resp = _es().search(index=settings.es_events_index, body=body)
    except Exception as exc:  # noqa: BLE001
        log.warning("对端聚合失败: %s", exc)
        return {"center": ip, "nodes": [], "edges": [], "error": str(exc)}

    nodes: list[dict[str, Any]] = [
        {"ip": ip, "internal": (not nets) or _in(ip, nets), "bytes": 0, "role": "center"}
    ]
    edges: list[dict[str, Any]] = []
    total = 0
    for bucket in (((resp.get("aggregations") or {}).get("peers") or {}).get("buckets")) or []:
        peer_ip = str(bucket.get("key") or "")
        if not peer_ip:
            continue
        value = int((bucket.get("bytes_out") or {}).get("value") or 0) + int(
            (bucket.get("bytes_in") or {}).get("value") or 0
        )
        hosts = ((bucket.get("hostname") or {}).get("buckets")) or []
        nodes.append(
            {
                "ip": peer_ip,
                "hostname": str(hosts[0].get("key") or "") if hosts else "",
                "internal": bool(_in(peer_ip, nets)),
                "bytes": value,
            }
        )
        edges.append({"source": ip, "target": peer_ip, "bytes": value})
        total += value
    nodes[0]["bytes"] = total
    return {
        "center": ip,
        "view": view,
        "minutes": minutes,
        "nodes": nodes,
        "edges": edges,
        "geo_available": False,
        "warning": shard_problem(resp),
    }
