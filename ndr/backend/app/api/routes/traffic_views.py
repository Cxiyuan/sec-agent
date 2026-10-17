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
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9092: "Kafka",
    9200: "Elasticsearch",
    11211: "Memcached",
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


def _build_body(view: str, *, minutes: int, size: int) -> dict[str, Any]:
    subject = _subject_field(view)
    peer = _peer_field(view)
    port = _port_field(view)
    return {
        "size": 0,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": f"now-{max(1, minutes)}m"}}}],
                # 只看网络类事实（主机日志没有流量语义）
                "must_not": [{"terms": {"log_type.keyword": ["analyzer", "stats", "metrics"]}}],
            }
        },
        "aggs": {
            "subject": {
                # 先按下行字节排序拿候选（总量在 Python 里算，排序只是选桶手段）
                "terms": {"field": f"{subject}.keyword", "size": size, "order": {"bytes_in": "desc"}},
                "aggs": {
                    "bytes_out": {"sum": {"field": "bytes_out"}},
                    "bytes_in": {"sum": {"field": "bytes_in"}},
                    # 不用 Painless 把两个字段加起来：缺字段的文档会让**整个分片**报
                    # "A document doesn't have a value for a field"，返回 0 桶还看不出来
                    # （2026-10 实机踩过：dns/weird 等日志没有 bytes_* → 三个视角全空）。
                    # 改成各求和、在 Python 里加总，口径一样且更快。
                    # 不同对端数（横向/外连的"访问了多少个不同 IP"）
                    "peers": {"cardinality": {"field": f"{peer}.keyword", "precision_threshold": 40000}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "hostname": {"terms": {"field": "hostname.keyword", "size": 1}},
                    "log_types": {"terms": {"field": "log_type.keyword", "size": 8}},
                    "ports": {
                        "terms": {"field": port, "size": 12, "order": {"bo": "desc"}},
                        "aggs": {
                            "bo": {"sum": {"field": "bytes_out"}},
                            "bi": {"sum": {"field": "bytes_in"}},
                        },
                    },
                    "top_peers": {
                        "terms": {"field": f"{peer}.keyword", "size": 30, "order": {"bytes_in": "desc"}},
                        "aggs": {
                            "bytes_out": {"sum": {"field": "bytes_out"}},
                            "bytes_in": {"sum": {"field": "bytes_in"}},
                            "hostname": {"terms": {"field": "hostname.keyword", "size": 1}},
                        },
                    },
                },
            }
        },
    }


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


def shape_rows(resp: Any, *, view: str, limit: int) -> dict[str, Any]:
    """ES 聚合 → 界面行（并按内外网口径过滤主语/对端）。"""
    nets = _nets()
    buckets = (((resp.get("aggregations") or {}).get("subject") or {}).get("buckets")) or []
    rows: list[dict[str, Any]] = []
    filtered_out = 0
    for bucket in buckets:
        ip = str(bucket.get("key") or "")
        if not ip:
            continue
        if view == "outbound":
            # 主语必须是被监控的资产；否则是"公网→公网"的噪声
            if nets and not _in(ip, nets):
                filtered_out += 1
                continue
        else:
            # 主语必须是内网主机
            if nets and not _in(ip, nets):
                filtered_out += 1
                continue

        ports = []
        for pb in ((bucket.get("ports") or {}).get("buckets")) or []:
            ports.append(
                {
                    "port": pb.get("key"),
                    "app": app_of(pb.get("key")),
                    "bytes": int((pb.get("bo") or {}).get("value") or 0)
                    + int((pb.get("bi") or {}).get("value") or 0),
                }
            )

        peers = []
        for pb in ((bucket.get("top_peers") or {}).get("buckets")) or []:
            peer_ip = str(pb.get("key") or "")
            if view == "lateral":
                if nets and not _in(peer_ip, nets):
                    continue  # 横向视角只算网段内的对端
            elif view == "egress":
                if nets and _in(peer_ip, nets):
                    continue  # 外连视角只算网段外的对端
            else:  # outbound：对端应是公网客户端
                if nets and _in(peer_ip, nets):
                    continue
            host_buckets = ((pb.get("hostname") or {}).get("buckets")) or []
            peers.append(
                {
                    "ip": peer_ip,
                    "hostname": str(host_buckets[0].get("key") or "") if host_buckets else "",
                    "bytes": int((pb.get("bytes_out") or {}).get("value") or 0)
                    + int((pb.get("bytes_in") or {}).get("value") or 0),
                }
            )

        ports.sort(key=lambda p: -int(p["bytes"]))
        peers.sort(key=lambda p: -int(p["bytes"]))
        bytes_out = int((bucket.get("bytes_out") or {}).get("value") or 0)
        bytes_in = int((bucket.get("bytes_in") or {}).get("value") or 0)
        hosts = ((bucket.get("hostname") or {}).get("buckets")) or []
        rows.append(
            {
                "ip": ip,
                "hostname": str(hosts[0].get("key") or "") if hosts else "",
                "bytes_out": bytes_out,
                "bytes_in": bytes_in,
                "bytes_total": bytes_out + bytes_in,
                "conns": int(bucket.get("doc_count") or 0),
                "peers": int((bucket.get("peers") or {}).get("value") or 0),
                "ports": ports,
                "peers_top": peers,
                "log_types": [
                    {"value": lb.get("key"), "count": lb.get("doc_count")}
                    for lb in (((bucket.get("log_types") or {}).get("buckets")) or [])
                ],
                "last_seen": (bucket.get("last_seen") or {}).get("value_as_string") or "",
                "regions": _regions_from_peers(peers),
            }
        )
    rows.sort(key=lambda r: -int(r["bytes_total"]))
    rows = rows[:limit]

    return {
        "items": rows,
        "scanned_buckets": len(buckets),
        "filtered_out": filtered_out,
        "geo_available": _geo_available(),
        "warning": shard_problem(resp),
        "note": "" if _geo_available() else "「地区」需要离线地理库（部署时用 ST_GEOIP_DB 指向 .mmdb），当前显示「未知」",
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
    body = _build_body(view, minutes=minutes, size=min(300, max(limit * 2, 60)))
    try:
        resp = _es().search(index=settings.es_events_index, body=body)
    except Exception as exc:  # noqa: BLE001
        log.warning("流量聚合失败: %s", exc)
        return {"items": [], "error": f"ES 查询失败：{exc}", "view": view, "minutes": minutes}
    out = shape_rows(resp, view=view, limit=limit)
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
