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
import time
from collections.abc import Iterable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

from app import geoip
from app.api.deps import get_current_user
from app.config import settings
from app.db.models import User
from app.ingestion import scope as scope_mod
from app.iputil import is_public_ip
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
    # 用 getattr 取版本：ipaddress 的抽象基类在类型存根里没有暴露 version
    return any(addr in net for net in nets if getattr(net, "version", 0) == addr.version)


def _clean_hostname(hostname: str, ip: str) -> str:
    """主机名清洗：Zeek 有时把 `IP:端口` 写进 host 字段（没有域名的连接），那不是主机名。"""
    text = str(hostname or "").strip()
    if not text:
        return ""
    bare = text.rsplit(":", 1)[0] if text.count(":") == 1 else text
    if bare == ip or text.startswith(ip):
        return ""
    # 纯 IP 不算主机名（实测有把对端 IP 写进 host 字段的情况）
    try:
        ipaddress.ip_address(bare)
        return ""
    except ValueError:
        pass
    if "/" in text or " " in text:
        return ""
    return text[:255]


def _geo_available() -> bool:
    """地理库是否可用（配了路径且能打开）。"""
    try:
        label = geoip.resolve("1.1.1.1")
        return bool(label) and label != "未知"
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
        return geoip.region_counts(counts, top=5)
    except Exception as exc:  # noqa: BLE001 — 地理库坏了不能挡住流量页
        log.warning("地域统计失败：%s", exc)
        return []


def _top_subjects_body(*, minutes: int, view: str, size: int) -> dict[str, Any]:
    """第一段查询：按**流量**取 top 主语 IP。

    为什么要有这一段：`composite` 聚合（按 IP 对）**只能按字典序返回**，
    直接取前 N 条拿到的是"字母序靠前的 IP 对"，不是流量最大的那些 ——
    这就是 2026-10 QA 里"最近 1 小时数据怎么这么少"的根因。
    先按流量选出候选主语，再把查询限定在这些主语上跑对聚合，数据才完整。
    """
    subject = _subject_field(view)
    return {
        "size": 0,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": f"now-{max(1, minutes)}m"}}}],
                "must_not": [{"terms": {"log_type.keyword": ["analyzer", "stats", "metrics"]}}],
            }
        },
        "aggs": {
            "subjects": {
                "terms": {
                    "field": f"{subject}.keyword",
                    "size": size,
                    "order": {"bytes_in": "desc"},
                },
                "aggs": {"bytes_in": {"sum": {"field": "bytes_in"}}},
            }
        },
    }


def _pair_body(
    *,
    minutes: int,
    size: int,
    subject_field: str = "",
    subjects: list[str] | None = None,
    use_real_client: bool = False,
) -> dict[str, Any]:
    """按 **(源 IP, 目的 IP) 对** 聚合。

    为什么必须按对聚合：三个视角的分母不同 ——
    对外业务看"公网→资产"，横向看"内网→内网"，外连看"内网→公网"。
    如果只在 Python 里过滤"显示出来的对端"，主语的**总流量仍是全方向合计**，
    横向与外连就会长得一模一样（2026-10 QA 实测到的错）。
    按对聚出来后，每一对都能判方向，再按视角归类，数字才对。
    """
    filters: list[dict[str, Any]] = [{"range": {"@timestamp": {"gte": f"now-{max(1, minutes)}m"}}}]
    if subject_field and subjects:
        # 只在这些候选主语上做对聚合（候选是"流量最大的那批"，见 _top_subjects_body）
        filters.append({"terms": {f"{subject_field}.keyword": subjects[:500]}})
    if use_real_client:
        # 只对"有真实客户端"的文档（反向代理后面的那部分）
        filters.append({"exists": {"field": "real_client_ip"}})
    return {
        "size": 0,
        "query": {
            "bool": {
                "filter": filters,
                "must_not": [{"terms": {"log_type.keyword": ["analyzer", "stats", "metrics"]}}],
            }
        },
        "aggs": {
            # 主机名单独按**主语**取：字节数来自 conn（无主机名），
            # 主机名来自 http/ssl（字节少），按"对"取会取不到（2026-10 QA 实测全空）。
            "subject_hosts": {
                "terms": {"field": "dst_ip.keyword", "size": size},
                "aggs": {"names": {"terms": {"field": "hostname.keyword", "size": 5}}},
            },
            "pairs": {
                "composite": {
                    "size": size,
                    "sources": (
                        [
                            # 代理后的**真实公网客户端**（X-Forwarded-For 等里的最左地址）
                            {"s": {"terms": {"field": "real_client_ip.keyword"}}},
                            {"d": {"terms": {"field": "dst_ip.keyword"}}},
                        ]
                        if use_real_client
                        else [
                            {"s": {"terms": {"field": "src_ip.keyword"}}},
                            {"d": {"terms": {"field": "dst_ip.keyword"}}},
                        ]
                    ),
                },
                "aggs": {
                    "bo": {"sum": {"field": "bytes_out"}},
                    "bi": {"sum": {"field": "bytes_in"}},
                    "docs": {"value_count": {"field": "@timestamp"}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                    # 取 3 个候选：每个"对"里排第一的常常是 `IP:端口`（Zeek 没域名时这么写），
                    # 清洗后会变空 —— 多取两个才容易捞到真域名
                    "hostname": {"terms": {"field": "hostname.keyword", "size": 3}},
                    "ports": {
                        "terms": {"field": "dst_port", "size": 10, "order": {"bo": "desc"}},
                        "aggs": {
                            "bo": {"sum": {"field": "bytes_out"}},
                            "bi": {"sum": {"field": "bytes_in"}},
                        },
                    },
                },
            },
        },
    }


#: 公网源 IP 的 terms 取数上限（24 小时实测约 1 万个不同源 IP，2 万够用且便宜）
_PUBLIC_SRC_TERMS = 20_000


def _base_filter(minutes: int) -> list[dict[str, Any]]:
    return [{"range": {"@timestamp": {"gte": f"now-{max(1, minutes)}m"}}}]


def _public_peers_body(minutes: int) -> dict[str, Any]:
    """第一段（对外业务专用）：把窗口内出现过的源 IP / 真实客户端 IP 全取出来。

    为什么不像横向/外连那样按主语取 TOP-N：对外业务的**主语是小流量资产**（被公网
    扫一枪、只有几条握手，`bytes_in` 接近 0），按流量排名永远排不进前几百，
    整台主机就从界面上消失了（2026-10 实测：1 小时 13 台只剩 8 台）。
    公网源 IP 本身是少数（1 小时几十个、24 小时一百多个），全取回来再过滤反而更准。
    """
    return {
        "size": 0,
        "query": {
            "bool": {
                "filter": _base_filter(minutes),
                "must_not": [{"terms": {"log_type.keyword": ["analyzer", "stats", "metrics"]}}],
            }
        },
        "aggs": {
            "src": {"terms": {"field": "src_ip.keyword", "size": _PUBLIC_SRC_TERMS}},
            "real": {"terms": {"field": "real_client_ip.keyword", "size": _PUBLIC_SRC_TERMS}},
        },
    }


def _outbound_body(
    *, minutes: int, peers: list[str], real_peers: list[str], size: int
) -> dict[str, Any]:
    """第二段（对外业务专用）：只看公网来源，按**被访问资产**（dst）聚合。

    单次 terms 聚合就能拿全，不需要 composite 翻页 —— `composite` 只返回字典序第一页，
    24 小时 1.8 万个 (源,目的) 对只取到 5000 个，资产数从 40 台掉到 1 台（2026-10 实测）。
    """
    should: list[dict[str, Any]] = []
    # terms 过滤器一次塞太多值会拖慢查询；5 千个公网源已经覆盖超长窗口
    if peers:
        should.append({"terms": {"src_ip.keyword": peers[:5000]}})
    if real_peers:
        should.append({"terms": {"real_client_ip.keyword": real_peers[:5000]}})
    return {
        "size": 0,
        "query": {
            "bool": {
                "filter": _base_filter(minutes),
                "should": should,
                "minimum_should_match": 1,
                "must_not": [{"terms": {"log_type.keyword": ["analyzer", "stats", "metrics"]}}],
            }
        },
        "aggs": {
            "assets": {
                "terms": {"field": "dst_ip.keyword", "size": size, "order": {"bi": "desc"}},
                "aggs": {
                    "bo": {"sum": {"field": "bytes_out"}},
                    "bi": {"sum": {"field": "bytes_in"}},
                    "docs": {"value_count": {"field": "@timestamp"}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "clients": {"cardinality": {"field": "src_ip.keyword", "precision_threshold": 1000}},
                    "peer_top": {
                        "terms": {"field": "src_ip.keyword", "size": 10, "order": {"bi": "desc"}},
                        "aggs": {
                            "bo": {"sum": {"field": "bytes_out"}},
                            "bi": {"sum": {"field": "bytes_in"}},
                        },
                    },
                    "hostname": {"terms": {"field": "hostname.keyword", "size": 3}},
                    "ports": {
                        "terms": {"field": "dst_port", "size": 10, "order": {"bo": "desc"}},
                        "aggs": {
                            "bo": {"sum": {"field": "bytes_out"}},
                            "bi": {"sum": {"field": "bytes_in"}},
                        },
                    },
                },
            }
        },
    }


def _outbound_rows(
    resp: Any, *, limit: int, minutes: int
) -> dict[str, Any]:
    """对外业务：资产行（公网 → 监控网段）。字段形状与 `shape_pairs` 一致。"""
    nets = _nets()
    scanned = 0
    rows: list[dict[str, Any]] = []
    for bucket in (((resp.get("aggregations") or {}).get("assets") or {}).get("buckets")) or []:
        scanned += 1
        ip = str(bucket.get("key") or "")
        if not ip or not _in(ip, nets):
            continue
        bytes_out = int((bucket.get("bo") or {}).get("value") or 0)
        bytes_in = int((bucket.get("bi") or {}).get("value") or 0)
        hostname = ""
        for hb in ((bucket.get("hostname") or {}).get("buckets")) or []:
            cleaned = _clean_hostname(str(hb.get("key") or ""), ip)
            if cleaned:
                hostname = cleaned
                break
        peers = [
            {
                "ip": str(pb.get("key") or ""),
                # 对端是公网客户端，没有主机名（域名是资产的，不是客户端的）
                "hostname": "",
                "bytes": int((pb.get("bo") or {}).get("value") or 0)
                + int((pb.get("bi") or {}).get("value") or 0),
            }
            for pb in ((bucket.get("peer_top") or {}).get("buckets")) or []
            if pb.get("key")
        ]
        ports = [
            {
                "port": pb.get("key"),
                "app": app_of(pb.get("key")),
                "bytes": int((pb.get("bo") or {}).get("value") or 0)
                + int((pb.get("bi") or {}).get("value") or 0),
            }
            for pb in ((bucket.get("ports") or {}).get("buckets")) or []
        ]
        rows.append(
            {
                "ip": ip,
                "hostname": hostname,
                "bytes_out": bytes_out,
                "bytes_in": bytes_in,
                "bytes_total": bytes_out + bytes_in,
                "conns": int((bucket.get("docs") or {}).get("value") or 0),
                "peers": int((bucket.get("clients") or {}).get("value") or 0),
                "ports": ports,
                "peers_top": peers[:10],
                "log_types": [],
                "last_seen": (bucket.get("last_seen") or {}).get("value_as_string") or "",
                "regions": _regions_from_peers(peers[:10]),
            }
        )
    rows.sort(key=lambda r: -int(r["bytes_total"]))
    return {
        "items": rows[:limit],
        "scanned_pairs": scanned,
        "kept_pairs": len(rows),
        "filtered_out": max(0, scanned - len(rows)),
        "geo_available": _geo_available(),
        "note": ""
        if _geo_available()
        else "「地区」需要离线地理库（部署时用 ST_GEOIP_DB 指向 .mmdb），当前显示「未知」",
        "monitored_nets": [str(n) for n in nets],
        "truncated": False,
        "minutes": minutes,
    }


def _classify(view: str, src: str, dst: str, nets: list[ipaddress._BaseNetwork]) -> bool:
    """这一对是否属于该视角。

    口径（2026-10 用户定义 + QA 修正）：
    - 对外业务 = **公网** → 监控网段资产（"公网"用 `is_public_ip` 判，不能只判"不在监控网段"——
      否则 `10.1.90.x` 这类**未监控的内网段**会被当成公网客户端，地域里就冒出一堆「内网」）；
    - 横向 = 监控网段 ↔ 监控网段（两端都在监控网段内）；
    - 外连 = 监控网段 → **公网**。

    未监控网段 → 监控网段（例如 10.1.90.x → 10.1.2.x）不属于这三个视角：
    它是"另一片内网访问我们的资产"，要看就把那片网段加进监控网段。
    """
    s_in = _in(src, nets)
    d_in = _in(dst, nets)
    if view == "outbound":
        return d_in and is_public_ip(src)
    if view == "lateral":
        return s_in and d_in
    return s_in and is_public_ip(dst)


def shape_pairs(resp: Any, *, view: str, limit: int, extra: Any = None) -> dict[str, Any]:
    """(源,目的) 对 → 每台主机的行（按视角选主语）。"""
    nets = _nets()
    # 主语 → 候选主机名（按出现次数；对外业务视角用它给资产配域名）
    host_by_subject: dict[str, list[str]] = {}
    for hb in (((resp.get("aggregations") or {}).get("subject_hosts") or {}).get("buckets")) or []:
        key = str(hb.get("key") or "")
        names = [
            str(nb.get("key") or "") for nb in (((hb.get("names") or {}).get("buckets")) or [])
        ]
        if key and names:
            host_by_subject[key] = names
    buckets = list((((resp.get("aggregations") or {}).get("pairs") or {}).get("buckets")) or [])
    # 反向代理场景：真实公网客户端在 real_client_ip 里，单独一份聚合合进来
    if extra is not None:
        buckets += (((extra.get("aggregations") or {}).get("pairs") or {}).get("buckets")) or []
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
        # 主机名只从"对外业务"视角取（那时它才是被访问资产的域名）；
        # 横向/外连视角里 hostname 是"客户端访问过的域名"，不是这台主机自己的名字。
        if view == "outbound" and not row["hostname"]:
            for name in host_by_subject.get(subject, []):
                cleaned = _clean_hostname(name, subject)
                if cleaned:
                    row["hostname"] = cleaned
                    break
        row["peer_set"].add(peer)
        for pb in ((bucket.get("ports") or {}).get("buckets")) or []:
            port = pb.get("key")
            slot = row["ports"].setdefault(port, {"port": port, "app": app_of(port), "bytes": 0})
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
    minutes: int = Query(default=60, ge=1, le=60 * 24 * 30),
    limit: int = Query(default=100, ge=1, le=300),
) -> dict[str, Any]:
    """按 IP 出三个视角的流量明细（对外业务 / 横向 / 外连）。

    **对外业务走单独一条路**（2026-10 修正）：公网来源取全量 → 按被访问资产聚合。
    旧的两段式（按流量取 TOP-N 主语 + composite 对聚合）会把"被扫一枪的小流量资产"
    和"第 5000 条之后的资产"悄悄丢掉（实测 1 小时 13 台只显示 8 台、24 小时 40 台只剩 1 台）。

    横向/外连仍是两段式（内网主语太多，必须按流量抽样），但 composite **会翻页**，
    并在 `truncated=true` 时明确告诉界面"这还不是全部"。
    """
    if view not in VIEWS:
        view = "outbound"
    # 窗口越大越要收着查（7 天/30 天把 ES 打超时过：2026-10 实测 ConnectionTimeout）
    if minutes <= 120:
        candidate_size, pair_size = min(1500, max(limit * 3, 300)), 8000
    elif minutes <= 1440:
        candidate_size, pair_size = 400, 5000
    else:
        candidate_size, pair_size = 200, 1500
    # composite 翻页上限：一页 5000 对，4 页够覆盖 24 小时的资产量，再大就太慢
    pair_pages = 4 if minutes <= 1440 else 2

    # ---------- 对外业务：公网来源全量 → 按资产聚合（不抽样、不翻页截断） ----------
    if view == "outbound":
        try:
            peers_resp = _es().search(
                index=settings.es_events_index,
                body=_public_peers_body(minutes),
                request_timeout=120,
            )
            aggs = (peers_resp.get("aggregations") or {})
            peers = [
                str(b.get("key"))
                for b in ((aggs.get("src") or {}).get("buckets") or [])
                if b.get("key") and is_public_ip(str(b.get("key")))
            ]
            real_peers = [
                str(b.get("key"))
                for b in ((aggs.get("real") or {}).get("buckets") or [])
                if b.get("key") and is_public_ip(str(b.get("key")))
            ]
            # terms 聚合只返回出现最多的 2 万个源 IP；更长窗口里"只出现一次"的公网源
            # 可能被截断（sum_other_doc_count > 0）——这时如实标 truncated，不假装完整
            peers_truncated = bool(
                (aggs.get("src") or {}).get("sum_other_doc_count")
                or (aggs.get("real") or {}).get("sum_other_doc_count")
            )
            if not peers and not real_peers:
                return {
                    "items": [],
                    "view": view,
                    "minutes": minutes,
                    "scanned_pairs": 0,
                    "kept_pairs": 0,
                    "filtered_out": 0,
                    "truncated": False,
                    "warning": "",
                    "note": "窗口内没有公网来源的访问",
                    # 字段形状与正常返回一致：前端不用做"空结果是另一套结构"的兼容
                    "geo_available": _geo_available(),
                    "monitored_nets": [str(n) for n in _nets()],
                }
            resp = _es().search(
                index=settings.es_events_index,
                body=_outbound_body(
                    minutes=minutes,
                    peers=peers,
                    real_peers=real_peers,
                    size=min(3000, max(limit * 3, 500)),
                ),
                request_timeout=120,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("对外流量聚合失败: %s", exc)
            return {"items": [], "error": f"ES 查询失败：{exc}", "view": view, "minutes": minutes}
        out = _outbound_rows(resp, limit=limit, minutes=minutes)
        out["truncated"] = bool(out.get("truncated")) or peers_truncated
        if peers_truncated and not out.get("note"):
            out["note"] = "窗口内有大量只出现一次的来源地址，统计可能不完整（缩小时间范围可看全）"
        out.update({"view": view, "warning": shard_problem(resp)})
        return out

    # ---------- 横向 / 外连：按流量取 TOP-N 主语 → 对聚合（翻页，标明截断） ----------
    subject_field = _subject_field(view)
    try:
        top = _es().search(
            index=settings.es_events_index,
            body=_top_subjects_body(minutes=minutes, view=view, size=candidate_size),
            request_timeout=120,
        )
        candidates = [
            str(b.get("key"))
            for b in (
                (((top.get("aggregations") or {}).get("subjects") or {}).get("buckets")) or []
            )
            if b.get("key")
        ]
        buckets: list[dict[str, Any]] = []
        subject_hosts: dict[str, Any] = {}
        once = False
        after: Any = None
        started = time.monotonic()
        for _page in range(pair_pages):
            # 时间预算：24 小时的对聚合单页就要 20 秒，翻页再多会把接口拖死；
            # 超预算就停在当前页，用 truncated 告诉界面"这不是全部"（比静默丢数据好）。
            if _page > 0 and time.monotonic() - started > 8:
                break
            body = _pair_body(
                minutes=minutes, size=pair_size, subject_field=subject_field, subjects=candidates
            )
            if after is not None:
                body["aggs"]["pairs"]["composite"]["after"] = after
            resp = _es().search(index=settings.es_events_index, body=body, request_timeout=120)
            if not once:
                subject_hosts = (resp.get("aggregations") or {}).get("subject_hosts") or {}
                once = True
            agg = ((resp.get("aggregations") or {}).get("pairs") or {})
            buckets.extend(agg.get("buckets") or [])
            after = agg.get("after_key")
            if after is None:
                break
        truncated = after is not None
        resp = {"aggregations": {"pairs": {"buckets": buckets}, "subject_hosts": subject_hosts}}
    except Exception as exc:  # noqa: BLE001
        log.warning("流量聚合失败: %s", exc)
        return {"items": [], "error": f"ES 查询失败：{exc}", "view": view, "minutes": minutes}
    out = shape_pairs(resp, view=view, limit=limit, extra=None)
    out.update({"view": view, "minutes": minutes, "warning": shard_problem(resp)})
    out["truncated"] = truncated
    if truncated:
        out["note"] = (
            (out.get("note") or "") + "；窗口内数据量较大，只统计了流量最高的部分资产（缩小时间范围可看全）"
        ).strip("；")
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
        up = int((bucket.get("bytes_out") or {}).get("value") or 0)
        down = int((bucket.get("bytes_in") or {}).get("value") or 0)
        value = up + down
        hosts = ((bucket.get("hostname") or {}).get("buckets")) or []
        nodes.append(
            {
                "ip": peer_ip,
                "hostname": str(hosts[0].get("key") or "") if hosts else "",
                "internal": bool(_in(peer_ip, nets)),
                "bytes": value,
            }
        )
        # 边上带上下行：鼠标移到线路上要能提示"上行多少、下行多少"
        edges.append(
            {"source": ip, "target": peer_ip, "bytes": value, "bytes_out": up, "bytes_in": down}
        )
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
