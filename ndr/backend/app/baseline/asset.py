"""被访问方（内网源站 / 内网 DNS 转发器）的行为基线。

**为什么要有它**（用户 2026-10 选定的方案 A）：数值基线是按**源 IP（发起方）**建的，所以
「服务器被访问」这件事在现有基线里没有归属 —— 外网打内网服务器时，事件都记在**客户端**
那一侧，服务器本身没有基线，看不出「今天被 200 个不同外网 IP 访问、平时只有 5 个」。

**怎么算**（2026-10 用户选定 B2）：按**连接**（Zeek `uid`）算 —— 一个连接 = 一次「访问」：

- `visits`：被访问**连接数**（同一连接内的多条日志只算一次）；
- `requests`：**请求数**（`ST_ASSET_REQUEST_LOG_TYPES`，默认 http,dns）—— 连接数暴增
  （扫描/探测）与请求数暴增（突发负载/CC）是两件事，必须分开看；
- `distinct_clients`：不同**真实客户端**数（取 `real_client_ip`，没有才用 `src_ip`）。
  **真实客户端是一组而不是一个**：WAF/反代的一条长连接会复用/承载很多个客户端 —— 实测
  `www.example.com` 近 5 分钟 206 个请求只走了 11 条连接，而 XFF 里有 112 个不同客户端；
  只记一个会把「不同客户端数」恒压成 1（2026-10 实机验收抳出来的缺陷）。
- `distinct_client_ports`：不同客户端源端口数；
- `distinct_targets`：不同目标数（HTTP=URI、DNS=域名）。

**为什么不能按事件算**（2026-10 实机数据）：同一次业务访问在抓包点会产生 `conn`（**无** Host/SNI）
与 `http`/`ssl`（**有** Host/SNI）多条事件，按事件计就会把同一次访问同时记到 `IP:端口`
与 hostname 两个键上 —— 实测 1215 个资产里 18 个是「中继自身」却占了 **30.6%** 的被访问量
（第一名 `10.1.2.10:8000` 1817/区间，而真正要看的 `www.example.com` 只有 114/区间）。

**资产标识**：`hostname` 优先（HTTP 的 Host / SSL 的 SNI —— 中继场景下**前跳也带 Host/SNI**，
所以经代理的访问同样能归到站点上）；没有 hostname 时回落 `IP:端口`（内网 DNS 转发器就是
`IP:53`）。**中继自身不作为资产**（前跳的 dst 就是中继 —— 那是「代理被连接」，不是业务资产
被访问），**但端口 53 的中继保留**：内网 DNS 被多少客户端查询正是要看的东西。

**只统计 Zeek 网络事件**（有 `uid` 的）：主机监控日志（它的 dst 是主机自己，算成「资产被访问」
是错的）以及 files/x509/dhcp/notice 这类没有 `uid` 的日志不进基线；丢了多少条在心跳里可见
（`asset_uids_dropped`），不静默。

**v1 只展示与标记，不写进摘要标签**：判据还没在真实流量上校准，先看数据、再决定要不要标签化。
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select

from app.baseline import stats as stats_mod
from app.config import settings
from app.db.base import SessionLocal
from app.db.models import AssetStat
from app.ingestion import relay_nodes
from app.schemas import UnifiedLog
from app.workers.log import get_logger

log = get_logger(__name__)

#: 特征名（key = f"{资产}:{特征}"，读回来用 rpartition(":") 切 —— 资产里可能有冒号，如 `IP:端口`）
FEATURES: tuple[str, ...] = (
    "visits",
    "requests",
    "distinct_clients",
    "distinct_client_ports",
    "distinct_targets",
)
#: 窗口内每个集合保留多少成员（内存优先；只影响「不同 X 数」的上限）
_SET_LIMIT = 200
#: DNS 端口：用来给资产标一个粗粒度角色（站点 / DNS 服务），只为界面可读，不参与判定
_DNS_PORT = 53

#: 资产归属（用户 2026-10 口径 C）：
#: - `internal`：目标在监控网段/内网（**我们自己的源站、DNS 转发器**）—— 行为基线有意义；
#: - `external`：目标在公网（含公共 DNS 解析器，实机 `1.1.1.1`/`8.8.8.8`/
#:   `9.9.9.9` 三台就占了公网请求的 91%）—— 那是「我们的客户端去访问人家」，
#:   行为不由我们控制，**异常判定只对 internal 做**；两块都保留，界面分组展示。
SCOPE_INTERNAL = "internal"
SCOPE_EXTERNAL = "external"


def scope_of_ip(ip: Any) -> str:
    """目标 IP 属于内网还是公网（组播/链路本地/回环都算内网：它们只在本段内活动）。"""
    import ipaddress

    text = str(ip or "").strip()
    if not text:
        return SCOPE_INTERNAL
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        # 不是 IP（域名等其他形式）：保守当成内网，不把未知归到「外部」
        return SCOPE_INTERNAL
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
        return SCOPE_INTERNAL
    return SCOPE_EXTERNAL


#: 一个观测区间多少秒（界面展示「平均每区间」用）：与基线落库节奏一致，不写死。
def window_seconds() -> int:
    return max(1, int(stats_mod.params.flush_seconds()))


def request_log_types() -> frozenset[str]:
    """哪些日志类型算「一次请求」（默认 http,dns）。改成空串即不记请求数。"""
    raw = str(getattr(settings, "asset_request_log_types", "") or "")
    return frozenset(part.strip().lower() for part in raw.split(",") if part.strip())


def max_uids() -> int:
    """单个观测区间内最多保留多少条连接记录（内存保护，0 = 不限制）。"""
    return max(0, int(getattr(settings, "asset_max_uids", 0) or 0))


def asset_key(entry: UnifiedLog) -> str:
    """单条事件的资产标识：hostname 优先，无则 `IP:端口`；拿不到目的地址返回空串。

    只用于「这条事件落在哪个资产上」的判断（单条事件视角）；**窗口定稿**用的是
    `finalize()` —— 那里能把同一连接里 `conn` 的 `IP:端口` 与 `http/ssl` 的 hostname 合成一个身份。
    """
    host = str(entry.hostname or "").strip().lower()
    if host:
        return host[:200]
    ip = str(entry.dst_ip or "").strip()
    if not ip:
        return ""
    port = entry.dst_port
    return f"{ip}:{port}" if port else ip


def _target_of(entry: UnifiedLog) -> str:
    """目标标识：HTTP 用路径，DNS 用查询名（其它类型没有可比的“目标”，返回空串）。"""
    path = str(entry.uri_path or "").strip()
    if path:
        return path[:200]
    query = str(entry.query or "").strip()
    return query[:200]


# ---------- 窗口内：按连接（uid）累计 ----------


def observe_entry(records: dict[str, dict[str, Any]], entry: UnifiedLog) -> int:
    """把一条事件并进**它所属连接**的记录。无 I/O，引擎逐条调用。

    返回值：``1`` = 新开一条连接记录（计入「观测」）、``0`` = 并进已有连接、
    ``-1`` = 该事件不进基线（没有 `uid`，或连接数已达 `ST_ASSET_MAX_UIDS` 上限）。

    一条连接的身份是**逐步补全**的（与事件到达顺序无关）：`conn` 先到就先记 `IP:端口`，
    `http/ssl` 到了再把 hostname 补上；最终身份在 `finalize()` 里定。
    """
    uid = str(getattr(entry, "uid", "") or "").strip()
    if not uid:
        return -1
    record = records.get(uid)
    if record is None:
        cap = max_uids()
        if cap and len(records) >= cap:
            return -1
        record = records[uid] = {
            "hostname": "",
            "ip": "",
            "port": None,
            # 客户端：**真实客户端是一组**，不是一个 —— WAF/反代的一条长连接会复用/承载很多个
            # 客户端（实测 `www.example.com` 近 5 分钟：206 个请求只走了 11 条连接，而 XFF 里
            # 有 112 个不同真实客户端）。只记一个会把「不同客户端数」恒压成 1。
            "clients_real": set(),
            "client_src": "",
            "client_port": None,
            "targets": set(),
            "requests": 0,
        }
        fresh = 1
    else:
        fresh = 0
    # 身份：hostname 最强（Host/SNI），拿到就一直用；`IP:端口` 只是回落候选
    host = str(entry.hostname or "").strip().lower()
    if host and not record["hostname"]:
        record["hostname"] = host[:200]
    if not record["ip"]:
        record["ip"] = str(entry.dst_ip or "").strip()
        record["port"] = entry.dst_port or None
    # 客户端：优先 real_client_ip（中继链路上 src 是代理），没有才用 src_ip；
    # real_client_ip 收进集合（一条连接上可能有很多个真实客户端）
    real = str(entry.real_client_ip or "").strip()
    if real and len(record["clients_real"]) < _SET_LIMIT:
        record["clients_real"].add(real[:64])
    src = str(entry.src_ip or "").strip()
    if src and not record["client_src"]:
        record["client_src"] = src[:64]
    if record["client_port"] is None and entry.src_port:
        record["client_port"] = int(entry.src_port)
    target = _target_of(entry)
    if target and len(record["targets"]) < _SET_LIMIT:
        record["targets"].add(target)
    if str(entry.log_type or "").strip().lower() in request_log_types():
        record["requests"] += 1
    return fresh


def finalize(records: dict[str, dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], int]:
    """把窗口内的连接记录定稿成「每个资产一份计数」。返回 ``(资产桶, 丢弃的连接数)``。

    - 身份：有 hostname 用 hostname，否则回落 `IP:端口`；
    - **纯连接不算被访问方**（2026-10 实机修正，见下）：既无 Host/SNI、又一条请求都没有的连接
      （只有 `conn`/`weird`/`files`）直接丢弃 —— 否则资产表会被「收到过连接的目标 IP:高位端口」
      灌满：实测 95,443 个资产里 94,642 个是 `IP:端口`，其中 **48,971 个端口 ≥32768**
      （P2P/IM/客户端侧高位端口，如 `10.1.2.66:53650` 只有 305 条 conn、零请求）；
      反过来真正带 Host 的站点只有一两千个。界面上的「资产数」因此虚高几十倍。
      这个基线的特征是「请求数 / 不同 URI / 不同客户端」，只有请求类连接才算得出来。
    - 一条连接都没有可用的身份（既无 Host/SNI 也无目的地址）→ 丢弃；
    - **中继自身不作为资产**（端口 53 除外）：前跳的 dst 就是中继，非 HTTP 流量没有 Host/SNI，
      身份会落到它身上 —— 按端口判而不是按「检测器推算的角色」判，免得依赖角色回写的时序。
    """
    out: dict[str, dict[str, Any]] = {}
    dropped = 0
    for record in records.values():
        host = str(record.get("hostname") or "")
        ip = str(record.get("ip") or "")
        port = record.get("port")
        key = host or (f"{ip}:{port}" if port else ip)
        if not key:
            dropped += 1
            continue
        if not host and not int(record.get("requests") or 0):
            # 无域名 + 零请求 = 只是「有过一条 TCP 连接」，不是被访问方
            dropped += 1
            continue
        if not host and ip and port != _DNS_PORT and relay_nodes.is_relay(ip):
            dropped += 1
            continue
        bucket = out.get(key)
        if bucket is None:
            bucket = out[key] = {
                "visits": 0,
                "requests": 0,
                "clients": set(),
                "client_ports": set(),
                "targets": set(),
                # 归属：同一身份出现内网与外网两种 IP 时（CDN/双线）算内网（宁可对内判，不漏）
                "scope": SCOPE_EXTERNAL if ip else SCOPE_INTERNAL,
            }
        if scope_of_ip(ip) == SCOPE_INTERNAL:
            bucket["scope"] = SCOPE_INTERNAL
        bucket["visits"] += 1
        bucket["requests"] += int(record.get("requests") or 0)
        # 真实客户端优先（有不只一个就是一组）；一个都没有才回落连接的 src
        real_clients = record.get("clients_real") or set()
        fallback = str(record.get("client_src") or "")
        for client in real_clients if real_clients else ([fallback] if fallback else []):
            if len(bucket["clients"]) >= _SET_LIMIT:
                break
            bucket["clients"].add(client)
        client_port = record.get("client_port")
        if client_port and len(bucket["client_ports"]) < _SET_LIMIT:
            bucket["client_ports"].add(client_port)
        for target in record.get("targets") or ():
            if len(bucket["targets"]) >= _SET_LIMIT:
                break
            bucket["targets"].add(target)
    return out, dropped


def window_values(buckets: dict[str, dict[str, Any]]) -> dict[str, list[float]]:
    """把本窗口各资产的计数转成 Welford 样本（每资产每特征一个样本）。

    口径：一个聚合窗口 = 一个观测点。所以 `visits` 的均值就是「平均每窗口被访问多少条连接」，
    标准差是「窗口间波动」—— 与数值基线一致（那边的 conn_count 也是窗口值）。
    """
    out: dict[str, list[float]] = {}
    for key, bucket in buckets.items():
        out[f"{key}:visits"] = [float(bucket.get("visits") or 0)]
        out[f"{key}:requests"] = [float(bucket.get("requests") or 0)]
        out[f"{key}:distinct_clients"] = [float(len(bucket.get("clients") or ()))]
        out[f"{key}:distinct_client_ports"] = [float(len(bucket.get("client_ports") or ()))]
        out[f"{key}:distinct_targets"] = [float(len(bucket.get("targets") or ()))]
    return out


def apply_window(buckets: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """把一个窗口的观测落进 `asset_stats`（复用数值基线那套 Welford）。

    Welford 那层按 key 写均值/方差，不认归属；`scope` 通过 `attrs` 跟 `:visits` 行
    一起写进同一会话（口径换代后重学时也会重新写上），不另开连接。
    """
    values = window_values(buckets)
    if not values:
        return {}
    return stats_mod.apply_stats(values, model=AssetStat, attrs=_scope_attrs(buckets))


def _scope_attrs(buckets: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """把每个资产的归属写到它的 `:visits` 行。"""
    return {
        f"{key}:visits": {"scope": str(bucket.get("scope") or SCOPE_INTERNAL)}
        for key, bucket in buckets.items()
        if key
    }


def refresh_scopes() -> int:
    """把 `scope` 为空/非法的资产行按**当前网段口径**重算（自愈），返回修正行数。

    为什么需要：`scope` 列是口径 C 后加的 —— 加列那一刻起，**只有再次被观测到的资产**
    才会写入 scope。实测某环境 6,480 行里 5,184 行（80%）还是空串，界面「共 N 个资产
    （内网 X / 外部 Y）」对不上 N，按归属筛也筛不到这些老资产。
    清理任务每小时调一次，一小时内全库对齐（不活跃的旧资产也能修好）。

    只处理能从资产标识里解析出 IP 的行（`IP:端口`）；hostname 类资产无从判定归属，跳过。
    """
    fixed = 0
    try:
        with SessionLocal() as db:
            rows = db.scalars(
                select(AssetStat).where(
                    or_(AssetStat.scope == "", AssetStat.scope.is_(None))
                )
            ).all()
            for row in rows:
                asset, feature = _split(row.key)
                if not feature:
                    continue
                candidate = asset.rpartition(":")[0] or asset
                try:
                    ipaddress.ip_address(candidate)
                except ValueError:
                    continue  # hostname 资产：判不了归属，保持原样
                scope = scope_of_ip(candidate)
                if row.scope != scope:
                    row.scope = scope
                    fixed += 1
            if fixed:
                db.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("重算资产归属失败: %s", exc)
    return fixed


def cleanup(retention_days: int | None = None) -> dict[str, int]:
    """按 `updated_at` 清理长期没更新的资产基线；顺手把归属为空的老行按当前口径重算。"""
    # 自愈放在清理里：每小时一次，全库一小时内对齐（口径改了之后老数据不会永久错着）
    fixed = refresh_scopes()
    result = stats_mod.cleanup(retention_days, model=AssetStat)
    if fixed:
        result = {**result, "scope_fixed": fixed}
    return result


# ---------- 读：给界面用 ----------


def _split(key: str) -> tuple[str, str]:
    """`{资产}:{特征}` → (资产, 特征)。资产里可能有冒号（`IP:端口`），所以从右切一次。"""
    asset, _, feature = str(key).rpartition(":")
    return (asset or str(key)), feature


def role_of(asset: str) -> str:
    """粗粒度角色：端口 53 → `dns`，其余 → `site`。只用于界面可读，不参与判定。"""
    _, _, port = asset.rpartition(":")
    return "dns" if port == str(_DNS_PORT) else "site"


def state_of(row: Any, now: datetime) -> str:
    """`生效中`（过观测期，可判偏离）/ `观测中`。"""
    return "ready" if stats_mod._warmed(getattr(row, "first_seen", None), now) else "learning"


def list_assets(
    *, q: str = "", sort: str = "visits", limit: int = 50, offset: int = 0, scope: str = ""
) -> dict[str, Any]:
    """资产列表（分页）。

    以 `:visits` 那一行为“主线”（每个资产必有），按它的**均值**排序（= 平均每窗口被访问次数），
    再把这批资产的其它特征一起取出来。`q` 匹配资产标识子串。

    `scope`：`internal`（内网被访问方，**异常判定只看这一块**）/ `external`（公网目标，含公共 DNS）；
    留空 = 全部（界面分组展示用）。返回里同时给两块的数量，免得前端再发两次请求。
    """
    cap = max(1, min(int(limit or 50), 500))
    start = max(0, int(offset or 0))
    now = datetime.now(UTC)
    visits_like = "%:visits"
    conds: list[Any] = [AssetStat.key.like(visits_like)]
    if (q or "").strip():
        conds.append(AssetStat.key.like(stats_mod.like_pattern(q), escape="\\"))
    wanted = str(scope or "").strip().lower()
    if wanted in (SCOPE_INTERNAL, SCOPE_EXTERNAL):
        conds.append(AssetStat.scope == wanted)
    order = AssetStat.mean.desc() if (sort or "visits").strip() != "asset" else AssetStat.key.asc()
    try:
        with SessionLocal() as db:
            total = int(db.scalar(select(func.count()).select_from(AssetStat).where(*conds)) or 0)
            by_scope = {
                str(k or ""): int(n)
                for k, n in db.execute(
                    select(AssetStat.scope, func.count())
                    .where(AssetStat.key.like(visits_like))
                    .group_by(AssetStat.scope)
                ).all()
            }
            rows = db.scalars(
                select(AssetStat).where(*conds).order_by(order).limit(cap).offset(start)
            ).all()
            assets = [_split(row.key)[0] for row in rows]
            keys = [f"{asset}:{feature}" for asset in assets for feature in FEATURES]
            detail_rows = (
                list(db.scalars(select(AssetStat).where(AssetStat.key.in_(keys))).all())
                if keys
                else []
            )
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读被访问方基线失败：{exc}", "total": 0, "items": []}
    per_asset: dict[str, dict[str, Any]] = {}
    for row in detail_rows:
        asset, feature = _split(row.key)
        per_asset.setdefault(asset, {})[feature] = row
    items: list[dict[str, Any]] = []
    for asset in assets:
        features = per_asset.get(asset) or {}
        visits = features.get("visits")
        if visits is None:
            continue
        items.append(
            {
                "asset": asset,
                "role": role_of(asset),
                "state": state_of(visits, now),
                "windows": int(visits.count or 0),
                "first_seen": visits.first_seen.isoformat() if visits.first_seen else "",
                "visits_mean": visits.mean,
                # internal（内网被访问方） / external（公网目标）：界面分组、异常判定只看 internal
                "scope": str(getattr(visits, "scope", "") or SCOPE_INTERNAL),
                "requests_mean": (
                    features["requests"].mean if features.get("requests") is not None else 0.0
                ),
                "clients_mean": (features.get("distinct_clients") or visits).mean,
                "targets_mean": (features.get("distinct_targets") or visits).mean,
                "window_seconds": window_seconds(),
            }
        )
    return {
        "total": total,
        "returned": len(items),
        "items": items,
        # 按归属的数量（口径 C）：界面直接用它渲染「内网 / 外部」两个分组
        "by_scope": {
            "internal": int(by_scope.get(SCOPE_INTERNAL, 0)),
            "external": int(by_scope.get(SCOPE_EXTERNAL, 0)),
            "unknown": int(
                sum(n for k, n in by_scope.items() if k not in (SCOPE_INTERNAL, SCOPE_EXTERNAL))
            ),
        },
        "window_seconds": window_seconds(),
    }


def asset_detail(asset: str) -> dict[str, Any]:
    """单个资产的全部特征明细（均值/标准差/观测次数/是否生效）。"""
    target = str(asset or "").strip()
    if not target:
        return {"error": "缺少资产标识"}
    now = datetime.now(UTC)
    keys = [f"{target}:{feature}" for feature in FEATURES]
    try:
        with SessionLocal() as db:
            rows = list(db.scalars(select(AssetStat).where(AssetStat.key.in_(keys))).all())
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读被访问方基线失败：{exc}", "asset": target, "items": []}
    items = [{"feature": _split(row.key)[1], **stats_mod._state(row, now)} for row in rows]
    items.sort(key=lambda item: item["feature"])
    return {
        "asset": target,
        "role": role_of(target),
        "observe_days": stats_mod.params.observe_days(),
        "window_seconds": window_seconds(),
        "items": items,
    }


def snapshot() -> dict[str, Any]:
    """给「行为分析」页顶部用的规模概览：资产数 + 观测中/生效中。"""
    now = datetime.now(UTC)
    days = max(0, int(stats_mod.params.observe_days()))
    cut = now - timedelta(days=days)
    try:
        with SessionLocal() as db:
            total = int(
                db.scalar(
                    select(func.count())
                    .select_from(AssetStat)
                    .where(AssetStat.key.like("%:visits"))
                )
                or 0
            )
            ready = int(
                db.scalar(
                    select(func.count())
                    .select_from(AssetStat)
                    .where(
                        AssetStat.key.like("%:visits"),
                        AssetStat.first_seen.is_not(None),
                        AssetStat.first_seen <= cut,
                    )
                )
                or 0
            )
            by_scope = {
                str(k or ""): int(n)
                for k, n in db.execute(
                    select(AssetStat.scope, func.count())
                    .where(AssetStat.key.like("%:visits"))
                    .group_by(AssetStat.scope)
                ).all()
            }
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读被访问方基线失败：{exc}", "total_assets": 0}
    return {
        "total_assets": total,
        "ready_assets": ready,
        "learning_assets": max(0, total - ready),
        # 分归属计数（口径 C）：内网被访问方是异常判定的对象，外部目标（含公共 DNS）只展示
        "internal_assets": int(by_scope.get(SCOPE_INTERNAL, 0)),
        "external_assets": int(by_scope.get(SCOPE_EXTERNAL, 0)),
        "scope_unknown_assets": int(
            sum(n for k, n in by_scope.items() if k not in (SCOPE_INTERNAL, SCOPE_EXTERNAL))
        ),
        "observe_days": days,
        "window_seconds": window_seconds(),
        "checked_at": now.isoformat(),
    }
