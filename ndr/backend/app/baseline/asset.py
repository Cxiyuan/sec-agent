"""被访问方（内网源站 / 内网 DNS 转发器）的行为基线。

**为什么要有它**（用户 2026-10 选定的方案 A）：数值基线是按**源 IP（发起方）**建的，所以
「服务器被访问」这件事在现有基线里没有归属 —— 外网打内网服务器时，事件都记在**客户端**
那一侧，服务器本身没有基线，看不出「今天被 200 个不同外网 IP 访问、平时只有 5 个」。

**建什么**：按**被访问方**记四个特征，用同一套 Welford + 观测期 + zσ 判规模偏离 ——
- `visits`：被访问次数
- `distinct_clients`：不同真实客户端数（中继链路上取 `real_client_ip or src_ip`）
- `distinct_client_ports`：不同客户端源端口数
- `distinct_targets`：不同目标数（HTTP=URI、DNS=域名）

**资产标识**：`hostname` 优先（HTTP 的 Host / SSL 的 SNI —— 中继场景下**前跳也带 Host/SNI**，
所以经代理的访问同样能归到站点上）；没有 hostname 时回落 `IP:端口`
（内网 DNS 转发器就是 `10.0.0.53:53`）。

**与中继去重的关系**：去重已在检测器入口完成（后跳不进检测），所以这一层看到的就是
「一次业务访问一条」，不需要再处理前跳/后跳。

**v1 只展示与标记，不写进摘要标签**：判据还没在真实流量上校准，先看数据、再决定要不要标签化。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select

from app.baseline import stats as stats_mod
from app.db.base import SessionLocal
from app.db.models import AssetStat
from app.schemas import UnifiedLog
from app.workers.log import get_logger

log = get_logger(__name__)

#: 特征名（key = f"{资产}:{特征}"，读回来用 rsplit(":", 1) 切 —— 资产里可能有冒号，如 `IP:端口`）
FEATURES: tuple[str, ...] = (
    "visits",
    "distinct_clients",
    "distinct_client_ports",
    "distinct_targets",
)
#: 窗口内每个集合保留多少成员（内存优先；只影响「不同 X 数」的上限）
_SET_LIMIT = 200


#: 一个观测区间多少秒（界面展示「平均每区间」用）：与基线落库节奏一致，不写死。
def window_seconds() -> int:
    return max(1, int(stats_mod.params.flush_seconds()))


#: DNS 端口：用来给资产标一个粗粒度角色（站点 / DNS 服务），只为界面可读，不参与判定
_DNS_PORT = 53


def asset_key(entry: UnifiedLog) -> str:
    """资产标识：hostname 优先，无则 `IP:端口`；拿不到目的地址返回空串（不建基线）。"""
    host = str(entry.hostname or "").strip().lower()
    if host:
        return host[:200]
    ip = str(entry.dst_ip or "").strip()
    if not ip:
        return ""
    port = entry.dst_port
    return f"{ip}:{port}" if port else ip


def _client_of(entry: UnifiedLog) -> str:
    return str(entry.real_client_ip or entry.src_ip or "").strip()


def _target_of(entry: UnifiedLog) -> str:
    """目标标识：HTTP 用路径，DNS 用查询名（其它类型没有可比的“目标”，返回空串）。"""
    path = str(entry.uri_path or "").strip()
    if path:
        return path[:200]
    query = str(entry.query or "").strip()
    return query[:200]


def observe_entry(buckets: dict[str, dict[str, Any]], entry: UnifiedLog) -> int:
    """把一条事件并进「被访问方」观测桶（返回 0/1：并入的资产数）。无 I/O，引擎逐条调用。"""
    key = asset_key(entry)
    if not key:
        return 0
    bucket = buckets.get(key)
    if bucket is None:
        bucket = buckets[key] = {
            "visits": 0,
            "clients": set(),
            "client_ports": set(),
            "targets": set(),
        }
    bucket["visits"] += 1
    client = _client_of(entry)
    if client and len(bucket["clients"]) < _SET_LIMIT:
        bucket["clients"].add(client)
    if entry.src_port and len(bucket["client_ports"]) < _SET_LIMIT:
        bucket["client_ports"].add(int(entry.src_port))
    target = _target_of(entry)
    if target and len(bucket["targets"]) < _SET_LIMIT:
        bucket["targets"].add(target)
    return 1


def window_values(buckets: dict[str, dict[str, Any]]) -> dict[str, list[float]]:
    """把本窗口各资产的计数转成 Welford 样本（每资产每特征一个样本）。

    口径：一个聚合窗口 = 一个观测点。所以 `visits` 的均值就是「平均每窗口被访问多少」，
    标准差是「窗口间波动」—— 与数值基线一致（那边的 conn_count 也是窗口值）。
    """
    out: dict[str, list[float]] = {}
    for key, bucket in buckets.items():
        out[f"{key}:visits"] = [float(bucket.get("visits") or 0)]
        out[f"{key}:distinct_clients"] = [float(len(bucket.get("clients") or ()))]
        out[f"{key}:distinct_client_ports"] = [float(len(bucket.get("client_ports") or ()))]
        out[f"{key}:distinct_targets"] = [float(len(bucket.get("targets") or ()))]
    return out


def apply_window(buckets: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """把一个窗口的观测落进 `asset_stats`（复用数值基线那套 Welford）。"""
    values = window_values(buckets)
    if not values:
        return {}
    return stats_mod.apply_stats(values, model=AssetStat)


def cleanup(retention_days: int | None = None) -> dict[str, int]:
    """按 `updated_at` 清理长期没更新的资产基线（与数值基线同一节奏与默认值）。"""
    return stats_mod.cleanup(retention_days, model=AssetStat)


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
    *, q: str = "", sort: str = "visits", limit: int = 50, offset: int = 0
) -> dict[str, Any]:
    """资产列表（分页）。

    以 `:visits` 那一行为“主线”（每个资产必有），按它的**均值**排序（= 平均每窗口被访问次数），
    再把这批资产的其它特征一起取出来。`q` 匹配资产标识子串。
    """
    cap = max(1, min(int(limit or 50), 500))
    start = max(0, int(offset or 0))
    now = datetime.now(UTC)
    visits_like = "%:visits"
    conds = [AssetStat.key.like(visits_like)]
    if (q or "").strip():
        conds.append(AssetStat.key.like(stats_mod.like_pattern(q), escape="\\"))
    order = AssetStat.mean.desc() if (sort or "visits").strip() != "asset" else AssetStat.key.asc()
    try:
        with SessionLocal() as db:
            total = int(db.scalar(select(func.count()).select_from(AssetStat).where(*conds)) or 0)
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
                "clients_mean": (features.get("distinct_clients") or visits).mean,
                "targets_mean": (features.get("distinct_targets") or visits).mean,
                "window_seconds": window_seconds(),
            }
        )
    return {
        "total": total,
        "returned": len(items),
        "items": items,
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
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读被访问方基线失败：{exc}", "total_assets": 0}
    return {
        "total_assets": total,
        "ready_assets": ready,
        "learning_assets": max(0, total - ready),
        "observe_days": days,
        "window_seconds": window_seconds(),
        "checked_at": now.isoformat(),
    }
