"""检测器历史采样：把每轮统计快照存成**有界列表**，供「总览」页画 24 小时趋势。

为什么需要它：`shentong:detector:rates` 每次都是 `HSET` **覆盖**，只留最新一份快照，
界面想要「随时间变化」就必须有人在旁边留历史。采样挂在检测器**已有**的统计块里
（每 `detector_stats_log_seconds`，默认 300s 一轮），不新增循环、不新增进程。

有界方式与 `handled` 注册表同一个思路（那次 1677 万成员撑爆 Redis 的教训）：
`LPUSH` + `LTRIM` 固定条数（默认 288 条 = 24h @ 5min），再挂一个 7 天 `EXPIRE` 兜底。

失败语义：这是**旁路**。Redis 不可用只记 debug，绝不影响检测主循环（与
`detector/health.py` 的 fail-open 风格一致）。
"""

from __future__ import annotations

import json
from typing import Any

from app.workers.log import get_logger

log = get_logger(__name__)

#: 本区间「按规则」计数在计数器里的键前缀。**用后即清**（见 `extract_interval_rules`），
#: 否则会变成「自进程启动以来」的累计，规则 TOP 就永远只反映历史。
RULE_PREFIX = "digest_rule_"
#: 按严重度的**累计**计数器前缀；区间增量走 `rate_prev`（与 `d_scanned` 同一套机制）。
SEV_PREFIX = "digest_sev_"
#: 摘要的严重度取值（与 `Rule.severity` 一致）；不认识的归 info。
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

#: 历史键的 TTL 兜底（正常靠 LTRIM 界，这个只在 LTRIM 没跑到时兜住）
_HISTORY_TTL_SECONDS = 7 * 24 * 3600


def sev_counter_key(severity: Any) -> str:
    """摘要严重度 → 累计计数器键（不认识的归 info）。"""
    sev = str(severity or "").strip().lower()
    return f"{SEV_PREFIX}{sev if sev in SEVERITIES else 'info'}"


def mark_digest(stats: Any, digest: dict[str, Any]) -> None:
    """摘要入投递队列时记一笔：按严重度累计 + 按规则记本区间数。

    `stats` 是检测器的 `Counter[str]`：额外键不会影响统计日志（日志只打印具名键），
    与既有 `stats["digest"] += 1` 同一处调用。
    """
    stats[sev_counter_key(digest.get("rule_severity"))] += 1
    rule = str(digest.get("rule") or "").strip()
    if rule:
        stats[f"{RULE_PREFIX}{rule}"] += 1


def extract_interval_rules(stats: Any, prefix: str = RULE_PREFIX) -> dict[str, int]:
    """抽走本区间的「按规则」计数并清键，返回 `{规则名: 条数}`。

    只保留条数 > 0 的项；规则名里可能带 `|`、空格等，前缀切掉即可（键唯一）。
    """
    out: dict[str, int] = {}
    for key in [k for k in list(stats) if isinstance(k, str) and k.startswith(prefix)]:
        try:
            count = int(stats.pop(key) or 0)
        except (TypeError, ValueError):
            continue
        name = key[len(prefix) :]
        if name and count > 0:
            out[name] = count
    return out


def severity_deltas(stats: Any, prev: dict[str, float]) -> dict[str, float]:
    """按严重度的区间增量（键形如 `d_digest_sev_high`），并同步更新 `prev`。"""
    out: dict[str, float] = {}
    for sev in SEVERITIES:
        key = f"{SEV_PREFIX}{sev}"
        now = float(stats[key] or 0)
        out[f"d_{key}"] = max(0.0, now - float(prev.get(key) or 0.0))
        prev[key] = now
    return out


def append(
    client: Any,
    sample: dict[str, Any],
    *,
    key: str,
    max_items: int,
    ttl_seconds: int = _HISTORY_TTL_SECONDS,
) -> bool:
    """追加一条采样（LPUSH + LTRIM + EXPIRE）。成功返回 True；失败只记 debug。"""
    if not key or max_items <= 0:
        return False
    try:
        payload = json.dumps(sample, ensure_ascii=False, default=str)
        client.lpush(key, payload)
        client.ltrim(key, 0, max_items - 1)
        client.expire(key, max(1, int(ttl_seconds)))
        return True
    except Exception as exc:  # noqa: BLE001
        log.debug("写入检测器历史采样失败（不影响检测）: %s", exc)
        return False


def read(client: Any, *, key: str, limit: int) -> list[dict[str, Any]]:
    """读历史采样，**时间正序**返回（最旧在前，直接喂图表）。

    坏 JSON / 非 dict 的行跳过（不因为一行脏数据让整张图挂掉）；Redis 出错返回空表。
    """
    if not key or limit <= 0:
        return []
    try:
        raw_items = client.lrange(key, 0, max(0, int(limit) - 1))
    except Exception as exc:  # noqa: BLE001
        log.debug("读取检测器历史采样失败: %s", exc)
        return []
    if not isinstance(raw_items, list):
        return []
    out: list[dict[str, Any]] = []
    for raw in raw_items:
        try:
            item = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if isinstance(item, dict):
            out.append(item)
    out.reverse()  # LPUSH 是新的在前 → 反转成时间正序
    return out
