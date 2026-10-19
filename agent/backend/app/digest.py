"""摘要判据：年龄（契约副本，与 ndr 侧 detector/fingerprint.py 的 digest_age 一致）+ 事件组指纹。

任务侧（analyze_digests）做「超龄过滤」把关：投递侧已有同样检查，但消费进程
被杀重投时同一批摘要会原样再进，必须在这里再拦一次，否则产出窗口很旧的事件组。

事件组指纹（``group_fingerprint``）原来是 ``agents/nodes.py`` 的私有函数；第 5 期改成
「摘要经 HTTP 推送进来」后，**接收端点要在跑图之前就判重**，所以指纹算法挪到这里
（轻量模块，不拖 agents 那一大坨 import），``nodes._group_fingerprint`` 转发调用，
两侧共用同一份实现 —— 判重算出来的指纹必须和图里落库的指纹**逐字节一致**，
否则每推一次都会新建一个组。
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

#: 等价于 3.11 的 `datetime.UTC`（本仓库 requires-python >=3.11）；用别名写法
#: 免得按旧语法解析的静态检查工具报「unknown import symbol」。
UTC = timezone.utc


def _safe_int(value: Any, default: int) -> int:
    """宽松转 int（None / 脏字符串回默认值）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_dt(value: Any) -> datetime | None:
    """宽松解析 ISO 时间（失败返回 None）。"""
    if isinstance(value, datetime):
        parsed = value
    else:
        raw = str(value or "").strip()
        if not raw:
            return None
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def digest_age(digest: dict[str, Any], *, now: datetime | None = None) -> float:
    """摘要「存了多久」（秒）：取 last_seen（事件时间），解析失败按 0（视为新鲜）。

    为什么解析失败要当新鲜：解析不出来就丢掉会**静默漏分析**；宁可多分析一条。
    """
    seen = _parse_dt(digest.get("last_seen"))
    if seen is None:
        return 0.0
    current = now or datetime.now(UTC)
    return max(0.0, (current - seen).total_seconds())


def bucket_minutes() -> int:
    """事件组时间桶宽（分钟，``ST_GROUP_BUCKET_MINUTES``，与检测器摘要指纹共用）。"""
    from app.config import settings

    return max(1, _safe_int(settings.group_bucket_minutes, 30))


def time_bucket(start: datetime) -> int:
    """时间桶序号（自 epoch 起的分钟数整除桶宽）。"""
    minutes = _safe_int(start.timestamp() // 60, 0)
    return (minutes // bucket_minutes()) * bucket_minutes()


def group_fingerprint(ips: set[str], start: datetime, excluded: bool = False) -> str:
    """事件组指纹：IP 集合 + **时间桶**（默认 30 分钟，见 ``group_bucket_minutes``）。

    原来按“分钟”取整 → 持续攻击每个窗口/每批都会生成新组与新报告（界面被刷屏）。
    改为按可配时间桶：同一对象在桶内复用同一个组（事件累加、窗口前移）。

    excluded=True 走独立命名空间：被排除的事件不能和正常事件合并成同一个组，
    否则整组会被拉去跑模型，“跳过模型”就失效了。

    注意 ``start`` 的口径：图里传的是**本批任务的开工时间**（``analyze_digests`` 的
    ``window_start = now``），不是事件时间；推送接收端点判重时也必须用「现在」，
    否则和落库那条算不到一个桶里去。
    """
    key = ("ex|" if excluded else "") + "|".join(sorted(ips)) + "|" + str(time_bucket(start))
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def digest_ips(digest: dict[str, Any]) -> set[str]:
    """摘要涉及的 IP 集合（源 + 全部目的），供判重算指纹用。

    与图里 ``_build_groups`` 的口径一致：那边是对 ``ev.log.src_ip`` / ``ev.log.dst_ip``
    做并集，摘要侧就是 ``src_ip`` + ``dst_ips``。
    """
    ips: set[str] = set()
    src = str(digest.get("src_ip") or "").strip()
    if src:
        ips.add(src)
    dsts = digest.get("dst_ips") or []
    if isinstance(dsts, str):
        dsts = [dsts]
    for dst in dsts:
        text = str(dst or "").strip()
        if text:
            ips.add(text)
    return ips
