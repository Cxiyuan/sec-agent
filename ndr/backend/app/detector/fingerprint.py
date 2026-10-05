"""摘要判据：年龄 + 指纹（检测器与智能体两端共用同一套算法）。

**为什么单独一个模块**：这两个判据原来长在查库去重闸门 ``analyzed.py`` 里（该闸门已于 2026 第 5 期退役并删除）。
第 5 期把「已分析过没有」的判重下放到智能体侧接收端点，NDR 侧那份闸门退役，
但**摘要指纹仍然要算**（推送载荷里带指纹、超龄摘要仍要丢），所以判据从闸门里搬出来，
不再随闸门一起消失。

- ``digest_age``：超龄摘要在投递前丢弃（并落丢弃计数），任务侧再查一次
  （Celery ``acks_late`` 重投会绕过投递侧检查）。
- ``digest_fingerprint``：检测器侧与 worker 侧对同一批摘要必须算出同一个指纹，
  所以两侧都 import 这个函数（agent 侧是 ``app.digest``，两侧口径逐字节一致）。
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from app.config import settings


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

    这个判据被两处使用（缺一不可）：
    - **投递侧**（detector.runner._flush）：超龄摘要在投递前丢弃，并落丢弃计数；
    - **任务侧**（workers.tasks.analyze_digests）：再次把关。
      为什么任务侧也要查：Celery 开了 ``acks_late``，worker 被杀死（发布重启、OOM、超时）
      时 broker 会把**同一个任务消息原样重投**，里面带着当初那批摘要 —— 这条路径完全
      绕过了投递侧的检查。部署实测：11:00 的摘要在 14:09 被重新分析，产出窗口很旧的事件组。
    """
    seen = _parse_dt(digest.get("last_seen"))
    if seen is None:
        return 0.0
    current = now or datetime.now(UTC)
    return max(0.0, (current - seen).total_seconds())


def bucket_start_of(first_seen: Any) -> datetime | None:
    """摘要归属的时间桶起点（与事件组指纹同一起点、同桶宽）。"""
    ts = _parse_dt(first_seen)
    if ts is None:
        return None
    bucket_minutes = max(1, int(settings.group_bucket_minutes or 30))
    minutes = int(ts.timestamp() // 60)
    return datetime.fromtimestamp((minutes // bucket_minutes) * bucket_minutes * 60, tz=UTC)


def digest_fingerprint(digest: dict[str, Any]) -> str | None:
    """摘要指纹：sha256("{规则}|{源IP}|{桶起点}|{目标}|{端口}|{事件类型}")[:32]；信息不全返回 None。

    为什么是摘要级而不是事件/组级：检测器手里只有摘要（规则/源IP/次数/样例/首末时间），
    组级指纹是"IP 簇 + 桶"，检测器无法复现；worker 侧用同一函数对同一批摘要复算，
    两边必然一致。
    """
    rule = str(digest.get("rule") or "").strip()
    bucket = bucket_start_of(digest.get("first_seen"))
    if not rule or bucket is None:
        return None
    src_ip = str(digest.get("src_ip") or "-").strip()
    # 指纹必须描述"同一个事件"，而不是"同一个源+规则"：
    # 原来只有 rule|src|时间桶 → 同一台源机在 30 分钟桶内换了目标/端口也算重复，
    # 后续真正的新行为（打新目标、摸新端口）会被整段去重 = 漏报。
    # 现在纳入 目标集合 + 端口集合 + 事件类型：完全相同才视为重复（按窗口去重、只留计数）；
    # 出现新目标/新端口/新类型 → 指纹不同 → 照旧进智能体分析。
    dsts = ",".join(sorted(str(x) for x in (digest.get("dst_ips") or []))[:20])
    ports = ",".join(
        sorted({str(p) for p in (digest.get("dst_ports") or []) if p is not None})[:20]
    )
    etypes = ",".join(sorted(str(x) for x in (digest.get("event_types") or []))[:10])
    raw = f"{rule}|{src_ip}|{int(bucket.timestamp())}|{dsts}|{ports}|{etypes}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]
