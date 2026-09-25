"""投递前去重闸门：按「规则|源IP|时间桶」指纹查库，已分析过的不再重复投。

为什么需要：检测器按 60 秒短窗产摘要，而事件组按 30 分钟桶复用 —— 同一
(规则, 源IP) 在桶内最多产出约 30 份摘要，每份都会跑完整 LLM 尾部
（边缘研判 → 深度分析 → 定级 → 处置 → 报告 → 记忆写入），最多重复约 30 次。
闸门把"投递"收敛到每个桶一次。

两态设计（关键，不可省）：
- inflight：投递成功、图还在跑；由检测器写
- done：图正常跑完；由 worker（tasks.analyze_digests）写

只查 done → 分析期间每批摘要照样重复投；只查 inflight → 任务失败的事件被永久吞掉。
两者共用 expires_at 作为"是否仍在拦"的判据：inflight 到期视为失败可重投，
done 到期（保留期）后由清理删除，都不需要额外的状态机。

失效策略：查库/写库异常一律 **fail-open**（视为未分析过，照常投递）——
宁可重复分析，绝不静默漏报。
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select

from app.config import settings
from app.db.base import SessionLocal
from app.db.models import AnalyzedFingerprint
from app.workers.log import get_logger

log = get_logger(__name__)


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
    """摘要指纹：sha256("{规则}|{源IP}|{桶起点}")[:32]；信息不全时返回 None（不参与去重）。

    为什么是摘要级而不是事件/组级：检测器手里只有摘要（规则/源IP/次数/样例/首末时间），
    组级指纹是"IP 簇 + 桶"，检测器无法复现；worker 侧用同一函数对同一批摘要复算，
    两边必然一致。
    """
    rule = str(digest.get("rule") or "").strip()
    bucket = bucket_start_of(digest.get("first_seen"))
    if not rule or bucket is None:
        return None
    src_ip = str(digest.get("src_ip") or "-").strip()
    raw = f"{rule}|{src_ip}|{int(bucket.timestamp())}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


class AnalyzedRegistry:
    """指纹闸门：投递前查（filter_new）、投递后登记（mark_inflight）、跑完标记（mark_done）。"""

    def __init__(self, ttl_seconds: int | None = None) -> None:
        ttl = settings.dedup_inflight_ttl_seconds if ttl_seconds is None else ttl_seconds
        self.ttl = max(60, int(ttl))
        self.retention_days = max(1, int(settings.analyzed_retention_days))

    @property
    def enabled(self) -> bool:
        return bool(settings.dedup_enabled)

    def filter_new(self, digests: list[dict[str, Any]]) -> list[tuple[dict[str, Any], str]]:
        """挑出需要投递的摘要，返回 [(摘要, 指纹)]；已分析/在途未过期的被过滤掉。

        指纹算不出来（缺规则名/首末时间）的摘要一律保留投递 —— 不能因为算不出指纹就丢事件。
        """
        pairs: list[tuple[dict[str, Any], str | None]] = [
            (d, digest_fingerprint(d)) for d in digests
        ]
        fps = [fp for _, fp in pairs if fp]
        if not self.enabled or not fps:
            return [(d, fp) for d, fp in pairs if fp]

        now = datetime.now(UTC)
        try:
            with SessionLocal() as db:
                rows = db.execute(
                    select(AnalyzedFingerprint.fingerprint).where(
                        AnalyzedFingerprint.fingerprint.in_(fps),
                        # 只需一个判据：done 的 expires_at 在保留期内、inflight 到期即失效
                        AnalyzedFingerprint.expires_at > now,
                    )
                ).all()
            known = {fp for (fp,) in rows}
        except Exception as exc:  # noqa: BLE001
            log.warning("去重查询失败，本批按“未分析过”处理（照常投递）: %s", exc)
            known = set()

        kept = [(d, fp) for d, fp in pairs if fp and fp not in known]
        if known:
            log.info("投递前去重：本批 %d 条中 %d 条已分析/在途，跳过", len(pairs), len(known))
        return kept

    def mark_inflight(self, items: list[tuple[dict[str, Any], str]]) -> None:
        """投递成功后登记"在途"（失败只告警，不影响投递结果）。"""
        if not items:
            return
        now = datetime.now(UTC)
        rows = [
            {
                "fingerprint": fp,
                "rule": str(d.get("rule") or "")[:128],
                "src_ip": str(d.get("src_ip") or "")[:64],
                "bucket_start": bucket_start_of(d.get("first_seen")),
                "status": "inflight",
                "dispatched_at": now,
                "analyzed_at": None,
                "expires_at": now + timedelta(seconds=self.ttl),
                "thread_id": None,
            }
            for d, fp in items
        ]
        self._write(rows, allow_overwrite=False)

    def mark_done(self, digests: list[dict[str, Any]], thread_id: str = "") -> None:
        """图正常跑完后标记"已分析完结"（图抛异常时不要调用）。"""
        now = datetime.now(UTC)
        rows = []
        for d in digests:
            fp = digest_fingerprint(d)
            if not fp:
                continue
            rows.append(
                {
                    "fingerprint": fp,
                    "rule": str(d.get("rule") or "")[:128],
                    "src_ip": str(d.get("src_ip") or "")[:64],
                    "bucket_start": bucket_start_of(d.get("first_seen")),
                    "status": "done",
                    "dispatched_at": now,
                    "analyzed_at": now,
                    "expires_at": now + timedelta(days=self.retention_days),
                    "thread_id": thread_id or None,
                }
            )
        self._write(rows, allow_overwrite=True)

    def _write(self, rows: list[dict[str, Any]], *, allow_overwrite: bool) -> None:
        """逐行写入（ORM 写法）：本路径量很小（每次投递几十行以内），不需要裸 upsert。

        allow_overwrite=False 时不动仍然有效的行 —— 同一指纹已是 done 的不会因为
        再次投递被降级回 inflight（否则去重会被自己解除）。
        """
        if not rows:
            return
        now = datetime.now(UTC)
        try:
            with SessionLocal() as db:
                for row in rows:
                    existing = db.get(AnalyzedFingerprint, str(row["fingerprint"]))
                    if existing is None:
                        db.add(AnalyzedFingerprint(**row))
                        continue
                    if not allow_overwrite and existing.expires_at and existing.expires_at > now:
                        continue
                    for key, value in row.items():
                        if key != "fingerprint":
                            setattr(existing, key, value)
                db.commit()
        except Exception as exc:  # noqa: BLE001
            log.warning("写入去重指纹失败（不影响分析，可能导致重复投递）: %s", exc)

    def cleanup(self) -> int:
        """删除已过期的指纹行（inflight 超时 / done 超保留期）。"""
        try:
            with SessionLocal() as db:
                rows = (
                    db.execute(
                        select(AnalyzedFingerprint).where(
                            AnalyzedFingerprint.expires_at <= datetime.now(UTC)
                        )
                    )
                    .scalars()
                    .all()
                )
                for row in rows:
                    db.delete(row)
                db.commit()
                return len(rows)
        except Exception as exc:  # noqa: BLE001
            log.warning("清理去重指纹失败: %s", exc)
            return 0

    def counts(self) -> dict[str, int]:
        """在途 / 已完结 数量（供状态接口）。"""
        try:
            now = datetime.now(UTC)
            with SessionLocal() as db:
                inflight = db.execute(
                    select(func.count())
                    .select_from(AnalyzedFingerprint)
                    .where(
                        AnalyzedFingerprint.status == "inflight",
                        AnalyzedFingerprint.expires_at > now,
                    )
                ).scalar_one()
                done = db.execute(
                    select(func.count())
                    .select_from(AnalyzedFingerprint)
                    .where(
                        AnalyzedFingerprint.status == "done",
                        AnalyzedFingerprint.expires_at > now,
                    )
                ).scalar_one()
            return {"inflight": int(inflight), "done": int(done)}
        except Exception as exc:  # noqa: BLE001
            log.warning("统计去重指纹失败: %s", exc)
            return {"inflight": 0, "done": 0}
