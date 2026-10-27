"""候选线索生成器：把"变了 / 第一次见 / 很久没看 / 规则命中"变成可领取的任务。

## 边界：这里不做威胁判断

生成器只产出**客观事实**（第几窗口偏离多少倍、是不是第一次见、多久没分析过），
判断权在智能体。所以 `hint` 里没有 severity、没有"疑似攻击"这类词。

## 性能纪律（必须遵守，否则检测热路径会被拖死）

- **每事件零 I/O**：`observe()` 只做内存累积（集合/set），落库与入队都在 `flush()`；
- 窗口级批处理：一次 `flush()` 做**一条** SELECT + **一条** UPSERT + **一条** 批量 UPDATE，
  而不是每对象一次往返（实测事件速率 ~240/秒，逐条打库会把检测器压垮）；
- 生成器整体被 `runner` 包在 `try/except` 里：任何异常只计数（`candidate_error`），
  **绝不影响检测、聚合与推送**。

## 五类线索

| kind | 来源 | 强度分量 |
|---|---|---|
| `novelty` | `observed_subjects` 首次出现（资产/服务端口/外部对端/协议/签名） | rarity + staleness |
| `shift` | 自身数值基线的计数上尾偏离（复用 `baseline` 的泊松检验） | significance + scale |
| `structure` | 失败率/单字母参数串等结构特征（默认关，需额外统计） | scale |
| `coverage` | 久未分析 / 从未分析的对象 | staleness（刻意压低，不与异常抢预算） |
| `hit` | 规则命中（`hit_events`） | 只用规模与首见，**不用 rule_severity** |
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select, tuple_

from app.analysis import cold_start as cold_start_mod, feedback, params, queue, subjects
from app.baseline import poisson
from app.db.base import SessionLocal
from app.db.models import AnalysisResult, ObservedSubject
from app.detector import suppression
from app.schemas import UnifiedLog
from app.workers.log import get_logger

#: 等价于 3.11 的 `datetime.UTC`（本仓库 requires-python >=3.11）；用别名写法
#: 免得按旧语法解析的静态检查工具报「unknown import symbol」。
UTC = timezone.utc

log = get_logger(__name__)

#: 每窗口最多登记多少个对象值（代理出口/扫描器场景下对端可能上千个，不封顶会无界增长）
_MAX_PER_KIND = 5000
#: 单窗口最多产出多少条线索（入队本身有去重，这里是第二道保险）
_MAX_ENQUEUE_PER_FLUSH = 200
#: 一次 IN 查询最多带多少个 (kind,value)（对象可达数千，分块避免超长语句）
_SELECT_CHUNK = 500

#: 结构性特征的轻量判据（默认不在 candidate_kinds 里，开着才生效）
_FAIL_RATIO = 0.6
_MIN_FAIL_EVENTS = 20


# ---------- 客观强度（纯函数，好测） ----------


def rarity_strength(seen_count: int, *, first_seen: bool) -> float:
    """第一次见 = 1.0；见得多就越不稀奇（长期高频出现的对象不该反复打扰智能体）。"""
    if first_seen:
        return 1.0
    try:
        count = max(0, int(seen_count or 0))
    except (TypeError, ValueError):
        count = 0
    if count <= 2:
        return 0.4
    return 0.1


def significance_strength(p_value: float) -> float:
    """计数上尾 p 值 → 0~1：p=1e-8 记满，p=0.01 只有 0.25。"""
    try:
        p = max(1e-12, min(1.0, float(p_value)))
    except (TypeError, ValueError):
        return 0.0
    if p >= 1.0:
        return 0.0
    return max(0.0, min(1.0, -math.log10(p) / 8.0))


def scale_strength(distinct_objects: int) -> float:
    """现象涉及的对象规模（对数归一，10 万个和 100 万个不该差 1000 倍）。"""
    count = max(0, int(distinct_objects or 0))
    if count <= 1:
        return 0.0
    return max(0.0, min(1.0, math.log10(count) / 5.0))


def combined_strength(*parts: float) -> float:
    """**取最大不求和**（求和会重演"三个弱信号 ≈ 一个强信号"的误报教训）。"""
    values = [max(0.0, min(1.0, float(p or 0))) for p in parts]
    return round(max(values) if values else 0.0, 3)


# ---------- 每窗口累积（零 I/O） ----------


class Collector:
    """按窗口累积"见过哪些对象 + 统计事实"，`flush()` 时才落库与入队。"""

    def __init__(self) -> None:
        #: kind -> set(value)
        self.seen: dict[str, set[str]] = {}
        #: (src_ip, dst_ip:port) 之类的对端计数，用于 structure 线索
        self.fail_events: dict[str, int] = {}
        self.total_events: dict[str, int] = {}
        self.window_start: float = 0.0

    def observe(self, entry: UnifiedLog) -> None:
        """每条事件调用；只往 set 里塞，不做任何数据库/网络操作。"""
        src = str(entry.src_ip or "")
        dst = str(entry.dst_ip or "")
        if src and src != "-":
            self._add(subjects.KIND_ASSET, src)
        port = entry.dst_port
        if dst and dst != "-" and port:
            # 服务 = "被谁访问的哪个端口"（新监听端口是典型的"第一次见"）
            self._add(subjects.KIND_PORT, f"{dst}:{port}")
        if str(getattr(entry, "protocol", "") or ""):
            self._add(subjects.KIND_PROTOCOL, str(entry.protocol).lower())
        sig_id = str(getattr(entry, "signature_id", "") or "")
        if sig_id:
            self._add(subjects.KIND_SIGNATURE, sig_id)
        account = str(getattr(entry, "account", "") or getattr(entry, "user", "") or "")
        if account:
            self._add(subjects.KIND_ACCOUNT, account[:160])
        # structure 用的轻量计数（默认不产出线索，开着才用）
        status = getattr(entry, "status_code", None)
        if status is not None and int(status) >= 400 and src:
            self.fail_events[src] = self.fail_events.get(src, 0) + 1
        if src:
            self.total_events[src] = self.total_events.get(src, 0) + 1

    def _add(self, kind: str, value: str) -> None:
        bucket = self.seen.setdefault(kind, set())
        if len(bucket) >= _MAX_PER_KIND:
            return
        bucket.add(value[:160])

    def reset(self) -> None:
        self.seen = {}
        self.fail_events = {}
        self.total_events = {}


# ---------- 落库与入队 ----------


def _record_seen(db: Any, rows: list[tuple[str, str]], now: datetime) -> list[tuple[str, str]]:
    """批量登记"见过"，返回其中**首次出现**的 (kind, value)。

    只用 ORM 会话接口（`scalars` / `add`），不手写任何 SQL 拼接；一次读 + 一次刷，
    新对象靠唯一索引 `(kind, value)` 兜并发重复。
    """
    if not rows:
        return []
    keys = list(dict.fromkeys(rows))
    found: dict[tuple[str, str], ObservedSubject] = {}
    for start in range(0, len(keys), _SELECT_CHUNK):
        chunk = keys[start : start + _SELECT_CHUNK]
        for row in db.scalars(
            select(ObservedSubject).where(
                tuple_(ObservedSubject.kind, ObservedSubject.value).in_(chunk)
            )
        ).all():
            found[(str(row.kind), str(row.value))] = row
    # 已见过的：只刷新"最近见到时间"与计数（覆盖率与 rarity 的数据源）
    for row in found.values():
        row.last_seen_at = now
        row.seen_count = int(row.seen_count or 0) + 1
    fresh = [kv for kv in keys if kv not in found]
    for kind, value in fresh:
        db.add(
            ObservedSubject(
                kind=kind,
                value=value[:160],
                first_seen_at=now,
                last_seen_at=now,
                seen_count=1,
                analyzed_count=0,
            )
        )
    return fresh


def _novelty_tasks(db: Any, fresh: list[tuple[str, str]], now: datetime, client: Any) -> int:
    """首见对象 → novelty 线索（强度按"多久没分析过"加成，冷门口对象更容易排上）。"""
    made = 0
    for kind, value in fresh[:_MAX_ENQUEUE_PER_FLUSH]:
        stale = subjects.staleness("asset", value, now) if kind == subjects.KIND_ASSET else 0.6
        # 套反馈系数：这个对象上同类现象被连判过误报就捐低优先级（只衰减不否决）
        strength = feedback.apply(
            combined_strength(rarity_strength(0, first_seen=True), stale), "novelty", value
        )
        # 冷启动保护：基线重学期内首见一律压到保留名额之下（见 cold_start 模块说明）
        strength = cold_start_mod.damped(strength, client)
        result = queue.enqueue(
            kind="novelty",
            subject_kind="asset" if kind == subjects.KIND_ASSET else kind,
            subject=value,
            strength=strength,
            feature=f"first:{kind}",
            hint={
                "事实": f"第一次见到该{kind}",
                "对象类型": kind,
                "距上次分析": "从未分析" if stale >= 0.9 else "近期未分析",
                "客观强度": strength,
            },
            window_start=now - timedelta(minutes=30),
            window_end=now,
            client=client,
        )
        if result in ("new", "merged"):
            made += 1
    return made


def flush(collector: Collector, client: Any, *, stats: Any = None) -> dict[str, int]:
    """窗口到期：登记对象 + 产出 novelty / structure 线索。返回各步计数。"""
    now = datetime.now(UTC)
    rows: list[tuple[str, str]] = []
    for kind, values in collector.seen.items():
        for value in values:
            rows.append((kind, value))
    out = {"seen": len(rows), "novelty": 0, "structure": 0}
    # 无论后面成功与否都要清空：这是常驻进程，累积器不清空就会无界增长
    collector.reset()
    if not rows:
        return out
    try:
        with SessionLocal() as db:
            fresh = _record_seen(db, rows, now)
            db.commit()
            out["novelty"] = _novelty_tasks(db, fresh, now, client)
    except Exception as exc:  # noqa: BLE001 — 生成线索失败绝不能影响检测
        log.warning("线索生成（首见登记）失败：%s", exc)
        queue.bump(client, "candidate_error")
        return out
    if "structure" in params.candidate_kinds():
        out["structure"] = _structure_tasks(collector, now, client)
    if stats is not None:
        try:
            stats["candidate_novelty"] = int(stats.get("candidate_novelty", 0)) + out["novelty"]
        except (TypeError, ValueError):
            pass
    return out


def _structure_tasks(collector: Collector, now: datetime, client: Any) -> int:
    """轻量结构特征：失败响应占比异常高（只给事实，不说是攻击）。"""
    made = 0
    for src, fails in collector.fail_events.items():
        total = collector.total_events.get(src, 0) or 1
        if fails < _MIN_FAIL_EVENTS or (fails / total) < _FAIL_RATIO:
            continue
        strength = feedback.apply(combined_strength(scale_strength(fails), 0.5), "structure", src)
        # 冷启动保护：结构特征也是冷启动噪声大户（大量链路第一次出现）
        strength = cold_start_mod.damped(strength, client)
        result = queue.enqueue(
            kind="structure",
            subject_kind="ip",
            subject=src,
            strength=strength,
            feature="fail_ratio",
            hint={
                "事实": f"本窗口失败响应 {fails}/{total}（占比 {fails / total:.0%}）",
                "窗口": f"{collector.window_start or ''}",
                "客观强度": strength,
            },
            window_start=now - timedelta(minutes=30),
            window_end=now,
            client=client,
        )
        if result in ("new", "merged"):
            made += 1
    return made


def enqueue_shift(deviations: list[dict[str, Any]], client: Any) -> int:
    """自身基线偏离 → `shift` 线索（由 `baseline` 的计数上尾检验产出）。"""
    made = 0
    now = datetime.now(UTC)
    for item in deviations[:_MAX_ENQUEUE_PER_FLUSH]:
        src = str(item.get("src_ip") or "")
        feature = str(item.get("feature") or "")
        if not src or not feature:
            continue
        p_value = float(item.get("p") or 1.0)
        strength = feedback.apply(
            combined_strength(
                significance_strength(p_value),
                scale_strength(int(item.get("value") or 0)),
                subjects.staleness("ip", src, now),
            ),
            "shift",
            src,
        )
        result = queue.enqueue(
            kind="shift",
            subject_kind="ip",
            subject=src,
            strength=strength,
            feature=feature,
            hint={
                "事实": f"{feature} 本窗口={item.get('value')}，历史均值={item.get('mean')}",
                "上尾概率": item.get("p"),
                "显著性阈值": item.get("alpha"),
                "方差": item.get("var"),
                "是否用了网段先验": bool(item.get("pooled_with")),
                "客观强度": strength,
            },
            window_start=now - timedelta(minutes=30),
            window_end=now,
            client=client,
        )
        if result in ("new", "merged"):
            made += 1
    return made


def _hit_hint(
    digest: dict[str, Any], rule: str, event_id: str, strength: float, distinct_dst: int
) -> dict[str, Any]:
    """命中线索的 hint：在客观事实之外补上"省一次查询"的元数据。

    全部是**客观字段**——绝不带 `rule_severity`（严重度判断权在智能体，
    与 candidates 模块顶部的边界一致）。中继链路提示很值钱：代理后面的"在扫内网"
    经常是外部流量转发，agent 拿到就能少跑一轮方向判定。
    """
    hint: dict[str, Any] = {
        "事实": f"规则「{rule}」命中 {digest.get('count')} 次，目的 {distinct_dst} 个",
        "事件ID": event_id,
        "客观强度": strength,
    }
    source_label = _hits_source_label(str(digest.get("rule_source") or ""))
    if source_label:
        hint["命中来源"] = source_label
    ports = digest.get("dst_ports") or []
    if ports:
        hint["目的端口"] = [str(p) for p in ports[:8]]
    types = digest.get("event_types") or []
    if types:
        hint["事件类型"] = [str(t) for t in types[:4]]
    states = digest.get("conn_states") or []
    if states:
        # 连接状态是客观字段（ShR 等）：出现过 S 建立即"这条流水里有真实会话"，
        # 智能体能直接回答"成功没有"，不必再查
        hint["会话状态"] = [str(t) for t in states[:6]]
    if digest.get("proxied"):
        hint["中继提示"] = "命中经代理/中继：源 IP 可能是转发点，方向判定看 real_client_ips"
        reals = digest.get("real_client_ips") or []
        if reals:
            hint["真实客户端"] = [str(v) for v in reals[:5]]
    return hint


def _hits_source_label(rule_source: str) -> str:
    """把 rule_source 译成来源类别（与 hits.SOURCE_LABELS 的三类对齐）。"""
    mapping = {
        "suricata": "特征签名",
        "baseline": "基线偏离",
        "builtin": "内置规则",
        "rules": "内置规则",
    }
    return mapping.get(rule_source, "")


def enqueue_hit(digest: dict[str, Any], event_id: str, client: Any) -> str:
    """规则命中 → `hit` 线索。

    强度**只用客观量**（涉及多少个目的、命中多少次、这条规则是否第一次见），
    不读 `rule_severity` —— 严重度是 NDR 的判断，读它等于继续替智能体下结论。
    """
    src = str(digest.get("src_ip") or "")
    rule = str(digest.get("rule") or "")
    if not src or not rule:
        return "skipped"
    now = datetime.now(UTC)
    distinct_dst = len(digest.get("dst_ips") or []) or len(digest.get("dst_pairs") or [])
    strength = feedback.apply(
        combined_strength(
            scale_strength(int(digest.get("count") or 1) or distinct_dst),
            subjects.staleness("ip", src, now),
            rarity_strength(0, first_seen=False),
        ),
        "hit",
        src,
    )
    return queue.enqueue(
        kind="hit",
        subject_kind="ip",
        subject=src,
        strength=strength,
        feature=rule,
        hint=_hit_hint(digest, rule, event_id, strength, distinct_dst),
        window_start=_as_dt(digest.get("first_seen")),
        window_end=_as_dt(digest.get("last_seen")) or now,
        client=client,
    )


def enqueue_coverage(client: Any) -> int:
    """盲区线索：从未/久未分析的对象（低强度，保证不与异常抢预算）。"""
    made = 0
    data = subjects.coverage(days=params.coverage_stale_days(), limit=200)
    now = datetime.now(UTC)
    for item in data.get("items") or []:
        stale = subjects.staleness(
            str(item.get("subject_kind") or ""), str(item.get("subject") or ""), now
        )
        strength = feedback.apply(
            combined_strength(stale * 0.35, 0.05), "coverage", str(item.get("subject") or "")
        )
        # 冷启动保护：盲区线索同样压到保留名额之下
        strength = cold_start_mod.damped(strength, client)
        result = queue.enqueue(
            kind="coverage",
            subject_kind="asset",
            subject=str(item.get("subject") or ""),
            strength=strength,
            feature="coverage",
            hint={
                "事实": f"{item.get('why')}（近 {params.coverage_stale_days()} 天可见 {item.get('seen_count')} 次）",
                "首次出现": item.get("first_seen_at"),
                "上次分析": item.get("last_analyzed_at") or "从未",
                "客观强度": strength,
            },
            window_start=now - timedelta(days=params.coverage_stale_days()),
            window_end=now,
            client=client,
        )
        if result in ("new", "merged"):
            made += 1
    return made


#: 复测只对这些结论做：它们意味着"当时认定这里没问题"，也意味着可能被抑制挡住
RETESTABLE_VERDICTS = ("false_positive", "benign")


def enqueue_retest(client: Any) -> int:
    """复测线索：把"当时判成误报、且身上还挂着抑制、很久没复核"的对象重新捞出来。

    为什么需要（借鉴 artex 的 retester）：
    抑制**到期是静默的**，没人回头看它是不是又变成了真问题（攻击者换手法、业务变更、
    或者当初就判错）。我们已有的"真阳性自动回弹"是**被动**等事实打脸；
    复测是**主动**抽样复核，两者互补。

    同时满足三条才捞（缺一条就是浪费预算）：
    ① 最近一次结论是 `false_positive` / `benign`（说明当时认为没问题）；
    ② 距上次分析超过 `analysis.retest_days`（刚看过的不重复看）；
    ③ 该对象身上还有**生效中的抑制**（没有抑制就没有"被挡住的东西"，复测无意义）。
    """
    limit = params.retest_max_per_round()
    if limit <= 0:
        return 0
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=params.retest_days())
    try:
        with SessionLocal() as db:
            candidates = db.execute(
                select(
                    AnalysisResult.subject_kind,
                    AnalysisResult.subject,
                    func.max(AnalysisResult.created_at),
                )
                .where(AnalysisResult.verdict.in_(RETESTABLE_VERDICTS))
                .group_by(AnalysisResult.subject_kind, AnalysisResult.subject)
                .having(func.max(AnalysisResult.created_at) < cutoff)
                .order_by(func.max(AnalysisResult.created_at).asc())
                .limit(max(limit * 3, 12))
            ).all()
    except Exception as exc:  # noqa: BLE001 — 复测是增值功能，失败不能影响派工
        log.debug("复测线索生成失败：%s", exc)
        return 0

    made = 0
    for subject_kind, subject, _last_at in candidates:
        if made >= limit:
            break
        kind_text = str(subject_kind or "")
        subject_text = str(subject or "")
        if not subject_text:
            continue
        try:
            with SessionLocal() as db:
                latest = db.scalars(
                    select(AnalysisResult)
                    .where(
                        AnalysisResult.subject_kind == kind_text,
                        AnalysisResult.subject == subject_text,
                    )
                    .order_by(AnalysisResult.created_at.desc())
                    .limit(1)
                ).first()
        except Exception as exc:  # noqa: BLE001
            log.debug("复测：读 %s 最近一次结论失败，跳过：%s", subject_text[:64], exc)
            continue
        if latest is None or str(latest.verdict) not in RETESTABLE_VERDICTS:
            # 之后又判过别的（真阳性/可疑/不确定）→ 这条不是"当时说没问题"，跳过
            continue
        suppression_ids = suppression.ids_for_subject(subject_text)
        if not suppression_ids:
            continue
        strength = feedback.apply(0.5, "retest", subject_text)
        result = queue.enqueue(
            kind="retest",
            subject_kind=kind_text or "ip",
            subject=subject_text,
            strength=strength,
            feature="retest",
            hint={
                "事实": (
                    f"上次判定 {latest.verdict}（{latest.created_at:%Y-%m-%d}），"
                    f"距今超过 {params.retest_days()} 天，且该对象上有 {len(suppression_ids)} 条生效中的抑制"
                ),
                "复测对象": latest.task_id,
                "上次结论": latest.verdict,
                "抑制条目": suppression_ids[:10],
                "客观强度": strength,
                "要求": "重新判断同一现象是否仍然无害；结论用 complete_task 的 verdict 三态表达",
            },
            window_start=cutoff,
            window_end=now,
            client=client,
        )
        if result in ("new", "merged"):
            made += 1
    return made


def _as_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def significance_for(value: float, mean: float, var: float) -> float:
    """把（值, 均值, 方差）换算成上尾概率 —— 复用基线那套检验，避免两处口径漂移。"""
    return poisson.count_p_value(value, mean=mean, var=var)
