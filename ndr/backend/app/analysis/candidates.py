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

import hashlib
import math
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import Text, cast, func, select, tuple_

from app.analysis import cold_start as cold_start_mod, feedback, params, queue, subjects
from app.baseline import poisson
from app.db.base import SessionLocal
from app.db.models import AnalysisResult, AnalysisTask, HitEvent, Observation, ObservedSubject
from app.detector import suppression
from app.detector.clustering import cluster_label
from app.iputil import is_internal_ip
from app.schemas import UnifiedLog
from app.workers.log import get_logger

#: 等价于 3.11 的 `datetime.UTC`（本仓库 requires-python >=3.11）；用别名写法
#: 免得按旧语法解析的静态检查工具报「unknown import symbol」。
UTC = timezone.utc

log = get_logger(__name__)

#: 服务端口首见只关心这些（暴露面/横向常用）：随机端口是 NAT/临时连接，不是"新服务"
_HIGH_RISK_PORTS: frozenset[int] = frozenset({
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211,
})

#: 队列里 pending novelty 的上限：首见线索的价值随时间快速衰减，
#: 堆到 500 条以上只会把 observation/hit 饿死（实测 4914 条把队占满）。
_NOVELTY_PENDING_CAP = 500

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
        # 资产首见只看**被访问方**（监控网段内的 dst）：取 src 会把"新手机/新客户端 IP"
        # 当成新资产，校园网一天上千条（实测 3659 条待办，97% 是客户端噪声）。
        # 口径 C1（2026-10-29）：is_internal_ip() 是唯一坐标系 —— 不能用"非公网"代替，
        # 否则 10.9.9.9 这类**未监控内网段**会被登记成我们的资产、出盲区派工任务。
        if dst and dst != "-" and is_internal_ip(dst):
            self._add(subjects.KIND_ASSET, dst)
            port = entry.dst_port
            # 服务端口只记高危/常用端口：随机高端口（NAT/临时连接）没有暴露面含义
            if port and int(port) in _HIGH_RISK_PORTS:
                self._add(subjects.KIND_PORT, f"{dst}:{port}")
        if str(getattr(entry, "protocol", "") or ""):
            self._add(subjects.KIND_PROTOCOL, str(entry.protocol).lower())
        sig_id = str(getattr(entry, "signature_id", "") or "")
        if sig_id:
            self._add(subjects.KIND_SIGNATURE, sig_id)
        account = str(getattr(entry, "account", "") or getattr(entry, "user", "") or "")
        # 账号首见只在**监控网段内的源**登记（C1）：外部攻击者打的账号字典
        # 不是"我们见过的新账号"，登记进去只会产生永远瞎的盲区任务
        if account and is_internal_ip(src):
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


def is_recurring(seen_count: int) -> bool:
    """跨窗口再现才算"值得派工的对象"（纯函数，便于测）。

    `seen_count` 每个采集窗口出现一次 +1：首次登记是 1，第二个窗口再出现就是 2。
    只有 1~2 的还可能是**一次性对象**（代理/NAT 的临时套接字、扫描器的单次探测），
    它们不是"新服务"，派工过去只会白烧模型调用。门槛从 2 提到 3：校园网里
    客户端换 IP/重连非常频繁，2 个窗口就派工基本等于"给每个新手机发一单"。
    """
    try:
        return int(seen_count or 0) >= 3
    except (TypeError, ValueError):
        return False


def is_newcomer(first_seen_at: datetime | None, now: datetime, window_hours: int) -> bool:
    """还在"新面孔窗口"内的对象才算新线索（纯函数，便于测）。

    过了窗口，这个对象就是环境的一部分了 —— 再派"第一次见到"没有意义，
    想让它别被忘掉应该走 `coverage`（久未分析的盲区提醒）。
    """
    if first_seen_at is None:
        return True
    try:
        age = (now - first_seen_at).total_seconds() / 3600.0
    except TypeError:
        return True
    if age < 0:
        return True
    return age <= max(1, int(window_hours))


def _record_seen(db: Any, rows: list[tuple[str, str]], now: datetime) -> list[tuple[str, str, datetime]]:
    """批量登记"见过"，返回其中**跨窗口反复出现**的 (kind, value, 首次出现时间)。

    只用 ORM 会话接口（`scalars` / `add`），不手写任何 SQL 拼接；一次读 + 一次刷，
    新对象靠唯一索引 `(kind, value)` 兜并发重复。

    **为什么不是"第一次见到就派工"**：镜像口上的一次性连接也会造出一个"新对象"——
    代理/NAT 的临时套接字、扫描器的单次探测，端口每次都不同。实测一个采集窗口
    能刷出 25 万个一次性 `dst_ip:dst_port`，队列直接被这类垃圾线索灌满
    （实测丢弃 1.5 万条、队列常年满），真正值得看的新服务反而被挤掉。
    值得分析的服务端口是**反复出现**的那些，所以这里只把「跨窗口再现」的对象交出去。
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
    recurring: list[tuple[str, str, datetime]] = []
    window_hours = params.novelty_newcomer_hours()
    for row in found.values():
        row.last_seen_at = now
        row.seen_count = int(row.seen_count or 0) + 1
        # seen_count ≥ 2 = 本次之前已经在别的窗口出现过（本次是第二次及以后）
        if is_recurring(row.seen_count) and is_newcomer(row.first_seen_at, now, window_hours):
            recurring.append((str(row.kind), str(row.value), row.first_seen_at or now))
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
    return recurring


def _novelty_tasks(
    db: Any, recurring: list[tuple[str, str, datetime]], now: datetime, client: Any
) -> int:
    """反复出现、且还在新面孔窗口内的对象 → novelty 线索。

    强度按"多久没分析过"加成，冷门口对象更容易排上。

    C2（2026-10-29）：novelty 只给**资产/服务端口/账号**派工；协议/签名这类"全局首见"
    不再单独立线索（它们由 `hit_cluster` 或 agent 主动 `asset_map`/`list_rules` 覆盖，
    否则一个新签名/新协议就占一条任务，信息量为零）。登记表仍然照记，覆盖率不受影响。
    """
    made = 0
    novelty_kinds = (subjects.KIND_ASSET, subjects.KIND_PORT, subjects.KIND_ACCOUNT)
    for kind, value, first_seen in recurring[:_MAX_ENQUEUE_PER_FLUSH]:
        if kind not in novelty_kinds:
            continue
        stale = subjects.staleness("asset", value, now) if kind == subjects.KIND_ASSET else 0.6
        # 套反馈系数：这个对象上同类现象被连判过误报就捐低优先级（只衰减不否决）
        strength = feedback.apply(
            combined_strength(rarity_strength(0, first_seen=True), stale), "novelty", value
        )
        # 冷启动保护：基线重学期内首见一律压到高强度档之下（见 cold_start 模块说明）
        strength = cold_start_mod.damped(strength, client)
        result = queue.enqueue(
            kind="novelty",
            subject_kind="asset" if kind == subjects.KIND_ASSET else kind,
            subject=value,
            strength=strength,
            feature=f"first:{kind}",
            hint={
                # 事实要跟口径一致：不是"第一次见到"，而是"这个对象反复出现"，
                # 第一次见到的时间一并给出，智能体自己判断是新服务还是老熟人。
                "事实": f"该{kind}在多个采集窗口反复出现（首次出现：{first_seen.isoformat()}）",
                "对象类型": kind,
                "距上次分析": "从未分析" if stale >= 0.9 else "近期未分析",
                "客观强度": strength,
                # B1：所有 kind 都下发稳定身份，agent 侧复用只认"同一事实"
                "reuse_identity": f"novelty|{kind}:{value}",
            },
            window_start=now - timedelta(minutes=30),
            window_end=now,
            client=client,
        )
        if result in ("new", "merged"):
            made += 1
    return made



#: 事实转任务的门槛：低于它的只留在库里给 MCP 查（避免"每条事实都派一单"）
_OBS_MIN_STRENGTH = 0.45
_OBS_WINDOW_MINUTES = 30

#: 观察事实按类别自带的方向（D1）：别的类别方向不明，就别下发，不下发 ≠ 让 agent 猜
_OBSERVATION_DIRECTION: dict[str, str] = {
    "egress_new": "in→out",
    "egress_rare": "in→out",
    "egress_sustained": "in→out",
    "path_probe": "out→in",
}

#: 每轮最多派多少条 `hit_cluster`（D2）：先全貌再逐条，扫几十个 IP 也只占 20 个坑
_HIT_CLUSTER_PER_ROUND = 20
#: 簇查询回看窗口（与去重桶 60 分钟一致：同一簇在桶内只派一次）
_HIT_CLUSTER_RECALL_MINUTES = 60
#: 每轮最多读多少条近期命中事件参与成簇（防大站点把内存吃满）
_HIT_CLUSTER_EVENT_CAP = 600


def enqueue_hit_clusters(client: Any) -> int:
    """命中簇 → `hit_cluster` 线索（D2，2026-10-29）：资产为中心，先全貌再逐条。

    为什么不直接开逐条 hit：一次扫描命中几十个 IP，逐条派 = 几十条外部 IP 任务，
    队列立刻爆量；簇把同一（归类·网段·小时）折成一件，主体是被访问资产。
    强度只读客观量（事件数/涉及资产数/staleness），**不读 rule_severity** ——
    严重度是 NDR 的判断，读了就等于替智能体下结论。

    护栏（用户拍板）：60 分钟桶去重（queue 层自带）＋每轮上限 20＋
    **同一簇族 24 小时最多观察一次**（持续扫描不是新现象，每小时重派刷不完的队列）。
    """
    if "hit_cluster" not in params.candidate_kinds():
        return 0
    now = datetime.now(UTC)
    since = now - timedelta(minutes=_HIT_CLUSTER_RECALL_MINUTES)
    guard_prefixes: set[str] = set()
    try:
        with SessionLocal() as db:
            rows = list(
                db.scalars(
                    select(HitEvent)
                    .where(
                        HitEvent.created_at >= since,
                        HitEvent.ignored.is_(False),
                    )
                    .order_by(HitEvent.created_at.desc())
                    .limit(_HIT_CLUSTER_EVENT_CAP)
                ).all()
            )
            # 24h 观察护栏的账本：最近一天派过工的簇族（去重键去掉末尾时间桶）不再重复派
            day_ago = now - timedelta(hours=24)
            guard_prefixes = {
                str(k).rsplit("|", 1)[0]
                for k in db.scalars(
                    select(AnalysisTask.dedupe_key).where(
                        AnalysisTask.kind == "hit_cluster",
                        AnalysisTask.created_at >= day_ago,
                    )
                )
            }
    except Exception:  # noqa: BLE001 — 派工失败不能拖垮检测
        return 0
    clusters: dict[str, list[Any]] = {}
    for row in rows:
        cid = str(row.cluster_id or "")
        if cid:
            clusters.setdefault(cid, []).append(row)

    def _objective_strength(events: list[Any], principal: str) -> float:
        distinct_assets = len(
            {str(x) for ev in events for x in (ev.dst_ips or []) if is_internal_ip(str(x))}
        )
        return feedback.apply(
            combined_strength(
                scale_strength(len(events) or distinct_assets),
                subjects.staleness("asset", principal, now),
                rarity_strength(0, first_seen=False),
            ),
            "hit_cluster",
            principal,
        )

    scored: list[tuple[float, str, list[Any], str, list[str]]] = []
    for events in clusters.values():
        principal = ""
        for ev in events:
            for cand_ip in [str(x) for x in (ev.dst_ips or [])] + [str(ev.src_ip or "")]:
                if cand_ip and is_internal_ip(cand_ip):
                    principal = cand_ip
                    break
            if principal:
                break
        if not principal:
            continue  # 外部↔外部不是我们的资产
        rule_names = sorted({str(ev.rule or "") for ev in events} - {""})[:10]
        # 簇族身份：主体资产 + 规则集合，**不含小时桶**（同一族跨小时可复用结论）
        family_raw = f"hit_cluster|{principal}|{','.join(rule_names)}"
        family = hashlib.sha256(family_raw.encode("utf-8")).hexdigest()[:32]
        if f"hit_cluster|asset:{principal}|cluster:{family}" in guard_prefixes:
            continue  # 24h 观察护栏：这个簇族 24h 内已经派过工
        scored.append(
            (
                _objective_strength(events, principal),
                principal,
                events,
                family,
                rule_names,
            )
        )
    scored = sorted(scored, key=lambda item: item[0], reverse=True)
    made = 0
    for strength, principal, events, family, rule_names in scored[:_HIT_CLUSTER_PER_ROUND]:
        event_ids = [str(ev.id) for ev in events[:20]]
        direction = str((events[0].direction if events else "") or "")
        lead = events[0]
        cluster_text = cluster_label(
            str(lead.rule or ""), str(lead.src_ip or ""), getattr(lead, "last_seen", None)
        )
        # 受影响资产：事件里的网段内侧（被访问资产/我方外连源），不预设威胁
        if direction == "in→out":
            affected = sorted({str(ev.src_ip or "") for ev in events} - {""})
        else:
            affected = sorted(
                {str(x) for ev in events for x in (ev.dst_ips or []) if is_internal_ip(str(x))}
            )
        hint: dict[str, Any] = {
            "簇": cluster_text,
            "事件数": len(events),
            "事件ID": event_ids,
            "规则": rule_names,
            "主体资产": {"kind": "ip", "value": principal},
            "principal_asset": {"kind": "ip", "value": principal},
            "受影响资产": [{"kind": "ip", "value": v} for v in affected[:20]],
            "affected_assets": [{"kind": "ip", "value": v} for v in affected[:20]],
            # 智能体侧复用键（不含时间桶）：同一簇族可以复用上次的结论
            "reuse_identity": family,
        }
        if direction:
            hint["方向"] = direction
            hint["direction"] = direction
            if direction == "in→out":
                # 我方外连：对端 = 外部目的地
                peers = sorted(
                    {
                        str(x)
                        for ev in events
                        for x in (ev.dst_ips or [])
                        if not is_internal_ip(str(x))
                    }
                    - {""}
                )
            else:
                # 入站/横向：对端 = 外部发起方（中继场景优先真实客户端）
                peers = sorted(
                    {
                        str(ev.client or ev.src_ip or "")
                        for ev in events
                        if not is_internal_ip(str(ev.client or ev.src_ip or ""))
                    }
                    - {""}
                )
            if peers:
                hint["对端"] = peers[:20]
                hint["peer"] = peers[:20]
        result = queue.enqueue(
            kind="hit_cluster",
            subject_kind="asset",
            subject=principal,
            strength=strength,
            feature=f"cluster:{family}",
            hint=hint,
            window_start=events[-1].first_seen if events else None,
            window_end=events[0].last_seen if events else None,
            client=client,
        )
        if result in ("new", "merged"):
            made += 1
    return made


#: 每轮最多派几条（总配额）
_OBS_PER_ROUND = 5
#: 每类最多派几条（D7 分类型配额）：防止 egress_new 把 login_bruteforce/asset_shift 挤掉
_OBS_PER_KIND = 2
#: 同一事实的派工冷却（小时）：强事实不再每 5 分钟重新占位
_OBS_COOLDOWN_HOURS = 6


def _recent_rule_hits(subject: str, *, limit: int = 5) -> list[dict[str, Any]]:
    """该对象最近的规则命中（作为事实的附加证据，不参与判定）。

    D6（2026-10-29）：之前只查 `src_ip`/`client`，内网资产被外网源**打**时（它是
    dst）带不上任何规则证据 —— 而"这个资产被扫了"恰恰要靠这些证据。现在同时按
    dst 匹配，并标明它是源侧还是目的侧（`as_source`/`as_destination`）。
    """
    if subject == "":
        return []
    since = datetime.now(UTC) - timedelta(hours=24)
    try:
        with SessionLocal() as db:
            rows = list(
                db.scalars(
                    select(HitEvent)
                    .where(
                        HitEvent.created_at >= since,
                        (HitEvent.src_ip == subject)
                        | (HitEvent.client == subject)
                        # dst_ips 是 JSON 数组：用转文本包含匹配（PG/SQLite 都可用）
                        | (cast(HitEvent.dst_ips, Text).like(f'%"{subject}"%')),
                    )
                    .order_by(HitEvent.created_at.desc())
                    .limit(max(1, min(limit, 20)))
                ).all()
            )
    except Exception as exc:  # noqa: BLE001
        log.debug("读近期规则命中失败：%s", exc)
        return []
    out: list[dict[str, Any]] = []
    for row in rows:
        as_source = subject in (str(row.src_ip or ""), str(row.client or ""))
        out.append(
            {
                "rule": row.rule,
                "source_kind": row.source_kind,
                "count": int(row.count or 0),
                "last_seen": row.last_seen.isoformat() if row.last_seen else "",
                "event_id": str(row.id),
                "direction": str(getattr(row, "direction", "") or ""),
                "as_source": as_source,
                "as_destination": subject in [str(x) for x in (row.dst_ips or [])],
            }
        )
    # 目的侧证据优先（"它被谁打了"通常比"它打了谁"更值得先看）
    out.sort(key=lambda item: (not item["as_destination"], not item["as_source"]))
    return out


def enqueue_observations(client: Any) -> int:
    """把**近期强事实**转成分析任务（hint 里只有事实，没有任何结论/严重度）。

    为什么需要这一步：基线事实是给智能体看的，但它不会主动去翻库 ——
    必须有一条"这些事实值得你看一眼"的派工路径。重复事实由队列的去重键合并，
    同一对象同一类事实只会有一条任务。

    D7（2026-10-29）：之前每轮只取"强度最高的 5 条"、还不记录派过没有 ——
    同一条强事实每 5 分钟重新占位，低强度事实（login_bruteforce/asset_shift）
    永远轮不到。现在：
    - 同一事实 6 小时冷却（`last_enqueued_at`）；
    - 分类型配额：每类最多 2 条（`ROW_NUMBER() OVER (PARTITION BY kind ...)`）；
    - 强度 < 0.45 的（conn_shift 0.2 / egress_rare 0.35）**只可查询、不派工**，
      文档与工具描述里如实说明，不假装会派。
    """
    if "observation" not in params.candidate_kinds():
        return 0
    now = datetime.now(UTC)
    since = now - timedelta(minutes=_OBS_WINDOW_MINUTES)
    cutoff = now - timedelta(hours=_OBS_COOLDOWN_HOURS)
    try:
        with SessionLocal() as db:
            ranked = (
                select(
                    Observation.id.label("id"),
                    func.row_number()
                    .over(
                        partition_by=Observation.kind,
                        order_by=(Observation.strength.desc(), Observation.last_seen.desc()),
                    )
                    .label("rn"),
                )
                .where(
                    Observation.last_seen >= since,
                    Observation.strength >= _OBS_MIN_STRENGTH,
                    (Observation.last_enqueued_at.is_(None))
                    | (Observation.last_enqueued_at < cutoff),
                )
                .subquery()
            )
            picked = select(ranked.c.id).where(ranked.c.rn <= _OBS_PER_KIND).subquery()
            rows = list(
                db.scalars(
                    select(Observation)
                    .where(Observation.id.in_(select(picked.c.id)))
                    .order_by(Observation.strength.desc(), Observation.last_seen.desc())
                    .limit(_OBS_PER_ROUND)
                ).all()
            )
            recent_total = int(
                db.scalar(
                    select(func.count())
                    .select_from(Observation)
                    .where(Observation.last_seen >= since)
                )
                or 0
            )
            cooling = int(
                db.scalar(
                    select(func.count())
                    .select_from(Observation)
                    .where(
                        Observation.last_seen >= since,
                        Observation.strength >= _OBS_MIN_STRENGTH,
                        Observation.last_enqueued_at.is_not(None),
                        Observation.last_enqueued_at >= cutoff,
                    )
                )
                or 0
            )
    except Exception as exc:  # noqa: BLE001 — 事实派工失败不能拖垮检测
        log.warning("读观察事实失败：%s", exc)
        return 0
    queue.bump(client, "observation_skipped_cooldown", cooling)
    if recent_total > len(rows) + cooling:
        # 有事实但没进本轮配额（被同类上限/总上限挡住）：低强度事实正在挨饿
        queue.bump(client, "observation_starved")
    made = 0
    enqueued_ids: list[str] = []
    for row in rows:
        # 主体类型保留原样（asset_shift 的 subject 是站点、profile_anomaly 可能是会话）；
        # 一律写成 ip 会让 agent 把「会话标识」当 IP、把资产当发起方（C2 口径）
        raw_kind = str(row.subject_kind or "")
        subject_kind = raw_kind if raw_kind in ("asset", "account", "session") else "ip"
        # 规则命中只作为**附加证据**：默认不再单独派工，但对象被事实选中时把它带上，
        # 免得 agent 又要单独去翻一遍（2026-10 用户口径：规则是证据，不是结论）
        evidence = _recent_rule_hits(str(row.subject or ""))
        # D1：观察事实按"类别决定方向"下发（egress 类是 in→out，入口探测是 out→in）。
        # 不能派工后再判 —— agent 需要"这个事实本身发生在哪个方向"来选查询路径。
        direction = _OBSERVATION_DIRECTION.get(str(row.kind or ""), "")
        result = queue.enqueue(
            kind="observation",
            subject_kind=subject_kind,
            subject=str(row.subject or ""),
            strength=float(row.strength or 0),
            feature=str(row.kind or ""),
            hint={
                "事实类型": row.kind,
                "事实": row.facts or {},
                "出现次数": int(row.count or 0),
                "首次观测": row.first_seen.isoformat() if row.first_seen else "",
                "最近观测": row.last_seen.isoformat() if row.last_seen else "",
                # B1：复用身份 = 观察事实的稳定去重键（含事实 key，如同一资产的不同
                # 外连目标各有各的身份）—— 之前 agent 只能拿 kind 拼键，
                # "同资产外连 A/B 两条事实"会共用一条结论（实测踩过）
                **({"reuse_identity": str(row.dedupe_key or "")} if str(row.dedupe_key or "") else {}),
                **({"方向": direction} if direction else {}),
                **({"direction": direction} if direction else {}),
                **({"相关规则命中": evidence} if evidence else {}),
            },
            client=client,
        )
        if result in ("new", "merged"):
            made += 1
            enqueued_ids.append(str(row.id))
    if enqueued_ids:
        try:
            with SessionLocal() as db:
                for obs_id in enqueued_ids:
                    item = db.get(Observation, obs_id)
                    if item is not None:
                        item.last_enqueued_at = now
                db.commit()
        except Exception as exc:  # noqa: BLE001 — 冷却记账失败只影响频率，不影响派工
            log.debug("观察事实冷却记账失败：%s", exc)
    queue.bump(client, "observation_enqueued", made)
    return made

def flush(collector: Collector, client: Any, *, stats: Any = None) -> dict[str, int]:
    """窗口到期：登记对象 + 产出 novelty / structure 线索。返回各步计数。"""
    now = datetime.now(UTC)
    rows: list[tuple[str, str]] = []
    for kind, values in collector.seen.items():
        for value in values:
            rows.append((kind, value))
    out = {"seen": len(rows), "novelty": 0, "structure": 0}
    # 结构特征的计数要在清空前留一份快照：`reset()` 会把 fail_events/total_events
    # 清空，之后 _structure_tasks 看到的永远是空字典（这条线索其实一直没产出过）。
    fail_events = dict(collector.fail_events)
    total_events = dict(collector.total_events)
    window_start = collector.window_start
    # 无论后面成功与否都要清空：这是常驻进程，累积器不清空就会无界增长
    collector.reset()
    if not rows:
        return out
    try:
        with SessionLocal() as db:
            recurring = _record_seen(db, rows, now)
            db.commit()
            pending_novelty = int(
                db.scalar(
                    select(func.count())
                    .select_from(AnalysisTask)
                    .where(
                        AnalysisTask.kind == "novelty",
                        AnalysisTask.state.in_(("pending", "deferred")),
                    )
                )
                or 0
            )
            if pending_novelty < _NOVELTY_PENDING_CAP:
                room = _NOVELTY_PENDING_CAP - pending_novelty
                out["novelty"] = _novelty_tasks(db, recurring[:room], now, client)
    except Exception as exc:  # noqa: BLE001 — 生成线索失败绝不能影响检测
        log.warning("线索生成（首见登记）失败：%s", exc)
        queue.bump(client, "candidate_error")
        return out
    if "structure" in params.candidate_kinds():
        out["structure"] = _structure_tasks(fail_events, total_events, window_start, now, client)
    if stats is not None:
        try:
            stats["candidate_novelty"] = int(stats.get("candidate_novelty", 0)) + out["novelty"]
        except (TypeError, ValueError):
            pass
    return out


def _structure_tasks(
    fail_events: dict[str, int],
    total_events: dict[str, int],
    window_start: float,
    now: datetime,
    client: Any,
) -> int:
    """轻量结构特征：失败响应占比异常高（只给事实，不说是攻击）。"""
    made = 0
    for src, fails in fail_events.items():
        total = total_events.get(src, 0) or 1
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
                "窗口": f"{window_start or ''}",
                "客观强度": strength,
                "reuse_identity": f"structure|{src}|fail_ratio",
            },
            window_start=now - timedelta(minutes=30),
            window_end=now,
            client=client,
        )
        if result in ("new", "merged"):
            made += 1
    return made


def enqueue_suppression_followup(client: Any) -> int:
    """降级的精准抑制 → 一条待办任务（让智能体自己收窄后同名重提）。

    为什么需要这一条：抑制被爆炸半径护栏降级时只是"只不派工"，现象从此不再
    出现在智能体面前 —— 它就没有机会发现自己那条抑制其实没生效。闭环要闭上，
    就得把这件事**重新派回给它**：它按 `downgrade.advice` 收窄条件、同名重提，
    通过护栏即真正生效。

    强度给 0.75（高于"首见新资产"那类 0.7 的调查型线索）：这条待办的**证据都在
    hint 里**（试算数字、降级原因、该怎么改），智能体补两三份取证就能改完；
    而"某个新资产出现了"那种调查型线索单条成本高得多 —— 让便宜的待办先做完。
    """
    made = 0
    now = datetime.now(UTC)
    for item in suppression.downgraded_items():
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        reason = dict(item.get("downgrade") or {})
        trial = dict(item.get("trial") or {})
        matched = int(trial.get("matched_rows") or 0)
        if matched == 0 and int(trial.get("scanned_rows") or 0) > 0:
            reason = {
                **reason,
                "reason": (
                    "这条抑制的条件在近 "
                    f"{int(trial.get('days') or 0)} 天的命中事件里一条都匹配不到"
                    "（多半是拿良性流量的字段写的）"
                ),
                "advice": (
                    "重写条件去匹配**触发噪声的那条规则的命中事件**："
                    "加 rule 维度指出是哪条规则，或把 src_ip 精确到具体来源"
                ),
            }
        strength = feedback.apply(0.75, "structure", name)
        result = queue.enqueue(
            kind="structure",
            subject_kind="suppression",
            subject=name,
            strength=strength,
            feature="suppression_downgrade",
            hint={
                "事实": (
                    f"你之前提交的精准抑制「{name}」没有真正生效（当前只不派工）："
                    f"{reason.get('reason') or '影响面过大被降级'}"
                ),
                "怎么收窄": reason.get("advice") or "收窄到单个来源 + 具体行为特征",
                "超限维度": reason.get("dimension") or "",
                "实际值": reason.get("actual"),
                "上限": reason.get("limit"),
                "试算": trial,
                "抑制ID": item.get("id") or "",
                "原任务": item.get("source_task_id") or "",
                "要求": (
                    "按上面的建议收窄条件（收窄到单个来源 src_ip + 具体行为特征），"
                    "重新取证后用**同一个 name** 调用 submit_suppression 提交（同名会覆盖旧条目）；"
                    "不要换新名字，也不要直接撤销"
                ),
                "客观强度": strength,
            },
            window_start=now - timedelta(hours=24),
            window_end=now,
            client=client,
            # 运维类待办：不受「生成哪些线索」的旋钮约束
            force=True,
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
                # B1：所有 kind 都下发稳定身份（agent 侧复用只认同一个事实）
                "reuse_identity": f"shift|ip:{src}|{feature}",
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
    与 candidates 模块顶部的边界一致）。中继状态与客户端地址只按原始字段下发，
    由智能体自行判断是否影响分析方向。
    """
    hint: dict[str, Any] = {
        "事实": f"规则「{rule}」命中 {digest.get('count')} 次，目的 {distinct_dst} 个",
        "事件ID": event_id,
        "客观强度": strength,
        # 跨时间窗的同类事件身份（不含时间桶），只用于智能体侧去重；
        # 不含计数/严重度/结论，也不参与线索强弱和 NDR 的任何判定。
        "reuse_identity": _hit_reuse_identity(digest, rule),
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
        # 只下发原始元数据，不把“这是中继/该如何判方向”写成 NDR 的分析建议。
        hint["proxied"] = True
        reals = digest.get("real_client_ips") or []
        if reals:
            hint["真实客户端"] = [str(v) for v in reals[:5]]
    # D1/C2（2026-10-29 架构整改）：方向定型时算好，主体/对端一次说清 ——
    # 之前 hint 不带方向，agent 得先自己查反代、浏览器真实来源才能开始判断。
    direction = str(digest.get("direction") or "")
    if direction:
        hint["方向"] = direction
        # 英文别名（C2/D1 验收字段名）：界面/智能体两侧都认这两套键
        hint["direction"] = direction
        dsts = [str(x) for x in (digest.get("dst_ips") or [])[:5] if str(x or "").strip()]
        reals = [str(v) for v in (digest.get("real_client_ips") or [])[:5]]
        init_src = str(digest.get("src_ip") or "")
        initiator = reals or ([init_src] if init_src else [])
        if direction == "in→out":
            # 主体（=任务 subject）是发起外连的我方资产；"对端"是外部目的地
            hint["对端"] = dsts
            hint["peer"] = dsts
        elif direction:
            # out→in / in→in / unknown：受影响的是被访问方资产（=分析重点），发起方列出
            if dsts:
                affected_assets = [{"kind": "ip", "value": v} for v in dsts]
                hint["受影响资产"] = affected_assets
                hint["affected_assets"] = affected_assets
            if initiator:
                hint["发起方"] = initiator
                hint["peer"] = initiator
    return hint


def _hit_reuse_identity(digest: dict[str, Any], rule: str) -> str:
    """同一规则命中事件的跨窗口身份：规则 + 源 + 目标/端口/事件类型集合。

    与旧事件分析 ID 使用同一组稳定字段，刻意不含时间桶和易变计数；
    与 `digest_fingerprint` 的区别也正是去掉桶起点（后者用来区分窗口）。
    这是对象身份元数据，不是 NDR 对事件的分析结论。
    """
    src = str(digest.get("src_ip") or "").strip()
    dsts = ",".join(sorted(str(x) for x in (digest.get("dst_ips") or []))[:20])
    ports = ",".join(
        sorted({str(p) for p in (digest.get("dst_ports") or []) if p is not None})[:20]
    )
    etypes = ",".join(sorted(str(x) for x in (digest.get("event_types") or []))[:10])
    if not rule.strip() or not src or not (dsts or ports or etypes):
        return ""
    raw = f"{rule}|{src}|{dsts}|{ports}|{etypes}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


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
    """规则命中 → `hit` 线索（逐条，**默认关**；批量走 `hit_cluster`）。

    强度**只用客观量**（涉及多少个目的、命中多少次、这条规则是否第一次见），
    不读 `rule_severity` —— 严重度是 NDR 的判断，读它等于继续替智能体下结论。

    主体口径（C2，2026-10-29）：任务主体 = **监控网段内资产**，不是外部触发方。
    外→内命中时主体是被访问资产（外部源进 hint.peer）；内→外时主体是我方发起资产。
    外部↔外部不是我们的资产，直接跳过（旧实现在这类情况下给外部 IP 派工，队列全是噪音）。
    """
    src = str(digest.get("src_ip") or "")
    rule = str(digest.get("rule") or "")
    if not src or not rule:
        return "skipped"
    now = datetime.now(UTC)
    direction = str(digest.get("direction") or "")
    dsts_internal = [str(d) for d in (digest.get("dst_ips") or []) if is_internal_ip(str(d))]
    if direction == "in→out":
        principal, subject_kind = src, "ip"
    elif dsts_internal:
        principal, subject_kind = dsts_internal[0], "asset"
    elif is_internal_ip(src):
        principal, subject_kind = src, "asset"
    else:
        return "skipped"
    distinct_dst = len(digest.get("dst_ips") or []) or len(digest.get("dst_pairs") or [])
    strength = feedback.apply(
        combined_strength(
            scale_strength(int(digest.get("count") or 1) or distinct_dst),
            subjects.staleness(subject_kind, principal, now),
            rarity_strength(0, first_seen=False),
        ),
        "hit",
        principal,
    )
    return queue.enqueue(
        kind="hit",
        subject_kind=subject_kind,
        subject=principal,
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
        item_kind = str(item.get("subject_kind") or "asset")
        stale = subjects.staleness(item_kind, str(item.get("subject") or ""), now)
        strength = feedback.apply(
            combined_strength(stale * 0.35, 0.05), "coverage", str(item.get("subject") or "")
        )
        # 冷启动保护：盲区线索同样压到高强度档之下
        strength = cold_start_mod.damped(strength, client)
        result = queue.enqueue(
            kind="coverage",
            # C4/C2：盲区主体保留原类型（signature 的盲区任务还是 signature），
            # 一律写成 asset 会让"签名覆盖率"算到资产头上，口径全歪
            subject_kind=item_kind,
            subject=str(item.get("subject") or ""),
            strength=strength,
            feature="coverage",
            hint={
                "事实": f"{item.get('why')}（近 {params.coverage_stale_days()} 天可见 {item.get('seen_count')} 次）",
                "首次出现": item.get("first_seen_at"),
                "上次分析": item.get("last_analyzed_at") or "从未",
                "客观强度": strength,
                "reuse_identity": f"coverage|{item_kind}:{item.get('subject')}",
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
                "reuse_identity": f"retest|{kind_text or 'ip'}:{subject_text}",
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
