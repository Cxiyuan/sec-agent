"""账号 / 会话跨窗口长期画像（UEBA 式统计基线）。

第 8 期从智能体侧迁来（原 `agent/backend/app/agents/profile.py`）：基线是纯统计、
不需要模型，而检测器本来就逐条看到归一化事件，所以在数据产生侧算、算完随摘要打标。

- **提取**：账号（`user` 字段优先；归一化阶段已从登录路径参数兜底提取）；
  会话（从 Cookie 提取会话 id → **SHA-256 哈希**）
- **基线**：频次分布（源 IP / UA / 时段 / 路径）+ 成功失败计数，跨窗口增量累积
- **异常**：新源 IP / 新 UA / 非常用时段 / 认证失败突增 / 会话跨 IP
- **安全**：会话只存哈希；**不落库明文 cookie / 口令 / Token**
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
import time
from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from sqlalchemy import CursorResult, and_, delete, func, or_, select

from app import geoip
from app.baseline import observations, params
from app.baseline.stats import like_pattern
from app.config import settings
from app.db.base import SessionLocal
from app.db.models import AlertDisposition, EntityProfile
from app.ingestion.session_cookie import session_id_from_cookie as _shared_session_id
from app.iputil import is_public_ip
from app.schemas import UnifiedLog

UTC = timezone.utc
from app.workers.log import get_logger

log = get_logger(__name__)

ACCOUNT = "account"
SESSION = "session"

# 基线分布各字段保留的条目上限（避免 JSON 无限膨胀）
_LIMITS: dict[str, int] = {
    "src_ips": 50,
    "dst_ips": 30,
    "user_agents": 20,
    "paths": 30,
    "hour_hist": 24,
}
# `_LIMITS` 的键是**落库列名**（`hour_hist` 列对的是观测桶里的 `hours`），
# 这里给出列名 -> 观测桶字段的映射，剪枝与落库共用同一份上限。
_BUCKET_FIELDS: dict[str, str] = {
    "src_ips": "src_ips",
    "dst_ips": "dst_ips",
    "user_agents": "user_agents",
    "paths": "paths",
    "hour_hist": "hours",
}
#: 时段基线**一律按北京时间**统计。
#: 为什么不直接用 `entry.ts.hour`：事件时间戳是 UTC（归一化产物），直接取 .hour 得到的是
#: UTC 小时，而界面（时间线、日志时间、分区线）全部按北京时间展示 —— 差 8 小时的
#: 「非常用时段」等于胡说。实机证据：账号 2601125122 报「非常用时段：5 时」，
#: 它北京时间根本没有 5 时活动（那是 UTC 5 时 = 北京 13 时）。
BEIJING_TZ = timezone(timedelta(hours=8))


def beijing_hour(ts: datetime) -> int:
    """把事件时间转成北京时间的小时（0-23）。naive 时间按 UTC 处理。"""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(BEIJING_TZ).hour


# 窗口内的 Counter 也设个上限：一个窗口里同一实体可能撞出成千上万个路径，
# 落库时才裁剪就晚了（内存先炸）。超出这个倍数就先裁一次，保留 top N。
_TRIM_FACTOR = 4


def _csv(value: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in (value or "").split(",") if x.strip())


def _v6_prefix(ip: str) -> str:
    """取 IPv6 的 /64 前缀。

    为什么需要：IPv6 隐私扩展地址（RFC 4941）会在同一 /64 里不断轮换新地址，
    「没见过这个地址」并不等于「换了客户端」。所以 v6 只在**前缀**也新时才算新源 IP。
    """
    try:
        return str(ipaddress.IPv6Network(f"{ip}/64", strict=False))
    except ValueError:
        return str(ip)


def _v4_prefix(ip: str) -> str:
    """取 IPv4 的 /24 网段。

    为什么：会话跨 IP 判据原来数「同族里有几个不同地址」，而移动网/负载均衡在**同一个 /24**
    里换地址是常态 —— 实测抽查 200 条高风险会话，36 条是「跨 2~3 个同族源 IP（疑似会话劫持）」，
    绝大多数是这种同网段切换。压到 /24（v6 压到 /64）后，只有真正跨网段才算跨 IP。
    """
    try:
        return str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
    except ValueError:
        return str(ip)


def _families(ips: Iterable[str]) -> tuple[set[str], set[str]]:
    """把地址按 v4 / v6 分开。

    为什么要分：同一个客户端在双栈网络（移动端尤甚）会同时用 v4 与 v6 访问，
    把「v4+v6 各一个」当成「会话跨 2 个源 IP（疑似会话劫持）」是纯误报——
    2026-10 实机 QA：被判会话劫持的 5 条**全部**是这种双栈（或 v6 换地址），
    没有一条是真的多 IPv4。所以「跨 IP」只在**同族内** ≥ 2 个时才成立。
    """
    v4: set[str] = set()
    v6: set[str] = set()
    for ip in ips:
        text = str(ip)
        (v6 if ":" in text else v4).add(text)
    return v4, v6


_path_regex_cache: dict[tuple[str, str], tuple[re.Pattern[str] | None, re.Pattern[str] | None]] = {}


def _build_regex(pattern: str) -> re.Pattern[str] | None:
    text = (pattern or "").strip()
    if not text:
        return None
    try:
        return re.compile(text)
    except re.error:
        log.warning("路径正则写错了，已忽略：%r", text)
        return None


def _path_regexes() -> tuple[re.Pattern[str] | None, re.Pattern[str] | None]:
    """（include, exclude）两个路径正则；空字符串 = 那一步不过滤。

    缓存键就是两个正则文本：后台「行为分析」页改完参数后再调就是新键，不需要显式失效。
    （原先是 `lru_cache`，改了配置必须重启进程才生效。）
    """
    key = (params.path_include_regex(), params.path_exclude_regex())
    cached = _path_regex_cache.get(key)
    if cached is not None:
        return cached
    built = (_build_regex(key[0]), _build_regex(key[1]))
    if len(_path_regex_cache) > 32:  # 反复改配置会积旧键，给个上限
        _path_regex_cache.clear()
    _path_regex_cache[key] = built
    return built


def api_path(path: str) -> bool:
    """这条路径要不要计进画像（只留接口、排掉静态资源与页面）。

    为什么要排：前端 js/css/图片/字体访问次数天然最多，会把 30 条上限占满
    （2026-10 实机：会话画像的 paths 里全是前端 js 与字体，如 /static/app.js、
    /assets/font.woff2），有价值的接口路径反而被挤出去。两个正则都能在配置里改；
    默认**只用排除名单**（include 为空），因为实测真实接口不一定会带 `/api/`。
    """
    text = (path or "").strip()
    if not text:
        return False
    include, exclude = _path_regexes()
    if include is not None and not include.search(text):
        return False
    return not (exclude is not None and exclude.search(text))


# 认证失败突增的分档权重（用户 2026-10 定的口径）。
# 为什么要分档：原来固定 +0.25，而异常阈值是 0.6 —— **单条永远到不了阈值**，
# 真爆破只要没伴随新 IP/新 UA（同台机器、同一 UA 一直试）就报不出来（漏报）。
# 分档后「≥20 次且零成功」单独就过阈值（这类形态基本就是脚本在撞），
# 而「输错几次」仍然只是 0.25，不放大误报。
#: 认证失败分档（阈值下限, 是否要求零成功, 分值）。
#:
#: 最高档必须**高于** `profile.risk_threshold`（默认 0.75）：26 次失败零成功是几乎不可能
#: 误报的真信号（G7 用例），阈值上移后若它仍取 0.6 就会被一起压掉 —— 2026-10 调参时踩到过。
_FAIL_BANDS: tuple[tuple[int, bool, float], ...] = (
    (20, True, 0.8),  # ≥20 次且一次没成功 → 单独过线（真爆破/撞库）
    # ≥10 次：单独 0.45 够不到阈值（压误报），但配上「新源 IP」(0.35) 两个中等信号叠加 = 0.8 过线
    (10, False, 0.45),
    (5, False, 0.25),  # ≥5 次：只作为辅助证据
)


#: 信号层级（2026-10 误报治理）。
#: 实测背景：线上 1,826 个风险实体里 **1,688 个是「新源 IP(0.35) + 新接口路径(0.25) = 0.60」**
#: 正好凑到阈值 —— 换台设备 + 调个新接口这种完全正常的组合也会报。
#: 加和式打分的根本问题：三个弱信号 ≈ 一个强信号。改成按层级聚合：
#:   HIGH（会话跨 IP / 零成功爆破 / 错误响应突增）**单独即可达阈值**；
#:   MED（新源 IP、未到零成功的失败突增）可叠加，但不能单独越线；
#:   LOW（新 UA / 新路径 / 非常用时段）**组合打折 + 封顶在阈值以下**。
HIGH = 3
MED = 2
LOW = 1


#: 信号定义：`code → (似然比参数, 相关组)`。
#:
#: 为什么要有 code：原来的 `hits` 只有 (层级, 分值)，算得出"分数"但算不出"概率"，
#: 也无法表达"这几个信号其实是一件事"。code 把"给机器算的信号"和"给人看的中文理由"分开。
#:
#: 为什么按组去相关：`new_src_ip` / `cross_ip` / `new_ua` 本质都是「换设备」，
#: 朴素独立相加会把证据放大约 2~3 倍，正好把 OA 换手机的正常行为又推回阈值。
#: 组内取最大 LLR（取最有力的那条证据），**组间**才相加。
#:
#: 先验概率刻意保守（`p_mal` 是行业经验值而非本环境实测）：有标注数据后由 L4 校准替换。
#: 各组取「最有力的那条证据」（组内取最大 LLR），组间才相加。
#:
#: 参数标定目标（既有守卫用例 `tests/py/test_baseline_posterior.py` 钉住，改这里必须一起改）：
#: 默认先验 0.001（logit≈-6.91）+ 后验阈值 0.05（logit≈-2.94）⇒ 需要 **总 LLR ≥ 3.96** 才告警。
#: 于是三层语义与旧的层级加和打分完全一致：
#:   HIGH 单独越线（cross_ip 4.32 / error_surge 4.40 / fail_burst_hard 5.14）；
#:   MED 单独不够（new_src_ip 1.32 / fail_burst 2.80），但 MED+MED=4.12 过线；
#:   弱信号合成一组（weak），组内只取最大（new_path 0.92），MED+weak=3.72 仍不过线
#:   —— 保证「换手机 + 装 App + 换个钟点」这类弱信号叠加永远不告警。
_SIGNALS: dict[str, tuple[str, float, float]] = {
    # code                group      p(信号|恶意)  p(信号|良性)
    "cross_ip": ("network", 0.60, 0.008),
    "new_src_ip": ("network", 0.30, 0.08),
    "error_surge": ("network", 0.65, 0.008),
    "new_ua": ("weak", 0.25, 0.12),
    "new_path": ("weak", 0.20, 0.08),
    "unusual_hour": ("weak", 0.30, 0.15),
    "fail_burst": ("auth", 0.70, 0.0425),
    "fail_burst_hard": ("auth", 0.85, 0.005),
}


def _llr(code: str) -> float:
    entry = _SIGNALS.get(code)
    if entry is None:
        return 0.0
    _group, p_mal, p_ben = entry
    if p_ben <= 0 or p_mal <= 0:
        return 0.0
    return math.log(p_mal / p_ben)


def posterior_of(codes: list[str]) -> dict[str, Any]:
    """把信号码聚合为**后验概率**（组内取最大、组间相加 + 先验）。

    返回 `{"posterior": 0~1, "llr": n, "groups": {组: (code, llr)}, "contributions": {...}}`。
    与加和分相比，概率语义带来的好处：不同实体的分数**可以按大小排序**（旧的加和分
    只要有强信号就顶到 1.0，1,833 个过线会话里 TOP 全是 1.0，等于没有优先级）。
    """
    best: dict[str, tuple[str, float]] = {}
    contributions: dict[str, float] = {}
    for code in codes:
        entry = _SIGNALS.get(code)
        if entry is None:
            continue
        group = entry[0]
        llr = _llr(code)
        contributions[code] = round(llr, 3)
        current = best.get(group)
        if current is None or llr > current[1]:
            best[group] = (code, llr)
    total = sum(llr for _code, llr in best.values())
    raw_prior = params.knob("profile.prior_odds")
    prior = float(raw_prior) if isinstance(raw_prior, (int, float)) else 1e-3
    prior = max(1e-9, min(1 - 1e-9, prior))
    log_prior = math.log(prior / (1.0 - prior))
    logit = total + log_prior
    # 数值稳定：logit 很大时直接取 1
    posterior = 1.0 / (1.0 + math.exp(-max(-700.0, min(700.0, logit))))
    return {
        "posterior": round(posterior, 6),
        "llr": round(total, 3),
        "groups": {g: code for g, (code, _llr_) in best.items()},
        "contributions": contributions,
    }


def score_risk(hits: list[tuple[int, float]]) -> float:
    """把 (层级, 分值) 聚合成 0~1 的风险分（单调、可解释）。"""
    threshold = params.risk_threshold()
    damping = params.signal_damping()
    high = [w for tier, w in hits if tier == HIGH]
    med = [w for tier, w in hits if tier == MED]
    low = [w for tier, w in hits if tier == LOW]
    if high:
        # 强信号：抬到阈值；多个强信号再逐级加分
        risk = max(threshold, max(high)) + 0.1 * (len(high) - 1)
        return min(1.0, round(risk + sum(med) + sum(low) * damping, 2))
    if len(med) >= 2:
        # 两个中等信号互相印证 → 可以达阈值（如「失败突增 + 新源 IP」）
        return min(1.0, round(sum(med) + sum(low) * damping, 2))
    if med:
        # 只有**一个**中等信号：跟弱信号一起也必须封顶在阈值下
        # （否则「新源 IP + 新 UA + 新路径」= 0.62 又成了"换手机+装 App"就报）
        return min(
            round(sum(med) + sum(low) * damping, 2),
            round(threshold * params.weak_cap_ratio(), 2),
        )
    # 只有弱信号：打折，且**封顶在阈值以下**（本次修复的核心：弱信号叠加永不过线）
    return min(
        round(sum(low) * damping, 2),
        round(threshold * params.weak_cap_ratio(), 2),
    )


def fail_burst_score(fail: int, success: int) -> tuple[float, str]:
    """认证失败突增的分值：返回（分值, 理由后缀）。达不到最低档返回 (0.0, "")。

    门槛与原来一致：失败 ≥5 且多于成功；最高档额外要求「零成功」。
    """
    fails = max(0, int(fail or 0))
    wins = max(0, int(success or 0))
    if fails < 5 or fails <= wins:
        return 0.0, ""
    for floor, need_zero_success, score in _FAIL_BANDS:
        if fails >= floor and (not need_zero_success or wins == 0):
            suffix = "—— 疑似爆破/撞库（一次都没成功）" if need_zero_success else ""
            return score, suffix
    return 0.0, ""


def _old_enough(profile: EntityProfile) -> bool:
    """画像建立是否已满 `profile_hour_min_age_hours` 小时。"""
    min_hours = max(0, int(params.hour_min_age_hours()))
    if min_hours <= 0:
        return True
    first = profile.first_seen
    if first is None:
        return False
    if first.tzinfo is None:
        first = first.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - first >= timedelta(hours=min_hours)


def _safe_int(value: Any, default: int = 0) -> int:
    """安全转 int（JSONB 里可能是 None / 非数值）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ---------- 实体提取 ----------


def session_id_from_cookie(cookie: str) -> str:
    """从 Cookie 串中按配置的会话 cookie 名提取会话 id 值。

    实现在 `ingestion/session_cookie.py`（**唯一事实来源**）：同一份逻辑也被内置
    「会话跨IP复用」的判据用，避免「会话实体」与「会话劫持判据」两处实现漂移。
    """
    return _shared_session_id(cookie, settings.session_cookie_names)


def session_entity(cookie: str) -> tuple[str, str]:
    """返回 (entity_key=哈希, display=前 8 位)；无法识别返回 ("", "")。"""
    sid = session_id_from_cookie(cookie)
    if not sid:
        return "", ""
    digest = hashlib.sha256(sid.encode("utf-8", errors="ignore")).hexdigest()
    return digest, digest[:8]


def device_entity(entry: UnifiedLog) -> tuple[str, str]:
    """设备实体：`UA + TLS 指纹（JA3/JA4）` → 哈希。返回 (entity_key, display)。

    为什么要按设备而不是按 cookie 建会话画像（2026-10 实测）：
    会话实体原来按 cookie 值建键，而 cookie 会轮换、每个短命会话都是新实体 ——
    实测 **10.3 万个会话画像 vs 1,876 个账号画像**，绝大多数实体只被观测过一两个窗口，
    画像越多的实体越不可信（刚学完就开始判，跨 IP/失败稍多就过线）。
    同一台设备换个 cookie 不是"新实体"，是同一个东西的又一次会话。
    """
    # 用 getattr 容错：主机类事件/老文档可能没有 TLS 字段，不能让取值抛异常
    ua = str(getattr(entry, "user_agent", "") or "").strip()
    ja3 = str(getattr(entry, "ja3", "") or getattr(entry, "ja4", "") or "").strip()
    if not ua and not ja3:
        return "", ""
    digest = hashlib.sha256(f"{ua}\n{ja3}".encode("utf-8", errors="ignore")).hexdigest()
    return digest, f"设备 {digest[:8]}"


def account_entity(entry: UnifiedLog) -> str:
    """账号：归一化阶段已做提取（`user` 字段优先，其次登录路径参数）。"""
    return (entry.account or entry.user or "").strip()[:128]


def account_display(entry: UnifiedLog) -> str:
    """账号展示名：代理认证的"终端 ID"要标来源，否则运维只会看到一串像乱码的数字。

    （实机例子：`t14919610950627` 是校园出口代理 `Proxy-Authorization: Basic` 里的用户名。）
    """
    name = account_entity(entry)
    if name and str(getattr(entry, "account_source", "") or "") == "proxy_auth":
        return f"{name}（代理认证）"
    return name


# ---------- 窗口观测聚合 ----------


def _new_bucket(kind: str, key: str, display: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "key": key,
        "display": display,
        "src_ips": Counter(),
        "dst_ips": Counter(),
        "user_agents": Counter(),
        "paths": Counter(),
        "hours": Counter(),
        "success": 0,
        "fail": 0,
        # 4xx/5xx 里除认证失败之外的错误（404 风暴这类扫描痕迹）
        "errors": 0,
        "count": 0,
    }


#: 认证类日志（没有 HTTP 路径，但语义上就是"一次认证尝试"）
_AUTH_LOG_TYPES = frozenset({"ssh", "mysql", "radius", "ftp", "smtp", "ldap", "smb_mapping"})

_login_regex_cache: list[re.Pattern[str] | None] = []


def _login_path_regex() -> re.Pattern[str] | None:
    if not _login_regex_cache:
        try:
            _login_regex_cache.append(re.compile(settings.web_login_path_regex))
        except re.error:
            _login_regex_cache.append(re.compile(r"(?i)/(login|signin|auth)"))
    return _login_regex_cache[0]


def _is_auth_request(entry: UnifiedLog) -> bool:
    """这条事件算不算「一次认证尝试」（认证失败突增只在认证请求上才有意义）。

    为什么必须限定：成功原来统计**所有** <400 请求（含图片/静态/接口），一个活跃会话
    的成功数动辄成百上千 —— 失败:成功 的比例被稀释到几乎永不触发「认证失败突增」。
    """
    path = str(entry.uri_path or "")
    if path:
        pattern = _login_path_regex()
        return bool(pattern and pattern.search(path))
    return str(entry.log_type or "") in _AUTH_LOG_TYPES


def _accumulate(bucket: dict[str, Any], entry: UnifiedLog) -> None:
    bucket["count"] += 1
    # 源 IP 优先用代理头解析出的真实客户端 IP（real_client_ip），没有才用 TCP 对端：
    # 经反向代理进来的流量，画像要统计真实客户端，而不是代理地址。
    client_ip = entry.real_client_ip or entry.src_ip
    if client_ip:
        bucket["src_ips"][str(client_ip)] += 1
    # 服务端 IP（被访问的监控资产）：界面要展示「账号 + 关联服务端 IP」，
    # 让运维能直接看出「哪个账号在哪台服务器上活动」。
    if entry.dst_ip:
        bucket["dst_ips"][str(entry.dst_ip)] += 1
    if entry.user_agent:
        bucket["user_agents"][entry.user_agent[:128]] += 1
    # 路径只收接口形态（静态资源会让 30 条上限满掉，见 api_path 的说明）
    if entry.uri_path and api_path(entry.uri_path):
        bucket["paths"][entry.uri_path[:128]] += 1
    bucket["hours"][str(beijing_hour(entry.ts))] += 1
    if entry.status_code:
        if entry.status_code in (401, 403):
            # 认证失败：只认认证请求（登录路径 / ssh·mysql 这类认证日志）
            if _is_auth_request(entry):
                bucket["fail"] += 1
        elif entry.status_code < 400:
            # 成功也只认认证请求，否则静态资源/接口的成功把失败比例稀释掉
            if _is_auth_request(entry):
                bucket["success"] += 1
        else:
            # 4xx/5xx（除认证失败）：探测/扫描/坏链接的直接痕迹，单独计数
            bucket["errors"] += 1


def _trim(bucket: dict[str, Any]) -> None:
    """窗口内的分布先裁一刀，别等落库（内存优先）。"""
    for column, limit in _LIMITS.items():
        field = _BUCKET_FIELDS.get(column, column)
        counter = bucket.get(field)
        if not isinstance(counter, Counter) or len(counter) <= limit * _TRIM_FACTOR:
            continue
        bucket[field] = Counter(dict(counter.most_common(limit)))


def observe_entry(buckets: dict[str, dict[str, Any]], entry: UnifiedLog) -> int:
    """把一条事件并进观测桶，返回并入的实体数（账号 / 会话各算一个）。

    引擎逐条调用它（`app/baseline/engine.py`），所以这里不做任何 I/O。
    """
    added = 0
    account = account_entity(entry)
    if account:
        bucket_key = f"{ACCOUNT}|{account}"
        bucket = buckets.get(bucket_key)
        if bucket is None:
            bucket = buckets[bucket_key] = _new_bucket(
                ACCOUNT, account, account_display(entry) or account
            )
        _accumulate(bucket, entry)
        _trim(bucket)
        added += 1

    skey, sdisplay = session_entity(entry.cookie)
    if params.entity_key() == "device":
        # 设备维度优先：同一台设备的会话归到一个实体（cookie 轮换不再拆成多个画像）。
        # 取不到 UA/JA3 时回落到 cookie —— 宁可多一个画像，也不要丢掉这条观测。
        dkey, ddisplay = device_entity(entry)
        if dkey:
            skey, sdisplay = dkey, ddisplay
    if skey:
        bucket_key = f"{SESSION}|{skey}"
        bucket = buckets.get(bucket_key)
        if bucket is None:
            bucket = buckets[bucket_key] = _new_bucket(SESSION, skey, sdisplay)
        _accumulate(bucket, entry)
        _trim(bucket)
        added += 1
    return added


# ---------- 读画像 ----------


def load_profiles(keys: list[tuple[str, str]]) -> dict[str, EntityProfile]:
    """按 (kind, key) 批量读取画像。"""
    pairs = keys[:500]
    if not pairs:
        return {}
    conds = [
        and_(EntityProfile.kind == kind, EntityProfile.entity_key == key) for kind, key in pairs
    ]
    try:
        with SessionLocal() as db:
            rows = db.scalars(select(EntityProfile).where(or_(*conds))).all()
    except Exception as exc:  # noqa: BLE001
        log.warning("读取实体画像失败: %s", exc)
        return {}
    return {f"{r.kind}|{r.entity_key}": r for r in rows}


# ---------- 异常判定 ----------


#: 共享出口判定用的 Redis 客户端（由引擎注入；没有就退化成只看「存满上限」）
_rarity_client: Any = None


def set_client(client: Any) -> None:
    """注入 Redis 客户端（引擎初始化时调用；画像模块本身不做 I/O 初始化）。"""
    global _rarity_client
    _rarity_client = client


def _prefix_shared(prefix: str, entity_key: str) -> bool:
    """该 /24（v6 /64）是不是**共享出口**：当天出现过足够多不同实体就算。

    为什么要判：移动网、公司 NAT 出口、反向代理的 /24 里能同时出现几十个账号，
    「这个账号从新的 /24 来」在这种网段上根本不是信号（实测移动用户 4G/WiFi 切换即触发）。
    用 HLL 记当天实体集合，误差 ~0.8%，对「够不够 20 个」这种判断绰绰有余。
    """
    if _rarity_client is None or not params.ip_rarity_enabled():
        return False
    if not prefix or not entity_key:
        return False
    day = datetime.now(UTC).strftime("%Y%m%d")
    cache_key = f"shentong:profile:rarity:{day}:{prefix}"
    try:
        _rarity_client.pfadd(cache_key, entity_key)
        _rarity_client.expire(cache_key, 172800)  # 两天：跳天边界不用重算
        return int(_rarity_client.pfcount(cache_key)) >= params.ip_rarity_min_entities()
    except Exception as exc:  # noqa: BLE001 — 判不出来时按「不是共享出口」处理（保守）
        log.debug("共享出口判定失败（按不是处理）: %s", exc)
        return False


def _established(values: Any) -> int:
    """「已确立」的值的种数：见过 >= `profile.novelty_max_count` 次才算。

    只数已确立的，是为了让「一次性出现的一堆值」（爬虫路径、随机探针）不会把
    高基数降级提前触发掉。
    """
    threshold = params.novelty_max_count()
    counter = values or {}
    try:
        return sum(1 for v in counter.values() if _safe_int(v) >= threshold)
    except AttributeError:
        return 0


#: 误报标注缓存（进程内，短 TTL）：detect() 每个窗口每个实体都会问一次，
#: 直接查库会把 PG 打爆；标注是低频动作，45 秒延迟完全可以接受。
_SUPPRESS_TTL = 45.0
_SUPPRESS_CAP = 20000
_suppressed_cache: dict[str, tuple[float, frozenset[str]]] = {}


def invalidate_suppressed(kind: str, entity_key: str) -> None:
    """标注之后立刻失效缓存（不然要等 TTL 才生效）。"""
    _suppressed_cache.pop(f"{kind}|{entity_key}", None)


def load_suppressed(kind: str, entity_key: str) -> set[str]:
    """取该实体近 N 天被判"误报"的信号码；`*` 表示整条告警被否。

    降权口径（`profile.false_positive_suppress_days`，默认 7 天）：
    运维说"这条是误报"，就不该下周还在报同一条 —— 但也不能永久闭嘴（业务会变），
    所以用时间窗，而不是一票否决到底。
    """
    if not kind or not entity_key:
        return set()
    cache_key = f"{kind}|{entity_key}"
    now = time.monotonic()
    hit = _suppressed_cache.get(cache_key)
    if hit and now - hit[0] <= _SUPPRESS_TTL:
        return set(hit[1])
    days = max(0, int(params.knob("profile.false_positive_suppress_days") or 0))
    if days <= 0:
        _suppressed_cache[cache_key] = (now, frozenset())
        return set()
    since = datetime.now(UTC) - timedelta(days=days)
    found: set[str] = set()
    try:
        with SessionLocal() as db:
            rows = db.scalars(
                select(AlertDisposition).where(
                    AlertDisposition.kind == kind,
                    AlertDisposition.entity_key == entity_key,
                    AlertDisposition.verdict == "false_positive",
                    AlertDisposition.created_at >= since,
                )
            ).all()
            for row in rows:
                found.add(str(row.signal or "") or "*")
    except Exception as exc:  # noqa: BLE001 — 读不到标注不能挡住检测
        log.debug("读取误报标注失败（本次不降权）: %s", exc)
    if len(_suppressed_cache) >= _SUPPRESS_CAP:
        _suppressed_cache.clear()
    _suppressed_cache[cache_key] = (now, frozenset(found))
    return found


def record_disposition(
    kind: str,
    entity_key: str,
    verdict: str,
    *,
    signal: str = "",
    operator: str = "",
    note: str = "",
) -> dict[str, Any]:
    """写一条处置标注（`false_positive` / `confirm`），并让降权缓存立即失效。"""
    verdict = "confirm" if str(verdict).strip().lower() == "confirm" else "false_positive"
    row = AlertDisposition(
        kind=str(kind or "")[:16],
        entity_key=str(entity_key or "")[:128],
        signal=str(signal or "")[:48],
        verdict=verdict,
        operator=str(operator or "")[:64],
        note=str(note or "")[:500],
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        db.refresh(row)
        out = {
            "id": str(row.id),
            "kind": row.kind,
            "entity_key": row.entity_key,
            "signal": row.signal,
            "verdict": row.verdict,
            "operator": row.operator,
            "note": row.note,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
    invalidate_suppressed(row.kind, row.entity_key)
    return out


def disposition_for(
    profile_ref: str,
    verdict: str,
    *,
    signal: str = "",
    note: str = "",
    operator: str = "",
) -> dict[str, Any]:
    """按画像 UUID **或实体键**处置一条画像告警（界面与智能体共用同一份解析）。

    为什么两个都收：界面手里是 UUID，智能体手里往往只有 `entity_profile` 返回的实体键
    （账号名 / 设备哈希），不该逼它先查一次库再写。
    找不到时返回 `{"error": ...}`，由调用方决定回 404 还是报错给模型。
    """
    ref = str(profile_ref or "").strip()
    if not ref:
        return {"error": "要 profile_id 或实体键"}
    with SessionLocal() as db:
        row = db.get(EntityProfile, ref)
        if row is None:
            row = db.scalars(
                select(EntityProfile).where(EntityProfile.entity_key == ref).limit(1)
            ).first()
        if row is None:
            return {"error": f"画像不存在：{ref[:64]}"}
        kind = str(row.kind or "")
        entity_key = str(row.entity_key or "")
    out = record_disposition(
        kind, entity_key, verdict, signal=signal, operator=operator, note=note
    )
    out["kind"] = out.get("kind") or kind
    out["entity_key"] = out.get("entity_key") or entity_key
    return out


def detect(kind: str, obs: dict[str, Any], profile: EntityProfile | None) -> dict[str, Any]:
    """与长期基线比对，返回 {reasons, risk, posterior, codes, alerted, cold_start}。

    两个分数并存，用途不同：
    - `risk`：**层级加和分**（0~1，`score_risk`）。落库在 `entity_profiles.risk_score`，
      界面展示与 `min_risk` 过滤沿用它 —— 语义与改造前完全一致，回滚不动数据。
    - `posterior`：**似然比后验概率**（`posterior_of`）。可横向排序（旧的加和分只要有强信号
      就顶到 1.0，实测 1,833 个过线会话的 TOP 全是 1.0，等于没有优先级）。
    `alerted`：本窗口算不算异常。`profile.scoring=llr` 时看后验概率，`additive` 时看加和分。
    """
    # 冷启动按**窗口数**：原来按事件条数，一个实体刚来 5 条日志就参与打分，早期误报多。
    # 老画像（window_count 还是 0）由部署时的一次性回填处理，不会因此集体进冷启动。
    if profile is None or _safe_int(getattr(profile, "window_count", 0)) < params.min_windows():
        return {
            "reasons": [],
            "risk": 0.0,
            "posterior": 0.0,
            "llr": 0.0,
            "codes": [],
            "alerted": False,
            "cold_start": True,
        }

    reasons: list[str] = []
    # (层级, 分值) 收集，最后统一由 score_risk 聚合（见该函数的实测背景说明）
    hits: list[tuple[int, float]] = []
    # 信号码：同一批事实的机器可读版本，喂给 posterior_of（见 _SIGNALS 的标定说明）
    codes: list[str] = []

    known_ips = set((profile.src_ips or {}).keys())
    known_v6_prefixes = {_v6_prefix(ip) for ip in known_ips if ":" in ip}
    new_ips: list[str] = []
    for ip in obs["src_ips"]:
        ip = str(ip)
        if ip in known_ips:
            continue
        # v6 同 /64 内的新地址：同一个客户端的隐私地址轮换，不算新源 IP
        if ":" in ip and _v6_prefix(ip) in known_v6_prefixes:
            continue
        new_ips.append(ip)
    new_ips.sort()
    if new_ips:
        # 两个降权条件（P1-5，实测驱动）：
        # ① 来源地址已存满上限（销售/运维/服务账号天天从新地址来）→ 这个信号
        #    对它们**永远成立**，只能靠强信号判，不能靠"见过没见过"；
        # ② 本窗口来源地址很多而新的只占少数（多出口 / 移动网常态）→ 不构成异常。
        saturated = len(known_ips) >= _LIMITS["src_ips"]
        share = len(new_ips) / max(1, len(obs["src_ips"]))
        label = f"新源 IP：{', '.join(new_ips[:3])}"
        # ③ 该网段是共享出口（移动网/代理/NAT：当天同网段出现几十个实体）→ 新 IP 没信号量
        shared_egress = any(
            _prefix_shared(
                _v4_prefix(ip) if ":" not in ip else _v6_prefix(ip), str(profile.entity_key or "")
            )
            for ip in new_ips[:3]
        )
        if saturated:
            reasons.append(f"{label}（该实体来源地址已饱和，不计分）")
        elif shared_egress:
            reasons.append(f"{label}（该网段为共享出口，不计分）")
        elif share < params.new_ip_min_share():
            reasons.append(f"{label}（占本窗口来源地址 {share:.0%}，不计分）")
        else:
            reasons.append(label)
            hits.append((MED, 0.35))
            codes.append("new_src_ip")

    known_ua = set((profile.user_agents or {}).keys())
    new_ua = sorted(ua for ua in obs["user_agents"] if ua not in known_ua)
    if new_ua:
        # 高基数降级：已确立的 UA 种类够多 → 「新 UA」对这类实体没有信号量（看 browsers 多的人）
        if _established(profile.user_agents) >= params.high_cardinality_limit():
            reasons.append(f"新 User-Agent：{new_ua[0][:60]}（该实体 UA 种类已饱和，不计分）")
        else:
            reasons.append(f"新 User-Agent：{new_ua[0][:60]}")
            hits.append((LOW, 0.2))
            codes.append("new_ua")

    # 新接口路径：只算接口形态（静态资源已在采集时排掉），且要求画像已认识若干条路径，
    # 否则刚建的画像「第一条路径就是新的」等于白报。
    known_paths = set((profile.paths or {}).keys())
    new_paths = sorted(p for p in obs["paths"] if p not in known_paths)
    if new_paths and len(known_paths) >= max(0, int(params.path_min_known())):
        # 高基数降级：门户类站点路径成百上千，「第 51 条新路径」毫无信号量
        # （实测 200 条高风险会话里 182 条都是它）
        if _established(profile.paths) >= params.high_cardinality_limit():
            reasons.append(f"新接口路径：{', '.join(new_paths[:3])}（已知路径过多，不计分）")
        else:
            reasons.append(f"新接口路径：{', '.join(new_paths[:3])}")
            hits.append((LOW, 0.25))
            codes.append("new_path")

    # 非常用时段：三个条件都要满足才判（否则就是整点批量误报，见 config 里那两个门槛）
    hist = profile.hour_hist or {}
    total_hours = sum(_safe_int(v) for v in hist.values())
    covered = sum(1 for v in hist.values() if _safe_int(v) > 0)
    if (
        obs["hours"]
        and total_hours >= params.min_obs()
        and covered >= max(1, int(params.hour_min_coverage()))
        and _old_enough(profile)
    ):
        rare = [h for h in obs["hours"] if _safe_int(hist.get(h, 0)) / total_hours < 0.01]
        if len(rare) == len(obs["hours"]):
            reasons.append(f"非常用时段（北京时间）：{','.join(sorted(rare))} 时")
            hits.append((LOW, 0.15))
            codes.append("unusual_hour")

    if kind == SESSION:
        # 只在**同族内** ≥ 2 个才算会话跨 IP：v4+v6 是同一客户端的双栈，不是劫持
        v4, v6 = _families(obs["src_ips"])
        # 压到网段再看：同 /24（v6 /64）内的地址切换是移动网常态，不算跨 IP
        v4 = {_v4_prefix(ip) for ip in v4}
        v6 = {_v6_prefix(ip) for ip in v6}
        if len(v4) >= 2 or len(v6) >= 2:
            reasons.append(f"会话跨 {len(v4) + len(v6)} 个同族源 IP（疑似会话劫持）")
            hits.append((HIGH, 0.45))
            codes.append("cross_ip")

    # 错误响应突增：404/5xx 风暴是探测与扫描最直接的痕迹（成功/失败都看不到它）
    errors = _safe_int(obs.get("errors"))
    window_events = _safe_int(obs.get("count")) or 1
    error_ratio = errors / window_events
    if errors >= params.error_min_count() and error_ratio >= params.error_ratio():
        reasons.append(f"错误响应突增（{errors} 次，占本窗口事件 {error_ratio:.0%}）")
        hits.append((HIGH, 0.3))
        codes.append("error_surge")

    score, suffix = fail_burst_score(obs["fail"], obs["success"])
    if score > 0:
        reasons.append(f"认证失败突增（{obs['fail']} 次，成功 {obs['success']} 次）{suffix}")
        # 分档即分层：达到阈值的那一档（≥20 次零成功）是强信号，其余算中等
        hard = score >= params.risk_threshold()
        hits.append((HIGH if hard else MED, score))
        codes.append("fail_burst_hard" if hard else "fail_burst")

    # 误报闭环：运维判过"误报"的信号在时间窗内不再参与打分（`*` = 整条告警被否）。
    # 只降打分，不删理由 —— 界面上仍要看得到"为什么当初报了它"。
    suppressed = (
        load_suppressed(kind, str(profile.entity_key or "")) if profile is not None else set()
    )
    suppressed_notes: list[str] = []
    if suppressed:
        if "*" in suppressed:
            suppressed_notes.append("该告警已被标记为误报，本次不参与打分（降权期内）")
            codes = []
        else:
            kept = [c for c in codes if c not in suppressed]
            if len(kept) != len(codes):
                suppressed_notes.append(
                    "以下信号已被标记为误报，本次不参与打分：" + "、".join(sorted(suppressed))
                )
            codes = kept
    risk = score_risk(hits)
    posterior = posterior_of(codes)
    if params.scoring() == "additive":
        # 回滚档：判据与改造前一致（层级加和分过 risk_threshold）
        alerted = risk >= params.risk_threshold()
    else:
        alerted = posterior["posterior"] >= params.posterior_threshold()
    if suppressed_notes:
        reasons = suppressed_notes + reasons
    return {
        "reasons": reasons,
        "risk": risk,
        "posterior": posterior["posterior"],
        "llr": posterior["llr"],
        "codes": codes,
        "alerted": alerted,
        "cold_start": False,
    }


def recall_from_observations(observations: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """对一批窗口观测做画像比对，返回 {entities: [...], anomalies: [...]}。

    `entities` 是「有异常理由」的全部实体（按风险降序），`anomalies` 是其中过阈值的
    （`profile_risk_threshold`）—— 后者才会被写进摘要标签。
    """
    if not params.profile_enabled() or not observations:
        return {"entities": [], "anomalies": []}

    profiles = load_profiles([(o["kind"], o["key"]) for o in observations.values()])
    entities: list[dict[str, Any]] = []
    for key, obs in observations.items():
        profile = profiles.get(key)
        detection = detect(obs["kind"], obs, profile)
        if not detection["reasons"]:
            continue
        entities.append(
            {
                "kind": obs["kind"],
                "key": obs["key"],
                "display": obs["display"],
                "risk": round(detection["risk"], 3),
                # 后验概率：可横向排序的那个分数（见 detect 的说明）
                "posterior": round(float(detection.get("posterior") or 0.0), 6),
                "alerted": bool(detection.get("alerted")),
                "reasons": detection["reasons"],
                "obs_count": _safe_int(profile.obs_count) if profile else 0,
                "src_ips": sorted(obs["src_ips"].keys())[:5],
                "dst_ips": sorted(obs["dst_ips"].keys())[:5],
                "count": obs["count"],
            }
        )
    entities.sort(key=lambda x: -x["risk"])
    return {
        "entities": entities,
        "anomalies": [e for e in entities if e["alerted"]],
    }


# ---------- 基线更新 ----------


def _merge(base: Any, add: Counter, limit: int) -> dict[str, int]:
    merged: dict[str, int] = {str(k): _safe_int(v) for k, v in dict(base or {}).items()}
    for key, value in add.items():
        merged[str(key)] = merged.get(str(key), 0) + _safe_int(value)
    return dict(sorted(merged.items(), key=lambda item: -item[1])[:limit])


def _kept_paths(paths: Any) -> dict[str, int]:
    """把库里已有的路径按当前口径再过一遗（自愈）。

    为什么要过：口径是后加上的，老库里已经存了一堆静态资源路径（实测某环境有 5237 条
    不含 `/api/` 的旧值：.css/.png/页面）。合并前先剔掉，否则 30 条上限永远被它们占着，
    新口径等于没生效。（不需要额外的数据迁移：每个画像被再次观测时就自愈一次。）
    """
    return {k: _safe_int(v) for k, v in dict(paths or {}).items() if api_path(k)}



def _account_facts(obs: dict[str, Any], row: EntityProfile, now: datetime) -> None:
    """账号窗口观测 → 客观事实（爆破 / 异地），判断权在智能体。

    口径（2026-10 用户定）：
    - 地理只比**国家 + 省**，基准是**上一次成功登录**的公网 IP 位置；
    - 失败登录也生成事实，但**不更新**基准；
    - 局域网登录只标记（src 在内网），不比较、不更新。
    """
    srcs = {str(ip): int(n) for ip, n in (obs.get("src_ips") or {}).items()}
    public = {ip: n for ip, n in srcs.items() if is_public_ip(ip)}
    fails = int(obs.get("fail") or 0)
    success = int(obs.get("success") or 0)
    key = str(row.entity_key or "")

    # 1) 同账号、多公网来源的失败登录（分布式爆破）
    if fails >= params.brute_account_fails() and len(public) >= params.brute_account_ips():
        observations.emit(
            "login_bruteforce",
            "account",
            key,
            {
                "窗口失败次数": fails,
                "来源公网 IP 数": len(public),
                "来源示例": sorted(public.keys())[:5],
                "说明": "同一账号在短时间内被多个公网来源尝试登录（失败）",
            },
            key="bruteforce",
            now=now,
        )

    # 2) 异地登录：与上一次成功登录的位置比（国家+省）
    if not params.geo_enabled() or not public:
        return
    ip = max(public.items(), key=lambda kv: kv[1])[0]
    current = geoip.locate(ip)
    if current.get("lan") or not current.get("country"):
        return
    previous = dict(row.last_geo or {})
    if previous.get("country") and not geoip.same_place(previous, current):
        observations.emit(
            "geo_jump",
            "account",
            key,
            {
                "上次登录地点": previous.get("label") or previous.get("province") or previous.get("country"),
                "上次登录时间": previous.get("at") or "",
                "本次登录地点": current.get("label"),
                "本次来源 IP": ip,
                "本次结果": "成功" if success > 0 else "失败",
                "说明": "同一账号的登录地点发生了变化（只比国家+省，不含时间阈值）",
            },
            key="geo",
            now=now,
        )
    # 只有**成功登录**才更新基准；失败不回写（否则爆破会把基准带着跑）
    if success > 0:
        row.last_geo = {
            "country": current.get("country") or "",
            "province": current.get("province") or "",
            "city": current.get("city") or "",
            "label": current.get("label") or "",
            "ip": ip,
            "at": now.isoformat(),
        }


def update_profiles(
    observations: dict[str, dict[str, Any]],
    risks: dict[str, dict[str, Any]] | None = None,
) -> dict[str, int]:
    """把本窗口观测并入画像基线（增量累积），并回写本轮异常风险分。

    risks：key = f"{kind}|{key}"，值含 {risk, reasons}（来自 `recall_from_observations`）；
    回写后按风险排序的列表与 TOP 才生效。
    """
    if not observations or not params.profile_enabled():
        return {"created": 0, "updated": 0}
    now = datetime.now(timezone.utc)
    created = updated = 0
    try:
        with SessionLocal() as db:
            for obs in observations.values():
                row = db.scalars(
                    select(EntityProfile).where(
                        EntityProfile.kind == obs["kind"],
                        EntityProfile.entity_key == obs["key"],
                    )
                ).first()
                if row is None:
                    row = EntityProfile(
                        kind=obs["kind"],
                        entity_key=obs["key"],
                        entity_display=obs["display"],
                        first_seen=now,
                    )
                    db.add(row)
                    created += 1
                else:
                    updated += 1
                if obs["display"]:
                    row.entity_display = obs["display"]
                row.obs_count = (row.obs_count or 0) + _safe_int(obs["count"])
                row.last_seen = now
                row.src_ips = _merge(row.src_ips, obs["src_ips"], _LIMITS["src_ips"])
                # 账号级事实：多来源爆破 / 异地登录（只产出事实，不下结论）
                if obs["kind"] == ACCOUNT:
                    _account_facts(obs, row, now)
                row.dst_ips = _merge(row.dst_ips, obs["dst_ips"], _LIMITS["dst_ips"])
                row.user_agents = _merge(
                    row.user_agents, obs["user_agents"], _LIMITS["user_agents"]
                )
                row.paths = _merge(_kept_paths(row.paths), obs["paths"], _LIMITS["paths"])
                row.hour_hist = _merge(row.hour_hist, obs["hours"], _LIMITS["hour_hist"])
                row.success_count = (row.success_count or 0) + _safe_int(obs["success"])
                row.fail_count = (row.fail_count or 0) + _safe_int(obs["fail"])
                row.error_count = (row.error_count or 0) + _safe_int(obs.get("errors"))
                # 每落库一次算「被观测到一个窗口」（冷启动门槛按它算）
                row.window_count = (row.window_count or 0) + 1

                # 回写本轮异常风险（供列表排序与 TOP）：**本轮没理由就归零**。
                # 不归零的后果（2026-10 实机 QA）：实体一旦被报过就永久挂在「画像风险 TOP」，
                # 实测 4 条 risk≥0.6 的画像已 2~4 小时没再出现，界面仍当当前风险看。
                risk = (risks or {}).get(f"{obs['kind']}|{obs['key']}") or {}
                if risk:
                    row.risk_score = float(risk.get("risk") or 0.0)
                    row.posterior = float(risk.get("posterior") or 0.0)
                    row.anomalies = list(risk.get("reasons") or [])[:20]
                    row.risk_at = now
                else:
                    row.risk_score = 0.0
                    row.posterior = 0.0
                    row.anomalies = []
                    # 风险时间跟着归零：只保留「当前风险」的判定时间，避免陈旧时间被当新时间
                    row.risk_at = None
            db.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("更新实体画像失败: %s", exc)
    return {"created": created, "updated": updated}


def cleanup() -> dict[str, int]:
    """清理长期无观测的画像，并顺手把不合口径的旧路径剔掉。

    为什么在这里做路径自愈：路径口径是后加上的，老库里已经存了一堆静态资源/页面路径
    （实测某环境 3934 条），它们会把 30 条上限占着。只靠「该画像又被观测到」自愈的话，
    不再活跃的画像永远不会清；放到小时级清理里，一小时内全库都会对齐，
    而且口径仍然只来自配置（不在 SQL 里重写一份正则，避免两处漂移）。
    """
    before = datetime.now(timezone.utc) - timedelta(days=params.profile_retention_days())
    # 会话画像（cookie 哈希）单独一条更短的保留期：实测 11,117 条会话画像只有 14 条过线，
    # 留太久只是把库撑大、把列表刷满。账号画像仍按 profile.retention_days。
    session_before = datetime.now(timezone.utc) - timedelta(days=params.session_retention_days())
    deleted = pruned = 0
    try:
        with SessionLocal() as db:
            result = cast(
                CursorResult[Any],
                db.execute(
                    delete(EntityProfile).where(
                        or_(
                            EntityProfile.last_seen < before,
                            and_(
                                EntityProfile.kind == SESSION,
                                EntityProfile.last_seen < session_before,
                            ),
                        )
                    )
                ),
            )
            deleted = result.rowcount or 0
            for row in db.scalars(select(EntityProfile)).all():
                current = row.paths or {}
                kept = _kept_paths(current)
                if len(kept) != len(current):
                    pruned += len(current) - len(kept)
                    row.paths = kept
            db.commit()
            return {"deleted": deleted, "pruned": pruned}
    except Exception as exc:  # noqa: BLE001
        log.warning("清理实体画像失败: %s", exc)
        return {"deleted": 0, "pruned": 0}


# ---------- 列表 ----------


def _profile_dict(p: EntityProfile) -> dict[str, Any]:
    return {
        "id": p.id,
        "kind": p.kind,
        "entity_key": p.entity_key,
        "entity_display": p.entity_display,
        "obs_count": p.obs_count,
        "risk_score": p.risk_score,
        # 后验概率（似然比打分）：与 risk_score 同时给出，界面要排序就用它
        "posterior": p.posterior,
        # 风险分的判定时间：没有它，界面无法区分「现在异常」与「几小时前的陈旧结果」
        # （`updated_at` 每轮观测都刷新，不能当风险时间用）。
        "risk_at": p.risk_at.isoformat() if p.risk_at else None,
        "first_seen": p.first_seen.isoformat() if p.first_seen else None,
        "last_seen": p.last_seen.isoformat() if p.last_seen else None,
        "src_ips": p.src_ips or {},
        # 服务端 IP（被访问的监控资产）：界面展示「账号 + 关联服务端 IP」靠它
        "dst_ips": p.dst_ips or {},
        "user_agents": p.user_agents or {},
        "paths": p.paths or {},
        "hour_hist": p.hour_hist or {},
        "success_count": p.success_count,
        "fail_count": p.fail_count,
        "error_count": p.error_count,
        "window_count": p.window_count,
        "anomalies": p.anomalies or [],
    }


def list_profiles(
    *,
    kind: str | None = None,
    keys: list[str] | None = None,
    q: str = "",
    min_risk: float = 0.0,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """画像列表（风险降序）。

    `q`：按展示名/实体键模糊搜（账号名就是展示名；会话是 cookie 哈希，只能按哈希前几位搜）。
    风险分是「当前窗口」的值，列表里也会带上 `risk_at`（判定时间）好判断新旧。
    """
    try:
        with SessionLocal() as db:
            conds = []
            if kind:
                conds.append(EntityProfile.kind == kind)
            if keys:
                # 指名道姓查几个实体（智能体问「这组 IP 关联的账号/会话画像」走这里）
                conds.append(EntityProfile.entity_key.in_(list(keys)[:500]))
            if (q or "").strip():
                pattern = like_pattern(q)
                conds.append(
                    or_(
                        EntityProfile.entity_display.ilike(pattern, escape="\\"),
                        EntityProfile.entity_key.ilike(pattern, escape="\\"),
                    )
                )
            if min_risk > 0:
                conds.append(EntityProfile.risk_score >= min_risk)

            count_q = select(func.count()).select_from(EntityProfile)
            # 排序口径跟着打分方式走：LLR 档按后验概率（有区分度），回滚档按风险分。
            # 旧的加和分只要命中强信号就顶到 1.0，1,833 个过线会话 TOP 全是 1.0，排序等于没有。
            order = (
                EntityProfile.posterior.desc()
                if params.scoring() == "llr"
                else EntityProfile.risk_score.desc()
            )
            stmt = select(EntityProfile).order_by(order)
            for cond in conds:
                count_q = count_q.where(cond)
                stmt = stmt.where(cond)
            total = db.scalar(count_q) or 0
            rows = db.scalars(stmt.limit(limit).offset(offset)).all()
    except Exception as exc:  # noqa: BLE001
        return {"error": f"读实体画像失败：{exc}", "total": 0, "items": []}
    return {"total": total, "items": [_profile_dict(r) for r in rows]}


def top_anomalies(limit: int = 10, *, kind: str | None = None) -> dict[str, Any]:
    """按风险分取 TOP（运行状态页用）。

    只取``risk_at`` 在有效期（`profile_risk_ttl_minutes`）内的：本函数是「**当前**风险」，
    不是历史榜单 —— 实测旧实现会把 2~4 小时前判过、之后再没出现过的实体一直列出来。

    `kind`：界面只传 `"account"`（会话的展示名是 cookie 哈希前 8 位，运维看不懂；
    会话画像本身仍在算，摘要标签与 MCP 调查还看得到）。
    """
    ttl = max(0, int(params.risk_ttl_minutes()))
    # 打分方式决定「过线」的判据：llr 看后验概率（可排序），additive 看层级加和分
    llr_mode = params.scoring() != "additive"
    if llr_mode:
        stmt = select(EntityProfile).where(EntityProfile.posterior >= params.posterior_threshold())
        order_by = EntityProfile.posterior.desc()
    else:
        stmt = select(EntityProfile).where(EntityProfile.risk_score >= params.risk_threshold())
        order_by = EntityProfile.risk_score.desc()
    if kind:
        stmt = stmt.where(EntityProfile.kind == kind)
    if ttl > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=ttl)
        stmt = stmt.where(EntityProfile.risk_at.is_not(None), EntityProfile.risk_at >= cutoff)
    try:
        with SessionLocal() as db:
            rows = db.scalars(
                stmt.order_by(order_by).limit(max(1, min(int(limit or 10), 100)))
            ).all()
    except Exception as exc:  # noqa: BLE001
        return {
            "threshold": params.risk_threshold(),
            "posterior_threshold": params.posterior_threshold(),
            "scoring": params.scoring(),
            "ttl_minutes": ttl,
            "items": [],
            "error": str(exc),
        }
    return {
        "threshold": params.risk_threshold(),
        "posterior_threshold": params.posterior_threshold(),
        "scoring": params.scoring(),
        "ttl_minutes": ttl,
        "items": [_profile_dict(r) for r in rows],
    }
