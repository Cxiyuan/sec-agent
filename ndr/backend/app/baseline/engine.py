"""检测器进程内的基线引擎：数值 2σ（按摘要）+ 账号/会话画像（按事件）。

放在检测器里而不是另起服务：只有持锁实例消费队列（`detector/runner.py` 的选主），
所以进程内累加是一致的，不需要分布式锁，也不引入新的常驻进程。

两个节奏：
- **逐条**（`observe`）：把在监控网段内、没被排除过滤器丢掉的每条事件并进画像观测桶；
- **周期**（`maybe_flush` → `flush`）：把观测与数值统计批量落库、判画像异常、清理过期画像。

摘要打标（`annotate`）读的是**进程内缓存**：数值基线缓存每次落库后刷新，画像异常是
最近若干轮落库时判出来的（保留 `2 × 聚合窗口`，因为摘要按聚合窗口产出，比它更旧的就没人要了）。
"""

from __future__ import annotations

import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from app.baseline import egress, observations, params, profile as profiles
from app.baseline.asset import (
    apply_window as assets_apply_window,
    cleanup as assets_cleanup,
    finalize as assets_finalize,
    judge_window as assets_judge_window,
    observe_entry as assets_observe_entry,
)
from app.baseline.poisson import bonferroni_alpha, count_p_value
from app.baseline.stats import apply_stats, cleanup as stats_cleanup, load_stats
from app.config import settings
from app.iputil import is_internal_ip
from app.schemas import UnifiedLog
from app.workers.log import get_logger

UTC = timezone.utc

log = get_logger(__name__)

# 数值基线的三个特征：与智能体侧 `_stat_features` 同源（key = f"{src_ip}:{feature}"）
_FEATURES = ("conn_count", "distinct_dst_ports", "distinct_dst_ips")
_WANT_BATCH = 200  # 缓存里没有的键攒够这么多就批量捞一次
_MAX_LABEL_ENTITIES = 6  # 单条摘要最多带几个画像异常（防止摘要膨胀）
_MAX_WINDOW_DEV = 20000  # 窗口偏离表最多留多少个 IP（超了丢最老的，计入 expired）


def _num(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


#: 组的粒度：v4 按 /24、v6 按 /64（与画像「同族来源」口径一致）
def group_prefix(ip: str) -> str:
    """把源 IP 归到「等组」：v4 → /24，v6 → /64。取不到就返回空串（不参与池化）。"""
    text = str(ip or "").strip()
    if not text or text == "-":
        return ""
    if ":" in text:
        parts = text.split(":")
        return ":".join(parts[:4]) + "::/64" if len(parts) >= 4 else ""
    octets = text.split(".")
    if len(octets) == 4:
        return ".".join(octets[:3]) + ".0/24"
    return ""


def pooled_lambda(
    own: dict[str, Any], group: dict[str, Any] | None, k: float
) -> tuple[float, float]:
    """经验贝叶斯部分池化：自身样本少时向「等组」先验收缩。

    返回 `(均值, 方差)`。`own` / `group` 都是 `{count, mean, m2, std}` 形态。
    单观测实体（n=1）几乎全用组先验 —— 这正是"48.7% 的键只被观测过 1 次"的解药。
    """
    n = _num(own.get("count"))
    own_mean = _num(own.get("mean"))
    own_var = (_num(own.get("m2")) / (n - 1)) if n >= 2 else 0.0
    if group is None or k <= 0:
        return own_mean, own_var
    gn = _num(group.get("count"))
    if gn < 2:
        return own_mean, own_var
    g_mean = _num(group.get("mean"))
    g_var = _num(group.get("m2")) / (gn - 1) if gn >= 2 else 0.0
    total = n + k
    mean = (n * own_mean + k * g_mean) / total
    # 全方差分解：组内方差加权 + 组间均值差（少了后一半，池化后方差偏小 → 假阳性）
    second = (n * (own_var + own_mean * own_mean) + k * (g_var + g_mean * g_mean)) / total
    return mean, max(0.0, second - mean * mean)


class BaselineEngine:
    """基线引擎（单写者：只有持锁的检测器实例会用它）。"""

    def __init__(self, client: Any = None) -> None:
        self._client = client
        # 画像侧「共享出口」判定要用 Redis（HLL 记每个 /24 当天的实体集合）
        profiles.set_client(client)
        self._obs: dict[str, dict[str, Any]] = {}  # 画像窗口观测（key = kind|entity）
        self._assets: dict[str, dict[str, Any]] = {}  # 被访问方窗口观测（key = Zeek 连接 uid）
        self._pending: dict[str, list[float]] = {}  # 数值基线待落库样本
        self._base: dict[str, dict[str, Any]] = {}  # 数值基线缓存（键 -> 状态）
        self._wanted: set[str] = set()  # 缓存里没有、想捞的键
        self._anomalies: dict[str, dict[str, Any]] = {}  # 最近判出的画像异常（按实体去重）
        # 窗口通道的判异结果：src -> (判定时刻, 偏离列表, 已 warm 维度数)，等摘要来取
        self._window_dev: dict[str, tuple[float, list[dict[str, Any]], int]] = {}
        self._last_flush = 0.0
        self._last_cleanup = 0.0
        # 「距上次落库攒了多少条观测」——阈值必须看它，不能看累计值 stats["observed"]：
        # 累计值一旦越过 baseline_max_observations，之后每条事件都会触发一次整批落库。
        self._obs_since_flush = 0
        self.stats: Counter[str] = Counter()

    # ---------- 逐条：画像观测 ----------

    def observe(self, entry: UnifiedLog) -> None:
        """把一条（已在监控网段内、未被排除的）事件并进观测桶。

        两类观测：账号/会话画像（受 `profile.enabled` 控制）与**被访问方**（内网源站/DNS 转发器，
        只受总开关控制 —— 它不依赖画像，关掉画像也要能看「服务器被访问」的基线）。
        都是纯内存计数，没有 I/O；攒太多就提前落库，避免长时间不落库。

        被访问方按**连接**（Zeek `uid`）累计：没有 uid 的事件（主机日志、files/x509 等）
        不进基线，计入 `asset_uids_dropped`（可见，不静默）。
        """
        if not params.baseline_enabled():
            return
        added = 0
        if params.profile_enabled():
            added += profiles.observe_entry(self._obs, entry)
        merged = assets_observe_entry(self._assets, entry)
        if merged < 0:
            self.stats["asset_uids_dropped"] = self.stats.get("asset_uids_dropped", 0) + 1
        else:
            added += merged
        self.stats["observed"] += added
        self._obs_since_flush += added
        if self._obs_since_flush >= max(1000, int(params.max_observations())):
            self.flush()

    # ---------- 窗口：判异 + 学习（全量流量口径） ----------

    def observe_window(self, sample: dict[str, Any]) -> list[dict[str, Any]]:
        """把「一个窗口、一个源 IP」的计数样本**先判异、再并入**基线。

        为什么单开一条通道：聚合摘要只包含**命中规则**的流量，拿它当学习源等于拿异常当常态
        （见 `app/baseline/sampler.py`）。检测器在规则匹配**之前**把每条事件喂给采样器，
        窗口到期每个 IP 一条样本 —— **判异和学习都在这条通道上**，口径才一致：摘要的
        `count` 是「命中规则的事件数」，与全量窗口计数不是一回事，混着比就是拿两把尺子量。

        判出来的偏离先存在 `_window_dev`（每 IP 只留最近一个窗口），等该 IP 的摘要产出时
        由 `_numeric()` 取走挂上去 —— 只有摘才能落成命中事件，偏离必须搭这趟车。
        """
        if not params.baseline_enabled():
            return []
        src = str(sample.get("src_ip") or "")
        if not src or src == "-":
            return []
        # 单客户端"大量 404"= 路径探测：这是行为事实，不是结论（是否在扫由智能体判）
        requests = int(sample.get("requests") or 0)
        errors_404 = int(sample.get("errors_404") or 0)
        if requests >= params.path_probe_min_requests():
            ratio = errors_404 / requests if requests > 0 else 0.0
            if ratio >= params.path_probe_404_ratio():
                observations.emit(
                    "path_probe",
                    "asset",
                    src,
                    {
                        "窗口请求数": requests,
                        "404 数": errors_404,
                        "404 占比": round(ratio, 3),
                        "说明": "该客户端在这些请求里大部分路径不存在",
                    },
                    key="path_probe",
                    now=datetime.now(UTC),
                )
        # 公网来源只统计 404（入口路径探测），不建数值基线、不判异、不学习
        if bool(sample.get("skip_baseline")):
            return []
        values = {feature: _num(sample.get(feature)) for feature in _FEATURES}
        # 顺序很重要：先用**旧**基线判异，再把本窗口样本学进去（否则拿自己跟自己比）
        found, warmed = self._judge(src, values)
        if found or warmed:
            self._window_dev[src] = (time.monotonic(), found, warmed)
            self._trim_window_dev()
        prefix = group_prefix(src)
        added = 0
        for feature in _FEATURES:
            value = values[feature]
            key = f"{src}:{feature}"
            self._pending.setdefault(key, []).append(value)
            self._wanted.add(key)
            added += 1
            if prefix:
                # 组先验也要学：池化用它给"只观测过一两次"的实体兜底
                gkey = f"grp:{prefix}:{feature}"
                self._pending.setdefault(gkey, []).append(value)
                self._wanted.add(gkey)
        self.stats["baseline_sampled"] += added
        if len(self._wanted) >= _WANT_BATCH:
            self._load_wanted()
        # 交出去：派工队列按这些偏离生成 shift 线索（同一份判异结果，不重算第二把尺子）
        return found

    def _dev_keep_seconds(self) -> float:
        """偏离/窗口结果的生命期：摘要按聚合窗口产出，比两个窗口更旧的没人要。"""
        return max(120.0, float(settings.detector_agg_seconds) * 2)

    def _trim_window_dev(self) -> None:
        """限容：窗口偏离表最多留 `_MAX_WINDOW_DEV` 个 IP，超了先清过期的。"""
        if len(self._window_dev) <= _MAX_WINDOW_DEV:
            return
        keep = self._dev_keep_seconds()
        now = time.monotonic()
        for src, record in list(self._window_dev.items()):
            if now - record[0] > keep:
                self.stats["baseline_deviation_expired"] += len(record[1])
                self._window_dev.pop(src, None)
        overflow = len(self._window_dev) - _MAX_WINDOW_DEV
        if overflow > 0:
            # dict 保序：丢最老的（这些 IP 的偏离等不到摘要就算了，计数可见）
            for src in list(self._window_dev)[:overflow]:
                self.stats["baseline_deviation_expired"] += len(self._window_dev[src][1])
                self._window_dev.pop(src, None)

    def _take_window_deviations(self, src: str) -> tuple[list[dict[str, Any]], int]:
        """取走某 IP 最近一个窗口的判异结果（取走即删，避免同 IP 多条摘要重复报）。"""
        record = self._window_dev.pop(src, None)
        if record is None:
            return [], 0
        ts, found, warmed = record
        if time.monotonic() - ts > self._dev_keep_seconds():
            self.stats["baseline_deviation_expired"] += len(found)
            return [], 0
        return list(found), warmed

    def _allow_deviation(self, src: str) -> bool:
        """偏差限额：单实体每小时 + 全局每小时双上限。

        为什么必须有：泊松检验哪怕做了 Bonferroni，基数一大（3,345 IP × 3 特征 × 288 窗口/天）
        仍会积累可观假阳性。限额是**最后一道闸**，把"统计上显著"收敛成"值得人看"。
        """
        if self._client is None:
            return True
        hour = int(time.time() // 3600)
        per_entity = int(params.deviation_cap_per_entity_hour())
        globally = int(params.deviation_cap_per_hour())
        try:
            if per_entity > 0:
                key = f"shentong:baseline:dev:{src}:{hour}"
                hits = int(self._client.incr(key))
                if hits == 1:
                    self._client.expire(key, 3700)
                if hits > per_entity:
                    return False
            if globally > 0:
                key = f"shentong:baseline:dev:_all:{hour}"
                hits = int(self._client.incr(key))
                if hits == 1:
                    self._client.expire(key, 3700)
                if hits > globally:
                    return False
        except Exception as exc:  # noqa: BLE001 — 限额算不出来时不能挡住检测
            log.debug("偏差限额计数失败（放行）: %s", exc)
        return True

    # ---------- 摘要：打标 ----------

    def annotate(self, digest: dict[str, Any]) -> dict[str, Any]:
        """给摘要打基线标签：数值 2σ 偏离 + 最近的账号/会话画像异常。

        返回结构（智能体侧读它来定性，见 `docs/ndr-redesign.md` 第 8 期）::

            {"checked": 3, "warmed": 2,
             "numeric": [{feature, src_ip, value, mean, std, z}],
             "profiles": [{kind, display, risk, reasons, obs_count, src_ips, count}]}

        `warmed` 是「已经过了观测期的维度数」：为 0 说明基线还在学习，
        **没报偏离 ≠ 正常**。画像异常为空时 `profiles` 不出现。
        """
        if not params.baseline_enabled():
            return {}
        numeric, checked, warmed = self._numeric(digest)
        matched = self._profiles_for(digest)
        label: dict[str, Any] = {"checked": checked, "warmed": warmed}
        if numeric:
            label["numeric"] = numeric
        if matched:
            label["profiles"] = matched
        return label

    def _numeric(self, digest: dict[str, Any]) -> tuple[list[dict[str, Any]], int, int]:
        """数值基线：把判异结果挂到摘要上。

        两种学习源（`baseline.learn_source`）：

        - `window`（默认）：判异和学都发生在 `observe_window()`（全量流量口径），这里只是把
          该 IP 最近一个窗口的结论取走 —— 口径一致才不会拿两把尺子量。
        - `digest`（旧行为，回滚用）：用摘要自身的特征值判异，顺带学习。

        判据（`baseline.scheme`）：`poisson`（默认，计数上尾）或 `zscore`（旧的 mean+z·std）。
        """
        src = str(digest.get("src_ip") or "")
        count = _num(digest.get("count"))
        if not src or src == "-" or count <= 0:
            return [], 0, 0
        if params.learn_source() == "window":
            found, warmed = self._take_window_deviations(src)
            if found:
                self.stats["baseline_deviation_reported"] += len(found)
            return found, len(_FEATURES), warmed
        values = {
            "conn_count": count,
            "distinct_dst_ports": float(len(digest.get("dst_ports") or [])),
            "distinct_dst_ips": float(len(digest.get("dst_ips") or [])),
        }
        # 旧行为：先用摘要学，再判（落库在 flush，本轮判异看到的仍是上轮基线）
        for feature in _FEATURES:
            self._pending.setdefault(f"{src}:{feature}", []).append(values[feature])
        deviations, warmed = self._judge(src, values)
        self._trim_cache()
        return deviations, len(_FEATURES), warmed

    def _judge(self, src: str, values: dict[str, float]) -> tuple[list[dict[str, Any]], int]:
        """把一组特征值跟基线比一遍，返回 `(偏离列表, 已 warm 的维度数)`。

        只读缓存、不写待落库队列（学习由调用方负责）。
        """
        scheme = params.scheme()
        # 多重比较校正：一次判定里要检验 len(_FEATURES) 个特征
        alpha = bonferroni_alpha(params.alpha(), len(_FEATURES))
        prefix = group_prefix(src)
        pool_k = float(params.pool_k())
        zscore = params.zscore()
        deviations: list[dict[str, Any]] = []
        warmed = 0
        for feature in _FEATURES:
            value = values[feature]
            key = f"{src}:{feature}"
            base = self._base.get(key)
            if base is None:
                self._wanted.add(key)
                if len(self._wanted) >= _WANT_BATCH:
                    self._load_wanted()
                continue
            if int(base.get("count") or 0) < 2 or not base.get("warmed"):
                continue
            warmed += 1
            group = self._base.get(f"grp:{prefix}:{feature}") if prefix else None
            if prefix and group is None:
                self._wanted.add(f"grp:{prefix}:{feature}")
            mean, var = pooled_lambda(base, group, pool_k)
            raw_std = _num(base.get("std"))
            item: dict[str, Any] = {
                "feature": feature,
                "src_ip": src,
                "value": value,
                "mean": round(mean, 3),
                "std": round(raw_std, 3),
            }
            if scheme == "zscore":
                # 旧判据：标准差下限钳制（32% 的键 std=0，不钳制就是"多 1 个连接就报"）
                std = max(raw_std, abs(mean) * params.std_floor_ratio(), params.std_floor_min())
                if value <= mean + zscore * std:
                    continue
                item["std"] = round(std, 3)
                item["z"] = round((value - mean) / std, 2) if std > 0 else None
                if std > raw_std:
                    item["std_raw"] = round(raw_std, 3)
            else:
                p_value = count_p_value(value, mean=mean, var=var)
                if p_value >= alpha:
                    continue
                item["p"] = float(f"{p_value:.3g}")
                item["alpha"] = float(f"{alpha:.3g}")
                item["var"] = round(var, 3)
                if group is not None:
                    item["pooled_with"] = f"grp:{prefix}"
            if not self._allow_deviation(src):
                self.stats["baseline_deviation_capped"] += 1
                continue
            deviations.append(item)
        return deviations, warmed

    def _load_wanted(self) -> None:
        """把想捞的键批量读进缓存（读不到的记成「还没学到」）。"""
        wanted, self._wanted = self._wanted, set()
        if not wanted:
            return
        states = load_stats(sorted(wanted))
        for key in wanted:
            self._base[key] = states.get(
                key,
                {"count": 0, "mean": 0.0, "m2": 0.0, "std": 0.0, "first_seen": "", "warmed": False},
            )
        self.stats["cache_loads"] += len(states)

    def _trim_cache(self) -> None:
        cap = max(1000, int(params.cache_max()))
        if len(self._base) <= cap:
            return
        # dict 保序：丢掉最早插入的（再遇到会从库里重新捞）
        for key in list(self._base)[: len(self._base) - cap]:
            self._base.pop(key, None)

    def _profiles_for(self, digest: dict[str, Any]) -> list[dict[str, Any]]:
        """按 IP 交集把最近的画像异常挂到摘要上（与智能体侧原来的归属方式一致）。"""
        if not self._anomalies:
            return []
        ips = {str(digest.get("src_ip") or "")}
        ips.update(str(ip) for ip in (digest.get("dst_ips") or []))
        ips.discard("")
        if not ips:
            return []
        out: list[dict[str, Any]] = []
        for anomaly in self._anomalies.values():
            if not ips & set(anomaly.get("src_ips") or []):
                continue
            out.append({k: v for k, v in anomaly.items() if not k.startswith("_")})
            if len(out) >= _MAX_LABEL_ENTITIES:
                break
        return out

    def _remember_anomalies(self, found: list[dict[str, Any]]) -> None:
        """记住本轮异常，并清掉老得没人要的（摘要按聚合窗口产出）。"""
        now = time.monotonic()
        keep = max(120.0, float(settings.detector_agg_seconds) * 2)
        self._anomalies = {
            key: item
            for key, item in self._anomalies.items()
            if now - float(item.get("_at") or 0.0) <= keep
        }
        for item in found:
            eid = f"{item.get('kind')}|{item.get('key')}"
            self._anomalies[eid] = {**item, "_at": now}
        # 命名区分「本轮」与「累计」（2026-10 实机 QA：原来叫 anomalies，被当成累计计数读，
        # 而它其实是**上一轮的值** —— 实机 anomalies=0 但库里有 54 条风险>0 的画像）
        self.stats["anomalies_last_round"] = len(found)
        if found:
            self.stats["anomalies_total"] = self.stats.get("anomalies_total", 0) + len(found)
            self.stats["anomaly_rounds"] = self.stats.get("anomaly_rounds", 0) + 1

    # ---------- 周期：落库 + 判异常 + 清理 ----------

    def maybe_flush(self) -> None:
        if time.monotonic() - self._last_flush < max(5, int(params.flush_seconds())):
            return
        self.flush()

    def flush(self) -> None:
        """把攒下的观测与统计落库（`observe` 攒够量时也会直接调）。"""
        if not params.baseline_enabled():
            return
        now = time.monotonic()
        self._last_flush = now
        self._obs_since_flush = 0
        if self._pending or self._wanted:
            self._flush_stats()
        if self._obs:
            self._flush_profiles()
        if self._assets:
            self._flush_assets()
        if now - self._last_cleanup >= max(60, int(params.cleanup_seconds())):
            self._last_cleanup = now
            # 事实与外连基线的保留期（NDR 自己的表；agent 侧清理不到）
            observations.cleanup(30)
            egress.cleanup(90)
            if params.profile_enabled():
                result = profiles.cleanup()
                if result.get("deleted") or result.get("pruned"):
                    log.info(
                        "基线画像清理：删除 %d 条过期画像、剔除 %d 条不合口径的旧路径",
                        result.get("deleted") or 0,
                        result.get("pruned") or 0,
                    )
            # 数值基线的保留期清理：与画像同节奏（不依赖 profile_enabled，两者是两回事）
            dropped = stats_cleanup()
            if dropped.get("deleted"):
                log.info(
                    "数值基线清理：删除 %d 个超过 %d 天没更新的键",
                    dropped["deleted"],
                    params.retention_days(),
                )
            # 被访问方基线同节奏清理
            assets_dropped = assets_cleanup()
            if assets_dropped.get("deleted"):
                log.info(
                    "被访问方基线清理：删除 %d 个超过 %d 天没更新的键",
                    assets_dropped["deleted"],
                    params.retention_days(),
                )
        self._publish()

    def _flush_stats(self) -> None:
        pending, self._pending = self._pending, {}
        self._load_wanted()
        if not pending:
            return
        # 先补缓存：新键要拿库里已有的均值/方差来比较（这一轮已经错过，下一轮才比得上）
        missing = [key for key in pending if key not in self._base]
        if missing:
            states = load_stats(missing)
            for key in missing:
                self._base[key] = states.get(
                    key,
                    {
                        "count": 0,
                        "mean": 0.0,
                        "m2": 0.0,
                        "std": 0.0,
                        "first_seen": "",
                        "warmed": False,
                    },
                )
        applied = apply_stats(pending)
        if not applied and any(pending.values()):
            # `baseline/stats.py` 写失败时只 log 警告并返回 {}（不抛异常）。这里必须把样本并回
            # 待落库队列下一轮重试，否则「PG 抖一下」这批观测就永久丢失、而且任何指标都看不到。
            cap = max(1000, int(params.max_observations())) * 4
            for key, values in pending.items():
                if values:
                    self._pending.setdefault(key, []).extend(values)
            total = sum(len(v) for v in self._pending.values())
            if total > cap:
                # 极端情况（PG 长时间不可用）只做一次有界丢弃，避免内存无限增长，并留计数可查
                self.stats["stats_write_dropped"] = self.stats.get("stats_write_dropped", 0) + total
                self._pending.clear()
                log.error(
                    "基线落库持续失败，待落库样本超过 %d 条，已丢弃 %d 条（PG 恢复后请核查）",
                    cap,
                    total,
                )
            self.stats["stats_write_failed"] = self.stats.get("stats_write_failed", 0) + 1
            log.warning(
                "基线落库未成功（原因见上一条 stats 警告），已保留样本待下一轮重试（累计失败 %d 次）",
                self.stats["stats_write_failed"],
            )
            return
        for key, state in applied.items():
            self._base[key] = state
        # 同样是「上一轮」语义（见 _remember_anomalies 的说明）
        self.stats["numeric_keys_last_round"] = len(applied)
        self.stats["numeric_samples"] = self.stats.get("numeric_samples", 0) + sum(
            len(v) for v in pending.values()
        )

    def _flush_profiles(self) -> None:
        observations, self._obs = self._obs, {}
        if not params.profile_enabled() or not observations:
            return
        info = profiles.recall_from_observations(observations)
        risks = {f"{e['kind']}|{e['key']}": e for e in info.get("entities") or []}
        result = profiles.update_profiles(observations, risks)
        anomalies = list(info.get("anomalies") or [])
        self._remember_anomalies(anomalies)
        self._emit_profile_anomalies(anomalies)
        self.stats["flushes"] = self.stats.get("flushes", 0) + 1
        self.stats["profiles_created"] = self.stats.get("profiles_created", 0) + int(
            result.get("created") or 0
        )
        self.stats["profiles_updated"] = self.stats.get("profiles_updated", 0) + int(
            result.get("updated") or 0
        )
        if anomalies:
            log.info(
                "基线画像：本轮 %d 个实体、%d 个过阈值异常（在册 %d）",
                len(observations),
                len(anomalies),
                len(self._anomalies),
            )

    def _emit_profile_anomalies(self, anomalies: list[dict[str, Any]]) -> None:
        """画像异常 → `profile_anomaly` 事实（D4，2026-10-29）。

        口径：
        - 异常带**监控网段内**来源 IP → 按主源 IP 发资产主体事实（"这台机器在用新 UA/
          打新接口"）；纯外部来源不发资产主体（那不是我们的资产）；
        - 否则按账号/会话实体发（`subject_kind=account/session`）；
        - 与 `login_bruteforce`/`geo_jump` 去重：同一对象已有这类账号事实就不重复发；
        - 强度 = 画像风险分（客观分，不是严重度）。
        """
        if not params.profile_anomaly_enabled():
            return
        for item in anomalies:
            reasons = [str(x) for x in (item.get("reasons") or [])]
            if not reasons:
                continue
            risk = float(item.get("risk") or 0.0)
            src_ips = [str(x) for x in (item.get("src_ips") or [])][:10]
            internal_srcs = [ip for ip in src_ips if is_internal_ip(ip)]
            # reason code：判据名（冒号/全角括号前的部分），同一类异常共用一个 key
            code = reasons[0].split("（", 1)[0].split(":", 1)[0].strip()[:40] or "画像异常"
            facts = {
                "画像对象": str(item.get("display") or item.get("key") or ""),
                "对象类型": "账号" if str(item.get("kind")) == "account" else "会话",
                "风险分": round(risk, 3),
                "判定理由": reasons,
                "来源地址": src_ips,
                "历史观测次数": int(item.get("obs_count") or 0),
                "说明": "该对象的访问画像与它自己的历史基线不一致（客观事实，不含结论）",
            }
            if internal_srcs:
                for ip in internal_srcs[:3]:
                    if observations.has_recent(ip, ("login_bruteforce", "geo_jump")):
                        continue
                    observations.emit(
                        "profile_anomaly",
                        "asset",
                        ip,
                        facts,
                        key=f"profile_anomaly:{code}",
                        strength=max(0.0, min(1.0, risk)),
                    )
                continue
            subject = str(item.get("display") or item.get("key") or "").strip()
            if not subject:
                continue
            if observations.has_recent(subject, ("login_bruteforce", "geo_jump")):
                continue
            subject_kind = "account" if str(item.get("kind")) == "account" else "session"
            observations.emit(
                "profile_anomaly",
                subject_kind,
                subject,
                facts,
                key=f"profile_anomaly:{code}",
                strength=max(0.0, min(1.0, risk)),
            )

    def _flush_assets(self) -> None:
        """把被访问方的窗口观测定稿并落库（Welford，复用数值基线那套）。

        `self._assets` 里是**按连接**（uid）累计的记录；这里先把同一连接里 `conn` 的
        `IP:端口` 与 `http/ssl` 的 hostname 合成一个身份（并丢掉「中继自身」那些），
        再按资产聚合成一个观测点 —— 一个聚合窗口 = 一个观测点。
        """
        records, self._assets = self._assets, {}
        if not records:
            return
        buckets, dropped = assets_finalize(records)
        # D3：先拿**旧**基线判异，再把本窗口学进去（顺序反了就变成自己跟自己比）
        shifts = assets_judge_window(buckets)
        applied = assets_apply_window(buckets)
        for item in shifts:
            self._emit_asset_shift(item)
        links = max(0, len(records) - dropped)
        self.stats["asset_uids_last_round"] = links
        self.stats["asset_uids_total"] = self.stats.get("asset_uids_total", 0) + links
        if dropped:
            # 「有连接但没进基线」的量必须看得见：无 uid / 中继非 DNS 前跳 / 超上限
            self.stats["asset_uids_dropped"] = self.stats.get("asset_uids_dropped", 0) + dropped
        self.stats["assets_observed"] = self.stats.get("assets_observed", 0) + len(buckets)
        self.stats["assets_last_round"] = len(buckets)
        if buckets and not applied:
            log.warning("被访问方基线落库未成功（下一轮重试）")

    def _emit_asset_shift(self, item: dict[str, Any]) -> None:
        """把一条资产基线偏离发成 `asset_shift` 事实（D3）。

        强度：p 越小越强，基线 0.5、上限 0.7（`distinct_clients` 突增再加 0.05）——
        与"事实在前、判断在后"一致：这里只说"比它自己平时多了多少"，不说是不是攻击。
        """
        p = float(item.get("p") or 1.0)
        alpha = bonferroni_alpha(params.alpha(), 5)
        scale = 1.0 - min(1.0, p / alpha) if alpha > 0 else 0.0
        strength = 0.5 + 0.2 * max(0.0, min(1.0, scale))
        if str(item.get("feature")) == "distinct_clients":
            strength = min(0.7, strength + 0.05)
        labels = {
            "visits": "被访问连接数",
            "requests": "请求数",
            "distinct_clients": "客户端数",
            "distinct_client_ports": "客户端端口数",
            "distinct_targets": "被访问目标数",
        }
        feature = str(item.get("feature") or "")
        emitted = observations.emit(
            "asset_shift",
            "asset",
            str(item.get("asset") or ""),
            {
                "特征": labels.get(feature, feature),
                "本窗口值": item.get("value"),
                "基线均值": item.get("mean"),
                "标准差": item.get("std"),
                "p": item.get("p"),
                "涉及客户端数": item.get("clients"),
                "涉及目标数": item.get("targets"),
                "说明": "该资产本窗口的计数高于它自己的历史基线（客观事实，不含结论）",
            },
            key=f"asset_shift:{feature}",
            strength=strength,
        )
        if emitted:
            self.stats["asset_shift_reported"] = self.stats.get("asset_shift_reported", 0) + 1

    def _publish(self) -> None:
        """把进程内计数写进 Redis，运行状态页据此判断基线是否在跑。"""
        if self._client is None:
            return
        try:
            self._client.hset(
                settings.baseline_stats_key,
                mapping={
                    "observed": int(self.stats.get("observed", 0)),
                    # 累计量（只增）
                    "numeric_samples": int(self.stats.get("numeric_samples", 0)),
                    "flushes": int(self.stats.get("flushes", 0)),
                    "profiles_created": int(self.stats.get("profiles_created", 0)),
                    "profiles_updated": int(self.stats.get("profiles_updated", 0)),
                    "anomalies_total": int(self.stats.get("anomalies_total", 0)),
                    "anomaly_rounds": int(self.stats.get("anomaly_rounds", 0)),
                    # 被访问方（源站/DNS）基线：本轮观测到多少资产 + 累计
                    "assets_last_round": int(self.stats.get("assets_last_round", 0)),
                    "assets_observed": int(self.stats.get("assets_observed", 0)),
                    # 资产侧判异（D3）：发出多少条 asset_shift 事实（开关关着就一直是 0）
                    "asset_shift_reported": int(self.stats.get("asset_shift_reported", 0)),
                    # 被访问方按连接（uid）算：本轮多少条连接 / 累计多少条 / 有多少条没进基线
                    "asset_uids_last_round": int(self.stats.get("asset_uids_last_round", 0)),
                    "asset_uids_total": int(self.stats.get("asset_uids_total", 0)),
                    "asset_uids_dropped": int(self.stats.get("asset_uids_dropped", 0)),
                    # 上一轮的量（会被覆盖）——名字里必须带 last_round，别再让人当成累计值
                    "numeric_keys_last_round": int(self.stats.get("numeric_keys_last_round", 0)),
                    "anomalies_last_round": int(self.stats.get("anomalies_last_round", 0)),
                    "flush_at": int(time.time()),
                },
            )
            self._client.expire(settings.baseline_stats_key, 24 * 3600)
            # 清掉改名前的歧义字段：哈希只增不删（TTL 24h），不删就会新旧并存 ——
            # 读的人可能又拿到那个被当成累计值的 `anomalies`（2026-10 实机 QA 的误读源）。
            self._client.hdel(settings.baseline_stats_key, "anomalies", "numeric_keys")
        except Exception as exc:  # noqa: BLE001
            log.debug("基线计数写入 Redis 失败: %s", exc)
