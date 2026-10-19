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
from typing import Any

from app.baseline import params, profile as profiles
from app.baseline.asset import (
    apply_window as assets_apply_window,
    cleanup as assets_cleanup,
    finalize as assets_finalize,
    observe_entry as assets_observe_entry,
)
from app.baseline.stats import apply_stats, cleanup as stats_cleanup, load_stats
from app.config import settings
from app.schemas import UnifiedLog
from app.workers.log import get_logger

log = get_logger(__name__)

# 数值基线的三个特征：与智能体侧 `_stat_features` 同源（key = f"{src_ip}:{feature}"）
_FEATURES = ("conn_count", "distinct_dst_ports", "distinct_dst_ips")
_WANT_BATCH = 200  # 缓存里没有的键攒够这么多就批量捞一次
_MAX_LABEL_ENTITIES = 6  # 单条摘要最多带几个画像异常（防止摘要膨胀）


def _num(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


class BaselineEngine:
    """基线引擎（单写者：只有持锁的检测器实例会用它）。"""

    def __init__(self, client: Any = None) -> None:
        self._client = client
        self._obs: dict[str, dict[str, Any]] = {}  # 画像窗口观测（key = kind|entity）
        self._assets: dict[str, dict[str, Any]] = {}  # 被访问方窗口观测（key = Zeek 连接 uid）
        self._pending: dict[str, list[float]] = {}  # 数值基线待落库样本
        self._base: dict[str, dict[str, Any]] = {}  # 数值基线缓存（键 -> 状态）
        self._wanted: set[str] = set()  # 缓存里没有、想捞的键
        self._anomalies: dict[str, dict[str, Any]] = {}  # 最近判出的画像异常（按实体去重）
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
        """数值基线：算摘要的特征值 → 与基线比较 → 排队更新。"""
        src = str(digest.get("src_ip") or "")
        count = _num(digest.get("count"))
        if not src or src == "-" or count <= 0:
            return [], 0, 0
        values = {
            "conn_count": count,
            "distinct_dst_ports": float(len(digest.get("dst_ports") or [])),
            "distinct_dst_ips": float(len(digest.get("dst_ips") or [])),
        }
        zscore = params.zscore()
        deviations: list[dict[str, Any]] = []
        warmed = 0
        for feature in _FEATURES:
            value = values[feature]
            key = f"{src}:{feature}"
            self._pending.setdefault(key, []).append(value)
            base = self._base.get(key)
            if base is None:
                self._wanted.add(key)
                if len(self._wanted) >= _WANT_BATCH:
                    self._load_wanted()
                continue
            if int(base.get("count") or 0) < 2 or not base.get("warmed"):
                continue
            warmed += 1
            mean = _num(base.get("mean"))
            raw_std = _num(base.get("std"))
            # 标准差下限钳制（2026-10 误报治理，实测驱动）：
            # 线上 10,011 个基线维度里 **32% 的 std=0**（历史值恒定），而判据是
            # `value > mean + zscore*std` —— std=0 就等于「比均值多 1 个连接就报偏离」，
            # 抽样 200 条基线偏离事件里有 11.5% 就是这么来的。
            # 下限取「均值×比例」与「绝对底线」两者较大者，恒定基线因此要求有实际倍数偏离。
            std = max(
                raw_std,
                abs(mean) * params.std_floor_ratio(),
                params.std_floor_min(),
            )
            if value <= mean + zscore * std:
                continue
            item: dict[str, Any] = {
                "feature": feature,
                "src_ip": src,
                "value": value,
                "mean": round(mean, 3),
                "std": round(std, 3),
                "z": round((value - mean) / std, 2) if std > 0 else None,
            }
            if std > raw_std:
                # 钳制生效时把原始值也带上，证据里能看出「这条是靠下限兜住的」
                item["std_raw"] = round(raw_std, 3)
            deviations.append(item)
        self._trim_cache()
        return deviations, len(_FEATURES), warmed

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
        applied = assets_apply_window(buckets)
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
