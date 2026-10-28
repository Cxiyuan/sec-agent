"""数值基线的**独立采样通道**：按窗口对**全量事件**做计数，喂给基线学习。

## 为什么需要它（2026-10 生产实测）

数值基线原来是"按摘要学习"：`detector/aggregate.py` 的聚合键是
`(src_ip, rule, excluded, scope)`，**只有命中规则的流量才进聚合**，摘要再喂
`engine.annotate()`。后果有两个，都很致命：

1. **样本饥饿**：25 分钟只产出 441 个学习样本，3,345 个 IP 平摊 → 每个 IP 约 3.7 小时
   才被采到一次，`observe_days=7` 也攒不够样本，48.7% 的键只被观测过一次；
2. **幸存者偏差**：学到的是"已经够 noteworthy 才产摘要"的窗口 = 异常时段，
   而基线应该学**常态**。拿异常当常态，偏离判据自然既不准也无序。

修法不是"改聚合"（聚合里根本没有未命中规则的流量），而是在规则匹配**之前**加一条
独立的窗口计数通道：每个归一化事件都进这里，窗口到期产出「每 IP 一条样本」。

## 设计取舍

- **进程内内存**，不落 Redis：检测器是单进程、单写者，一个窗口的数据量很小
  （数千 IP），落 Redis 反而增加每秒数千次写和键churn。代价是重启丢一个窗口 —— 无所谓。
- **distinct 集合有上限**：代理出口/扫描器一个窗口可能碰几千个目的 IP，集合不封顶会吃光内存。
  超限时停止增长并打标记（`truncated`），样本仍可用（只是该维度的"观测值"是下限）。
- 只采样**已被归一化的事件**（runner 里 `entry`），不碰原始报文。
"""

from __future__ import annotations

import time
from typing import Any

from app.iputil import is_public_ip

#: 单窗口最多跟踪多少个源 IP（超出后新 IP 不再计入，防代理/扫描场景撑爆内存）
_MAX_IPS = 50000
#: 单 IP 每窗口最多跟踪多少个 distinct 值（超出即截断）
_MAX_DISTINCT = 2000
#: 公网来源（只统计 404）最多跟踪多少个 IP
_MAX_PROBE_IPS = 5000


class WindowSampler:
    """按时间窗对每个源 IP 累计计数特征 + 主动外连目的地 + 请求/404 计数。

    为什么外连目的地单独收：数值特征（连接数/端口数）解释不了"连了谁"，
    而"第一次连这个 IP/域名/端口"才是服务器异常程序最直接的痕迹（2026-10 用户口径）。
    """

    def __init__(
        self,
        window_seconds: int = 300,
        *,
        max_ips: int = _MAX_IPS,
        max_distinct: int = _MAX_DISTINCT,
    ) -> None:
        self.window = max(1, int(window_seconds))
        self.max_ips = max(1, int(max_ips))
        self.max_distinct = max(1, int(max_distinct))
        self._start = 0.0
        self._counts: dict[str, int] = {}
        self._ports: dict[str, set[str]] = {}
        self._dsts: dict[str, set[str]] = {}
        #: 主动外连目的地（源在内网、目的在公网）：IP / 域名 / 端口
        self._egress_dsts: dict[str, set[str]] = {}
        self._egress_domains: dict[str, set[str]] = {}
        self._egress_ports: dict[str, set[str]] = {}
        #: HTTP 请求数与 404 数（单客户端"大量 404"= 路径探测）
        self._requests: dict[str, int] = {}
        self._e404: dict[str, int] = {}
        #: 公网来源：**不建量基线**（用户口径），但仍统计 404（入口路径探测是行为不是体量）
        self._public: set[str] = set()
        self._truncated: set[str] = set()
        self.dropped_ips = 0

    # ------------------------------------------------------------------ 采集
    def observe(self, entry: Any, now: float | None = None) -> None:
        """记录一个事件（**每条归一化事件都调**，不做任何规则过滤）。"""
        ts = time.time() if now is None else now
        if not self._start:
            self._start = ts
        src = str(getattr(entry, "src_ip", "") or "")
        if not src or src == "-":
            return
        # 基线只学内网源（2026-10 用户口径）：给外网客户端建"连接数基线"没有处置意义，
        # 而且它们的行为不由我们控制，学进去只会制造偏离。
        # 但**入口 404 探测**必须统计（那正是"外部请求"里唯一有安全含义的行为）。
        if is_public_ip(src):
            is_http = str(getattr(entry, "event_type", "") or "") in ("http_request", "http_login")
            if is_http and (len(self._requests) < _MAX_PROBE_IPS or src in self._requests):
                self._public.add(src)
                self._requests[src] = self._requests.get(src, 0) + 1
                if int(getattr(entry, "status_code", 0) or 0) == 404:
                    self._e404[src] = self._e404.get(src, 0) + 1
            return
        if src not in self._counts and len(self._counts) >= self.max_ips:
            # 满了：新 IP 不再跟踪（已有 IP 继续累计），并记一次丢弃
            self.dropped_ips += 1
            return
        self._counts[src] = self._counts.get(src, 0) + 1
        port = str(getattr(entry, "dst_port", "") or "")
        if port:
            self._add(self._ports, src, port)
        dst = str(getattr(entry, "dst_ip", "") or "")
        if dst:
            self._add(self._dsts, src, dst)
            # 主动外连：源在内网、目的在公网（内网↔内网是横向，不在这里）
            if dst != src and is_public_ip(dst):
                self._add(self._egress_dsts, src, dst)
                host = str(getattr(entry, "hostname", "") or "").strip().lower().rstrip(".")
                if host and ":" not in host:
                    self._add(self._egress_domains, src, host)
                if port:
                    self._add(self._egress_ports, src, port)
        # 单客户端 404 占比（路径探测）：只统计 HTTP 请求
        if str(getattr(entry, "event_type", "") or "") in ("http_request", "http_login"):
            self._requests[src] = self._requests.get(src, 0) + 1
            if int(getattr(entry, "status_code", 0) or 0) == 404:
                self._e404[src] = self._e404.get(src, 0) + 1

    def _add(self, bucket: dict[str, set[str]], src: str, value: str) -> None:
        values = bucket.get(src)
        if values is None:
            values = bucket[src] = set()
        if len(values) >= self.max_distinct:
            self._truncated.add(src)
            return
        values.add(value)

    # ------------------------------------------------------------------ 出样
    def due(self, now: float | None = None) -> bool:
        """窗口是否已到期。"""
        if not self._start:
            return False
        ts = time.time() if now is None else now
        return (ts - self._start) >= self.window

    def pop_ready(self, now: float | None = None) -> list[dict[str, Any]]:
        """窗口到期则产出一批样本（每 IP 一条）并重置；未到期返回空列表。"""
        if not self.due(now):
            return []
        samples = self._samples()
        self._reset()
        return samples

    def _samples(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for src in set(self._counts) | set(self._requests):
            count = self._counts.get(src, 0)
            out.append(
                {
                    "src_ip": src,
                    "window_start": self._start,
                    "conn_count": float(count),
                    "distinct_dst_ports": float(len(self._ports.get(src) or ())),
                    "distinct_dst_ips": float(len(self._dsts.get(src) or ())),
                    "egress_dsts": sorted(self._egress_dsts.get(src) or ()),
                    "egress_domains": sorted(self._egress_domains.get(src) or ()),
                    "egress_ports": sorted(self._egress_ports.get(src) or ()),
                    "requests": self._requests.get(src, 0),
                    "errors_404": self._e404.get(src, 0),
                    # 公网来源只算 404，不参与数值基线（判异与学习都跳过）
                    "skip_baseline": src in self._public,
                    # 截断标记：该 IP 的 distinct 值是下限（集合已封顶）
                    "truncated": src in self._truncated,
                }
            )
        return out

    def _reset(self) -> None:
        self._start = 0.0
        self._counts = {}
        self._ports = {}
        self._dsts = {}
        self._egress_dsts = {}
        self._egress_domains = {}
        self._egress_ports = {}
        self._requests = {}
        self._e404 = {}
        self._public = set()
        self._truncated = set()

    # ------------------------------------------------------------------ 观测
    def stats(self) -> dict[str, int]:
        return {
            "ips": len(self._counts),
            "dropped_ips": self.dropped_ips,
            "truncated": len(self._truncated),
        }
