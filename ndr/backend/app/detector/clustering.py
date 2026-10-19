"""告警聚类（轻量自研，2026-10）。

## 为什么要聚类

一次扫描/爆破会同时命中几十个地址，逐条看就是噪声：运维看到的是「40 条高危」，
实际情况是**一件**事。按簇看才能一眼判断"这是同一次扫描，还是三件事同时在发生"。

## 一簇是什么（口径尽量笨，能解释得清）

**同一事件归类 + 同一网段（IPv4 /24、IPv6 /64）+ 同一小时** = 一簇。

- 归类：界面上的事件标题（「网络扫描」「认证失败激增」…），不同归类不合并；
- 网段：压到 /24（v6 /64）—— 同一网段换地址是常态，不压就会碎成一堆单条簇；
- 小时：只看一小时内的爆发，跨小时的持续攻击会自然分成多个簇（保留"还在继续"的语义）。

簇 ID 是这三者的短哈希（稳定、可回查），落在 `hit_events.cluster_id` 上。

## 不引入机器学习的原因

聚类只需要"把同一件事归到一起"，不需要发现未知分组。规则式口径**可解释**：
界面上能直接告诉运维这一簇是「网络扫描 · 10.0.0.0/24 · 14 时」，出问题也好查。
"""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime, timezone

#: `datetime.UTC` 是 3.11 的别名，这里用等价写法避开按旧语法解析的静态检查
UTC = timezone.utc

#: 簇 ID 长度（`hit_events.cluster_id` 是 VARCHAR(24)）
CLUSTER_ID_LEN = 16


def net_of(ip: str) -> str:
    """取该地址所在网段：IPv4 → /24，IPv6 → /64；解析不出来返回空串。

    为什么压这么粗：一台机器换地址、NAT 池轮换、移动网切基站，都发生在同一个 /24 内，
    按单地址聚等于没聚（实测同一次扫描里 30 多个地址几乎全在同一 /24）。
    """
    text = str(ip or "").strip()
    if not text:
        return ""
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return ""
    prefix = 64 if addr.version == 6 else 24
    try:
        return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))
    except ValueError:
        return ""


def hour_of(when: datetime | None) -> str:
    """事件所属的小时桶（`YYYYMMDDHH`，北京时间口径只影响展示，不影响分桶一致性）。"""
    moment = when or datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y%m%d%H")


def cluster_id(rule: str, ip: str, when: datetime | None = None) -> str:
    """算出簇 ID：`归类 + 网段 + 小时` 的短哈希。

    `ip` 为空时退化成「归类 + 小时」——没有地址的事件（例如数值基线偏离）也照样能聚。
    """
    key = "|".join(
        (
            str(rule or "").strip().lower(),
            net_of(ip),
            hour_of(when),
        )
    )
    return hashlib.sha1(key.encode("utf-8", errors="ignore")).hexdigest()[:CLUSTER_ID_LEN]


def cluster_label(rule: str, ip: str, when: datetime | None = None) -> str:
    """簇的人话标签（界面显示用）：「网络扫描 · 10.0.0.0/24 · 2026102014 时」。"""
    net = net_of(ip) or "无明显网段"
    return f"{str(rule or '未归类事件').strip() or '未归类事件'} · {net} · {hour_of(when)} 时"
