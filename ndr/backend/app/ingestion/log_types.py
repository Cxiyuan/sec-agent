"""日志类型分类（采集契约的一部分，两侧各持一份、内容必须一致）。

为什么要单独一层：Zeek 的日志流分三类，去向不同——

- ``event``（事件类）：协议/行为事件。入库 + 进检测/画像/规则——检测器只看这些。
- ``ops``（运维类）：时间同步、BPF 生效确认、Zeek 自身健康、丢包统计、JA4 SSH/D 证据。
  它们是"证据"不是"行为"：进了检测只会白占队列、污染画像与规则命中率，所以只入库。
- ``unknown``（名单外的新流）：Zeek 升级新增的流、`site/scripts.d/` 里第三方脚本的产出。
  保留原始名字并标 ``log_type_known=False``，先观察它的量与形状——静默丢掉等于连
  "漏采"信号都没有了。

类型清单在 `config.py`（`ST_ZEEK_EVENT_LOG_TYPES` / `ST_ZEEK_OPS_LOG_TYPES`），
加类型只改配置、不改代码；判定只有这一个入口（归一化层），避免两处漂移。
"""

from __future__ import annotations

import re
from functools import lru_cache

from app.config import settings
from app.schemas import UnifiedLog

EVENT = "event"
OPS = "ops"
UNKNOWN = "unknown"

# 轮转后缀：conn.log / conn.2026-10-01.log（本项目）/ conn.14-00-00.log（小时轮转）
_DATE_SUFFIX_RE = re.compile(r"\.\d{4}-\d{2}-\d{2}$|\.\d{2}-\d{2}-\d{2}$")


def canonical_log_type(name: str) -> str:
    """把文件名或字段里的类型名规范化：``conn.2026-10-01.log`` → ``conn``。

    顺带去掉目录前缀（``/logs/conn.log`` → ``conn``），这样外面传路径也不会判定失败。
    """
    text = str(name or "").strip().lower().rsplit("/", 1)[-1]
    text = text.removesuffix(".log")
    return _DATE_SUFFIX_RE.sub("", text)


@lru_cache
def _names(value: str) -> frozenset[str]:
    return frozenset(canonical_log_type(x) for x in (value or "").split(",") if x.strip())


@lru_cache
def event_log_types() -> frozenset[str]:
    return _names(settings.zeek_event_log_types)


@lru_cache
def ops_log_types() -> frozenset[str]:
    return _names(settings.zeek_ops_log_types)


@lru_cache
def known_log_types() -> frozenset[str]:
    return event_log_types() | ops_log_types()


def is_known(log_type: str) -> bool:
    return canonical_log_type(log_type) in known_log_types()


@lru_cache
def stats_protocol_log_types() -> frozenset[str]:
    """总览页「协议分析占比」用到的**协议识别类**日志类型白名单。

    与 ``event`` / ``ops`` **不是同一回事**：那两个决定「谁进检测」，这里只决定
    「谁算协议」。所以 ``ntp`` / ``dhcp`` 属 ops（不进检测）但仍是协议，会出现在图上；
    而 ``conn``（流记录）、``weird``（异常）、``files``（文件产物）、``syslog``（主机日志）
    虽然属 event / 名单外，却**不是**协议，不进这张图。
    """
    return _names(settings.stats_protocol_log_types)


def classify(log_type: str) -> str:
    """类型 → event / ops / unknown。"""
    name = canonical_log_type(log_type)
    if name in event_log_types():
        return EVENT
    if name in ops_log_types():
        return OPS
    return UNKNOWN


def classify_entry(entry: UnifiedLog) -> str:
    """事件条目的分类。

    非 Zeek 来源（签名引擎告警）一律按事件类处理：它的日志类型闸门由归一化层自己的
    口径决定（只发 alert），不需要再套 Zeek 的运维类名单。
    """
    if entry.source_system != "zeek":
        return EVENT
    return classify(entry.log_type)


def is_detectable(entry: UnifiedLog) -> bool:
    """是否允许进入检测/画像（只有事件类可以）。"""
    return classify_entry(entry) == EVENT


def is_baseline_eligible(entry: UnifiedLog) -> bool:
    """是否允许进行为基线/画像/资产统计。

    签名引擎（Suricata）的告警是**派生产物**：它说的是「某条签名命中了某条流」，不是「这个
    实体干了什么」。喂给基线等于把告警当成正常行为学进去——内网 IP 的常规画像里会多出一堆
    告警事件，数值统计的均值/方差也跟着被带偏。所以签名命中只进检测与入库、不进基线。
    """
    if entry.source_system == "suricata":
        return False
    return is_detectable(entry)
