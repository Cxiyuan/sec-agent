"""Zeek ``conn_state`` 语义表 —— **唯一事实来源**。

为什么要单独放一张表：``conn_state`` 的语义此前被三处各自手写一遍
（``ingestion/normalizer.py`` 翻事件类型、``triage_policy.SUCCESS_CONN_STATES`` 判分诊、
``agents/prefilter.py._looks_established`` 打预筛分），只要有一处漏写或写错，
结果就**静默翻转**。实测踩过的两个坑：

- ``RSTO``/``RSTR`` 是「握手已建立、随后一方 RST 断开」，但事件类型被兜底成 ``generic``，
  与分诊的「成功连接」口径不一致；
- ``SH`` 是「发了 SYN 又发 FIN、从没收到 SYN-ACK」（**没建立**），却因为被标成
  ``connection_shutdown`` 而进了「成功连接」集合 —— 没建立的连接被当成已建立，
  方向是**该分析的被降噪**。

约定（改这张表前先读 ``docs/ndr-redesign.md`` 的「连接状态语义」一节）：

- ``event_type`` 是给规则/技能判条件用的**标签**；
- ``established`` 是「TCP 握手是否真的完成过」的**语义**，分诊与预筛只能读它；
- 两者**分开维护，不允许用标签反推 established**；
- 表必须覆盖 Zeek 官方 conn_state 全集：``tests/py/test_conn_states.py`` 会逐项断言，
  Zeek 升级新增状态时 CI 先炸，而不是线上静默按 ``generic`` 处理。
"""

from __future__ import annotations

import logging
from typing import NamedTuple

log = logging.getLogger(__name__)

GENERIC_EVENT_TYPE = "generic"


class ConnStateInfo(NamedTuple):
    """单个 conn_state 的语义：规则用标签，分诊用 established。"""

    event_type: str
    established: bool


# Zeek 官方 conn_state 全集（见 Zeek conn.log 文档 "Connection state"）。
CONN_STATES: dict[str, ConnStateInfo] = {
    "S0": ConnStateInfo("scan_attempt", False),  # 只发了 SYN，没有任何回应
    "S1": ConnStateInfo("conn_established", True),  # 已建立，尚未结束
    "SF": ConnStateInfo("conn_established", True),  # 正常建立 + 正常结束
    "S2": ConnStateInfo("conn_established", True),  # 已建立，发起方关闭，未收到回应
    "S3": ConnStateInfo("conn_established", True),  # 已建立，应答方关闭，未收到回应
    "RSTO": ConnStateInfo("conn_established", True),  # 已建立，发起方 RST 断开
    "RSTR": ConnStateInfo("conn_established", True),  # 已建立，应答方 RST 断开
    "REJ": ConnStateInfo("rejected_connection", False),  # 连接尝试被拒（RST，无 SYN-ACK）
    "SH": ConnStateInfo("connection_shutdown", False),  # 发 SYN 后发 FIN，从未收到 SYN-ACK
    "SHR": ConnStateInfo("connection_shutdown", False),  # 收到 SYN-ACK 后 FIN，从未看到 SYN
    "RSTOS0": ConnStateInfo("rejected_connection", False),  # 发 SYN 后 RST，从未收到 SYN-ACK
    "RSTRH": ConnStateInfo("rejected_connection", False),  # 收到 SYN-ACK 后 RST，从未看到 SYN
    "OTH": ConnStateInfo("generic", False),  # 没看到 SYN 的中间流，保守判为未建立
}

# 「握手真的完成过」的集合 —— 分诊/预筛只能从这里读，不要再手写第二份。
ESTABLISHED_CONN_STATES: frozenset[str] = frozenset(
    state for state, info in CONN_STATES.items() if info.established
)

# 进程内见过的表外状态（每种只喊一次，避免刷屏）。
_unknown_seen: set[str] = set()


def normalize_state(conn_state: object) -> str:
    """统一大小写与空白；空值返回空串。"""
    return str(conn_state or "").strip().upper()


def event_type_of(conn_state: object) -> str | None:
    """``conn_state`` → 事件类型标签；入参为空返回 ``None``（调用方继续走别的分支）。

    表外状态按 ``generic`` 处理，但**不静默**：每种未知状态在进程内喊一次警告，
    提示把语义补进 ``CONN_STATES``（历史教训：兜底吞掉未知值 = 静默失效）。
    """
    state = normalize_state(conn_state)
    if not state:
        return None
    info = CONN_STATES.get(state)
    if info is not None:
        return info.event_type
    if state not in _unknown_seen:
        _unknown_seen.add(state)
        log.warning(
            "遇到未知 Zeek conn_state=%s：按 %s 处理，请把它的语义补进"
            " app/ingestion/conn_states.py 的 CONN_STATES 表（两侧都要改，"
            "tests/py/test_conn_states.py 会校验覆盖）",
            state,
            GENERIC_EVENT_TYPE,
        )
    return GENERIC_EVENT_TYPE


def is_known(conn_state: object) -> bool:
    """是否在表内。"""
    return normalize_state(conn_state) in CONN_STATES


def is_established(conn_state: object) -> bool:
    """TCP 握手是否真的完成过 —— 判断「有没有成功连接」的唯一入口。"""
    info = CONN_STATES.get(normalize_state(conn_state))
    return bool(info and info.established)


def produced_event_types() -> frozenset[str]:
    """本表能产出的事件类型标签（供词表与测试使用）。"""
    return frozenset(info.event_type for info in CONN_STATES.values()) | {GENERIC_EVENT_TYPE}
