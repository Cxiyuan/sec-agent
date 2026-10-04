"""``conn_state`` 语义表是唯一事实来源 —— 与三处调用点的一致性守卫。

背景（2026-10-03，用户追问「RSTO/RSTR 口径不一致如何彻底解决」）：同一份 conn_state 语义
此前被**手写三遍** ——

1. ``app/ingestion/normalizer.py::_zeek_event_type`` 翻事件类型标签；
2. ``triage_policy.SUCCESS_CONN_STATES`` / ``SUCCESS_EVENT_TYPES`` 判「有没有成功连接」；
3. ``app/agents/prefilter.py::_looks_established`` 打兜底预筛分（第三份白名单）。

三份只要错一处，结果就**静默翻转**。实测踩到两个坑：

- ``RSTO``/``RSTR`` 是「握手已建立、随后一方 RST 断开」，事件类型却被兜底成 ``generic``，
  与分诊的「成功连接」口径打架；
- ``SH`` 是「发了 SYN 又发 FIN、从没收到 SYN-ACK」（**没建立**），却因为标签是
  ``connection_shutdown`` 而混进「成功连接」集合 —— 没建立的连接被当成已建立，
  方向是**该分析的被降噪**。

修法是把语义收进 ``app/ingestion/conn_states.py`` 一张表（两侧同文件），本文件钉死：

- 表覆盖 Zeek 官方 conn_state 全集（Zeek 新增状态时 CI 先炸，而不是线上静默按 generic 处理）；
- 每个状态的 (标签, 是否已建立) 与 Zeek 文档一致（含上面两个坑的回归）；
- ``normalizer`` 产出的标签 == 表；
- 分诊的 ``SUCCESS_*`` 集合由表推导，不再手写；
- 表外状态不静默（限流警告）、按 generic + 未建立处理；
- 规则里引用的 event_type 都有生产者（词表守卫，防止规则引用一个永不产出的标签）。
"""

from __future__ import annotations

import logging
from typing import Any

import pytest
import samples
from app.ingestion import conn_states
from app.ingestion.normalizer import normalize_zeek
from app.rules import builtin

# Zeek 官方 conn_state 全集（conn.log "Connection state"）与它应有的语义。
# 增删状态必须同时改两侧 conn_states.py 的两份表；本表是"文档口径"的副本，
# 故意手写以便 CI 抓出「代码改了、语义没想清楚」。
OFFICIAL_CONN_STATES: dict[str, tuple[str, bool]] = {
    "S0": ("scan_attempt", False),
    "S1": ("conn_established", True),
    "SF": ("conn_established", True),
    "S2": ("conn_established", True),
    "S3": ("conn_established", True),
    "RSTO": ("conn_established", True),
    "RSTR": ("conn_established", True),
    "REJ": ("rejected_connection", False),
    "SH": ("connection_shutdown", False),
    "SHR": ("connection_shutdown", False),
    "RSTOS0": ("rejected_connection", False),
    "RSTRH": ("rejected_connection", False),
    "OTH": ("generic", False),
}

# 规则/技能里可能引用的 conn_state 来源标签（表能产出的就这些）。
CONN_SOURCED_LABELS = {
    "scan_attempt",
    "conn_established",
    "rejected_connection",
    "connection_shutdown",
    "generic",
}

# 非 conn_state 来源的事件类型标签全集：由 normalizer 的三个生产函数产出
# （``_http_event_type`` / ``_zeek_event_type`` 非 conn 分支 / ``_wazuh_event_type``）。
# 这是"规则引用的标签必须真的有人产出"的两半之一，另一半是 CONN_SOURCED_LABELS。
OTHER_EVENT_TYPES = {
    "http_login",
    "http_upload",
    "http_error",
    "http_request",
    "port_scan",
    "brute_force",
    "smtp_abuse",
    "tls_anomaly",
    "dns_anomaly",
    "protocol_anomaly",
    "dns_query",
    "tls_session",
    "file_transfer",
    "smtp_activity",
    "ssh_activity",
    "dhcp_activity",
    "zeek_notice",
    "web_attack",
    "wazuh_web_attack",
    "wazuh_malware",
    "wazuh_system_change",
    "wazuh_vulnerability",
    "wazuh_network_alert",
    "wazuh_policy_violation",
    "wazuh_high_alert",
    "wazuh_alert",
}


def _triage_policy() -> Any:
    """两个栈的 triage_policy 路径不同：ndr 是 ``app.triage_policy``，智能体是 ``app.agents.triage_policy``。"""
    try:
        import app.triage_policy as policy
    except ModuleNotFoundError:  # pragma: no cover - 由 --stack=agent 覆盖
        from app.agents import triage_policy as policy
    return policy


def test_table_covers_official_states() -> None:
    """表必须覆盖 Zeek 官方全集：多了要一起想清楚，少了 CI 先炸（别让线上静默 generic）。"""
    missing = sorted(set(OFFICIAL_CONN_STATES) - set(conn_states.CONN_STATES))
    assert not missing, (
        f"conn_states.CONN_STATES 缺官方状态 {missing}："
        "Zeek 新增/本表漏写会让这些连接静默按 generic + 未建立处理"
    )
    extra = sorted(set(conn_states.CONN_STATES) - set(OFFICIAL_CONN_STATES))
    assert not extra, f"conn_states.CONN_STATES 多出 {extra}：请同步本文件的官方口径表"


@pytest.mark.parametrize(("state", "want"), sorted(OFFICIAL_CONN_STATES.items()))
def test_table_semantics(state: str, want: tuple[str, bool]) -> None:
    info = conn_states.CONN_STATES[state]
    assert (info.event_type, info.established) == want


def test_established_set_is_derived_from_table() -> None:
    """「成功连接」集合必须由表推导；手写第二份就是本 bug 的成因。"""
    want = frozenset(s for s, (_, established) in OFFICIAL_CONN_STATES.items() if established)
    assert conn_states.ESTABLISHED_CONN_STATES == want
    # 两个实测坑的钉子：RSTO/RSTR 确实建立过；SH 没有。
    assert {"RSTO", "RSTR"} <= conn_states.ESTABLISHED_CONN_STATES
    assert "SH" not in conn_states.ESTABLISHED_CONN_STATES


@pytest.mark.parametrize(("state", "want"), sorted(OFFICIAL_CONN_STATES.items()))
def test_normalizer_label_matches_table(state: str, want: tuple[str, bool]) -> None:
    """normalizer 只是查表：标签必须与表逐字一致（RSTO/RSTR 曾兜底成 generic）。"""
    doc = samples.envelope({**samples.CONN, "conn_state": state}, "conn", "/logs/conn.log")
    entry = normalize_zeek(doc)
    assert entry is not None
    assert entry.event_type == want[0]


@pytest.mark.parametrize(("state", "want"), sorted(OFFICIAL_CONN_STATES.items()))
def test_has_success_follows_table(state: str, want: tuple[str, bool]) -> None:
    """分诊只认表：conn_state 分支的结果必须等于 established。"""
    policy = _triage_policy()
    assert policy.has_success(None, [state]) is want[1]
    assert policy.has_success(None, [state.lower()]) is want[1]  # 大小写不敏感


def test_has_success_event_type_branch() -> None:
    policy = _triage_policy()
    assert policy.has_success(["http_login"], None) is True
    assert policy.has_success(["http_request"], None) is True
    assert policy.has_success(["conn_established"], None) is True
    # 坑二的核心：connection_shutdown 标签（SH/SHR 产生的那个）不许再算"成功连接"。
    assert policy.has_success(["connection_shutdown"], None) is False
    assert policy.has_success(["scan_attempt", "rejected_connection"], None) is False
    assert policy.has_success(None, None) is False


def test_sh_regression_not_established_not_successful() -> None:
    """SH = 发 SYN 后发 FIN、从未收到 SYN-ACK ⇒ 没建立，不许进任何"成功"分支。"""
    policy = _triage_policy()
    assert conn_states.is_established("SH") is False
    doc = samples.envelope({**samples.CONN, "conn_state": "SH"}, "conn", "/logs/conn.log")
    entry = normalize_zeek(doc)
    assert entry is not None
    assert entry.event_type == "connection_shutdown"
    assert policy.has_success([entry.event_type], [entry.conn_state]) is False


def test_triage_sets_derived_from_table() -> None:
    policy = _triage_policy()
    assert set(policy.SUCCESS_CONN_STATES) == set(conn_states.ESTABLISHED_CONN_STATES)
    assert "connection_shutdown" not in policy.SUCCESS_EVENT_TYPES
    assert {"conn_established", "http_login", "http_upload", "http_request"} == set(
        policy.SUCCESS_EVENT_TYPES
    )
    # 曾经的幻影标签：全仓无生产者，留着会让 HTTP 侧永远判「无成功连接」
    assert "conn_http" not in policy.SUCCESS_EVENT_TYPES


def test_unknown_state_generic_not_established_and_warns_once(caplog: pytest.LogCaptureFixture) -> None:
    """表外状态不静默：按 generic + 未建立处理，并在进程内喊一次警告（提示补表）。"""
    unknown = "ZZ9"  # 用本文件独有的假状态，避免与其它测试的 _unknown_seen 干扰
    assert conn_states.is_known(unknown) is False
    with caplog.at_level(logging.WARNING, logger="app.ingestion.conn_states"):
        assert conn_states.event_type_of(unknown) == "generic"
        assert conn_states.event_type_of(unknown) == "generic"
    hits = [r for r in caplog.records if unknown in r.getMessage()]
    assert len(hits) == 1, f"未知状态应只警告一次，实际 {len(hits)} 次"
    assert conn_states.is_established(unknown) is False


def test_empty_and_whitespace_handling() -> None:
    assert conn_states.event_type_of(None) is None
    assert conn_states.event_type_of("") is None
    assert conn_states.event_type_of("  ") is None
    assert conn_states.event_type_of(" rstO ") == "conn_established"
    assert conn_states.is_established(" sF\t") is True
    assert conn_states.is_known(None) is False


def test_produced_event_types_covers_table_and_generic() -> None:
    produced = conn_states.produced_event_types()
    assert produced == CONN_SOURCED_LABELS
    assert all(conn_states.CONN_STATES[s].event_type in produced for s in OFFICIAL_CONN_STATES)


def _referenced_event_types() -> set[str]:
    found: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if node.get("field") == "event_type":
                value = node.get("value")
                for item in value if isinstance(value, list) else [value]:
                    if isinstance(item, str) and item:
                        found.add(item)
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(builtin.BUILTIN_RULES)
    return found


def test_rule_event_types_have_producers() -> None:
    """词表守卫：规则引用的每个 event_type 都必须真的有生产者，否则规则恒假（静默失效）。"""
    referenced = _referenced_event_types()
    assert referenced, "没有从内置规则里抽到 event_type —— 抽取逻辑或规则结构变了"
    producers = CONN_SOURCED_LABELS | OTHER_EVENT_TYPES
    unknown = sorted(referenced - producers)
    assert not unknown, (
        f"内置规则引用了没有生产者的事件类型 {unknown}："
        "要么是拼写错误（规则永不命中），要么新增了生产者但没更新本文件的词表"
    )


def test_skill_event_types_have_producers() -> None:
    """同一守卫覆盖智能体侧技能：技能声明的 event_types 没人产出 = 该技能永不触发。"""
    try:
        from app.skills import BUILTIN_SKILLS
    except ModuleNotFoundError:  # ndr 栈没有技能模块
        pytest.skip("本栈没有 app.skills（智能体侧模块）")
    referenced = {
        item
        for skill in BUILTIN_SKILLS
        for item in (skill.get("event_types") or [])
        if isinstance(item, str) and item
    }
    assert referenced, "没有从技能里抽到 event_types —— 技能结构变了"
    producers = CONN_SOURCED_LABELS | OTHER_EVENT_TYPES
    unknown = sorted(referenced - producers)
    assert not unknown, (
        f"技能声明了没有生产者的事件类型 {unknown}：技能永远不会被这些事件触发"
    )
