"""AnalysisFacts / verdict contract 的纯函数守卫。"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from app.analysis import facts, queue


def test_merge_task_hint_keeps_new_events_and_domains() -> None:
    old = {
        "事件ID": ["e1"],
        "dns_domains": ["smtcdns.com"],
        "受影响资产": [{"kind": "ip", "value": "10.1.2.3"}],
        "reuse_identity": "family-1",
    }
    new = {
        "事件ID": ["e2", "e1"],
        "dns_domains": ["tfogc.com"],
        "受影响资产": [{"kind": "ip", "value": "10.1.2.4"}],
        "reuse_identity": "family-1",
    }
    merged, changed = queue.merge_task_hint(old, new)
    assert changed is True
    assert merged["reuse_identity"] == "family-1"
    assert merged["事件ID"] == ["e1", "e2"]
    assert merged["dns_domains"] == ["smtcdns.com", "tfogc.com"]
    assert {"kind": "ip", "value": "10.1.2.4"} in merged["受影响资产"]


def test_success_state_distinguishes_established_and_unknown() -> None:
    established: Any = SimpleNamespace(
        conn_states=["SF"],
        evidence=[{"status_code": 200}],
    )
    out = facts._success_state([established])
    assert out["state"] == "success"

    unknown: Any = SimpleNamespace(conn_states=[], evidence=[])
    assert facts._success_state([unknown])["state"] == "unknown"


def test_dns_fields_promoted_from_nested_block() -> None:
    sample = {
        "dns": {"qtype": "16", "rcode": "0", "answers": ["v=spf1"]},
        "payload_printable": "aafd8cefac83e7667d4b1020157fd6db.v.smtcdns.com",
    }
    assert facts._qtype_of(sample) == "16"
    assert facts._rcode_of(sample) == "0"
    assert facts._answers_of(sample) == ["v=spf1"]


def test_contract_rejects_tp_without_malicious_basis() -> None:
    violations = queue._contract_violations(
        verdict="true_positive",
        basis={"evidence_categories": ["known_benign_infrastructure"]},
        evidence_refs=[],
        facts={"assets": {}, "dns": {"registrable_domains": ["tfogc.com"]}},
    )
    assert any("恶意证据" in item for item in violations)
    assert any("evidence_refs" in item for item in violations)


def test_contract_accepts_tp_with_malicious_basis() -> None:
    violations = queue._contract_violations(
        verdict="true_positive",
        basis={
            "evidence_categories": ["malicious_c2"],
            "contradictions_checked": ["prior_findings: none", "domain_owner: unknown"],
        },
        evidence_refs=["es:idx/1"],
        facts={"assets": {}, "dns": {"registrable_domains": []}},
    )
    assert violations == []


def test_contract_rejects_authorized_scanner_tp_without_malicious_evidence() -> None:
    violations = queue._contract_violations(
        verdict="true_positive",
        basis={"evidence_categories": ["authorized_scanner"]},
        evidence_refs=["es:idx/1"],
        facts={
            "dns": {},
            "assets": {
                "10.1.2.3": {
                    "role": "security_appliance",
                    "authorization": "authorized",
                }
            },
        },
    )
    assert any("已授权" in item for item in violations)


def test_contract_requires_benign_basis_for_fp() -> None:
    violations = queue._contract_violations(
        verdict="false_positive",
        basis={},
        evidence_refs=[],
        facts={},
    )
    assert violations
