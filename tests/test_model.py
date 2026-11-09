"""Model semantics: severity ranking direction, gate, risk, counts."""

from __future__ import annotations

from headervet.model import SEVERITY_ORDER, SEVERITY_RANK, Finding, ScanResult
from headervet.rules import by_id


def _finding(rid: str) -> Finding:
    rule = by_id(rid)
    return Finding(rule=rule, path="a", line=1, snippet="", detail="d")


def test_critical_is_0_for_display_and_top_rank():
    assert SEVERITY_ORDER["critical"] == 0
    assert SEVERITY_RANK["critical"] > SEVERITY_RANK["high"]


def test_gate_high_fires_on_critical_and_high_only():
    result = ScanResult(root=".", findings=[_finding("HDV009")])  # medium
    assert not result.gate("high")
    result2 = ScanResult(root=".", findings=[_finding("HDV004")])  # high
    assert result2.gate("high")
    result3 = ScanResult(root=".", findings=[_finding("HDV102")])  # critical
    assert result3.gate("high")


def test_gate_none_never_fires():
    result = ScanResult(root=".", findings=[_finding("HDV102")])
    assert not result.gate("none")
    assert not result.gate(None)


def test_risk_is_capped_at_100():
    many = [_finding("HDV102") for _ in range(10)]  # 25 each
    result = ScanResult(root=".", findings=many)
    assert result.risk_score() == 100


def test_worst_and_counts():
    result = ScanResult(root=".", findings=[_finding("HDV009"), _finding("HDV004")])
    assert result.worst() == "high"
    counts = result.counts()
    assert counts["high"] == 1 and counts["medium"] == 1


def test_rules_hit_is_deduped_in_severity_order():
    result = ScanResult(root=".", findings=[_finding("HDV009"), _finding("HDV004"), _finding("HDV009")])
    assert result.rules_hit() == ["HDV004", "HDV009"]
