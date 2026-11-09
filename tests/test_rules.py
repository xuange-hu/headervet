"""Registry integrity: ids stable, severities valid, one rule per concern."""

from __future__ import annotations

import re

from headervet.model import SEVERITIES
from headervet.rules import RULES, all_rules, by_id, groups


def test_registry_size_is_the_documented_36():
    assert len(RULES) == 36


def test_ids_are_unique_and_prefixed():
    ids = [r.id for r in all_rules()]
    assert len(ids) == len(set(ids))
    assert all(re.fullmatch(r"HDV\d{3}", rid) for rid in ids)


def test_severities_are_valid():
    for r in all_rules():
        assert r.severity in SEVERITIES, r.id


def test_every_rule_has_why_fix_group():
    for r in all_rules():
        assert r.group, r.id
        assert len(r.why) > 40, f"{r.id}: why too thin"
        assert len(r.fix) > 10, f"{r.id}: fix too thin"


def test_pass_numbers_match_id_family():
    for r in all_rules():
        if r.id.startswith("HDV0"):
            assert r.pass_no == 1, r.id
        elif r.id.startswith("HDV1"):
            assert r.pass_no == 2, r.id
        else:
            assert r.pass_no == 3, r.id


def test_cwe_format():
    for r in all_rules():
        if r.cwe:
            assert re.fullmatch(r"CWE-\d+", r.cwe), r.id


def test_by_id_is_case_insensitive_and_total():
    assert by_id("hdv001").id == "HDV001"
    assert by_id("NOPE-999") is None


def test_groups_are_nonempty_and_covered():
    gs = groups()
    assert len(gs) >= 8
    assert all(g in gs for g in ("transport", "csp", "cookies", "cors"))


def test_critical_rules_exist_for_the_worst_cors_shapes():
    assert RULES["HDV102"].severity == "critical"
    assert RULES["HDV106"].severity == "critical"
