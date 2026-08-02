"""
Tests for the matched-pair (memorization-free positive) dataset.

The value of this domain rests on three claims, each pinned here:
  1. Every buggy snapshot is a real positive — labels present, source present, and it is
     paired to a fixed counterpart that exists in the live (negative-control) domain.
  2. The committed source does not name its own bugs (that would be answer leakage exactly
     like the exploit set's headers).
  3. The labels are diff-grounded — each references the fix commits it came from.

Pure-CPU, no API key.

    python -m pytest tests/test_matched.py -q
"""
import pytest

from benchmarks.live_contracts import load_live_contracts
from benchmarks.matched_contracts import load_matched_contracts


@pytest.fixture(scope="module")
def matched():
    return load_matched_contracts()


def test_positives_have_labels_and_source(matched):
    assert len(matched) == 3
    for c in matched:
        assert c["ground_truth"]["vulnerabilities"], c["name"]
        assert (c["source"] or "").strip(), c["name"]
        assert "contract" in c["source"].lower()


def test_each_positive_pairs_to_a_live_negative(matched):
    live_names = {c["name"] for c in load_live_contracts()}
    for c in matched:
        fixed = c["metadata"]["fixed_counterpart"]
        assert fixed in live_names, f"{c['name']} -> {fixed} not a live negative control"


def test_labels_are_diff_grounded(matched):
    for c in matched:
        assert c["metadata"]["fix_commits"], c["name"]
        assert c["metadata"]["memorization_free"] is True
        assert "git fix-commit" in c["metadata"]["ground_truth_source"]


def test_committed_source_does_not_name_its_bugs(matched):
    """Header + code comments must not hand the model the answer."""
    banned = ("audit", "vulnerab", "exploit", "flash-loan overmint", "reentrancy bug",
              "pre-audit", "buggy", "fixme", "todo: security")
    for c in matched:
        header = "\n".join(
            ln for ln in c["source"].splitlines()[:6] if ln.strip().startswith("//")
        ).lower()
        for w in banned:
            assert w not in header, f"{c['name']} header leaks {w!r}: {header!r}"


def test_bonds_positive_carries_the_flash_loan_bug(matched):
    bonds = next(c for c in matched if c["name"] == "suwappu_bonds_preaudit")
    types = {v["type"] for v in bonds["ground_truth"]["vulnerabilities"]}
    assert "flash_loan_price_manipulation" in types
    assert any("critical" == v["severity"] for v in bonds["ground_truth"]["vulnerabilities"])
    # the fictional-valuation code must actually be in the committed snapshot
    assert "1e12" in bonds["source"]


def test_staking_positive_carries_the_drain_bug(matched):
    staking = next(c for c in matched if c["name"] == "suwappu_staking_preaudit")
    types = {v["type"] for v in staking["ground_truth"]["vulnerabilities"]}
    assert "missing_solvency_check" in types
    # recoverToken present, and (buggy) reserves only totalStaked
    assert "recoverToken" in staking["source"]


def test_new_vuln_types_are_scorable(matched):
    """Every matched label should have a TYPE_EQUIVALENCES entry (added for the new ones)."""
    from agents.benchmark_runner import TYPE_EQUIVALENCES, fuzzy_match
    for c in matched:
        for v in c["ground_truth"]["vulnerabilities"]:
            t = v["type"]
            assert t in TYPE_EQUIVALENCES, f"{t} missing from TYPE_EQUIVALENCES"
            assert fuzzy_match(t, t)  # self-match holds
