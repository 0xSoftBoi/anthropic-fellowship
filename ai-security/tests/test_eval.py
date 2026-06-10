"""
Unit tests for the BRIDGE-bench evaluation logic and dataset integrity.

These are pure-CPU tests — no API key, no model calls — so they run in CI on
every push. They lock down the scoring math (the numbers in the README depend on
it) and guard against the dataset-consistency bugs that silently degrade a run.

    python -m pytest tests/ -q
"""
import math

import pytest

from agents.benchmark_runner import evaluate_findings, fuzzy_match
from benchmarks.validate_dataset import validate


def _finding(t):
    return {"type": t, "severity": "high"}


def _gt(t):
    return {"type": t, "severity": "high"}


# ── fuzzy_match ──────────────────────────────────────────────────────────────

def test_fuzzy_exact_match():
    assert fuzzy_match("reentrancy", "reentrancy")


def test_fuzzy_equivalence_match():
    # fuzzy_match keys on the model's finding string (arg 1) and looks for the
    # ground-truth key (arg 2) in its equivalence list — both directions covered.
    assert fuzzy_match("input_validation", "missing_input_validation")
    assert fuzzy_match("missing_input_validation", "input_validation")


def test_fuzzy_non_match():
    assert not fuzzy_match("reentrancy", "oracle_price_manipulation")


# ── evaluate_findings ────────────────────────────────────────────────────────

def test_perfect_score():
    m = evaluate_findings([_finding("reentrancy")], [_gt("reentrancy")])
    assert m["tp"] == 1 and m["fp"] == 0 and m["fn"] == 0
    assert m["precision"] == 1.0 and m["recall"] == 1.0 and m["f1"] == 1.0


def test_all_false_positives():
    m = evaluate_findings([_finding("reentrancy"), _finding("reentrancy")], [_gt("oracle_price_manipulation")])
    assert m["tp"] == 0 and m["fn"] == 1 and m["fp"] >= 1
    assert m["f1"] == 0


def test_empty_findings():
    m = evaluate_findings([], [_gt("reentrancy")])
    assert m["tp"] == 0 and m["fp"] == 0 and m["fn"] == 1
    assert m["recall"] == 0.0


def test_each_gt_matched_once():
    # two identical findings cannot satisfy one ground-truth twice
    m = evaluate_findings([_finding("reentrancy"), _finding("reentrancy")], [_gt("reentrancy")])
    assert m["tp"] == 1 and m["fp"] == 1


def test_f1_is_harmonic_mean():
    m = evaluate_findings(
        [_finding("reentrancy"), _finding("oracle_price_manipulation")],
        [_gt("reentrancy"), _gt("missing_access_control")],
    )
    p, r = m["precision"], m["recall"]
    expected = 2 * p * r / (p + r) if (p + r) else 0
    assert math.isclose(m["f1"], expected, rel_tol=1e-9)


# ── Cohen's kappa (judge validation math) ────────────────────────────────────

def test_kappa_perfect_and_chance():
    # import lazily — validate_judge pulls anthropic; skip cleanly if unavailable
    try:
        from agents.validate_judge import kappa
    except Exception:
        pytest.skip("validate_judge import unavailable (anthropic not installed)")
    assert math.isclose(kappa([True, False, True], [True, False, True]), 1.0)
    # total disagreement on a balanced split → strongly negative
    assert kappa([True, True, False, False], [False, False, True, True]) < 0


# ── dataset integrity ────────────────────────────────────────────────────────

def test_dataset_has_no_hard_errors():
    errors, warnings, stats = validate()
    assert errors == [], f"dataset integrity errors: {errors}"


def test_dataset_source_counts():
    _, _, stats = validate()
    # the committed multi-domain corpus: bridges 16, DEX 5, lending 3
    assert stats["bridge"]["with_source"] == 16
    assert stats["defi"]["with_source"] == 5
    assert stats["lending"]["with_source"] == 3
