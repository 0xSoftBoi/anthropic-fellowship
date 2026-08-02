"""
Tests for the live / negative-control dataset.

Two things must hold for this domain to mean anything:
  1. It is a genuine negative-control set — empty ground truth, real committed source,
     and no answer-leaking header (for a negative, "this is clean" IS the leaked answer).
  2. Specificity is scored correctly — the axis F1 cannot measure.

Pure-CPU, no API key.

    python -m pytest tests/test_live.py -q
"""
import json

import pytest

from agents.specificity import score_negative_controls
from benchmarks.live_contracts import (
    load_external_dependency_registry,
    load_live_contracts,
)


@pytest.fixture(scope="module")
def live():
    return load_live_contracts()


def test_all_entries_are_negative_controls(live):
    assert len(live) >= 4
    for c in live:
        assert c["metadata"]["negative_control"] is True
        assert c["ground_truth"]["vulnerabilities"] == [], c["name"]
        assert c["metadata"]["in_training_data_as_incident"] is False


def test_first_party_contracts_have_real_source(live):
    with_source = [c for c in live if (c["source"] or "").strip()]
    assert len(with_source) >= 3, "expected the deployed first-party contracts to carry source"
    for c in with_source:
        assert "contract" in c["source"].lower()


def test_committed_source_does_not_leak_the_answer(live):
    """
    For a negative control the leakage risk is a header signalling 'nothing to find'.
    The header must be provenance only — no audit/clean/bug words, and no ground-truth
    label (there are none, but assert the words that would bias the model aren't present).
    """
    banned = ("audit", "hardened", "no known", "clean", "fixed", "vulnerab", "exploit", "negative control")
    for c in live:
        if not c["source"]:
            continue
        header = "\n".join(
            ln for ln in c["source"].splitlines()[:8] if ln.strip().startswith("//")
        ).lower()
        for w in banned:
            assert w not in header, f"{c['name']} header leaks bias word {w!r}: {header!r}"


def test_audit_facts_live_in_metadata_not_the_prompt(live):
    """The audit/clean facts must be recorded — just not where the model can read them."""
    staking = next(c for c in live if c["name"] == "suwappu_staking")
    assert "audit_note" in staking["metadata"]
    assert staking["metadata"]["audit_note"]  # non-empty
    assert "audit" not in (staking["source"] or "").lower()


def test_external_dependency_registry_is_catalogued():
    ext = load_external_dependency_registry()
    assert len(ext) >= 8
    for d in ext:
        assert d["address"].startswith("0x") and len(d["address"]) == 42
        assert d["memorization_exposure"] in ("low", "medium", "high")


# ── specificity scorer ───────────────────────────────────────────────────────

def _fake_results(findings_per_contract):
    return {
        "live_agentic": {
            "per_contract": {
                name: {"metrics": {"fp": n, "tp": 0, "fn": 0,
                                   "false_positives": [f"finding_{i}" for i in range(n)]}}
                for name, n in findings_per_contract.items()
            }
        }
    }


def test_specificity_perfect_when_nothing_flagged():
    r = score_negative_controls(_fake_results({"a": 0, "b": 0, "c": 0, "d": 0}))
    assert r["live_agentic"]["specificity"] == 1.0
    assert r["live_agentic"]["clean"] == 4
    assert r["live_agentic"]["mean_findings_per_contract"] == 0.0


def test_specificity_drops_with_false_positives():
    r = score_negative_controls(_fake_results({"a": 0, "b": 2, "c": 0, "d": 1}))["live_agentic"]
    assert r["clean"] == 2 and r["n_contracts"] == 4
    assert r["specificity"] == 0.5
    assert r["total_findings"] == 3
    assert r["mean_findings_per_contract"] == 0.75


def test_specificity_distinguishes_clean_from_total_failure():
    """
    The whole point: on an empty ground truth, F1 is 0 whether the model was perfect or
    useless. Specificity must separate the two.
    """
    perfect = score_negative_controls(_fake_results({"a": 0, "b": 0}))["live_agentic"]
    useless = score_negative_controls(_fake_results({"a": 5, "b": 5}))["live_agentic"]
    assert perfect["specificity"] == 1.0
    assert useless["specificity"] == 0.0


def test_committed_static_baseline_reproduces(tmp_path):
    """If the committed live static baseline exists, its specificity must recompute."""
    from pathlib import Path
    f = Path(__file__).parent.parent / "results_live.json"
    if not f.exists():
        pytest.skip("results_live.json not committed")
    r = score_negative_controls(json.loads(f.read_text()))
    assert "live_static" in r
    assert 0.0 <= r["live_static"]["specificity"] <= 1.0
