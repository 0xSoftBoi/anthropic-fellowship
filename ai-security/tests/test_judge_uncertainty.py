"""
Tests for the judge-validity analysis.

The headline claim — "swapping the Haiku judge for the human gold labels moves bridge F1
from 37% to 52%" — is arithmetic over committed artifacts, so it can and should be pinned.
The most important test is the REPRODUCTION GATE: scoring with the judge's own decisions
must reproduce the committed F1 exactly. If that breaks, the analysis is measuring
something other than the committed run and every derived number is void.

Pure-CPU, no API key.

    python -m pytest tests/test_judge_uncertainty.py -q
"""
import json

import pytest

from agents.judge_uncertainty import (
    BRIDGE,
    build,
    gold_map,
    prf,
    recovery_rate,
    score,
)


@pytest.fixture(scope="module")
def domains():
    return build()


def test_reproduces_committed_bridge_f1(domains):
    """Scoring the judge's own decisions must match the committed rescored file."""
    bridges, _ = domains
    rate = recovery_rate(bridges)
    tp, fp, fn = score(bridges, {n: r["n_promoted"] for n, r in bridges.items()}, rate)
    committed = json.loads(BRIDGE.read_text())["overall_semantic"]
    assert abs(prf(tp, fp, fn)[2] - committed["f1"]) < 1e-9
    assert (tp, fp, fn) == (committed["tp"], committed["fp"], committed["fn"])


def test_reproduces_committed_dexlend_f1(domains):
    _, dexlend = domains
    rate = recovery_rate(dexlend)
    tp, fp, fn = score(dexlend, {n: r["n_promoted"] for n, r in dexlend.items()}, rate)
    from agents.judge_uncertainty import DEXLEND
    committed = json.loads(DEXLEND.read_text())["overall_semantic"]
    assert abs(prf(tp, fp, fn)[2] - committed["f1"]) < 1e-9


def test_gold_standard_covers_every_bridge_decision(domains):
    """
    The gold standard must label exactly the decisions the judge made — this is what
    makes the gold-corrected F1 a direct measurement rather than an extrapolation.
    """
    bridges, _ = domains
    gold = gold_map()
    decisions = {
        (name, gt)
        for name, rec in bridges.items()
        for gt in rec["promoted_gts"] + rec["not_promoted_gts"]
    }
    assert decisions == set(gold), (
        f"gold/decision mismatch: {len(decisions ^ set(gold))} differing units"
    )


def test_judge_is_conservative_relative_to_gold(domains):
    """
    The judge promotes fewer matches than the human labeler, so gold-corrected F1 should
    be HIGHER. This is the direction the repo already claimed ("37% is a lower bound") —
    the test pins that the claim holds and is non-trivial in size.
    """
    bridges, _ = domains
    gold = gold_map()
    rate = recovery_rate(bridges)

    judged = score(bridges, {n: r["n_promoted"] for n, r in bridges.items()}, rate)
    gold_k = {
        name: sum(
            1 for gt in rec["promoted_gts"] + rec["not_promoted_gts"]
            if gold[(name, gt)]["gold"]
        )
        for name, rec in bridges.items()
    }
    golded = score(bridges, gold_k, rate)

    judge_f1, gold_f1 = prf(*judged)[2], prf(*golded)[2]
    assert gold_f1 > judge_f1, "judge should be conservative vs its own gold standard"
    assert gold_f1 - judge_f1 > 0.05, (
        f"expected a material gap; saw {(gold_f1 - judge_f1) * 100:.1f} points"
    )


def test_headline_is_sensitive_to_few_decisions(domains):
    """
    The fragility claim: a handful of flipped judge calls moves the headline several
    points. Pins that the sensitivity analysis is reporting a real effect.
    """
    bridges, dexlend = domains
    rb, rd = recovery_rate(bridges), recovery_rate(dexlend)
    btp, bfp, bfn = score(bridges, {n: r["n_promoted"] for n, r in bridges.items()}, rb)
    dtp, dfp, dfn = score(dexlend, {n: r["n_promoted"] for n, r in dexlend.items()}, rd)
    base = prf(btp + dtp, bfp + dfp, bfn + dfn)[2]
    plus5 = prf(btp + dtp + 5, bfp + dfp - 5 * ((rb + rd) / 2), bfn + dfn - 5)[2]
    assert plus5 - base >= 0.04, "5 flipped decisions should move the headline ~5 points"


def test_recovery_rates_are_plausible(domains):
    """FP-pool recovery per promotion must be in (0, 1] — outside that, the model is wrong."""
    bridges, dexlend = domains
    for name, d in (("bridges", bridges), ("dex/lending", dexlend)):
        r = recovery_rate(d)
        assert 0 < r <= 1.0, f"{name}: implausible recovery rate {r}"
