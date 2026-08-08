from agents.remeasure_report import _aggregate, paired_bootstrap


def test_aggregate_recomputes_micro_f1():
    got = _aggregate([
        {"tp": 2, "fp": 1, "fn": 1},
        {"tp": 1, "fp": 0, "fn": 2},
    ])
    assert got["tp"] == 3
    assert got["fp"] == 1
    assert got["fn"] == 3
    assert round(got["precision"], 6) == 0.75
    assert round(got["recall"], 6) == 0.5
    assert round(got["f1"], 6) == 0.6


def test_paired_bootstrap_preserves_direction_of_large_effect():
    names = ["a", "b", "c", "d"]
    rows = {
        "raw": {n: {"tp": 2, "fp": 0, "fn": 0} for n in names},
        "stripped": {n: {"tp": 1, "fp": 1, "fn": 1} for n in names},
        "anon": {n: {"tp": 0, "fp": 2, "fn": 2} for n in names},
    }
    boot = paired_bootstrap(rows, names, n=200)
    assert boot["delta_f1_95ci"]["raw_minus_stripped"][0] > 0
    assert boot["delta_f1_95ci"]["stripped_minus_anon"][0] > 0
    assert boot["delta_f1_95ci"]["raw_minus_anon"][0] > 0
