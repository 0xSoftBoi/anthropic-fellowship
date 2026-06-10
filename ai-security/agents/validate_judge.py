"""
Validate the semantic_rescorer LLM judge against a frozen gold standard.

Measures whether the Haiku judge's per-decision match verdicts agree with
hand-labeled ground truth (benchmarks/judge_gold_standard.json). Because the
judge is nondeterministic, each unit is judged K times; we report per-run
accuracy, majority-vote metrics vs gold (accuracy, precision/recall/F1, Cohen's
kappa), and run-to-run stability (how often the K verdicts for a unit disagree).

This is the calibration the 37% semantic-F1 headline needs: it tells you how much
to trust the judge that produced it.

Usage:
    export ANTHROPIC_API_KEY=sk-...
    python -m agents.validate_judge            # K=3 default
    K=5 python -m agents.validate_judge
"""

import json
import os
from pathlib import Path

from anthropic import Anthropic

from benchmarks.bridge_contracts_real import VULNERABILITY_TAXONOMY
from agents.semantic_rescorer import judge_match, JUDGE_MODEL

K = int(os.environ.get("K", "3"))
GOLD = Path(__file__).parent.parent / "benchmarks" / "judge_gold_standard.json"


def load_units():
    gold = json.loads(GOLD.read_text())
    results = json.loads((Path(__file__).parent.parent / gold["source_results"]).read_text())
    pc = results["real_agentic"]["per_contract"]
    units = []
    for lab in gold["labels"]:
        pool = pc[lab["contract"]]["metrics"].get("false_positives", [])
        units.append({**lab, "pool": pool})
    return units


def kappa(a, b):
    """Cohen's kappa for two boolean label lists."""
    n = len(a)
    po = sum(1 for x, y in zip(a, b) if x == y) / n
    pa_t = sum(a) / n
    pb_t = sum(b) / n
    pe = pa_t * pb_t + (1 - pa_t) * (1 - pb_t)
    return (po - pe) / (1 - pe) if (1 - pe) else 1.0


def main():
    units = load_units()
    client = Anthropic()
    n_true = sum(1 for u in units if u["gold"])
    print(f"Validating judge={JUDGE_MODEL} over {len(units)} units "
          f"({n_true} gold-true / {len(units)-n_true} gold-false), K={K} runs each\n")

    # runs[k][i] = judge verdict (bool) for unit i on run k
    runs = [[] for _ in range(K)]
    tokens = 0
    for k in range(K):
        for u in units:
            desc = VULNERABILITY_TAXONOMY.get(u["gt"], {}).get("description", u["gt"])
            matched, _f, _why, used = judge_match(client, u["gt"], desc, u["pool"])
            runs[k].append(bool(matched))
            tokens += used

    gold = [u["gold"] for u in units]

    # per-run accuracy
    print("Per-run accuracy vs gold:")
    for k in range(K):
        acc = sum(1 for j, g in zip(runs[k], gold) if j == g) / len(gold)
        print(f"  run {k+1}: {acc:.0%}")

    # majority vote per unit
    maj = [sum(runs[k][i] for k in range(K)) > K / 2 for i in range(len(units))]

    tp = sum(1 for j, g in zip(maj, gold) if j and g)
    fp = sum(1 for j, g in zip(maj, gold) if j and not g)
    fn = sum(1 for j, g in zip(maj, gold) if not j and g)
    tn = sum(1 for j, g in zip(maj, gold) if not j and not g)
    acc = (tp + tn) / len(gold)
    prec = tp / (tp + fp) if (tp + fp) else 0
    rec = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0

    # stability: fraction of units where all K runs agree
    stable = sum(1 for i in range(len(units)) if len({runs[k][i] for k in range(K)}) == 1)

    print(f"\nMajority-vote (K={K}) vs gold:")
    print(f"  accuracy : {acc:.0%}")
    print(f"  precision: {prec:.0%}   recall: {rec:.0%}   F1: {f1:.0%}")
    print(f"  Cohen's kappa: {kappa(maj, gold):.2f}")
    print(f"  confusion: TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"\nStability: {stable}/{len(units)} units unanimous across {K} runs "
          f"({stable/len(units):.0%})")
    print(f"Judge tokens: {tokens:,}  model: {JUDGE_MODEL}")

    # show disagreements (majority judge != gold)
    print("\nDisagreements (majority judge vs gold):")
    any_d = False
    for i, u in enumerate(units):
        if maj[i] != u["gold"]:
            any_d = True
            print(f"  [{u['contract']}] {u['gt']}: judge={'match' if maj[i] else 'no'} "
                  f"gold={'match' if u['gold'] else 'no'}  — {u['note'][:70]}")
    if not any_d:
        print("  (none)")

    out = GOLD.with_name("judge_validation_report.json")
    out.write_text(json.dumps({
        "judge_model": JUDGE_MODEL, "K": K, "n_units": len(units),
        "per_run_accuracy": [sum(1 for j, g in zip(runs[k], gold) if j == g)/len(gold) for k in range(K)],
        "majority": {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1,
                     "kappa": kappa(maj, gold), "tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "stability_unanimous": stable, "stability_frac": stable/len(units),
        "judge_tokens": tokens,
    }, indent=2))
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
