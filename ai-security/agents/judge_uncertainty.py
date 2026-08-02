"""
Judge-validity analysis: how much does the headline F1 depend on the judge?

WHY
---
The semantic F1 in this repo is produced by an LLM-as-judge that decides, for each
ground-truth vulnerability the string matcher missed, whether some unmatched model
finding refers to the same bug. Every promotion moves a MISS to a TP, so the headline
number is a direct function of ~53 binary judge calls. It has always been reported as a
point estimate ("37%", "35%"). That is not honest for a measurement resting on 53 coin
flips made by a small model with a *measured* error rate.

This module quantifies that dependence WITHOUT an API key, using only committed
artifacts. Three analyses:

1. GOLD-CORRECTED F1 (a direct measurement, not a simulation).
   `benchmarks/judge_gold_standard.json` hand-labels the truth for exactly the 38 bridge
   decisions the judge made. So for bridges we do not need to model judge error at all —
   we can score with the human labels instead and read off what the judge cost us.

2. UNCERTAINTY INTERVAL.
   A cluster bootstrap over contracts (the sampling unit — 16/5/3 contracts is small),
   combined with judge-error propagation for DEX/lending, where no gold standard exists
   and the bridge-derived error rates must be extrapolated. Reported as a range, not a
   point.

3. SENSITIVITY.
   How many judge decisions have to flip to move the headline by 5 points — the "how
   fragile is this number" question a reviewer should ask.

CAVEATS, stated up front:
- The gold standard is SINGLE-ANNOTATOR and IN-SAMPLE (same 38 decisions it scores). It
  is the repo author's judgment, not ground truth; a second labeler is needed for
  inter-annotator agreement. The gold-corrected F1 is therefore "what one careful human
  says", not "the true F1".
- 5 of the 38 gold labels are flagged BORDERLINE by that annotator. Analysis 1 is
  re-run with those flipped, to bound annotator-discretion effects.
- DEX/lending have NO gold standard. Their judge error is extrapolated from bridges,
  which is exactly the kind of extrapolation this repo criticizes elsewhere — so the
  all-24 interval is wider and flagged.
- FP accounting: each promotion also removes one finding from the FP pool. That held
  exactly on bridges (80 -> 60 for 20 promotions) but not on DEX/lending (34 -> 29 for
  7 promotions, since some findings satisfied two labels). The observed per-domain
  recovery rate is used so the point estimate reproduces the committed files exactly.

    python -m agents.judge_uncertainty
"""

from __future__ import annotations

import json
import random
from pathlib import Path

ROOT = Path(__file__).parent.parent
GOLD = ROOT / "benchmarks" / "judge_gold_standard.json"
BRIDGE = ROOT / "results_real__claude-opus-4-8__rescored.json"
DEXLEND = ROOT / "results_defi_lending__claude-opus-4-8__rescored.json"
RAW_BRIDGE = ROOT / "results_real__claude-opus-4-8.json"
RAW_DEXLEND = ROOT / "results_defi_lending__claude-opus-4-8.json"

N_BOOT = 20000
SEED = 20260802


def prf(tp: float, fp: float, fn: float) -> tuple[float, float, float]:
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f


def _beta(a: float, b: float, rng: random.Random) -> float:
    """Beta sample via two Gammas (stdlib only — numpy isn't a dependency here)."""
    x = rng.gammavariate(a, 1.0)
    y = rng.gammavariate(b, 1.0)
    return x / (x + y) if (x + y) else 0.0


def load_domain(rescored: Path):
    """Per-contract judge decisions + the string-match baseline they were applied to."""
    j = json.loads(rescored.read_text())
    out = {}
    for name, m in j["per_contract"].items():
        n_prom = len(m["promoted"])
        n_miss = len(m["still_missed"])
        out[name] = {
            "sem_tp": m["tp"], "sem_fp": m["fp"], "sem_fn": m["fn"],
            "n_promoted": n_prom,          # judge said MATCH
            "n_not_promoted": n_miss,      # judge said NO-MATCH
            "promoted_gts": [p["gt"] for p in m["promoted"]],
            "not_promoted_gts": list(m["still_missed"]),
            # string-match baseline this contract started from
            "str_tp": m["tp"] - n_prom,
            "str_fn": n_prom + n_miss,
        }
        out[name]["str_fp"] = m["fp"] + (m["tp"] - out[name]["str_tp"]) * 0  # filled below
    # recover string fp from the raw results file (exact, no inference)
    return out, j


def _string_fp(raw: Path, names: set[str]) -> dict:
    j = json.loads(raw.read_text())
    fp = {}
    for key in [k for k in j if k.endswith(("_agentic", "_hybrid", "_claude"))]:
        for name, info in j[key].get("per_contract", {}).items():
            if name in names:
                fp[name] = info["metrics"]["fp"]
    return fp


def build():
    """Assemble per-contract records for both domains."""
    bridges, _ = load_domain(BRIDGE)
    dexlend, _ = load_domain(DEXLEND)
    for d, raw in ((bridges, RAW_BRIDGE), (dexlend, RAW_DEXLEND)):
        fps = _string_fp(raw, set(d))
        for name, rec in d.items():
            rec["str_fp"] = fps[name]
    return bridges, dexlend


def recovery_rate(domain: dict) -> float:
    """
    Observed FP-pool reduction per promotion. 1.0 on bridges; <1 where one finding
    satisfied two labels. Used so the point estimate reproduces the committed files.
    """
    prom = sum(r["n_promoted"] for r in domain.values())
    drop = sum(r["str_fp"] - r["sem_fp"] for r in domain.values())
    return (drop / prom) if prom else 1.0


def score(domain: dict, promotions_by_contract: dict, rate: float):
    """Recompute aggregate tp/fp/fn given a promotion count per contract."""
    tp = fp = fn = 0.0
    for name, rec in domain.items():
        k = promotions_by_contract[name]
        tp += rec["str_tp"] + k
        fn += rec["str_fn"] - k
        fp += rec["str_fp"] - k * rate
    return tp, fp, fn


def gold_map() -> dict:
    g = json.loads(GOLD.read_text())["labels"]
    return {
        (x["contract"], x["gt"]): {
            "gold": bool(x["gold"]),
            "borderline": "BORDERLINE" in (x.get("note") or "").upper(),
        }
        for x in g
    }


def main() -> int:
    rng = random.Random(SEED)
    bridges, dexlend = build()
    r_bridge, r_dex = recovery_rate(bridges), recovery_rate(dexlend)
    gold = gold_map()

    # ── 0. reproduce the committed numbers (sanity gate) ─────────────────────
    as_judged_b = {n: r["n_promoted"] for n, r in bridges.items()}
    as_judged_d = {n: r["n_promoted"] for n, r in dexlend.items()}
    btp, bfp, bfn = score(bridges, as_judged_b, r_bridge)
    dtp, dfp, dfn = score(dexlend, as_judged_d, r_dex)
    committed_b = prf(btp, bfp, bfn)
    committed_all = prf(btp + dtp, bfp + dfp, bfn + dfn)

    ref_b = json.loads(BRIDGE.read_text())["overall_semantic"]["f1"]
    assert abs(committed_b[2] - ref_b) < 1e-6, f"reproduction failed: {committed_b[2]} vs {ref_b}"

    print("=" * 74)
    print("JUDGE VALIDITY: how much does the headline depend on the judge?")
    print("=" * 74)
    print(f"\nReproduced committed numbers  bridges F1 {committed_b[2]:.1%} | "
          f"all-24 F1 {committed_all[2]:.1%}   ✓")

    # ── 1. gold-corrected F1 (direct measurement, bridges only) ──────────────
    n_gold_missing = 0
    def gold_promotions(flip_borderline: bool = False) -> dict:
        nonlocal n_gold_missing
        out = {}
        for name, rec in bridges.items():
            k = 0
            for gt in rec["promoted_gts"] + rec["not_promoted_gts"]:
                g = gold.get((name, gt))
                if g is None:
                    n_gold_missing += 1
                    continue
                val = g["gold"]
                if flip_borderline and g["borderline"]:
                    val = not val
                k += 1 if val else 0
            out[name] = k
        return out

    gtp, gfp, gfn = score(bridges, gold_promotions(), r_bridge)
    gold_b = prf(gtp, gfp, gfn)
    ftp, ffp, ffn = score(bridges, gold_promotions(flip_borderline=True), r_bridge)
    gold_flip = prf(ftp, ffp, ffn)

    print("\n1. GOLD-CORRECTED F1 (bridges, n=38 decisions — a measurement, not a model)")
    print(f"   {'scored by the Haiku judge':38} F1 {committed_b[2]:6.1%}  "
          f"(P {committed_b[0]:.1%} R {committed_b[1]:.1%})")
    print(f"   {'scored by the human gold labels':38} F1 {gold_b[2]:6.1%}  "
          f"(P {gold_b[0]:.1%} R {gold_b[1]:.1%})")
    print(f"   {'gold, 5 BORDERLINE labels flipped':38} F1 {gold_flip[2]:6.1%}")
    delta = gold_b[2] - committed_b[2]
    print(f"\n   -> the judge is {'CONSERVATIVE' if delta > 0 else 'LENIENT'} by "
          f"{abs(delta)*100:.1f} F1 points vs its own gold standard.")
    print(f"      Judge promoted {sum(as_judged_b.values())}/38; the human labels "
          f"{sum(1 for k in gold if gold[k]['gold'])}/38 as genuine matches.")
    if n_gold_missing:
        print(f"      ({n_gold_missing} decisions had no gold entry and were skipped)")

    # ── 2. bootstrap interval ────────────────────────────────────────────────
    # Bridges: truth is known (gold), so only CONTRACT-SAMPLING uncertainty applies.
    # DEX/lending: no gold, so judge error is extrapolated via Beta posteriors on the
    # bridge-measured PPV/NPV. Jeffreys priors; counts from judge_validation_report.
    ppv_a, ppv_b = 24 + 0.5, 2 + 0.5      # judge said match: 24 right, 2 wrong
    npv_a, npv_b = 7 + 0.5, 5 + 0.5       # judge said no-match: 7 right, 5 wrong

    gold_k = gold_promotions()
    b_names, d_names = list(bridges), list(dexlend)
    f1_b, f1_all = [], []
    for _ in range(N_BOOT):
        # cluster bootstrap: resample contracts with replacement
        bs = [b_names[rng.randrange(len(b_names))] for _ in b_names]
        tp = fp = fn = 0.0
        for n in bs:
            rec, k = bridges[n], gold_k[n]
            tp += rec["str_tp"] + k
            fn += rec["str_fn"] - k
            fp += rec["str_fp"] - k * r_bridge
        f1_b.append(prf(tp, fp, fn)[2])

        # DEX/lending: sample judge correctness from the extrapolated posteriors
        ppv, npv = _beta(ppv_a, ppv_b, rng), _beta(npv_a, npv_b, rng)
        ds = [d_names[rng.randrange(len(d_names))] for _ in d_names]
        for n in ds:
            rec = dexlend[n]
            k = sum(1 for _ in range(rec["n_promoted"]) if rng.random() < ppv)
            k += sum(1 for _ in range(rec["n_not_promoted"]) if rng.random() > npv)
            tp += rec["str_tp"] + k
            fn += rec["str_fn"] - k
            fp += rec["str_fp"] - k * r_dex
        f1_all.append(prf(tp, fp, fn)[2])

    def ci(xs):
        xs = sorted(xs)
        return xs[int(0.025 * len(xs))], xs[int(0.975 * len(xs))]

    lo_b, hi_b = ci(f1_b)
    lo_a, hi_a = ci(f1_all)
    print("\n2. UNCERTAINTY (20k bootstrap; contract-level resampling + judge error)")
    print(f"   bridges  gold-corrected F1 {gold_b[2]:.1%}   95% CI [{lo_b:.1%}, {hi_b:.1%}]")
    print(f"   all-24   gold+extrapolated F1              95% CI [{lo_a:.1%}, {hi_a:.1%}]")
    print(f"   (committed point estimates: bridges {committed_b[2]:.1%}, "
          f"all-24 {committed_all[2]:.1%})")

    # ── 3. sensitivity ───────────────────────────────────────────────────────
    print("\n3. SENSITIVITY (how fragile is the headline?)")
    base = committed_all[2]
    total_prom = sum(as_judged_b.values()) + sum(as_judged_d.values())
    rows = []
    for flip in range(0, 13):
        # flip = additional promotions granted uniformly (leniency) or revoked
        tp = btp + dtp + flip
        fn = bfn + dfn - flip
        fp = bfp + dfp - flip * ((r_bridge + r_dex) / 2)
        rows.append((flip, prf(tp, fp, fn)[2]))
    need = next((f for f, v in rows if v - base >= 0.05), None)
    print(f"   headline all-24 F1 = {base:.1%} from {total_prom} judge 'match' calls "
          f"out of {total_prom + sum(r['n_not_promoted'] for r in {**bridges, **dexlend}.values())}")
    if need:
        print(f"   +5 F1 points requires only {need} more promotions "
              f"({need/53:.0%} of the 53 decisions flipping).")
    print(f"   one flipped decision moves the headline ~{(rows[1][1]-rows[0][1])*100:.1f} points.")

    out = {
        "committed": {"bridges_f1": committed_b[2], "all24_f1": committed_all[2]},
        "gold_corrected_bridges": {
            "f1": gold_b[2], "precision": gold_b[0], "recall": gold_b[1],
            "borderline_flipped_f1": gold_flip[2],
            "judge_vs_gold_delta_points": delta * 100,
        },
        "bootstrap_ci_95": {
            "bridges": [lo_b, hi_b], "all24": [lo_a, hi_a], "n_boot": N_BOOT, "seed": SEED,
        },
        "sensitivity": {
            "points_per_flipped_decision": (rows[1][1] - rows[0][1]) * 100,
            "flips_for_plus5_points": need,
            "n_decisions": 53,
        },
        "caveats": [
            "gold standard is single-annotator and in-sample (same 38 decisions)",
            "DEX/lending judge error is extrapolated from bridges; no gold standard exists there",
            "FP recovery modeled at the observed per-domain rate "
            f"(bridges {r_bridge:.2f}, dex/lending {r_dex:.2f})",
        ],
    }
    (ROOT / "benchmarks" / "judge_uncertainty_report.json").write_text(json.dumps(out, indent=2))
    print("\nwrote benchmarks/judge_uncertainty_report.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
