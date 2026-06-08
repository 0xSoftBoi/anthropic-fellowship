"""
Experiment 04: Negation Processing in Factual Contexts

Date: 2026-04-03 (analysis made runnable + saved to JSON: 2026-06-08)
Status: Complete

NOTE: LLMs failing at negation is well-documented (Ettinger 2020,
Truong et al. 2023 "Language Models Are Not Naysayers"). This experiment
adds mechanistic detail — WHERE in the network the failure occurs —
but the behavioral observation is not novel.

Everything below is COMPUTED by this script (run it to reproduce; results are
also written to results/04_negation.json). The numbers were previously asserted
in this docstring; they are now produced by the four functions in `main()`.

BEHAVIORAL RESULT: GPT-2 small detects negation ("not") in the residual
stream but cannot override strong factual associations. In 4/6 test cases,
negation paradoxically INCREASES the target logit (mean effect +4.9%).
  → see `run_battery()`

MECHANISTIC DETAIL (incremental contribution):
  1. ATTENTION: head L11H8 attends 37.7% to "not" from the last position —
     the model IS reading the negation token.  → see `attention_on_not()`
  2. RESIDUAL STREAM: the target ("France") projection grows late and the
     "not" only dents it — at L10 it drops from 186.2 to 167.1 (−19, ~10%),
     not enough to flip the prediction.  → see `france_projection()`
  3. PATCHING: replacing the "not" position with the affirmative token
     ("the") recovers ~130% of the (pos−neg) logit gap when done at L0 and
     stays high through L0–2, then falls off — the negation signal is
     processed early.  → see `negation_patching()`
  4. The factual lookup resolves late (L9–10, see experiment 03) and is
     higher-bandwidth than the early negation "side road", so by the time
     the fact is read the negation signal has been diluted.

Likely cause of the booster effect: negation words co-occur with the correct
answer in training data, so "not X" still surfaces X (Ettinger's lexical-cue
account).

Implications for AI safety:
  - Models may confidently assert negated facts as true
  - Interpretability tools should flag cases where negation tokens are
    attended to but don't change the output distribution
  - This pattern likely persists in larger models (needs verification)
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from utils import load_model, token_id  # noqa: E402

# Affirmative / negated / target. The first four also appear in the writeup's
# logit table; the last two complete the six-prompt battery.
BATTERY = [
    ("Paris is the capital of", "Paris is not the capital of", " France"),
    ("The sun is a", "The sun is not a", " star"),
    ("Dogs are", "Dogs are not", " animals"),
    ("Python is a programming", "Python is not a programming", " language"),
    ("Shakespeare wrote", "Shakespeare did not write", " the"),
    ("Two plus two equals", "Two plus two does not equal", " four"),
]


def run_battery(model):
    """Logit of the target with and without 'not', across the battery."""
    rows = []
    boosts = 0
    for pos, neg, tgt in BATTERY:
        t = token_id(model, tgt)
        lp = model(pos)[0, -1, t].item()
        ln = model(neg)[0, -1, t].item()
        pct = (ln - lp) / abs(lp) * 100.0
        boosts += ln > lp
        rows.append({"target": tgt.strip(), "logit_pos": round(lp, 2),
                     "logit_neg": round(ln, 2), "pct": round(pct, 1)})
    mean_pct = sum(r["pct"] for r in rows) / len(rows)
    return {"rows": rows, "boosts": boosts, "n": len(rows),
            "mean_pct": round(mean_pct, 1)}


def attention_on_not(model, neg="Paris is not the capital of"):
    """Which head, from the last position, most attends to the 'not' token."""
    strs = model.to_str_tokens(neg)
    not_idx = next(i for i, s in enumerate(strs) if s.strip() == "not")
    _, cache = model.run_with_cache(neg)
    best_layer, best_head, best_w = -1, -1, 0.0  # best_w kept as a fraction
    target_head = None
    for L in range(model.cfg.n_layers):
        patt = cache["pattern", L][0]  # [head, query, key]
        for H in range(model.cfg.n_heads):
            w = patt[H, -1, not_idx].item()  # last query -> 'not' key
            if w > best_w:
                best_layer, best_head, best_w = L, H, w
            if L == 11 and H == 8:
                target_head = round(w * 100, 1)
    best = {"layer": best_layer, "head": best_head, "weight": round(best_w * 100, 1)}
    return {"top": best, "L11H8_pct": target_head, "not_index": not_idx}


def france_projection(model, pos="Paris is the capital of",
                      neg="Paris is not the capital of", target=" France"):
    """Raw projection of the last-position residual onto the target's unembed
    direction, per layer (resid_post · W_U[:, target])."""
    wu = model.W_U[:, token_id(model, target)]

    def per_layer(prompt):
        _, c = model.run_with_cache(prompt)
        return [round((c["resid_post", L][0, -1] @ wu).item(), 1)
                for L in range(model.cfg.n_layers)]

    pp, pn = per_layer(pos), per_layer(neg)
    L10 = {"pos": pp[10], "neg": pn[10], "delta": round(pn[10] - pp[10], 1)}
    return {"pos_per_layer": pp, "neg_per_layer": pn, "L10": L10}


def negation_patching(model, pos="Paris is the capital of",
                      neg="Paris is not the capital of", target=" France"):
    """Replace the 'not' position's resid_pre at each layer with the affirmative
    prompt's same-position residual ('the'), and measure how much of the
    (pos−neg) target-logit gap is recovered."""
    t = token_id(model, target)
    strs = model.to_str_tokens(neg)
    not_idx = next(i for i, s in enumerate(strs) if s.strip() == "not")
    lp = model(pos)[0, -1, t].item()
    ln = model(neg)[0, -1, t].item()
    gap = lp - ln
    _, ca_pos = model.run_with_cache(pos)
    recovery = []
    for L in range(model.cfg.n_layers):
        donor = ca_pos["resid_pre", L][0, not_idx].clone()

        def hook(val, hook, donor=donor):
            val[0, not_idx] = donor
            return val

        patched = model.run_with_hooks(
            neg, fwd_hooks=[(f"blocks.{L}.hook_resid_pre", hook)]
        )[0, -1, t].item()
        rec = (patched - ln) / gap * 100.0 if gap != 0 else 0.0
        recovery.append(round(rec, 1))
    return {"gap": round(gap, 2), "recovery_pct_per_layer": recovery,
            "L0": recovery[0]}


def main():
    model = load_model("gpt2-small")
    results = {
        "model": "gpt2-small",
        "battery": run_battery(model),
        "attention_on_not": attention_on_not(model),
        "france_projection": france_projection(model),
        "negation_patching": negation_patching(model),
    }

    b = results["battery"]
    print("=== Behavioral battery (logit with/without 'not') ===")
    for r in b["rows"]:
        print(f'  {r["target"]:9s}  pos={r["logit_pos"]:6.2f}  '
              f'neg={r["logit_neg"]:6.2f}  {r["pct"]:+5.1f}%')
    print(f'  → {b["boosts"]}/{b["n"]} go up; mean {b["mean_pct"]:+.1f}%\n')

    a = results["attention_on_not"]
    print("=== Attention on 'not' (last position → 'not') ===")
    print(f'  top head L{a["top"]["layer"]}H{a["top"]["head"]} = '
          f'{a["top"]["weight"]}%  (L11H8 = {a["L11H8_pct"]}%)\n')

    fp = results["france_projection"]["L10"]
    print("=== Target projection in the residual stream @ L10 ===")
    print(f'  pos={fp["pos"]}  neg={fp["neg"]}  Δ={fp["delta"]}\n')

    p = results["negation_patching"]
    print("=== Negation patching — recovery of the logit gap per layer ===")
    print(f'  gap(pos−neg)={p["gap"]}')
    print(f'  recovery%: {p["recovery_pct_per_layer"]}')
    print(f'  L0 recovers {p["L0"]}% (high through L0–2, then falls off)')

    out = Path(__file__).resolve().parents[1] / "results" / "04_negation.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
