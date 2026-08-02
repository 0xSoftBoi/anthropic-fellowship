"""
Judge-space ablation: how much of the headline F1 is the model, and how much is the judge?

The semantic F1 in this repo is produced by ONE judge configuration — Haiku, one prompt,
blind to the contract source. `agents/judge_uncertainty.py` shows (without any API calls)
that swapping that judge for the repo's own human gold labels moves bridge F1 from 37.1%
to 51.6%: a 14.5-point swing from changing nothing but the grader. That is larger than
most effects this benchmark is used to argue about.

This module measures the judge-design space directly, sweeping three axes:

  model            haiku / sonnet / opus      — does a stronger judge grade differently?
  framing          default / strict / lenient — how much is prompt-induced leniency?
  source_visible   false / true               — THE KEY AXIS (see below)

Why source-visibility matters most
----------------------------------
The committed judge never sees the contract. It compares a label to a finding, so it can
only answer "do these mean the same thing?" — not "is this finding actually true of this
code?" A model can emit a finding that is semantically identical to the ground-truth label
and still be wrong about the contract, and the blind judge must credit it. That is a
systematic upward bias of unknown size, and it is invisible to the current validation
(which scores the judge against human labels that were also produced label-to-label).

Cost note: source-aware judging sends the contract with every call, so it is the expensive
arm. With Haiku over 53 decisions it is still cents; on Opus, budget accordingly. Use
--dry-run first — it prints the exact call/token plan without spending anything.

    python -m agents.judge_ablation --dry-run
    python -m agents.judge_ablation --models haiku,sonnet --framings default,strict
    python -m agents.judge_ablation --full            # all axes, incl. source-aware
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
from pathlib import Path

from agents.semantic_rescorer import (
    JUDGE_FRAMINGS,
    SOURCE_AWARE_SUFFIX,
    _TAXONOMY,
    real_source_contracts,
)

ROOT = Path(__file__).parent.parent

# Judge models, with list pricing per 1M tokens (input, output) for the dry-run cost
# estimate. `haiku` is pinned to the dated ID the committed rescore used, so the default
# config reproduces `results_*__rescored.json` exactly.
MODELS = {
    "haiku": ("claude-haiku-4-5-20251001", 1.00, 5.00),
    "sonnet": ("claude-sonnet-4-6", 3.00, 15.00),
    "opus": ("claude-opus-4-8", 5.00, 25.00),
}

# Judge replies are a small JSON object; max_tokens is 300 and observed replies are well
# under that. Used only for the estimate — actual spend is reported per config after a run.
EST_OUTPUT_TOKENS = 150

RESULTS = [
    ("bridge", ROOT / "results_real__claude-opus-4-8.json"),
    ("dexlend", ROOT / "results_defi_lending__claude-opus-4-8.json"),
]


def prf(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    return p, r, (2 * p * r / (p + r) if (p + r) else 0.0)


def load_decisions():
    """Every (contract, gt, candidate findings) decision the judge has to make."""
    evaluable = real_source_contracts()
    sources = _contract_sources()
    out = []
    for _dom, path in RESULTS:
        if not path.exists():
            continue
        j = json.loads(path.read_text())
        for key in [k for k in j if k.endswith(("_agentic", "_hybrid", "_claude"))]:
            for name, info in j[key].get("per_contract", {}).items():
                if name not in evaluable:
                    continue
                m = info["metrics"]
                for gt in m.get("missed", []):
                    out.append({
                        "contract": name,
                        "gt": gt,
                        "gt_desc": _TAXONOMY.get(gt, {}).get("description", gt),
                        "candidates": list(m.get("false_positives", [])),
                        "str_tp": m["tp"], "str_fp": m["fp"], "str_fn": m["fn"],
                        "source": sources.get(name, ""),
                    })
    return out


def _contract_sources() -> dict:
    from benchmarks.bridge_contracts_real import load_real_contracts
    from benchmarks.defi_contracts_real import load_defi_contracts
    from benchmarks.lending_contracts_real import load_lending_contracts
    out = {}
    for loader in (load_real_contracts, load_defi_contracts, load_lending_contracts):
        for c in loader():
            out[c["name"]] = c.get("source") or ""
    return out


def score_config(decisions, verdicts):
    """Aggregate F1 given a verdict per decision, mirroring semantic_rescorer accounting."""
    by_contract = {}
    for d, v in zip(decisions, verdicts):
        rec = by_contract.setdefault(d["contract"], {
            "str_tp": d["str_tp"], "str_fp": d["str_fp"], "str_fn": d["str_fn"], "prom": 0})
        rec["prom"] += 1 if v else 0
    tp = fp = fn = 0
    for rec in by_contract.values():
        tp += rec["str_tp"] + rec["prom"]
        fn += rec["str_fn"] - rec["prom"]
        fp += max(0, rec["str_fp"] - rec["prom"])
    return tp, fp, fn


def agreement(a: list[bool], b: list[bool]) -> tuple[float, float]:
    """Raw agreement and Cohen's kappa between two verdict vectors."""
    n = len(a)
    po = sum(1 for x, y in zip(a, b) if x == y) / n
    pa, pb = sum(a) / n, sum(b) / n
    pe = pa * pb + (1 - pa) * (1 - pb)
    return po, ((po - pe) / (1 - pe) if pe != 1 else 0.0)


def main() -> int:
    ap = argparse.ArgumentParser(description="Sweep the LLM-judge design space")
    ap.add_argument("--models", default="haiku")
    ap.add_argument("--framings", default="default")
    ap.add_argument("--source-visible", default="false",
                    help="false | true | both — show the judge the contract source")
    ap.add_argument("--full", action="store_true",
                    help="all models x all framings x both source settings")
    ap.add_argument("--dry-run", action="store_true", help="print the plan, spend nothing")
    ap.add_argument("--out", default="benchmarks/judge_ablation_report.json")
    args = ap.parse_args()

    if args.full:
        models = list(MODELS)
        framings = list(JUDGE_FRAMINGS)
        srcvis = [False, True]
    else:
        models = [m.strip() for m in args.models.split(",") if m.strip()]
        framings = [f.strip() for f in args.framings.split(",") if f.strip()]
        srcvis = {"false": [False], "true": [True], "both": [False, True]}[args.source_visible]

    for m in models:
        if m not in MODELS:
            raise SystemExit(f"unknown model {m!r}; choose from {list(MODELS)}")
    for f in framings:
        if f not in JUDGE_FRAMINGS:
            raise SystemExit(f"unknown framing {f!r}; choose from {list(JUDGE_FRAMINGS)}")

    decisions = load_decisions()
    configs = list(itertools.product(models, framings, srcvis))
    n_calls = len(decisions) * len(configs)
    avg_src = sum(len(d["source"][:24000]) for d in decisions) / max(1, len(decisions)) / 4

    print(f"decisions: {len(decisions)}   configs: {len(configs)}   judge calls: {n_calls}")
    total_cost = 0.0
    for m, f, s in configs:
        in_tok = len(decisions) * ((avg_src + 400) if s else 400)
        out_tok = len(decisions) * EST_OUTPUT_TOKENS
        _id, in_price, out_price = MODELS[m]
        cost = in_tok / 1e6 * in_price + out_tok / 1e6 * out_price
        total_cost += cost
        print(f"  - {m:7} {f:8} source={'yes' if s else 'no ':3}  "
              f"~{in_tok/1000:6,.0f}k in  ~${cost:5.2f}")
    print(f"  {'':38}estimated total: ~${total_cost:.2f}")
    if args.dry_run:
        print("\n--dry-run: no API calls made.")
        return 0

    from anthropic import Anthropic
    from concurrent.futures import ThreadPoolExecutor
    from agents.semantic_rescorer import judge_match

    client = Anthropic()
    concurrency = max(1, int(os.environ.get("JUDGE_CONCURRENCY", "8")))
    rows, verdict_vectors = [], {}

    for model_key, framing, source_visible in configs:
        system = JUDGE_FRAMINGS[framing] + (SOURCE_AWARE_SUFFIX if source_visible else "")
        model = MODELS[model_key][0]

        def one(d):
            matched, _f, _why, toks = judge_match(
                client, d["gt"], d["gt_desc"], d["candidates"],
                model=model, system=system,
                source=d["source"] if source_visible else None)
            return bool(matched), toks

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            res = list(pool.map(one, decisions))
        verdicts = [r[0] for r in res]
        tokens = sum(r[1] for r in res)
        tp, fp, fn = score_config(decisions, verdicts)
        p, r, f1 = prf(tp, fp, fn)
        name = f"{model_key}/{framing}/src={'Y' if source_visible else 'N'}"
        verdict_vectors[name] = verdicts
        rows.append({"config": name, "model": model_key, "framing": framing,
                     "source_visible": source_visible, "promotions": sum(verdicts),
                     "tp": tp, "fp": fp, "fn": fn,
                     "precision": p, "recall": r, "f1": f1, "judge_tokens": tokens})
        print(f"{name:34} promoted {sum(verdicts):2}/{len(decisions)}  F1 {f1:6.1%}")

    print("\npairwise judge agreement (raw / Cohen's kappa):")
    names = list(verdict_vectors)
    pairs = []
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            po, k = agreement(verdict_vectors[names[i]], verdict_vectors[names[j]])
            pairs.append({"a": names[i], "b": names[j], "raw": po, "kappa": k})
            print(f"  {names[i]:30} vs {names[j]:30}  {po:.0%} / k={k:.2f}")

    if rows:
        spread = max(r["f1"] for r in rows) - min(r["f1"] for r in rows)
        print(f"\nF1 SPREAD ACROSS JUDGE CONFIGURATIONS: {spread*100:.1f} points "
              f"({min(r['f1'] for r in rows):.1%} - {max(r['f1'] for r in rows):.1%})")
        print("Interpretation: this is variation from the GRADER alone — the model's "
              "findings are identical in every row.")

    out = ROOT / args.out
    out.write_text(json.dumps({"configs": rows, "agreement": pairs,
                               "n_decisions": len(decisions)}, indent=2))
    print(f"wrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
