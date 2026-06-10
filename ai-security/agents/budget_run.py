"""
Budget-capped multi-domain agentic run.

Runs Opus (or BENCH_MODEL) agentic analysis over the DEX + lending contracts that
have source, ordered cheapest-first, and SAVES AFTER EVERY CONTRACT so nothing is
lost if interrupted. Stops before the cumulative estimated cost would exceed BUDGET.

Pricing: input/output token cost at OPUS_IN/OPUS_OUT per million (Opus 4.8 default).
Output is written in the same shape as benchmark_runner (<domain>_static /
<domain>_agentic with per_contract), so semantic_rescorer.py consumes it directly.

    export ANTHROPIC_API_KEY=sk-...
    BENCH_MODEL=opus BUDGET=20 python -m agents.budget_run
"""
import json
import os
from pathlib import Path

from agents.static_analyzer_v2 import analyze_static
from agents.agentic_analyzer import run_agent
from agents.claude_analyzer import MODEL
from agents.benchmark_runner import evaluate_findings
from benchmarks.defi_contracts_real import load_defi_contracts
from benchmarks.lending_contracts_real import load_lending_contracts

BUDGET = float(os.environ.get("BUDGET", "20"))
OPUS_IN, OPUS_OUT = 15.0, 75.0   # $/million tokens
OUT = Path(__file__).parent.parent / f"results_defi_lending__{MODEL.replace('/', '-')}.json"


def cost(inp, out):
    return inp / 1e6 * OPUS_IN + out / 1e6 * OPUS_OUT


def main():
    items = []
    for domain, loader in (("defi", load_defi_contracts), ("lending", load_lending_contracts)):
        for c in loader():
            src = (c.get("source") or "").strip()
            if len(src) > 200:
                items.append((len(src), domain, c))
    items.sort(key=lambda x: x[0])  # cheapest (smallest) first

    results = {}                       # domain -> {static:{per_contract}, agentic:{per_contract}}
    spent = 0.0
    print(f"Budget ${BUDGET:.2f} | model {MODEL} | {len(items)} candidate contracts (cheapest first)\n")

    for size, domain, c in items:
        # Stop before this contract if we're close enough to the cap that a typical
        # contract could blow it (margin = $4, the largest observed single-contract cost).
        if spent >= BUDGET - 4.0:
            print(f"[stop] ${spent:.2f} spent; remaining contracts skipped to stay under ${BUDGET:.0f}")
            break

        name = c["name"]
        gt = c["ground_truth"]["vulnerabilities"]
        source = c["source"]
        print(f"→ {name} ({size/1024:.0f} KB, {domain})  [spent ${spent:.2f}]")

        # static (free) for the baseline comparison
        sfind = analyze_static(source)
        smetrics = evaluate_findings(sfind, gt)

        # agentic (paid)
        audit = run_agent(source, name, max_turns=8)
        ai = [{"type": f.vuln_type, "severity": f.severity} for f in audit.findings]
        ametrics = evaluate_findings(ai, gt)
        ccost = cost(audit.input_tokens, audit.output_tokens)
        spent += ccost
        print(f"   static F1={smetrics['f1']:.0%}  agentic F1={ametrics['f1']:.0%}  "
              f"in={audit.input_tokens:,} out={audit.output_tokens:,}  ${ccost:.2f}  (total ${spent:.2f})")

        d = results.setdefault(domain, {"static": {}, "agentic": {}})
        d["static"][name] = {"metrics": smetrics, "n_findings": len(sfind)}
        d["agentic"][name] = {
            "metrics": ametrics, "n_findings": len(ai),
            "tokens": audit.total_tokens, "input_tokens": audit.input_tokens,
            "output_tokens": audit.output_tokens, "cost_usd": round(ccost, 3),
            "tool_calls": audit.tool_calls_made, "findings": [f["type"] for f in ai],
        }

        # write after EVERY contract — never lose partial work
        out = {}
        for dom, dd in results.items():
            for kind in ("static", "agentic"):
                pc = dd[kind]
                if not pc:
                    continue
                tp = sum(v["metrics"]["tp"] for v in pc.values())
                fp = sum(v["metrics"]["fp"] for v in pc.values())
                fn = sum(v["metrics"]["fn"] for v in pc.values())
                p = tp / (tp + fp) if (tp + fp) else 0
                r = tp / (tp + fn) if (tp + fn) else 0
                f1 = 2 * p * r / (p + r) if (p + r) else 0
                out[f"{dom}_{kind}"] = {
                    "method": kind, "overall": {"precision": p, "recall": r, "f1": f1, "tp": tp, "fp": fp, "fn": fn},
                    "per_contract": pc,
                }
        out["_run"] = {"model": MODEL, "spent_usd": round(spent, 2), "budget_usd": BUDGET}
        OUT.write_text(json.dumps(out, indent=2, default=str))

    print(f"\nDONE. Spent ${spent:.2f} of ${BUDGET:.0f}. Wrote {OUT}")


if __name__ == "__main__":
    main()
