"""
Regenerate the multi-domain results tables from committed result files — no API.

Reads the raw agentic results (string-match scoring) and the rescored files
(semantic-judge scoring), aggregates per domain, and prints the headline table.
This is the source of truth for the numbers in the README; run it any time to
verify they still hold against the committed JSON.

    python -m agents.report
"""
import json
from pathlib import Path

from benchmarks.bridge_contracts_real import load_real_contracts
from benchmarks.defi_contracts_real import load_defi_contracts
from benchmarks.lending_contracts_real import load_lending_contracts

ROOT = Path(__file__).parent.parent
RAW = {
    "results_real__claude-opus-4-8.json": ["real_agentic"],
    "results_defi_lending__claude-opus-4-8.json": ["defi_agentic", "lending_agentic"],
}
RESCORED = [
    "results_real__claude-opus-4-8__rescored.json",
    "results_defi_lending__claude-opus-4-8__rescored.json",
]


def _domains():
    d = {}
    for name, loader in (("bridge", load_real_contracts),
                         ("defi", load_defi_contracts),
                         ("lending", load_lending_contracts)):
        for c in loader():
            d[c["name"]] = name
    return d


def _prf(t):
    p = t["tp"] / (t["tp"] + t["fp"]) if (t["tp"] + t["fp"]) else 0
    r = t["tp"] / (t["tp"] + t["fn"]) if (t["tp"] + t["fn"]) else 0
    f1 = 2 * p * r / (p + r) if (p + r) else 0
    return p, r, f1


def main():
    dom = _domains()
    string_agg, sem_agg, cost = {}, {}, {}

    for fname, keys in RAW.items():
        path = ROOT / fname
        if not path.exists():
            continue
        j = json.loads(path.read_text())
        for key in keys:
            for name, m in j[key]["per_contract"].items():
                d = dom.get(name, "?")
                a = string_agg.setdefault(d, {"tp": 0, "fp": 0, "fn": 0})
                for k in ("tp", "fp", "fn"):
                    a[k] += m["metrics"][k]
                if "cost_usd" in m:
                    cost[d] = cost.get(d, 0) + m["cost_usd"]

    for fname in RESCORED:
        path = ROOT / fname
        if not path.exists():
            continue
        j = json.loads(path.read_text())
        for name, m in j["per_contract"].items():
            d = dom.get(name, "?")
            a = sem_agg.setdefault(d, {"tp": 0, "fp": 0, "fn": 0})
            for k in ("tp", "fp", "fn"):
                a[k] += m[k]

    order = [d for d in ("bridge", "defi", "lending") if d in sem_agg]
    print(f"{'domain':9} {'string F1':>9} {'semantic F1':>11} {'sem recall':>10} {'cost':>8}")
    print("-" * 52)
    tot_s = {"tp": 0, "fp": 0, "fn": 0}
    tot_g = {"tp": 0, "fp": 0, "fn": 0}
    for d in order:
        s, g = sem_agg[d], string_agg.get(d, {"tp": 0, "fp": 0, "fn": 0})
        for k in ("tp", "fp", "fn"):
            tot_s[k] += s[k]
            tot_g[k] += g[k]
        _, _, gf = _prf(g)
        _, sr, sf = _prf(s)
        c = f"${cost[d]:.2f}" if d in cost else "—"
        print(f"{d:9} {gf*100:8.0f}% {sf*100:10.0f}% {sr*100:9.0f}% {c:>8}")
    _, _, gf = _prf(tot_g)
    _, sr, sf = _prf(tot_s)
    total_cost = sum(cost.values())
    print("-" * 52)
    print(f"{'ALL':9} {gf*100:8.0f}% {sf*100:10.0f}% {sr*100:9.0f}% "
          f"{('$%.2f' % total_cost) if total_cost else '—':>8}")
    print(f"\n(string-match tp/fp/fn = {tot_g['tp']}/{tot_g['fp']}/{tot_g['fn']}; "
          f"semantic = {tot_s['tp']}/{tot_s['fp']}/{tot_s['fn']})")


if __name__ == "__main__":
    main()
