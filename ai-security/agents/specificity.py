"""
Specificity scorer for the negative-control (live) domain.

F1 is undefined on a negative control: there is no positive to recall, and the scorer's
empty-ground-truth path returns F1=0 whether the model correctly found nothing OR flagged
ten false bugs — the two outcomes a negative control exists to distinguish. This module
scores the axis F1 cannot: **specificity** — did the model correctly stay silent on
hardened, unfamiliar, first-party code?

    specificity = (# contracts with 0 findings) / (# negative-control contracts)
    mean false-positive load = mean findings-per-contract

WHAT THIS IS AND ISN'T
- It is a **screen**, not a verdict. A "false positive" here is a raw finding count; some of
  those findings may be *real* bugs the author's audit passes missed (these contracts had a
  self-run audit, not a paid external one — see live_contracts.py). Whether a flagged finding
  is a true FP or a real miss requires the source-aware semantic judge
  (agents/judge_ablation.py, source_visible arm) reading the contract.
- Reported alongside recall on the exploit domains, it completes the picture: a detector's
  value is recall AND specificity, and the exploit-only benchmark could only ever show the
  first half.

    python -m agents.specificity results_live__<model>.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def score_negative_controls(results: dict) -> dict:
    """Compute specificity from a committed results file's live-domain section(s).

    Looks at any `live_*` section (live_static, live_agentic, ...). For each contract, a
    finding count of 0 is a correct silence (true negative); >0 is flagged (screened FP).
    """
    sections = {k: v for k, v in results.items() if k.startswith("live_")}
    out = {}
    for sec, data in sections.items():
        pc = data.get("per_contract", {})
        rows = []
        clean = 0
        total_findings = 0
        for name, info in pc.items():
            m = info.get("metrics", info)
            # On a negative control, every reported finding is fp (empty ground truth).
            n = m.get("fp", 0)
            flagged = m.get("false_positives", [])
            total_findings += n
            if n == 0:
                clean += 1
            rows.append({"contract": name, "findings": n, "flagged": flagged})
        n_contracts = len(pc)
        out[sec] = {
            "n_contracts": n_contracts,
            "clean": clean,
            "specificity": (clean / n_contracts) if n_contracts else None,
            "mean_findings_per_contract": (total_findings / n_contracts) if n_contracts else None,
            "total_findings": total_findings,
            "per_contract": rows,
        }
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python -m agents.specificity <results_live_file.json>")
        return 1
    path = Path(sys.argv[1])
    if not path.exists():
        print(f"no such file: {path}")
        return 1
    report = score_negative_controls(json.loads(path.read_text()))
    if not report:
        print("no live_* section found — is this a --live results file?")
        return 1

    for sec, r in report.items():
        print(f"\n=== {sec} (negative controls) ===")
        print(f"{'contract':24}{'findings':>9}  flagged types")
        print("-" * 72)
        for row in r["per_contract"]:
            tag = "clean" if row["findings"] == 0 else ", ".join(row["flagged"])[:44]
            print(f"{row['contract']:24}{row['findings']:>9}  {tag}")
        print("-" * 72)
        spec = r["specificity"]
        print(f"specificity: {r['clean']}/{r['n_contracts']} contracts clean "
              f"= {spec:.0%}" if spec is not None else "specificity: n/a")
        print(f"mean false-positive load: {r['mean_findings_per_contract']:.1f} findings/contract")
        print("\nNote: raw finding count is a SCREEN. Whether a flagged finding is a true false "
              "positive\nor a real bug the self-audit missed needs the source-aware judge "
              "(judge_ablation.py).")

    out = path.with_name(path.stem + "__specificity.json")
    out.write_text(json.dumps(report, indent=2))
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
