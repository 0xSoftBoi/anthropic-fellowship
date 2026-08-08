"""Locked BRIDGE-bench contamination re-measurement runner.

This module exists because the contamination experiment has stricter requirements than
an ordinary benchmark run:

* the population must stay fixed to the 24 contracts in the committed Opus baseline;
* raw / stripped / anon must differ only by sanitization and anonymized display name;
* sanitizer invariants must pass before any paid model call;
* result files are immutable artifacts, never silent overwrites of the historical baseline;
* paid execution requires an explicit estimated-cost cap;
* pricing is versioned in the run manifest instead of being buried in code comments.

The cost guard is an ESTIMATE, not a provider billing limit. It conservatively prices all
reported input tokens at the base input rate and output tokens at the output rate, ignoring
prompt-cache discounts. A single API call can still cross the remaining estimate cap, so a
per-contract reserve is enforced before each call. For a true hard billing limit, configure
one at the provider/account layer as well.

Free validation:
    python -m agents.remeasure --preflight
    python -m agents.remeasure --estimate

Paid run (explicit cap required):
    BENCH_MODEL=opus python -m agents.remeasure --run stripped --max-estimated-cost-usd 30

All three conditions on the same checkout:
    BENCH_MODEL=opus python -m agents.remeasure --run all --max-estimated-cost-usd 90
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from agents import llm
from agents.agentic_analyzer import run_agent
from agents.benchmark_runner import evaluate_findings
from agents.claude_analyzer import MODEL
from benchmarks.bridge_contracts_real import load_real_contracts
from benchmarks.defi_contracts_real import load_defi_contracts
from benchmarks.lending_contracts_real import load_lending_contracts
from benchmarks.sanitize import leakage_scan, sanitize, verify

ROOT = Path(__file__).resolve().parent.parent
RESULT_DIR = ROOT / "results_remeasure"
BASELINE_BRIDGE = ROOT / "results_real__claude-opus-4-8.json"
BASELINE_OTHER = ROOT / "results_defi_lending__claude-opus-4-8.json"
EXPECTED = {"bridge": 16, "defi": 5, "lending": 3}
LEVELS = ("raw", "stripped", "anon")

# Anthropic global standard list price for Claude Opus 4.8, verified 2026-08-08.
# Keep the source/date in every output manifest so later readers can re-price a run.
DEFAULT_INPUT_USD_PER_M = 5.0
DEFAULT_OUTPUT_USD_PER_M = 25.0
PRICING_SOURCE = "https://www.anthropic.com/news/claude-opus-4-8"
PRICING_AS_OF = "2026-08-08"


def _json(path: Path) -> dict:
    return json.loads(path.read_text())


def _baseline_population() -> dict[str, list[str]]:
    """Lock the experiment to the contracts that produced the published raw baseline."""
    bridge = _json(BASELINE_BRIDGE)
    other = _json(BASELINE_OTHER)
    out = {
        "bridge": list(bridge["real_agentic"]["per_contract"].keys()),
        "defi": list(other["defi_agentic"]["per_contract"].keys()),
        "lending": list(other["lending_agentic"]["per_contract"].keys()),
    }
    problems = [
        f"{d}: baseline lock has {len(names)}, expected {EXPECTED[d]}"
        for d, names in out.items() if len(names) != EXPECTED[d]
    ]
    if problems:
        raise RuntimeError("population lock changed: " + "; ".join(problems))
    if sum(map(len, out.values())) != 24:
        raise RuntimeError("population lock is not 24 contracts")
    return out


def _corpus() -> dict[str, dict[str, dict]]:
    loaders = {
        "bridge": load_real_contracts,
        "defi": load_defi_contracts,
        "lending": load_lending_contracts,
    }
    out: dict[str, dict[str, dict]] = {}
    for domain, loader in loaders.items():
        out[domain] = {c["name"]: c for c in loader()}
    return out


def locked_items() -> list[dict]:
    lock = _baseline_population()
    corpus = _corpus()
    items = []
    ordinal = 0
    for domain in ("bridge", "defi", "lending"):
        for name in lock[domain]:
            ordinal += 1
            c = corpus[domain].get(name)
            if c is None:
                raise RuntimeError(f"locked contract disappeared from {domain}: {name}")
            source = (c.get("source") or "").strip()
            if len(source) <= 200:
                raise RuntimeError(f"locked contract has no usable source: {domain}/{name}")
            items.append({"ordinal": ordinal, "domain": domain, "name": name, "contract": c})
    return items


def _gt_types(c: dict) -> list[str]:
    return [v["type"] for v in c["ground_truth"]["vulnerabilities"]]


def run_preflight(write_report: bool = True) -> dict:
    """Zero-cost proof that the locked corpus and both sanitizer levels are valid."""
    items = locked_items()
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "population": {d: sum(i["domain"] == d for i in items) for d in EXPECTED},
        "total": len(items),
        "levels": {},
        "failures": [],
    }

    for level in ("stripped", "anon"):
        level_rows = []
        for item in items:
            c = item["contract"]
            source = c["source"]
            transformed, srep = sanitize(source, level, item["name"], c.get("metadata"))
            invariant_problems = verify(source, transformed, level, srep)
            leak = leakage_scan(transformed, _gt_types(c), item["name"], c.get("metadata"))
            semantic_leak = bool(leak["label_hits"] or leak["narrative"] or leak["mechanism"])
            identity_leak = bool(leak["identity"])
            problems = list(invariant_problems)
            if semantic_leak:
                problems.append(
                    "author-injected answer leakage survived: "
                    f"labels={leak['label_hits']} narrative={leak['narrative']} mechanism={leak['mechanism']}"
                )
            if level == "anon" and identity_leak:
                problems.append(f"protocol identity survived anonymization: {leak['identity']}")
            row = {
                "domain": item["domain"],
                "name": item["name"],
                "source_bytes": len(source.encode()),
                "sanitized_bytes": len(transformed.encode()),
                "problems": problems,
            }
            level_rows.append(row)
            if problems:
                report["failures"].append({"level": level, **row})
        report["levels"][level] = {
            "contracts": len(level_rows),
            "bytes_before": sum(r["source_bytes"] for r in level_rows),
            "bytes_after": sum(r["sanitized_bytes"] for r in level_rows),
            "failed": sum(bool(r["problems"]) for r in level_rows),
        }

    report["ok"] = not report["failures"]
    if write_report:
        out = ROOT / "benchmarks" / "remeasure_preflight.json"
        out.write_text(json.dumps(report, indent=2) + "\n")
        print(f"wrote {out.relative_to(ROOT)}")
    print(json.dumps({k: report[k] for k in ("population", "total", "levels", "ok")}, indent=2))
    return report


def _current_pricing() -> dict:
    return {
        "input_usd_per_m": float(os.environ.get("BENCH_INPUT_USD_PER_M", DEFAULT_INPUT_USD_PER_M)),
        "output_usd_per_m": float(os.environ.get("BENCH_OUTPUT_USD_PER_M", DEFAULT_OUTPUT_USD_PER_M)),
        "source": PRICING_SOURCE,
        "as_of": PRICING_AS_OF,
        "method": "standard-list estimate; prompt-cache discounts ignored",
    }


def estimated_cost(input_tokens: int, output_tokens: int, pricing: dict | None = None) -> float:
    p = pricing or _current_pricing()
    return input_tokens / 1_000_000 * p["input_usd_per_m"] + output_tokens / 1_000_000 * p["output_usd_per_m"]


def planning_estimate() -> dict:
    """Re-price the eight historical DEX/lending calls, then scale by locked source bytes.

    This is deliberately labeled a planning estimate. Token use is not linear in source
    bytes, agentic tool use varies by contract, and the historical bridge result did not
    persist input/output splits. The estimate exists to stop accidental unbounded runs,
    not to masquerade as accounting data.
    """
    pricing = _current_pricing()
    old = _json(BASELINE_OTHER)
    known_cost = 0.0
    known_n = 0
    known_bytes = 0
    corpus = _corpus()
    for domain in ("defi", "lending"):
        for name, rec in old[f"{domain}_agentic"]["per_contract"].items():
            inp = int(rec.get("input_tokens", 0))
            out = int(rec.get("output_tokens", 0))
            if inp or out:
                known_cost += estimated_cost(inp, out, pricing)
                known_n += 1
                known_bytes += len(corpus[domain][name]["source"].encode())

    items = locked_items()
    all_bytes = sum(len(i["contract"]["source"].encode()) for i in items)
    if not known_n or not known_bytes:
        raise RuntimeError("historical result lacks input/output token splits; cannot plan safely")
    projected = known_cost * all_bytes / known_bytes
    recommended = projected * 1.50  # guard band for variable agent turns / output length
    report = {
        "pricing": pricing,
        "historical_sample_contracts": known_n,
        "historical_sample_repriced_usd": round(known_cost, 4),
        "historical_sample_source_bytes": known_bytes,
        "locked_population_source_bytes": all_bytes,
        "projected_one_condition_usd": round(projected, 2),
        "recommended_one_condition_cap_usd": round(recommended, 2),
        "projected_three_condition_usd": round(projected * 3, 2),
        "recommended_three_condition_cap_usd": round(recommended * 3, 2),
        "warning": "planning estimate, not a provider bill or hard cap",
    }
    print(json.dumps(report, indent=2))
    return report


def _aggregate(per_contract: dict) -> dict:
    tp = sum(v["metrics"]["tp"] for v in per_contract.values())
    fp = sum(v["metrics"]["fp"] for v in per_contract.values())
    fn = sum(v["metrics"]["fn"] for v in per_contract.values())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": p, "recall": r, "f1": f1, "tp": tp, "fp": fp, "fn": fn}


def _git_sha() -> str:
    return os.environ.get("GITHUB_SHA") or os.environ.get("GIT_COMMIT") or "unknown"


def _run_id() -> str:
    raw = f"{_git_sha()}|{MODEL}|{datetime.now(timezone.utc).isoformat()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def run_condition(level: str, max_cost: float, run_id: str, prior_spend: float = 0.0) -> tuple[dict, float, Path]:
    if level not in LEVELS:
        raise ValueError(level)
    if max_cost <= 0:
        raise SystemExit("paid remeasurement requires --max-estimated-cost-usd > 0")
    if not llm.has_credentials():
        raise SystemExit("no LLM credentials available; refusing to create a fake paid result")

    pre = run_preflight(write_report=False)
    if not pre["ok"]:
        raise SystemExit("sanitizer/population preflight failed; refusing paid inference")

    pricing = _current_pricing()
    plan = planning_estimate()
    recommended = plan["recommended_one_condition_cap_usd"]
    available_for_condition = max_cost - prior_spend
    if available_for_condition < recommended:
        raise SystemExit(
            f"remaining cap ${available_for_condition:.2f} is below the planning guard-band "
            f"${recommended:.2f} for a complete condition; refusing a selective partial run"
        )

    items = locked_items()
    result: dict = {
        "_run": {
            "run_id": run_id,
            "condition": level,
            "model": MODEL,
            "code_commit_sha": _git_sha(),
            "started_at": datetime.now(timezone.utc).isoformat(),
            "python": platform.python_version(),
            "population": _baseline_population(),
            "pricing": pricing,
            "max_estimated_cost_usd_all_conditions": max_cost,
            "prior_estimated_spend_usd": round(prior_spend, 4),
            "estimated_list_cost_usd": 0.0,
            "completed": False,
        }
    }
    for domain in EXPECTED:
        result[f"{domain}_agentic"] = {"method": "agentic", "per_contract": {}}

    RESULT_DIR.mkdir(exist_ok=True)
    safe_model = MODEL.replace("/", "-")
    out = RESULT_DIR / f"{run_id}__{safe_model}__{level}.json"
    if out.exists():
        raise SystemExit(f"result artifact already exists: {out}")

    spent = prior_spend
    condition_spend = 0.0
    # Reserve at least $5 of estimated list cost before starting another contract. This
    # is intentionally conservative relative to the historical sample, but still not a
    # provider-side billing limit.
    reserve = max(5.0, plan["projected_one_condition_usd"] / len(items) * 2.0)

    for item in items:
        remaining = max_cost - spent
        if remaining < reserve:
            result["_run"]["stopped_reason"] = (
                f"remaining estimated-cost cap ${remaining:.2f} < per-contract reserve ${reserve:.2f}"
            )
            out.write_text(json.dumps(result, indent=2) + "\n")
            raise SystemExit(result["_run"]["stopped_reason"] + "; partial artifact saved, do not score it")

        c = item["contract"]
        source, srep = sanitize(c["source"], level, item["name"], c.get("metadata"))
        problems = verify(c["source"], source, level, srep) if level != "raw" else []
        if problems:
            raise SystemExit(f"{level}/{item['name']} sanitizer invariant failed: {problems}")

        # Identity is deliberately preserved for raw/stripped and neutralized only for anon.
        analysis_name = item["name"] if level != "anon" else f"contract_{item['ordinal']:02d}"
        print(f"[{level}] {item['ordinal']:02d}/24 {item['domain']}/{analysis_name}  spent≈${spent:.2f}")
        audit = run_agent(source, analysis_name, max_turns=8)
        findings = [{"type": f.vuln_type, "severity": f.severity} for f in audit.findings]
        metrics = evaluate_findings(findings, c["ground_truth"]["vulnerabilities"])
        inp = int(getattr(audit, "input_tokens", 0))
        otp = int(getattr(audit, "output_tokens", 0))
        ccost = estimated_cost(inp, otp, pricing)
        condition_spend += ccost
        spent += ccost
        rec = {
            "metrics": metrics,
            "n_findings": len(findings),
            "findings": [f["type"] for f in findings],
            "input_tokens": inp,
            "output_tokens": otp,
            "cached_tokens": int(getattr(audit, "cached_tokens", 0)),
            "tool_calls": int(getattr(audit, "tool_calls_made", 0)),
            "estimated_list_cost_usd": round(ccost, 4),
            "analysis_name": analysis_name,
        }
        result[f"{item['domain']}_agentic"]["per_contract"][item["name"]] = rec
        result["_run"]["estimated_list_cost_usd"] = round(condition_spend, 4)
        result["_run"]["cumulative_estimated_list_cost_usd"] = round(spent, 4)
        out.write_text(json.dumps(result, indent=2) + "\n")  # checkpoint every contract

    for domain in EXPECTED:
        section = result[f"{domain}_agentic"]
        section["overall"] = _aggregate(section["per_contract"])
        section["total_tokens"] = sum(
            v["input_tokens"] + v["output_tokens"] for v in section["per_contract"].values()
        )
    result["_run"]["completed"] = True
    result["_run"]["finished_at"] = datetime.now(timezone.utc).isoformat()
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(f"completed {level}: estimated list cost ${condition_spend:.2f}; wrote {out}")
    return result, spent, out


def write_exact_comparison(paths: list[Path], run_id: str) -> Path | None:
    if len(paths) != 3:
        return None
    by_level = {_json(p)["_run"]["condition"]: _json(p) for p in paths}
    if set(by_level) != set(LEVELS):
        return None
    for level, data in by_level.items():
        if data["_run"]["run_id"] != run_id or not data["_run"]["completed"]:
            raise RuntimeError(f"cannot compare incomplete/mismatched {level} artifact")
    out = RESULT_DIR / f"{run_id}__exact_comparison.csv"
    with out.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["domain", "contract", "raw_f1", "stripped_f1", "anon_f1", "raw_recall", "stripped_recall", "anon_recall"])
        for domain in EXPECTED:
            names = by_level["raw"]["_run"]["population"][domain]
            for name in names:
                row = [domain, name]
                for metric in ("f1", "recall"):
                    for level in LEVELS:
                        row.append(by_level[level][f"{domain}_agentic"]["per_contract"][name]["metrics"][metric])
                w.writerow(row)
    print(f"wrote {out}")
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--estimate", action="store_true")
    mode.add_argument("--run", choices=(*LEVELS, "all"))
    ap.add_argument("--max-estimated-cost-usd", type=float, default=0.0)
    args = ap.parse_args()

    if args.preflight:
        rep = run_preflight()
        raise SystemExit(0 if rep["ok"] else 1)
    if args.estimate:
        planning_estimate()
        return

    run_id = _run_id()
    levels = LEVELS if args.run == "all" else (args.run,)
    total_plan = planning_estimate()
    needed = total_plan[
        "recommended_three_condition_cap_usd" if args.run == "all" else "recommended_one_condition_cap_usd"
    ]
    if args.max_estimated_cost_usd < needed:
        raise SystemExit(
            f"cap ${args.max_estimated_cost_usd:.2f} is below the planning guard-band ${needed:.2f}; "
            "refusing to start a run likely to stop mid-population"
        )

    spent = 0.0
    paths = []
    for level in levels:
        _, spent, path = run_condition(level, args.max_estimated_cost_usd, run_id, spent)
        paths.append(path)
    if args.run == "all":
        write_exact_comparison(paths, run_id)
    print(f"all requested conditions complete; cumulative estimated list cost ${spent:.2f}")


if __name__ == "__main__":
    main()
