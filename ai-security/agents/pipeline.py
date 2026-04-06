"""
End-to-End Pipeline: Smart Contract Security Analysis

Runs the complete workflow:
  1. Load contract (from benchmark or Etherscan)
  2. Static pre-screening
  3. Claude deep analysis
  4. Evaluate against ground truth
  5. Generate report

Usage:
    export ANTHROPIC_API_KEY=your_key
    python pipeline.py --contract SimpleBridge
    python pipeline.py --contract NomadStyle
    python pipeline.py --all  # run against full benchmark
"""

import argparse
import json
import sys
import os
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.contract_analyzer import analyze_contract_static
from agents.claude_analyzer import (
    VULNERABLE_BRIDGE,
    NOMAD_STYLE_VULN,
    static_prescreen,
    format_report,
)
from agents.eval_harness import (
    GroundTruth,
    evaluate,
    format_eval,
    SIMPLE_BRIDGE_GT,
    NOMAD_STYLE_GT,
)

# Map of available test contracts
TEST_CONTRACTS = {
    "SimpleBridge": {
        "source": VULNERABLE_BRIDGE,
        "ground_truth": SIMPLE_BRIDGE_GT,
    },
    "NomadStyle": {
        "source": NOMAD_STYLE_VULN,
        "ground_truth": NOMAD_STYLE_GT,
    },
}


def run_static_only(name: str, source: str, ground_truth: GroundTruth) -> dict:
    """Run static analysis only (no API key needed)."""
    print(f"\n{'='*60}")
    print(f"STATIC ANALYSIS: {name}")
    print(f"{'='*60}")

    findings = static_prescreen(source)
    print(f"Findings: {findings}")

    # Map static findings to ground truth categories
    # (static tool uses different names than ground truth)
    static_to_gt = {
        "reentrancy": "reentrancy",
        "oracle_manipulation": "oracle_manipulation",
        "access_control": "missing_access_control",
        "bridge_verification": "message_validation",
        "upgrade_risk": "no_timelock",
        "initialization": "re_initialization",
    }

    mapped = [static_to_gt.get(f, f) for f in findings]
    mock_ai = [{"type": f, "severity": "medium"} for f in mapped]

    result = evaluate(ground_truth, mock_ai, findings)
    print(f"\nPrecision: {result.precision:.1%}")
    print(f"Recall:    {result.recall:.1%}")
    print(f"F1:        {result.f1:.1%}")

    return {
        "name": name,
        "method": "static",
        "findings": findings,
        "precision": result.precision,
        "recall": result.recall,
        "f1": result.f1,
    }


def run_full_pipeline(name: str, source: str, ground_truth: GroundTruth) -> dict:
    """Run full pipeline: static + Claude analysis."""
    try:
        from agents.claude_analyzer import analyze_with_claude
    except ImportError:
        print("ERROR: Could not import Claude analyzer")
        return run_static_only(name, source, ground_truth)

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("WARNING: ANTHROPIC_API_KEY not set, running static-only")
        return run_static_only(name, source, ground_truth)

    print(f"\n{'='*60}")
    print(f"FULL PIPELINE: {name}")
    print(f"{'='*60}")

    # Step 1: Static pre-screen
    static = static_prescreen(source)
    print(f"\n[1/4] Static findings: {static}")

    # Step 2: Claude analysis
    print(f"[2/4] Running Claude analysis...")
    report = analyze_with_claude(source, name, static)
    print(f"       Found {len(report.vulnerabilities)} vulnerabilities")
    print(f"       Overall risk: {report.overall_risk}")

    # Step 3: Evaluate
    print(f"[3/4] Evaluating against ground truth...")
    ai_findings = [
        {"type": v.type, "severity": v.severity}
        for v in report.vulnerabilities
    ]
    result = evaluate(ground_truth, ai_findings, static)

    # Step 4: Report
    print(f"[4/4] Results:")
    print(format_eval(result))
    print()
    print(format_report(report))

    return {
        "name": name,
        "method": "claude",
        "findings": [v.type for v in report.vulnerabilities],
        "precision": result.precision,
        "recall": result.recall,
        "f1": result.f1,
        "ai_only": result.ai_only,
        "static_only": result.static_only,
    }


def run_benchmark():
    """Run against all benchmark contracts."""
    results = []
    for name, data in TEST_CONTRACTS.items():
        if os.environ.get("ANTHROPIC_API_KEY"):
            r = run_full_pipeline(name, data["source"], data["ground_truth"])
        else:
            r = run_static_only(name, data["source"], data["ground_truth"])
        results.append(r)

    # Summary
    print(f"\n{'='*60}")
    print(f"BENCHMARK SUMMARY")
    print(f"{'='*60}")
    for r in results:
        print(f"  {r['name']:<20} P={r['precision']:.0%}  R={r['recall']:.0%}  F1={r['f1']:.0%}  ({r['method']})")

    mean_f1 = sum(r["f1"] for r in results) / len(results)
    print(f"\n  Mean F1: {mean_f1:.0%}")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Smart Contract Security Pipeline")
    parser.add_argument("--contract", type=str, help="Contract name to analyze")
    parser.add_argument("--all", action="store_true", help="Run full benchmark")
    parser.add_argument("--static-only", action="store_true", help="Skip Claude, static only")
    args = parser.parse_args()

    if args.all:
        run_benchmark()
    elif args.contract:
        if args.contract not in TEST_CONTRACTS:
            print(f"Unknown contract: {args.contract}")
            print(f"Available: {list(TEST_CONTRACTS.keys())}")
            sys.exit(1)
        data = TEST_CONTRACTS[args.contract]
        if args.static_only:
            run_static_only(args.contract, data["source"], data["ground_truth"])
        else:
            run_full_pipeline(args.contract, data["source"], data["ground_truth"])
    else:
        # Default: run benchmark
        run_benchmark()
