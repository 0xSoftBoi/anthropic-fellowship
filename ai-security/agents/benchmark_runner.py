"""
BRIDGE-bench: Cross-Chain Bridge Vulnerability Detection Benchmark

Runs static analysis (v2) against test contract suite and produces
evaluation metrics. When ANTHROPIC_API_KEY is set, also runs Claude
analysis and produces comparison metrics.

Supports both synthetic patterns (test_contracts.py) and real verified
contracts (bridge_contracts_real.py).

This is the core evaluation artifact for the AI Security Fellowship
application. The key question: does Claude find the compositional
vulnerabilities that static analysis misses?

Usage:
    python benchmark_runner.py                  # synthetic, static only
    ANTHROPIC_API_KEY=sk-... python benchmark_runner.py  # synthetic, static + Claude
    python benchmark_runner.py --real          # real contracts
    python benchmark_runner.py --compare       # synthetic vs real comparison
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.static_analyzer_v2 import analyze_static, StaticFinding
from benchmarks.test_contracts import TEST_CONTRACTS
from benchmarks.bridge_contracts_real import load_real_contracts


# Fuzzy type matching for evaluation
TYPE_EQUIVALENCES = {
    "unprotected_admin_function": ["unprotected_admin_function", "missing_access_control"],
    "untrusted_external_call": ["untrusted_external_call", "signature_verification_bypass"],
    "unused_signature_parameter": ["missing_signature_verification"],
    "missing_signature_verification": ["missing_signature_verification", "unused_signature_parameter"],
    "missing_reentrancy_guard": ["reentrancy"],
    "reentrancy": ["reentrancy", "missing_reentrancy_guard"],
    "spot_price_oracle": ["spot_price_oracle", "flash_loan_exploitable"],
    "flash_loan_exploitable": ["flash_loan_exploitable", "spot_price_oracle"],
    "unprotected_initializer": ["unprotected_initializer"],
    "reinitializable": ["reinitializable"],
    "zero_root_acceptance": ["zero_root_acceptance"],
    "no_rate_limiting": ["no_rate_limiting"],
    "low_validator_threshold": ["low_validator_threshold"],
    "duplicate_signature_acceptance": ["duplicate_signature_acceptance"],
    "no_withdrawal_delay": ["no_withdrawal_delay"],
    "missing_proof_link": ["missing_proof_link"],
    # Real contract types (Phase 4 expansion)
    "approval_exploitation": ["approval_exploitation", "arbitrary_external_call", "infinite_approval_drain"],
    "arbitrary_external_call": ["arbitrary_external_call", "approval_exploitation", "infinite_approval_drain"],
    "infinite_approval_drain": ["infinite_approval_drain", "approval_exploitation", "arbitrary_external_call"],
    "faulty_route_validation": ["faulty_route_validation", "missing_input_validation"],
    "zero_root_initialization": ["zero_root_initialization", "default_value_exploit", "zero_root_acceptance"],
    "default_value_exploit": ["default_value_exploit", "zero_root_initialization"],
    "keeper_key_overwrite": ["keeper_key_overwrite", "missing_access_control", "unprotected_admin_function"],
    "zero_value_deposit": ["zero_value_deposit", "missing_input_validation"],
    "unrestricted_cross_chain_call": ["unrestricted_cross_chain_call", "arbitrary_external_call"],
    "missing_upgrade_validation": ["missing_upgrade_validation", "unprotected_upgrade"],
    "flash_loan_price_manipulation": ["flash_loan_price_manipulation", "spot_price_dependency", "flash_loan_exploitable"],
    "spot_price_dependency": ["spot_price_dependency", "flash_loan_price_manipulation", "spot_price_oracle"],
}


def fuzzy_match(finding_type: str, gt_type: str) -> bool:
    f, g = finding_type.lower(), gt_type.lower()
    if f == g:
        return True
    return g in TYPE_EQUIVALENCES.get(f, [f])


def evaluate_findings(findings: list, gt_vulns: list, exclude_unreachable: bool = True) -> dict:
    """
    Evaluate findings against ground truth.

    Args:
        findings: List of detected vulnerabilities
        gt_vulns: List of ground truth vulnerabilities
        exclude_unreachable: If True, filter out code-unreachable vulnerabilities (off-chain issues)

    Returns:
        Dict with tp, fp, fn, precision, recall, f1, missed, false_positives
    """
    from benchmarks.bridge_contracts_real import CODE_UNREACHABLE_VULN_TYPES

    # Filter ground truth to only code-detectable vulnerabilities
    if exclude_unreachable:
        gt_vulns = [g for g in gt_vulns if g["type"] not in CODE_UNREACHABLE_VULN_TYPES]

    gt_matched = set()
    finding_matched = set()

    for fi, f in enumerate(findings):
        ftype = f.vuln_type if isinstance(f, StaticFinding) else f.get("type", "")
        for gi, g in enumerate(gt_vulns):
            if gi not in gt_matched and fuzzy_match(ftype, g["type"]):
                gt_matched.add(gi)
                finding_matched.add(fi)
                break

    tp = len(gt_matched)
    fp = len(findings) - len(finding_matched)
    fn = len(gt_vulns) - len(gt_matched)
    p = tp / (tp + fp) if (tp + fp) > 0 else 0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0

    missed = [g["type"] for i, g in enumerate(gt_vulns) if i not in gt_matched]
    false_pos_types = []
    for i, f in enumerate(findings):
        if i not in finding_matched:
            false_pos_types.append(f.vuln_type if isinstance(f, StaticFinding) else f.get("type", ""))

    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": p, "recall": r, "f1": f1,
        "missed": missed, "false_positives": false_pos_types,
    }


def run_static_benchmark(dataset: Optional[dict] = None, dataset_name: str = "Synthetic") -> dict:
    """
    Run static analysis benchmark against a dataset.

    Args:
        dataset: Dict of contract_name -> {source, ground_truth} (default: TEST_CONTRACTS)
        dataset_name: Name for output display

    Returns:
        Results dict with metrics
    """
    if dataset is None:
        dataset = TEST_CONTRACTS

    print(f"BRIDGE-bench: Static Analysis (v2) on {dataset_name}")
    print("=" * 60)

    results = {}
    totals = {"tp": 0, "fp": 0, "fn": 0}

    for name, data in dataset.items():
        # Handle both dict and list-of-dicts formats
        if isinstance(data, dict) and "source" in data:
            source = data["source"]
            gt_vulns = data["ground_truth"]["vulnerabilities"]
        else:
            continue  # Skip if format doesn't match

        if source is None:
            print(f"\n{name}: SKIPPED (source not available)")
            continue

        findings = analyze_static(source)
        metrics = evaluate_findings(findings, gt_vulns)

        results[name] = {
            "metrics": metrics,
            "n_findings": len(findings),
            "n_gt": len(gt_vulns),
            "findings": [{"type": f.vuln_type, "severity": f.severity, "confidence": f.confidence} for f in findings],
        }

        for k in ["tp", "fp", "fn"]:
            totals[k] += metrics[k]

        print(f"\n{name}: P={metrics['precision']:.0%} R={metrics['recall']:.0%} F1={metrics['f1']:.0%}")
        if metrics["missed"]:
            print(f"  MISSED: {metrics['missed']}")
        if metrics["false_positives"]:
            print(f"  FALSE+: {metrics['false_positives']}")

    p = totals["tp"] / (totals["tp"] + totals["fp"]) if (totals["tp"] + totals["fp"]) > 0 else 0
    r = totals["tp"] / (totals["tp"] + totals["fn"]) if (totals["tp"] + totals["fn"]) > 0 else 0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0

    print(f"\n{'=' * 60}")
    print(f"STATIC v2 OVERALL: P={p:.0%} R={r:.0%} F1={f1:.0%}")
    print(f"  {totals['tp']} true positives, {totals['fp']} false positives, {totals['fn']} missed")
    print()

    # What static CAN'T find (the gap Claude should fill)
    all_missed = []
    for name, result in results.items():
        for m in result["metrics"]["missed"]:
            all_missed.append(f"{name}: {m}")

    print("VULNERABILITIES STATIC ANALYSIS CANNOT DETECT:")
    print("(These require compositional reasoning — the Claude agent thesis)")
    for m in all_missed:
        print(f"  • {m}")

    return {
        "method": "static_v2",
        "overall": {"precision": p, "recall": r, "f1": f1, **totals},
        "per_contract": results,
        "systematic_gaps": all_missed,
    }


def run_claude_benchmark(dataset: Optional[dict] = None, dataset_name: str = "Synthetic") -> dict | None:
    """
    Run Claude analysis benchmark against a dataset.

    Args:
        dataset: Dict of contract_name -> {source, ground_truth} (default: TEST_CONTRACTS)
        dataset_name: Name for output display

    Returns:
        Results dict with metrics, or None if API key not set
    """
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("\nSkipping Claude analysis (set ANTHROPIC_API_KEY to enable)")
        return None

    if dataset is None:
        dataset = TEST_CONTRACTS

    from agents.claude_analyzer import analyze_with_claude, static_prescreen

    print(f"\n{'=' * 60}")
    print(f"BRIDGE-bench: Claude Analysis on {dataset_name}")
    print("=" * 60)

    results = {}
    totals = {"tp": 0, "fp": 0, "fn": 0}

    for name, data in dataset.items():
        # Handle both dict and list-of-dicts formats
        if isinstance(data, dict) and "source" in data:
            source = data["source"]
            gt_vulns = data["ground_truth"]["vulnerabilities"]
        else:
            continue  # Skip if format doesn't match

        if source is None:
            print(f"\n{name}: SKIPPED (source not available)")
            continue

        static = static_prescreen(source)
        report = analyze_with_claude(source, name, static)

        ai_findings = [{"type": v.type, "severity": v.severity} for v in report.vulnerabilities]
        metrics = evaluate_findings(ai_findings, gt_vulns)

        results[name] = {"metrics": metrics, "n_findings": len(ai_findings)}
        for k in ["tp", "fp", "fn"]:
            totals[k] += metrics[k]

        print(f"\n{name}: P={metrics['precision']:.0%} R={metrics['recall']:.0%} F1={metrics['f1']:.0%}")

    p = totals["tp"] / (totals["tp"] + totals["fp"]) if (totals["tp"] + totals["fp"]) > 0 else 0
    r = totals["tp"] / (totals["tp"] + totals["fn"]) if (totals["tp"] + totals["fn"]) > 0 else 0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0

    print(f"\n{'=' * 60}")
    print(f"CLAUDE OVERALL: P={p:.0%} R={r:.0%} F1={f1:.0%}")

    return {
        "method": "claude",
        "overall": {"precision": p, "recall": r, "f1": f1, **totals},
        "per_contract": results,
    }


def run_agentic_benchmark(dataset: Optional[dict] = None, dataset_name: str = "Synthetic") -> dict | None:
    """
    Run multi-turn agentic analysis benchmark against a dataset.

    Args:
        dataset: Dict of contract_name -> {source, ground_truth} (default: TEST_CONTRACTS)
        dataset_name: Name for output display

    Returns:
        Results dict with metrics, or None if API key not set
    """
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("\nSkipping agentic analysis (set ANTHROPIC_API_KEY to enable)")
        return None

    if dataset is None:
        dataset = TEST_CONTRACTS

    from agents.agentic_analyzer import run_agent
    from agents.claude_analyzer import static_prescreen

    print(f"\n{'=' * 60}")
    print(f"BRIDGE-bench: Agentic (Multi-Turn) Analysis on {dataset_name}")
    print("=" * 60)

    results = {}
    totals = {"tp": 0, "fp": 0, "fn": 0}

    for name, data in dataset.items():
        if isinstance(data, dict) and "source" in data:
            source = data["source"]
            gt_vulns = data["ground_truth"]["vulnerabilities"]
        else:
            continue

        if source is None:
            print(f"\n{name}: SKIPPED (source not available)")
            continue

        static = static_prescreen(source)
        audit = run_agent(source, name, static)

        # Convert AgentFinding to dict for evaluate_findings()
        ai_findings = [{"type": f.vuln_type, "severity": f.severity} for f in audit.findings]
        metrics = evaluate_findings(ai_findings, gt_vulns)

        results[name] = {"metrics": metrics, "n_findings": len(ai_findings)}
        for k in ["tp", "fp", "fn"]:
            totals[k] += metrics[k]

        print(f"\n{name}: P={metrics['precision']:.0%} R={metrics['recall']:.0%} F1={metrics['f1']:.0%}")

    p = totals["tp"] / (totals["tp"] + totals["fp"]) if (totals["tp"] + totals["fp"]) > 0 else 0
    r = totals["tp"] / (totals["tp"] + totals["fn"]) if (totals["tp"] + totals["fn"]) > 0 else 0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0

    print(f"\n{'=' * 60}")
    print(f"AGENTIC OVERALL: P={p:.0%} R={r:.0%} F1={f1:.0%}")

    return {
        "method": "agentic",
        "overall": {"precision": p, "recall": r, "f1": f1, **totals},
        "per_contract": results,
    }


def convert_real_contracts_to_dict(real_contracts: list) -> dict:
    """Convert list of real contracts to dict format for benchmark."""
    result = {}
    for contract in real_contracts:
        result[contract["name"]] = {
            "source": contract["source"],
            "ground_truth": contract["ground_truth"],
            "metadata": contract.get("metadata", {}),
        }
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="BRIDGE-bench: Cross-chain bridge vulnerability detection benchmark"
    )
    parser.add_argument(
        "--real",
        action="store_true",
        help="Run against real verified contracts from Etherscan/BSCScan",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Compare synthetic vs real contract results",
    )
    parser.add_argument(
        "--no-claude",
        action="store_true",
        help="Skip Claude analysis even if ANTHROPIC_API_KEY is set",
    )
    parser.add_argument(
        "--agentic",
        action="store_true",
        help="Use multi-turn agentic analysis instead of single-turn Claude",
    )

    args = parser.parse_args()

    # Determine which dataset(s) to run
    run_synthetic = not args.real or args.compare
    run_real = args.real or args.compare

    results_all = {}

    # ──────────────────────────────────────────────────────────────────
    # Run synthetic benchmarks
    # ──────────────────────────────────────────────────────────────────
    if run_synthetic:
        synthetic_static = run_static_benchmark(TEST_CONTRACTS, "Synthetic Patterns")
        results_all["synthetic_static"] = synthetic_static

        if not args.no_claude:
            if args.agentic:
                synthetic_agentic = run_agentic_benchmark(TEST_CONTRACTS, "Synthetic Patterns")
                results_all["synthetic_agentic"] = synthetic_agentic

                if synthetic_agentic:
                    print(f"\n{'=' * 60}")
                    print("SYNTHETIC: Static v2 vs Agentic")
                    print("=" * 60)
                    s = synthetic_static["overall"]
                    a = synthetic_agentic["overall"]
                    print(f"  Static v2:  P={s['precision']:.0%}  R={s['recall']:.0%}  F1={s['f1']:.0%}")
                    print(f"  Agentic:    P={a['precision']:.0%}  R={a['recall']:.0%}  F1={a['f1']:.0%}")
                    delta = a["f1"] - s["f1"]
                    print(f"  Delta F1:   {delta:+.0%}")
            else:
                synthetic_claude = run_claude_benchmark(TEST_CONTRACTS, "Synthetic Patterns")
                results_all["synthetic_claude"] = synthetic_claude

                if synthetic_claude:
                    print(f"\n{'=' * 60}")
                    print("SYNTHETIC: Static v2 vs Claude")
                    print("=" * 60)
                    s = synthetic_static["overall"]
                    c = synthetic_claude["overall"]
                    print(f"  Static v2:  P={s['precision']:.0%}  R={s['recall']:.0%}  F1={s['f1']:.0%}")
                    print(f"  Claude:     P={c['precision']:.0%}  R={c['recall']:.0%}  F1={c['f1']:.0%}")
                    delta = c["f1"] - s["f1"]
                    print(f"  Delta F1:   {delta:+.0%}")

    # ──────────────────────────────────────────────────────────────────
    # Run real contract benchmarks
    # ──────────────────────────────────────────────────────────────────
    if run_real:
        real_contracts_list = load_real_contracts()
        real_contracts_dict = convert_real_contracts_to_dict(real_contracts_list)

        print(f"\n{'='*60}")
        print(f"Real contracts loaded: {sum(1 for c in real_contracts_list if c['source'])}/{len(real_contracts_list)}")
        print(f"{'='*60}\n")

        real_static = run_static_benchmark(real_contracts_dict, "Real Verified Contracts")
        results_all["real_static"] = real_static

        if not args.no_claude:
            if args.agentic:
                real_agentic = run_agentic_benchmark(real_contracts_dict, "Real Verified Contracts")
                results_all["real_agentic"] = real_agentic

                if real_agentic:
                    print(f"\n{'=' * 60}")
                    print("REAL: Static v2 vs Agentic")
                    print("=" * 60)
                    s = real_static["overall"]
                    a = real_agentic["overall"]
                    print(f"  Static v2:  P={s['precision']:.0%}  R={s['recall']:.0%}  F1={s['f1']:.0%}")
                    print(f"  Agentic:    P={a['precision']:.0%}  R={a['recall']:.0%}  F1={a['f1']:.0%}")
                    delta = a["f1"] - s["f1"]
                    print(f"  Delta F1:   {delta:+.0%}")
            else:
                real_claude = run_claude_benchmark(real_contracts_dict, "Real Verified Contracts")
                results_all["real_claude"] = real_claude

                if real_claude:
                    print(f"\n{'=' * 60}")
                    print("REAL: Static v2 vs Claude")
                    print("=" * 60)
                    s = real_static["overall"]
                    c = real_claude["overall"]
                    print(f"  Static v2:  P={s['precision']:.0%}  R={s['recall']:.0%}  F1={s['f1']:.0%}")
                    print(f"  Claude:     P={c['precision']:.0%}  R={c['recall']:.0%}  F1={c['f1']:.0%}")
                    delta = c["f1"] - s["f1"]
                    print(f"  Delta F1:   {delta:+.0%}")

    # ──────────────────────────────────────────────────────────────────
    # Save results
    # ──────────────────────────────────────────────────────────────────
    if args.compare and "synthetic_static" in results_all and "real_static" in results_all:
        print(f"\n{'=' * 60}")
        print("OVERALL COMPARISON: Synthetic vs Real")
        print("=" * 60)
        s_syn = results_all["synthetic_static"]["overall"]
        s_real = results_all["real_static"]["overall"]

        print(f"\nStatic Analysis v2:")
        print(f"  Synthetic:  F1={s_syn['f1']:.0%} (P={s_syn['precision']:.0%} R={s_syn['recall']:.0%})")
        print(f"  Real:       F1={s_real['f1']:.0%} (P={s_real['precision']:.0%} R={s_real['recall']:.0%})")
        print(f"  Delta:      {s_real['f1'] - s_syn['f1']:+.0%}")

        if "synthetic_claude" in results_all and "real_claude" in results_all:
            c_syn = results_all["synthetic_claude"]["overall"]
            c_real = results_all["real_claude"]["overall"]

            print(f"\nClaude Analysis:")
            print(f"  Synthetic:  F1={c_syn['f1']:.0%} (P={c_syn['precision']:.0%} R={c_syn['recall']:.0%})")
            print(f"  Real:       F1={c_real['f1']:.0%} (P={c_real['precision']:.0%} R={c_real['recall']:.0%})")
            print(f"  Delta:      {c_real['f1'] - c_syn['f1']:+.0%}")

    # Save JSON results
    output_filename = "results_real.json" if args.real and not args.compare else "results.json"
    output_path = Path(__file__).parent.parent / output_filename
    with open(output_path, "w") as f:
        json.dump(results_all, f, indent=2, default=str)
    print(f"\nResults saved to {output_path}")
