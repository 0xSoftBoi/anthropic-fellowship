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
import time
import argparse
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents import llm
from agents.static_analyzer_v2 import analyze_static, StaticFinding
from benchmarks.test_contracts import TEST_CONTRACTS
from benchmarks.bridge_contracts_real import load_real_contracts
from benchmarks.defi_contracts_real import load_defi_contracts
from benchmarks.lending_contracts_real import load_lending_contracts


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
    # Phase 5A: Added from Sonnet's real findings
    "replay_attack": ["replay_attack", "message_replay", "status_update_reentrancy"],
    # Phase 5B: DEX/AMM/Lending protocol types
    "oracle_price_manipulation": ["oracle_price_manipulation", "flash_loan_price_manipulation", "spot_price_dependency", "spot_price_oracle"],
    "tick_boundary_exploit": ["tick_boundary_exploit", "precision_loss_rounding", "integer_boundary_exploit"],
    "flash_loan_collateral_inflation": ["flash_loan_collateral_inflation", "flash_loan_price_manipulation"],
    "donation_attack_bad_debt": ["donation_attack_bad_debt", "bad_debt_accumulation", "zero_value_deposit"],
    "reentrancy_in_dex_callback": ["reentrancy_in_dex_callback", "reentrancy"],
    "spot_price_oracle": ["spot_price_oracle", "flash_loan_price_manipulation", "spot_price_dependency"],
    "precision_loss_rounding": ["precision_loss_rounding", "tick_boundary_exploit", "integer_boundary_exploit"],
    "jit_liquidity_attack": ["jit_liquidity_attack", "sandwich_attack_vector"],
    "sandwich_attack_vector": ["sandwich_attack_vector", "jit_liquidity_attack"],
    "liquidation_manipulation": ["liquidation_manipulation", "oracle_price_manipulation"],
    "interest_rate_oracle_abuse": ["interest_rate_oracle_abuse", "oracle_price_manipulation"],
    "bad_debt_accumulation": ["bad_debt_accumulation", "donation_attack_bad_debt"],
    "missing_slippage_protection": ["missing_slippage_protection", "price_impact_manipulation"],
    "price_impact_manipulation": ["price_impact_manipulation", "missing_slippage_protection"],
    # 2026 bridge additions (CrossCurve, Hyperbridge). Map likely model phrasings
    # onto the committed ground-truth keys so semantically-correct findings count.
    "missing_gateway_origin_check": ["missing_gateway_origin_check", "missing_source_validation", "unauthenticated_message_handler", "missing_access_control", "unrestricted_cross_chain_call"],
    "missing_access_control": ["missing_access_control", "missing_gateway_origin_check", "unauthenticated_message_handler", "unprotected_admin_function"],
    "missing_source_validation": ["missing_source_validation", "missing_gateway_origin_check", "forged_cross_chain_message"],
    "unauthenticated_message_handler": ["unauthenticated_message_handler", "missing_gateway_origin_check", "missing_access_control"],
    "forged_cross_chain_message": ["forged_cross_chain_message", "message_forgery", "spoofed_message", "missing_gateway_origin_check", "missing_source_validation"],
    "message_forgery": ["message_forgery", "forged_cross_chain_message", "spoofed_message"],
    "mmr_missing_bounds_check": ["mmr_missing_bounds_check", "missing_bounds_check", "improper_proof_verification", "missing_input_validation", "out_of_bounds"],
    "improper_proof_verification": ["improper_proof_verification", "mmr_missing_bounds_check", "missing_proof_link"],
    "unbounded_mint_authority": ["unbounded_mint_authority", "privileged_mint", "admin_takeover", "missing_access_control", "unprotected_admin_function"],
    "admin_takeover": ["admin_takeover", "unbounded_mint_authority", "missing_access_control"],
    # 2024-2025 DeFi additions (Penpie, Seneca, Prisma, Sonne, Dough, Abracadabra)
    "reentrancy": ["reentrancy", "missing_reentrancy_guard", "reentrancy_in_dex_callback", "untrusted_external_call", "cross_function_reentrancy"],
    "untrusted_external_call": ["untrusted_external_call", "arbitrary_external_call", "reentrancy", "unsafe_external_call"],
    "unvalidated_callback": ["unvalidated_callback", "arbitrary_external_call", "missing_input_validation", "unvalidated_flashloan_callback", "untrusted_external_call"],
    "exchange_rate_manipulation": ["exchange_rate_manipulation", "empty_market_donation", "rounding_error", "first_depositor", "donation_attack_bad_debt", "share_inflation"],
    "rounding_error": ["rounding_error", "precision_loss_rounding", "exchange_rate_manipulation"],
    "empty_market_donation": ["empty_market_donation", "donation_attack_bad_debt", "first_depositor", "exchange_rate_manipulation"],
    "missing_solvency_check": ["missing_solvency_check", "skipped_solvency_check", "undercollateralized_borrow", "missing_health_check", "state_flag_reset"],
    "state_flag_reset": ["state_flag_reset", "missing_solvency_check", "logic_error"],
    "logic_error": ["logic_error", "state_flag_reset", "missing_solvency_check", "insufficient_validation"],
    "event_spoofing": ["event_spoofing", "forged_event", "spoofed_deposit", "input_validation", "message_forgery"],
    "improper_whitelist": ["improper_whitelist", "arbitrary_external_call", "approval_exploitation", "unchecked_user_calldata", "missing_input_validation"],
    # DEX/lending domain (Euler, Onyx, Compound P062, Cream crAMP)
    "missing_solvency_check": ["missing_solvency_check", "solvency_check_bypass", "missing_health_check", "donate_to_reserves", "skipped_solvency_check"],
    "exchange_rate_manipulation": ["exchange_rate_manipulation", "empty_market_donation", "rounding_error", "donation_attack", "donation_attack_bad_debt", "first_depositor", "share_inflation", "integer_truncation"],
    "empty_market_donation": ["empty_market_donation", "donation_attack", "donation_attack_bad_debt", "exchange_rate_manipulation", "first_depositor"],
    "erc777_callback": ["erc777_callback", "reentrancy", "cross_function_reentrancy", "token_hook_reentrancy", "tokens_received_hook"],
    "cross_function_reentrancy": ["cross_function_reentrancy", "reentrancy", "erc777_callback", "cei_violation"],
    "reward_accounting_bug": ["reward_accounting_bug", "incorrect_comparison_operator", "reward_distribution_error", "comp_distribution", "logic_error", "incorrect_distribution"],
    "incorrect_comparison_operator": ["incorrect_comparison_operator", "reward_accounting_bug", "off_by_one", "logic_error"],
    "unprotected_initializer": ["unprotected_initializer", "reinitialization", "missing_access_control", "unprotected_init", "reinitializable"],
    "missing_input_validation": ["missing_input_validation", "input_validation", "insufficient_validation", "unvalidated_input", "missing_validation", "no_input_validation"],
    # reverse-direction keys: fuzzy_match keys on the model's finding string, so the
    # model's likely phrasings must each map onto the canonical ground-truth key.
    "input_validation": ["input_validation", "missing_input_validation"],
    "insufficient_validation": ["insufficient_validation", "missing_input_validation"],
    "missing_validation": ["missing_validation", "missing_input_validation"],
    "unvalidated_input": ["unvalidated_input", "missing_input_validation"],
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
    if not llm.has_credentials():
        print("\nSkipping LLM analysis (set ANTHROPIC_API_KEY, a provider key, or LLM_BASE_URL to enable)")
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


def _run_audit_benchmark(dataset, dataset_name, worker, method, banner) -> dict | None:
    """
    Shared core for audit-style benchmarks (agentic, cascade): run a per-contract
    `worker(source, name) -> audit` concurrently and score the findings.

    `audit` must expose .findings (objects with .vuln_type/.severity),
    .total_tokens, .cached_tokens, .tool_calls_made. Cascade audits additionally
    expose cheap/strong token splits, recorded when present.
    """
    if not llm.has_credentials():
        print(f"\nSkipping {method} analysis (set ANTHROPIC_API_KEY, a provider key, or LLM_BASE_URL to enable)")
        return None
    if dataset is None:
        dataset = TEST_CONTRACTS

    print(f"\n{'=' * 60}")
    print(f"BRIDGE-bench: {banner} on {dataset_name}")
    print("=" * 60)

    results = {}
    totals = {"tp": 0, "fp": 0, "fn": 0}

    # Build the worklist (contracts with usable source), preserving dataset order.
    worklist = []
    for name, data in dataset.items():
        if not (isinstance(data, dict) and "source" in data):
            continue
        if data["source"] is None:
            print(f"\n{name}: SKIPPED (source not available)")
            continue
        worklist.append((name, data["source"], data["ground_truth"]["vulnerabilities"]))

    # Contracts are independent and I/O-bound (API round-trips), so run them
    # concurrently behind a bounded pool. Each worker owns its own state; LiteLLM
    # retries handle transient rate limits. Tune with BENCH_CONCURRENCY.
    concurrency = max(1, int(os.environ.get("BENCH_CONCURRENCY", "4")))
    t0 = time.monotonic()
    audits: dict[str, object] = {}
    if concurrency == 1 or len(worklist) <= 1:
        for name, source, _ in worklist:
            audits[name] = worker(source, name)
    else:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            fut_by_name = {name: pool.submit(worker, source, name) for name, source, _ in worklist}
            for name, fut in fut_by_name.items():
                audits[name] = fut.result()  # propagates any exception
    elapsed = time.monotonic() - t0

    # Score + record in deterministic worklist order.
    for name, source, gt_vulns in worklist:
        audit = audits[name]
        ai_findings = [{"type": f.vuln_type, "severity": f.severity} for f in audit.findings]
        metrics = evaluate_findings(ai_findings, gt_vulns)

        # Persist tokens/tool-calls (cost) and the raw finding types so a run is fully
        # auditable and re-scorable offline without re-invoking the model.
        rec = {
            "metrics": metrics,
            "n_findings": len(ai_findings),
            "tokens": getattr(audit, "total_tokens", 0),
            "cached_tokens": getattr(audit, "cached_tokens", 0),
            "tool_calls": getattr(audit, "tool_calls_made", 0),
            "findings": [f["type"] for f in ai_findings],
        }
        # Cascade provenance (only present on cascade audits).
        if hasattr(audit, "cheap_tokens"):
            rec["cheap_tokens"] = audit.cheap_tokens
            rec["strong_tokens"] = audit.strong_tokens
            rec["escalated"] = getattr(audit, "escalated", False)
        results[name] = rec
        for k in ["tp", "fp", "fn"]:
            totals[k] += metrics[k]

        print(f"\n{name}: P={metrics['precision']:.0%} R={metrics['recall']:.0%} "
              f"F1={metrics['f1']:.0%}  ({rec['tokens']:,} tok)")

    p = totals["tp"] / (totals["tp"] + totals["fp"]) if (totals["tp"] + totals["fp"]) > 0 else 0
    r = totals["tp"] / (totals["tp"] + totals["fn"]) if (totals["tp"] + totals["fn"]) > 0 else 0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
    total_tokens = sum(v.get("tokens", 0) for v in results.values())
    total_cached = sum(v.get("cached_tokens", 0) for v in results.values())
    cache_rate = (total_cached / total_tokens) if total_tokens else 0.0

    print(f"\n{'=' * 60}")
    print(f"{method.upper()} OVERALL: P={p:.0%} R={r:.0%} F1={f1:.0%}  total {total_tokens:,} tokens")
    print(f"  {len(worklist)} contracts in {elapsed:.1f}s "
          f"(concurrency={concurrency}); cache hits: {total_cached:,} tok ({cache_rate:.0%})")
    if method == "cascade":
        cheap = sum(v.get("cheap_tokens", 0) for v in results.values())
        strong = sum(v.get("strong_tokens", 0) for v in results.values())
        n_esc = sum(1 for v in results.values() if v.get("escalated"))
        print(f"  cheap {cheap:,} tok + strong {strong:,} tok; escalated {n_esc}/{len(worklist)} contracts")

    out = {
        "method": method,
        "overall": {"precision": p, "recall": r, "f1": f1, **totals},
        "total_tokens": total_tokens,
        "cached_tokens": total_cached,
        "wall_clock_seconds": round(elapsed, 1),
        "concurrency": concurrency,
        "per_contract": results,
    }
    if method == "cascade":
        out["cheap_tokens"] = sum(v.get("cheap_tokens", 0) for v in results.values())
        out["strong_tokens"] = sum(v.get("strong_tokens", 0) for v in results.values())
    return out


def run_agentic_benchmark(dataset: Optional[dict] = None, dataset_name: str = "Synthetic") -> dict | None:
    """Multi-turn agentic analysis benchmark (one model). See _run_audit_benchmark."""
    from agents.agentic_analyzer import run_agent
    return _run_audit_benchmark(
        dataset, dataset_name,
        worker=lambda source, name: run_agent(source, name, max_turns=8),
        method="agentic", banner="Agentic (Multi-Turn) Analysis",
    )


def run_cascade_benchmark(dataset: Optional[dict] = None, dataset_name: str = "Synthetic") -> dict | None:
    """Cascade benchmark: cheap wide-net -> focused strong-model escalation."""
    from agents.cascade_analyzer import run_cascade
    return _run_audit_benchmark(
        dataset, dataset_name,
        worker=lambda source, name: run_cascade(source, name),
        method="cascade", banner="Cascade (cheap -> strong) Analysis",
    )


def run_hybrid_benchmark(dataset: Optional[dict] = None, dataset_name: str = "Synthetic") -> dict | None:
    """
    Run hybrid analysis benchmark: static pre-filter + targeted Sonnet analysis.

    Args:
        dataset: Dict of contract_name -> {source, ground_truth} (default: TEST_CONTRACTS)
        dataset_name: Name for output display

    Returns:
        Results dict with metrics, or None if API key not set
    """
    if not llm.has_credentials():
        print("\nSkipping hybrid analysis (set ANTHROPIC_API_KEY, a provider key, or LLM_BASE_URL to enable)")
        return None

    if dataset is None:
        dataset = TEST_CONTRACTS

    from agents.hybrid_analyzer import run_hybrid_analysis

    print(f"\n{'=' * 60}")
    print(f"BRIDGE-bench: Hybrid (Static+Agentic) Analysis on {dataset_name}")
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

        audit = run_hybrid_analysis(source, name)

        # Convert findings to dict for evaluate_findings()
        ai_findings = [{"type": f.vuln_type, "severity": f.severity} for f in audit.combined_findings]
        metrics = evaluate_findings(ai_findings, gt_vulns)

        results[name] = {
            "metrics": metrics,
            "n_findings": len(ai_findings),
            "analysis_depth": audit.analysis_depth,
        }
        for k in ["tp", "fp", "fn"]:
            totals[k] += metrics[k]

        print(f"\n{name} ({audit.analysis_depth}): P={metrics['precision']:.0%} R={metrics['recall']:.0%} F1={metrics['f1']:.0%}")

    p = totals["tp"] / (totals["tp"] + totals["fp"]) if (totals["tp"] + totals["fp"]) > 0 else 0
    r = totals["tp"] / (totals["tp"] + totals["fn"]) if (totals["tp"] + totals["fn"]) > 0 else 0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0

    print(f"\n{'=' * 60}")
    print(f"HYBRID OVERALL: P={p:.0%} R={r:.0%} F1={f1:.0%}")

    return {
        "method": "hybrid",
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


def run_domain(dataset_list, label, args, results_all):
    """Run static + the selected LLM mode over one domain dataset (real/defi/lending).

    Stores results under <label>_static and <label>_<mode>. Shared by every domain so
    bridges, DEX, and lending go through one identical evaluation path.
    """
    dset = convert_real_contracts_to_dict(dataset_list)
    loaded = sum(1 for c in dataset_list if (c.get("source") or "").strip())
    print(f"\n{'='*60}\n{label}: {loaded}/{len(dataset_list)} contracts have source\n{'='*60}")

    static = run_static_benchmark(dset, label)
    results_all[f"{label}_static"] = static
    if args.no_claude:
        return

    if args.hybrid:
        mode, fn = "hybrid", run_hybrid_benchmark
    elif args.cascade:
        mode, fn = "cascade", run_cascade_benchmark
    elif args.agentic:
        mode, fn = "agentic", run_agentic_benchmark
    else:
        mode, fn = "claude", run_claude_benchmark
    res = fn(dset, label)
    results_all[f"{label}_{mode}"] = res
    if res:
        s, c = static["overall"], res["overall"]
        print(f"\n{label}: Static F1={s['f1']:.0%}  {mode.title()} F1={c['f1']:.0%}  "
              f"Delta={c['f1']-s['f1']:+.0%}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="BRIDGE-bench: Cross-chain bridge vulnerability detection benchmark"
    )
    parser.add_argument(
        "--real",
        action="store_true",
        help="Run against real verified bridge contracts",
    )
    parser.add_argument(
        "--defi",
        action="store_true",
        help="Run against the DEX/AMM dataset (benchmarks/defi_contracts_real.py)",
    )
    parser.add_argument(
        "--lending",
        action="store_true",
        help="Run against the lending dataset (benchmarks/lending_contracts_real.py)",
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
    parser.add_argument(
        "--hybrid",
        action="store_true",
        help="Use hybrid analysis (static pre-filter + targeted Sonnet)",
    )
    parser.add_argument(
        "--cascade",
        action="store_true",
        help="Use cascade analysis (cheap wide-net -> focused strong-model escalation). "
             "Tune via CASCADE_CHEAP_MODEL / CASCADE_STRONG_MODEL.",
    )

    args = parser.parse_args()

    # Determine which dataset(s) to run
    run_synthetic = (not args.real and not args.defi and not args.lending) or args.compare
    run_real = args.real or args.compare

    results_all = {}

    # ──────────────────────────────────────────────────────────────────
    # Run synthetic benchmarks
    # ──────────────────────────────────────────────────────────────────
    if run_synthetic:
        synthetic_static = run_static_benchmark(TEST_CONTRACTS, "Synthetic Patterns")
        results_all["synthetic_static"] = synthetic_static

        if not args.no_claude:
            if args.hybrid:
                synthetic_hybrid = run_hybrid_benchmark(TEST_CONTRACTS, "Synthetic Patterns")
                results_all["synthetic_hybrid"] = synthetic_hybrid

                if synthetic_hybrid:
                    print(f"\n{'=' * 60}")
                    print("SYNTHETIC: Static v2 vs Hybrid")
                    print("=" * 60)
                    s = synthetic_static["overall"]
                    h = synthetic_hybrid["overall"]
                    print(f"  Static v2:  P={s['precision']:.0%}  R={s['recall']:.0%}  F1={s['f1']:.0%}")
                    print(f"  Hybrid:     P={h['precision']:.0%}  R={h['recall']:.0%}  F1={h['f1']:.0%}")
                    delta = h["f1"] - s["f1"]
                    print(f"  Delta F1:   {delta:+.0%}")
            elif args.cascade:
                synthetic_cascade = run_cascade_benchmark(TEST_CONTRACTS, "Synthetic Patterns")
                results_all["synthetic_cascade"] = synthetic_cascade

                if synthetic_cascade:
                    print(f"\n{'=' * 60}")
                    print("SYNTHETIC: Static v2 vs Cascade")
                    print("=" * 60)
                    s = synthetic_static["overall"]
                    a = synthetic_cascade["overall"]
                    print(f"  Static v2:  P={s['precision']:.0%}  R={s['recall']:.0%}  F1={s['f1']:.0%}")
                    print(f"  Cascade:    P={a['precision']:.0%}  R={a['recall']:.0%}  F1={a['f1']:.0%}")
                    print(f"  Delta F1:   {a['f1'] - s['f1']:+.0%}")
            elif args.agentic:
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
            if args.hybrid:
                real_hybrid = run_hybrid_benchmark(real_contracts_dict, "Real Verified Contracts")
                results_all["real_hybrid"] = real_hybrid

                if real_hybrid:
                    print(f"\n{'=' * 60}")
                    print("REAL: Static v2 vs Hybrid")
                    print("=" * 60)
                    s = real_static["overall"]
                    h = real_hybrid["overall"]
                    print(f"  Static v2:  P={s['precision']:.0%}  R={s['recall']:.0%}  F1={s['f1']:.0%}")
                    print(f"  Hybrid:     P={h['precision']:.0%}  R={h['recall']:.0%}  F1={h['f1']:.0%}")
                    delta = h["f1"] - s["f1"]
                    print(f"  Delta F1:   {delta:+.0%}")
            elif args.cascade:
                real_cascade = run_cascade_benchmark(real_contracts_dict, "Real Verified Contracts")
                results_all["real_cascade"] = real_cascade

                if real_cascade:
                    print(f"\n{'=' * 60}")
                    print("REAL: Static v2 vs Cascade")
                    print("=" * 60)
                    s = real_static["overall"]
                    a = real_cascade["overall"]
                    print(f"  Static v2:  P={s['precision']:.0%}  R={s['recall']:.0%}  F1={s['f1']:.0%}")
                    print(f"  Cascade:    P={a['precision']:.0%}  R={a['recall']:.0%}  F1={a['f1']:.0%}")
                    print(f"  Delta F1:   {a['f1'] - s['f1']:+.0%}")
            elif args.agentic:
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
    # Run DEX / lending domains (same evaluation path as bridges)
    # ──────────────────────────────────────────────────────────────────
    if args.defi:
        run_domain(load_defi_contracts(), "defi", args, results_all)
    if args.lending:
        run_domain(load_lending_contracts(), "lending", args, results_all)

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

    # Save JSON results. Stamp the model into the filename so a non-default model
    # (e.g. BENCH_MODEL=fable) doesn't clobber the committed Sonnet baseline.
    from agents.claude_analyzer import MODEL as _RUN_MODEL
    _model_tag = "" if _RUN_MODEL == "claude-sonnet-4-6" else "__" + _RUN_MODEL.replace("/", "-")
    # Cascade uses two models (cheap+strong), so its tag reflects the mode, not
    # the single BENCH_MODEL — and never clobbers the committed single-model baseline.
    if args.cascade:
        _cheap = os.environ.get("CASCADE_CHEAP_MODEL", "deepseek")
        _strong = os.environ.get("CASCADE_STRONG_MODEL", "opus")
        _model_tag = f"__cascade_{_cheap}_{_strong}".replace("/", "-")
    if (args.defi or args.lending) and not args.real and not args.compare:
        _dom = "defi" if args.defi else ""
        _dom = (_dom + ("_lending" if args.lending else "")).strip("_") or "domain"
        output_filename = f"results_{_dom}{_model_tag}.json"
    elif args.real and not args.compare:
        output_filename = f"results_real{_model_tag}.json"
    else:
        output_filename = f"results{_model_tag}.json"
    output_path = Path(__file__).parent.parent / output_filename
    with open(output_path, "w") as f:
        json.dump(results_all, f, indent=2, default=str)
    print(f"\nResults saved to {output_path}")
