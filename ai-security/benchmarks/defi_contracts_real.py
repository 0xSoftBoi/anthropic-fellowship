"""
DEX/AMM Real Contract Dataset

Extension to bridge_contracts_real.py targeting DEX/AMM protocol exploits.
Same structure as bridge contracts for unified benchmarking.

Contracts:
  - Euler Finance ($197M) — donation_attack_bad_debt
  - Curve Finance ($70M) — reentrancy_vyper_compiler
  - Kyberswap ($46M) — tick_boundary_exploit
  - Platypus ($8.5M) — flash_loan_collateral_inflation
  - DODO ($3.8M) — price_oracle_manipulation
"""

from pathlib import Path
from typing import Optional


DEX_VULNERABILITY_TAXONOMY = {
    "oracle_price_manipulation": {
        "type": "oracle_price_manipulation",
        "severity": "critical",
        "description": "DEX vulnerable to price oracle manipulation via flash loans or spot price dependency",
    },
    "tick_boundary_exploit": {
        "type": "tick_boundary_exploit",
        "severity": "critical",
        "description": "Integer precision loss at tick boundaries enables pool manipulation",
    },
    "flash_loan_collateral_inflation": {
        "type": "flash_loan_collateral_inflation",
        "severity": "critical",
        "description": "Flash loans used to inflate collateral valuation and drain reserves",
    },
    "donation_attack_bad_debt": {
        "type": "donation_attack_bad_debt",
        "severity": "critical",
        "description": "Donation attacks used to manipulate exchange rates and accumulate bad debt",
    },
    "reentrancy_in_dex_callback": {
        "type": "reentrancy_in_dex_callback",
        "severity": "critical",
        "description": "Reentrancy vulnerability in DEX callback handlers (Uniswap v3 flash, etc.)",
    },
    "price_impact_manipulation": {
        "type": "price_impact_manipulation",
        "severity": "high",
        "description": "DEX price impact calculation exploitable for profit",
    },
    "jit_liquidity_attack": {
        "type": "jit_liquidity_attack",
        "severity": "high",
        "description": "Just-in-time liquidity provision used for sandwich attacks",
    },
    "sandwich_attack_vector": {
        "type": "sandwich_attack_vector",
        "severity": "medium",
        "description": "MEV-friendly pool design enables sandwich attacks",
    },
    "missing_slippage_protection": {
        "type": "missing_slippage_protection",
        "severity": "high",
        "description": "Insufficient slippage checks on swap operations",
    },
    "spot_price_dependency": {
        "type": "spot_price_dependency",
        "severity": "critical",
        "description": "Protocol depends on spot price without TWAP or price oracle protection",
    },
    "missing_solvency_check": {
        "type": "missing_solvency_check",
        "severity": "critical",
        "description": "Privileged/state-changing path skips an account health/solvency check (e.g. Euler donateToReserves)",
    },
    "unprotected_initializer": {
        "type": "unprotected_initializer",
        "severity": "critical",
        "description": "init() lacks access control / re-init guard, allowing state takeover (e.g. DODO crowdpool)",
    },
}


# Contract metadata: {name: {metadata}}
CONTRACTS = {
    "euler_finance_lending": {
        "loss_usd": 197_000_000,
        "fork_block": 16_928_000,
        "fork_chain": "mainnet",
        "exploit_date": "2023-03-15",
        "vuln_class": "donation_attack",
        "chain": "ethereum",
        "protocol": "Lending/DEX",
    },
    "curve_finance_vyper_reentrancy": {
        "loss_usd": 70_000_000,
        "fork_block": 18_500_000,
        "fork_chain": "mainnet",
        "exploit_date": "2023-07-30",
        "vuln_class": "reentrancy",
        "chain": "ethereum",
        "protocol": "DEX/AMM",
    },
    "kyberswap_elastic_swap": {
        "loss_usd": 46_000_000,
        "fork_block": 18_900_000,
        "fork_chain": "mainnet",
        "exploit_date": "2023-11-22",
        "vuln_class": "tick_boundary",
        "chain": "ethereum",
        "protocol": "DEX/AMM",
    },
    "platypus_finance_pool": {
        "loss_usd": 8_500_000,
        "fork_block": 16_788_000,
        "fork_chain": "avalanche",
        "exploit_date": "2023-02-16",
        "vuln_class": "flash_loan",
        "chain": "avalanche",
        "protocol": "DEX/AMM",
    },
    "dodo_v1_oracle": {
        # CORRECTED 2026-06: the March-2021 DODO crowdpool hack was on ETHEREUM (not BSC)
        # and the root cause was an unprotected init() (re-initialization via the flash-loan
        # callback), not oracle manipulation. Verified pool address still unconfirmed.
        "loss_usd": 3_800_000,
        "fork_block": 12_000_000,
        "fork_chain": "mainnet",
        "exploit_date": "2021-03-09",
        "vuln_class": "unprotected_initializer",
        "chain": "ethereum",
        "protocol": "DEX/AMM",
    },
}


# Ground truth vulnerability types for each contract
GROUND_TRUTH = {
    "euler_finance_lending": [
        # CORRECTED 2026-06: the exploited bug is the missing solvency/health check on
        # donateToReserves, not slippage. Verified source committed (module 0x2718...25d3).
        "donation_attack_bad_debt",
        "missing_solvency_check",
    ],
    "curve_finance_vyper_reentrancy": [
        "reentrancy_in_dex_callback",
    ],
    "kyberswap_elastic_swap": [
        "tick_boundary_exploit",
        "price_impact_manipulation",
    ],
    "platypus_finance_pool": [
        # CORRECTED 2026-06: root cause is emergencyWithdraw solvency-check ordering
        # (checks before accounting for USP debt), flash-loan assisted — not spot price.
        "missing_solvency_check",
        "flash_loan_collateral_inflation",
    ],
    "dodo_v1_oracle": [
        # CORRECTED 2026-06: unprotected init() (re-init via flash-loan callback), not oracle manip.
        "unprotected_initializer",
    ],
}


def load_defi_contracts() -> list:
    """
    Load DEX/AMM contracts for analysis.

    Returns the canonical benchmark format (same as bridge/lending loaders) so the
    runner can evaluate every domain through one code path:
        [{name, source, ground_truth: {vulnerabilities, overall_risk}, metadata}]

    Source is read from benchmarks/contracts/<name>.sol (was previously a broken
    relative "sources/" path that never resolved).
    """
    contracts_dir = Path(__file__).parent / "contracts"
    dataset = []

    for contract_name, metadata in CONTRACTS.items():
        sol_path = contracts_dir / f"{contract_name}.sol"
        source = None
        if sol_path.exists():
            txt = sol_path.read_text()
            source = txt if txt.strip() else None

        vulnerabilities = [
            {
                "type": vuln_type,
                "severity": DEX_VULNERABILITY_TAXONOMY.get(vuln_type, {}).get("severity", "medium"),
                "description": DEX_VULNERABILITY_TAXONOMY.get(vuln_type, {}).get("description", ""),
            }
            for vuln_type in GROUND_TRUTH.get(contract_name, [])
        ]

        dataset.append({
            "name": contract_name,
            "source": source,
            "ground_truth": {
                "vulnerabilities": vulnerabilities,
                "overall_risk": "critical" if vulnerabilities else "unknown",
            },
            "metadata": {
                **metadata,
                "total_loss_usd": metadata["loss_usd"],
                "exploit_class": metadata["vuln_class"],
            },
        })

    return dataset


if __name__ == "__main__":
    defi = load_defi_contracts()
    print(f"Loaded {len(defi)} DEX contracts")
    for c in defi:
        has_source = "✓" if (c["source"] or "").strip() else "✗"
        print(f"  {c['name']}: {has_source} source, {len(c['ground_truth']['vulnerabilities'])} vulns")
