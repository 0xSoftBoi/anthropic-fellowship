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
        "loss_usd": 3_800_000,
        "fork_block": 12_000_000,
        "fork_chain": "bsc",
        "exploit_date": "2021-03-23",
        "vuln_class": "oracle_manipulation",
        "chain": "bsc",
        "protocol": "DEX/AMM",
    },
}


# Ground truth vulnerability types for each contract
GROUND_TRUTH = {
    "euler_finance_lending": [
        "donation_attack_bad_debt",
        "missing_slippage_protection",
    ],
    "curve_finance_vyper_reentrancy": [
        "reentrancy_in_dex_callback",
    ],
    "kyberswap_elastic_swap": [
        "tick_boundary_exploit",
        "price_impact_manipulation",
    ],
    "platypus_finance_pool": [
        "flash_loan_collateral_inflation",
        "spot_price_dependency",
    ],
    "dodo_v1_oracle": [
        "oracle_price_manipulation",
    ],
}


def load_defi_contracts() -> dict:
    """
    Load DEX/AMM contracts for analysis.

    Returns:
        Dict mapping contract names to {source, metadata, ground_truth}
    """
    contracts = {}

    for contract_name, metadata in CONTRACTS.items():
        # Try to load source from disk
        source_path = Path("sources") / f"{contract_name}.sol"

        source = ""
        if source_path.exists():
            try:
                source = source_path.read_text()
            except Exception:
                pass

        contracts[contract_name] = {
            "source": source,
            "metadata": metadata,
            "ground_truth": GROUND_TRUTH.get(contract_name, []),
            "vulnerabilities": [
                {
                    "type": vuln_type,
                    "severity": DEX_VULNERABILITY_TAXONOMY.get(vuln_type, {}).get("severity", "medium"),
                    "description": DEX_VULNERABILITY_TAXONOMY.get(vuln_type, {}).get("description", ""),
                }
                for vuln_type in GROUND_TRUTH.get(contract_name, [])
            ],
        }

    return contracts


if __name__ == "__main__":
    defi = load_defi_contracts()
    print(f"Loaded {len(defi)} DEX contracts")
    for name, data in defi.items():
        has_source = "✓" if data["source"] else "✗"
        print(f"  {name}: {has_source} source, {len(data['vulnerabilities'])} vulns")
