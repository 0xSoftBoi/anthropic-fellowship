"""
DeFi Protocol Vulnerability Dataset (Phase 5B Expansion)

Real verified Solidity source code for DEX/AMM/Lending protocol exploits.
Uses the same schema as bridge_contracts_real.py for unified benchmarking.

Dataset includes:
  - Euler Finance donation attack ($197M)
  - Curve Finance reentrancy ($70M)
  - Kyberswap tick boundary exploit ($46M)
  - Platypus flash loan collateral inflation ($8.5M)
  - DODO price oracle manipulation ($3.8M)
"""

import json
from pathlib import Path
from typing import Optional


# Vulnerabilities specific to DEX/AMM/Lending protocols
# (distinct from bridge-specific issues in bridge_contracts_real.py)
DEFI_VULNERABILITY_TAXONOMY = {
    "oracle_price_manipulation": {
        "type": "oracle_price_manipulation",
        "severity": "critical",
        "description": "Price oracle vulnerable to manipulation via flash loans or spot price reliance",
    },
    "tick_boundary_exploit": {
        "type": "tick_boundary_exploit",
        "severity": "critical",
        "description": "Uniswap V3 tick boundary arithmetic allows LP withdrawal exploit",
    },
    "flash_loan_collateral_inflation": {
        "type": "flash_loan_collateral_inflation",
        "severity": "critical",
        "description": "Collateral value inflated via flash loan price manipulation",
    },
    "donation_attack_bad_debt": {
        "type": "donation_attack_bad_debt",
        "severity": "critical",
        "description": "Donation attack enables bad debt accumulation in lending protocol",
    },
    "reentrancy_in_dex_callback": {
        "type": "reentrancy_in_dex_callback",
        "severity": "critical",
        "description": "Reentrancy during DEX callback (Uniswap V3 IFlashCallback)",
    },
    "spot_price_oracle": {
        "type": "spot_price_oracle",
        "severity": "critical",
        "description": "Spot price from DEX reserves without TWAP or price feed",
    },
    "precision_loss_rounding": {
        "type": "precision_loss_rounding",
        "severity": "high",
        "description": "Integer division rounding enables dust amount attacks",
    },
    "jit_liquidity_attack": {
        "type": "jit_liquidity_attack",
        "severity": "high",
        "description": "Just-in-time liquidity sandwich attacks on Uniswap V3",
    },
    "sandwich_attack_vector": {
        "type": "sandwich_attack_vector",
        "severity": "high",
        "description": "Sandwich attack vulnerability in order execution",
    },
    "liquidation_manipulation": {
        "type": "liquidation_manipulation",
        "severity": "critical",
        "description": "Liquidation parameters can be manipulated via price oracle",
    },
    "interest_rate_oracle_abuse": {
        "type": "interest_rate_oracle_abuse",
        "severity": "high",
        "description": "Interest rate oracle can be manipulated or is stale",
    },
    "bad_debt_accumulation": {
        "type": "bad_debt_accumulation",
        "severity": "high",
        "description": "Protocol allows accumulation of uncovered bad debt",
    },
}

# Map DEX types to bridge taxonomy for cross-domain equivalences
TYPE_EQUIVALENCES_DEFI = {
    "oracle_price_manipulation": ["flash_loan_price_manipulation", "spot_price_dependency"],
    "tick_boundary_exploit": ["precision_loss_rounding", "integer_boundary_exploit"],
    "flash_loan_collateral_inflation": ["flash_loan_price_manipulation"],
    "donation_attack_bad_debt": ["bad_debt_accumulation", "zero_value_deposit"],
    "reentrancy_in_dex_callback": ["reentrancy"],
}


def load_defi_contracts() -> list:
    """
    Load all DeFi protocol exploits for Phase 5B expansion.

    Returns:
        List of dicts in format: {name, source, ground_truth, metadata}
    """
    contracts_dir = Path(__file__).parent / "contracts"

    # DeFi exploit metadata — 5 real protocols with verified source
    contract_metadata = {
        "euler_finance_donation_attack": {
            "loss_usd": 197_000_000,
            "fork_block": 17_016_736,
            "fork_chain": "mainnet",
            "exploit_date": "2023-03-13",
            "vuln_class": "donation_attack_bad_debt",
            "chain": "ethereum",
            "protocol": "Lending",
            "description": "Donation attack inflates asset prices, allows bad debt accumulation",
        },
        "curve_finance_reentrancy": {
            "loss_usd": 70_000_000,
            "fork_block": 18_040_000,
            "fork_chain": "mainnet",
            "exploit_date": "2023-07-30",
            "vuln_class": "reentrancy_in_dex_callback",
            "chain": "ethereum",
            "protocol": "DEX/AMM",
            "description": "Vyper compiler reentrancy check bypass in LP callbacks",
        },
        "kyberswap_tick_boundary": {
            "loss_usd": 46_000_000,
            "fork_block": 18_538_460,
            "fork_chain": "mainnet",
            "exploit_date": "2023-11-22",
            "vuln_class": "tick_boundary_exploit",
            "chain": "ethereum",
            "protocol": "DEX/AMM",
            "description": "Uniswap V3 clone with tick boundary arithmetic vulnerability",
        },
        "platypus_flash_loan": {
            "loss_usd": 8_500_000,
            "fork_block": 9_202_262,
            "fork_chain": "avalanche",
            "exploit_date": "2023-02-15",
            "vuln_class": "flash_loan_collateral_inflation",
            "chain": "avalanche",
            "protocol": "Stablecoin Protocol",
            "description": "Flash loan enables collateral inflation and LP withdrawal exploit",
        },
        "dodo_price_oracle": {
            "loss_usd": 3_800_000,
            "fork_block": 5_261_101,
            "fork_chain": "bsc",
            "exploit_date": "2021-03-23",
            "vuln_class": "oracle_price_manipulation",
            "chain": "bsc",
            "protocol": "DEX/AMM",
            "description": "Spot price oracle vulnerability via reserves manipulation",
        },
    }

    # Vulnerability labels for each contract (what was actually exploited)
    vuln_details = {
        "euler_finance_donation_attack": [
            "donation_attack_bad_debt",
            "bad_debt_accumulation",
        ],
        "curve_finance_reentrancy": [
            "reentrancy_in_dex_callback",
        ],
        "kyberswap_tick_boundary": [
            "tick_boundary_exploit",
            "precision_loss_rounding",
        ],
        "platypus_flash_loan": [
            "flash_loan_collateral_inflation",
        ],
        "dodo_price_oracle": [
            "oracle_price_manipulation",
            "spot_price_oracle",
        ],
    }

    # Load and structure contracts
    dataset = []

    for contract_name, metadata in contract_metadata.items():
        sol_path = contracts_dir / f"{contract_name}.sol"

        # Try to load source code
        if sol_path.exists():
            with open(sol_path, "r") as f:
                source_code = f.read()
        else:
            source_code = None

        # Build ground truth from vulnerability list
        vulnerabilities = []
        for vuln_key in vuln_details.get(contract_name, []):
            if vuln_key in DEFI_VULNERABILITY_TAXONOMY:
                vulnerabilities.append(DEFI_VULNERABILITY_TAXONOMY[vuln_key])

        overall_risk = "critical" if vulnerabilities else "unknown"

        contract_dict = {
            "name": contract_name,
            "source": source_code,
            "ground_truth": {
                "vulnerabilities": vulnerabilities,
                "overall_risk": overall_risk,
            },
            "metadata": {
                **metadata,
                "total_loss_usd": metadata["loss_usd"],
                "exploit_class": metadata["vuln_class"],
            },
        }

        dataset.append(contract_dict)

    return dataset


def get_loaded_defi_contracts() -> dict:
    """Get statistics on loaded DeFi contracts."""
    contracts = load_defi_contracts()

    loaded_count = sum(1 for c in contracts if c["source"] is not None)
    total_vuln = sum(len(c["ground_truth"]["vulnerabilities"]) for c in contracts)

    return {
        "total": len(contracts),
        "loaded": loaded_count,
        "not_loaded": len(contracts) - loaded_count,
        "total_vulnerabilities": total_vuln,
        "by_vuln_class": {
            "donation_attack_bad_debt": sum(1 for c in contracts if c["metadata"]["exploit_class"] == "donation_attack_bad_debt"),
            "reentrancy_in_dex_callback": sum(1 for c in contracts if c["metadata"]["exploit_class"] == "reentrancy_in_dex_callback"),
            "tick_boundary_exploit": sum(1 for c in contracts if c["metadata"]["exploit_class"] == "tick_boundary_exploit"),
            "flash_loan_collateral_inflation": sum(1 for c in contracts if c["metadata"]["exploit_class"] == "flash_loan_collateral_inflation"),
            "oracle_price_manipulation": sum(1 for c in contracts if c["metadata"]["exploit_class"] == "oracle_price_manipulation"),
        },
    }


if __name__ == "__main__":
    contracts = load_defi_contracts()
    stats = get_loaded_defi_contracts()

    print(f"DeFi Protocol Exploit Dataset (Phase 5B)")
    print(f"{'='*60}")
    print(f"Total contracts: {stats['total']}")
    print(f"Loaded from disk: {stats['loaded']}")
    print(f"Not yet fetched: {stats['not_loaded']}")
    print(f"\nTotal vulnerabilities: {stats['total_vulnerabilities']}")

    print(f"\nBy vulnerability class:")
    for vuln_class, count in stats["by_vuln_class"].items():
        print(f"  {vuln_class:<35} {count}")

    print(f"\n{'='*60}")
    print(f"To fetch contracts, run:")
    print(f"  export ETHERSCAN_API_KEY=<your_key>")
    print(f"  python3 fetch_contracts.py --defi")
