"""
Lending Protocol Vulnerability Dataset (Phase 5C Expansion)

Real verified Solidity source code for lending/money market exploits.
Uses the same schema as bridge_contracts_real.py for unified benchmarking.

Dataset includes:
  - Compound price oracle manipulation ($80M)
  - Venus flash loan collateral inflation ($200M)
  - Cream Finance reentrancy & price oracle ($130M)
"""

import json
from pathlib import Path
from typing import Optional


# Vulnerabilities specific to lending/money market protocols
LENDING_VULNERABILITY_TAXONOMY = {
    "price_oracle_manipulation": {
        "type": "price_oracle_manipulation",
        "severity": "critical",
        "description": "Lending oracle vulnerable to flash loan or external price manipulation",
    },
    "flash_loan_collateral_inflation": {
        "type": "flash_loan_collateral_inflation",
        "severity": "critical",
        "description": "Flash loan inflates collateral value, enables over-borrowing",
    },
    "donation_attack_bad_debt": {
        "type": "donation_attack_bad_debt",
        "severity": "critical",
        "description": "Donation attack enables bad debt accumulation in lending pool",
    },
    "reentrancy_price_oracle": {
        "type": "reentrancy_price_oracle",
        "severity": "critical",
        "description": "Reentrancy during price oracle update or liquidation",
    },
    "liquidation_manipulation": {
        "type": "liquidation_manipulation",
        "severity": "critical",
        "description": "Liquidation collateral/incentive parameters can be manipulated",
    },
    "collateral_factor_exploit": {
        "type": "collateral_factor_exploit",
        "severity": "critical",
        "description": "Collateral factor calculation or enforcement has exploitable edge case",
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
    "ctoken_inflation": {
        "type": "ctoken_inflation",
        "severity": "high",
        "description": "cToken exchange rate manipulation via donation or rounding",
    },
}

# Map lending types to bridge/DEX taxonomy for cross-domain equivalences
TYPE_EQUIVALENCES_LENDING = {
    "price_oracle_manipulation": ["flash_loan_price_manipulation", "spot_price_dependency"],
    "flash_loan_collateral_inflation": ["flash_loan_price_manipulation"],
    "donation_attack_bad_debt": ["bad_debt_accumulation", "zero_value_deposit"],
    "reentrancy_price_oracle": ["reentrancy"],
    "liquidation_manipulation": ["oracle_price_manipulation"],
    "collateral_factor_exploit": ["integer_boundary_exploit"],
}


def load_lending_contracts() -> list:
    """
    Load all lending protocol exploits for Phase 5C expansion.

    Returns:
        List of dicts in format: {name, source, ground_truth, metadata}
    """
    contracts_dir = Path(__file__).parent / "contracts"

    # Lending exploit metadata — 3 real protocols
    contract_metadata = {
        "compound_oracle_manipulation": {
            "loss_usd": 80_000_000,
            "fork_block": 12_255_000,
            "fork_chain": "mainnet",
            "exploit_date": "2021-05-15",
            "vuln_class": "price_oracle_manipulation",
            "chain": "ethereum",
            "protocol": "Money Market",
            "description": "Oracle price manipulation enables liquidation of healthy positions",
        },
        "venus_flash_loan": {
            "loss_usd": 200_000_000,
            "fork_block": 6_000_000,
            "fork_chain": "bsc",
            "exploit_date": "2021-05-19",
            "vuln_class": "flash_loan_collateral_inflation",
            "chain": "bsc",
            "protocol": "Money Market",
            "description": "Flash loan inflates collateral, enables liquidator undercut via borrow",
        },
        "cream_finance_reentrancy": {
            "loss_usd": 130_000_000,
            "fork_block": 13_055_000,
            "fork_chain": "mainnet",
            "exploit_date": "2021-10-27",
            "vuln_class": "reentrancy_price_oracle",
            "chain": "ethereum",
            "protocol": "Money Market",
            "description": "Reentrancy in price oracle update during liquidation",
        },
    }

    # Vulnerability labels for each contract (what was actually exploited)
    vuln_details = {
        "compound_oracle_manipulation": [
            "price_oracle_manipulation",
            "oracle_price_manipulation",
        ],
        "venus_flash_loan": [
            "flash_loan_collateral_inflation",
            "ctoken_inflation",
        ],
        "cream_finance_reentrancy": [
            "reentrancy_price_oracle",
            "price_oracle_manipulation",
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
            if vuln_key in LENDING_VULNERABILITY_TAXONOMY:
                vulnerabilities.append(LENDING_VULNERABILITY_TAXONOMY[vuln_key])

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


def get_loaded_lending_contracts() -> dict:
    """Get statistics on loaded lending contracts."""
    contracts = load_lending_contracts()

    loaded_count = sum(1 for c in contracts if c["source"] is not None)
    total_vuln = sum(len(c["ground_truth"]["vulnerabilities"]) for c in contracts)

    return {
        "total": len(contracts),
        "loaded": loaded_count,
        "not_loaded": len(contracts) - loaded_count,
        "total_vulnerabilities": total_vuln,
        "by_vuln_class": {
            "price_oracle_manipulation": sum(1 for c in contracts if c["metadata"]["exploit_class"] == "price_oracle_manipulation"),
            "flash_loan_collateral_inflation": sum(1 for c in contracts if c["metadata"]["exploit_class"] == "flash_loan_collateral_inflation"),
            "reentrancy_price_oracle": sum(1 for c in contracts if c["metadata"]["exploit_class"] == "reentrancy_price_oracle"),
        },
    }


if __name__ == "__main__":
    contracts = load_lending_contracts()
    stats = get_loaded_lending_contracts()

    print(f"Lending Protocol Exploit Dataset (Phase 5C)")
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
    print(f"  python3 fetch_contracts.py --lending")
