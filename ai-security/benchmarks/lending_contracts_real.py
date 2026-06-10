"""
Lending Protocol Vulnerability Dataset (Phase 5C Expansion)

Uses the same schema as bridge_contracts_real.py for unified benchmarking.

  REBUILT June 2026 (see docs/DATA_QUALITY.md). The original entries were dropped
  after a post-mortem audit found them unusable for source detection:
    - "Compound oracle manipulation $80M" — no such event existed.
    - "Venus flash loan $200M" — a market/oracle event, not a code bug.
    - "Cream reentrancy $130M Oct-2021" — conflated two hacks (Oct = oracle manip).
  The domain is now built around 3 GENUINE source-level bugs with verified on-chain
  Solidity:
    - Onyx oPEPE — empty-market exchange-rate manipulation (rounding/donation).
    - Compound P062 Comptroller — COMP reward-accounting comparison bug.
    - Cream crAMP — ERC-777 cross-function reentrancy (NOTE: on-chain impl is the
      post-hack patched version; flagged in metadata).
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
    # ── rebuilt 2026-06: genuine source-level lending bugs (verified contracts) ──
    "reentrancy": {
        "type": "reentrancy",
        "severity": "critical",
        "description": "External call (e.g. ERC-777 hook) before state finalized; re-entry manipulates accounting",
    },
    "erc777_callback": {
        "type": "erc777_callback",
        "severity": "critical",
        "description": "ERC-777 tokensReceived hook used to re-enter a market mid-borrow (CEI violation)",
    },
    "cross_function_reentrancy": {
        "type": "cross_function_reentrancy",
        "severity": "critical",
        "description": "Re-entry into a different function while the first call's state is stale",
    },
    "rounding_error": {
        "type": "rounding_error",
        "severity": "high",
        "description": "Integer truncation in mint/redeem share math lets attacker extract more than deposited",
    },
    "empty_market_donation": {
        "type": "empty_market_donation",
        "severity": "high",
        "description": "First-depositor/donation attack on an empty market inflates the exchange rate",
    },
    "exchange_rate_manipulation": {
        "type": "exchange_rate_manipulation",
        "severity": "critical",
        "description": "cToken/oToken exchange rate manipulated via direct donation on a low-supply market",
    },
    "reward_accounting_bug": {
        "type": "reward_accounting_bug",
        "severity": "critical",
        "description": "Incentive/reward distribution logic over-pays due to a comparison/branch error",
    },
    "incorrect_comparison_operator": {
        "type": "incorrect_comparison_operator",
        "severity": "high",
        "description": "Wrong comparison (>, >=) or branch in accounting causes incorrect payouts",
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

    # Lending exploit metadata — REBUILT 2026-06 around genuine source-level bugs with
    # verified on-chain Solidity (see docs/DATA_QUALITY.md for why the old Compound/
    # Venus/Cream-Oct entries were dropped: non-existent event / market event / wrong hack).
    contract_metadata = {
        "onyx_opepe_market": {
            "loss_usd": 2_100_000,
            "fork_block": 0,
            "fork_chain": "mainnet",
            "exploit_date": "2023-11-01",
            "vuln_class": "exchange_rate_manipulation",
            "chain": "ethereum",
            "protocol": "Money Market (Compound-V2 fork)",
            "address": "0x5FdBcD61bC9bd4B6D3FD1F49a5D253165Ea11750",
            "description": "Empty-market exchange-rate manipulation via donation + integer truncation in mint/redeem",
        },
        "compound_p062_comptroller": {
            "loss_usd": 80_000_000,
            "fork_block": 0,
            "fork_chain": "mainnet",
            "exploit_date": "2021-09-29",
            "vuln_class": "reward_accounting_bug",
            "chain": "ethereum",
            "protocol": "Money Market",
            "address": "0x374ABb8cE19A73f2c4EFAd642bda76c797f19233",
            "description": "Proposal-062 Comptroller over-distributed COMP via a comparison/branch error in distributeSupplierComp",
        },
        "cream_cramp_market": {
            "loss_usd": 18_800_000,
            "fork_block": 0,
            "fork_chain": "mainnet",
            "exploit_date": "2021-08-30",
            "vuln_class": "reentrancy",
            "chain": "ethereum",
            "protocol": "Money Market (Compound fork)",
            "address": "0x2Db6c82CE72C8d7D770ba1b5F5Ed0b6E075066d6",
            "description": "ERC-777 AMP tokensReceived hook re-enters borrow() before debt state update (CEI violation). NOTE: on-chain impl is post-hack patched.",
        },
    }

    # Vulnerability labels for each contract (the actual source-level root cause)
    vuln_details = {
        "onyx_opepe_market": [
            "exchange_rate_manipulation",
            "rounding_error",
            "empty_market_donation",
        ],
        "compound_p062_comptroller": [
            "reward_accounting_bug",
            "incorrect_comparison_operator",
        ],
        "cream_cramp_market": [
            "reentrancy",
            "erc777_callback",
            "cross_function_reentrancy",
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
            "exchange_rate_manipulation": sum(1 for c in contracts if c["metadata"]["exploit_class"] == "exchange_rate_manipulation"),
            "reward_accounting_bug": sum(1 for c in contracts if c["metadata"]["exploit_class"] == "reward_accounting_bug"),
            "reentrancy": sum(1 for c in contracts if c["metadata"]["exploit_class"] == "reentrancy"),
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
