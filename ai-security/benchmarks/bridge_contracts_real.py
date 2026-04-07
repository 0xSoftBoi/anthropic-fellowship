"""
BRIDGE-bench Real Contract Dataset

Real verified Solidity source code fetched from Etherscan/BSCScan.
Uses the same schema as test_contracts.py so both datasets can be evaluated
with the same benchmark runner.

Each contract includes:
  - name: Identifier for benchmark
  - source: Full verified Solidity source code (flattened multi-file)
  - ground_truth: Vulnerability labels from bridge_bench.py post-mortems
  - metadata: Fork info, loss, addresses, exploit class
"""

import json
from pathlib import Path
from typing import Optional


# Vulnerabilities that cannot be detected via code analysis
# These are operational/policy issues, not code patterns
CODE_UNREACHABLE_VULN_TYPES = {
    "social_engineering_vector",      # Key compromise via social engineering (not in code)
    "no_anomaly_detection",           # Off-chain monitoring requirement
    "multisig_key_compromise",        # Key management issue (not in code)
    "recurring_vulnerability",        # Historical pattern (not detectable in current code)
}


# Map vulnerability details from bridge_bench.py to ground truth format
VULNERABILITY_TAXONOMY = {
    "unrestricted_cross_chain_call": {
        "type": "unrestricted_cross_chain_call",
        "severity": "critical",
        "description": "Bridge accepted arbitrary contract calls via cross-chain messages",
    },
    "keeper_key_overwrite": {
        "type": "keeper_key_overwrite",
        "severity": "critical",
        "description": "Routine operation allowed overwriting keeper public keys",
    },
    "zero_value_deposit": {
        "type": "zero_value_deposit",
        "severity": "critical",
        "description": "Bridge credited deposits with zero ETH value",
    },
    "missing_input_validation": {
        "type": "missing_input_validation",
        "severity": "critical",
        "description": "Insufficient validation of bridge input parameters",
    },
    "low_validator_threshold": {
        "type": "low_validator_threshold",
        "severity": "critical",
        "description": "Multisig or validator set had dangerously low signature threshold",
    },
    "no_anomaly_detection": {
        "type": "no_anomaly_detection",
        "severity": "high",
        "description": "No monitoring or anomaly detection for unusual activity",
    },
    "social_engineering_vector": {
        "type": "social_engineering_vector",
        "severity": "high",
        "description": "Vulnerability exploitable via social engineering (key compromise)",
    },
    "multisig_key_compromise": {
        "type": "multisig_key_compromise",
        "severity": "critical",
        "description": "Multisig keys were compromised or insufficient in count",
    },
    "arbitrary_external_call": {
        "type": "arbitrary_external_call",
        "severity": "critical",
        "description": "Bridge allowed arbitrary external calls with user-supplied calldata",
    },
    "infinite_approval_drain": {
        "type": "infinite_approval_drain",
        "severity": "critical",
        "description": "Bridge exploited infinite approvals to drain user tokens",
    },
    "approval_exploitation": {
        "type": "approval_exploitation",
        "severity": "critical",
        "description": "Bridge allowed exploitation of user token approvals",
    },
    "faulty_route_validation": {
        "type": "faulty_route_validation",
        "severity": "critical",
        "description": "Insufficient validation of bridge routes enabled attacks",
    },
    "recurring_vulnerability": {
        "type": "recurring_vulnerability",
        "severity": "critical",
        "description": "Same vulnerability class exploited previously",
    },
    "flash_loan_price_manipulation": {
        "type": "flash_loan_price_manipulation",
        "severity": "critical",
        "description": "Bridge was vulnerable to flash loan price manipulation",
    },
    "spot_price_dependency": {
        "type": "spot_price_dependency",
        "severity": "critical",
        "description": "Bridge pricing relied on spot price without manipulation protection",
    },
    "zero_root_initialization": {
        "type": "zero_root_initialization",
        "severity": "critical",
        "description": "Merkle tree root was initialized to zero or default value",
    },
    "default_value_exploit": {
        "type": "default_value_exploit",
        "severity": "critical",
        "description": "Uninitialized mapping/storage values treated as valid",
    },
    "missing_upgrade_validation": {
        "type": "missing_upgrade_validation",
        "severity": "critical",
        "description": "Bridge upgrade logic didn't validate state changes",
    },
    "replay_attack": {
        "type": "replay_attack",
        "severity": "critical",
        "description": "Message status updated after external call, enabling replay attacks",
    },
}


def load_real_contracts() -> list:
    """
    Load all fetched real contracts and return as benchmark dataset.

    Returns:
        List of dicts in format: {name, source, ground_truth, metadata}
    """
    contracts_dir = Path(__file__).parent / "contracts"

    # Contract metadata from bridge_bench.py
    contract_metadata = {
        "poly_network_eth_cross_chain_manager": {
            "loss_usd": 610_000_000,
            "fork_block": 12_996_658,
            "fork_chain": "mainnet",
            "exploit_date": "2021-08-10",
            "vuln_class": "message_validation",
            "chain": "ethereum",
        },
        "nomad_bridge_replica": {
            "loss_usd": 190_000_000,
            "fork_block": 15_259_100,
            "fork_chain": "mainnet",
            "exploit_date": "2022-08-01",
            "vuln_class": "message_validation",
            "chain": "ethereum",
        },
        "qubit_finance_bridge": {
            "loss_usd": 80_000_000,
            "fork_block": 14_090_169,
            "fork_chain": "bsc",
            "exploit_date": "2022-01-28",
            "vuln_class": "input_validation",
            "chain": "bsc",
        },
        "ronin_bridge_validator": {
            "loss_usd": 625_000_000,
            "fork_block": 14_442_834,
            "fork_chain": "mainnet",
            "exploit_date": "2022-03-23",
            "vuln_class": "validator_governance",
            "chain": "ethereum",
        },
        "orbit_chain_multisig": {
            "loss_usd": 82_000_000,
            "fork_block": 18_908_049,
            "fork_chain": "mainnet",
            "exploit_date": "2024-01-01",
            "vuln_class": "validator_governance",
            "chain": "ethereum",
        },
        "lifi_protocol_diamond_march_2022": {
            "loss_usd": 600_000,
            "fork_block": 14_420_686,
            "fork_chain": "mainnet",
            "exploit_date": "2022-03-20",
            "vuln_class": "approval_exploitation",
            "chain": "ethereum",
        },
        "socket_gateway_registry": {
            "loss_usd": 3_300_000,
            "fork_block": 19_021_453,
            "fork_chain": "mainnet",
            "exploit_date": "2024-01-16",
            "vuln_class": "approval_exploitation",
            "chain": "ethereum",
        },
        "xbridge_approval_drain": {
            "loss_usd": 1_600_000,
            "fork_block": 19_723_701,
            "fork_chain": "mainnet",
            "exploit_date": "2024-04-01",
            "vuln_class": "approval_exploitation",
            "chain": "ethereum",
        },
        "lifi_protocol_diamond_july_2024": {
            "loss_usd": 10_000_000,
            "fork_block": 20_318_962,
            "fork_chain": "mainnet",
            "exploit_date": "2024-07-16",
            "vuln_class": "approval_exploitation",
            "chain": "ethereum",
        },
        "allbridge_oracle_pool": {
            "loss_usd": 570_000,
            "fork_block": 26_982_067,
            "fork_chain": "bsc",
            "exploit_date": "2023-04-01",
            "vuln_class": "oracle_manipulation",
            "chain": "bsc",
        },
    }

    # Vulnerability details from bridge_bench.py
    vuln_details = {
        "poly_network_eth_cross_chain_manager": [
            "unrestricted_cross_chain_call",
            "keeper_key_overwrite",
        ],
        "nomad_bridge_replica": [
            "zero_root_initialization",
            "default_value_exploit",
            "missing_upgrade_validation",
            "replay_attack",
            "arbitrary_external_call",
        ],
        "qubit_finance_bridge": [
            "zero_value_deposit",
            "missing_input_validation",
        ],
        "ronin_bridge_validator": [
            "low_validator_threshold",
            "no_anomaly_detection",
            "social_engineering_vector",
        ],
        "orbit_chain_multisig": [
            "multisig_key_compromise",
        ],
        "lifi_protocol_diamond_march_2022": [
            "arbitrary_external_call",
            "infinite_approval_drain",
        ],
        "socket_gateway_registry": [
            "approval_exploitation",
            "faulty_route_validation",
        ],
        "xbridge_approval_drain": [
            "approval_exploitation",
        ],
        "lifi_protocol_diamond_july_2024": [
            "arbitrary_external_call",
            "infinite_approval_drain",
            "recurring_vulnerability",
        ],
        "allbridge_oracle_pool": [
            "flash_loan_price_manipulation",
            "spot_price_dependency",
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
            # If not fetched yet, source will be None
            source_code = None

        # Build ground truth from vulnerability list
        vulnerabilities = []
        for vuln_key in vuln_details.get(contract_name, []):
            if vuln_key in VULNERABILITY_TAXONOMY:
                vulnerabilities.append(VULNERABILITY_TAXONOMY[vuln_key])

        # Determine overall risk (all are critical for real exploits)
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


def get_loaded_contracts() -> dict:
    """Get statistics on loaded real contracts."""
    contracts = load_real_contracts()

    loaded_count = sum(1 for c in contracts if c["source"] is not None)
    total_vuln = sum(len(c["ground_truth"]["vulnerabilities"]) for c in contracts)

    return {
        "total": len(contracts),
        "loaded": loaded_count,
        "not_loaded": len(contracts) - loaded_count,
        "total_vulnerabilities": total_vuln,
        "by_vuln_class": {
            "message_validation": sum(1 for c in contracts if c["metadata"]["exploit_class"] == "message_validation"),
            "input_validation": sum(1 for c in contracts if c["metadata"]["exploit_class"] == "input_validation"),
            "validator_governance": sum(1 for c in contracts if c["metadata"]["exploit_class"] == "validator_governance"),
            "approval_exploitation": sum(1 for c in contracts if c["metadata"]["exploit_class"] == "approval_exploitation"),
            "oracle_manipulation": sum(1 for c in contracts if c["metadata"]["exploit_class"] == "oracle_manipulation"),
        },
    }


if __name__ == "__main__":
    contracts = load_real_contracts()
    stats = get_loaded_contracts()

    print(f"Real Bridge Exploit Dataset")
    print(f"{'='*60}")
    print(f"Total contracts: {stats['total']}")
    print(f"Loaded from disk: {stats['loaded']}")
    print(f"Not yet fetched: {stats['not_loaded']}")
    print(f"\nTotal vulnerabilities: {stats['total_vulnerabilities']}")

    print(f"\nBy vulnerability class:")
    for vuln_class, count in stats["by_vuln_class"].items():
        print(f"  {vuln_class:<30} {count}")

    print(f"\n{'='*60}")
    print(f"To fetch contracts, run:")
    print(f"  export ETHERSCAN_API_KEY=<your_key>")
    print(f"  export BSCSCAN_API_KEY=<your_key>")
    print(f"  python3 fetch_contracts.py --all")
