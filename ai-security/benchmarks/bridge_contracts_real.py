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
    # ── 2026 additions (CrossCurve, Hyperbridge) ──
    "missing_gateway_origin_check": {
        "type": "missing_gateway_origin_check",
        "severity": "critical",
        "description": "Cross-chain message handler never verified the message came from the bridge gateway",
    },
    "unauthenticated_message_handler": {
        "type": "unauthenticated_message_handler",
        "severity": "critical",
        "description": "Permissionless entrypoint reached privileged execution without authenticating the caller/source",
    },
    "forged_cross_chain_message": {
        "type": "forged_cross_chain_message",
        "severity": "critical",
        "description": "Spoofed cross-chain payload accepted as legitimate, unlocking/minting unbacked assets",
    },
    "mmr_missing_bounds_check": {
        "type": "mmr_missing_bounds_check",
        "severity": "critical",
        "description": "Merkle Mountain Range proof verification lacked a bounds check, allowing forged leaves",
    },
    "unbounded_mint_authority": {
        "type": "unbounded_mint_authority",
        "severity": "critical",
        "description": "Governance/admin path could reassign mint authority over bridged assets without strong origin checks",
    },
    # ── 2024-2025 DeFi additions (Penpie, Seneca, Prisma, Sonne, Dough, Abracadabra) ──
    "reentrancy": {
        "type": "reentrancy",
        "severity": "critical",
        "description": "External call made before state finalized, allowing re-entrant calls to manipulate accounting",
    },
    "untrusted_external_call": {
        "type": "untrusted_external_call",
        "severity": "critical",
        "description": "Call into attacker-controlled contract during a sensitive flow (e.g. permissionless-registered token)",
    },
    "unvalidated_callback": {
        "type": "unvalidated_callback",
        "severity": "critical",
        "description": "Flashloan/swap callback executed attacker-supplied parameters without validation",
    },
    "exchange_rate_manipulation": {
        "type": "exchange_rate_manipulation",
        "severity": "critical",
        "description": "Empty/low-supply lending market exchange rate manipulated via direct donation",
    },
    "rounding_error": {
        "type": "rounding_error",
        "severity": "high",
        "description": "Precision/rounding in redeem or share math let attacker extract more than deposited",
    },
    "empty_market_donation": {
        "type": "empty_market_donation",
        "severity": "high",
        "description": "First-depositor/donation attack on a freshly created market with no supply guard",
    },
    "missing_solvency_check": {
        "type": "missing_solvency_check",
        "severity": "critical",
        "description": "Solvency/collateralization check skipped on a borrow path, enabling undercollateralized debt",
    },
    "state_flag_reset": {
        "type": "state_flag_reset",
        "severity": "critical",
        "description": "A security flag (e.g. needsSolvencyCheck) reset by a later action, bypassing an end-of-call check",
    },
    "logic_error": {
        "type": "logic_error",
        "severity": "high",
        "description": "Control-flow/logic flaw in a multi-action dispatcher leading to skipped validation",
    },
    # ── bridge aggregator / router additions (THORChain, Rubic) ──
    "event_spoofing": {
        "type": "event_spoofing",
        "severity": "critical",
        "description": "Off-chain observer trusts an on-chain event/memo an attacker can forge to trigger a payout",
    },
    "improper_whitelist": {
        "type": "improper_whitelist",
        "severity": "critical",
        "description": "Router whitelist included token contracts, so an arbitrary call could invoke transferFrom",
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
        # ── 2026 additions: real verified source committed (Blockscout), source-detectable ──
        "crosscurve_receiveraxelar": {
            "loss_usd": 3_000_000,
            "fork_block": 0,  # exploit tx 0x37d9b911...; pre-attack fork block TBD
            "fork_chain": "mainnet",
            "exploit_date": "2026-01-31",
            "vuln_class": "message_validation",
            "chain": "ethereum",
            "address": "0xB2185950F5A0A46687ac331916508aadA202e063",
        },
        "hyperbridge_tokengateway": {
            "loss_usd": 2_500_000,
            "fork_block": 0,  # exploit 2026-04-13 03:55 UTC; pre-attack fork block TBD
            "fork_chain": "mainnet",
            "exploit_date": "2026-04-13",
            "vuln_class": "proof_verification",
            "chain": "ethereum",
            "address": "0xFd413e3AFe560182C4471F4d143A96d3e259B6dE",
        },
        # ── 2024-2025 DeFi exploits: real verified source committed (Blockscout) ──
        "penpie_pendlestaking": {
            "loss_usd": 27_000_000,
            "fork_block": 0,
            "fork_chain": "mainnet",
            "exploit_date": "2024-09-03",
            "vuln_class": "reentrancy",
            "chain": "ethereum",
            "address": "0x86A499D84E355D2Cb41851d91425c86Eb2758627",
        },
        "seneca_chamber": {
            "loss_usd": 6_400_000,
            "fork_block": 0,
            "fork_chain": "mainnet",
            "exploit_date": "2024-02-28",
            "vuln_class": "arbitrary_external_call",
            "chain": "ethereum",
            "address": "0x45e15d1e4F92f28A916F4f2971Ad9adc278e148B",
        },
        "prisma_migratetrovezap": {
            "loss_usd": 11_600_000,
            "fork_block": 0,
            "fork_chain": "mainnet",
            "exploit_date": "2024-03-28",
            "vuln_class": "input_validation",
            "chain": "ethereum",
            "address": "0xcC7218100da61441905e0c327749972e3CBee9EE",
        },
        "sonne_soVELO_cerc20": {
            "loss_usd": 20_000_000,
            "fork_block": 0,
            "fork_chain": "optimism",
            "exploit_date": "2024-05-15",
            "vuln_class": "exchange_rate_manipulation",
            "chain": "optimism",
            "address": "0xe3b81318B1b6776F0877c3770AfDdFf97b9f5fE5",
        },
        "dough_connector_paraswap": {
            "loss_usd": 2_000_000,
            "fork_block": 0,
            "fork_chain": "mainnet",
            "exploit_date": "2024-07-12",
            "vuln_class": "arbitrary_external_call",
            "chain": "ethereum",
            "address": "0x9f54e8eAa9658316Bb8006E03FFF1cb191AafBE6",
        },
        "abracadabra_cauldronv4": {
            "loss_usd": 1_800_000,
            "fork_block": 0,
            "fork_chain": "mainnet",
            "exploit_date": "2025-10-04",
            "vuln_class": "logic_error",
            "chain": "ethereum",
            "address": "0x5E70F7AcB8ec0231c00220d11c74dC2B23187103",
        },
        # ── bridge router/aggregator exploits: verified source committed (Blockscout) ──
        "thorchain_router": {
            "loss_usd": 8_000_000,
            "fork_block": 0,
            "fork_chain": "mainnet",
            "exploit_date": "2021-07-23",
            "vuln_class": "message_validation",
            "chain": "ethereum",
            "address": "0xC145990E84155416144C532E31f89B840Ca8c2cE",
        },
        "rubic_proxy": {
            "loss_usd": 1_400_000,
            "fork_block": 0,
            "fork_chain": "mainnet",
            "exploit_date": "2022-12-25",
            "vuln_class": "approval_exploitation",
            "chain": "ethereum",
            "address": "0x3332241a5a4eCb4c28239A9731ad45De7f000333",
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
        "crosscurve_receiveraxelar": [
            "missing_gateway_origin_check",
            "unauthenticated_message_handler",
            "forged_cross_chain_message",
        ],
        "hyperbridge_tokengateway": [
            "mmr_missing_bounds_check",
            "unbounded_mint_authority",
            "forged_cross_chain_message",
        ],
        "penpie_pendlestaking": [
            "reentrancy",
            "untrusted_external_call",
        ],
        "seneca_chamber": [
            "arbitrary_external_call",
            "missing_input_validation",
        ],
        "prisma_migratetrovezap": [
            "unvalidated_callback",
            "missing_input_validation",
        ],
        "sonne_soVELO_cerc20": [
            "exchange_rate_manipulation",
            "rounding_error",
            "empty_market_donation",
        ],
        "dough_connector_paraswap": [
            "arbitrary_external_call",
            "unvalidated_callback",
            "missing_input_validation",
        ],
        "abracadabra_cauldronv4": [
            "missing_solvency_check",
            "state_flag_reset",
            "logic_error",
        ],
        "thorchain_router": [
            "event_spoofing",
            "arbitrary_external_call",
            "reentrancy",
        ],
        "rubic_proxy": [
            "improper_whitelist",
            "arbitrary_external_call",
            "approval_exploitation",
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
            if not source_code.strip():
                # File exists but is empty — the source was never fetched. The
                # contract still gets "analyzed" (on an empty string) and scored as
                # all-misses, which silently degrades the benchmark. Warn loudly.
                import sys
                print(f"[bench] WARNING: {contract_name}.sol is empty — no source to "
                      f"analyze; its score is not meaningful.", file=sys.stderr)
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
