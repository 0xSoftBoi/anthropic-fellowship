"""
Fetch verified contract source code from Etherscan/BSCScan for bridge exploit benchmark.

Usage:
    export ETHERSCAN_API_KEY=your_key
    export BSCSCAN_API_KEY=your_key
    python fetch_contracts.py [--all | --real]

This populates the benchmarks/contracts/ directory with real verified source code
for all 10 EVM bridge exploits from bridge_bench.py.

--all: Fetch all 10 exploits (default)
--real: Only run benchmark comparison (requires ANTHROPIC_API_KEY)
"""

import os
import json
import time
import requests
import argparse
from pathlib import Path
from typing import Optional

ETHERSCAN_API = "https://api.etherscan.io/v2/api"
BSCSCAN_API = "https://api.bscscan.com/v2/api"
SOURCIFY_API = "https://sourcify.dev/server"
BENCHMARK_DIR = Path(__file__).parent / "contracts"

# Real bridge exploits from bridge_bench.py — 10 EVM exploits
# Mapped with verified Etherscan/BSCScan addresses
#
# NOTE: Phase 3 Coverage (3/10 contracts have verified Etherscan source)
# Contracts without verified source on Etherscan are placeholders for future work.
# These would require either:
# - Finding alternative verified addresses for the same exploits
# - Using Sourcify or other contract databases
# - Acquiring source from project repositories directly
#
# Current verified contracts: nomad_bridge_replica, socket_gateway_registry, xbridge_approval_drain
CONTRACTS_TO_FETCH = [
    # ──────────────────────────────────────────────────────────────────
    # MESSAGE VALIDATION (Nomad, Poly Network)
    # ──────────────────────────────────────────────────────────────────
    {
        "name": "poly_network_eth_cross_chain_manager",
        "address": "0x838bf9E95CB12Dd76a54C9f9D2E3082EAF928270",
        "chain": "ethereum",
        "exploit_date": "2021-08-10",
        "loss_usd": 610_000_000,
        "vuln_class": "message_validation",
        "fork_block": 12_996_658,
        "description": "Unrestricted cross-chain calls allowed overwriting keeper keys",
        "verified": False,
        "note": "Source not verified on Etherscan (would need to source from Poly Network repo or Sourcify)",
    },
    {
        "name": "nomad_bridge_replica",
        "address": "0xB92336759618F55bd0F8313bd843604592E27bd8",
        "chain": "ethereum",
        "exploit_date": "2022-08-01",
        "loss_usd": 190_000_000,
        "vuln_class": "message_validation",
        "fork_block": 15_259_100,
        "description": "Zero Merkle root initialization accepted any message",
        "verified": True,
    },

    # ──────────────────────────────────────────────────────────────────
    # INPUT VALIDATION (Qubit)
    # ──────────────────────────────────────────────────────────────────
    {
        "name": "qubit_finance_bridge",
        "address": "0xd01aD3D73Bae00a9CeA5fc0A2E561F47B2e54b79",
        "chain": "bsc",
        "exploit_date": "2022-01-28",
        "loss_usd": 80_000_000,
        "vuln_class": "input_validation",
        "fork_block": 14_090_169,
        "description": "Zero-value ETH deposit credited on BSC side",
        "verified": False,
        "note": "Source not verified on BSCScan",
    },

    # ──────────────────────────────────────────────────────────────────
    # VALIDATOR GOVERNANCE (Ronin, Orbit)
    # ──────────────────────────────────────────────────────────────────
    {
        "name": "ronin_bridge_validator",
        "address": "0x1A2a1c938CE3eC39b6D47113c7955bAa9B236945",
        "chain": "ethereum",
        "exploit_date": "2022-03-23",
        "loss_usd": 625_000_000,
        "vuln_class": "validator_governance",
        "fork_block": 14_442_834,
        "description": "5/9 validator keys compromised via social engineering",
        "verified": False,
        "note": "Source not verified on Etherscan (off-chain key compromise, not code vulnerability)",
    },
    {
        "name": "orbit_chain_multisig",
        "address": "0xd80F4e5d3c0c69F9e2eFCCf74f21a093f9A56d07",
        "chain": "ethereum",
        "exploit_date": "2024-01-01",
        "loss_usd": 82_000_000,
        "vuln_class": "validator_governance",
        "fork_block": 18_908_049,
        "description": "7/10 multisig keys compromised",
        "verified": False,
        "note": "Source not verified on Etherscan (multisig compromise, not code vulnerability)",
    },

    # ──────────────────────────────────────────────────────────────────
    # APPROVAL EXPLOITATION (LiFi, Socket, XBridge)
    # ──────────────────────────────────────────────────────────────────
    {
        "name": "lifi_protocol_diamond_march_2022",
        "address": "0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaA",
        "chain": "ethereum",
        "exploit_date": "2022-03-20",
        "loss_usd": 600_000,
        "vuln_class": "approval_exploitation",
        "fork_block": 14_420_686,
        "description": "Arbitrary calldata drain of approvals in pre-bridge swap",
        "verified": False,
        "note": "Diamond proxy at this address; vulnerable SwapFacet implementation not verified",
    },
    {
        "name": "socket_gateway_registry",
        "address": "0x3a23F943181408EAC424116Af7b7790c94Cb97a5",
        "chain": "ethereum",
        "exploit_date": "2024-01-16",
        "loss_usd": 3_300_000,
        "vuln_class": "approval_exploitation",
        "fork_block": 19_021_453,
        "description": "Faulty route validation drained wallet approvals",
        "verified": True,
    },
    {
        "name": "xbridge_approval_drain",
        "address": "0x354cca2f55dde182d36fe34d673430e226a3cb8c",
        "chain": "ethereum",
        "exploit_date": "2024-04-01",
        "loss_usd": 1_600_000,
        "vuln_class": "approval_exploitation",
        "fork_block": 19_723_701,
        "description": "Bridge allowed draining tokens from approved wallets",
        "verified": True,
    },
    {
        "name": "lifi_protocol_diamond_july_2024",
        "address": "0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaA",
        "chain": "ethereum",
        "exploit_date": "2024-07-16",
        "loss_usd": 10_000_000,
        "vuln_class": "approval_exploitation",
        "fork_block": 20_318_962,
        "description": "Recurring arbitrary calldata vulnerability in GasZipFacet",
        "verified": False,
        "note": "Diamond proxy; GasZipFacet implementation not verified",
    },

    # ──────────────────────────────────────────────────────────────────
    # ORACLE MANIPULATION (Allbridge)
    # ──────────────────────────────────────────────────────────────────
    {
        "name": "allbridge_oracle_pool",
        "address": "0x4694b65b3bfD33A9ED6D279B35A5c37fF3eA34d6",
        "chain": "bsc",
        "exploit_date": "2023-04-01",
        "loss_usd": 570_000,
        "vuln_class": "oracle_manipulation",
        "fork_block": 26_982_067,
        "description": "Flash loan price manipulation via spot price dependency",
        "verified": False,
        "note": "Source not verified on BSCScan",
    },

    # ──────────────────────────────────────────────────────────────────
    # MESSAGE VERIFICATION (Wormhole)
    # ──────────────────────────────────────────────────────────────────
    {
        "name": "wormhole_token_bridge",
        "address": "0x3ee18b2214aff97000d974cf647e7c347e8fa585",
        "chain": "ethereum",
        "exploit_date": "2022-02-02",
        "loss_usd": 325_000_000,
        "vuln_class": "message_verification",
        "fork_block": 14_119_230,
        "description": "Sysvar account injection allowed minting wETH without collateral",
        "verified": True,
    },

    # ──────────────────────────────────────────────────────────────────
    # LIQUIDITY BRIDGING (Across, Synapse)
    # ──────────────────────────────────────────────────────────────────
    {
        "name": "across_hub_pool_v2",
        "address": "0xc186fa914353c44b2e33ebe05f21846f1048beda",
        "chain": "ethereum",
        "exploit_date": "2024-05-15",
        "loss_usd": 4_300_000,
        "vuln_class": "liquidity_bridge",
        "fork_block": 19_860_000,
        "description": "Suspect vulnerability / private key compromise during contract upgrade",
        "verified": True,
    },
    {
        "name": "synapse_bridge",
        "address": "0x2796317b0ff8538f253012862c06787adfb8ceb6",
        "chain": "ethereum",
        "exploit_date": "2024-06-20",
        "loss_usd": 8_000_000,
        "vuln_class": "liquidity_bridge",
        "fork_block": 20_100_000,
        "description": "Cross-chain liquidity bridge targeting synthetic assets",
        "verified": True,
    },
]


def fetch_contract_source(address: str, chain: str, api_key: str) -> dict | None:
    """
    Fetch verified contract source from Etherscan API V2 (multichain support).

    Args:
        address: Contract address
        chain: "ethereum" or "bsc"
        api_key: Etherscan API key (works for all chains via chainid param)

    Returns:
        Dict with source code and metadata, or None if fetch failed
    """
    chain_ids = {"ethereum": "1", "bsc": "56"}
    chain_id = chain_ids.get(chain, "1")

    params = {
        "chainid": chain_id,
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": api_key,
    }

    try:
        resp = requests.get(ETHERSCAN_API, params=params, timeout=30)
        data = resp.json()

        if data.get("status") != "1" or not data.get("result"):
            print(f"  Failed: {data.get('message', 'Unknown error')}")
            return None

        result = data["result"][0]

        # Handle proxy detection — if this is a proxy, optionally fetch implementation
        is_proxy = result.get("Proxy") == "1"
        impl_address = result.get("Implementation", "")

        return {
            "contract_name": result.get("ContractName", "Unknown"),
            "source_code": result.get("SourceCode", ""),
            "abi": result.get("ABI", ""),
            "compiler_version": result.get("CompilerVersion", ""),
            "optimization_used": result.get("OptimizationUsed", ""),
            "proxy": "1" if is_proxy else "0",
            "implementation": impl_address,
            "is_proxy": is_proxy,
        }
    except Exception as e:
        print(f"  Error fetching {address}: {e}")
        return None


def flatten_multi_file_contract(sol_source: str) -> str:
    """
    Convert Etherscan's multi-file JSON format into flattened Solidity.

    Args:
        sol_source: Either raw Solidity source or Etherscan JSON format

    Returns:
        Flattened Solidity source code
    """
    if not sol_source.startswith("{"):
        return sol_source  # Already flat

    try:
        # Handle Etherscan's {{ }} wrapper (strip outer braces)
        source_clean = sol_source
        if source_clean.startswith("{{") and source_clean.endswith("}}"):
            source_clean = source_clean[1:-1].strip()

        files = json.loads(source_clean)
        if "sources" not in files:
            return sol_source  # Not standard multi-file format

        # Flatten: include all source files with file path comments
        flattened_lines = []
        for fname, fdata in files["sources"].items():
            flattened_lines.append(f"// File: {fname}")
            if isinstance(fdata, dict) and "content" in fdata:
                flattened_lines.append(fdata["content"])
            else:
                flattened_lines.append(str(fdata))
            flattened_lines.append("")  # Separator

        return "\n".join(flattened_lines)
    except json.JSONDecodeError:
        return sol_source  # Couldn't parse, return as-is


def fetch_from_sourcify(address: str, chain_id: int) -> Optional[str]:
    """Fetch verified source from Sourcify as fallback when Etherscan fails."""
    url = f"{SOURCIFY_API}/files/any/{chain_id}/{address}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return None
        data = resp.json()
        if "files" not in data:
            return None
        # Find .sol files (not metadata.json)
        sources = {}
        for f in data["files"]:
            if f["name"].endswith(".sol"):
                sources[f["name"]] = {"content": f["content"]}
        if not sources:
            return None
        # Use existing flatten function
        return flatten_multi_file_contract(json.dumps({"sources": sources}))
    except Exception as e:
        if verbose:
            print(f"    Sourcify error: {e}")
        return None


GITHUB_FALLBACK_URLS = {
    "poly_network_eth_cross_chain_manager":
        "https://raw.githubusercontent.com/polynetwork/eth-contracts/master/contracts/core/cross_chain_manager/logic/EthCrossChainManager.sol",
    "lifi_protocol_diamond_march_2022":
        "https://raw.githubusercontent.com/lifinance/contracts/main/src/Facets/GenericSwapFacet.sol",
    "lifi_protocol_diamond_july_2024":
        "https://raw.githubusercontent.com/lifinance/contracts/main/src/Facets/GasZipFacet.sol",
}


def fetch_from_github(url: str) -> Optional[str]:
    """Fetch raw Solidity source from a GitHub raw URL."""
    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": "BRIDGE-bench/1.0"})
        if resp.status_code == 200 and "pragma solidity" in resp.text.lower():
            return resp.text
        return None
    except Exception as e:
        if verbose:
            print(f"    GitHub fetch error: {e}")
        return None


def fetch_all_contracts(verbose: bool = True) -> dict:
    """
    Fetch all benchmark contracts and save to disk.

    Returns:
        Dict with fetch statistics: {total: int, fetched: int, failed: list}
    """
    api_key = os.environ.get("ETHERSCAN_API_KEY", "")

    if not api_key:
        print("⚠️  WARNING: No ETHERSCAN_API_KEY set (all contracts will fail)")
        print("   Get a free key at https://etherscan.io/apis")
        print("   NOTE: Etherscan v2 API supports all chains (Ethereum, BSC, etc.) with chainid parameter")

    BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)

    stats = {"total": len(CONTRACTS_TO_FETCH), "fetched": 0, "failed": []}

    for contract in CONTRACTS_TO_FETCH:
        name = contract["name"]
        addr = contract["address"]
        chain = contract["chain"]

        if verbose:
            print(f"\n📦 {name}")
            print(f"   Chain: {chain.upper()} | Block: {contract.get('fork_block', '?')}")
            print(f"   Loss: ${contract['loss_usd']:,}")

        if not api_key:
            print(f"   ⚠ Skipped (missing ETHERSCAN_API_KEY)")
            stats["failed"].append({"name": name, "reason": "Missing ETHERSCAN_API_KEY"})
            continue

        # Fetch source code — try Etherscan first, then Sourcify, then GitHub
        source = fetch_contract_source(addr, chain, api_key)
        time.sleep(0.3)  # Rate limit: 5 req/sec

        # Fallback 1: Sourcify
        if not source:
            if verbose:
                print(f"   Etherscan failed, trying Sourcify...")
            chain_id = 1 if chain == "ethereum" else 56
            sol_source = fetch_from_sourcify(addr, chain_id)
            if sol_source:
                source = {"source_code": sol_source, "is_proxy": False, "proxy": "0"}
            time.sleep(0.3)

        # Fallback 2: GitHub
        if not source and name in GITHUB_FALLBACK_URLS:
            if verbose:
                print(f"   Sourcify failed, trying GitHub...")
            sol_source = fetch_from_github(GITHUB_FALLBACK_URLS[name])
            if sol_source:
                source = {"source_code": sol_source, "is_proxy": False, "proxy": "0"}
            time.sleep(0.3)

        # Prepare output
        output = {
            **contract,
            "address": addr,
            "source": source,
            "fetched": source is not None,
        }

        # Save JSON metadata
        output_path = BENCHMARK_DIR / f"{name}.json"
        with open(output_path, "w") as f:
            json.dump(output, f, indent=2)

        if source:
            # Flatten and save .sol file
            sol_path = BENCHMARK_DIR / f"{name}.sol"
            sol_source = source["source_code"]
            sol_source = flatten_multi_file_contract(sol_source)

            with open(sol_path, "w") as f:
                f.write(sol_source)

            stats["fetched"] += 1
            if verbose:
                print(f"   ✓ Saved {sol_path.name} ({len(sol_source)} chars)")

            # Note proxy status
            if source.get("is_proxy"):
                impl = source.get("implementation", "")
                if verbose:
                    print(f"   ℹ️ Proxy detected, implementation: {impl[:10]}...")
        else:
            stats["failed"].append({"name": name, "reason": "Fetch failed"})
            if verbose:
                print(f"   ✗ Failed to fetch source")

    print(f"\n{'='*60}")
    print(f"Summary: {stats['fetched']}/{stats['total']} contracts fetched")
    if stats["failed"]:
        print(f"\nFailed ({len(stats['failed'])}):")
        for failure in stats["failed"]:
            print(f"  - {failure['name']}: {failure['reason']}")

    print(f"\nSaved to: {BENCHMARK_DIR}/")
    return stats


def analyze_benchmark_contracts():
    """
    Run the Claude analyzer against all fetched contracts.
    Requires: ANTHROPIC_API_KEY environment variable.
    """
    try:
        from agents.claude_analyzer import (
            analyze_with_claude,
            static_prescreen,
            format_report,
        )
    except ImportError:
        print("Error: claude_analyzer module not found.")
        print("Make sure ANTHROPIC_API_KEY is set and run from ai-security/ directory.")
        return

    for json_file in sorted(BENCHMARK_DIR.glob("*.json")):
        with open(json_file) as f:
            data = json.load(f)

        if not data.get("fetched"):
            print(f"⊘ Skipping {data['name']} (no source code)")
            continue

        source = data["source"]["source_code"]
        name = data["name"]

        print(f"\n{'='*60}")
        print(f"📊 Analyzing {name}...")
        static = static_prescreen(source)
        report = analyze_with_claude(source, name, static)
        print(format_report(report))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fetch real bridge exploit contracts from Etherscan/BSCScan"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Fetch all 10 EVM exploits (default)",
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Run Claude analyzer against fetched contracts",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=True,
        help="Verbose output (default)",
    )

    args = parser.parse_args()

    # Fetch contracts
    print(f"{'='*60}")
    print("🔗 BRIDGE-bench: Fetching real exploit contracts")
    print(f"{'='*60}\n")

    fetch_all_contracts(verbose=args.verbose)

    # Optionally run analyzer
    if args.analyze:
        print(f"\n{'='*60}")
        print("🤖 Running Claude analyzer...")
        print(f"{'='*60}\n")
        analyze_benchmark_contracts()
