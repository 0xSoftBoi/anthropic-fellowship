"""
Suwappu external-dependency registry: the real contracts the product depends on,
organised, labelled, and prioritised for a memorization-controlled negative-control run.

WHY THIS EXISTS
---------------
The user's instruction was precise: *before* spending on a paid model run, organise and
prioritise the right contracts, with variety, and — critically — **only contracts that have
not been hacked**, focused on the ones Suwappu actually uses (per www.suwappu.bot/docs and the
suwappubot repo). This module is that curated dataset.

It supersedes the thin `EXTERNAL_DEPENDENCIES` list previously in `live_contracts.py`.

HOW IT WAS BUILT
----------------
1. Mined the suwappubot repo (docs/ + gitbook/ + bot/ + api-ts/ code) for every external
   contract the product quotes/calls/settles against — 83 raw integration entries across
   swap, lending, oracle, bridge, streaming, accounts, tokens, perps, prediction.
2. Classified each by category and by *exploit history*, then applied the hard filter:
   drop anything with a protocol- or contract-level hack, or a disclosed critical drain vuln.
3. **Independently re-verified exploit history against 2025-2026 incident reporting** — this
   matters because "unexploited" decays over time. That check moved two contracts OUT of the
   clean set that a static reading would have kept:
     - **Across Protocol** — hacked ~17 Jul 2026 (~$3.6M on its Solana deployment). Excluded.
     - **Coinbase SpendPermissionManager** — disclosed drain vuln (ERC-6492 × ownerIndex lets
       an attacker rewrite the owner and drain a Smart Wallet). Excluded from the clean set.
   (This is the negative-control analogue of the memorization thesis: the "clean" label on a
   real contract is time-stamped, not permanent. Re-verify before every run.)
4. Verified concrete on-chain addresses / verified-source availability via Blockscout for the
   less-canonical picks (e.g. MorphoChainlinkOracleV2 and the Steakhouse MetaMorpho vault on
   Base both return is_verified=True).

TIERS
-----
- `clean`    : EVM, concrete verified address, NO known contract exploit or disclosed critical
               vuln. The core negative-control targets.
- `anchor`   : clean, but HIGH training-data exposure (Aave/Uniswap/USDC/EntryPoint). Kept
               deliberately as memorization/recall baselines to contrast against low-exposure
               controls — NOT thrown away, but flagged.
- `caveat`   : EVM concrete verified address, the *contract* was not exploited, but the protocol
               or a sibling vault had a real incident/loss/depeg. Usable, but the note travels
               with it.
- `excluded` : in-use but hacked, or carrying a disclosed critical vuln. Dropped per the
               unhacked-only rule; recorded here so the exclusion is auditable.
- `deferred` : in-use and unhacked, but non-EVM (Solana/Starknet/HyperCore) or no verified
               Solidity source (obscure-L2 Uniswap forks) — out of scope for a Solidity
               source-detection run until source is confirmed fetchable.

GROUND-TRUTH NOTE
-----------------
Like `live_contracts.py`, everything in the `clean`/`anchor`/`caveat` tiers is a **negative
control**: the honest label is "no known critical source bug," ground_truth.vulnerabilities is
empty, and the question is specificity (does the model over-flag hardened, unfamiliar, real
code?). A finding is a *screen*, adjudicated by the source-aware judge — not an automatic false
positive. Addresses/exploit-history verified as of 2026-08; RE-VERIFY before any run.
"""

# Each entry: protocol, contract_name, address, chain, category, tier, uses,
# in_use_evidence (repo path), exploit_history, memorization_exposure, notes.
DEPENDENCIES = [
    # ── clean negative controls (EVM, verified, no known exploit) ────────────
    {
        "protocol": "Morpho", "contract_name": "MorphoChainlinkOracleV2",
        "address": "0x663BECd10daE6C4A3Dcd89F1d76c1174199639B9", "chain": "base",
        "category": "oracle", "tier": "clean",
        "uses": "the one genuine on-chain oracle Suwappu reads — price() for health-factor / LTV math on /save",
        "in_use_evidence": "bot lend service; MARKET_ID asserted via keccak(MarketParams)",
        "exploit_history": "no known contract exploit (Morpho oracle wrappers); Morpho Blue core has withstood audits",
        "memorization_exposure": "low",
        "notes": "Blockscout Base: is_contract=True, is_verified=True, name=MorphoChainlinkOracleV2. Strongest oracle-category control.",
    },
    {
        "protocol": "Circle CCTP v2", "contract_name": "TokenMessengerV2",
        "address": "0x28b5a0e9C621a5BadaA536219b3a228C8168cf5d", "chain": "base",
        "category": "bridge", "tier": "clean",
        "uses": "default native-USDC bridge rail (burn/mint cross-chain); same canonical address across V2 EVM chains",
        "in_use_evidence": "bridge rails runbook; CCTP v2 default USDC path",
        "exploit_history": "no production CCTP V1/V2 contract exploit (a 2024 Noble/Cosmos handler bug was found & fixed, no funds lost)",
        "memorization_exposure": "low",
        "notes": "Low exposure (V2 is newer). Single address on ethereum/base/arbitrum/optimism/polygon/avalanche.",
    },
    {
        "protocol": "Gnosis / Polymarket", "contract_name": "ConditionalTokens (CTF)",
        "address": "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045", "chain": "polygon",
        "category": "prediction_market", "tier": "clean",
        "uses": "prediction-market settlement framework Suwappu calls (redeemPositions / payoutDenominator)",
        "in_use_evidence": "bot polymarket service (predict)",
        "exploit_history": "no contract hack (2019-era Gnosis CTF; Polymarket's 2025-26 incidents were a leaked key, a frontend supply-chain attack, and an auth bug — not the CTF contract)",
        "memorization_exposure": "medium",
        "notes": "The real, battle-tested framework under Polymarket. Sidesteps the fabricated CTF-exchange address in the repo (see DATA-QUALITY notes).",
    },
    {
        "protocol": "Polymarket", "contract_name": "NegRiskAdapter",
        "address": "0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296", "chain": "polygon",
        "category": "prediction_market", "tier": "clean",
        "uses": "neg-risk (multi-outcome) redemption adapter for Polymarket markets",
        "in_use_evidence": "bot polymarket service; distinct redeem signature",
        "exploit_history": "no contract hack (see Gnosis CTF note)",
        "memorization_exposure": "medium",
        "notes": "PolygonScan-confirmed. Second prediction-category control (distinct code path).",
    },

    # ── anchors (clean, but HIGH memorization exposure) ──────────────────────
    {
        "protocol": "Aave v3", "contract_name": "Pool (Base)",
        "address": "0xA238Dd80C259a72e81d7e4664a9801593F98d1c5", "chain": "base",
        "category": "lending", "tier": "anchor",
        "uses": "canonical lending pool called for /save deposits",
        "in_use_evidence": "bot lend service",
        "exploit_history": "Aave v3 CORE never hacked; 2026 incidents hit misconfigured FORKS (dTRINITY) and rsETH collateral via KelpDAO's LayerZero bridge, not Aave's contracts",
        "memorization_exposure": "high",
        "notes": "High-exposure recall anchor; contrast against low-exposure controls.",
    },
    {
        "protocol": "Uniswap v3", "contract_name": "NonfungiblePositionManager (Base)",
        "address": "0x03a520b32C04BF3bEEf7BEb72E919cf822Ed34f1", "chain": "base",
        "category": "dex_amm", "tier": "anchor",
        "uses": "LP-NFT position manager — the external dependency SuwppuBonds accepts LP NFTs from",
        "in_use_evidence": "contracts/SuwppuBonds.sol (positionManager.positions)",
        "exploit_history": "Uniswap v3 core never hacked",
        "memorization_exposure": "high",
        "notes": "Correct Base NPM ends ...Ed34f1 (Blockscout: 'Uniswap V3: Nonfungible Position Manager', verified). The repo README truncates it to 41 chars; the naive fill ...Ed34f4 is an unrelated EOA. Most-memorized dex_amm — recall baseline.",
    },
    {
        "protocol": "Circle", "contract_name": "USDC (Base)",
        "address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "chain": "base",
        "category": "stablecoin_token", "tier": "anchor",
        "uses": "primary settlement stablecoin / underlying",
        "in_use_evidence": "tokens config; settlement across services",
        "exploit_history": "no USDC contract exploit",
        "memorization_exposure": "high",
        "notes": "Top token-category recall anchor.",
    },
    {
        "protocol": "ERC-4337", "contract_name": "EntryPoint v0.7",
        "address": "0x0000000071727De22E5E9d8BAf0edAc6f37da032", "chain": "all-evm",
        "category": "account_abstraction", "tier": "anchor",
        "uses": "canonical AA singleton used for smart-account address prediction / userop flow",
        "in_use_evidence": "smart-accounts docs; AA wallet path",
        "exploit_history": "canonical audited singleton, no core exploit (2026 'ERC-4337 mistakes' writeups target account IMPLEMENTATIONS, not the EntryPoint)",
        "memorization_exposure": "high",
        "notes": "Deterministic singleton, same address on every EVM chain. AA recall anchor.",
    },

    # ── caveat (contract not exploited, but a real protocol/vault incident) ───
    {
        "protocol": "Ethena", "contract_name": "USDe",
        "address": "0x4c9EDD5852cd905f086C759E8383e09bff1E68B3", "chain": "ethereum",
        "category": "stablecoin_token", "tier": "caveat",
        "uses": "settlement/hold token",
        "in_use_evidence": "tokens config",
        "exploit_history": "no contract exploit — but USDe depegged to ~$0.65 on Binance (Oct 2025); that was exchange-side price manipulation, on-chain redemptions held at $1",
        "memorization_exposure": "medium",
        "notes": "Include with the depeg note attached.",
    },
    {
        "protocol": "MetaMorpho", "contract_name": "Steakhouse USDC vault (ERC-4626)",
        "address": "0xbeeF010f9cb27031ad51e3333f9aF9C6B1228183", "chain": "base",
        "category": "lending", "tier": "caveat",
        "uses": "default earn/yield vault for idle USDC",
        "in_use_evidence": "bot lend service (earn)",
        "exploit_history": "no contract exploit of THIS vault — but the MetaMorpho vault class saw an ~$18M market-driven loss (msY collapse, Jun 2026) and KelpDAO-exploit contagion; risk is collateral/curation, not a contract bug",
        "memorization_exposure": "medium",
        "notes": "Blockscout Base: is_verified=True, tagged MetaMorpho/Morpho. Lower-exposure lending control than Aave.",
    },
    {
        "protocol": "Superfluid", "contract_name": "GDAv1Forwarder",
        "address": "0x6DA13Bde224A05a288748d857b9e7DDEffd1dE08", "chain": "base",
        "category": "streaming", "tier": "caveat",
        "uses": "real-yield streaming Suwappu staking calls (createPool / distributeFlow)",
        "in_use_evidence": "contracts/SuwppuStaking.sol; DEPLOYMENTS.md (canonical GDA 0x6DA13Bde...)",
        "exploit_history": "GDA forwarder path not exploited — but the Superfluid Host suffered a Feb 2022 ctx-spoofing exploit (~$13M, mostly recovered); Base Host instance is post-fix",
        "memorization_exposure": "medium",
        "notes": "The Superfluid HOST contract (0x4C073B...) is in the excluded tier; the GDA forwarder Suwappu actually calls is kept here with the protocol-history caveat.",
    },
    {
        "protocol": "CoW Protocol", "contract_name": "GPv2Settlement",
        "address": "0x9008D19f58AAbD9eD0D60971565AA8510560ab41", "chain": "multi-evm",
        "category": "swap_aggregator", "tier": "caveat",
        "uses": "MEV-protected batch-auction swap settlement (raced provider); the one swap integration with a HARDCODED canonical address",
        "in_use_evidence": "bot/services/cow_api.py (COW_SETTLEMENT_ADDRESSES; Vault Relayer 0xC92E8bdf79f0507f65a392b0ab4667716BFE0110)",
        "exploit_history": "core settlement logic not broken — but a Feb 2023 incident let a malicious solver drain ~$166k of funds temporarily held in the settlement contract",
        "memorization_exposure": "high",
        "notes": "Same address on ethereum/arbitrum/base/gnosis. Every other swap aggregator (LiFi/0x/1inch/OKX/Kyber) uses a per-quote dynamic address — this is the exception with a fixed on-chain target.",
    },

    # ── excluded: in-use but hacked or carrying a disclosed critical vuln ─────
    {
        "protocol": "Across Protocol", "contract_name": "SpokePool V2 (Ethereum)",
        "address": "0x5c7BCd6E7De5423a257D81B442095A1a6ced35C5", "chain": "ethereum",
        "category": "bridge", "tier": "excluded",
        "uses": "canonical bridge rail (wired/enabled in the SDK)",
        "in_use_evidence": "bridge rails; Across SpokePool addresses",
        "exploit_history": "HACKED ~17 Jul 2026 (~$3.6M on the Solana deployment; relayer funds, Risk Labs; partial 331.8 ETH refund 28 Jul 2026)",
        "memorization_exposure": "high",
        "notes": "Was 'clean' in the extraction; re-verification moved it here. Live example that unexploited decays.",
    },
    {
        "protocol": "Coinbase", "contract_name": "SpendPermissionManager",
        "address": "0xf85210B21cC50302F477BA56686d2019dC9b67Ad", "chain": "base",
        "category": "account_abstraction", "tier": "excluded",
        "uses": "delegated-spend permissions for agent/smart wallets",
        "in_use_evidence": "smart-accounts / spend-permission flow",
        "exploit_history": "disclosed critical drain vuln: ERC-6492 × ownerIndex interaction (ownerIndex not in the signed message) lets an attacker rewrite the owner and drain a Coinbase Smart Wallet",
        "memorization_exposure": "medium",
        "notes": "A disclosed drain vector disqualifies it as a clean negative control; recorded for auditability.",
    },
    {"protocol": "Li.Fi", "contract_name": "LiFiDiamond", "address": "dynamic (per-quote tx.to)",
     "chain": "multi-evm", "category": "swap_aggregator", "tier": "excluded",
     "uses": "THE EVM swap path in the public SDK (quote/swap/execute)", "in_use_evidence": "bot/services/lifi_api.py; api-ts SwapService",
     "exploit_history": "HACKED twice: Mar 2022 (~$600k, arbitrary-calldata swap facet) and Jul 2024 (~$10M+, infinite-approval facet)",
     "memorization_exposure": "high", "notes": "Highest in-use swap integration but excluded per unhacked rule."},
    {"protocol": "KyberSwap", "contract_name": "MetaAggregationRouter", "address": "dynamic (per-quote routerAddress)",
     "chain": "multi-evm", "category": "swap_aggregator", "tier": "excluded",
     "uses": "raced swap quote provider", "in_use_evidence": "bot/services/kyberswap_api.py",
     "exploit_history": "KyberSwap Elastic pools drained ~$48M (Nov 2023); protocol-level hack (the aggregator router itself was not the exploited contract)",
     "memorization_exposure": "high", "notes": "Excluded at protocol level for honesty."},
    {"protocol": "OKX DEX", "contract_name": "DexRouter", "address": "dynamic (per-quote)",
     "chain": "multi", "category": "swap_aggregator", "tier": "excluded",
     "uses": "raced multi-chain swap provider", "in_use_evidence": "bot/services/okx_dex_api.py",
     "exploit_history": "proxy-admin compromise (~Dec 2023) enabled a malicious upgrade that drained ~$2.7M from approvers",
     "memorization_exposure": "medium", "notes": ""},
    {"protocol": "Socket / Bungee", "contract_name": "SocketGateway", "address": "dynamic",
     "chain": "multi-evm", "category": "bridge", "tier": "excluded",
     "uses": "bridge/route aggregation", "in_use_evidence": "bridge rails",
     "exploit_history": "SocketGateway exploited ~16 Jan 2024 (~$3.3M via route/approval handling; partially white-hat recovered)",
     "memorization_exposure": "medium", "notes": ""},
    {"protocol": "Wormhole / Portal", "contract_name": "Token Bridge", "address": "chain-specific",
     "chain": "multi", "category": "bridge", "tier": "excluded",
     "uses": "Solana<->EVM bridging", "in_use_evidence": "bridge rails",
     "exploit_history": "Feb 2022 Solana Token Bridge forged-VAA exploit minted 120k wETH (~$326M)",
     "memorization_exposure": "high", "notes": "Already appears as an exploit-domain example elsewhere."},
    {"protocol": "Allbridge Core", "contract_name": "pool", "address": "chain-specific",
     "chain": "multi", "category": "bridge", "tier": "excluded",
     "uses": "bridge rail (default-off but wired)", "in_use_evidence": "bridge rails",
     "exploit_history": "Apr 2023 BSC pool flash-loan / price-manipulation (~$570k)",
     "memorization_exposure": "medium", "notes": ""},
    {"protocol": "Superfluid", "contract_name": "Host (Superfluid)", "address": "0x4C073B3baB862572842bFB01F7B1FA40B61D1A06",
     "chain": "base", "category": "streaming", "tier": "excluded",
     "uses": "Superfluid protocol host (agreement dispatch)", "in_use_evidence": "Superfluid integration",
     "exploit_history": "Feb 2022 ctx-spoofing callAgreement exploit (~$13M, mostly recovered)",
     "memorization_exposure": "medium", "notes": "The GDAv1Forwarder path Suwappu calls is kept (caveat); the Host contract itself is excluded."},
    {"protocol": "ParaSwap", "contract_name": "AugustusV6", "address": "dynamic",
     "chain": "multi-evm", "category": "swap_aggregator", "tier": "excluded",
     "uses": "not a direct dep (only an internal Socket sub-route)", "in_use_evidence": "via Socket",
     "exploit_history": "AugustusV6 vuln disclosed 2024 (white-hat rescue, limited loss); not a direct dependency",
     "memorization_exposure": "medium", "notes": "Excluded on both counts (disclosed vuln + not directly used)."},

    # ── deferred: in-use, unhacked, but non-EVM or no verified Solidity source ─
    {"protocol": "Jupiter", "contract_name": "Aggregator program", "address": "Solana program (server-built tx)",
     "chain": "solana", "category": "swap_aggregator", "tier": "deferred",
     "uses": "Solana swap execution", "in_use_evidence": "bot/services/jupiter_api.py",
     "exploit_history": "no known compromise of the aggregator program",
     "memorization_exposure": "high", "notes": "Non-EVM; no Solidity source to analyze."},
    {"protocol": "Hyperliquid", "contract_name": "HLP Vault", "address": "0xdfc24b077bc1425ad1dea75bcb6f8158e10df303",
     "chain": "hyperliquid-hypercore", "category": "perps", "tier": "deferred",
     "uses": "perps liquidity vault (deposit/withdraw)", "in_use_evidence": "docs/features/hyperliquid.md",
     "exploit_history": "no contract exploit (the JELLY event was market manipulation)",
     "memorization_exposure": "medium", "notes": "HyperCore L1, not standard EVM verified source. Only perps candidate."},
    {"protocol": "AVNU", "contract_name": "AVNU Exchange", "address": "0x04270219d365d6b017231b52e92b3fb5d7c8378b05e9abc97724537a80e93b0f",
     "chain": "starknet", "category": "swap_aggregator", "tier": "deferred",
     "uses": "Starknet DEX aggregation", "in_use_evidence": "starknet swap path",
     "exploit_history": "no known exploit", "memorization_exposure": "low",
     "notes": "Cairo/Starknet, not Solidity — out of scope for a Solidity run, but a low-exposure diversifier if the harness gains Cairo."},
    {"protocol": "GOATSwap", "contract_name": "SwapRouter02 (Uniswap v3 fork)", "address": "0x0d230A6A3E49301F0Ef9663982a529412EAAFAf4",
     "chain": "goat", "category": "dex_amm", "tier": "deferred",
     "uses": "GOAT-network-only swaps", "in_use_evidence": "chain swap config",
     "exploit_history": "no known exploit", "memorization_exposure": "low",
     "notes": "Verified source availability on GOAT explorer unconfirmed — confirm before fetch. Low-exposure dex_amm if source resolves."},
    {"protocol": "JuiceSwap", "contract_name": "SwapRouter (Uniswap v3 fork)", "address": "0x565eD3D57fe40f78A46f348C220121AE093c3cF8",
     "chain": "citrea", "category": "dex_amm", "tier": "deferred",
     "uses": "Citrea (Bitcoin L2) swaps", "in_use_evidence": "chain swap config",
     "exploit_history": "no known exploit", "memorization_exposure": "low",
     "notes": "Verified source on Citrea explorer unconfirmed. Very low exposure."},
]

# Data-quality issues found in the suwappubot repo while building this (worth fixing there).
REPO_DATA_QUALITY_NOTES = [
    "Polymarket CTF Exchange 0xE111180000d2663C0091e4f400237545B87B996B appears FABRICATED "
    "(a repo test asserts it is NOT the real exchange); the real signing exchange is "
    "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E. The prior EXTERNAL_DEPENDENCIES list carried "
    "the fabricated one — dropped here; use the real Gnosis CTF + NegRiskAdapter instead.",
    "Polymarket 'pUSD' collateral 0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB is actually "
    "MakerDAO DAI, mislabeled (claimed 6dp/Polygon; real DAI is 18dp/Ethereum). Real Polymarket "
    "collateral is USDC.e 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174.",
    "Python config DAI (bot/config/tokens.py) does not match canonical DAI "
    "0x6B175474E89094C44Da98b954EedeAC495271d0F used in api-ts TokenService.ts.",
    "Foundry DeployTestnet.s.sol hardcodes stale Superfluid values differing from "
    "DEPLOYMENTS.md; treat GDAv1Forwarder 0x6DA13Bde... as canonical.",
    "Uniswap v3 NonfungiblePositionManager (Base): the repo README truncates the address to 41 "
    "hex chars. The correct verified contract ends ...Ed34f1 "
    "(0x03a520b32C04BF3bEEf7BEb72E919cf822Ed34f1); the naive 42nd-char fill ...Ed34f4 resolves to "
    "an unrelated EOA (is_contract=false). Confirmed on Blockscout Base.",
]


import re
from pathlib import Path

_DEPS_DIR = Path(__file__).parent / "contracts_dependencies"


def slug(protocol: str, contract_name: str) -> str:
    """Stable filename key for a dependency contract (shared by the fetcher and the loader)."""
    base = re.sub(r"\(.*?\)", "", f"{protocol}_{contract_name}".lower())   # drop parentheticals
    base = re.sub(r"[^a-z0-9]+", "_", base).strip("_")
    return re.sub(r"_+", "_", base)


def _evm(entry) -> bool:
    a = entry["address"]
    return isinstance(a, str) and a.startswith("0x") and len(a) == 42


def by_tier(tier: str) -> list:
    return [dict(e) for e in DEPENDENCIES if e["tier"] == tier]


def run_ready_targets() -> list:
    """EVM, concrete-address, unhacked contracts to run the eventual model pass on:
    clean + anchor + caveat (each a negative control; anchors/caveats carry a flag)."""
    return [dict(e) for e in DEPENDENCIES if e["tier"] in ("clean", "anchor", "caveat") and _evm(e)]


def categories() -> dict:
    out = {}
    for e in run_ready_targets():
        out.setdefault(e["category"], []).append(e["protocol"] + " / " + e["contract_name"])
    return out


def load_dependency_contracts() -> list:
    """External-dependency negative controls with fetched verified source.

    Canonical benchmark format (same shape as the bridge/live/matched loaders), so the runner
    scores it through one code path. `ground_truth.vulnerabilities` is empty and
    `metadata.negative_control` is True — score with agents/specificity.py, not F1. Only the
    run-ready targets whose source was fetched to contracts_dependencies/ are returned; run
    `python -m benchmarks.fetch_dependencies` (keyless) to populate it.
    """
    dataset = []
    for e in run_ready_targets():
        sol = _DEPS_DIR / f"{slug(e['protocol'], e['contract_name'])}.sol"
        if not (sol.exists() and sol.read_text().strip()):
            continue
        dataset.append({
            "name": slug(e["protocol"], e["contract_name"]),
            "source": sol.read_text(),
            "ground_truth": {"vulnerabilities": [], "overall_risk": "negative_control"},
            "metadata": {
                "negative_control": True,
                "first_party": False,
                "in_training_data_as_incident": False,
                "protocol": e["protocol"],
                "contract_name": e["contract_name"],
                "address": e["address"],
                "chain": e["chain"],
                "category": e["category"],
                "tier": e["tier"],
                "memorization_exposure": e["memorization_exposure"],
                "exploit_history": e["exploit_history"],
            },
        })
    return dataset


if __name__ == "__main__":
    order = ["clean", "anchor", "caveat", "excluded", "deferred"]
    print("Suwappu dependency registry\n" + "=" * 60)
    for t in order:
        rows = by_tier(t)
        print(f"\n[{t.upper()}]  ({len(rows)})")
        for e in rows:
            print(f"  {e['category']:20} {e['protocol']:22} {e['contract_name'][:34]:34} {e['address']}")
    rr = run_ready_targets()
    print("\n" + "=" * 60)
    print(f"RUN-READY negative-control targets (EVM, unhacked): {len(rr)}")
    cats = categories()
    print(f"Category variety: {len(cats)} categories -> {', '.join(sorted(cats))}")
    print(f"Excluded (hacked / disclosed vuln): {len(by_tier('excluded'))}")
    print(f"Deferred (non-EVM / no verified source): {len(by_tier('deferred'))}")
    print(f"\nRepo data-quality issues found: {len(REPO_DATA_QUALITY_NOTES)} (see REPO_DATA_QUALITY_NOTES)")
