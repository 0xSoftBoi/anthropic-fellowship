"""
Live / negative-control dataset: contracts a real, unexploited product depends on.

WHY THIS EXISTS
---------------
Every other domain in this benchmark is a *famous historical exploit*. That has two
structural problems this dataset fixes:

1. **Memorization confound.** Ronin, Euler, Nomad each have a public post-mortem almost
   certainly in the model's training data (see docs/CONTAMINATION.md). "Find the Euler bug"
   is confounded by recall of the Euler write-up.
2. **No negative controls.** All 24 exploit contracts have a labeled bug, so the base rate
   is 100% and the false-positive rate — the model's *specificity* — is literally
   unmeasurable. A detector that screams "reentrancy!" at every contract scores identically
   to a real one on a 100%-positive set.

The contracts here are the first-party Solidity that Suwappu (github.com/0xSoftBoi/suwappubot,
a cross-chain DeFi SDK) deploys and depends on. They are:

- **Not in training data as an incident.** First-party, never exploited, no public
  post-mortem — so a finding cannot come from recall. This is the memorization control the
  perturbation experiment in CONTAMINATION.md approximates synthetically; here it is real.
- **Audit-hardened negative controls.** These went through three manual audit passes (nine
  critical/high bugs found and fixed) plus Slither/Aderyn/Mythril/Medusa; the committed
  versions are the *fixed* code. The honest ground truth is therefore "no known
  critical/high source bug." The question they answer is the one the exploit set cannot:
  **does the model over-flag real, hardened, unfamiliar code?** — i.e. its specificity.

IMPORTANT — this is a *softer* negative than a formally-audited mainnet contract:
- The audits were the author's own manual passes + open-source tooling, not a paid external
  audit. "No known critical bug" means "none found by those passes," not "provably none."
- The contracts are testnet-deployed (Base Sepolia), not mainnet.
- A finding the model makes here is therefore not automatically a false positive — it may be
  a real bug the author's passes missed. Negative-control results need the SAME adjudication
  as any other: the source-aware semantic judge (agents/judge_ablation.py, source_visible
  arm) deciding whether a flagged finding is actually true of the code. Specificity computed
  by raw finding-count is a *screen*, not a verdict.

GROUND TRUTH
------------
`ground_truth.vulnerabilities = []` and `metadata.negative_control = True`. The scorer's
`fp` count on an empty ground truth is exactly the number of things the model flagged;
`fp == 0` ⇒ the model correctly reported nothing on hardened code. F1 is meaningless on a
negative and is ignored — use `agents/specificity.py` to score this domain, not F1.

The natural extension (not built here) is the **matched pair**: recover the pre-audit
versions from git history, label them with the documented audit findings, and measure
recall on real bugs with zero memorization confound — the buggy/fixed pair being the
cleanest possible contamination control. Recipe in docs/LIVE_DATASET.md.
"""

from pathlib import Path

_DIR = Path(__file__).parent / "contracts_live"

# ── First-party contracts (committed source, runnable negative controls) ─────
#
# metadata.audit_note is documentation for humans; it is NOT injected into the prompt
# (the committed .sol carries provenance only — no "this is clean" signal that would leak
# the expected answer for a negative control).
FIRST_PARTY = {
    "suwappu_suwp": {
        "chain": "base-sepolia",
        "address": "0x0b96a41a2a4c9b50097049d24f43848be3A892e8",
        "role": "ERC-20 protocol token (AccessControl-gated mint, batchMint, pausable)",
        "audit_note": "3 manual passes + Slither/Aderyn/Mythril; committed = hardened version",
    },
    "suwappu_staking": {
        "chain": "base-sepolia",
        "address": "0xAe0E9e82cdc8E72F75B6E15c1989858Dd01Fb9a6",
        "role": "staking with Superfluid GDA real-yield streaming; pull-based reward claim",
        "audit_note": "HIGH fixed: flowRate==0 guard that bricked epoch 2; solvency invariant "
                      "fuzzed 25.6k (Foundry) + 51k (Medusa) sequences, 0 violations",
    },
    "suwappu_bonds": {
        "chain": "base-sepolia",
        "address": "0x9aCCf607AF27327B4940827a5c389F109847562D",
        "role": "protocol-owned-liquidity bonds: Uniswap v3 LP NFT -> discounted vested SUWP",
        "audit_note": "CRITICAL fixed: LP now decomposed at TWAP not spot (flash-loan overmint "
                      "blocked); CEI reorder in bond()",
    },
    "suwappu_oft": {
        "chain": "(not deployed on testnet)",
        "address": None,
        "role": "LayerZero OFT omnichain SUWP variant (cross-chain mint/burn messaging)",
        "audit_note": "omnichain variant of SUWP; source-only, not testnet-deployed",
    },
}

# ── External dependencies (contracts Suwappu CALLS but does not own) ─────────
#
# Catalogued for completeness — "all the contracts it's reliant on" — but source is NOT
# committed here (many are large and some, like Uniswap v3, carry heavy training-data
# exposure that dilutes the memorization-control value). They are fetchable via
# fetch_contracts.py for a future negative-control expansion. Registry only, à la
# bridge_bench.py's off-chain-hack registry: documented, not yet runnable.
EXTERNAL_DEPENDENCIES = [
    {"name": "superfluid_gda_forwarder", "chain": "base", "address": "0x6DA13Bde224A05a288748d857b9e7DDEffd1dE08",
     "role": "Superfluid GDAv1Forwarder (real-yield streaming to stakers)", "memorization_exposure": "low"},
    {"name": "superfluid_host", "chain": "base", "address": "0x4C073B3baB862572842bFB01F7B1FA40B61D1A06",
     "role": "Superfluid Host", "memorization_exposure": "low"},
    {"name": "usdcx_super_token", "chain": "base", "address": "0xD04383398dD2426297da660F9CCA3d439AF9ce1b",
     "role": "USDCx Superfluid super token (wrapped USDC)", "memorization_exposure": "low"},
    # NB: the Suwappu repo's README truncates this to 41 hex chars; the correct Base
    # NonfungiblePositionManager address ends ...Ed34f4 (42 chars). Corrected here.
    {"name": "uniswap_v3_position_manager", "chain": "base", "address": "0x03a520b32C04BF3bEEf7BEb72E919cf822Ed34f4",
     "role": "Uniswap v3 NonfungiblePositionManager (bonds accept LP NFTs)", "memorization_exposure": "high"},
    {"name": "uniswap_v3_factory", "chain": "base", "address": "0x33128a8fC17869897dcE68Ed026d694621f6FDfD",
     "role": "Uniswap v3 Factory", "memorization_exposure": "high"},
    {"name": "usdc_base", "chain": "base", "address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
     "role": "USDC (Base) — settlement/underlying", "memorization_exposure": "high"},
    {"name": "polymarket_ctf_exchange", "chain": "polygon", "address": "0xE111180000d2663C0091e4f400237545B87B996B",
     "role": "Polymarket CTF exchange (prediction-market orders, EIP-712)", "memorization_exposure": "medium"},
    {"name": "coinbase_spend_permission_manager", "chain": "base", "address": "0xf85210B21cC50302F477BA56686d2019dC9b67Ad",
     "role": "Coinbase SpendPermissionManager (delegated spend for agent wallets)", "memorization_exposure": "medium"},
    # Swap execution is routed through third-party aggregators the SDK quotes against.
    # Their router contracts are the deepest external dependency; several (KyberSwap, LiFi)
    # DO have exploit history and already appear in the bridge/DEX domains — a reminder that
    # "depended-on" and "unexploited" are not the same set.
    {"name": "oneinch_aggregation_router_v6", "chain": "multi", "address": "0x111111125421cA6dc452d289314280a0f8842A65",
     "role": "1inch AggregationRouterV6 (swap execution)", "memorization_exposure": "high"},
    {"name": "cowswap_gpv2_settlement", "chain": "multi", "address": "0x9008D19f58AAbD9eD0D60971565AA8510560ab41",
     "role": "CoW Protocol GPv2Settlement (batch-auction swap settlement)", "memorization_exposure": "medium"},
]


def load_live_contracts() -> list:
    """First-party Suwappu contracts as negative controls.

    Canonical benchmark format (same shape as the bridge/DEX/lending loaders) so the runner
    evaluates it through one code path. `ground_truth.vulnerabilities` is empty and
    `metadata.negative_control` is True — score with agents/specificity.py, not F1.
    """
    dataset = []
    for key, meta in FIRST_PARTY.items():
        sol = _DIR / f"{key}.sol"
        source = sol.read_text() if sol.exists() and sol.read_text().strip() else None
        dataset.append({
            "name": key,
            "source": source,
            "ground_truth": {"vulnerabilities": [], "overall_risk": "negative_control"},
            "metadata": {
                **meta,
                "negative_control": True,
                "first_party": True,
                "in_training_data_as_incident": False,
            },
        })
    return dataset


def load_external_dependency_registry() -> list:
    """External contracts Suwappu depends on (address registry; source not committed)."""
    return [dict(d) for d in EXTERNAL_DEPENDENCIES]


if __name__ == "__main__":
    ds = load_live_contracts()
    print(f"First-party negative controls: {len(ds)}")
    for c in ds:
        n = len((c["source"] or "").splitlines())
        print(f"  {c['name']:20} source={'yes' if c['source'] else 'NO ':3} ({n:4} lines)  {c['metadata']['role'][:60]}")
    ext = load_external_dependency_registry()
    print(f"\nExternal dependencies catalogued (source not committed): {len(ext)}")
    for d in ext:
        print(f"  {d['name']:34} {d['chain']:8} mem-exposure={d['memorization_exposure']:6} {d['address']}")
