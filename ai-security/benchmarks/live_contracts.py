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
# The full, tiered, exploit-history-checked catalogue now lives in
# benchmarks/dependency_registry.py — built from the suwappubot docs+code, with the
# "unhacked only" filter applied and 2025-2026 exploit history RE-VERIFIED (which moved
# Across and Coinbase SpendPermissionManager out of the clean set). This list is the
# backward-compatible view: the EVM, concrete-address, unhacked *run-ready* targets
# (clean + anchor + caveat tiers), mapped to the legacy shape. Source is not committed here
# — see docs/DEPENDENCY_DATASET.md; fetch via keyless Blockscout/Sourcify.
from benchmarks.dependency_registry import run_ready_targets as _run_ready_targets

EXTERNAL_DEPENDENCIES = [
    {
        "name": e["protocol"],
        "contract_name": e["contract_name"],
        "chain": e["chain"],
        "address": e["address"],
        "role": e["uses"],
        "category": e["category"],
        "tier": e["tier"],
        "memorization_exposure": e["memorization_exposure"],
    }
    for e in _run_ready_targets()
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
