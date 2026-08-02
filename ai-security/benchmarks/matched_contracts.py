"""
Matched-pair dataset: memorization-free POSITIVES.

The negative-control (live) domain answered "does the model over-flag hardened code?" This
is its positive complement, and the strongest artifact in the benchmark: real, exploitable
bugs in first-party code, with **no public post-mortem in any training set** and ground truth
taken from the **actual git fix commit** — not a prose write-up.

These are the *pre-audit* versions of the same Suwappu contracts the live domain ships in
their *fixed* form. Suwappu (github.com/0xSoftBoi/suwappubot) went through three manual audit
passes; each fix is a commit whose diff shows the vulnerable line and its repair. The buggy
snapshot for each contract is its source at the parent of its earliest audit-fix commit, so it
contains every bug the later passes removed. Every label below is grounded in a specific fix
commit's diff (cited in metadata.fix_commits) and was confirmed present in the committed
snapshot by reading that diff against the snapshot.

WHY THIS IS BETTER GROUND TRUTH THAN THE EXPLOIT DOMAINS
- **No memorization.** First-party, never exploited, no post-mortem — a finding cannot be
  recall. This is the real version of the synthetic perturbation control in CONTAMINATION.md.
- **Diff-grounded labels.** The exploit domains label from public post-mortems (prose, and the
  labels shared a source with the model's likely training data — see DATA_QUALITY.md). Here
  the label IS the fix: `git show <sha>` shows the exact before/after.
- **Matched to a negative.** The fixed counterpart (contracts_live/) is the same contract with
  the bug removed. Recall here + specificity there, on one contract pair, is the measurement
  no famous-exploit benchmark can make.

HONEST LIMITS
- The buggy snapshot predates ALL audit passes, so it carries multiple bugs; labels are the
  union of the documented fixes for that contract. A model finding not in the label set may be
  a real bug the audits also caught at a different line, or a genuine false positive — the
  source-aware judge (judge_ablation.py) adjudicates, as everywhere else.
- Severities are the audit's own (from commit messages), not a formal CVSS.
- SUWP is intentionally absent: its only pre-audit change was a non-exploitable `batchMint`
  gas cap, so it is not a positive (its hardened form remains a negative control in the live
  domain).

Scored by recall/F1 like the exploit domains (these are positives). Run with `--matched`.
"""

from pathlib import Path

_DIR = Path(__file__).parent / "contracts_matched"

# vuln labels grounded in the fix-commit diffs. type -> (severity). Types reuse canonical
# TYPE_EQUIVALENCES keys where one fits; a few precise types are new (equivalences added in
# benchmark_runner so string-match and the validator recognize them).
MATCHED = {
    "suwappu_bonds_preaudit": {
        "fixed_counterpart": "suwappu_bonds",
        "snapshot": "c56c53f",  # parent of 0421c76
        "fix_commits": ["0421c76", "ab8c57f", "fd4da95", "35cceb2"],
        "vulns": [
            ("flash_loan_price_manipulation", "critical",
             "LP position decomposed at the pool's spot price (slot0) and via a fictional "
             "liquidity/1e12 valuation → flash-loan the pool to overvalue the bonded LP and "
             "overmint discounted SUWP"),
            ("spot_price_oracle", "critical",
             "bond payout derived from manipulable spot pricing rather than a TWAP"),
            ("precision_loss_rounding", "high",
             "linear tick→price approximation 1e6+tick*1e6/1e4 underflows at negative ticks, "
             "mispricing the payout"),
            ("missing_input_validation", "high",
             "the LP's pool was never authenticated against factory.getPool, so an attacker "
             "could bond an LP NFT from a fake pool; setSuwpUsdcPool accepted any address"),
            ("reentrancy", "high",
             "bond() transferred the LP NFT (external call, ERC721 receive hook) before "
             "writing bond state — a CEI violation"),
            ("logic_error", "high",
             "no per-bond or global cap on SUWP minted, so any mispricing mints unbounded SUWP"),
        ],
    },
    "suwappu_staking_preaudit": {
        "fixed_counterpart": "suwappu_staking",
        "snapshot": "cd69c58",  # parent of a661eab
        "fix_commits": ["a661eab", "0421c76", "ab8c57f", "35cceb2"],
        "vulns": [
            ("missing_solvency_check", "high",
             "recoverToken reserved only totalStaked, letting the owner withdraw stakers' "
             "unclaimed bonus reserve; distributeSuwpBonus allocated bonuses without checking "
             "the contract held them"),
            ("missing_token_transfer", "high",
             "depositVaultYield incremented the yield counter without ever pulling the USDC — "
             "accounting credited funds that never arrived"),
            ("front_running", "high",
             "distributeSuwpBonus allocated each share from the LIVE stakedBalance/totalStaked, "
             "so an attacker could flash-stake right before distribution to capture bonus"),
            ("denial_of_service", "high",
             "fundStream required the GDA flow rate == 0, which bricked every epoch after the "
             "first (a live stream never returns to 0)"),
            ("unchecked_return_value", "medium",
             "pool.updateMemberUnits and gda.distributeFlow bool returns were ignored; a silent "
             "false desyncs accounting from the stream"),
            ("integer_truncation", "medium",
             "flowRate cast to int96 from usdcxAmount/durationSeconds with no bound check"),
            ("precision_loss_rounding", "medium",
             "stake accepted any amount>0 but _toUnits rounds small amounts to 0 pool units"),
            ("incorrect_decimal_scaling", "medium",
             "fundStream passed the 6-decimal USDC amount to Superfluid upgrade(), which expects "
             "an 18-decimal super-token amount (reclassified from the initial label by verify)"),
        ],
    },
    "suwappu_oft_preaudit": {
        "fixed_counterpart": "suwappu_oft",
        "snapshot": "c56c53f",  # parent of 0421c76
        "fix_commits": ["0421c76"],
        "vulns": [
            ("missing_access_control", "high",
             "mint/batchMint were callable on any chain the OFT is deployed to; minting on a "
             "satellite (non-canonical) chain breaks the omnichain supply invariant"),
            ("denial_of_service", "medium",
             "_update carried whenNotPaused; inbound LayerZero delivery runs _credit→_mint→"
             "_update, so a pause bricks bridge credits and can strand in-flight funds"),
        ],
    },
}


def load_matched_contracts() -> list:
    """Pre-audit Suwappu contracts as memorization-free positives (canonical benchmark format)."""
    dataset = []
    for key, spec in MATCHED.items():
        sol = _DIR / f"{key}.sol"
        source = sol.read_text() if sol.exists() and sol.read_text().strip() else None
        vulns = [{"type": t, "severity": s, "description": d} for (t, s, d) in spec["vulns"]]
        dataset.append({
            "name": key,
            "source": source,
            "ground_truth": {"vulnerabilities": vulns, "overall_risk": "critical"},
            "metadata": {
                "fixed_counterpart": spec["fixed_counterpart"],
                "snapshot_commit": spec["snapshot"],
                "fix_commits": spec["fix_commits"],
                "first_party": True,
                "memorization_free": True,
                "in_training_data_as_incident": False,
                "ground_truth_source": "git fix-commit diffs (github.com/0xSoftBoi/suwappubot)",
            },
        })
    return dataset


if __name__ == "__main__":
    ds = load_matched_contracts()
    tot = sum(len(c["ground_truth"]["vulnerabilities"]) for c in ds)
    print(f"Matched positives: {len(ds)} contracts, {tot} diff-grounded labels")
    for c in ds:
        n = len((c["source"] or "").splitlines())
        print(f"\n  {c['name']:26} ({n} lines) -> fixed: {c['metadata']['fixed_counterpart']}")
        for v in c["ground_truth"]["vulnerabilities"]:
            print(f"      {v['severity']:8} {v['type']}")
