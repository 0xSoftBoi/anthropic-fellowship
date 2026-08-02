# Matched pairs: recall on real bugs the model cannot have read about

**Static baseline is key-free:** `python -m agents.benchmark_runner --matched --no-claude`
then inspect `results_matched.json`. The LLM run needs a key.

## The one measurement no famous-exploit benchmark can make

Every exploit domain in this benchmark labels bugs from public post-mortems that are almost
certainly in the model's training data ([CONTAMINATION.md](CONTAMINATION.md)), and the labels
shared a source with that training text ([DATA_QUALITY.md](DATA_QUALITY.md)). So "the model
found the bug" is confounded by "the model read about the bug." The
[live domain](LIVE_DATASET.md) removed that confound on the *negative* side (specificity on
unmemorized clean code). This is the positive side: **real, exploitable bugs the model cannot
have memorized, with ground truth taken from the actual fix.**

The contracts are the **pre-audit** versions of the same first-party Suwappu contracts the
live domain ships in **fixed** form. Suwappu (github.com/0xSoftBoi/suwappubot) went through
three manual audit passes; each fix is a commit whose diff shows the vulnerable line and its
repair. The buggy snapshot of each contract is its source at the parent of its earliest
audit-fix commit — so it carries every bug the passes later removed.

| | Exploit domains | Matched pairs |
|---|---|---|
| Bug in training data | Yes (famous hack) | **No** (first-party, never exploited) |
| Ground truth from | public post-mortem (prose) | **the git fix commit's diff** |
| Fixed counterpart to score specificity | none | **yes** (`contracts_live/`) |

## The bugs (16 labels across 3 contracts, each grounded in a fix-commit diff)

**`suwappu_bonds_preaudit`** (fixed → `suwappu_bonds`; commits 0421c76, ab8c57f, fd4da95, 35cceb2)
- `flash_loan_price_manipulation` (critical) — LP decomposed at spot price / valued by
  fictional `liquidity / 1e12` math → flash-loan the pool to overmint discounted SUWP
- `spot_price_oracle` (critical) — payout from manipulable spot, not a TWAP
- `precision_loss_rounding` (high) — linear tick→price approx underflows at negative ticks
- `missing_input_validation` (high) — bonded LP's pool never authenticated (fake-pool inject)
- `reentrancy` (high) — `bond()` transferred the LP NFT before writing state (CEI violation)
- `logic_error` (high) — no per-bond or global mint cap

**`suwappu_staking_preaudit`** (fixed → `suwappu_staking`; commits a661eab, 0421c76, ab8c57f, 35cceb2)
- `missing_solvency_check` (high) — `recoverToken` reserved only `totalStaked`, so the owner
  could drain stakers' unclaimed bonus reserve
- `missing_token_transfer` (high) — `depositVaultYield` credited yield it never pulled
- `front_running` (high) — bonus allocated from live balances → flash-stake front-run
- `denial_of_service` (high) — `fundStream`'s flow-rate==0 guard bricked every epoch after 1
- `unchecked_return_value`, `integer_truncation`, `precision_loss_rounding`,
  `incorrect_decimal_scaling` (medium) — see `matched_contracts.py` for each

**`suwappu_oft_preaudit`** (fixed → `suwappu_oft`; commit 0421c76)
- `missing_access_control` (high) — mint callable on satellite chains → cross-chain supply
  inflation
- `denial_of_service` (medium) — `whenNotPaused` on `_update` bricks inbound bridge credits

`SUWP` is intentionally absent: its only pre-audit change was a non-exploitable `batchMint`
gas cap — not a positive. (Its hardened form stays a negative control in the live domain.)

## How the labels were produced (and verified)

1. **Discover** the audit-fix commits (`git log` over `contracts/*.sol`): a661eab, 0421c76,
   ab8c57f, 35cceb2, fd4da95 — each commit message is an explicit audit report.
2. **Extract** the security fixes from each commit's diff (fan-out, one agent per commit),
   emitting `{contract, vuln_type, severity, mechanism, evidence}` and marking refactors /
   gas caps / renames as *not* security fixes (the SUWP and OFT `batchMint` caps were
   correctly excluded).
3. **Verify** each bug is genuinely a security fix and **present in the buggy snapshot**, by
   reading the diff against `git show <snapshot>:contracts/<file>`. The two headline bugs
   (Bonds `liquidity/1e12`, Staking `recoverToken`) were also confirmed by hand.

The ground truth is therefore the diff itself — the strongest form available, and strictly
better than a prose post-mortem: `git show <sha> -- contracts/<file>` reproduces it.

## What the static baseline already shows

`static_v2` finds **0 of 16** bugs on these contracts (`results_matched.json`) — the "static
analysis fails on real compositional bugs" thesis, now on ground truth with no memorization
confound. The LLM's recall here, paired with its **specificity on the fixed counterparts**
(live domain, 75% for static), is the matched-pair result: capability measured where recall
can't be recall-of-a-write-up.

## Honest limits

- The snapshot predates all passes, so it carries several bugs at once; a model finding
  outside the label set may be a real bug at a different line or a false positive — the
  source-aware judge ([JUDGE_VALIDITY.md](JUDGE_VALIDITY.md)) adjudicates, as everywhere.
- Severities are the audit's own, not formal CVSS.
- The verify fan-out was flaky (one verdict landed cleanly, a `RECLASSIFIED` that this doc
  folds in — the decimal bug is `incorrect_decimal_scaling`, not solvency); the labels stand
  on the diffs, read directly. Re-running the adversarial verify is a documented follow-up.
