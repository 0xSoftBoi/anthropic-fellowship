# What Opus 4.8 catches and misses: a per-contract analysis

A qualitative read of the committed run (`results_*__claude-opus-4-8__rescored.json`) across
24 verified contracts in three domains. Numbers are from the semantic-judge scoring; the
per-contract "caught/missed" below is reconstructed from the rescored files.

**Headline:** static/string-match ~4% F1 → Opus semantic **35% F1 / 54% recall**. But the
aggregate hides a clear, interpretable pattern in *which* bugs it gets.

## Where Opus is strong: access control, arbitrary calls, compositional logic

Opus reliably identifies bugs that are about **who is allowed to do what** and **untrusted
control flow**, even buried in large proxy/diamond/fork code:

- **Arbitrary external call / approval drain** — caught on `socket`, `xbridge`, `lifi_july_2024`,
  `rubic`, `seneca`, `dough`, `thorchain`. These are the LiFi/Socket/Rubic exploit class, and the
  model names the unvalidated-calldata → `transferFrom` drain path directly.
- **Cross-chain message authentication** — `crosscurve`: caught both `missing_gateway_origin_check`
  and `unauthenticated_message_handler` (the exact `expressExecute` bug). `hyperbridge`: caught the
  governance/mint-authority takeover.
- **Reentrancy** — `cream_cramp`: caught the ERC-777 `tokensReceived` reentrancy.
- **Solvency / state-flag logic** — `abracadabra`: caught `missing_solvency_check` + `state_flag_reset`
  (the `cook()` `[5,0]` flag-reset bug); `platypus`: caught the `emergencyWithdraw` solvency miss.
- **Donation / rounding** — `onyx`: caught **all three** labels (`exchange_rate_manipulation`,
  `rounding_error`, `empty_market_donation`) — a clean empty-market-inflation read.

## Where Opus misses, and why it's interesting

1. **Non-Solidity is invisible (expected).** `curve_finance_vyper_reentrancy` — the bug is a
   **Vyper compiler** reentrancy-lock flaw; a Solidity reader cannot see it. Included as an honest
   negative case, not a model failure.

2. **Deep numeric/precision bugs are hard.** `kyberswap` (tick-crossing double-counted
   reinvestment liquidity) and `compound_p062` (a `>`-vs-`>=` reward-accounting comparison) were
   both **missed**. These require tracing exact integer/branch arithmetic across the contract —
   the current frontier of difficulty.

3. **Same bug, different source, different result.** `onyx` (empty-market donation) was caught
   3/3, but `sonne` (the *same* exchange-rate-manipulation class) was missed 0/3. Same vulnerability
   family, opposite outcome — suggesting the model's success depends on how cleanly the buggy math
   surfaces in that contract's structure, not just on "knowing" the bug class.

4. **Many "misses" are redundant secondary labels.** Where a ground-truth contract carries two
   tags for one underlying issue, Opus often catches one and "misses" the synonym: `lifi` caught
   `arbitrary_external_call`, "missed" `infinite_approval_drain`; `dough` caught the callback bug,
   "missed" `missing_input_validation`; `abracadabra` caught the solvency+flag bugs, "missed"
   `logic_error`. These inflate the FN count without representing a real blind spot — a dataset
   granularity artifact, not a capability gap.

5. **Initialization/default-value bugs in bridges.** `nomad` (zero-root init → any message valid)
   was missed at the specific-mechanism level — the model flagged related issues that the judge
   (correctly, conservatively) did not accept as the same root cause.

## Implications

- **The thesis holds, unevenly.** LLM compositional reasoning beats static pattern-matching on
  real code (4% → 35% F1), but the lift is concentrated in access-control/arbitrary-call/logic
  bugs and thins out on deep numeric reasoning.
- **Per-domain:** bridges 37% F1, lending 40%, DEX 21% — DEX is hardest precisely because it
  contains the Vyper and tick-precision cases.
- **Benchmark design matters.** A non-trivial share of FNs are redundant-label artifacts; future
  versions should de-duplicate near-synonymous ground-truth tags so recall reflects capability,
  not labeling granularity.

*Reproduce these lists:* the per-contract `promoted` / `still_missed` fields live in the rescored
result files; `python -m agents.report` prints the aggregate tables.
