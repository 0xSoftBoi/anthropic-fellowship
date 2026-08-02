# Prompt-Leakage Audit: my own benchmark was scoring answers it had printed in the prompt

**Measured, no API key required.** Reproduce with `python -m benchmarks.sanitize`.

## Summary

While building a contamination control for this benchmark, I found a more basic problem
underneath it. The committed `.sol` files each begin with a provenance header written for
human auditability. The loader reads the file whole and the analyzer feeds it into the
prompt, so **the header goes to the model**. In 13 of 24 contracts (54%) that header states
the bug mechanism in prose; in 4 the machine check finds a ground-truth label string in the
header itself (`leakage_report.json`, `label_hits.raw`) — Euler states the explicit label
token `missing_solvency_check`, two headers say "reentrancy", one says "arbitrary external call".

The benchmark was, in part, scoring the model's ability to read a comment.

| Level | What the model sees | SEVERE | MODERATE | IDENTITY | CLEAN |
|-------|--------------------|-------:|---------:|---------:|------:|
| `raw` (**as committed / as scored**) | file verbatim, header included | **13 (54%)** | 7 | 3 | 1 |
| `stripped` (L1) | comments removed | **0** | 0 | 19 | 5 |
| `anon` (L2) | L1 + protocol identity removed | **0** | 0 | 0 | 24 |

- **SEVERE** — header names an exploit *and* describes the mechanism, or states a GT label
- **MODERATE** — header names the exploit/loss but not the mechanism
- **IDENTITY** — no exploit narrative, but the protocol is still identifiable (memorization cue)
- **CLEAN** — provenance only

Severity is scored on the **author-injected header** (the leading comment block), not on
comments inside the contract body. That distinction is deliberate: upstream NatSpec and
OpenZeppelin revert strings ship with the real verified source and a human auditor sees them
too, so counting them would inflate the finding. An earlier version of this scan did count
them and reported 92%; the honest number is 54%.

## The case study: Euler

`benchmarks/contracts/euler_finance_lending.sol` begins:

```solidity
// Euler Finance module bundle (verified) — Ethereum mainnet
// Exploit 2023-03-13 (~$197M): EToken.donateToReserves had no account health/solvency
// check; attacker self-donated to go underwater then self-liquidated at the max dynamic
// discount (flash-loan assisted). Source: Blockscout. CORRECTED label: missing_solvency_check
```

Opus 4.8's top finding for this contract was `missing_solvency_check`, and it was scored a
**true positive** (`results_defi_lending__claude-opus-4-8__rescored.json`, `tp: 1`).

But `donateToReserves` **is not in the committed source**. The file is the Euler module
bundle — `Base`, `Constants`, `Events`, `Proxy`, `Storage`, 6 functions — not the `EToken`
module where the bug lives. Verify it:

```bash
grep -c donateToReserves benchmarks/contracts/euler_finance_lending.sol   # 1 — the comment
python -c "from benchmarks.sanitize import strip_comments; \
  print('donateToReserves' in strip_comments(open('benchmarks/contracts/euler_finance_lending.sol').read()))"  # False
```

So the model could not have derived that finding from the code: the vulnerable function
isn't there. The label was in the prompt, and the scorer counted it as a detection. This is
pinned by a regression test (`tests/test_sanitize.py::test_euler_header_states_the_answer...`)
so it cannot silently reappear.

Euler is the only contract in the corpus where a header-named symbol is absent from the
source (1 of 7 header-named symbols checked) — but it is also the one header that states the
explicit underscored label token (`missing_solvency_check`) and the highest-loss DEX entry, so
it disproportionately affected the DEX number.

## What this does and does not imply

**Does:** every F1 in this repo produced before this fix — including the headline
35% semantic F1 / 54% recall — was measured under prompt conditions that leaked the answer
for over half the corpus. Those numbers are upper bounds contaminated by leakage, and should
not be cited as detection performance until re-measured at L1.

**Does not:** it does not mean the model found nothing. Most contracts' headers describe the
bug without naming the label, and the model still had to locate it in the source and phrase a
finding. The size of the effect is exactly what Δ(raw→stripped) measures, and that requires
an API key to run. I am not going to estimate it; I'm going to measure it.

## The fix, and the experiment it enables

`benchmarks/sanitize.py` implements three levels and is wired into every LLM mode through
one choke point in `benchmark_runner._run_audit_benchmark`:

```bash
BENCH_SANITIZE=raw      python -m agents.benchmark_runner --real --agentic   # reproduce the leaky baseline
BENCH_SANITIZE=stripped python -m agents.benchmark_runner --real --agentic   # leakage removed
BENCH_SANITIZE=anon     python -m agents.benchmark_runner --real --agentic   # + identity removed
```

Two deltas, separately meaningful:

- **Δ(raw → stripped) = the prompt-leakage effect.** How much of the reported score was
  reading the answer out of the prompt.
- **Δ(stripped → anon) = the memorization effect.** How much survives on de-identified but
  semantically identical code — the contamination question from
  [CONTAMINATION.md](CONTAMINATION.md), now with tooling behind it.

At `anon` the *contract name in the prompt* is neutralized too (`Contract_07`), since
`euler_finance_lending` would otherwise re-leak identity on its own.

## Why you can trust the sanitizer

If sanitizing broke contracts, a drop in F1 would measure the sanitizer, not leakage. So the
safety invariant is checked for every contract at every level, and the audit refuses to
report if it fails:

1. **Comment stripping is string-literal aware** — `"https://…"` and `"/* not a comment */"`
   survive. The code token stream is *bit-identical* before and after L1.
2. **Renaming is whole-word, uniform across the file, keyword-guarded, and collision-
   checked**; the L2 token stream matches L1 under the rename map, so structure, control
   flow, and call graph are unchanged.
3. **Structural fingerprints** (counts of `function`/`if`/`for`/`while`/`require`/`revert`/
   `return`/`;`/braces) must match exactly.

This is *structural* equivalence, not compile verification — there is no `solc` in this
environment. Stated as a limitation, not papered over.

The verifier earned its keep during development: the address-neutralizing regex initially
matched the first 40 hex characters of 64-character `bytes32` literals (function selectors,
keccak constants) and silently rewrote them, which would have changed dispatch behavior.
`verify()` caught it on 5 contracts before any experiment ran. That regression is now a test
(`test_anon_does_not_corrupt_bytes32_literals`).

## Generalization

The mechanism here is not specific to Solidity or to this repo. Any benchmark that pairs
"artifact under test" with "curated provenance/annotation metadata" risks feeding the
annotation to the model along with the artifact — CVE corpora with advisory text, bug-bounty
datasets with report summaries, incident datasets with post-mortem links. The check is cheap
and worth running before publishing a number:

> Print the exact string the model receives. Grep it for your ground-truth labels. Then grep
> it for a prose description of the answer.

I did not do that until after publishing numbers. That is the lesson.
