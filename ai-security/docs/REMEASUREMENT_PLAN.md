# BRIDGE-bench re-measurement protocol

This is the next load-bearing experiment after the prompt-leakage audit.

The original `raw` benchmark is contaminated: 13/24 source-bearing prompts contained prose describing the vulnerability and two included the corrected label. The purpose of this rerun is to separate three effects that the original number conflated:

1. **prompt leakage** — answers stated in benchmark-authored comments/provenance headers;
2. **protocol memorization** — model recognition of famous historical incidents;
3. **actual vulnerability detection** — reasoning from code presented in the prompt.

## Population lock — 24 means 16 + 5 + 3

The published multi-domain population is exactly:

- **16 source-bearing bridge contracts** from the historical bridge run;
- **5 DEX/AMM contracts** from `results_defi_lending__claude-opus-4-8.json`;
- **3 lending contracts** from the same file.

There is a subtle but important historical detail: `results_real__claude-opus-4-8.json` contains 20 bridge rows, but four of those rows correspond to empty-source placeholders and were not meaningful code-evaluation examples:

- `poly_network_eth_cross_chain_manager`;
- `ronin_bridge_validator`;
- `orbit_chain_multisig`;
- `lifi_protocol_diamond_march_2022`.

`agents.remeasure` permanently excludes those four historical placeholders from this paired experiment, even if their source is fetched later. Otherwise the experimental population could silently change from 16 bridge contracts to 20. The 16+5+3 names and order are recorded in every new run manifest.

> **Protocol correction (2026-08-08).** An earlier version of this document described the experiment as a 24-contract rerun but showed only `benchmark_runner --real`, which executes the bridge domain. Following the old command literally would therefore have produced a mislabeled 24-contract claim. The dedicated remeasurement runner fixes that ambiguity and records the exact population in every artifact.

## Experimental matrix

Run the same locked 24 contracts at three sanitizer levels:

| condition | prompt | interpretation |
|---|---|---|
| `raw` | original source verbatim | contaminated baseline reproduced on the same checkout |
| `stripped` | comments removed by the sanitizer | removes direct textual leakage while preserving protocol identity |
| `anon` | comments removed + protocol identity neutralized | reduces both direct leakage and easy incident recognition |

The primary estimand is the paired change in semantic F1 and recall between `raw → stripped → anon` on the same contract population.

The historical raw results remain useful context, but the cleanest comparison reruns **raw on the same code commit** as stripped and anon. Otherwise a harness change can be mistaken for a contamination effect.

## Gate 0 — free validation before any API call

From `ai-security/`:

```bash
python -m benchmarks.sanitize
python -m agents.remeasure --preflight
python -m agents.remeasure --estimate
pytest -q
```

The preflight must establish all of the following:

- population is exactly bridge=16, defi=5, lending=3;
- `stripped` preserves the code-token stream;
- `anon` preserves structural/token invariants under its rename map;
- no benchmark-authored answer leakage survives `stripped`;
- no protocol-identity token detected by the sanitizer survives `anon`.

The sanitizer currently provides **structural equivalence**, not a Solidity compilation proof. That limitation remains explicit because `verify()` does not invoke `solc`.

### Validated zero-cost gate — 2026-08-08

CI reproduced the following before any paid call:

- 61 tests passed, 1 skipped;
- leakage audit: raw = 13 SEVERE / 7 MODERATE / 3 IDENTITY / 1 CLEAN;
- stripped = 0 SEVERE / 0 MODERATE / 19 IDENTITY / 5 CLEAN;
- anon = 0 SEVERE / 0 MODERATE / 0 IDENTITY / 24 CLEAN;
- remeasurement preflight: 16 bridge + 5 DEX + 3 lending = 24, with zero sanitizer failures;
- source bytes: 2,074,440 raw → 1,314,832 stripped → 1,314,080 anon.

Those numbers describe the prompt audit, **not model performance**. No sanitized inference score exists yet.

## Paid execution — explicit cap required

Use the dedicated runner, not `budget_run.py`. The older budget runner is retained for historical/raw convenience runs but is deliberately blocked from pretending to implement the contamination experiment.

```bash
# one condition
BENCH_MODEL=opus \
python -m agents.remeasure --run stripped --max-estimated-cost-usd <CAP>

# preferred: all three conditions on one checkout / one run id
BENCH_MODEL=opus \
python -m agents.remeasure --run all --max-estimated-cost-usd <CAP>
```

The command refuses to start without a positive cap and refuses a cap below its planning guard-band, because a selectively truncated contract set would invalidate the paired comparison. It checkpoints after every contract but marks a partial artifact `completed: false`; partial artifacts must not be scored as the experiment.

A manual GitHub Actions workflow, `.github/workflows/bridge-remeasure.yml`, exposes the same operation with two separate gates: `confirm_paid=true` and an explicit `max_estimated_cost_usd`. Ordinary pull-request CI never performs paid inference.

### Pricing provenance and current planning estimate

The old `agents/budget_run.py` used `$15/M input + $75/M output`. That price assumption is stale for Opus 4.8. As of 2026-08-08, Anthropic's published global standard list price for Opus 4.8 is **$5/M input + $25/M output**. `agents.remeasure` records the pricing rates, source URL and as-of date in every manifest and labels the amount an **estimated list cost**, not a provider bill. Prompt-cache discounts are intentionally ignored in the estimate.

Pricing source: https://www.anthropic.com/news/claude-opus-4-8

Using the eight historical DEX/lending calls as a token-use sample and scaling by locked source bytes, the 2026-08-08 planning gate produced:

- historical 8-contract sample repriced at current list rates: **$5.4316**;
- projected one 24-contract condition: **$18.61**;
- recommended one-condition estimator cap with 50% guard band: **$27.91**;
- projected raw+stripped+anon run: **$55.82**;
- recommended three-condition estimator cap: **$83.72**.

These are planning estimates. Agentic token use is not linear in source bytes, cache treatment can reduce billed cost, and a repository-side estimate is not a provider hard billing limit. Configure a provider/account spending limit as the final financial boundary when available.

## Locked protocol

For every condition use the same:

- model (`claude-opus-4-8` via `BENCH_MODEL=opus`);
- analysis mode (`agentic`);
- max turns (`8`);
- prompt/tool implementation;
- contract population and order;
- evaluator implementation;
- semantic-judge version when rescoring.

Only the sanitization condition and, for `anon`, the deliberately neutralized display name may change.

Each result manifest records at minimum:

- run id and condition;
- model id;
- code commit SHA;
- exact population lock and historical exclusions;
- Python version;
- pricing version;
- per-contract input/output/cache token counts;
- per-contract estimated list cost;
- exact-string metrics and findings;
- completion state.

## Reporting requirements

Report all three conditions together. Do not publish a sanitized score without the raw condition beside it.

For each condition report:

- exact-string precision / recall / F1;
- semantic-judge precision / recall / F1;
- per-domain scores (bridge, DEX/AMM, lending);
- per-contract paired outcome changes;
- bootstrap 95% confidence intervals over contracts;
- token usage and versioned list-cost estimate;
- judge agreement against the existing human gold set.

Also report the two paired deltas:

- **leakage effect proxy** = `raw - stripped`;
- **identity/memorization proxy** = `stripped - anon`.

These are descriptive paired differences, not clean causal estimates. The benchmark is small, the contracts are not an IID sample, comment stripping removes upstream comments as well as the benchmark-authored header, and anonymization is an intervention on source presentation rather than a perfect erasure of training-set knowledge.

## Evaluator validity remains part of the result

The existing judge-validity analysis must travel with the new scores rather than becoming a footnote. On the historical bridge result, the Haiku semantic judge scored 37.1% F1 while the human gold labels imply 51.6% F1; the judge was conservative by 14.5 F1 points on that validation set. The all-24 historical headline was also sensitive: five additional promotions among 53 judge decisions would move F1 by roughly five points.

That does not make semantic scoring unusable. It means the new article must present exact scoring, semantic scoring, judge validation, and uncertainty together.

## Matched-pair follow-up

The stronger complementary test is the first-party matched-pair domain already in the repository: pre-audit buggy contracts and their fixed descendants, where labels come from the actual fix commits and the incidents are not famous training-set artifacts.

For each pair measure:

- recall on the buggy revision;
- specificity on the fixed revision;
- whether the same alleged finding persists after the bug is removed.

A model that raises the same finding on both revisions is recognizing surface patterns, not localizing the defect.

## Decision rules

The experiment is informative even if performance collapses.

- If `raw >> stripped`, the original result was substantially prompt-leakage driven.
- If `stripped >> anon`, protocol identity or memorized incident knowledge is carrying material signal.
- If `anon` remains strong and matched-pair specificity is high, that is the strongest evidence in this repository for code-grounded detection.
- If all three are weak, publish that result. The benchmark's value is measurement validity, not preserving a headline score.

## Artifact checklist

A complete run should leave behind:

- immutable JSON for raw / stripped / anon sharing one run id and commit SHA;
- a machine-readable manifest inside each result;
- a contract-level exact comparison CSV;
- semantic-rescored artifacts for all three conditions;
- bootstrap confidence-interval output;
- figures generated only from committed/saved results;
- a short results note that clearly supersedes the contaminated headline number.

No number becomes a headline until another person can reproduce how it was produced from the saved artifacts.
