# BRIDGE-bench re-measurement protocol

This is the next load-bearing experiment after the prompt-leakage audit.

The original `raw` benchmark is contaminated: 13/24 prompts contained prose describing the vulnerability and two included the corrected label. The purpose of this rerun is to separate three effects that the original number conflated:

1. **prompt leakage** — answers stated in comments/provenance headers;
2. **protocol memorization** — model recognition of famous historical incidents;
3. **actual vulnerability detection** — reasoning from code presented in the prompt.

## Experimental matrix

Run the exact same 24-contract benchmark at three sanitizer levels:

| condition | prompt | interpretation |
|---|---|---|
| `raw` | original source verbatim | contaminated historical baseline only |
| `stripped` | comments/provenance removed | removes direct textual leakage |
| `anon` | comments removed + protocol identity neutralized | reduces both leakage and easy incident recognition |

The primary estimand is the paired change in semantic F1 and recall between `raw → stripped → anon` on the same contract set.

## Locked protocol

Before running paid inference:

```bash
python -m benchmarks.sanitize
pytest -q
```

The sanitizer safety invariant must pass for every contract: code-token stream and control-flow counts are unchanged by sanitization. If this fails, stop; do not interpret downstream model scores.

Use the same model, decoding parameters, prompt template, tool budget, judge version, and contract ordering for every condition. Only `BENCH_SANITIZE` may change.

```bash
BENCH_MODEL=opus BENCH_SANITIZE=raw      python -m agents.benchmark_runner --real --agentic
BENCH_MODEL=opus BENCH_SANITIZE=stripped python -m agents.benchmark_runner --real --agentic
BENCH_MODEL=opus BENCH_SANITIZE=anon     python -m agents.benchmark_runner --real --agentic
```

Save the model identifier, provider response metadata, git commit SHA, environment lockfile hash, and result JSON for every run.

## Reporting requirements

Report all three conditions together. Do not publish a sanitized score without the contaminated baseline beside it.

For each condition report:

- exact-string precision / recall / F1;
- semantic-judge precision / recall / F1;
- per-domain scores (bridge, DEX/AMM, lending);
- per-contract paired outcome changes;
- bootstrap 95% confidence intervals over contracts;
- cost and token usage;
- judge agreement against the existing human gold set.

Also report the two paired deltas:

- **leakage effect** = `raw - stripped`;
- **identity/memorization proxy** = `stripped - anon`.

These are descriptive differences, not clean causal estimates; the benchmark is small and the historical contracts are not an IID sample.

## Matched-pair follow-up

The stronger test is the first-party matched-pair domain already in the repository: pre-audit buggy contracts and their fixed descendants, where labels come from the actual fix commits and the incidents are not famous training-set artifacts.

For each pair measure:

- recall on the buggy revision;
- specificity on the fixed revision;
- whether the same alleged finding persists after the bug is removed.

A model that raises the same finding on both revisions is recognizing surface patterns, not localizing the defect.

## Decision rules

The experiment is informative even if performance collapses.

- If `raw >> stripped`, the original result was substantially prompt-leakage driven.
- If `stripped >> anon`, protocol identity or memorized incident knowledge is carrying material signal.
- If `anon` remains strong and matched-pair specificity is high, that is the strongest evidence in this repository for genuine code-grounded detection.
- If all three are weak, publish that result. The benchmark's value is measurement validity, not preserving a headline score.

## Artifact checklist

A complete rerun should leave behind:

- immutable result JSON for every condition;
- a machine-readable run manifest with commit/model/config hashes;
- a single comparison CSV at contract granularity;
- confidence-interval script/output;
- updated figures generated from saved results only;
- a short results note that clearly supersedes the contaminated headline number.

No number becomes a headline until another person can reproduce how it was produced from the committed artifacts.
