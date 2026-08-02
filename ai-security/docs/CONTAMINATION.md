# Training-Data Contamination: the confound, and the experiment that would resolve it

**Status: OPEN. Not yet run.** This document states the single biggest threat to validity of
every F1 number in this repo, and specifies the experiment that would measure it. It is
written before running the experiment deliberately — the design should be committed to before
seeing results, not fitted to them afterwards.

## The problem

Every contract in this benchmark is a **famous historical exploit**: Nomad, Euler, Qubit,
Wormhole, Cream, Compound, KyberSwap, Platypus. Each has a widely-circulated public
post-mortem — blog posts, Rekt.news entries, audit reports, Twitter threads — published well
before the models under test were trained.

So when Opus 4.8 reads the Euler module and reports `missing_solvency_check` on
`donateToReserves()`, at least three mechanisms could produce that output:

1. **Compositional reasoning from source** (the capability the benchmark claims to measure)
2. **Recall of the Euler post-mortem** keyed off recognizable identifiers, and
3. **Prior familiarity with the codebase** shaping where attention goes, even without
   explicit recall.

The current design **cannot distinguish these**. Reported numbers are therefore
*detection-under-possible-memorization*, and any claim of the form "the model reasons about
novel code" is unsupported by this evidence alone. A reviewer should discount the headline
accordingly until the experiment below is run.

This is not a hypothetical concern for this dataset specifically: the labels were themselves
derived from those same public post-mortems (see [DATA_QUALITY.md](DATA_QUALITY.md)), so the
ground truth and the likely memorized text share a source.

## What would actually settle it

Three complementary arms. Arm A is the cheapest and most informative; run it first.

### Arm A — Semantic-preserving perturbation (identifier/constant scrubbing)

Rewrite each contract so the *bug is bit-for-bit preserved* but the surface identifiers that
make it recognizable are gone:

- rename contract/function/variable names to neutral equivalents
  (`EToken` → `TokenA`, `donateToReserves` → `transferToPool`, `submitVAA` → `submitMessage`)
- strip comments, NatSpec, event names, and revert strings that name the protocol
- change numeric constants that fingerprint the deployment (chain IDs, magic addresses)
- keep control flow, ordering, and the vulnerable pattern **exactly** as-is

Then re-run the identical agentic harness + validated judge, and report:

```
Δ = semantic_F1(original) − semantic_F1(perturbed)
```

**Interpretation.** A large Δ (say >10 F1 points) is evidence that recognition, not analysis,
was carrying the original score. A near-zero Δ is real evidence the model is reading code.
Either outcome is publishable and worth knowing; the null result is the *stronger* result for
the thesis, which is exactly why it must be pre-registered rather than discovered.

**Validity requirement:** the perturbation must be verified not to remove the bug. Each
perturbed contract needs a manual diff review confirming the vulnerable path is intact, and
the ground-truth label is unchanged. A perturbation that accidentally patches the bug would
manufacture a fake contamination effect.

### Arm B — Post-cutoff holdout

Assemble a small set (target n ≥ 5) of verified contracts with **source-level bugs disclosed
after the model's training cutoff**, labeled from the same methodology. Score them with the
same harness and judge.

This is the cleanest arm scientifically and the most expensive operationally: it requires
recent, verified, correctly-labeled exploits, and it goes stale as models are retrained. Report
the cutoff date of each model tested alongside the disclosure date of each contract, so the
comparison is auditable.

### Arm C — Recognition probe (control for what the model already knows)

Before the detection prompt, ask the model — in a *separate* context — to identify the contract
from its source alone ("what protocol is this, and is it associated with a known incident?").
Bucket contracts into **recognized** vs **not recognized**, then compare detection F1 across
buckets.

If F1 on recognized contracts is much higher than on unrecognized ones, that is a direct
within-dataset contamination signal, obtainable **without** building any new dataset — the
cheapest possible partial answer. Confounder to note in the writeup: famous contracts may also
be simpler or better-documented, so treat this as suggestive rather than decisive.

## Reporting rules (bind these in advance)

1. Report Δ per domain, not just pooled — bridges may behave differently from lending.
2. Report the perturbed run with the **same** judge, gold standard, and prompt. Changing the
   scorer between arms would invalidate the comparison.
3. Publish the perturbed contracts and the perturbation script, so Δ is reproducible.
4. If Δ is large, the headline numbers in [README](../README.md) must be restated as
   recognition-assisted, not corrected quietly.
5. Report the null result if that is what comes out. A pre-registered design is only worth
   something if the disconfirming outcome is published too.

## Cost estimate

Arm A over the current 24 contracts is one additional agentic pass plus a judge re-score.
Measured reference: the committed 8-contract DEX+lending Opus pass cost **$16.29**
(`_run.spent_usd`), so 24 contracts is roughly **$40–50** at Opus pricing, less on a cheaper
model via `BENCH_MODEL`. The judge re-score is ~$0.02. Arm C is a single cheap call per
contract (~$1 total). This is a **weekend experiment, not a research program** — which is
precisely why its absence is the most conspicuous gap in the current results.

## Honest status

Until Arm A is run, the correct reading of every headline in this repo is:

> Opus 4.8 identifies the documented root cause in 15 of 16 bridge contracts **that it has
> very likely read about during training**. Whether it would do so on unfamiliar code of
> equivalent difficulty is untested.
