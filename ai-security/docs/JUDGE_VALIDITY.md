# Judge Validity: the headline moves 14.5 F1 points depending on who grades it

**Measured, no API key required.** Reproduce with `python -m agents.judge_uncertainty`.

## The finding

The semantic F1 in this repo is produced by an LLM-as-judge deciding, for each ground-truth
vulnerability the string matcher missed, whether some unmatched model finding refers to the
same bug. The headline is therefore a direct function of **53 binary judge calls**, and it
has always been reported as a point estimate.

`benchmarks/judge_gold_standard.json` hand-labels the truth for exactly the 38 bridge
decisions the judge made. So for bridges we don't have to *model* judge error — we can score
with the human labels instead and read off what the judge cost us:

| Bridge scoring | Precision | Recall | **F1** |
|---|---|---|---|
| Haiku judge (the committed number) | 27.7% | 56.1% | **37.1%** |
| Human gold labels, same findings | 38.6% | 78.0% | **51.6%** |
| Human gold, 5 BORDERLINE labels flipped | — | — | **50.0%** |

**The two graders differ by 14.5 F1 points on identical model output.** The judge promoted
20 of 38 decisions; the human labeled 29 of 38 as genuine matches.

That gap is larger than most of the effects this benchmark gets used to argue about. It is
the "how much does the grader matter" number, and it was previously unmeasured.

## What this does and does not mean

**It confirms a claim the repo already made, and quantifies it.** The README said 37% was "a
conservative lower bound" because the judge is high-precision and errs toward under-crediting.
That was right, and the size of the under-credit is ~14.5 points.

**It is not evidence that the true F1 is 52%.** The gold standard is:

- **single-annotator** — one person's judgment, with no inter-annotator agreement to check it
  against;
- **in-sample** — the same 38 decisions it is used to score, so this is a self-consistency
  measurement, not held-out validation;
- **authored by the person whose benchmark is being graded**, which is a standing incentive
  toward leniency. Five labels are self-flagged BORDERLINE; flipping all five only moves the
  result 1.6 points, which bounds that particular worry but does not remove it.

The honest reading is not "37% was too low" or "52% is right." It is: **on this benchmark,
the choice of grader is worth ~15 F1 points, which is a larger effect than the model
differences the benchmark is designed to detect.** A number that moves that much under a
defensible change of grader needs to be reported with that range attached.

## Uncertainty

20,000-iteration bootstrap: contracts resampled with replacement (the sampling unit — 16/5/3
contracts is small), with judge error propagated via Beta posteriors on the bridge-measured
PPV/NPV for DEX/lending, where **no gold standard exists** and the bridge error rates have to
be extrapolated.

| Set | Point estimate (gold-corrected) | 95% CI |
|---|---|---|
| Bridges (16) | 51.6% | **[39.7%, 63.8%]** |
| All 24 (gold + extrapolated) | — | **[38.5%, 57.4%]** |

Note where the committed numbers fall: **bridges 37.1% is below the 39.7% lower bound, and
all-24 35.0% is below 38.5%.** The reported figures sit outside the interval implied by the
repo's own gold standard — consistent with the judge being systematically conservative rather
than noisy.

The interval is wide because n is small, and it is wider than it looks for DEX/lending, where
the error model is borrowed from a different domain.

## Fragility

| Question | Answer |
|---|---|
| How many judge calls produce the headline? | 27 "match" out of 53 decisions |
| What does one flipped decision move it by? | **~1.1 F1 points** |
| What does +5 F1 points cost? | **5 flipped decisions — 9% of the corpus** |

A benchmark where 9% of the grading decisions swing the headline by 5 points is not a
precision instrument. Report a range.

## What the current judge cannot check at all

Beyond grader disagreement, the judge has a structural blind spot: **it never sees the
contract source.** It compares a ground-truth label to a finding string, so it can answer
"do these mean the same thing?" but not "is this finding actually true of this code?"

A model can emit a finding that is semantically identical to the label and still be wrong
about the contract — and the blind judge must credit it. That is a systematic upward bias of
unknown size, and the current validation cannot detect it, because the human gold labels were
produced the same label-to-label way.

Euler makes this concrete: its committed source doesn't contain the vulnerable function at
all (see [LEAKAGE_AUDIT.md](LEAKAGE_AUDIT.md)), yet `missing_solvency_check` scored as a true
positive under both the judge *and* the gold standard. Neither grader could have caught it,
because neither was looking at the code.

## The ablation harness (needs a key)

`agents/judge_ablation.py` sweeps the judge design space to measure how much of the headline
is the grader. Three axes:

| Axis | Values | Question |
|---|---|---|
| `model` | haiku / sonnet / opus | Does a stronger judge grade differently? |
| `framing` | default / strict / lenient | How much of the score is prompt-induced leniency? |
| `source_visible` | false / true | **Can the judge tell a correct finding from a plausible one?** |

The source-visible arm is the one that addresses the blind spot above — it gives the judge the
contract and asks whether the finding is *true of this code*, not merely synonymous with the
label.

```bash
python -m agents.judge_ablation --dry-run          # plan + cost, spends nothing
python -m agents.judge_ablation --full             # all 18 configs
```

The full sweep is **954 judge calls, ~$11.51** — the whole judge-validity study costs about
twelve dollars, which is the main reason it should just be run. Output includes F1 per
configuration, pairwise inter-judge agreement (Cohen's κ), and the **F1 spread across
configurations** — variation attributable to the grader alone, since the model's findings are
identical in every row.

## Why this belongs in the reframe

Prompt leakage (the answer in the input), memorization (the answer in the weights), and judge
validity (the answer depends on who grades) are three independent ways this benchmark can
report a number that isn't measuring detection. Each has a different fix, each is cheap to
measure, and none of the three is standard practice in the security-capability benchmarks this
work builds on.

That is the research contribution: not "AI agents find bridge bugs at X% F1," but **what it
takes for an X to mean anything.**
