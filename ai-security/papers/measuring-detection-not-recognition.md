<!--
  DRAFT — sections marked [[PENDING]] are filled after the literature review lands.
  Every number in this paper is reproducible from the committed repo; the exact command
  is given inline. No API key is required for any figure reported here (all LLM-dependent
  measurements are stated as designs with cost estimates, not results).
-->

# Measuring Detection, Not Recognition: Four Validity Confounds in AI Security-Capability Benchmarks

**Working paper — companion to BRIDGE-bench.** All figures reproduce from
[`github.com/0xSoftBoi/anthropic-fellowship`](https://github.com/0xSoftBoi/anthropic-fellowship)
(`ai-security/`). Reproduction commands are inline; none of the reported numbers require a model
API key.

---

## Abstract

Dangerous-capability evaluations decide what we believe a model can do. A vulnerability-detection
benchmark reports a single number — here, an F1 score — and that number is read as *capability*.
This paper is a case study in how much has to be true for that reading to be valid, using a
smart-contract vulnerability-detection benchmark I built and then audited until it broke.

I identify **four separable confounds**, each of which lets the benchmark report a number that is
not measuring detection, and I instrument all four cheaply:

1. **Prompt leakage** — the answer is *in the input*. 13 of 24 contracts (54%) shipped a
   provenance comment that described the bug; 4 contained a ground-truth label string directly.
2. **Memorization** — the answer is *in the weights*. Every contract is a famous exploit with a
   public post-mortem in training data, and the labels were derived from those same post-mortems.
3. **Judge validity** — the answer depends on *who grades*. The semantic-F1 headline is produced
   by an LLM-as-judge; scoring the identical model findings with human gold labels instead moves
   bridge F1 by **14.5 points** (37.1% → 51.6%). One flipped judge call out of 53 moves the
   headline ≈1.1 points, and the judge never sees the contract source.
4. **No negative controls** — every exploit contract has a bug, so the base rate is 100% and
   **specificity is unmeasurable**. A detector that flags everything scores identically to a real
   one.

For (1) I ship a sanitizer with a *structural safety invariant* (the code token stream and all
control-flow counts are preserved, so a decontamination F1 drop cannot be the sanitizer breaking
the contract). For (4) I add first-party, never-exploited, audit-hardened contracts as negative
controls, and — the paper's main new construction — their positive complement: the **pre-audit
versions of those same contracts**, giving 16 real, exploitable bugs the model cannot have
memorized, with ground truth taken from the **git fix-commit diff** rather than any prose
post-mortem. This measures recall where recall cannot be recall-of-a-write-up: the one
measurement a famous-exploit benchmark structurally cannot make.

The contribution is not a capability number. It is a reusable method — tooling plus a construction
checklist — for telling whether a security-capability number means anything.

---

## 1. Introduction

[[PENDING — positioned against the literature. Core claims to make here, after the novelty check:
the framing that eval validity is upstream of every deployment decision; that these four confounds
are individually known but rarely instrumented together on one security benchmark; the honest
statement of what is genuinely new vs. what extends prior work (esp. PrimeVul, SecLLMHolmes,
counterfactual-data, LLM-judge-bias literature).]]

### 1.1 The object of study

BRIDGE-bench is a smart-contract vulnerability-detection benchmark: 24 verified, deployed
contracts across three DeFi domains (16 cross-chain bridges, 5 DEX/AMM, 3 lending), each paired
with a root-cause vulnerability label an auditor would assign, drawn from public exploits
2021–2026 (full provenance in the [datasheet](../docs/DATASHEET.md)). A model reads a contract and
emits findings; findings are scored against the labels by exact/synonym string match and, for the
misses, by an LLM-as-judge that decides semantic equivalence. The headline is Opus 4.8 at **35%
semantic F1 / 54% recall** over the 24 contracts.

Smart contracts are a near-ideal testbed for capability measurement: the code is adversarial, the
ground truth is unusually crisp (money either moved or it did not), and there is a public incident
record. That last property is also the problem — it is exactly what makes memorization plausible.

### 1.2 Why validity, not capability, is the contribution

The four confounds below are the reason the 35% cannot be cited as detection performance without
qualification. Each is individually cheap to measure; none is standard practice in the
security-capability benchmarks this work builds on. The rest of the paper measures the ones that
can be measured without a key, ships the tooling for the ones that need one, and states — for each
— exactly what the current evidence does and does not support.

---

## 2. Confound 1 — Prompt leakage: the answer in the input

**Reproduce:** `python -m benchmarks.sanitize` (no key).

Each committed `.sol` file begins with a human-readable provenance header. The loader reads the
file whole and the analyzer feeds it into the prompt, so **the header goes to the model.** A scan
of the leading comment block against three severity tiers:

| Level | What the model sees | SEVERE | MODERATE | IDENTITY | CLEAN |
|-------|--------------------|-------:|---------:|---------:|------:|
| `raw` (as committed / as scored) | file verbatim, header included | **13 (54%)** | 7 | 3 | 1 |
| `stripped` | comments removed | 0 | 0 | 19 | 5 |
| `anon` | + protocol identity removed | 0 | 0 | 0 | 24 |

- **SEVERE** — header names the exploit *and* describes the mechanism, or states a label.
- **MODERATE** — names the exploit/loss but not the mechanism.
- **IDENTITY** — no exploit narrative, but the protocol is still identifiable (a memorization cue).
- **CLEAN** — provenance only.

Severity is scored on the **author-injected header**, not on upstream NatSpec/OpenZeppelin
strings that ship with the real verified source (a human auditor sees those too; counting them
inflated an earlier version of this scan to 92%). The machine check
(`benchmarks/leakage_report.json`) further finds a **ground-truth label string in the header of 4
contracts** — Euler states the label token `missing_solvency_check`; two headers say "reentrancy";
one says "arbitrary external call."

**The case study (Euler).** Euler's header ends `CORRECTED label: missing_solvency_check`, on
`EToken.donateToReserves`. Opus's top finding was `missing_solvency_check`, scored a true positive.
But `donateToReserves` **is not in the committed source** — the file is the Euler *module bundle*,
not the `EToken` module where the bug lives (`grep -c donateToReserves …` → 1, the comment). The
model could not have derived that finding from the code; the label was in the prompt and the
scorer counted it. Pinned by a regression test so it cannot silently reappear.

**What this implies.** Every F1 in the repo produced before this fix — including the 35% headline
— was measured under prompt conditions that leaked the answer for over half the corpus. Those are
upper bounds contaminated by leakage. What it does *not* imply: that the model found nothing — most
headers describe the mechanism without stating the label, and the model still had to locate it in
source and phrase a finding. The size of the effect is exactly Δ(raw→stripped), which needs a key.

**The generalization** (the cheap check any benchmark author can run before publishing):

> Print the literal string the model receives. Grep it for your labels. Then grep it for a prose
> description of the answer.

Any benchmark that pairs an artifact with curated provenance/annotation metadata is exposed:
CVE corpora with advisory text, bug-bounty sets with report summaries, incident datasets with
post-mortem links. Full audit: [`LEAKAGE_AUDIT.md`](../docs/LEAKAGE_AUDIT.md).

### 2.1 The sanitizer and its safety invariant

If sanitizing broke a contract, a drop in F1 would measure the sanitizer, not leakage. So the
sanitizer (`benchmarks/sanitize.py`) enforces a **structural equivalence invariant**, checked for
every contract at every level in CI, and refuses to report if it fails:

1. Comment stripping is **string-literal aware** (`"https://…"`, `"/* not a comment */"` survive);
   the code token stream is bit-identical before and after.
2. Renaming is whole-word, uniform, keyword-guarded, and collision-checked; the anonymized token
   stream matches the stripped one under the rename map, so control flow and call graph are
   unchanged.
3. Structural fingerprints (counts of `function`/`if`/`for`/`while`/`require`/`revert`/`return`/
   `;`/braces) must match exactly.

This is *structural* equivalence, not a compile check (there is no `solc` in the environment) —
stated as a limitation, not papered over. The verifier earned its keep during development: the
address-neutralizing regex was rewriting the first 40 hex chars of 64-char `bytes32` literals
(function selectors, keccak constants), which would have changed dispatch; `verify()` caught it on
5 contracts before any experiment ran, and it is now a regression test.

---

## 3. Confound 2 — Memorization: the answer in the weights

**Design (needs a key); tooling shipped.** Full spec: [`CONTAMINATION.md`](../docs/CONTAMINATION.md).

Every contract is a famous historical exploit — Nomad, Euler, Qubit, Wormhole, Cream, Compound,
KyberSwap — each with a widely circulated post-mortem published before the models under test were
trained. When Opus reports `missing_solvency_check` on the Euler module, at least three mechanisms
could produce that output: (i) compositional reasoning from source (the capability claimed),
(ii) recall of the post-mortem keyed off identifiers, (iii) prior familiarity shaping attention.
The design cannot distinguish them, so every reported number is
*detection-under-possible-memorization*. This is not hypothetical for this dataset in particular:
the **labels were themselves derived from those same post-mortems** (see
[`DATA_QUALITY.md`](../docs/DATA_QUALITY.md)), so ground truth and the likely-memorized text share
a source.

The sanitizer's third level (`anon`) is the control: rewrite each contract so the **bug is
bit-for-bit preserved** (invariant §2.1) but the identifiers that make it recognizable are gone.
Then two deltas separate the two confounds cleanly:

- **Δ(raw → stripped) = prompt leakage** — how much of the score was reading the answer.
- **Δ(stripped → anon) = memorization** — how much survives on de-identified but semantically
  identical code.

```bash
BENCH_SANITIZE=raw      python -m agents.benchmark_runner --real --agentic   # leaky baseline
BENCH_SANITIZE=stripped python -m agents.benchmark_runner --real --agentic   # leakage removed
BENCH_SANITIZE=anon     python -m agents.benchmark_runner --real --agentic   # + identity removed
```

A large Δ(stripped→anon) is evidence that recognition, not analysis, carried the score; a
near-zero Δ is real evidence the model reads code. The null is the stronger result for the thesis,
which is exactly why the design is pre-registered rather than fitted after the fact. Cost is a
weekend, not a research program: ≈$40–50 at Opus pricing over 24 contracts (measured reference:
the committed 8-contract DEX+lending pass cost $16.29), less on a cheaper model.

Section 5 gives the complementary attack that needs no key at all: rather than de-identify a
memorized contract, **use contracts the model never saw.**

---

## 4. Confound 3 — Judge validity: the answer depends on who grades

**Reproduce:** `python -m agents.judge_uncertainty` (no key). Full analysis:
[`JUDGE_VALIDITY.md`](../docs/JUDGE_VALIDITY.md).

The semantic F1 is a function of **53 binary LLM-as-judge calls** (for each label the string
matcher missed, does some unmatched finding refer to the same bug?), and it has always been
reported as a point estimate. `benchmarks/judge_gold_standard.json` hand-labels the truth for the
38 bridge decisions, so for bridges we can score with human labels and read off the judge's cost:

| Bridge scoring | Precision | Recall | **F1** |
|---|---|---|---|
| Haiku judge (committed) | 27.7% | 56.1% | **37.1%** |
| Human gold labels, same findings | 38.6% | 78.0% | **51.6%** |
| Human gold, 5 borderline labels flipped | — | — | **50.0%** |

**Two graders differ by 14.5 F1 points on identical model output** — a larger effect than most of
the model differences the benchmark exists to detect.

- **Fragility.** 27 "match" calls out of 53 produce the headline; one flipped decision moves it
  ≈1.1 points; +5 points costs 5 flips (9% of the corpus). A benchmark where 9% of grading
  decisions swing the headline 5 points is not a precision instrument — report a range.
- **Uncertainty.** 20,000-iteration bootstrap (contracts resampled; judge error propagated via
  Beta posteriors where no gold standard exists): bridges 95% CI **[39.7%, 63.8%]**, all-24
  **[38.5%, 57.4%]**. The committed 37.1%/35.0% fall *below* both lower bounds — consistent with a
  systematically conservative judge, not a noisy one.
- **The structural blind spot.** The judge **never sees the contract source.** It compares a label
  to a finding string, so it can answer "do these mean the same thing?" but not "is this finding
  true of this code?" A finding synonymous with the label but wrong about the contract must be
  credited. Euler again makes it concrete: the vulnerable function isn't in the source, yet
  `missing_solvency_check` scored a true positive under both the judge *and* the human gold —
  neither was looking at the code.

The correction is a *range*, not a point, and a judge design that can see the artifact.
`agents/judge_ablation.py` sweeps model × framing × source-visibility (18 configs, 954 calls,
≈$11.51) and reports F1 per config plus inter-judge Cohen's κ — the whole judge-validity study
costs about twelve dollars, which is the main reason it should just be run.

---

## 5. Confound 4 — No negative controls, and the matched-pair positive that fixes it

This is the paper's main new construction. It attacks confounds 2 and 4 together, **without a
key.**

### 5.1 The hole

All 24 exploit contracts carry a bug, so the base rate is 100% and the model's **false-positive
rate is unmeasurable.** A detector that flags every contract scores identically to a real one.
Half of "is this a good detector?" — the specificity half — the exploit set structurally cannot
answer. And every positive is a famous hack (confound 2), so even the recall half is
recall-under-memorization.

### 5.2 Negative controls (specificity)

**Reproduce:** `python -m agents.benchmark_runner --live --no-claude && python -m agents.specificity results_live.json`.
Full doc: [`LIVE_DATASET.md`](../docs/LIVE_DATASET.md).

I add the first-party Solidity that **Suwappu**
([`github.com/0xSoftBoi/suwappubot`](https://github.com/0xSoftBoi/suwappubot), my own cross-chain
DeFi SDK) deploys: a token, a Superfluid real-yield staking contract, protocol-owned-liquidity
bonds, and a LayerZero omnichain token. These went through three manual audit passes (nine
critical/high bugs found and fixed) plus Slither/Aderyn/Mythril/Medusa. They are **first-party,
never exploited, with no incident in any training set** — so `ground_truth.vulnerabilities = []`,
`negative_control = True`, and the honest label is "no known critical/high source bug."

| Property | Exploit domains | Negative controls |
|---|---|---|
| In training data as an incident | Yes | **No** |
| Base rate of bugs | 100% | ≈0% (audit-hardened) |
| Measures | recall | **specificity** |

Scored by **specificity = (contracts flagged with nothing) / (total)**, not F1 (F1 is 0 on empty
ground truth whether the model was perfect or useless). Static baseline: **75%** (3/4 clean; the
static analyzer raises `unprotected_admin_function` twice on the bonds contract — a centralization
nit on owner functions). *Honesty caveats, stated:* the audits were the author's own manual passes
plus open-source tooling (not an external firm), the contracts are testnet-deployed, and a finding
here is not automatically wrong — it may be a real miss the self-audit made, which is why raw
finding-count is a **screen** and the source-aware judge (§4) adjudicates.

### 5.3 Matched pairs (recall without memorization)

**Reproduce:** `python -m agents.benchmark_runner --matched --no-claude` → `results_matched.json`.
Full doc: [`MATCHED_PAIRS.md`](../docs/MATCHED_PAIRS.md).

The negative controls answer "does the model over-flag clean code?" Their positive complement is
the one measurement a famous-exploit benchmark cannot make: **real, exploitable bugs the model
cannot have memorized.** The construction:

- Take the **pre-audit versions** of the same first-party contracts — the source at the parent of
  each contract's earliest audit-fix commit, so it carries every bug the passes later removed.
- Label each bug directly from the **fix-commit diff**. The ground truth is the diff itself —
  `git show <sha> -- contracts/<file>` reproduces it — which is strictly stronger than a prose
  post-mortem and, unlike every exploit-domain label, **not in any training set.**
- Pair each buggy contract to its fixed counterpart in the negative-control set, so the *same*
  contract yields a recall measurement (buggy) and a specificity measurement (fixed).

| | Exploit domains | Matched pairs |
|---|---|---|
| Bug in training data | Yes (famous hack) | **No** (first-party) |
| Ground truth from | public post-mortem (prose) | **git fix-commit diff** |
| Fixed counterpart for specificity | none | **yes** |

**16 diff-grounded labels across 3 contracts** (bonds, staking, OFT): e.g. a critical
flash-loan/LP-valuation bug (LP decomposed at spot price, valued by a fictional `liquidity / 1e12`
term); a `recoverToken` that reserved only `totalStaked` and so let the owner drain stakers'
unclaimed bonus reserve; a `mint` callable on satellite chains enabling cross-chain supply
inflation. The token is intentionally excluded — its only pre-audit change was a non-exploitable
gas cap, and labeling a non-bug as a positive is the mirror image of the leakage error in §2.

**Anti-leakage discipline (both directions).** For an exploit contract a leaky header states the
bug; for a *negative* it states "nothing to find here"; for a *matched positive*, naming the bug
in the source **is** answer leakage. So every committed `.sol` — positive and negative — carries
**provenance only** (repo, SHA, path); all bug/audit facts live in loader metadata and docs, never
in the prompt. A test enforces it.

**What the static baseline already shows:** `static_v2` finds **0 of 16** — the "static analysis
fails on real compositional bugs" thesis, now on ground truth with no memorization confound. The
LLM's recall here, paired with its specificity on the fixed counterparts, is the matched-pair
result the key-holding run will produce.

### 5.4 How the labels were verified

1. **Discover** the audit-fix commits via `git log` over `contracts/*.sol` (each commit message is
   an explicit audit report).
2. **Extract** the security fixes from each diff (one agent per commit), emitting
   `{contract, vuln_type, severity, mechanism, evidence}` and marking refactors/gas-caps/renames
   as *not* security fixes.
3. **Verify** each bug is present in the buggy snapshot by reading the diff against
   `git show <snapshot>:contracts/<file>`; the two headline bugs were confirmed by hand.

*Honest limit:* the snapshot predates all passes, so it carries several bugs at once; a model
finding outside the label set may be a real bug at a different line or a false positive — the
source-aware judge adjudicates, as everywhere. Severities are the audit's own, not formal CVSS.

---

## 6. Results summary (reproducible, key-free)

| Measurement | Command | Result |
|---|---|---|
| Prompt leakage | `python -m benchmarks.sanitize` | 13/24 SEVERE at `raw`; 0 at `stripped`/`anon`; invariant holds |
| Sanitizer safety invariant | (same) | structural equivalence for all 24 × 3 levels |
| Judge grader-sensitivity | `python -m agents.judge_uncertainty` | 37.1% → 51.6% (Δ 14.5 pts); 1 flip ≈1.1 pts |
| Judge bootstrap CI | (same) | bridges [39.7, 63.8]; all-24 [38.5, 57.4] |
| Negative-control specificity (static) | `--live --no-claude` + `specificity` | 75% (3/4 clean) |
| Matched-pair recall (static) | `--matched --no-claude` | 0/16 |
| Dataset integrity | `python -m benchmarks.validate_dataset` | 5 domains, 31 source-bearing contracts |
| Test suite | `python -m pytest tests/ -q` | 46 passed, 1 skipped |

The LLM-dependent measurements (Δ(raw→stripped), Δ(stripped→anon), the judge ablation sweep,
matched-pair and negative-control *model* runs) are specified with cost estimates and left as the
key-holding follow-up; the harnesses and scorers are committed and CI-checked.

---

## 7. A construction standard for security-capability evals

From the four confounds, a checklist any benchmark author can run before publishing a number —
cheap, and none of it standard practice today:

1. **Print the literal prompt and grep it for your labels** (and for a prose description of the
   answer). Separate author-injected annotation from upstream artifact content.
2. **Report a de-identified arm** with a verified semantic-preservation invariant, so a
   decontamination delta cannot be the perturbation breaking the artifact.
3. **State whether the labeled bug is even present in the supplied code** (the Euler failure).
4. **Report a grader-sensitivity range, not a point estimate**, with at least one judge arm that
   can see the artifact — not just the label.
5. **Include negative controls** (measure specificity, not only recall) and, where possible,
   **matched positives with labels from outside any training corpus** (fix-commit diffs).
6. **Publish a datasheet** ([Gebru et al., 2018](https://arxiv.org/abs/1803.09010)) and the
   perturbation/label scripts, so every delta is reproducible.

---

## 8. Related work

[[PENDING — filled from the literature review. Themes: contamination detection & memorization;
contamination in code/freshness benchmarks; LLM-as-judge bias & calibration; LLM/DL
vulnerability-detection evals and their validity (PrimeVul, SecLLMHolmes, Risse & Böhme,
DiverseVul, Big-Vul/CVEfixes); smart-contract detection benchmarks; counterfactual/matched-pair &
behavioral-testing methodology; evaluation science / construct validity / leaderboard critiques;
frontier dangerous-capability & cyber evaluations (Anthropic RSP + "Challenges in Evaluating AI
Systems", METR, UK AISI Inspect, DeepMind FSF, Meta CyberSecEval). Each theme gets a paragraph
that cites by title+year and says how this work relates.]]

---

## 9. Threats to validity (of this paper's own claims)

- **Single-author, single-annotator gold standard.** The judge gold labels are one person's
  judgment, in-sample (the same 38 decisions), authored by the person whose benchmark is graded —
  a standing incentive toward leniency. Five self-flagged borderline labels bound the worry
  (flipping all five moves 1.6 points) but do not remove it. A second annotator + a held-out
  standard is the first follow-up.
- **Negative controls are a softer negative than a paid audit** — author's own manual passes plus
  open-source tooling, testnet-deployed. "No known critical bug," not "provably clean."
- **The matched-pair snapshot carries several bugs at once**, so out-of-label findings are
  ambiguous without the source-aware judge; severities are the audit's, not CVSS.
- **Structural, not compiled, equivalence** for the sanitizer (no `solc` available).
- **Small n.** 24 exploit contracts + 3 matched pairs + 4 negative controls; the bootstrap
  intervals are wide, and DEX/lending judge error is extrapolated from bridges.
- **The verify fan-out for the matched-pair labels was flaky** (one adversarial verdict landed
  cleanly, a reclassification this paper folds in); the labels stand on the diffs, read directly,
  and re-running the adversarial verify is a documented follow-up.

---

## 10. Why this is safety-relevant, not just crypto

Dangerous-capability evaluations are how we decide what models can do. A contaminated eval reports
capability that isn't there — or masks capability that is. Getting vulnerability-detection
measurement right is upstream of every deployment decision that depends on it. Smart contracts are
the cleanest testbed available — adversarial code, unambiguous ground truth, a public incident
record — but the four confounds and the six-point checklist are domain-general: they transfer to
any benchmark that pairs an artifact under test with curated provenance or annotation metadata.

**The method is the contribution; the domain is where it executes fastest.**

---

## Reproducibility

Everything above runs CPU-only, no API key, from `ai-security/`:

```bash
python -m benchmarks.validate_dataset            # dataset integrity (5 domains)
python -m pytest tests/ -q                        # 46 pass, 1 skipped
python -m benchmarks.sanitize                     # leakage audit + safety invariant
python -m agents.judge_uncertainty                # judge grader-sensitivity + bootstrap CI
python -m agents.benchmark_runner --live --no-claude && python -m agents.specificity results_live.json
python -m agents.benchmark_runner --matched --no-claude
```

The CI workflow (`.github/workflows/ci.yml`) runs all of these on every push.

## Appendix — companion documents

- [`LEAKAGE_AUDIT.md`](../docs/LEAKAGE_AUDIT.md) — prompt leakage, full audit + Euler case study
- [`CONTAMINATION.md`](../docs/CONTAMINATION.md) — memorization confound + pre-registered design
- [`JUDGE_VALIDITY.md`](../docs/JUDGE_VALIDITY.md) — grader-dependence, full analysis
- [`LIVE_DATASET.md`](../docs/LIVE_DATASET.md) — negative controls / specificity
- [`MATCHED_PAIRS.md`](../docs/MATCHED_PAIRS.md) — matched positives, git-diff labels
- [`DATASHEET.md`](../docs/DATASHEET.md) — dataset datasheet (Gebru et al.)
- [`DATA_QUALITY.md`](../docs/DATA_QUALITY.md) — label audit and corrections
