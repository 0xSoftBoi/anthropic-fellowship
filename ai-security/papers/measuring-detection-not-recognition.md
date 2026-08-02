<!--
  Working paper. Every number is reproducible from the committed repo; the exact command is
  given inline. No API key is required for any figure reported here (all LLM-dependent
  measurements are stated as designs with cost estimates, not results). Related-work citations
  were gathered via a structured literature sweep + adversarial novelty check; load-bearing
  entries were hand-verified against their source pages (see the note under References).
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

I identify **four confounds**, each of which lets the benchmark report a number that is not
measuring detection. For each I either measure its effect without a model API key or ship committed
tooling plus a pre-registered design — a distinction I keep explicit throughout, because today only
judge validity yields a key-free, model-level effect size:

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
controls, and — the paper's central construction — their positive complement: the **pre-audit
versions of those same contracts**, giving **16 diff-grounded vulnerability labels** whose ground
truth is the **git fix-commit diff** rather than any prose post-mortem. Because these contracts are
first-party and were never exploited, they have **no public post-mortem** — so a finding here
cannot be recall-of-a-write-up.

**Relation to prior work (stated up front, so the contribution is not overclaimed).** Every
individual confound has strong parents this paper confirms rather than discovers — PrimeVul (Ding
et al., 2024) owns the matched-pairs / git-diff / paired-recall-and-specificity core, and the exact
setup studied (GPT-4/Claude on compromised DeFi contracts) is David et al. (2023); full
per-confound crediting is in §8. Only two claims are defended as genuinely new: **(a) provably
un-memorizable first-party positives** — pre-audit contracts with no public post-mortem, so unlike
PrimeVul's mined third-party fix commits they cannot be recall-of-a-write-up; and **(b) a
mechanically verified structural sanitizer invariant**, so a decontamination F1 drop is
attributable to sanitizing, not a broken artifact. Everything else is a known failure mode
measured, for the first time jointly and with executable checks, in smart-contract security.

The contribution is not a capability number. It is a reusable method — tooling plus a construction
checklist — for telling whether a security-capability number means anything. The same structural
gap sits in today's frontier cyber evals (Cybench, CyberSecEval, NYU CTF): all-positive corpora
scored by flag oracles, where specificity is unmeasurable and no grader is validated — the
confounds instrumented here.

---

## 1. Introduction

Dangerous-capability evaluations are how frontier labs decide what a model can do, and those
decisions gate deployment (Anthropic's Responsible Scaling Policy; OpenAI's Preparedness
Framework; DeepMind's Frontier Safety Framework). An inflated score can flip a go/no-go threshold,
so the *validity* of a security-capability number — whether it measures the capability it claims —
is a safety quantity, not a methodological nicety. Anthropic's own "Challenges in Evaluating AI
Systems" (2023) names the three pathologies this paper operationalizes: benchmark contamination,
format fragility, and over-interpreting a single score; its third-party-evaluations initiative
(2024) explicitly asks that evals be "not in the training data" and use "diverse formats."

Each way a benchmark can report a number that is not measuring detection is, individually, known.
What is rarely done is to instrument several of them *at once, on one benchmark, with executable
checks*, and to report the resulting effect sizes. That is what this paper does, in the
smart-contract vulnerability-detection domain, using a benchmark I built and then audited until
it broke. Four confounds — prompt leakage (the answer in the input), memorization (the answer in
the weights), judge validity (the answer depends on who grades), and missing negative controls
(specificity unmeasurable) — are each measured key-free or given committed tooling plus a
pre-registered design, and each is credited to its prior literature. What is new is not the
individual techniques but their joint decomposition in this domain, plus two narrow primitives —
un-memorizable first-party positives and a verified sanitizer invariant (§8).

The same structural gap sits one level up, in the frontier cyber evaluations that gate real
deployment decisions (Cybench, Meta's CyberSecEval, NYU CTF): all-positive task corpora scored by
executable/flag oracles, where the model's false-positive rate is unmeasurable and no grader is
validated. The confounds instrumented here are theirs too; smart contracts are just where the
ground truth is crisp enough to measure them.

The nearest single prior work is David et al. (2023), "Do you still need a manual smart contract
audit?", which evaluates GPT-4/Claude on 52 previously-compromised DeFi contracts and reports ~40%
vulnerability-type identification with a high false-positive rate. That setup exhibits all four
confounds — a 100% vulnerable base rate with no negatives, every contract a famous hack with a
public post-mortem, no check for in-prompt bug descriptions, and detection scored without judge
controls. (Notably, David et al. *do* run a small injected-mutation arm on five fresh contracts,
reaching a best-case 78.7% true-positive rate — an early gesture at the un-memorizable-positive
idea this paper builds out with real, first-party, git-diff-labeled bugs rather than manual
injections.) This paper turns that class of setup into a validity study.

### 1.1 The object of study

BRIDGE-bench is a smart-contract vulnerability-detection benchmark: 24 verified, deployed
contracts across three DeFi domains (16 cross-chain bridges, 5 DEX/AMM, 3 lending — Euler, counted
under DEX/AMM, is strictly a lending/money-market protocol), each paired with a root-cause
vulnerability label an auditor would assign, drawn from public exploits 2021–2026 (full provenance
in the [datasheet](../docs/DATASHEET.md)). A model reads a contract and
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

### 1.3 Contributions

1. A **joint decomposition of four validity confounds** — prompt leakage, memorization, judge
   validity, missing negative controls — instrumented together on one smart-contract benchmark
   with executable, key-free checks, and reported effect sizes where they can be measured without
   a model key.
2. **Committed tooling** for each: a structural-invariant sanitizer, a judge grader-sensitivity +
   bootstrap harness, first-party negative controls, and matched vulnerable/fixed pairs — all run
   in CI.
3. **[New] Provably un-memorizable first-party positives** — pre-audit contracts with no public
   post-mortem, labeled from the first-party git fix-commit diff.
4. **[New] A mechanically verified structural safety invariant** on the sanitizer, so a
   decontamination F1 drop is attributable to sanitizing rather than to a broken artifact.
5. A **six-point construction checklist** (§7) and a datasheet, so the checks transfer to other
   security-capability benchmarks.

Only items 3 and 4 are claimed as genuinely new; items 1, 2, and 5 are integration and
method-transfer contributions whose parents are credited in §8.

### 1.4 The four confounds at a glance

| Confound (channel) | How measured | Effect / status (this paper) | Nearest prior |
|---|---|---|---|
| **C1 Prompt leakage** — answer in the *input* | grep the literal prompt for labels + prose; sanitizer | **13/24 SEVERE** at `raw` (diagnosed, key-free); effect size Δ(raw→stripped) needs a key | SWE-Bench+ (2024); Fang et al. (2024) |
| **C2 Memorization** — answer in the *weights* | anonymizer arm, Δ(stripped→anon); matched pairs | tooling + pre-registered design; **no measured effect yet** (needs a key) | Carlini et al. (2022); Yang et al. (2023) |
| **C3 Judge validity** — depends on *who grades* | re-score identical findings vs human gold + bootstrap | **37.1%→51.6%, Δ 14.5 pts** (measured, key-free) | Krumdick et al. (2025); Thakur et al. (2025) |
| **C4 No negative controls** — base rate 100% | first-party negatives (specificity) + matched pairs (recall) | static **zero-finding 75%**, static **recall 0/16** (key-free); model runs are design | PrimeVul (2024); David et al. (2023) |

The **status** column is the honest line through the paper: only C3 yields a key-free, model-level
effect size today; C1 is diagnosed key-free with its effect size left as a committed run; C2 and
the *model-side* of C4 are pre-registered designs with tooling shipped.

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

Every contract is a famous historical exploit — Nomad, Euler, Qubit, Cream, Compound, KyberSwap —
each with a widely circulated post-mortem published before the models under test were trained. When
Opus reports `missing_solvency_check` on the Euler module, at least three mechanisms could produce
that output: (i) compositional reasoning from source (the capability claimed), (ii) recall of the
post-mortem keyed off identifiers, (iii) prior familiarity shaping attention.
The design cannot distinguish them, so every reported number is
*detection-under-possible-memorization*. This is not hypothetical for this dataset in particular:
the **labels were themselves derived from those same post-mortems** (see
[`DATA_QUALITY.md`](../docs/DATA_QUALITY.md)), so ground truth and the likely-memorized text share
a source.

The sanitizer's third level (`anon`) is the control: rewrite each contract so the **bug is
bit-for-bit preserved** (invariant §2.1) but the identifiers that make it recognizable are gone.
Then two deltas separate the two confounds cleanly:

- **Δ(raw → stripped) = prompt leakage** — how much of the score was reading the answer.
- **Δ(stripped → anon) = recognition** — how much survives on de-identified but semantically
  identical code. Anonymization strips the cues behind both mechanisms (ii) and (iii), so this
  delta bounds recognition (post-mortem recall *plus* general familiarity) jointly; it does not
  isolate narrow memorization from familiarity.

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
38 bridge decisions, so for bridges we can re-score the *identical* findings with human labels and
measure how much the score depends on the grader. (The human labels are a single, in-sample
annotator — the benchmark's author — so this bounds *grader-dependence*, not the correct value;
§9.)

| Bridge scoring | Precision | Recall | **F1** |
|---|---|---|---|
| Haiku judge (committed) | 27.7% | 56.1% | **37.1%** |
| Human gold labels, same findings | 38.6% | 78.0% | **51.6%** |
| Human gold, 5 borderline labels flipped | — | — | **50.0%** |

**Two graders differ by 14.5 F1 points on identical model output** — plausibly comparable to the
model differences the benchmark exists to detect. The gap robustly demonstrates grader-*dependence*;
it does not establish that the human number is the correct one (the two hypotheses "conservative
judge" and "lenient self-annotation" are observationally identical here).

- **Fragility.** 27 "match" calls out of 53 produce the headline; one flipped decision moves it
  ≈1.1 points; +5 points costs 5 flips (9% of the corpus). A benchmark where 9% of grading
  decisions swing the headline 5 points is not a precision instrument — report a range.
- **Uncertainty.** 20,000-iteration bootstrap (contracts resampled; judge error propagated via
  Beta posteriors where no gold standard exists): bridges 95% CI **[39.7%, 63.8%]**, all-24
  **[38.5%, 57.4%]**. The committed 37.1%/35.0% fall *below* both lower bounds. This is by
  construction, not a separate finding: the interval injects modeled false-positive recovery (a
  Beta posterior over the judge's missed matches), so it is centred above the committed point — the
  point-below-interval gap is exactly the judge's modeled conservatism, not an error.
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

This is the paper's central construction, and it attacks Confounds 2 and 4 together, **without a
key.** Its novelty is narrow and scoped in §5.3 — the first-party, un-memorizable *provenance*, not
the matched-pair *method* itself, which is PrimeVul's. The matched pair is the fix for Confound 4,
not a fifth confound.

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
ground truth whether the model was perfect or useless). Static baseline: **75%** — 3/4 flagged with
nothing (a zero-finding *screen*, not a validated false-positive rate; n=4 admits no confidence
interval, and the one "failure" is a debatable centralization nit — the static analyzer raises
`unprotected_admin_function` twice on the bonds contract's owner functions). *Honesty caveats, stated:* the audits were the author's own manual passes
plus open-source tooling (not an external firm), the contracts are testnet-deployed, and a finding
here is not automatically wrong — it may be a real miss the self-audit made, which is why raw
finding-count is a **screen** and the source-aware judge (§4) adjudicates.

### 5.3 Matched pairs (recall without memorization)

**Reproduce:** `python -m agents.benchmark_runner --matched --no-claude` → `results_matched.json`.
Full doc: [`MATCHED_PAIRS.md`](../docs/MATCHED_PAIRS.md).

The negative controls answer "does the model over-flag clean code?" Their positive complement is
the measurement a *famous-exploit* benchmark cannot make: **16 diff-grounded vulnerability labels
with no public post-mortem, so a finding cannot be recall-of-a-write-up.** Matched vulnerable/fixed
pairs with git-fix-commit labels are not new — PrimeVul (Ding et al., 2024) and Risse & Böhme
(2024) build exactly this in C/C++, and PrimeVul's pair-wise metric (P-C/P-V/P-B/P-R) is already a
joint recall/specificity measurement on pairs. The distinction here is **provenance**: PrimeVul and
Risse mine *public, third-party* fix commits, which can themselves sit in a training corpus. Ours
are **first-party and never-exploited, with no public post-mortem** — so recall-of-a-write-up is
impossible — and the domain is Solidity, where (to our knowledge) no matched-pair set previously
existed. The construction:

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
flash-loan/LP-valuation bug — the bonded LP position is valued by a fictional `liquidity / 1e12`
term (raw Uniswap-v3 position liquidity treated as a USDC amount), so the pool can be
flash-manipulated to overmint discounted SUWP; a `recoverToken` that reserved only `totalStaked`
and so let the owner drain stakers' unclaimed bonus reserve; a `mint` callable on satellite chains
enabling cross-chain supply inflation. Several labels are privileged-role or invariant findings and
one is a guarded CEI-ordering issue — these are audit-grade labels, not all critical exploits. The
token is intentionally excluded — its only pre-audit change was a non-exploitable gas cap, and
labeling a non-bug as a positive is the mirror image of the leakage error in §2.

**Anti-leakage discipline (both directions).** For an exploit contract a leaky header states the
bug; for a *negative* it states "nothing to find here"; for a *matched positive*, naming the bug
in the source **is** answer leakage. So every committed `.sol` — positive and negative — carries
**provenance only** (repo, SHA, path); all bug/audit facts live in loader metadata and docs, never
in the prompt. A test enforces it.

**What the static baseline already shows:** our heuristic static baseline (`static_v2`) finds
**0 of 16**. `static_v2` is a regex/pattern analyzer, not a production detector — a classic tool
like Slither would plausibly flag the one guarded CEI/reentrancy label — so the claim holds
specifically for the **compositional valuation/accounting bugs** (the `liquidity / 1e12` valuation,
the `recoverToken` solvency miss), which is where the thesis lives and where memorization-free
ground truth matters most. The LLM's recall here, paired with its specificity on the fixed
counterparts, is the matched-pair result the key-holding run will produce.

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
| Negative-control zero-finding rate (static) | `--live --no-claude` + `specificity` | 75% (3/4 flagged with nothing; n=4, a screen) |
| Matched-pair recall (static) | `--matched --no-claude` | 0/16 |
| Dataset integrity | `python -m benchmarks.validate_dataset` | 5 domains, 31 source-bearing contracts |
| Test suite | `python -m pytest tests/ -q` | 46 passed, 1 skipped |

The **31** reconciles with the **24** thus: the 24 exploit contracts (3 domains) plus 4
negative controls and 3 matched pairs = 31 source-bearing contracts across the 5 registered
domains. The LLM-dependent measurements (Δ(raw→stripped), Δ(stripped→anon), the judge ablation
sweep, matched-pair and negative-control *model* runs) are specified with cost estimates and left
as the key-holding follow-up; the harnesses and scorers are committed and CI-checked.

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

Every technique below has established parents; the honest framing is that this paper transfers and
integrates them, adding two narrow primitives (§1). References with URLs are collected at the end.

**Contamination detection, and the memorization/leakage distinction.** A large family detects that
test data reached the model without controlling for it: black-box statistical tests (Oren et al.,
2023, *Proving Test Set Contamination*), outlier-token membership inference (Shi et al., 2023,
*Min-K% Prob*), guided-completion probes (Golchin & Surdeanu, 2023, *Time Travel in LLMs*), and
temporal natural experiments showing pre-cutoff data scores higher (Li & Flanigan, 2023, *Task
Contamination*; Roberts et al., 2023). Our conceptual parent is Magar & Schwartz (2022), *From
Memorization to Exploitation*, which shows test data can be memorized yet not exploited — so
presence-in-training does not by itself inflate a score; we split this into three channels
(answer-in-input, answer-in-weights, genuine capability). Carlini et al. (2022) supply the
mechanism (memorization scales with duplication, model size, context) that makes famous,
heavily-duplicated hacks the worst case and justifies an anonymizer. Closest *in technique* is Yang
et al. (2023), *Rephrased Samples*, which shows semantic-preserving rewrites defeat n-gram
decontamination — but it rewrites test items to *evade* filters, whereas we rewrite the *input* to
strip the answer while a structural invariant preserves task difficulty. Prevention/measurement
calls (Jacovi et al., 2023, *Stop Uploading Test Data*; Sainz et al., 2023, *NLP Evaluation in
Trouble*) frame the per-benchmark validity program; our Confound 1 is exactly the "solution appears
next to the data" failure Jacovi et al. warn against.

**Contamination and freshness in code benchmarks.** Controlling contamination on code costs 20–50
points: Riddell et al. (2024) measure 43.7 pt (HumanEval) / 50 pt (MBPP) pass@1 gaps between
contamination deciles, and LiveCodeBench (Jain et al., 2024) uses time-windowed problems as the
dominant freshness control. Our single closest code prior is **SWE-Bench+ (Aleithan et al.,
2024)**: auditing SWE-bench, it finds **32.67%** of passing patches had the fix leaked into the
issue report and **31.08%** passed on weak tests, dropping resolution from 12.47% to 3.97% — our
Confounds 1 and 4, one benchmark over. *The SWE-Bench Illusion* (2025) isolates the weights channel
(76% in- vs 53% out-of-benchmark file-path recall). Freshness cannot exist for a fixed set of
famous hacks, which is precisely why our matched first-party pre-audit contracts with git-diff
ground truth are the domain-appropriate substitute; we additionally separate leakage from
memorization and add negative controls, which the freshness line does not.

**LLM-as-judge validity.** The foundational ">80% agreement with humans" claim (Zheng et al.,
2023, *MT-Bench / Chatbot Arena*) is specific to open-ended chat and does not transfer to tasks
needing verifiable correctness — which is why we re-score with human gold labels (bridge F1 moves
14.5 points). Our closest prior is **Krumdick et al. (2025), *No Free Labels***: an ungrounded
judge agrees with experts only on questions it could itself answer, and expert references largely
close the gap. We extend it to code and to a *stronger* blindness — our judge never sees the
contract at all, so it cannot separate "true-of-the-code" from "synonymous-with-the-label," a gap
references alone cannot restore. Judges are also fragile and gameable: order-swaps flip 66/80
verdicts (Wang et al., 2023, *Not Fair Evaluators*), style beats correctness (*Style Over
Substance*, 2023/2024), and judge choice reshuffles rankings while high percent-agreement hides
multi-point gaps (Thakur et al., 2025, *Judging the Judges*) — consistent with our one-flip-of-53
≈1.1-point sensitivity, which we report as a single-benchmark descriptive statistic, not a general
claim.

**Vulnerability-detection evaluations and matched pairs.** **PrimeVul (Ding et al., 2024)** is our
closest vuln-detection prior and owns the methods core: matched vulnerable/fixed pairs, labels from
git fix commits, contamination control (chronological split + dedup), and a pair-wise correctness
metric that is exactly joint recall/specificity — with a 7B model dropping 68.26% → 3.09% F1 from
BigVul to PrimeVul. Risse & Böhme (2024) and their VulnPatchPairs show detectors cannot separate
vulnerable functions from their patched counterparts. SecLLMHolmes (Ullah et al., 2024) is the
closest analog to our anonymizer — renaming flips 26% of top-model answers — but treats
perturbation as a robustness test over hand-crafted CWE scenarios, not as a memorization/leakage
disentangler over real bugs. Fix-commit labeling is standard (Big-Vul, 2020; CVEfixes, 2021;
DiverseVul, 2023) with recurring label-noise complaints (Chakraborty et al., 2021), and the
validity-gap motif recurs (*Top Score on the Wrong Exam*, 2025, high scores from word-counts
alone). **We claim neither matched-pairs-from-git-diffs nor paired recall/specificity as novel** —
PrimeVul and Risse own them; our defensible additions are the Solidity domain, first-party
un-memorizable provenance, and the judge/leakage/negative-control axes this cluster does not touch.

**Smart-contract benchmarks.** David et al. (2023), *Do you still need a manual smart contract
audit?*, is the object of our study (§1): 52 previously-compromised contracts, ~40% type
identification, high false positives, post-mortem labels, 100% base rate. The domain's datasets
are structurally ~100% vulnerable — SmartBugs / SB Curated (Durieux et al., 2020) and later
catalogs list only buggy code, with labels usually post-hoc prose. Bug injection (SolidiFI,
Ghaleb & Pattabiraman, 2020) is the methodological ancestor of matched pairs but injects synthetic
snippets, whereas our 16 pre-audit bugs are real and exploitable and their labels come from the
actual fix commit. GPTScan (Sun et al., 2024) and static-tool comparisons report detectors without
simultaneously controlling leakage, memorization, judge dependence, and missing negatives — the
combined gap this paper fills.

**Counterfactual and matched-pair methodology.** Our fixed-vs-buggy pairs instantiate a method
family unified by one move: construct two inputs identical except the causal feature. Gardner et
al. (2020), *Contrast Sets*, is the tightest analog to our matched-pair construction (§5.3, the fix
for Confound 4): minimal label-flipping perturbations probing the local decision boundary, and
Kaushik et al. (2020), *Counterfactually-
Augmented Data*, is the conceptual parent. We differ in provenance: our perturbation is the *real*
security fix and the label is the git diff, making the pair immune to both leakage and
memorization. The confound-diagnosis lineage — Gururangan et al. (2018), *Annotation Artifacts*
(a hypothesis-only model hits 67% on SNLI); *Right for the Wrong Reasons* / HANS (McCoy et al.,
2019) — is the precedent for our leakage and judge critiques, and CheckList's Invariance test
(Ribeiro et al., 2020) is the template for our sanitizer's structural invariant.

**Evaluation science and construct validity.** Closest methodologically is **ABC (Zhu et al.,
2025), *Best Practices for Building Rigorous Agentic Benchmarks***: it audits real benchmarks,
quantifies inflation (up to 100%), ships a checklist, and empirically fixes CVE-Bench (−33%
overestimation). We follow the audit→quantify→checklist→fix pattern but go deep on one benchmark,
make the checks *executable* (a sanitizer with a verified structural invariant), separate two
contamination channels ABC does not distinguish, and build the negatives and matched pairs its
checklist calls for. Validity frameworks (BetterBench, Reuel et al., 2024; construct-validity
reviews) and position papers (Bowman & Dahl, 2021, *What Will it Take to Fix Benchmarking*; Raji et
al., 2021, *The Everything in the Whole Wide World Benchmark*) anchor the argument; our datasheet
sits in the *Datasheets for Datasets* (Gebru et al., 2018) lineage.

**Frontier cyber-capability evaluation.** Anthropic's *Challenges in Evaluating AI Systems* (2023)
is the canonical statement of the pathologies we operationalize. **Fang et al. (2024), *LLM Agents
can Autonomously Exploit One-day Vulnerabilities*** is the clearest external corroboration of
Confound 1: GPT-4 exploits **87%** of one-day CVEs with the CVE description in the prompt but only
**7%** without it — the answer-in-the-input effect our sanitizer measures, though they frame it as
a capability caveat, not a validity program, and never separate leakage from memorization. Across
the cyber landscape — Cybench (Zhang et al., 2024), NYU CTF Bench (2024), Meta's CyberSecEval suite
(2023–2024) — benchmarks are all-positive with executable/flag oracles, so false-positive
specificity is unmeasurable and judge validity is sidestepped, exactly the hole our negative
controls and judge study fill. Why this is high-stakes rather than academic is argued in §1 and
§10; here it is enough that the same four confounds sit in the evals the field already relies on.

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
measurement right is upstream of every deployment decision that depends on it. Anthropic's
third-party-evaluations initiative (2024) states the requirement this paper is built around
directly:

> "Too often, evaluations end up measuring model memorization because the data is in its training
> set. Where possible and useful, make sure the model hasn't seen the evaluation."

A matched pair of first-party, never-exploited contracts — labeled from a first-party git
fix-commit with no public post-mortem — is one concrete way to satisfy that requirement in a domain
where every other dataset is a famous, memorizable hack. Smart contracts are the cleanest testbed available — adversarial code,
unambiguous ground truth, a public incident record — but the four confounds and the six-point
checklist are domain-general: they transfer to any benchmark that pairs an artifact under test with
curated provenance or annotation metadata.

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

---

## References

Contamination & memorization:
- Oren et al. (2023), *Proving Test Set Contamination in Black Box Language Models*. https://arxiv.org/abs/2310.17623
- Shi et al. (2023), *Detecting Pretraining Data from LLMs (Min-K% Prob)*. https://arxiv.org/abs/2310.16789
- Golchin & Surdeanu (2023), *Time Travel in LLMs*. https://arxiv.org/abs/2308.08493
- Li & Flanigan (2023), *Task Contamination*. https://arxiv.org/abs/2312.16337
- Roberts et al. (2023), *Data Contamination Through the Lens of Time*. https://arxiv.org/abs/2310.10628
- Magar & Schwartz (2022), *Data Contamination: From Memorization to Exploitation*. https://aclanthology.org/2022.acl-short.18/
- Carlini et al. (2022), *Quantifying Memorization Across Neural Language Models*. https://arxiv.org/abs/2202.07646
- Yang et al. (2023), *Rethinking Benchmark and Contamination with Rephrased Samples*. https://arxiv.org/abs/2311.04850
- Jacovi et al. (2023), *Stop Uploading Test Data in Plain Text*. https://arxiv.org/abs/2305.10160
- Sainz et al. (2023), *NLP Evaluation in Trouble*. https://aclanthology.org/2023.findings-emnlp.722/

Code/freshness benchmarks:
- Aleithan et al. (2024), *SWE-Bench+*. https://arxiv.org/abs/2410.06992
- *The SWE-Bench Illusion* (2025). https://arxiv.org/abs/2506.12286
- Riddell et al. (2024), *Quantifying Contamination in Code Generation*. https://aclanthology.org/2024.acl-long.761/
- Jain et al. (2024), *LiveCodeBench*. https://arxiv.org/abs/2403.07974

LLM-as-judge:
- Krumdick et al. (2025), *No Free Labels*. https://arxiv.org/abs/2503.05061
- Zheng et al. (2023), *Judging LLM-as-a-Judge (MT-Bench / Chatbot Arena)*. https://arxiv.org/abs/2306.05685
- Wang et al. (2023), *Large Language Models are not Fair Evaluators*. https://arxiv.org/abs/2305.17926

Vulnerability detection & matched pairs:
- Ding et al. (2024), *Vulnerability Detection with Code Language Models: How Far Are We?* (PrimeVul). https://arxiv.org/abs/2403.18624
- Risse & Böhme (2024), *Uncovering the Limits of ML for Automatic Vulnerability Detection* (VulnPatchPairs). https://arxiv.org/abs/2306.17193
- Ullah et al. (2024), *SecLLMHolmes: LLMs Cannot Reliably Identify and Reason About Security Vulnerabilities*. https://arxiv.org/abs/2312.12575
- Bhandari et al. (2021), *CVEfixes*. https://arxiv.org/abs/2107.08760
- Chakraborty et al. (2021), *Deep Learning based Vulnerability Detection: Are We There Yet?*. https://arxiv.org/abs/2009.07235

Smart contracts:
- David et al. (2023), *Do you still need a manual smart contract audit?*. https://arxiv.org/abs/2306.12338
- Durieux et al. (2020), *SmartBugs*. https://arxiv.org/abs/2007.04771

Counterfactual / behavioral testing:
- Gardner et al. (2020), *Evaluating Models' Local Decision Boundaries via Contrast Sets*. https://arxiv.org/abs/2004.02709
- Kaushik et al. (2020), *Counterfactually-Augmented Data*. https://arxiv.org/abs/1909.12434
- Gururangan et al. (2018), *Annotation Artifacts in NLI Data*. https://aclanthology.org/N18-2017/
- Ribeiro et al. (2020), *Beyond Accuracy: Behavioral Testing with CheckList*. https://arxiv.org/abs/2005.04118

Evaluation science:
- Zhu et al. (2025), *Establishing Best Practices for Building Rigorous Agentic Benchmarks* (ABC). https://arxiv.org/abs/2507.02825
- Gebru et al. (2018), *Datasheets for Datasets*. https://arxiv.org/abs/1803.09010

Frontier cyber / safety:
- Anthropic (2023), *Challenges in Evaluating AI Systems*. https://www.anthropic.com/research/evaluating-ai-systems
- Anthropic (2024), *A new initiative for developing third-party model evaluations*. https://www.anthropic.com/news/a-new-initiative-for-developing-third-party-model-evaluations
- Fang et al. (2024), *LLM Agents can Autonomously Exploit One-day Vulnerabilities*. https://arxiv.org/abs/2404.08144
- Zhang et al. (2024), *Cybench*. https://arxiv.org/abs/2408.08926

*Citations were gathered via a structured literature sweep and an adversarial novelty check; the
load-bearing entries (PrimeVul, SWE-Bench+, David et al., No Free Labels, Fang et al.) were
verified by hand against their source pages. arXiv identifiers for a few very recent (2025–2026)
entries mentioned in passing were not all hand-verified and are cited conservatively.*
