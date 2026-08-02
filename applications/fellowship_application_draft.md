# Anthropic Fellows Program — Application Draft

## Track: AI Security Fellow

---

## Research Proposal: Are We Measuring Vulnerability Detection, or Recognition?

### Problem

AI-agent vulnerability detection is being evaluated on benchmarks built from
*famous historical exploits*. That construction has a validity problem, and I
found a concrete instance of it in my own work.

I built BRIDGE-bench: 24 real verified contracts across bridges, DEX, and
lending, with hand-audited labels and a validated LLM-judge. Opus 4.8 scored
35% semantic F1 / 54% recall — a result I was ready to write up.

Then I printed the exact string the model receives, and grepped it.

**13 of 24 prompts (54%) contained a comment describing the bug in prose. Two
stated the ground-truth label verbatim.** The contracts' provenance headers —
written for human auditability — were being fed to the model along with the
source.

The sharpest case is Euler. Its header reads `...donateToReserves had no
account health/solvency check ... CORRECTED label: missing_solvency_check`.
Opus's top finding was `missing_solvency_check`, scored a **true positive** —
and `donateToReserves` **is not in the committed source**. The bug was not
there to find. The answer was.

I doubt I am the only one with this problem. The same shape — artifact under
test bundled with curated annotation metadata — recurs in CVE corpora with
advisory text, bug-bounty datasets with report summaries, and incident
datasets with post-mortem links. Nobody publishes the exact prompt string, so
nobody greps it.

### Proposed Research

Shift the question from *"can an agent find bridge bugs?"* to **"what do
security-capability benchmarks actually measure, and how do we build ones that
measure detection?"** Three contributions:

**1. A validity methodology, with tooling**

Three independent ways a security-capability benchmark reports a number that
isn't measuring detection — separable, and each cheap to measure:

- **Prompt leakage** — the answer is in the input. Found, fixed, and now
  regression-tested in my repo (`benchmarks/sanitize.py`).
- **Memorization** — the answer is in the weights. The contract is famous, its
  post-mortem is in training data, and recognition substitutes for analysis.
- **Judge validity** — the answer depends on who grades. I measured this one
  too: scoring the *same* model findings with my human gold labels instead of
  the LLM judge moves bridge F1 from **37.1% to 51.6%**. A 14.5-point swing
  from changing nothing but the grader — larger than the model differences the
  benchmark exists to detect. One flipped judge call out of 53 moves the
  headline ~1.1 points.
- **No negative controls** — every exploit contract has a bug, so the base rate
  is 100% and specificity is unmeasurable. I added a **negative-control domain**:
  first-party, *unexploited*, audit-hardened contracts from a live cross-chain
  DeFi SDK, with no incident in any training set. It measures whether the model
  over-flags hardened, unfamiliar code — the half of "good detector" a
  famous-exploit benchmark structurally cannot show, and the direct answer to
  "why only test on things that got hacked?" Its **positive complement is built
  too**: the *pre-audit* versions of those same contracts, giving 16 real,
  exploitable bugs the model cannot have memorized — with ground truth taken not
  from a prose post-mortem but from the **git fix-commit diff** itself. That is
  the one measurement a famous-exploit benchmark cannot make: recall where recall
  can't be recall-of-a-write-up.

The harness now runs at three levels — `raw` / `stripped` (comments removed) /
`anon` (protocol identity removed, semantics preserved) — through one choke
point, so **Δ(raw→stripped)** isolates leakage and **Δ(stripped→anon)**
isolates memorization. Sanitization is guarded by a safety invariant (token
stream and control-flow counts must be unchanged) so a drop in F1 cannot be the
sanitizer breaking contracts. That verifier already caught a real bug of mine:
the address-neutralizing regex was corrupting `bytes32` function selectors.

**2. Re-measurement, and the honest number**

Re-run the committed 24-contract Opus benchmark at all three levels and publish
all three, including whatever it does to my own headline. If Δ(raw→stripped) is
large, my 35% was substantially reading comments — and that is the finding. If
Δ(stripped→anon) is large, exploit-derived benchmarks measure recognition
generally. If both are small, the capability claim survives its strongest
attack and is worth much more than it was before. **I do not know which, which
is why it is worth running.**

**3. A construction standard for security-capability evals**

From the deltas plus the audits, a short checklist for anyone building these
benchmarks: print the literal prompt and grep it for your labels; separate
author-injected annotation from upstream artifact content; report a
de-identified arm; state whether the labeled bug is even present in the supplied
code; and report a grader-sensitivity range rather than a point estimate — with
at least one arm where the judge can see the artifact, not just the label.
Cheap, and none of it is standard practice today.

### Why this is safety-relevant, not just crypto

Dangerous-capability evaluations are how we decide what models can do. A
contaminated eval reports capability that isn't there — or masks capability
that is. Getting vulnerability-detection measurement right is upstream of every
deployment decision that depends on it, and smart contracts are just the
cleanest testbed I have: adversarial code, unambiguous ground truth (money
moved), and a public incident record. The method is the contribution; the
domain is where I can execute fastest.

### Why Me

I'm not coming from academia — I'm a builder, and the relevant evidence is that
I audited my own result until it broke:

- **I found the defect in my own benchmark and published it.** Nobody asked me
  to grep my prompts. The finding cost me my headline number and is now the
  strongest thing in the repo. That is the disposition this work needs — an
  eval you cannot bring yourself to attack is not an eval.
- **This is the third time I've corrected my own record.** I audited the
  dataset and found mislabeled exploits (a "$80M Compound oracle hack" that
  never happened; two Cream incidents conflated), and rebuilt the lending
  domain around verified source bugs before reporting any F1. I caught a
  methodological mistake in my mech-interp work (single-position patching of a
  multi-token entity) and documented it rather than quietly fixing it.
- **8+ years in DeFi infrastructure, and I ship it.** I build Suwappu, a live
  cross-chain DeFi SDK — its own audited contracts became the benchmark's
  negative-control set. I know what these contracts do and how they get drained,
  which is why I can label ground truth and tell a real bug from an audit nitpick.
- **Working code, not just ideas.** Provider-agnostic harness (any hosted or
  local model through one path), validated LLM-judge, leakage sanitizer with a
  safety invariant, a negative-control domain with a specificity scorer, a
  matched buggy/fixed-pair domain labeled from git fix diffs, 46 CPU-only tests
  in CI. Day-1 ready.
- **Strong Python + Rust**, familiar with Solidity, ethers/web3.

What I don't have: a PhD or ML publications. I'm betting that finding the
measurement bug is worth more than another point of F1.

### Timeline (4 months)

- **Month 1 — measure the deltas.** Re-run the committed 24-contract Opus
  benchmark at `raw` / `stripped` / `anon`; publish all three plus the revised
  honest number. Run the judge sweep (`judge_ablation.py`, ~$12 for 18
  configurations) — including the source-visible arm, which is the only one that
  can tell a finding that is *correct about the code* from one that merely
  matches the label. Add a second labeler for inter-annotator agreement and a
  held-out judge gold standard (the current one is in-sample, n=26 positives).
- **Month 2 — generalize the audit.** Apply the leakage scan to other public
  security-capability benchmarks (SCONE-bench, CVE- and bug-bounty-derived
  sets). Question: is this repo's defect idiosyncratic or endemic? Either
  answer is worth publishing.
- **Month 3 — rebuild for validity.** Expand toward 50+ contracts under the
  construction standard: post-cutoff holdout arm, annotation stored *outside*
  the artifact, verification that the labeled bug is present in the supplied
  code, de-identified arm reported by default. Grow the negative-control set
  (external dependencies are already catalogued) and extend the matched
  buggy/fixed-pair domain — the first 16 diff-grounded positives from Suwappu's
  own audit history are already built; scale them and add other repos with clean
  fix-commit histories, so the zero-memorization positive set grows alongside the
  negatives.
- **Month 4 — write up**, release the tooling as a reusable package, and
  publish the checklist.

### Expected Output

- Paper: *"Measuring Detection, Not Recognition: Prompt Leakage and
  Memorization in AI Security-Capability Benchmarks"*
- Open-source: the leakage/anonymization tooling as a standalone package any
  benchmark author can run, plus the corrected BRIDGE-bench
- A construction checklist for security-capability evals

---

## Supplementary: Mechanistic Interpretability Portfolio

To demonstrate technical range beyond my DeFi domain, I spent a week
doing hands-on mech interp research. This is capability demonstration,
not novelty claims.

**What I did:**
- Replicated ROME-style causal tracing (Meng et al. 2022) across
  GPT-2 small, Pythia-70m, and Pythia-160m using TransformerLens
- Confirmed factual recall resolves at 75-83% network depth
- Investigated negation processing: added mechanistic evidence
  (layer-level localization of negation vs factual signals) to
  the well-known finding that LLMs fail at negation
- Made a methodological mistake (single-position patching of
  multi-token entities), caught it, documented it

**What this shows:**
- I can pick up a new technical domain (mech interp) and produce
  working experiments in days, not months
- I read the literature, identify when my results are replicating
  vs extending prior work, and frame honestly
- I'm comfortable with the TransformerLens/PyTorch research stack

**What this does NOT show:**
- Novel mech interp findings (the field has covered this ground)
- Deep theoretical understanding of superposition, SAEs, or
  circuit tracing (I'm still learning)

5 experiments, 2 writeups, documented on GitHub.

---

## About Me

Systems engineer and startup founder, 8+ years in crypto/DeFi
infrastructure. Based in the DC defense corridor. Currently building
SensorForge (open-source robotics data capture) and exploring
AI safety research as a career transition.

I'm motivated by reducing catastrophic risks from advanced AI systems.
The concrete version of that, for me, is measurement: we decide what
models are allowed to do based on evaluations, and an evaluation that
measures the wrong thing is a safety failure that looks like a result.
Smart contracts are where I can test that claim fastest — adversarial
code, ground truth denominated in money moved, a public incident record
— but the failure mode I found is not specific to them.

I don't have a PhD or prior ML publications. What I have is the ability
to ship working systems fast, enough domain depth to label ground truth
honestly, and a demonstrated willingness to run the experiment that
costs me my own headline number.

Code: github.com/0xSoftBoi/anthropic-fellowship
Start here: `ai-security/docs/LEAKAGE_AUDIT.md`
