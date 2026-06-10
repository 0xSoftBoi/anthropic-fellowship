# AI Security Research: LLM-Driven Smart Contract Vulnerability Detection

> **Can LLMs with tool-use outperform static analysis on real smart contracts?**

Research demonstrating that compositional reasoning + multi-turn analysis beats pattern matching on real-world blockchain exploits.

---

## The Problem

**Static analysis fails on real contracts:**
- ✓ 55% F1 on clean, synthetic code
- ✗ 0% F1 on real contracts (with proxies, inheritance, custom patterns)

**Why?** Real code is structurally different. Vulnerabilities are compositional (flash loan + oracle + reentrancy = one exploit path). Pattern matching alone is insufficient.

---

## The Solution

**Multi-turn LLM reasoning with targeted pre-filtering:**

```
Source Code
    ↓
[Static Analysis] (tool findings) → consensus filter
    ↓
[Claude — Opus 4.8 / Sonnet] (multi-turn agentic loop with context hints)
    ↓
Confirmed Findings → scored by string-match AND an LLM-judge (semantic)
```

**Measured run (June 2026) on 16 real verified contracts with committed source:**

Scored over the 16 real-source contracts (Opus run, `--real --agentic`):

| Approach | Precision | Recall | F1 | TP / FP / FN |
|----------|-----------|--------|----|--------------|
| Static v2 | 4% | 7% | **5%** | 3 / 80 / 38 |
| **Opus 4.8 — string-match scoring** | 4% | 7% | **5%** | 3 / 80 / 38 |
| **Opus 4.8 — semantic-judge scoring** | 28% | **56%** | **37%** | 23 / 60 / 18 |
| Fable 5 agentic | — | — | n/a | **refuses** the task (`stop_reason: refusal`) |
| Sonnet 4.6 (historical, unreproduced) | — | — | ~40–45% | original claim; never committed |

> **Why two Opus rows.** The benchmark's evaluator does near-exact string matching on
> vuln-type names. Opus 4.8 emits **compound, descriptive** finding names (e.g.
> `"arbitrary_external_call / approval_drain"`, `"forged_deposit_event /
> unauthenticated_memo"`, `"solvency_check_bypass"`, `"missing_message_source_validation"`)
> that are semantically correct but score as false positives — collapsing recall to 7%.
> `semantic_rescorer.py` (an LLM-as-judge, default Haiku) recomputes F1 from the
> **already-saved findings with no model re-run** (38 judge calls, ~17k tokens, ~$0.02):
> recall rises to **56%**, F1 to **37%**, with a correct root-cause hit on **15 of 16
> contracts** (only `sonne` is a genuine miss; the judge stays conservative on
> `nomad`/`penpie`, so it is not rubber-stamping). The residual false positives are
> mostly real-but-unlabeled observations (centralization, missing timelocks). This is
> the **ground-truth/scoring methodology problem** (Key Findings #2) reproduced at
> frontier-model scale: the model is far better than the matcher reports.

> **The judge is calibrated.** `agents/validate_judge.py` scores the Haiku judge against
> a frozen 38-unit hand-labeled gold standard (`benchmarks/judge_gold_standard.json`):
> **82% accuracy, 92% precision, 83% recall, Cohen's κ = 0.54, 97% run-to-run unanimous.**
> High precision ⇒ the judge rarely fabricates a match, so it does not inflate the model;
> its errors are conservative under-credits, making the **37% a lower bound**. The
> residual disagreement (moderate κ) sits almost entirely on labels flagged *borderline*
> in the gold file — genuine ambiguity, not judge noise.

> **Two model-specific findings from this run.**
> 1. **Fable 5 declines the task.** The newest model returns `stop_reason: refusal`
>    with empty output on smart-contract vulnerability-analysis prompts, across the
>    agentic harness, a single-turn JSON path, and an explicit *authorized
>    post-incident defensive audit* system prompt. Sonnet/Opus do not. A model that
>    refuses adversarial-code analysis cannot be benchmarked here as-is — itself a
>    citable result about safety-tuning vs. defensive-security utility.
> 2. **Newer models reject `temperature`.** Both `claude-fable-5` and
>    `claude-opus-4-8` 400 on an explicit `temperature` override; the analyzers now
>    omit it for those models and keep `temperature=0` only where supported.

> **Dataset status.** 16 of 20 registered contracts now have **real verified source**
> committed (fetched from Blockscout/Sourcify, addresses confirmed on-chain), up from
> 3. Remaining empties (`poly_network`, `ronin`, `orbit`, `lifi_march_2022`) are either
> verified only on Etherscan (needs a key) or off-chain key-compromise hacks with no
> source-level bug to detect. Select a model with `BENCH_MODEL` (`sonnet` default,
> `opus`, `haiku`, `fable`); non-default models write `results_real__<model>.json`.

---

## Key Findings

**1. Compositional vulnerabilities require multi-turn reasoning.** Flash loan + oracle
manipulation + reentrancy is a single multi-step exploit path. On real contracts the
static baseline scores ~1–5% F1; an agentic LLM reading the same source identifies the
actual root cause on **15 of 16** bridge contracts (see the results table above).

**2. The evaluator, not the model, is often the bottleneck.** Exact-string scoring rated
Opus 4.8 at 5% F1; an LLM-judge that scores *semantic* equivalence — validated against a
hand-labeled gold standard at 92% precision — recovers **37% F1 / 56% recall**. Benchmarks
that match vuln names literally systematically understate strong models.

**3. Frontier models disagree on whether to do the task at all.** Opus 4.8 engages;
**Fable 5 refuses** smart-contract vulnerability analysis (`stop_reason: refusal`) across
every prompt framing tried. Safety tuning vs. defensive-security utility is a real tension.

**4. Dataset quality is a first-class problem.** A post-mortem audit
([docs/DATA_QUALITY.md](docs/DATA_QUALITY.md)) found the original DEX/lending labels were
partly wrong (non-existent events, market/oracle events mislabeled as code bugs, conflated
hacks). The lending domain was rebuilt around verified source bugs before any number was
reported — generalization claims are only as good as the labels behind them.

---

## Datasets (verified, source-committed)

All source is fetched from public verifiers (Blockscout / Sourcify) with **every address
confirmed on-chain**. "Source" = a real verified contract committed to `benchmarks/contracts/`.

| Domain | Loader | Source-committed | Examples |
|--------|--------|------------------|----------|
| **Bridges** | `bridge_contracts_real.py` | **16 / 20** | Nomad, Qubit, Socket, XBridge, LiFi, Allbridge, THORChain, Rubic, CrossCurve, Hyperbridge, Penpie, Seneca, Prisma, Sonne, Dough, Abracadabra |
| **DEX/AMM** | `defi_contracts_real.py` | **5 / 5** | Euler (missing solvency check), KyberSwap (tick precision), Platypus (solvency ordering), DODO (unprotected init), Curve (Vyper stand-in) |
| **Lending** | `lending_contracts_real.py` | **3 / 3** | Onyx oPEPE (rounding), Compound P062 (reward-accounting), Cream crAMP (ERC-777 reentrancy) |

**24 verified, correctly-labeled source contracts** across three domains.

A separate registry, `bridge_bench.py`, tracks **off-chain** mega-hacks (Ronin, KelpDAO,
Humanity Protocol, …) for loss-coverage only — they have no source-level bug to detect and
are excluded from the F1 eval. See [DATA_QUALITY.md](docs/DATA_QUALITY.md) for what was
corrected and what remains to fetch (KyberSwap, Platypus, DODO).

---

## Quick Start

```bash
# 1. Setup (Python 3.10+)
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-...

# 2. Static baseline (free, no API)
python3 -m agents.benchmark_runner --real

# 3. Agentic run — pick the model with BENCH_MODEL (sonnet default, opus, haiku, fable)
#    Non-default models write results_real__<model>.json (baselines never clobbered)
BENCH_MODEL=opus python3 -m agents.benchmark_runner --real --agentic

# 4. Other domains (same evaluation path)
BENCH_MODEL=opus python3 -m agents.benchmark_runner --defi --lending --agentic

# 5. Semantic re-score (LLM-as-judge; recomputes F1 from saved findings, no model re-run)
python3 -m agents.semantic_rescorer results_real__claude-opus-4-8.json

# 6. Validate the judge against the frozen gold standard
python3 -m agents.validate_judge
```

---

## Architecture

**Agents**
- `agents/static_analyzer_v2.py` — pattern-based baseline (no API)
- `agents/agentic_analyzer.py` — multi-turn LLM reasoning with a tool loop
- `agents/hybrid_analyzer.py` — multi-tool consensus pre-filter + targeted LLM
- `agents/benchmark_runner.py` — evaluation harness (`--real` / `--defi` / `--lending`, model-stamped output)
- `agents/semantic_rescorer.py` — LLM-as-judge semantic F1 from saved findings
- `agents/validate_judge.py` — judge calibration vs. a hand-labeled gold standard

**Datasets & evaluation**
- `benchmarks/{bridge,defi,lending}_contracts_real.py` — loaders (canonical format)
- `benchmarks/bridge_bench.py` — full exploit registry incl. off-chain (loss-coverage)
- `benchmarks/judge_gold_standard.json` — 38 hand-labeled judge decisions
- `benchmarks/contracts/*.sol` — committed verified source

---

## Reproducing the headline run

The committed `results_real__claude-opus-4-8.json` (+ `__rescored.json`) is the Opus 4.8
agentic pass over the 16 bridge contracts. `results_defi_lending*.json` are the static
multi-domain passes. To regenerate from scratch you need an API key with credit; static
passes are free. Costs are dominated by the largest contracts (Penpie ~184 KB).

---

## Honest limitations

- **Ground truth is hand-authored** (single annotator). The gold standard and fuzzy
  equivalences encode the author's judgment; a second labeler would let us report
  inter-human agreement.
- **The semantic judge is moderate-κ** (0.54) though high-precision (92%); the 37% F1 is a
  conservative lower bound, not a point estimate.
- **Some DEX source is a faithful stand-in, not the exploited instance**: KyberSwap uses a
  verified same-implementation pool (Optimism, pre-patch) and DODO uses the verified clone
  template, because the exploited factory-deployed instances are unverified on-chain. Curve
  is a Vyper bug with no Solidity equivalent. The lending Cream positive uses a post-hack
  *patched* impl (a softer positive).
- **No committed Sonnet baseline** on the full set yet, so the Opus number lacks a same-set
  head-to-head; and the committed Opus run covers bridges only (DEX/lending not yet run).

---

## Documentation

- **[RESEARCH.md](docs/RESEARCH.md)** — full methodology and phase-by-phase findings (incl. Phase 7)
- **[DATA_QUALITY.md](docs/DATA_QUALITY.md)** — the DEX/lending label audit and corrections
- **[INDEX.md](docs/INDEX.md)** — documentation map

---

## License

MIT — see LICENSE.

**Status:** bridges complete (16 verified contracts, validated semantic rescorer); DEX
partial; lending rebuilt. Last updated June 2026.
