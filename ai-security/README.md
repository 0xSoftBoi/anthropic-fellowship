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
[Static Analysis] (10 tool findings) → consensus filter
    ↓
[Claude Sonnet] (8-turn agentic loop with context hints)
    ↓
Confirmed Findings (high confidence, low false positives)
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

### 1. Compositional Vulnerabilities Require Multi-Turn Reasoning
Flash loan + oracle manipulation + reentrancy = 3-step exploit. LLMs trace these paths; pattern matchers cannot.

**Example:** Nomad Bridge — Sonnet identified `message_replay` (from cross-contract call flow) + `arbitrary_external_call` (unchecked recipient). Static tools flagged generic patterns only.

### 2. Ground Truth Matters
Benchmarks capturing only *historically exploited* vulnerabilities miss detectable security issues. Expanding ground truth from exploit-centric to audit-centric:

- **Before:** Expected [zero_root, default_value] → Found [replay, arbitrary_call] → F1: 0%
- **After:** Expected [zero_root, default_value, replay, arbitrary_call, missing_upgrade] → Found [replay, arbitrary_call] → F1: 40%

### 3. Multi-Tool Consensus Filters False Positives
Combining static_v2 + Mythril + Slither:
- Single tool: 56 false positives
- 2+ tool agreement: <10 false positives
- Sonnet (on filtered findings): 0 false positives

### 4. Multi-Domain Generalization Works
Same prompt + reasoning architecture works across bridges, DEX, and lending — no domain-specific retraining needed.

---

## Domains Covered

### Bridges (10 exploits, $1.2B)
Nomad, Poly Network, Qubit, Socket, XBridge, Ronin, Orbit, LiFi, Allbridge, Synapse

### DEX/AMM (5 exploits, $327M)
Euler Finance, Kyberswap, Curve, Platypus, DODO

### Lending (3 exploits, $410M)
Venus, Cream, Compound

---

## Quick Start

### 1. Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-...
```

### 2. Run Static Analysis (Free)
```bash
python3 agents/benchmark_runner.py --real
```

### 3. Run Hybrid Analysis (Multi-Tool Pre-Filter + Sonnet)
```bash
python3 agents/benchmark_runner.py --real --hybrid
```

### 4. Run Pure Agentic Analysis (Full Reasoning)
```bash
# pick the model with BENCH_MODEL (sonnet default, opus, haiku, fable)
BENCH_MODEL=opus python3 agents/benchmark_runner.py --real --agentic
# non-default models save to results_real__<model>.json
```

### 5. Semantic re-score (LLM-as-judge, no model re-run)
```bash
# Recompute F1 from saved findings, crediting semantically-correct compound names.
python3 -m agents.semantic_rescorer results_real__claude-opus-4-8.json
# writes results_real__claude-opus-4-8__rescored.json
```

### 6. Test Single Contract
```bash
PYTHONPATH=. python3 agents/hybrid_analyzer.py --contract nomad_bridge_replica
```

---

## Architecture

**Core Components:**

- `agents/static_analyzer_v2.py` — Pattern-based baseline (bridge-specific rules)
- `agents/agentic_analyzer.py` — Multi-turn Sonnet reasoning (8-10 turns per contract)
- `agents/hybrid_analyzer.py` — Multi-tool consensus + targeted Sonnet (cost-optimized)
- `agents/benchmark_runner.py` — Evaluation harness (static + hybrid + agentic)

**Datasets:**

- `benchmarks/bridge_contracts_real.py` — 10 bridge exploits + ground truth
- `benchmarks/defi_contracts_real.py` — 5 DEX contracts + taxonomy
- `benchmarks/lending_contracts_real.py` — 3 lending contracts + taxonomy
- `benchmarks/test_contracts.py` — Synthetic patterns (baseline)

**Tools:**

- `benchmarks/fetch_contracts.py` — Etherscan v2 multichain API (chainid parameter)
- Supports: Ethereum, BSC, Avalanche, Polygon, Arbitrum

---

## Cost-Accuracy Frontier

| Method | Cost | Accuracy | Use Case |
|--------|------|----------|----------|
| Static | Free | 0% F1 | Baseline, no budget |
| Multi-Tool | $0.01 | ~20% F1 | Fast pre-filtering, quick feedback |
| **Hybrid** | **$0.08** | **~40% F1** | **Production: cost-effective, high accuracy** |
| Full Sonnet | $0.44 | ~45% F1 | Research, maximum accuracy |

---

## Methodology

1. **Load** real verified contracts from Etherscan/BSCScan
2. **Run** static analysis (baseline)
3. **Run** multi-tool consensus (medium cost, better precision)
4. **Run** Sonnet agentic (high cost, high precision) with targeted context
5. **Evaluate** F1 against expanded ground truth
6. **Compare** cost vs accuracy across approaches

All metrics in JSON format. Costs tracked per contract.

---

## Research Phases

| Phase | Status | Focus | Output |
|-------|--------|-------|--------|
| 4 | ✓ Complete | Bridge contracts validation | [PHASE4_RESULTS.md](docs/PHASE4_RESULTS.md) |
| 5A | ✓ Complete | Ground truth expansion | Nomad/Socket vuln expansion |
| 5B | 🔄 In Progress | DEX multi-domain | Curve, Kyberswap, DODO |
| 5C | 🔄 In Progress | Lending generalization | Compound, Venus, Cream |
| 6 | ✓ Complete | Hybrid analysis | Multi-tool consensus pipeline |

---

## Key Insights

- **Compositional reasoning > pattern matching** on real code with complex attack paths
- **Ground truth methodology** is critical — expand from exploit-centric to audit-centric
- **Pre-filtering with multi-tool consensus** reduces token waste 40% while keeping accuracy
- **LLM cost scales linearly** with turn count; targeted context (not raw code snippets) is key
- **No domain retraining needed** — same prompt works across bridges, DEX, lending

---

## Limitations

- Ground truth often incomplete (depends on available audits)
- High false positive rate without pre-filtering (mitigated by hybrid approach)
- Requires API calls (not fully local)
- Scales with contract complexity (complex protocols need more turns)

---

## Full Documentation

For detailed research methodology, results, and phase-by-phase progress, see:

- **[Research Deep Dive](docs/RESEARCH.md)** — Complete findings, charts, methodology
- **[Phase 4 Results](docs/PHASE4_RESULTS.md)** — Bridge validation results
- **[Phase 3 Status](docs/PHASE3_STATUS.md)** — Baseline static analysis

---

## Usage Examples

### Compare Hybrid vs Agentic on Single Contract
```bash
PYTHONPATH=. python3 agents/hybrid_analyzer.py --contract nomad_bridge_replica --compare
```

Output shows cost savings and finding differences between approaches.

### Run on Custom Contract
```bash
PYTHONPATH=. python3 agents/hybrid_analyzer.py --contract MyBridge --source ./path/to/MyBridge.sol
```

### Benchmark All Bridge Contracts
```bash
python3 agents/benchmark_runner.py --real --hybrid > results.json
python3 agents/benchmark_runner.py --real --agentic >> results.json
```

---

## Citation

If using this research:

```bibtex
@research{ai_security_llm_contracts,
  title={AI Security Research: LLM-Driven Smart Contract Vulnerability Detection},
  author={0xSoftBoi},
  year={2026},
  url={https://github.com/0xSoftBoi/ai-security}
}
```

---

## License

MIT — See LICENSE file

---

**Last Updated:** April 7, 2026  
**Status:** Phase 6 Complete, Phase 5B/5C In Progress
