# Documentation Index

## Getting Started

- **[README](../README.md)** — Project overview, quick start, key findings
- **[RESEARCH.md](RESEARCH.md)** — Detailed research methodology, all charts, full results

## Phase Reports

- **[Phase 3 Status](PHASE3_STATUS.md)** — Static analysis baseline and validation
- **[Phase 4 Plan](PHASE4_PLAN.md)** — Agentic analyzer architecture and approach
- **[Phase 4 Results](PHASE4_RESULTS.md)** — Bridge contract validation results

## Datasets

- `benchmarks/bridge_contracts_real.py` — bridge exploits (16/20 source-committed)
- `benchmarks/defi_contracts_real.py` — DEX/AMM (5/5 source-committed)
- `benchmarks/lending_contracts_real.py` — lending (3/3 source-committed, rebuilt)
- `benchmarks/bridge_bench.py` — full exploit registry incl. off-chain (loss-coverage)
- `benchmarks/judge_gold_standard.json` — 38 hand-labeled judge decisions
- `benchmarks/test_contracts.py` — synthetic patterns (baseline)

## Tools & Agents

- `agents/static_analyzer_v2.py` — pattern-based baseline (no API)
- `agents/agentic_analyzer.py` — multi-turn LLM reasoning with a tool loop
- `agents/hybrid_analyzer.py` — multi-tool pre-filter + targeted LLM
- `agents/benchmark_runner.py` — harness (`--real`/`--defi`/`--lending`, model-stamped output)
- `agents/semantic_rescorer.py` — LLM-as-judge semantic F1 from saved findings
- `agents/validate_judge.py` — judge calibration vs. the gold standard

## Key Results (Opus 4.8, June 2026 — 24 verified contracts, 3 domains)

| Domain | Contracts | String-match F1 | Semantic F1 | Recall |
|--------|-----------|-----------------|-------------|--------|
| Bridges | 16 | 4% | **37%** | 56% |
| DEX/AMM | 5 | 7% | **21%** | 38% |
| Lending | 3 | 0% | **40%** | 62% |
| **All three** | **24** | **4%** | **35%** | **54%** |

Judge validated at **92% precision / κ = 0.54** vs. a hand-labeled gold standard.
Fable 5 **refuses** the task. DEX+lending compute: $16.29 (budget-capped).
See [RESEARCH.md](RESEARCH.md) and [DATA_QUALITY.md](DATA_QUALITY.md).

### Why LLMs Win

1. **Compositional reasoning** — Trace multi-step attack paths (flash loan + oracle + reentrancy)
2. **Context awareness** — Understand contract interactions and dependencies
3. **Multi-domain** — Same prompt works for bridges, DEX, lending
4. **Low false positives** — When pre-filtered with static tools

### Ground Truth Insight

Real vulnerabilities ≠ exploited vulnerabilities. Expanding ground truth:
- **Before:** Only capture historical exploit → 0% F1
- **After:** Capture all detectable security issues → 40% F1

---

## Quick Reference

```bash
# Static baseline (free, no API)
python3 -m agents.benchmark_runner --real

# Agentic — choose the model; non-default models write results_real__<model>.json
BENCH_MODEL=opus python3 -m agents.benchmark_runner --real --agentic

# DEX / lending domains
BENCH_MODEL=opus python3 -m agents.benchmark_runner --defi --lending --agentic

# Semantic re-score + validate the judge (no model re-run)
python3 -m agents.semantic_rescorer results_real__claude-opus-4-8.json
python3 -m agents.validate_judge
```

---

## Domains Analyzed (source-detectable, verified)

### Bridges (16 source-committed)
Nomad, Qubit, Socket, XBridge, LiFi, Allbridge, THORChain, Rubic, CrossCurve, Hyperbridge,
Penpie, Seneca, Prisma, Sonne, Dough, Abracadabra

### DEX/AMM (5 source-committed)
Euler (solvency check), KyberSwap (tick precision), Platypus (solvency ordering), DODO (unprotected init), Curve (Vyper stand-in)

### Lending (3 source-committed, rebuilt)
Onyx oPEPE (rounding/donation), Compound P062 (reward-accounting), Cream crAMP (ERC-777 reentrancy)

---

## Architecture Overview

```
Source Code
    ↓
[Static Analysis v2] — Fast pattern matching
    ↓
[Mythril] (symbolic execution, if available)
[Slither] (data flow analysis, if available)
    ↓
[Multi-Tool Consensus] — Deduplicate, filter by confidence
    ↓
[Create Targeted Context] — Structured summary of findings (~280 chars vs 2000+ char code snippets)
    ↓
[Claude Sonnet] — 8-turn agentic loop with tool-use
    ↓
[Confirmed Findings] — Merged static + agentic findings
```

---

## Phase Status

| Phase | Status | Notes |
|-------|--------|-------|
| **Phase 4: Bridges** | ✓ Complete | thesis validated on bridge domain |
| **Phase 5A: Ground Truth** | ✓ Complete | exploit-centric → audit-centric labels |
| **Phase 5B: DEX** | ✓ Complete | 5/5 verified source (Routescan/Sourcify/template); labels corrected |
| **Phase 5C: Lending** | ✓ Rebuilt | dropped mislabeled entries; 3 verified source bugs committed |
| **Phase 6: Hybrid** | ✓ Complete | multi-tool consensus pipeline |
| **Phase 7: Expansion + Opus run** | ✓ Complete | 16 bridge contracts, Opus run, validated semantic rescorer |

---

## Vocabulary

- **F1 Score** — Harmonic mean of precision and recall (0-1)
- **Compositional Vulnerability** — Multi-step attack requiring 2+ interactions (flash loan + oracle)
- **Ground Truth** — Set of known vulnerabilities in a contract (from audit or exploit post-mortem)
- **Multi-Tool Consensus** — Finding confirmed by 2+ static analyzers (boosts confidence)
- **Targeted Context** — Structured summary of static findings passed to LLM (not raw code)
- **Agentic Loop** — Multi-turn interaction where LLM iteratively refines analysis using tools

---

**Last Updated:** June 2026
