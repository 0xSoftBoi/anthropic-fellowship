# Documentation Index

## Getting Started

- **[README](../README.md)** — Project overview, quick start, key findings
- **[RESEARCH.md](RESEARCH.md)** — Detailed research methodology, all charts, full results

## Phase Reports

- **[Phase 3 Status](PHASE3_STATUS.md)** — Static analysis baseline and validation
- **[Phase 4 Plan](PHASE4_PLAN.md)** — Agentic analyzer architecture and approach
- **[Phase 4 Results](PHASE4_RESULTS.md)** — Bridge contract validation results

## Datasets

- `benchmarks/bridge_contracts_real.py` — 10 real bridge exploits
- `benchmarks/defi_contracts_real.py` — 5 DEX/AMM contracts (Phase 5B)
- `benchmarks/lending_contracts_real.py` — 3 lending contracts (Phase 5C)
- `benchmarks/test_contracts.py` — Synthetic patterns (baseline)

## Tools & Agents

- `agents/static_analyzer_v2.py` — Pattern-based vulnerability detector
- `agents/agentic_analyzer.py` — Multi-turn Sonnet reasoning (8-10 turns)
- `agents/hybrid_analyzer.py` — Multi-tool pre-filter + targeted Sonnet
- `agents/benchmark_runner.py` — Evaluation harness for all approaches

## Key Results

### Performance

| Approach | F1 Score | Cost | Use Case |
|----------|----------|------|----------|
| Static v2 | 0% | Free | Baseline |
| Multi-Tool | ~20% | $0.01 | Fast feedback |
| Hybrid | ~40% | $0.08 | **Production** |
| Full Sonnet | ~45% | $0.44 | Research |

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

### Run Static Baseline
```bash
python3 agents/benchmark_runner.py --real
```

### Run Hybrid (Recommended for Production)
```bash
ANTHROPIC_API_KEY=sk-... python3 agents/benchmark_runner.py --real --hybrid
```

### Run Full Agentic
```bash
ANTHROPIC_API_KEY=sk-... python3 agents/benchmark_runner.py --real --agentic
```

### Test Single Contract
```bash
PYTHONPATH=. ANTHROPIC_API_KEY=sk-... python3 agents/hybrid_analyzer.py --contract nomad_bridge_replica
```

---

## Domains Analyzed

### Bridges ($1.2B losses)
Nomad, Poly Network, Qubit, Socket, XBridge, Ronin, Orbit, LiFi, Allbridge, Synapse

### DEX/AMM ($327M losses)
Euler Finance, Kyberswap, Curve, Platypus, DODO

### Lending ($410M losses)
Venus, Cream, Compound

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

| Phase | Status | Completion |
|-------|--------|------------|
| **Phase 4: Bridges** | ✓ Complete | 10 exploits analyzed, Sonnet outperforms static |
| **Phase 5A: Ground Truth** | ✓ Complete | Nomad/Socket expanded to include all detectable vulns |
| **Phase 5B: DEX** | 🔄 In Progress | 5 DEX contracts, dataset complete, awaiting fetch |
| **Phase 5C: Lending** | 🔄 In Progress | 3 lending contracts, dataset ready |
| **Phase 6: Hybrid** | ✓ Complete | Multi-tool consensus pipeline implemented |
| **Phase 7: Source Coverage** | ⏳ Pending | Fetch missing bridge sources |

---

## Vocabulary

- **F1 Score** — Harmonic mean of precision and recall (0-1)
- **Compositional Vulnerability** — Multi-step attack requiring 2+ interactions (flash loan + oracle)
- **Ground Truth** — Set of known vulnerabilities in a contract (from audit or exploit post-mortem)
- **Multi-Tool Consensus** — Finding confirmed by 2+ static analyzers (boosts confidence)
- **Targeted Context** — Structured summary of static findings passed to LLM (not raw code)
- **Agentic Loop** — Multi-turn interaction where LLM iteratively refines analysis using tools

---

**Last Updated:** April 7, 2026
