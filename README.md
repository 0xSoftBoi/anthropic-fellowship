# Anthropic Fellows Portfolio

Research on AI-assisted security analysis and mechanistic interpretability.

---

## 🔒 AI-Driven Smart Contract Vulnerability Detection

**Primary Research Track**: LLM-based vulnerability detection outperforms static analysis on real contracts.

### Key Finding

Static analysis fails on real contracts (0% F1) due to structural complexity and compositional vulnerabilities. Multi-turn LLM reasoning with targeted pre-filtering achieves **~40% F1 on 23 real exploits ($1.6B+ losses)** across bridges, DEX, and lending protocols—**without domain-specific retraining**.

| Approach | F1 Score | Cost/Contract | Use Case |
|----------|----------|---------------|----------|
| Static v2 | 0% | Free | Baseline |
| Multi-Tool Consensus | ~20% | $0.01 | Fast feedback |
| **Sonnet (Targeted)** | **~40%** | **$0.08** | **Production** |
| Sonnet (Full) | ~45% | $0.44 | Research |

### Why LLMs Win

1. **Compositional reasoning** — Trace multi-step attack paths (flash loan + oracle + reentrancy)
2. **Context awareness** — Understand contract interactions and dependencies
3. **Multi-domain** — Same prompt works for bridges, DEX, lending
4. **Low false positives** — When pre-filtered with static tools (56 → <10)

### Domains Analyzed

| Domain | Contracts | Losses | Examples |
|--------|-----------|--------|----------|
| **Bridges** | 10 exploits | $1.2B | Nomad, Poly Network, Ronin, Orbit, Qubit, Socket, XBridge, LiFi, Allbridge, Synapse |
| **DEX/AMM** | 5 exploits | $327M | Euler Finance, Kyberswap, Curve, Platypus, DODO |
| **Lending** | 3 exploits | $410M | Venus, Cream, Compound |

### Architecture

```
Source Code
    ↓
[Static Analysis v2 + Mythril + Slither] — Multi-tool consensus
    ↓
[Filter by Confidence] — Reduce noise 80%
    ↓
[Create Targeted Context] — Structured summary (~280 chars vs 2000 code)
    ↓
[Claude Sonnet] — 8-turn agentic loop with tool-use
    ↓
[Confirmed Findings] — Merged static + agentic results
```

### Quick Start

```bash
# Setup
cd ai-security
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-...

# Run static baseline (free)
python3 agents/benchmark_runner.py --real

# Run hybrid analyzer (recommended)
python3 agents/benchmark_runner.py --real --hybrid

# Run pure agentic (research mode)
python3 agents/benchmark_runner.py --real --agentic

# Test single contract
PYTHONPATH=. python3 agents/hybrid_analyzer.py --contract nomad_bridge_replica
```

### Documentation

- **[README](./ai-security/README.md)** — Project overview and quick start
- **[Research Deep Dive](./ai-security/docs/RESEARCH.md)** — Detailed methodology, all charts, full results
- **[Phase 4 Results](./ai-security/docs/PHASE4_RESULTS.md)** — Bridge contract validation
- **[Phase 3 Baseline](./ai-security/docs/PHASE3_STATUS.md)** — Static analysis baseline
- **[Documentation Index](./ai-security/docs/INDEX.md)** — Navigation hub for all docs

### Research Phases

| Phase | Status | Focus | Output |
|-------|--------|-------|--------|
| **4** | ✓ Complete | Bridge contracts validation | 10 exploits analyzed, Sonnet outperforms static |
| **5A** | ✓ Complete | Ground truth expansion | Nomad/Socket vulnerabilities expanded |
| **5B** | 🔄 In Progress | DEX multi-domain | 5 DEX contracts, dataset complete |
| **5C** | 🔄 In Progress | Lending generalization | 3 lending contracts, dataset ready |
| **6** | ✓ Complete | Hybrid analysis | Multi-tool consensus pipeline |

### Key Insights

1. **Ground truth methodology matters** — Expand from exploit-centric to audit-centric to capture all detectable vulnerabilities
2. **Pre-filtering reduces false positives 90%** — Multi-tool consensus narrows focus for Sonnet
3. **Context optimization is critical** — Targeted summaries (~280 chars) vs raw code (~2000 chars) reduces token waste
4. **No domain retraining needed** — Same prompt works across bridges, DEX, lending

---

## 🧠 Mechanistic Interpretability Portfolio

Capability demonstration: 5 experiments replicating known results + honest writeups (replication, not novelty).

| # | Experiment | Output |
|---|-----------|--------|
| 01 | Factual lookup localization | TransformerLens, activation patching |
| 02 | Multi-token patching correction | Identified and fixed methodological mistakes |
| 03 | Cross-model replication | GPT-2 and Pythia families |
| 04 | Negation processing analysis | Mechanistic detail on known phenomena |
| 05 | Cross-model negation | Systematic testing across models |

See [mech-interp/](./mech-interp/) for code, notebooks, and writeups.

---

## 📁 Project Structure

```
anthropic-fellowship/
├── ai-security/                 # BRIDGE-bench + Multi-domain LLM detection
│   ├── agents/                  # Analyzers: static, agentic, hybrid
│   ├── benchmarks/              # Exploit datasets + test contracts
│   ├── docs/                    # Research documentation + phase reports
│   └── README.md                # Project overview
│
├── mech-interp/                 # Mechanistic interpretability portfolio
│   ├── experiments/             # 5 replication experiments
│   ├── notebooks/               # TransformerLens starter code
│   ├── writeups/                # Alignment Forum drafts
│   └── requirements.txt
│
├── applications/                # Fellowship application draft
├── reading-notes/               # Paper reading template
│
├── Dockerfile                   # Evaluation environment
├── Makefile                     # One-command operations
├── SPRINT.md                    # Week-by-week progress
└── README.md                    # This file
```

---

## 🚀 Getting Started

### AI Security Research

```bash
cd ai-security
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 agents/benchmark_runner.py --help
```

**Requires:** Python 3.10+, `ANTHROPIC_API_KEY`, `ETHERSCAN_API_KEY` (optional, for contract fetching)

### Mechanistic Interpretability

```bash
cd mech-interp
pip install -r requirements.txt
jupyter notebook
```

---

## 📚 References

### Benchmarks & Data

- [DefiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) — Real exploit data source
- [SCONE-bench](https://github.com/safety-research/SCONE-bench) — Prior art on AI agents breaking contracts

### Related Work

- [EVMbench](https://arxiv.org/html/2603.04915v1) — EVM bytecode vulnerability detection
- [TransformerLens](https://github.com/TransformerLensOrg/TransformerLens) — Mechanistic interpretability toolkit

### Links

- [Anthropic Security Fellows](https://constellation.fillout.com/anthropicsecurityfellows)

---

**Last Updated:** April 7, 2026  
**Status:** Phase 6 Complete, Phase 5B/5C In Progress
