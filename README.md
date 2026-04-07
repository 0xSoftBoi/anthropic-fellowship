# BRIDGE-bench + Mech Interp Portfolio

Research portfolio for the Anthropic Fellows Program (July 2026 cohort).

## BRIDGE-bench: AI-Assisted Cross-Chain Bridge Vulnerability Detection

Defense-focused benchmark for evaluating AI agents on cross-chain bridge security.
Built on real exploit data from [DefiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs),
the same source used by [SCONE-bench](https://github.com/safety-research/SCONE-bench) (Xiao & Killian, 2026).

### The Thesis

SCONE-bench asks: *"Can AI break smart contracts?"*
BRIDGE-bench asks: *"Can AI protect bridges?"*

Static analysis tools catch pattern-matching vulnerabilities (55% F1 baseline).
LLM agents should catch compositional bridge vulnerabilities — message validation flaws,
approval drain via arbitrary calldata, flash loan + oracle composability — that static
tools systematically miss. These gaps represent $811M in historical losses.

### Data

10 real bridge exploits ($1.6B total losses) with fork data for reproduction:

| Exploit | Date | Loss | Vulnerability Class |
|---------|------|------|---------------------|
| Poly Network | 2021-08 | $610M | Message validation |
| Ronin Bridge | 2022-03 | $625M | Validator governance |
| Nomad Bridge | 2022-08 | $190M | Message validation |
| Qubit Finance | 2022-01 | $80M | Input validation |
| Orbit Chain | 2024-01 | $82M | Validator governance |
| LiFi v2 | 2024-07 | $10M | Approval exploitation |
| Socket Gateway | 2024-01 | $3.3M | Approval exploitation |
| XBridge | 2024-04 | $1.6M | Approval exploitation |
| LiFi v1 | 2022-03 | $600K | Approval exploitation |
| Allbridge | 2023-04 | $570K | Oracle manipulation |
| Drift Protocol | 2026-04 | $285M | Governance takeover + oracle manipulation |

### Architecture: Detect → Patch → Verify

```
agents/
├── static_analyzer_v2.py    # Pattern-matching baseline (55% F1)
├── claude_analyzer.py       # Single-prompt Claude analysis
├── agentic_analyzer.py      # Multi-turn Claude agent with tools
├── patch_generator.py       # Claude generates Solidity patches
├── harness.py               # Docker + Foundry evaluation harness
├── benchmark_runner.py      # Head-to-head comparison with metrics
├── eval_harness.py          # Precision / Recall / F1 evaluation
└── pipeline.py              # End-to-end pipeline

benchmarks/
├── bridge_bench.py          # Real exploit database (from DefiHackLabs)
├── test_contracts.py        # 4 simplified contracts, 14 labeled vulns
├── bridge_exploits.py       # Exploit metadata catalog
└── fetch_contracts.py       # Etherscan source code fetcher
```

### Quick Start

```bash
# Install deps and clone DefiHackLabs
make setup

# Run static analyzer baseline (no API key needed)
make test-static

# Run Claude analyzer (needs API key)
export ANTHROPIC_API_KEY=sk-ant-...
make test-claude

# Full benchmark comparison
make benchmark
```

### Current Results

| Analyzer | F1 | Notes |
|----------|-----|-------|
| Static v2 | 55% | Catches reentrancy, access control, oracle, init bugs |
| Claude (single-prompt) | TBD | Run with `make test-claude` |
| Claude (agentic) | TBD | Run with `python ai-security/agents/agentic_analyzer.py` |

---

## Mechanistic Interpretability Portfolio

5 experiments replicating known results as capability demonstration.
Not claiming novelty — demonstrating research execution skills.

| # | Experiment | What It Shows |
|---|-----------|---------------|
| 01 | Factual lookup localization | Can use TransformerLens, activation patching |
| 02 | Multi-token patching correction | Can identify and fix methodological mistakes |
| 03 | Cross-model replication | Can work across GPT-2 and Pythia families |
| 04 | Negation processing analysis | Can add mechanistic detail to known phenomena |
| 05 | Cross-model negation | Can systematically test across models |

2 writeups documenting findings with honest framing (replication, not novelty).

---

## Structure

```
anthropic-fellowship/
├── ai-security/              # BRIDGE-bench (primary track)
│   ├── agents/               # Detection + patching + evaluation code
│   ├── benchmarks/           # Exploit database + test contracts
│   └── requirements.txt
├── mech-interp/              # Capability demonstration
│   ├── experiments/          # 5 experiments (Python scripts)
│   ├── notebooks/            # TransformerLens starter
│   ├── writeups/             # 2 Alignment Forum drafts
│   └── requirements.txt
├── applications/             # Fellowship application draft
├── reading-notes/            # Paper reading template
├── Dockerfile                # Docker evaluation environment
├── Makefile                  # One-command operations
└── SPRINT.md                 # Week-by-week progress tracker
```

## Requirements

- Python 3.10+
- [Foundry](https://book.getfoundry.sh/) for Solidity compilation and blockchain forking
- `ANTHROPIC_API_KEY` for Claude-based analysis
- `ETHERSCAN_API_KEY` (free) for fetching real contract source

## Links

- [Anthropic Fellows Application](https://constellation.fillout.com/anthropicsecurityfellows)
- [SCONE-bench](https://github.com/safety-research/SCONE-bench) (prior art)
- [DefiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) (exploit data source)
- [EVMbench](https://arxiv.org/html/2603.04915v1) (related work)
