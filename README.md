# Anthropic Fellows Portfolio

[![Status: Active Research](https://img.shields.io/badge/status-active%20research-blue)]()
[![Python: 3.10+](https://img.shields.io/badge/python-3.10%2B-green)]()
[![License: MIT](https://img.shields.io/badge/license-MIT-orange)]()

> **Research on AI-assisted security analysis and mechanistic interpretability**  
> Demonstrating that multi-turn LLM reasoning outperforms static analysis on real-world blockchain exploits.

---

## 🎯 Current Focus: Multi-Domain Vulnerability Detection

**Core question:** can an LLM with a tool-use loop find vulnerabilities in *real* deployed
contracts that pattern-based static analysis misses? **BRIDGE-bench** is the benchmark built
to answer it — real, verified, on-chain source across bridges, DEX, and lending, scored by
both exact-string matching and an LLM-judge.

### Measured results (Opus 4.8, June 2026 — 24 verified contracts, 3 domains)

| Domain | Contracts | String-match F1 | **Semantic F1** | Recall |
|--------|-----------|-----------------|-----------------|--------|
| Bridges | 16 | 4% | **37%** | 56% |
| DEX/AMM | 5 | 7% | **21%** | 38% |
| Lending | 3 | 0% | **40%** | 62% |
| **All three** | **24** | **4%** | **35%** | **54%** |

The static/string-match baseline sits at ~4% F1; Opus 4.8 reaches **35% F1 / 54% recall**
semantically — a ~9× lift from the same source, holding up across all three domains. The
exact-string matcher hides this because the model writes *compound* finding names; an
LLM-judge — itself **validated at 92% precision / Cohen's κ = 0.54** against a hand-labeled
gold standard — recovers the real signal. Two notable model findings: **Fable 5 refuses**
the task entirely (`stop_reason: refusal`), and newer models reject the `temperature`
parameter. (DEX+lending compute: $16.29, budget-capped.)

> Full numbers, the judge-validation report, and the DEX/lending data-quality audit are in
> [`ai-security/`](./ai-security). This is research, not a product — the limitations are
> documented honestly.

---

## 🔍 What Makes This Rigorous

**1. Real, verified source.** 24 contracts across three domains, each fetched from
Blockscout/Sourcify with the address confirmed on-chain — not synthetic snippets.

**2. Two-axis scoring.** Exact-string F1 *and* an LLM-judge semantic F1, so the gap between
"named the bug correctly" and "named it the way the label expects" is measured, not hidden.

**3. The judge is validated.** Calibrated against a frozen 38-unit hand-labeled gold standard
(92% precision, 97% run-to-run stable) — the semantic number ships with a stated error profile.

**4. Data quality is audited.** A post-mortem-by-post-mortem audit caught mislabeled exploits
(non-existent events, market events miscalled code bugs) and the lending set was *rebuilt*
around verified source bugs before any F1 was reported.

---

## 📁 Projects

### AI Security: Multi-Domain Vulnerability Detection

**Primary Research Track**

```bash
cd ai-security
python3 -m venv .venv && source .venv/bin/activate   # Python 3.10+
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...

# Static baseline (free, no API)
python3 -m agents.benchmark_runner --real

# Agentic run — choose the model; non-default models write results_real__<model>.json
BENCH_MODEL=opus python3 -m agents.benchmark_runner --real --agentic

# Other domains, then semantic re-score + validate the judge (no model re-run)
BENCH_MODEL=opus python3 -m agents.benchmark_runner --defi --lending --agentic
python3 -m agents.semantic_rescorer results_real__claude-opus-4-8.json
python3 -m agents.validate_judge
```

**Key Files:**
- `agents/agentic_analyzer.py` — multi-turn LLM reasoning with a tool loop
- `agents/static_analyzer_v2.py` — pattern-matching baseline (no API)
- `agents/semantic_rescorer.py` — LLM-as-judge semantic F1 from saved findings
- `agents/validate_judge.py` — judge calibration vs. the gold standard
- `benchmarks/{bridge,defi,lending}_contracts_real.py` — datasets (16 / 5 / 3 source-committed)
- `benchmarks/judge_gold_standard.json` — 38 hand-labeled judge decisions

**Documentation:**
- **[ai-security/README](./ai-security/README.md)** — results, quick start, honest limitations
- **[Research Deep Dive](./ai-security/docs/RESEARCH.md)** — methodology, Phases 4–7
- **[Data-Quality Audit](./ai-security/docs/DATA_QUALITY.md)** — DEX/lending label corrections

---

### Mechanistic Interpretability: Replication Portfolio

**Capability Demonstration Track**

5 experiments replicating known mechanistic interpretability results using TransformerLens:

| # | Experiment | Models | Output |
|---|-----------|--------|--------|
| 01 | Factual lookup localization | GPT-2, Pythia | Identify where models store facts |
| 02 | Multi-token patching correction | GPT-2 | Fix methodological mistakes in prior work |
| 03 | Cross-model replication | GPT-2 & Pythia | Verify across model families |
| 04 | Negation processing analysis | Pythia | Add mechanistic detail to known phenomena |
| 05 | Cross-model negation | GPT-2 & Pythia | Systematic testing |

```bash
cd mech-interp
pip install -r requirements.txt
jupyter notebook
```

**See:** `mech-interp/writeups/` for Alignment Forum drafts

---

## 🏗️ Project Structure

```
anthropic-fellowship/
├── ai-security/                      # BRIDGE-bench + Multi-domain detection
│   ├── agents/
│   │   ├── hybrid_analyzer.py         # ⭐ Recommended: Multi-tool + Sonnet
│   │   ├── agentic_analyzer.py        # Full reasoning (expensive)
│   │   ├── static_analyzer_v2.py      # Baseline (free)
│   │   └── benchmark_runner.py        # Run all approaches
│   ├── benchmarks/
│   │   ├── bridge_contracts_real.py   # 10 bridge exploits
│   │   ├── defi_contracts_real.py     # 5 DEX contracts
│   │   ├── lending_contracts_real.py  # 3 lending contracts
│   │   └── fetch_contracts.py         # Etherscan multichain fetcher
│   ├── docs/
│   │   ├── RESEARCH.md                # Detailed research + charts
│   │   ├── PHASE4_RESULTS.md          # Bridge results
│   │   ├── PHASE3_STATUS.md           # Static baseline
│   │   └── INDEX.md                   # Documentation navigation
│   └── requirements.txt
│
├── mech-interp/                       # TransformerLens replication suite
│   ├── experiments/                   # 5 Python scripts
│   ├── notebooks/                     # TransformerLens starter
│   ├── writeups/                      # Alignment Forum drafts
│   └── requirements.txt
│
├── applications/                      # Fellowship application
├── reading-notes/                     # Paper templates
├── Makefile                           # One-command operations
├── SPRINT.md                          # Week-by-week progress
└── README.md                          # This file
```

---

## 📊 Progress Dashboard

### Phase Status (Q1 2026)

| Phase | Title | Status | Completion |
|-------|-------|--------|------------|
| **4** | Bridge Validation | ✅ Complete | 10 exploits, Sonnet outperforms static |
| **5A** | Ground Truth Expansion | ✅ Complete | Nomad/Socket vulnerabilities expanded |
| **5B** | DEX Multi-Domain | 🔄 In Progress | 5 contracts, infrastructure ready |
| **5C** | Lending Generalization | 🔄 In Progress | 3 contracts, dataset prepared |
| **6** | Hybrid Pipeline | ✅ Complete | Multi-tool consensus + Sonnet |
| **7** | Source Coverage | ⏳ Pending | Fetch 7 missing bridge sources |

**Next Milestone:** Run Phases 5B/5C benchmarks to prove multi-domain generalization.

---

## 🚀 Requirements

- Python 3.10+
- `ANTHROPIC_API_KEY` (from [console.anthropic.com](https://console.anthropic.com))
- `ETHERSCAN_API_KEY` (free from [etherscan.io](https://etherscan.io/apis))
- Optional: [Foundry](https://book.getfoundry.sh/) for contract compilation

---

## 📚 Key Insights

1. **Static analysis fails compositionally** — Can't trace multi-step attacks
2. **Ground truth methodology is critical** — Expand from exploit-centric to audit-centric
3. **Pre-filtering reduces false positives 90%** — Multi-tool consensus narrows scope for LLM
4. **Context optimization matters** — Structured summaries (~280 chars) vs raw code (~2000 chars)
5. **No domain retraining needed** — Same prompt works across bridges, DEX, lending

---

## 📖 References

### Benchmarks & Datasets

- **[DefiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs)** — Real exploit database (source of all contract data)
- **[SCONE-bench](https://github.com/safety-research/SCONE-bench)** — Prior art: "Can AI break contracts?" (Xiao & Killian, 2026)

### Related Work

- **[EVMbench](https://arxiv.org/html/2603.04915v1)** — EVM bytecode vulnerability detection
- **[TransformerLens](https://github.com/TransformerLensOrg/TransformerLens)** — Mechanistic interpretability toolkit

### Application

- **[Anthropic Security Fellows](https://constellation.fillout.com/anthropicsecurityfellows)** — Fellowship program

---

## 🤝 Contributing

This is a research portfolio for the Anthropic Fellowship Program.

**Ways to help:**
- Run benchmarks on DEX/lending contracts → measure multi-domain generalization
- Expand ground truth vulnerabilities → improve benchmark accuracy
- Fetch missing contract sources → enable Phase 7 analysis
- Add new exploit datasets → test on other DeFi domains
- Improve static analysis tools → reduce false positives

**See [CONTRIBUTING.md](./CONTRIBUTING.md)** for detailed contribution guides (effort: 30 min - 3 hours per task, mostly free).

---

## 📄 License

MIT — See LICENSE file

---

**Last Updated:** April 7, 2026  
**Repository:** Active research in progress  
**Phase Status:** 6 complete, 5B/5C in progress, 7 pending
