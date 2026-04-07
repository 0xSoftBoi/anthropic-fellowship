# Anthropic Fellows Program — Application Draft

## Track: AI Security Fellow

---

## Research Proposal: Cross-Chain Bridge Vulnerability Detection with AI Agents

### Problem

Cross-chain bridges have lost over $3 billion to exploits since 2021. Six days ago, Drift Protocol was drained for $285M — the largest DeFi exploit of 2026 — with $232M in stolen USDC bridged via Circle's CCTP while Circle had 6 hours to freeze and didn't act. The attack surface is growing, and exploit sophistication is increasing: the Drift attacker (attributed to DPRK/Lazarus) used social-engineered pre-signed nonce transactions, a fabricated token with wash-traded price history, and a zero-timelock governance migration.

Xiao & Killian (Anthropic Fellows, 2026) demonstrated that AI agents can find $4.6M in exploitable single-chain contract vulnerabilities. But their SCONE-bench focuses on single-chain EVM contracts. The hardest vulnerabilities — cross-chain message forgery, bridge governance takeover, oracle manipulation via fake tokens, and cross-domain composability attacks — remain under-studied.

### Results So Far

I built BRIDGE-bench and ran the experiments. Here are the numbers:

**BRIDGE-bench v3: 29 contracts, 65 labeled vulnerabilities, 23 Foundry exploit tests**

| Analyzer | F1 | Precision | Recall | TP/Total |
|----------|-----|-----------|--------|----------|
| Slither (Trail of Bits) | 11.1% | 10.9% | 11.4% | 5/44* |
| Static Analyzer v2 (custom) | 37.8% | 45.7% | 32.3% | 21/65 |
| **Agent v2 (Claude Sonnet)** | **60.3%** | **46.0%** | **87.7%** | **57/65** |

*Slither tested on 20-contract subset.

**The Claude agent finds 88% of bridge vulnerabilities** — 2.7x the recall of our best static analyzer and 7.7x Slither's recall. More importantly, it catches the compositional vulnerabilities that static tools completely miss:

| Vulnerability | Real Loss | Static | Agent |
|---|---|---|---|
| Drift governance takeover + oracle manipulation | $285M | MISS | **5/5 PERFECT** |
| CCTP bridge centralization + no rate limiting | (used in $285M Drift bridge) | MISS | **3/4** |
| LiFi approval drain via arbitrary calldata | $11.6M | MISS | **2/2** |
| Poly Network unrestricted cross-chain call | $611M | MISS | **2/3** |
| Ronin duplicate signatures + low threshold | $625M | 2/5 | **5/5** |
| Timelock bypass + centralization risk | common pattern | MISS | **2/2** |

The tradeoff: the agent produces more false positives (67 FP vs 25 for static). In security, missing a real vulnerability is far worse than flagging a false positive, so the recall advantage is decisive.

### The Benchmark

**11 real bridge exploits** ($1.9B total losses) with fork block data:

| Exploit | Date | Loss | Vulnerability |
|---------|------|------|---------------|
| Poly Network | 2021-08 | $610M | Unrestricted cross-chain call |
| Ronin Bridge | 2022-03 | $625M | Validator key compromise (5/9) |
| Nomad Bridge | 2022-08 | $190M | Zero-root message validation |
| Qubit Finance | 2022-01 | $80M | Zero-value deposit |
| Orbit Chain | 2024-01 | $82M | Multisig key compromise |
| LiFi v2 | 2024-07 | $10M | Approval drain via calldata |
| Socket Gateway | 2024-01 | $3.3M | Approval exploitation |
| LiFi v1 | 2022-03 | $600K | Arbitrary external call |
| Allbridge | 2023-04 | $570K | Flash loan oracle manipulation |
| XBridge | 2024-04 | $1.6M | Approval exploitation |
| **Drift Protocol** | **2026-04** | **$285M** | **Governance takeover + oracle + CCTP bridge** |

**29 simplified pattern contracts** with 65 labeled vulnerabilities across 17 vulnerability classes, including partially-fixed variants (test if analyzers handle fixes), combined patterns (multi-vuln), and clean contracts (test false positive rate).

**23 passing Foundry exploit reproduction tests** across 4 test suites:
- Nomad: zero root drain, re-initialization, unsigned update, process-without-proof
- Wormhole: fake verifier bypass, multiple mints
- Ronin: 5/9 threshold drain, duplicate signatures, validator takeover
- CCTP: no rate limiting, single attester compromise, attester rotation without timelock, no amount cap

**Full pipeline:** Detect → Patch → Compile → Verify (Foundry)

### Proposed Fellowship Research

With the benchmark and baselines established, the fellowship would focus on:

**1. Improving Agent Precision (46% → 70%+)**
The agent's main weakness is false positives. I'd experiment with:
- Few-shot examples of true vs. false positives in the prompt
- Chain-of-thought verification ("are you sure this is exploitable?")
- Agentic multi-turn analysis with tool use (read source → check pattern → verify)
- Confidence calibration against the labeled dataset

**2. Expanding to Real Deployed Contracts**
The current benchmark uses simplified patterns. Next step: fetch real bridge contract source from Etherscan, test the agent against code that's actually deployed and securing billions.

**3. Patch Generation + Verification**
The pipeline architecture (detect → patch → compile) is built. The key research question: can Claude generate patches that compile AND block the original exploit when replayed in Foundry simulation?

**4. Defense-First Framing**
Unlike Xiao & Killian's offense-focused approach, I emphasize detection *before* deployment. The DeFi security community needs pre-audit AI tools, not better exploit generation.

### Why Me

I'm not coming from academia — I'm a builder with domain expertise:

- **8+ years in DeFi infrastructure:** Cross-chain arbitrage systems (Bellman-Ford pathfinder), MEV protection, bridge integrations, trading bot with Rust execution + Python ML signals
- **Attacker + defender mindset:** I've built arbitrage systems (attacker perspective) and monitoring/protection layers (defender perspective). I've personally experienced a USDC theft incident and executed multi-channel recovery.
- **Working code, not just ideas:** I have a functional benchmark with measured results (60% F1) built *before applying*. The research is ready to scale on day 1.
- **Current domain awareness:** I added the Drift exploit ($285M, Apr 1 2026) to the benchmark within days of it happening.
- **Strong Python + Rust**, familiar with Solidity, Foundry, ethers/web3

### Timeline (4 months)

- Month 1: Expand benchmark to 50+ real contracts (Etherscan source), improve agent precision to 70%+ F1
- Month 2: Multi-turn agentic analysis, patch generation experiments, exploit replay verification
- Month 3: Real-world validation on deployed bridge contracts, comparison with professional audit findings
- Month 4: Paper writing, open-source release, blog post for DeFi security community

### Expected Output

- Paper: "BRIDGE-bench: Evaluating AI Agents on Cross-Chain Bridge Vulnerability Detection"
- Open-source: BRIDGE-bench dataset + detection agent + eval harness + Foundry tests
- Measured result: agent F1 on real deployed bridge contracts
- Blog post for the DeFi security community

---

## Supplementary: Mechanistic Interpretability Portfolio

To demonstrate technical range beyond my DeFi domain, I completed a full mechanistic interpretability research sprint. This is capability demonstration, not novelty claims.

**14 experiments completed:**

| # | Experiment | Key Finding |
|---|-----------|-------------|
| 01-05 | Factual recall, multi-token patching, cross-model replication, negation | 75-83% depth, negation booster effect |
| 06 | Induction head detection | L5H5=0.92, 33x loss on ablation |
| 07 | Direct logit attribution + logit lens | Predictions crystallize at L9-L10 |
| 08 | Activation patching | 98% recovery from last-position patch |
| 09 | Toy models of superposition | Phase transitions, importance-based encoding |
| 10 | SAE on GPT-2 small | From-scratch, 100% variance explained |
| 11 | Greater-than circuit (mini-project #1) | 117x year ordering ratio, L7-L8 transition |
| 12 | IOI circuit (mini-project #2) | Name movers (L0H9: +3.52) + S-inhibitors (L0H8: -3.17) |
| 13 | SAE feature steering | **Negative result** — insufficient data for monosemantic features |
| 14 | Activation steering | **Positive result** — sentiment/formality are linear directions |

**4 writeups:** factual recall replication, negation as factual booster, greater-than circuit, IOI circuit

**What this shows:**
- I can pick up a new technical domain and produce 14 working experiments covering the full ARENA curriculum in weeks
- Two independent mini-projects demonstrating end-to-end circuit-level analysis
- From-scratch SAE implementation following Anthropic's "Towards Monosemanticity" architecture
- Honest reporting of negative results (experiment 13) alongside positive ones (14)
- I read the literature, replicate before extending, and frame honestly

---

## About Me

Systems engineer and startup founder, 8+ years in crypto/DeFi infrastructure. Currently exploring AI safety research as a career transition.

I'm motivated by reducing catastrophic risks from advanced AI systems. The intersection of AI capabilities and DeFi attack surfaces is a concrete, measurable domain where safety research has immediate real-world impact — bridges get exploited every month, and the dollar amounts are growing. The Drift hack happened while I was building this benchmark.

I don't have a PhD or prior ML publications. What I have is the ability to ship working systems fast, deep domain expertise in exactly the area Anthropic's security team is researching, and the intellectual honesty to say what I don't know.

Code: github.com/0xSoftBoi/anthropic-fellowship
