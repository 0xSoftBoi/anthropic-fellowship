# Anthropic Fellows Program — Application Draft

## Track: AI Security Fellow

---

## Research Proposal: Cross-Chain Bridge Vulnerability Detection with AI Agents

### Problem

Cross-chain bridges have lost over $2.8 billion to exploits since 2022,
representing ~40% of all DeFi hacks. The attack surface is growing:
bridge TVL exceeds $55B, and exploit sophistication is increasing.

Xiao & Killian (Anthropic Fellows, 2026) demonstrated that AI agents
can find $4.6M in exploitable single-chain contract vulnerabilities,
with exploit revenue doubling every 1.3 months. But their work focused
on single-chain EVM contracts. The hardest vulnerabilities — cross-chain
message forgery, bridge proof verification bugs, and cross-domain
composability attacks — remain under-studied.

### Proposed Research

I propose to build and evaluate AI agents specialized for cross-chain
bridge vulnerability detection, with three contributions:

**1. Cross-Chain Bridge Benchmark (BRIDGE-bench)**

An extension of SCONE-bench focused on bridge-specific vulnerabilities.
I've built a working benchmark with:
- 10 real bridge exploits ($1.6B total losses) with fork data
- 20 simplified pattern contracts with 44 labeled vulnerabilities
- 3-tier vulnerability taxonomy (static-detectable → LLM-reasoning → operational)
- 16 passing Foundry exploit reproduction tests (Nomad, Wormhole, Ronin)
- Formal benchmark specification with evaluation modes (Detect → Patch → Verify)

I will expand this to 50+ contracts and systematically evaluate
Claude-based agents against established baselines.

**2. Claude-Based Detection Agent vs Static Tool Baselines**

I've built a working pipeline and measured baselines:

| Analyzer | F1 | Precision | Recall | Notes |
|----------|-----|-----------|--------|-------|
| Slither (Trail of Bits) | 11% | 11% | 11% | Generic detectors miss bridge patterns |
| Static Analyzer v2 (custom) | 42% | 49% | 36% | Regex heuristics tuned for bridges |
| Agent v2 (Claude) | TBD | — | — | Bridge-specific prompt engineering |

The core research question: does Claude find vulnerabilities that
static tools miss? Our gap analysis shows the static tools completely
miss compositional vulnerabilities worth $621M+ (Poly Network, LiFi)
— exactly the class where LLM reasoning should excel.

**3. Defense-First Framing**

Unlike Xiao & Killian's exploit-focused approach, I'll emphasize
detection *before* deployment (shift-left security) and concrete
patch suggestions. This is the angle the DeFi security community
needs most.

### Why Me

I'm not coming from academia — I'm a builder with domain expertise:

- **8+ years in DeFi infrastructure:** Cross-chain arbitrage systems
  (Bellman-Ford pathfinder), MEV protection, bridge integrations,
  trading bot with Rust execution + Python ML signals
- **Attacker + defender mindset:** I've built arbitrage systems (attacker
  perspective) and monitoring/protection layers (defender perspective).
  I've also personally experienced a USDC theft incident and executed
  multi-channel recovery.
- **Working code, not just ideas:** I have a functional pipeline
  (benchmark → static analysis → Claude analysis → evaluation)
  built before applying. The security track is ready to run experiments
  on day 1 of the fellowship.
- **Strong Python + Rust**, familiar with Solidity, ethers/web3

### Timeline (4 months)

- Month 1: Expand benchmark to 50+ contracts, reproduce top 10 exploits
  in simulation, run Claude analyzer against full benchmark
- Month 2: Systematic comparison: Claude agent vs Slither vs Mythril
  vs manual audit baselines
- Month 3: Compositional vulnerability detection experiments,
  cross-chain-specific agent improvements
- Month 4: Paper writing, open-source release

### Expected Output

- Paper: "AI Agents for Cross-Chain Bridge Security: Benchmark,
  Detection, and Compositional Vulnerability Reasoning"
- Open-source: BRIDGE-bench dataset + detection agent + eval harness
- Blog post for the DeFi security community

---

## Supplementary: Mechanistic Interpretability Portfolio

To demonstrate technical range beyond my DeFi domain, I spent a week
doing hands-on mech interp research. This is capability demonstration,
not novelty claims.

**12 experiments completed:**

| # | Experiment | Technique |
|---|-----------|-----------|
| 01-05 | Factual recall localization, multi-token patching, cross-model replication, negation processing | Activation patching, ablation |
| 06 | Induction head detection | Repeated sequence analysis, composition |
| 07 | Direct logit attribution | Residual stream decomposition, logit lens |
| 08 | Activation patching practice | Causal interventions, heatmaps |
| 09 | Toy models of superposition | Phase transitions, importance-based encoding |
| 10 | Sparse autoencoder on GPT-2 | From-scratch SAE, 4x expansion, feature analysis |
| 11 | Greater-than circuit (mini-project #1) | Full 5-step circuit analysis |
| 12 | IOI circuit (mini-project #2) | Name mover / S-inhibition head groups |

**3 writeups:** factual recall replication, negation as factual booster, greater-than circuit

**What this shows:**
- I can pick up a new technical domain (mech interp) and produce
  12 working experiments covering the full ARENA curriculum
- Two independent mini-projects demonstrating circuit-level analysis
- From-scratch SAE implementation following Anthropic's architecture
- I read the literature, identify when my results are replicating
  vs extending prior work, and frame honestly

**What this does NOT show:**
- Novel mech interp findings (I'm building capability, not claiming discovery)
- Deep theoretical contributions (I'm still learning)

---

## About Me

Systems engineer and startup founder, 8+ years in crypto/DeFi
infrastructure. Based in the DC defense corridor. Currently building
SensorForge (open-source robotics data capture) and exploring
AI safety research as a career transition.

I'm motivated by reducing catastrophic risks from advanced AI systems.
The intersection of AI capabilities and DeFi attack surfaces is a
concrete, measurable domain where safety research has immediate
real-world impact — bridges get exploited every month, and the
dollar amounts are growing.

I don't have a PhD or prior ML publications. What I have is the
ability to ship working systems fast, deep domain expertise in
exactly the area Anthropic's security team is researching, and
the intellectual honesty to say what I don't know.

Code: github.com/[username]/anthropic-fellowship
