# BRIDGE-bench: Benchmark Specification

**Version:** 0.2.0-draft
**Date:** 2026-04-06
**Author:** BRIDGE-bench contributors

## 1. Overview

BRIDGE-bench evaluates AI agents on **defense-oriented** cross-chain bridge vulnerability detection, patching, and verification. Unlike SCONE-bench (Xiao & Killian, 2026) which focuses on exploit generation, BRIDGE-bench asks: *"Can AI protect bridges before they're exploited?"*

### 1.1 Motivation

Cross-chain bridges represent a uniquely dangerous attack surface:
- **$2.1B+ stolen** from bridge exploits (2021-2024)
- **Compositional vulnerabilities** that static analysis tools miss
- **Bridge-specific bug classes** not taxonomized in existing benchmarks
- **Recurring patterns** — LiFi was exploited twice for the same bug class (2022, 2024)

### 1.2 Scope

| Dimension | SCONE-bench | BRIDGE-bench |
|-----------|-------------|--------------|
| Focus | Offense (exploit generation) | Defense (detect + patch + verify) |
| Contracts | 405 general smart contracts | 10 real bridge exploits + 4 pattern contracts |
| Vulnerability types | All smart contract vulns | Bridge-specific taxonomy (§2) |
| Evaluation | Did the agent exploit it? | Did the agent detect, patch, and prevent it? |
| Data source | DefiHackLabs | DefiHackLabs (same source, bridge subset) |

## 2. Vulnerability Taxonomy

Bridge-specific vulnerability classes, organized by detection difficulty:

### Tier 1: Static-Detectable (pattern matching)
| Class | Description | Example Exploit | Loss |
|-------|-------------|-----------------|------|
| `input_validation` | Missing checks on deposit values, addresses | Qubit Finance | $80M |
| `approval_exploitation` | Arbitrary calldata drains approved tokens | Socket, XBridge | $15M |
| `access_control` | Missing onlyOwner or role checks | Various | — |

### Tier 2: LLM-Reasoning Required (compositional)
| Class | Description | Example Exploit | Loss |
|-------|-------------|-----------------|------|
| `message_validation` | Cross-chain message verification flaws | Nomad, Poly Network | $800M |
| `signature_verification` | Guardian/validator sig bypass | Wormhole | $320M |
| `oracle_manipulation` | Flash loan + spot price dependency | Allbridge | $570K |
| `approval_exploitation` (complex) | Multi-step approval drain via swap routing | LiFi v1, v2 | $10.6M |

### Tier 3: Operational (not code-level)
| Class | Description | Example Exploit | Loss |
|-------|-------------|-----------------|------|
| `validator_governance` | Key compromise, low threshold | Ronin, Orbit | $707M |
| `upgrade_mechanism` | Malicious or flawed proxy upgrades | Various | — |

**Hypothesis:** LLM agents should significantly outperform static tools on Tier 2 vulnerabilities, which require understanding cross-contract interactions, message flow semantics, and bridge-specific domain knowledge.

## 3. Dataset

### 3.1 Real Exploits (10)

Each entry in `benchmarks/bridge_bench.py` includes:
- **Contract addresses** and **fork block numbers** for blockchain forking
- **Vulnerability classification** (class + detection mode)
- **Dollar loss** and chain information
- **Ground truth vulnerability details** (type + severity)
- **Path to DefiHackLabs PoC** for exploit reproduction

### 3.2 Pattern Contracts (4)

Simplified reproductions in `benchmarks/test_contracts.py` isolating specific bug patterns:

| Contract | Based On | Vulnerabilities | Total Ground Truth Labels |
|----------|----------|-----------------|--------------------------|
| WormholeStyle | Wormhole ($320M) | Untrusted external call, reentrancy | 2 |
| NomadStyle | Nomad ($190M) | Unprotected init, zero root, no sig verify, no proof link | 5 |
| RoninStyle | Ronin ($625M) | Low threshold, duplicate sigs, no rate limit, unprotected admin | 5 |
| OracleManipulation | Allbridge ($570K) | Spot price oracle, flash loan exploitable | 2 |

**Total: 14 labeled vulnerabilities across 4 contracts**

### 3.3 Foundry Reproduction Tests

Executable exploit reproductions in `foundry/test/`:

| Test File | Exploit Tests | Sanity Tests |
|-----------|---------------|--------------|
| `NomadExploit.t.sol` | 5 (zero root, re-init, no sig, no proof, unlimited msgs) | 1 (replay blocked) |
| `WormholeExploit.t.sol` | 2 (fake verifier, multiple mints) | 2 (replay blocked, CEI reentrancy) |
| `RoninExploit.t.sol` | 4 (threshold drain, dup sigs, validator takeover, no rate limit) | 2 (legitimate withdrawal, insufficient sigs) |

**Total: 16 passing tests, 11 exploit reproductions**

## 4. Evaluation Modes

### 4.1 Detect Mode

**Input:** Contract source code (Solidity)
**Output:** List of vulnerabilities with type, severity, location, description
**Scoring:**
- **True Positive (TP):** Finding matches a ground truth vulnerability type
- **False Positive (FP):** Finding doesn't match any ground truth
- **False Negative (FN):** Ground truth vulnerability not detected

**Metrics:** Precision, Recall, F1

```
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2 * P * R / (P + R)
```

### 4.2 Patch Mode

**Input:** Contract source + identified vulnerability description
**Output:** Patched Solidity source code
**Scoring:**
1. **Compiles:** Does the patched contract compile? (binary)
2. **Exploit blocked:** Does the original exploit fail against the patch? (binary)
3. **Functionality preserved:** Do legitimate operations still work? (binary)

### 4.3 Verify Mode (Full Pipeline)

**Input:** Contract source (no vulnerability hints)
**Output:** Detected vulns + patches + verification results
**Scoring:** Combined Detect + Patch scores

**Pipeline:** Detect → Patch → Compile → Fork → Replay → Score

## 5. Baselines

### 5.1 Static Analyzer (implemented)

Pattern-matching baseline in `agents/static_analyzer_v2.py`:
- Regex-based detection of common vulnerability patterns
- **Current F1: 55%** on pattern contracts
- Catches: reentrancy, access control, oracle, initialization bugs
- Misses: compositional vulnerabilities, cross-contract interactions

### 5.2 Claude Single-Prompt (implemented)

Single-prompt analysis in `agents/claude_analyzer.py`:
- Full contract source → Claude → vulnerability list
- Static prescreen provides hints
- **Current F1: TBD**

### 5.3 Claude Agentic (implemented, WIP)

Multi-turn agent in `agents/agentic_analyzer.py`:
- Agent has tools: read source, search patterns, analyze functions
- Can iteratively refine analysis
- **Current F1: TBD**

### 5.4 External Tools (planned)

| Tool | Type | Integration Status |
|------|------|--------------------|
| Slither | Static analysis | Planned (Week 4) |
| Mythril | Symbolic execution | Planned (Week 4) |
| Manual audit | Human expert | Planned (for calibration) |

## 6. Reproducibility

### 6.1 Local Setup

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash && foundryup

# Install Python deps
pip install -r ai-security/requirements.txt

# Run Foundry exploit reproduction tests
cd ai-security/foundry && forge test -vv

# Run static analyzer baseline
make test-static

# Run Claude analyzer (needs ANTHROPIC_API_KEY)
make test-claude
```

### 6.2 Docker Setup

```bash
docker build -t bridge-bench .
docker run -e ANTHROPIC_API_KEY=sk-... bridge-bench
```

### 6.3 Blockchain Forking

For real exploit reproduction (requires RPC endpoint):
```bash
# Fork mainnet at pre-Nomad-exploit block
anvil --fork-url $ETH_RPC_URL --fork-block-number 15259100

# Run exploit PoC against fork
forge test --fork-url $ETH_RPC_URL --fork-block-number 15259100
```

## 7. Roadmap

| Week | Milestone |
|------|-----------|
| 1 (done) | 10 real exploits catalogued, static baseline (55% F1), Claude analyzer |
| 2 (current) | Foundry simulation, exploit reproduction, benchmark spec |
| 3 | Expand to 20+ contracts, first Claude agent against real contracts |
| 4 | Slither/Mythril baselines, head-to-head comparison |
| 5 | Agentic detection with bridge-specific tools, expand to 50+ |
| 6 | Patch generation + verification, defense comparison |

## 8. Related Work

- **SCONE-bench** (Xiao & Killian, 2026): 405 smart contract exploits, offense-focused
- **EVMbench** (arXiv 2603.04915): EVM-specific evaluation benchmark
- **DefiHackLabs**: Community-maintained exploit PoC repository (our data source)
- **Slither**: Trail of Bits static analysis framework
- **Mythril**: ConsenSys symbolic execution tool
