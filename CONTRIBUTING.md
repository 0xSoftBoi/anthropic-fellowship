# Contributing to Anthropic Fellows Research

We welcome contributions! This document outlines ways to help, especially with **data collection and benchmarking**.

---

## 🎯 Current Needs (Priority Order)

### 1. **Run Benchmarks on DEX/Lending Contracts** (HIGHEST PRIORITY)

**What:** Execute existing benchmark suite on DEX and lending datasets to measure F1 across domains.

**Why:** Proves that LLM reasoning generalizes beyond bridges to all DeFi domains.

**How:**

```bash
# Setup (one time)
cd ai-security
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
export ETHERSCAN_API_KEY=...

# Run DEX contracts (Phase 5B)
python3 agents/benchmark_runner.py --defi --hybrid > results_defi_hybrid.json
python3 agents/benchmark_runner.py --defi --agentic > results_defi_agentic.json

# Run lending contracts (Phase 5C)
python3 agents/benchmark_runner.py --lending --hybrid > results_lending_hybrid.json
python3 agents/benchmark_runner.py --lending --agentic > results_lending_agentic.json

# Report results back to project
```

**Cost:** ~$5-10 total for all runs (Sonnet API calls)

**Effort:** 30 minutes setup, ~2 hours runtime, 10 minutes reporting

**Output:** JSON files with F1 scores for each contract + aggregate metrics

---

### 2. **Expand Ground Truth Vulnerabilities**

**What:** Manually verify Sonnet findings on real contracts and add to ground truth dataset.

**Why:** Ground truth determines F1 scoring. Better ground truth = accurate metrics.

**How:**

1. Run agentic analyzer on a contract:
```bash
PYTHONPATH=. python3 agents/agentic_analyzer.py --contract euler_finance
```

2. Review findings (check against public audits or exploit post-mortems)

3. For each finding with confidence ≥0.85:
   - Verify it's a real vulnerability (read audit or CVE)
   - Add to `benchmarks/defi_contracts_real.py`:
```python
"euler_finance": {
    "vulnerabilities": [
        {"type": "donation_attack_bad_debt", "severity": "critical", ...},
        {"type": "price_oracle_manipulation", "severity": "critical", ...},
    ]
}
```

**Cost:** Free (no API calls)

**Effort:** 2-3 hours per contract

**Output:** Updated ground truth + improved benchmark accuracy

---

### 3. **Fetch Missing Contract Source Code**

**What:** Use `fetch_contracts.py` to download Solidity source for 7 missing bridge contracts.

**Why:** Can't analyze contracts without source code.

**Contracts:**

| Contract | Chain | Status | Issue |
|----------|-------|--------|-------|
| Ronin Bridge | Ethereum | Missing | Not verified on Etherscan |
| Qubit Finance | BSC (56) | Missing | Needs chainid parameter |
| Poly Network | Ethereum | Missing | Proxy → impl resolution |
| Orbit Chain | Ethereum | Missing | Korean protocol (Klaytn?) |
| LiFi Facets | Ethereum | Missing | Diamond proxy pattern |
| Allbridge | BSC | Missing | Chainid verification |
| Wormhole | Ethereum | Missing | Complex multi-sig |

**How:**

```bash
cd ai-security
export ETHERSCAN_API_KEY=...

# Test fetching a contract
python3 benchmarks/fetch_contracts.py --contract nomad_bridge_replica --output contracts/

# Fix chainid issues (update fetch_contracts.py)
# For BSC contracts, add chainid=56
# For Polygon, add chainid=137
# etc.

# For proxy contracts, resolve implementation address from Etherscan API
```

**Cost:** Free (Etherscan has free tier)

**Effort:** 1-2 hours (debugging proxy resolution, chainid issues)

**Output:** Updated `benchmarks/bridge_contracts_real.py` with 7 new sources

---

### 4. **Add New Exploit Datasets**

**What:** Identify new real exploits from DeFiHackLabs and create new domain datasets.

**Domains to target:**
- **Cross-chain swaps** (e.g., 1inch, Squid, Li.Fi v3)
- **Isolated markets** (e.g., Ajna, Benqi, Moonwell)
- **Stablecoins** (e.g., Curve/crvUSD, MakerDAO-adjacent)
- **Liquid staking** (e.g., Lido, Rocket Pool derivatives)
- **Options/Futures** (e.g., Opyn, Perp Protocol)

**How:**

1. Find exploit on [DefiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs)
2. Create new file: `benchmarks/swaps_contracts_real.py`
3. Follow existing structure:
```python
def load_swaps_contracts():
    return [
        {
            "name": "squid_router",
            "source": "...",  # From Etherscan or GitHub
            "chain": "ethereum",
            "vulnerabilities": [
                {"type": "...", "severity": "...", ...}
            ]
        }
    ]
```

4. Update `agents/benchmark_runner.py` to add `--swaps` flag

**Cost:** Free

**Effort:** 2-3 hours per dataset (research + structure)

**Output:** New exploitable dataset + expanded benchmark coverage

---

### 5. **Cross-Chain Testing**

**What:** Test vulnerability detector on contracts from chains other than Ethereum.

**Chains to cover:**
- Polygon (137)
- Arbitrum (42161)
- Optimism (10)
- Base (8453)
- Avalanche (43114)

**How:**

```bash
# Modify fetch_contracts.py to set chainid
# Run benchmarks on contracts from different chains

python3 benchmarks/fetch_contracts.py --contract bridge_xyz --chain 137 --output contracts/

# Test hybrid analyzer
PYTHONPATH=. python3 agents/hybrid_analyzer.py --contract polygon_bridge
```

**Cost:** Minimal (Etherscan API calls, few Sonnet runs)

**Effort:** 1-2 hours per chain

**Output:** Cross-chain performance metrics (does LLM generalize across chains?)

---

### 6. **Create Analysis Tools**

**What:** Build new static analysis detectors or improve existing ones.

**Ideas:**
- Detector for "tick boundary exploits" (Uniswap V3 tick arithmetic)
- Detector for "flash loan price manipulation" (getReserves patterns)
- Detector for "diamond proxy facet shadowing" (multi-facet access control)
- Improved CFG (control flow graph) builder for cross-contract analysis

**How:**

Create new checker in `agents/static_analyzer_v2.py`:

```python
def check_tick_boundary_exploit(source_code: str) -> list[StaticFinding]:
    """Detect tick arithmetic precision loss in Uniswap V3-like AMMs."""
    findings = []
    # Check for unchecked tick boundary calculations
    # Look for integer truncation patterns
    # Flag if no rounding protection
    return findings
```

**Cost:** Free

**Effort:** 3-5 hours per tool

**Output:** Improved static baseline F1 score

---

## 🏃 Quick Start for Contributors

### Option A: Run Existing Benchmarks (Easiest, ~2 hours)

```bash
# 1. Clone repo
git clone <repo>
cd anthropic-fellowship/ai-security

# 2. Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Get API keys (free)
# - ANTHROPIC_API_KEY: https://console.anthropic.com
# - ETHERSCAN_API_KEY: https://etherscan.io/apis

# 4. Run benchmarks
export ANTHROPIC_API_KEY=sk-ant-...
export ETHERSCAN_API_KEY=...
python3 agents/benchmark_runner.py --real --hybrid

# 5. Share results
# Create an issue with the JSON output from results.json
```

### Option B: Expand Ground Truth (Free, ~3 hours)

```bash
# 1-2. Clone + setup (same as Option A, skip API keys)
# 3. Run analyzer on one contract
python3 agents/agentic_analyzer.py --contract my_contract
# 4. Verify findings against audits
# 5. Update benchmarks/defi_contracts_real.py
# 6. Submit PR with expanded ground truth
```

### Option C: Fetch Missing Sources (Free, ~1-2 hours)

```bash
# 1-2. Clone + setup (same as Option A)
# 3. Run fetch_contracts.py on missing contracts
python3 benchmarks/fetch_contracts.py --contract ronin_bridge --output contracts/
# 4. Fix chainid/proxy issues in fetch_contracts.py
# 5. Update benchmarks/bridge_contracts_real.py with new sources
# 6. Submit PR with new sources
```

---

## 📋 Submission Process

1. **Fork the repo** or create a branch
2. **Make changes** (add data, run benchmarks, expand ground truth, etc.)
3. **Create a Pull Request** with:
   - Clear title: e.g., "feat: Add DEX benchmark results for Curve, Kyberswap"
   - Description: Why this matters, what was tested, what were the results
   - Results: JSON files, metrics, or updated ground truth
4. **Maintainers will review** and merge

---

## 💡 Ideas for Advanced Contributors

- **Multi-turn optimization:** Reduce Sonnet turns from 8 to 6 while keeping F1. (Cost reduction)
- **Prompt engineering:** Test different system prompts for different vulnerability classes. (Accuracy improvement)
- **Tool integration:** Add Mythril + Slither to hybrid analyzer. (Reduce false positives)
- **Formal verification:** Compare LLM findings against formal verification (Z3, Coq). (Validation)
- **Reproducibility:** Run benchmarks with different model versions (Sonnet 3, 4, 4.5). (Consistency)

---

## 🚀 Contact

Have questions? Open an issue or submit a discussion.

---

**Last Updated:** April 7, 2026  
**Focus Areas:** DEX/lending benchmarks (Phase 5B/5C), source fetching (Phase 7)
