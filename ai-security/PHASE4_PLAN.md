# Phase 4: Scaling and Refinement

## Current State (End of Phase 3)

✅ **Completed**:
- Claude achieves 21% F1 on real production contracts (vs 0% static)
- Function extraction enables analysis of 500KB+ contracts
- Ground truth filtering for off-chain vulnerabilities
- 6 verified Etherscan contracts with scoring labels
- SYSTEM_PROMPT covers 19 vulnerability classes

✅ **Validated**:
- Thesis: LLM-based compositional reasoning outperforms static tools at scale
- Function extraction solves token budget problem (80KB budget → unlimited contract size)
- Real contract analysis is feasible (21% F1 target exceeded)

---

## Phase 4 Goals

### 1. Improve Real Contract Coverage

**Current blockers**:
- 7/13 contracts unverified (off-chain compromises, unverified proxies, BSC)
- ~2% of bridge contracts have verified Etherscan source

**Strategy**:
- [ ] Add GitHub source fallback (fetch from protocol repos if Etherscan fails)
- [ ] Implement Sourcify integration (community-verified contract database)
- [ ] Configure BSC API key for BSC contracts (Qubit, Allbridge)
- [ ] Extract Diamond proxy implementations from transaction traces

**Target**: Increase verified coverage from 6/13 (46%) to 10+ contracts

---

### 2. Enhance Claude Analysis

**Opportunities**:
- Multi-turn analysis: Ask Claude follow-up questions about detected patterns
- Context injection: Provide known exploits as reference for similar patterns
- Confidence calibration: Fine-tune confidence scores based on false positive rates
- Comparative analysis: "Compare this to Nomad bridge exploit" for similar contracts

**Target**: Improve F1 from 21% to 30%+ through better prompting

---

### 3. Extend Beyond Bridge Contracts

**Current scope**: Bridge-specific vulnerabilities (cross-chain, liquidity, message auth)

**Expansion candidates**:
- [ ] DEX/AMM vulnerabilities (sandwich attacks, oracle manipulation, impermanent loss)
- [ ] Lending protocol vulnerabilities (liquidation, collateral, rate manipulation)
- [ ] Governance vulnerabilities (voting power, proposal injection, timelock bypass)
- [ ] Wrapper token vulnerabilities (peg loss, collateral shortfall, bridge trustlessness)

**Target**: Demonstrate Claude advantage across vulnerability classes, not just bridges

---

### 4. Integration with Existing Tools

**Opportunity**: Combine Claude with Slither, Mythril for hybrid analysis

**Strategy**:
- [ ] Run Slither first → get pattern matches
- [ ] Feed Slither findings to Claude with context: "Slither found X, analyze for compositional issues"
- [ ] Aggregate findings with proper deduplication
- [ ] Measure precision/recall improvement over Claude-only approach

**Target**: Show hybrid approach beats either tool alone

---

## Implementation Priority

| Phase | Task | Effort | Impact | Timeline |
|-------|------|--------|--------|----------|
| 4.1 | GitHub source fallback | Medium | +3-4 contracts | 1-2 days |
| 4.2 | Multi-turn Claude analysis | Medium | +5-10% F1 | 2-3 days |
| 4.3 | Sourcify integration | Low | +1-2 contracts | 0.5 days |
| 4.4 | Diamond proxy extraction | High | +2 contracts | 2-3 days |
| 4.5 | DEX vulnerability expansion | High | Validate generalization | 3-5 days |
| 4.6 | Slither hybrid integration | Medium | +5% precision | 1-2 days |

---

## Success Metrics

- [ ] Claude F1 > 30% on real contracts
- [ ] 10+ verified contracts in dataset
- [ ] Multi-turn analysis implemented and tested
- [ ] Hybrid (Claude + Slither) shows measurable improvement
- [ ] 2+ non-bridge vulnerability classes analyzed

---

## Research Questions

1. **Does multi-turn analysis improve F1?** (Ask Claude: "Explain how these patterns could compose")
2. **Do similar contracts reuse exploits?** (Template-based prompt injection)
3. **Can Claude learn from prior analysis?** (Few-shot: "Like Nomad's zero-root bug, this contract...")
4. **What's the scaling limit?** (Test on arbitrarily large contracts with aggressive extraction)
5. **How does this compare to security auditors?** (Estimate human recall on same contracts)

---

## Next Immediate Steps

1. Push current work to remote: `git push origin master`
2. Create feature branch: `git checkout -b phase-4/improvements`
3. Start with GitHub fallback implementation
4. Add multi-turn analysis to claude_analyzer.py
5. Expand test dataset to non-bridge contracts

