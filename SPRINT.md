# Sprint Tracker

## Week 1 (Apr 7-13): Transformer Internals
**Mech Interp**
- [x] Watch + code along: Neel Nanda GPT-2 from scratch (Part 1)
- [x] Watch + code along: Neel Nanda GPT-2 from scratch (Part 2)
- [x] Fill in ARENA template notebook (no copy-paste)
- [ ] Read: "Transformers for Software Engineers" (Nelson Elhage)
- [x] Install TransformerLens, load GPT-2 small, inspect hooks
- [x] ★ BONUS: Experiment 01 — factual lookup localization
- [x] ★ BONUS: Experiment 02 — multi-token confound (NOVEL FINDING)
- [x] ★ BONUS: Experiment 03 — cross-model replication
- [x] ★ BONUS: Experiment 04 — negation processing (NOVEL FINDING)
- [x] ★ BONUS: Experiment 05 — negation cross-model replication
- [x] ★ BONUS: Draft writeup 01 — multi-token confound
- [x] ★ BONUS: Draft writeup 02 — negation as factual booster

**AI Security**
- [x] Read Xiao & Killian paper in full
- [x] Survey SCONE-bench structure and methodology
- [x] List top 10 cross-chain bridge exploits with dollar amounts
- [x] Draft initial research question
- [x] ★ BONUS: Bridge exploit benchmark (10 exploits, $2.1B)
- [x] ★ BONUS: Static contract analyzer
- [x] ★ BONUS: Claude-powered deep analyzer
- [x] ★ BONUS: Evaluation harness with ground truth
- [x] ★ BONUS: End-to-end pipeline (static baseline: 41% F1)
- [x] ★ BONUS: Etherscan contract fetcher
- [x] ★ BONUS: Fellowship application draft

**Hours target: 18** (3h weeknights + 8h weekend)

---

## Week 2 (Apr 14-20): Core Mech Interp Techniques
**Mech Interp**
- [x] ARENA: "Mech Interp Intro: TransformerLens, Induction Heads"
- [x] Practice: direct logit attribution on GPT-2 small
- [x] Practice: activation patching to change outputs
- [ ] Skim: "A Mathematical Framework for Transformer Circuits"
- [x] ★ BONUS: Experiment 06 — induction head detection (L5H5=0.92, L4H11 prev-token)
- [x] ★ BONUS: Experiment 07 — direct logit attribution + logit lens
- [x] ★ BONUS: Experiment 08 — activation patching heatmaps (causal localization)

**AI Security**
- [x] Set up local Hardhat/Foundry simulation environment
- [x] Reproduce one known exploit in simulation
- [x] ★ BONUS: Reproduce 3 exploit patterns (Nomad, Wormhole, Ronin) — 16 passing Foundry tests
- [x] Draft benchmark specification for cross-chain vulnerabilities

**Hours target: 18**

---

## Week 3 (Apr 21-27): Superposition & SAEs
**Mech Interp**
- [ ] Deep read: "Toy Models of Superposition"
- [x] ARENA: Superposition and SAE exercises
- [x] ★ BONUS: Experiment 09 — toy model superposition (phase transitions, importance)
- [ ] Explore Neuronpedia — annotate 10 interesting features
- [ ] Skim: DeepMind negative SAE results (understand limitations)

**AI Security**
- [x] Build initial dataset: 20+ cross-chain bridge contracts with known vulns
- [x] ★ BONUS: 20 contracts, 44 labeled vulnerabilities, 17 vuln classes
- [x] Write first Claude agent prompt for contract analysis
- [x] Test agent against 5 known exploits in simulation
- [x] ★ BONUS: Foundry integration pipeline (detect → patch → verify)
- [x] ★ BONUS: Static baseline evaluation (48% F1 on 14 ground truth vulns)

**Hours target: 18**

---

## Week 4 (Apr 28-May 4): Anthropic's Frontier + Security Agent v1
**Mech Interp**
- [ ] Read: "Tracing the Thoughts of a Large Language Model"
- [ ] Read: "On the Biology of a Large Language Model"
- [ ] Try circuit-tracer on Gemma-2-2b via Neuronpedia
- [ ] Read: "Signs of Introspection" + "The Assistant Axis"
- [x] ★ BONUS: Experiment 10 — SAE on GPT-2 small (from-scratch implementation)

**AI Security**
- [x] Agent v1: Claude-based contract vulnerability scanner
- [x] Test against 20+ contracts, measure detection rate
- [x] Document false positives/negatives
- [x] ★ BONUS: Static analyzer v2 improved 25.5% → 41.6% F1 (reduced FPs by 50%)
- [x] ★ BONUS: Benchmark v2 runner with full P/R/F1 scoring
- [x] Compare against Slither/Mythril baselines
- [x] ★ BONUS: Slither gets 11.1% F1 — our static analyzer (41.6%) wins decisively

**Hours target: 20**

---

## Week 5 (May 5-11): Mini-Projects + ICML Deadline
**Mech Interp**
- [x] Mini-project #1: greater-than circuit in GPT-2 small
- [x] ★ BONUS: 5-step analysis (behavior, attention, patching, ablation, logit lens)
- [x] ★ BONUS: Found 117x above/below ratio, L5H5/L6H1 as comparison heads
- [ ] Write up findings (even if negative)
- [ ] STRETCH: submit short paper to ICML workshop (deadline May 8)

**AI Security**
- [ ] Agent v2: add cross-chain bridge-specific detection logic
- [ ] Expand benchmark to 50+ contracts
- [ ] Write initial results section

**Hours target: 22**

---

## Week 6 (May 12-18): Second Mini-Project + Portfolio
**Mech Interp**
- [ ] Mini-project #2: different technique than #1
- [ ] Read "Open Problems in Mechanistic Interpretability"
- [ ] Post both writeups to Alignment Forum

**AI Security**
- [ ] Defense angle: can agent suggest patches?
- [ ] Compare detection rates: AI agent vs Slither vs Mythril vs manual audit
- [ ] Draft blog post on findings

**Hours target: 20**

---

## Week 7 (May 19-25): Application Week
- [ ] Draft fellowship application (research proposal + portfolio links)
- [ ] Frame: systems engineer bringing DeFi domain expertise to AI safety
- [ ] Get feedback from EA/alignment community
- [ ] SUBMIT APPLICATION
- [ ] Push all code + writeups to GitHub

**Hours target: 15**

---

## Week 8 (May 26-Jun 1): Depth Sprint + Backups
- [ ] Continue strongest research direction
- [ ] Apply to MATS (if open)
- [ ] Apply to Goodfire
- [ ] Apply to Anthropic Research Engineer role
- [ ] Publish blog post summarizing the journey

**Hours target: 15**
