# Datasheet — BRIDGE-bench

Following [*Datasheets for Datasets* (Gebru et al., 2018)](https://arxiv.org/abs/1803.09010).
This documents the dataset behind the F1 numbers so they can be trusted, audited, and
reproduced. Companion docs: [DATA_QUALITY.md](DATA_QUALITY.md) (the label audit) and
[RESEARCH.md](RESEARCH.md) (methodology).

## Motivation

- **Why created?** To test whether an LLM with a tool-use loop can identify the *root-cause*
  vulnerability in real, deployed smart contracts — code that static pattern-matchers fail on
  (proxies, inheritance, compositional bugs) — across multiple DeFi domains.
- **Gap addressed.** Most public exploit datasets capture *which* contract was hacked, not a
  clean, source-level, correctly-labeled artifact suitable for detection benchmarking. Several
  widely-cited "lending hack" labels turned out to be market/oracle events or mis-attributed
  mechanisms (see DATA_QUALITY.md).

## Composition

- **Instances.** Each instance is a verified, deployed smart contract (`.sol`) paired with a
  ground-truth list of source-level vulnerability types and metadata (chain, exploit date,
  USD loss, vulnerable-contract address).
- **Counts (source-committed).** 24 contracts: **bridges 16, DEX/AMM 5, lending 3**, plus a
  separate `bridge_bench.py` registry of off-chain mega-hacks held **for loss-coverage only**
  (excluded from F1 — no source-level bug to detect).
- **Labels.** 66 ground-truth vulnerability tags across the 24 contracts (e.g. `reentrancy`,
  `missing_solvency_check`, `unprotected_initializer`, `exchange_rate_manipulation`,
  `event_spoofing`). Labels are the *root cause* a security auditor would cite.
- **Not a representative sample.** It is a curated set of notable, source-detectable exploits
  (2021–2026). It is deliberately biased toward bugs an LLM *could* see in source — pure
  key-compromise/oracle/market events are excluded.
- **Known gaps.** 4 bridge placeholders have no committed source (Etherscan-only or off-chain);
  Curve is a Vyper compiler bug included as a Solidity stand-in (a deliberate negative-ish case);
  the Cream crAMP positive uses the post-hack *patched* implementation.

## Collection process

- **Source acquisition.** Solidity source fetched programmatically from public verifiers —
  **Blockscout**, **Sourcify**, and **Routescan** (keyless) — with **every contract address
  confirmed on-chain** (verification status + name) before fetching. Provenance (address, chain,
  fetch source) is recorded in each `.sol` file header.
- **Factory-deployed pools.** Where the exploited instance is unverified (KyberSwap, DODO), a
  verified *same-implementation* deployment or the verified clone *template* is used; this is
  flagged in the file header and DATA_QUALITY.md.
- **Time frame.** Exploits span 2021-08 (Poly Network) to 2026-06 (Humanity Protocol).

## Preprocessing / labeling

- Large contracts are function-extracted at analysis time (not in storage) to fit the agent's
  context; stored source is the full flattened verified source minus heavy libraries (OpenZeppelin etc.).
- **Ground-truth labels** were assigned by the author from public post-mortems, corrected during
  a June-2026 audit (DATA_QUALITY.md). A frozen **38-unit judge gold standard**
  (`benchmarks/judge_gold_standard.json`) hand-labels match/no-match decisions for the semantic
  scorer, with written justifications.

## Uses

- **Intended.** Benchmarking source-level vulnerability *detection* by LLMs/static tools;
  studying the exploit-centric-vs-detectable ground-truth problem; LLM-as-judge calibration.
- **Not suitable for.** Training a detector (too small; risk of memorization of public exploits),
  or claiming detection of off-chain/operational risks (those are explicitly out of scope).
- **Caveats for users.** Public exploits may appear in model training data — treat results as
  detection-under-possible-leakage. The single-annotator labels and moderate-κ judge mean F1 is
  a *direction with a stated error profile*, not a precise constant.

## Distribution & maintenance

- **License.** MIT (code + annotations). Contract source is public on-chain code under its
  original terms.
- **Integrity.** `benchmarks/validate_dataset.py` (run in CI) checks every contract has labels,
  filenames match loader keys, and every label has a scoring equivalence — so silent degradation
  is caught on each push.
- **Maintainer.** Repo owner (`0xSoftBoi`); see `CITATION.cff`.
- **Extending.** Add a verified contract to `benchmarks/contracts/<key>.sol`, register it in the
  domain loader with correctly-audited labels, and run the validator before committing.
