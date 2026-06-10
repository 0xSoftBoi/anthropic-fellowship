# Data-Quality Audit: DEX & Lending Datasets (June 2026)

While wiring the DEX/AMM (`defi_contracts_real.py`) and lending
(`lending_contracts_real.py`) datasets into the runner, an exploit-by-exploit
verification against public post-mortems found that **several entries were
mislabeled, mis-chained, or are not source-level code bugs at all.** This file
records the findings so the labels can be trusted (or the entries excluded)
before any F1 number is reported on these domains. Methodology mirrors the
bridge work: confirm the vulnerable contract address on-chain, read the
post-mortem, and only keep entries that are genuine source-detectable bugs in
verifiable Solidity.

## Summary

| Entry | Committed label | Verdict | Action |
|-------|-----------------|---------|--------|
| Euler Finance | donation_attack + slippage | ✅ source bug; label refined | source committed (module `0x2718…25d3`); GT → `missing_solvency_check` |
| KyberSwap Elastic | tick_boundary + price_impact | ✅ correct mechanism | ⚠️ exploited pool not explorer-verified (repo-only); source not committed |
| Platypus | flash_loan + spot_price | ✅ correct mechanism | verified `0xc007…6ec7` on Snowtrace; needs a Snowtrace key (not on Sourcify) |
| DODO | oracle_manipulation, **BSC** | ❌ wrong chain + mechanism | corrected → Ethereum, `unprotected_initializer`; address unconfirmed |
| Curve (Vyper) | reentrancy | ⚠️ not Solidity | **exclude** from a Solidity source-detection set (Vyper compiler bug) |
| Compound | oracle_manipulation, **$80M** | ❌ event does not exist | the real 2021 event is the COMP **reward-accounting** bug; relabel |
| Venus | flash_loan_collateral_inflation, $200M | ❌ not a code bug | **exclude** — market/oracle event (XVS spot-price-driven bad debt) |
| Cream | reentrancy, **$130M, Oct-2021** | ❌ conflates two hacks | Oct-2021 $130M = oracle manip; the reentrancy is Aug-2021 (~$18.8M) |

## DEX details

- **Euler ($197M, 2023-03-13, Ethereum).** Real Solidity bug: `EToken.donateToReserves()`
  performed no account health/solvency check, enabling self-underwatering + self-liquidation
  at the max dynamic discount. The per-asset eTokens are *proxies* (verified as `Proxy` only);
  the bug lives in the **module implementation `0x27182842E098f60e3D576794A5bFFb0777E025d3`**
  (verified "Euler" on Etherscan/Blockscout) — now committed. Ground truth corrected from
  `missing_slippage_protection` to `missing_solvency_check`.
- **KyberSwap Elastic ($46M, 2023-11-22, Ethereum).** Correct mechanism (tick-crossing /
  double-counted reinvestment liquidity from an off-by-one precision bug). But the exploited
  pool `0x1694…909a` is factory-deployed and **not source-verified on the explorer**; the
  Solidity is repo-only (`KyberNetwork/ks-elastic-sc`). Not committed pending a verified artifact.
- **Platypus ($8.5M, 2023-02-16, Avalanche).** Correct mechanism: `MasterPlatypusV4.emergencyWithdraw()`
  checked solvency before accounting for outstanding USP debt. Verified at
  `0xc007f27B757A782c833C568f5851Ae1DFE0e6ec7` on Snowtrace, but Avalanche isn't served by
  the Blockscout instance used here and it's not on Sourcify — needs a Snowtrace key to fetch.
- **DODO (~$3.8M, 2021-03-09).** **Chain was wrong (BSC → Ethereum)** and **mechanism was wrong
  (oracle → `unprotected_initializer`)**: the crowdpool `init()` lacked an access-control / re-init
  guard, abused via the flash-loan callback. Metadata corrected; verified pool address still
  unconfirmed (derive from the attack tx before committing source).
- **Curve ($70M, 2023-07-30).** **Vyper** compiler reentrancy-lock bug — the affected pools have
  **no verified Solidity version**. A Solidity source-detection benchmark cannot see a Vyper
  compiler bug; recommend excluding (the committed `curve_finance_*reentrancy.sol` is a stand-in,
  not the exploited Vyper code).

## Lending details (the weakest domain)

- **Compound ("$80M oracle").** No such event exists. The real 2021 Compound incident was the
  **COMP reward-distribution accounting bug** (Sept 2021, Proposal 062 / `drip()`), which
  *over-paid* COMP — an accounting/logic error in the Comptroller, **not** oracle manipulation
  and not an external hacker drain. If kept, relabel `reward_accounting_error` and point at the
  P062 Comptroller implementation behind Unitroller `0x3d98…Cd3B`.
- **Venus (~$200M, 2021-05-18, BSC).** **Not a protocol code bug.** XVS spot price spiked then
  crashed on thin liquidity; the oracle tracked spot, users over-borrowed against inflated XVS
  collateral, and the crash created mass bad debt. The code worked as designed — a market/oracle
  *design* failure with no buggy line to detect. **Exclude from source-detection.**
- **Cream ("reentrancy, $130M, Oct-2021").** Conflates two distinct hacks:
  - **Oct-27-2021, ~$130M** — flash-loan **price-oracle manipulation** of yUSDVault collateral
    valuation (a share-price design flaw), **not reentrancy**.
  - **Aug-30-2021, ~$18.8M** — genuine **ERC-777 cross-function reentrancy** (AMP `tokensReceived`
    hook re-entered `borrow()` before state update; a CEI violation in the crAMP market). *This*
    is the real source-detectable reentrancy bug and where the `reentrancy` label belongs.

## Bottom line

- **DEX**: 2 of 5 are cleanly source-detectable + fetchable today (Euler committed; Curve is a
  Vyper stand-in). KyberSwap (unverified pool) and Platypus (Snowtrace key) are fetchable with
  more effort; DODO needs address derivation. Labels corrected in `defi_contracts_real.py`.
- **Lending**: as committed, 2 of 3 are not source-level code bugs (Venus, Cream-Oct) and the
  third (Compound) is mislabeled. The domain should not be run for an F1 number until it is
  rebuilt around genuine source bugs (e.g. Cream-Aug ERC-777 reentrancy, a real Compound-fork
  reentrancy, an Euler-style health-check miss). **Recommend not reporting lending F1 yet.**

This audit is the honest precondition for any multi-domain generalization claim: the bridge
domain is solid (16 verified contracts), DEX is partially solid (needs 2–3 more fetches), and
lending needs a rebuild. Reporting a cross-domain number before this would be measuring noise.
