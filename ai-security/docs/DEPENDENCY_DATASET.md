# Suwappu dependency dataset: the unhacked, in-use contracts to run on

**Goal (pre-run prep, no API key spent).** Before any paid model run, organise and prioritise the
*right* contracts: real, in-use, and — the hard rule — **not hacked**. This is the curated set of
external contracts the Suwappu product actually depends on, drawn from the product's own docs and
code, filtered to unexploited contracts, and ranked for category variety.

Data lives in [`benchmarks/dependency_registry.py`](../benchmarks/dependency_registry.py);
`python -m benchmarks.dependency_registry` prints the summary. It supersedes the thin
`EXTERNAL_DEPENDENCIES` list that used to sit in `live_contracts.py`.

## Why these and not the exploit contracts

The rest of BRIDGE-bench is famous hacks (recall-under-memorization). This dataset is the
opposite by construction: contracts a live product *relies on* that were *never* exploited — so a
model finding here is a screened false positive or a real miss, i.e. it measures **specificity**
on real, hardened, unfamiliar code. It is the negative-control complement to the exploit set, and
a superset of the first-party negative controls in [`LIVE_DATASET.md`](LIVE_DATASET.md).

## How the set was built

1. **Mined** the suwappubot repo (docs + gitbook + `bot/` + `api-ts/`) for every external
   contract the product quotes / calls / settles against — 83 raw integration entries across
   swap, lending, oracle, bridge, streaming, accounts, tokens, perps, prediction.
2. **Filtered** to the unhacked-only rule: drop anything with a protocol- or contract-level hack,
   or a disclosed critical drain vuln.
3. **Re-verified exploit history against 2025-2026 reporting.** This is the step that matters:
   *"unexploited" is time-stamped, not permanent.* Re-verification moved two contracts a static
   read would have kept **out of the clean set**:
   - **Across Protocol** — hacked ~17 Jul 2026 (~$3.6M, Solana deployment). → excluded.
   - **Coinbase SpendPermissionManager** — disclosed drain vuln (ERC-6492 × `ownerIndex`). → excluded.
   That is the negative-control analogue of the memorization thesis in this repo: re-verify the
   "clean" label before every run.
4. **Verified addresses / source** on-chain for the less-canonical picks (Blockscout: the Morpho
   oracle and the Steakhouse MetaMorpho vault on Base both return `is_verified=True`).

## Run-ready targets (EVM, unhacked, verified) — 12 contracts, 9 categories

Tiers: **clean** (no known issue) · **anchor** (clean but high training-data exposure, kept as a
recall baseline) · **caveat** (contract not exploited, but a real protocol/vault incident — note
travels with it).

| # | Tier | Category | Protocol / contract | Chain | Address | Mem. exposure |
|---|------|----------|---------------------|-------|---------|---------------|
| 1 | clean | oracle | Morpho / MorphoChainlinkOracleV2 | base | `0x663BECd10daE6C4A3Dcd89F1d76c1174199639B9` | low |
| 2 | clean | bridge | Circle CCTP v2 / TokenMessengerV2 | base | `0x28b5a0e9C621a5BadaA536219b3a228C8168cf5d` | low |
| 3 | clean | prediction | Gnosis / ConditionalTokens (CTF) | polygon | `0x4D97DCd97eC945f40cF65F87097ACe5EA0476045` | medium |
| 4 | clean | prediction | Polymarket / NegRiskAdapter | polygon | `0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296` | medium |
| 5 | anchor | lending | Aave v3 / Pool | base | `0xA238Dd80C259a72e81d7e4664a9801593F98d1c5` | high |
| 6 | anchor | dex_amm | Uniswap v3 / NonfungiblePositionManager | base | `0x03a520b32C04BF3bEEf7BEb72E919cf822Ed34f1` | high |
| 7 | anchor | token | Circle / USDC | base | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` | high |
| 8 | anchor | account_abstraction | ERC-4337 / EntryPoint v0.7 | all-evm | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` | high |
| 9 | caveat | token | Ethena / USDe | ethereum | `0x4c9EDD5852cd905f086C759E8383e09bff1E68B3` | medium |
| 10 | caveat | lending | MetaMorpho / Steakhouse USDC vault | base | `0xbeeF010f9cb27031ad51e3333f9aF9C6B1228183` | medium |
| 11 | caveat | streaming | Superfluid / GDAv1Forwarder | base | `0x6DA13Bde224A05a288748d857b9e7DDEffd1dE08` | medium |
| 12 | caveat | swap | CoW Protocol / GPv2Settlement | multi-evm | `0x9008D19f58AAbD9eD0D60971565AA8510560ab41` | high |

**Variety:** all nine target categories are covered — oracle, bridge, prediction (×2), lending
(×2), dex_amm, token (×2), account_abstraction, streaming, swap. Chains span Base, Polygon,
Ethereum, and the multi-chain rails. Ranking front-loads **low/medium-exposure** controls (1–4,
9–11) — the ones that best preserve the memorization-control value — and keeps four **high-exposure
anchors** (5–8) deliberately as recall baselines to contrast against them.

**Caveat notes (carried with the contract, never in the prompt):** USDe depegged to ~$0.65 on
Binance (Oct 2025) — exchange-side, on-chain redemptions held at $1. A MetaMorpho vault took an
~$18M market loss (Jun 2026) — collateral collapse, not a contract bug. Superfluid's *Host* had a
2022 exploit — the GDA forwarder Suwappu calls was not the exploited path. CoW's GPv2Settlement had
a 2023 solver incident (~$166k of temporarily-held funds) — core logic not broken.

## Excluded — in-use but hacked / carrying a disclosed vuln (10)

Dropped per the unhacked-only rule; recorded so the exclusion is auditable.

| Protocol / contract | Category | Why excluded |
|---|---|---|
| Across / SpokePool | bridge | **hacked ~17 Jul 2026 (~$3.6M, Solana deployment)** |
| Coinbase / SpendPermissionManager | account_abstraction | **disclosed drain vuln (ERC-6492 × ownerIndex)** |
| Li.Fi / LiFiDiamond | swap | hacked Mar 2022 (~$600k) + Jul 2024 (~$10M+) |
| KyberSwap / MetaAggregationRouter | swap | KyberSwap Elastic drained ~$48M (Nov 2023) |
| OKX DEX / DexRouter | swap | proxy-admin compromise, ~$2.7M drained (Dec 2023) |
| Socket / SocketGateway | bridge | ~$3.3M exploit (Jan 2024) |
| Wormhole / Token Bridge | bridge | forged-VAA, ~$326M (Feb 2022) |
| Allbridge Core / pool | bridge | flash-loan price manipulation, ~$570k (Apr 2023) |
| Superfluid / Host | streaming | ctx-spoofing exploit, ~$13M (Feb 2022) |
| ParaSwap / AugustusV6 | swap | disclosed vuln 2024; also not a direct dependency |

Note: the biggest in-use swap path (Li.Fi) and several routers are excluded. Most swap aggregators
(Li.Fi, 0x, 1inch, OKX, KyberSwap) also use a **per-quote dynamic address** — there is no single
on-chain target to fetch. CoW's GPv2Settlement is the exception (hardcoded canonical address), which
is why it is the one swap entry in the run-ready set.

## Deferred — in-use and unhacked, but no verified Solidity source (5)

Non-EVM or obscure-L2 forks, out of scope for a Solidity source-detection run until source is
confirmed fetchable: Jupiter (Solana), Hyperliquid HLP (HyperCore L1 — the only perps candidate),
AVNU (Starknet/Cairo), GOATSwap (GOAT), JuiceSwap (Citrea).

## Data-quality issues found in the repo (bonus)

Surfaced while mining — worth fixing in suwappubot:

- The **Polymarket CTF Exchange** address `0xE111180000d2663C0091e4f400237545B87B996B` in the code
  appears **fabricated** (a repo test asserts it is not the real exchange; the real one is
  `0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E`). The prior dependency list carried the fabricated
  one — dropped here; this dataset uses the real Gnosis CTF + NegRiskAdapter instead.
- **"pUSD" collateral** `0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB` is actually MakerDAO DAI,
  mislabeled (claimed 6dp/Polygon; DAI is 18dp/Ethereum). Real Polymarket collateral is USDC.e.
- Python config **DAI** doesn't match canonical DAI `0x6B17…271d0F`.
- Foundry `DeployTestnet.s.sol` hardcodes **stale Superfluid** values vs `DEPLOYMENTS.md`.
- **Uniswap v3 NPM (Base)** — the README truncates the address to 41 chars; the correct verified
  contract ends `…Ed34f1`, while the naive 42nd-char fill `…Ed34f4` is an unrelated **EOA**
  (found when the keyless fetch missed it; confirmed on Blockscout).

## Run-ready: source fetched, wired, tested

All 12 targets are **fetched and committed** (verified source, keyless, provenance-only headers):

```bash
python -m benchmarks.fetch_dependencies            # keyless Blockscout v2 + Sourcify fallback
python -m agents.benchmark_runner --deps --no-claude   # static baseline
python -m agents.specificity results_deps.json     # score specificity
```

- Source lives in `benchmarks/contracts_dependencies/*.sol`, each with a **provenance-only**
  header (protocol, contract, address, chain, explorer — no bug/audit/clean words; a test enforces
  it). Bug/tier/exploit metadata lives in the loader, never the prompt.
- The loader is `dependency_registry.load_dependency_contracts()`; the runner exposes `--deps`;
  `validate_dataset` covers the domain (now 6 domains, 43 source-bearing contracts).
- **Static baseline (`static_v2`, committed `results_deps.json`): specificity 17% (2/12 clean),
  ~13 findings/contract.** That is the mirror image of its 0/16 recall on the matched positives:
  the regex/heuristic analyzer both misses real bugs *and* over-flags real hardened code — useless
  in both directions on real compositional Solidity, which is the whole point of the LLM comparison.
  The interesting number is the **LLM's** specificity here (needs a key); the harness is ready.

## Before the paid run

1. **Re-verify exploit history** immediately before the run — "unexploited" decays (the Across
   lesson: it was clean when this set was assembled and hacked days later).
2. Spend the API budget — scored by `agents/specificity.py`, adjudicated by the source-aware judge
   (`judge_ablation.py` source-visible arm), exactly like the first-party negative controls. A
   flagged finding is a *screen*, not a verdict: some may be real bugs, not false positives.
3. Weight results by `memorization_exposure`: the low-exposure controls (Morpho oracle, CCTP)
   carry more negative-control signal than the high-exposure anchors (Aave, USDC, EntryPoint).
