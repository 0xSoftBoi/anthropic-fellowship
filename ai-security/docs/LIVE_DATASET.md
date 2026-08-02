# The live / negative-control dataset: testing on code that *wasn't* hacked

**Measured, no API key required for the static baseline:**
`python -m agents.benchmark_runner --live --no-claude && python -m agents.specificity results_live.json`

## Why this exists

Every other domain in this benchmark is a famous historical exploit. That construction has
two holes, and this dataset is the direct fix for both:

1. **Memorization.** Ronin, Euler, Nomad each have a public post-mortem almost certainly in
   the model's training data ([CONTAMINATION.md](CONTAMINATION.md)). A finding can come from
   recalling the write-up rather than reading the code.
2. **No negative controls.** All 24 exploit contracts carry a labeled bug, so the base rate
   is 100% and the model's **false-positive rate is unmeasurable**. A detector that flags
   every contract scores identically to a real one. Half of "is this a good detector?" —
   the specificity half — the exploit set structurally cannot answer.

The contracts here are the first-party Solidity that **Suwappu**
(github.com/0xSoftBoi/suwappubot, a cross-chain DeFi SDK) deploys and depends on:
`SUWP` (token), `SuwppuStaking` (Superfluid real-yield staking), `SuwppuBonds`
(protocol-owned-liquidity bonds), and `SuwpOFT` (LayerZero omnichain token). They are the
answer to "shouldn't we test on stuff that wasn't hacked?"

| Property | Exploit domains | This domain |
|---|---|---|
| In training data as an incident | Yes (famous hacks) | **No** (first-party, never exploited) |
| Base rate of bugs | 100% | ~0% (audit-hardened) |
| Measures | recall | **specificity** (false-positive rate) |
| A finding is | expected | a screened false positive **or** a real miss |

## What the ground truth is

`ground_truth.vulnerabilities = []`, `metadata.negative_control = True`. These contracts went
through three manual audit passes (nine critical/high bugs found and fixed) plus
Slither / Aderyn / Mythril / Medusa; the committed versions are the *fixed* code. So the honest
label is **"no known critical/high source bug,"** and the question is the one the exploit set
can't ask: **does the model over-flag real, hardened, unfamiliar code?**

Scored by `agents/specificity.py`, not F1 — F1 is 0 on an empty ground truth whether the model
was perfect or useless, which is exactly the distinction a negative control exists to make:

```
specificity = (# contracts flagged with nothing) / (# negative-control contracts)
```

**Static baseline (committed, `results_live.json`):** specificity **75%** — 3/4 clean; the
static analyzer flags `unprotected_admin_function` twice on `SuwppuBonds` (a centralization
nit on owner-privileged functions, the exact pattern SECURITY.md notes the tooling raises).
The LLM run needs a key; the harness and scorer are ready.

## Three honesty caveats (stated, not buried)

1. **Softer negative than a paid audit.** The audits were the author's own manual passes plus
   open-source tooling, not an external firm, and the contracts are testnet-deployed
   (Base Sepolia), not mainnet. "No known critical bug" = "none found by those passes."
2. **A finding here is not automatically wrong.** It may be a real bug the self-audit missed.
   Raw finding-count is a **screen**; deciding whether a flagged item is a true false positive
   or a genuine miss needs the **source-aware semantic judge**
   ([JUDGE_VALIDITY.md](JUDGE_VALIDITY.md), `judge_ablation.py` source-visible arm) reading the
   contract — the two pieces compose.
3. **Leakage cuts the other way for negatives.** For an exploit contract, a leaky header
   states the bug; for a negative, a leaky header states "nothing to find here." The committed
   `.sol` files therefore carry **provenance only** (repo, address, chain) — the audit/clean
   facts live in the loader metadata and this doc, never in the prompt. A test
   (`test_live.py::test_committed_source_does_not_leak_the_answer`) enforces it.

## The contracts Suwappu is reliant on

**First-party (committed, runnable negative controls):** `suwappu_suwp`, `suwappu_staking`,
`suwappu_bonds`, `suwappu_oft`.

**External dependencies (catalogued in `live_contracts.py`, source not committed):** Superfluid
(Host / GDA forwarder / USDCx), Uniswap v3 (PositionManager / Factory), USDC, Polymarket CTF
exchange, Coinbase SpendPermissionManager, and the swap-execution routers it quotes against
(1inch, CoW; also KyberSwap and LiFi — which, tellingly, *do* have exploit history and already
appear in the bridge/DEX domains: "depended-on" and "unexploited" are not the same set). Each
is tagged with a `memorization_exposure` estimate — Uniswap v3 is `high` (heavily in training
data), Superfluid is `low` — so a future expansion can pick the low-exposure ones to preserve
the memorization-control value. Fetching their source is the next build step
(`fetch_contracts.py` + keyless Blockscout/Sourcify, which are reachable from this environment).

## The strongest extension (not built here): the matched pair

The single most valuable follow-up is a **buggy/fixed matched pair**. The nine audit findings
were fixed in git history; recovering the pre-audit versions and labeling them with the
documented findings would give **real positives with zero memorization confound** — the same
contract, before and after the fix. That is the naturally-occurring version of the synthetic
perturbation experiment in [CONTAMINATION.md](CONTAMINATION.md), and it is strictly better
because the bugs are real.

It is deliberately **not** built here, for the same reason the rest of this work exists:
mapping prose audit notes to exact pre-fix source is error-prone, and hasty labels are the
defect this whole review has been removing. The recipe, to do it right:

1. `git -C suwappubot fetch --unshallow` (the clone here is `--depth 1`).
2. Find the audit-fix commits (`DEPLOYMENTS.md` says the full bug history is in the commit log).
3. For each fix, take the **parent** commit's contract as the buggy version.
4. Label it from the fix commit's own description + the audit note — and have the source-aware
   judge confirm the labeled bug is actually present in that pre-fix source before committing it.

That closes the loop: leakage (fixed), memorization (measured, plus this real control),
judge validity (measured), and finally recall-on-unmemorized-bugs — the one measurement no
famous-exploit benchmark can honestly make.
