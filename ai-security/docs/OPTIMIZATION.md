# Performance & Cost Optimization

This documents the optimization work on BRIDGE-bench across three axes — **cost
($/scan)**, **latency (wall-clock)**, and **accuracy-per-dollar (F1/$)** — plus
the roadmap for what's next.

## Phase 1 — Infra wins (shipped)

Pure cost/latency improvements. They do **not** change what the model is asked
or how its output is parsed, so they cannot regress the measured 35% F1 — they
just make each run cheaper and faster.

### 1. Prompt caching (biggest cost lever)

The agentic loop re-sends `SYSTEM_PROMPT` + tool definitions + the **entire
contract source** on every turn (up to 8–10×). Cached reads cost ~90% less, and
the consensus is that caching is *not optional* for agents running >3–5 steps.

- `agents/llm.py:cacheable()` marks the system prompt and the source-bearing
  message as cache breakpoints. Model-aware: explicit `cache_control:
  {"type":"ephemeral"}` for Anthropic/Bedrock/Gemini (LiteLLM passes it
  through); a plain string for DeepSeek/OpenAI, which **cache automatically**.
- Within a contract's loop, turns 2..N read the static prefix from cache; across
  contracts the shared system+tools prefix stays warm (5-min TTL — concurrency
  helps keep it hot).
- `cached_tokens` is tracked per run and reported as a cache-hit rate, so the
  saving is measured, not assumed.

Expected: **~50–75% input-token cost reduction** on the agentic path; input
tokens dominate the ~29K/contract budget.

### 2. Concurrency

Contracts are independent and I/O-bound (API round-trips), so the runner now
executes them through a bounded thread pool instead of one-at-a-time.

- `BENCH_CONCURRENCY` (default 4) in `run_agentic_benchmark`.
- `JUDGE_CONCURRENCY` (default 8) parallelizes the semantic rescorer's
  per-contract judge calls.
- Wall-clock is timed and printed/persisted (`wall_clock_seconds`).

Expected: **~3–8× wall-clock** on the 24-contract suite, and again across the
multi-model bake-off.

### 3. Reliability

`agents/llm.py:completion()` now passes `num_retries` (default 3, exponential
backoff inside LiteLLM) and `timeout` (default 120s). High concurrency is safe
and a transient 429/5xx no longer loses a contract. Tunable via `LLM_NUM_RETRIES`
/ `LLM_TIMEOUT`.

### 4. Instrumentation

Results now persist `cached_tokens`, `wall_clock_seconds`, and `concurrency`
alongside the existing token/tool-call counts — the baseline every later change
is measured against.

### New environment knobs

| Var | Default | Effect |
|-----|---------|--------|
| `BENCH_CONCURRENCY` | 4 | Parallel contracts in the agentic benchmark |
| `JUDGE_CONCURRENCY` | 8 | Parallel contracts in the semantic rescorer |
| `LLM_NUM_RETRIES` | 3 | Retries on transient errors (LiteLLM backoff) |
| `LLM_TIMEOUT` | 120 | Per-call timeout (seconds) |

## Phase 2 — Accuracy-per-dollar (roadmap)

These change F1 and must be validated with the calibrated judge, so they ship
behind measurement, not by default.

- **Model cascade.** Cheap wide-net pass (DeepSeek/Flash or a local model) to
  flag suspicious functions, then escalate only those to Opus, then judge-filter.
  Targets the cost-accuracy frontier: most tokens spent by the cheap model, the
  expensive model touches a fraction of the code.
- **Large-context path.** For 1M-context models (MiniMax M3, Gemini, DeepSeek),
  skip the regex function-extraction in `prepare_source_for_analysis` and feed
  whole contracts — extraction can drop cross-function context that compositional
  exploits live in. Likely recall ↑.
- **Self-consistency.** k-sample borderline findings and merge via the judge;
  trades a little cost for precision on ambiguous calls.

## Phase 3 — Bake-off throughput (roadmap)

- Parallelize `validate_judge` the same way the rescorer now is.
- Optional **Batch API** mode (Anthropic/OpenAI, −50% cost, ~24h turnaround) for
  offline bake-off runs where latency doesn't matter.
- Per-model `$`-cost rollup via `litellm.completion_cost` for a single
  F1-vs-dollar leaderboard.

## Measuring the wins

Every optimization is observable in the results JSON and run output:
`cached_tokens` + cache-hit %, `wall_clock_seconds`, `concurrency`, and the
existing token/tool-call counts. Re-run a model before/after and compare —
F1 should be unchanged by Phase 1, cost and wall-clock materially lower.
