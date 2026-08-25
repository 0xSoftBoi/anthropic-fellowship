---
name: anthropic-fellowship
description: How BRIDGE-bench works — the provider-agnostic LLM smart-contract vulnerability benchmark in ai-security/. Use when adding analyzers, running the benchmark across models, changing the evaluation, or touching the model layer.
---

# BRIDGE-bench (anthropic-fellowship / ai-security)

BRIDGE-bench measures how well LLMs find vulnerabilities in real smart contracts.
Every model runs the same contracts through the same analyzers and is scored by the
same calibrated judge, so F1 differences reflect the *model*, not the harness. A
sibling track lives in `mech-interp/` (TransformerLens replication); this skill
covers `ai-security/`.

## Repo map

- `agents/` — analyzers + the model layer + evaluation.
- `benchmarks/` — datasets (verified bridge / DeFi / lending contracts as Solidity
  fixtures) and `validate_dataset.py`. Solidity here is *data*, not app code.
- `docs/` — `INDEX.md` (start here), `RESEARCH.md`, `MULTI_MODEL.md`,
  `OPTIMIZATION.md`, `DATA_QUALITY.md`, `DATASHEET.md`.
- `tests/` — pytest (`test_eval.py`).

## The one rule: all model calls go through `agents/llm.py`

`llm.completion(...)` is the single path to any model. Never import a provider SDK
directly. The layer gives you:
- `MODELS` registry + aliases: `sonnet`, `opus`, `haiku`, `fable` (Anthropic
  baselines) and `deepseek`, `kimi`, `qwen`, `minimax`, `glm`, `local` (candidates).
- `litellm_model()` resolves `BENCH_MODEL`; `model_tag()` gives the bare name used
  to **stamp result filenames** (keeps committed baselines from being clobbered).
- `has_credentials()` — lets a DeepSeek/local run proceed without
  `ANTHROPIC_API_KEY`.
- `cacheable()` / `cached_tokens()` — prompt caching; `to_openai_tools()` —
  Anthropic→OpenAI tool-schema conversion; `context_budget_chars()` /
  `LARGE_CONTEXT_MODELS` — big-context models read whole contracts, Anthropic stays
  at the conservative default so its baseline is byte-reproducible.

## Analysis modes

| Mode | Flag | Entry point | Idea |
|------|------|-------------|------|
| Static baseline | (default) | `static_analyzer_v2.analyze_static` | free regex/heuristic — no API |
| Single-turn | (default, key set) | `claude_analyzer` | one prompt |
| Agentic | `--agentic` | `agentic_analyzer.run_agent` → `AgentAudit` | multi-turn tool loop |
| Hybrid | `--hybrid` | `hybrid_analyzer.run_hybrid_analysis` | Slither/Mythril pre-filter → targeted Sonnet |
| Cascade | `--cascade` | `cascade_analyzer.run_cascade` → `CascadeAudit` | cheap wide-net → strong-model escalation |
| Self-consistency | `--sc` / `--selfconsistency` | `selfconsistency_analyzer.run_self_consistent` → `SelfConsistencyAudit` | k samples, majority vote |

Datasets: `--real` (bridges), `--defi` (DEX/AMM), `--lending`. Also `--compare`,
`--no-claude`.

## Running

```bash
cd ai-security
make setup                                              # venv + deps
python3 -m benchmarks.validate_dataset                  # dataset integrity, no API key
python3 -m agents.benchmark_runner --real               # free static baseline
BENCH_MODEL=opus python3 -m agents.benchmark_runner --real --agentic
BENCH_MODEL=deepseek python3 -m agents.benchmark_runner --real --cascade
```

Self-host / open weights: `BENCH_MODEL=local LLM_BASE_URL=http://... LLM_API_KEY=... LOCAL_MODEL=...`
(contract source never leaves the network). Makefile targets: `setup`,
`test-static`, `test-claude`, `benchmark`, `benchmark-real`, `benchmark-compare`,
`fetch-contracts`.

## Evaluation — and the judge invariant

`eval_harness.py` computes precision / recall / F1. Exact string matching
under-counts real hits, so `semantic_rescorer.py` uses an LLM judge
(`JUDGE_MODEL`, default `claude-haiku-4-5-...`) to semantically match findings to
ground truth and recompute F1; `validate_judge.py` sanity-checks the judge.

**Invariant:** the judge stays on a fixed, calibrated Anthropic model for every
candidate. Do **not** set `JUDGE_MODEL` to the model under test — that breaks
cross-model comparability, which is the entire point of the benchmark.

## Config (environment variables)

- Model: `BENCH_MODEL`, `LLM_BASE_URL`, `LLM_API_KEY`, `LOCAL_MODEL`,
  `LLM_NUM_RETRIES`, `LLM_TIMEOUT`, `LLM_MAX_SOURCE_CHARS`.
- Throughput: `BENCH_CONCURRENCY`, `JUDGE_CONCURRENCY`.
- Modes: `CASCADE_CHEAP_MODEL`, `CASCADE_STRONG_MODEL`, `CASCADE_MAX_TURNS`,
  `CASCADE_ALWAYS_ESCALATE`; `SC_SAMPLES`, `SC_MIN_VOTES`, `SC_TEMPERATURE`; `BUDGET`.
- Eval: `JUDGE_MODEL`. Data fetching: `ETHERSCAN_API_KEY`, `ETH_RPC_URL`.

## Conventions

- Absolute, package-rooted imports (`from agents.llm import completion`); no
  relative imports, no `__all__`.
- `snake_case` files/functions, `PascalCase` dataclasses (`AgentAudit`,
  `CascadeAudit`, `StaticFinding`), `SCREAMING_SNAKE_CASE` constants.
- Tests in `tests/`, pytest: `python -m pytest tests/ -q`.
- Commits: concise, often `type:` prefixed (`feat:`, `docs:`, `fix:`), with a
  `Co-Authored-By:` trailer on agent commits.

## Invariants to protect

1. Route every model call through `llm.completion` — never a provider SDK.
2. Result files are model-stamped (`model_tag()`); don't overwrite committed baselines.
3. Keep the judge on a calibrated Anthropic model (comparability).
4. Leave the Anthropic context budget at its default so its baseline stays byte-reproducible.
5. No API key? Use the static baseline and `validate_dataset` — both run keyless.
