---
name: anthropic-fellowship
description: Development patterns and conventions for the anthropic-fellowship research repo (Python 3.10+; BRIDGE-bench AI-security harness + mech-interp). Use when adding code, writing tests, or running benchmarks in this repo.
---

# anthropic-fellowship — Development Patterns

Research portfolio with two tracks:
- **ai-security/** — BRIDGE-bench: LLM-driven smart-contract vulnerability detection, provider-agnostic via LiteLLM.
- **mech-interp/** — TransformerLens replication experiments (Python + notebooks).

## Conventions (verified against the codebase)

- **Language:** Python 3.10+ (plus Solidity fixtures under `ai-security/benchmarks/contracts/`).
- **Imports:** absolute, package-rooted — `from agents.llm import completion`, `from benchmarks.bridge_contracts_real import load_real_contracts`. The repo does **not** use relative (`from ..`) imports.
- **Naming:** `snake_case` files and functions, `PascalCase` classes (e.g. `AgentAudit`), `SCREAMING_SNAKE_CASE` constants (e.g. `MAX_SOURCE_CHARS`). There is no `__all__` / named-export convention.
- **Models:** never hard-code a provider. Route calls through `agents/llm.py` (LiteLLM) and select with `BENCH_MODEL`; result files are stamped per model so baselines aren't clobbered.
- **Commits:** concise and descriptive; a `type:` prefix (`docs:`, `feat:`, `fix:`) is common, and agent commits add a `Co-Authored-By:` trailer.

## Tests

- Live in `ai-security/tests/` (e.g. `test_eval.py`); framework is **pytest**.
- Run: `cd ai-security && python -m pytest tests/ -q`
- Dataset integrity (no API key): `python -m benchmarks.validate_dataset`

## Running the benchmark

```bash
cd ai-security
make setup                                   # venv + deps
python3 -m agents.benchmark_runner --real    # static baseline (free, no API)
BENCH_MODEL=opus python3 -m agents.benchmark_runner --real --agentic
# modes: --agentic | --cascade | --sc | --hybrid   domains: --real --defi --lending
```

Makefile targets: `setup`, `test-static`, `test-claude`, `benchmark`, `benchmark-real`, `benchmark-compare`, `fetch-contracts`.

## Adding code

1. New module → `ai-security/agents/<name>.py` (snake_case), absolute imports.
2. Route any model call through `agents/llm.py` (`llm.completion(...)`), never a provider SDK directly.
3. Add or extend tests in `ai-security/tests/`; run `python -m pytest tests/ -q`.
4. Keep result-file naming model-stamped so committed baselines aren't overwritten.
5. Commit with a concise, descriptive message.

## Docs

`ai-security/docs/`: `INDEX.md` (map), `RESEARCH.md`, `MULTI_MODEL.md`, `OPTIMIZATION.md`, `DATA_QUALITY.md`, `DATASHEET.md`.
