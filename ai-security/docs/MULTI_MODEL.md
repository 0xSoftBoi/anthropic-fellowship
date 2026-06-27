# Multi-Model Support & the Cheap-Model Bake-Off

BRIDGE-bench now runs on **any model**, through one provider-agnostic path
(`agents/llm.py`, built on [LiteLLM](https://github.com/BerriAI/litellm)).
The same OpenAI-format tool loop drives Anthropic, DeepSeek, Kimi (Moonshot),
Qwen, MiniMax, GLM, and **any local OpenAI-compatible server** (vLLM / Ollama /
SGLang). Because every model is driven identically, differences in measured F1
reflect the *model*, not the harness.

## Why LiteLLM and not a hosted router

LiteLLM is an **MIT-licensed translation layer, not a router**: no per-token
markup, and requests go **straight to the provider or to a local endpoint you
control**. Nothing third-party sits in the data path. For a security tool that
matters — point `LLM_BASE_URL` at a model inside your own infrastructure and the
**contract source never leaves your network**. That on-prem guarantee is the
differentiator a hosted-API-only competitor can't offer.

## Configuration (all via environment)

| Var | Meaning |
|-----|---------|
| `BENCH_MODEL` | A short alias (see table) or a full LiteLLM id (e.g. `deepseek/deepseek-chat`). Default: Sonnet baseline. |
| `LLM_BASE_URL` | Optional. An OpenAI-compatible endpoint, e.g. `http://localhost:8000/v1` for local vLLM/Ollama. Maps to LiteLLM `api_base`. |
| `LLM_API_KEY` | Optional. Key for the endpoint; omit for keyless local servers. Hosted providers may instead use their standard var (`ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`, `MOONSHOT_API_KEY`, …). |

### Model aliases

| Alias | LiteLLM id | Notes |
|-------|-----------|-------|
| `sonnet` | `anthropic/claude-sonnet-4-6` | committed baseline |
| `opus` | `anthropic/claude-opus-4-8` | headline 35% F1 run |
| `haiku` / `fable` | `anthropic/claude-haiku-…` / `…-fable-5` | |
| `deepseek` / `deepseek-pro` | `deepseek/deepseek-chat` / `deepseek-reasoner` | |
| `kimi` | `moonshot/kimi-k2-0711-preview` | best tool-call stability |
| `qwen` / `minimax` / `glm` | `openai/…` (via `LLM_BASE_URL`) | hosted or self-host |
| `local` | `openai/$LOCAL_MODEL` | generic local escape hatch |

> Provider id strings drift over time — edit the right-hand side of `MODELS`
> in `agents/llm.py` to whatever your provider/endpoint actually serves.

## Three deployment modes (same code)

**1. Hosted Anthropic (current baseline)** — unchanged:
```bash
export ANTHROPIC_API_KEY=sk-ant-...
BENCH_MODEL=opus python3 -m agents.benchmark_runner --real --agentic
```

**2. Direct provider, your own key (no middleman markup):**
```bash
export DEEPSEEK_API_KEY=sk-...
BENCH_MODEL=deepseek python3 -m agents.benchmark_runner --real --agentic
```

**3. Local / self-hosted — zero data egress (the security-team mode):**
```bash
# e.g. serve an open-weight model with vLLM: it speaks the OpenAI API
export LLM_BASE_URL=http://localhost:8000/v1
export BENCH_MODEL=local LOCAL_MODEL=Qwen3-Coder    # served model name
python3 -m agents.benchmark_runner --real --agentic
# no key leaves the box; the contract never leaves the box
```

## Running the bake-off

Each run stamps its own results file (`results_real__<model-tag>.json`), so
runs don't clobber each other. Re-score every run with the **validated judge**
(unchanged, stays on the calibrated Anthropic model so the comparison is fair):

```bash
for M in sonnet deepseek kimi qwen minimax; do
  BENCH_MODEL=$M python3 -m agents.benchmark_runner --real --defi --lending --agentic
  python3 -m agents.semantic_rescorer results_real__$M*.json   # adjust to actual filename
done
python3 -m agents.validate_judge
```

That yields a single **F1-vs-cost leaderboard on our own task** — the only way
to know whether a Sonnet-class-but-cheaper model (or a self-hosted one) actually
holds the 35% semantic F1, rather than trusting generic SWE-bench scores.

## Caveats

- **SWE-bench ≠ vulnerability-finding.** A high coding score is a prior, not a
  guarantee on this task. Measure, don't assume.
- **Tool-calling fidelity varies by model.** LiteLLM exposes a uniform
  interface, but a given model's *native* tool support can be weak; if a model
  answers in prose instead of calling `submit_finding`, the loop nudges it once,
  and `litellm.add_function_to_prompt = True` is the fallback.
- **The judge is deliberately not swapped.** Keep it on the calibrated model so
  semantic F1 stays comparable to the committed baseline.
