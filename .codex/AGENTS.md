# ECC for Codex CLI

Supplements the root `AGENTS.md` with a repo-local ECC baseline.

## Repo

Python 3.10+ research repo, two tracks: `ai-security/` (BRIDGE-bench) and `mech-interp/`.
- Tests: `cd ai-security && python -m pytest tests/ -q`
- Benchmarks: `python3 -m agents.benchmark_runner --real [--agentic|--cascade|--sc]`

## Repo Skill

- Codex skill: `.agents/skills/anthropic-fellowship/SKILL.md`
- Claude companion: `.claude/skills/anthropic-fellowship/SKILL.md`
- Keep user-specific credentials and private MCPs in `~/.codex/config.toml`, not in this repo.

## MCP Baseline

`.codex/config.toml` is the default ECC baseline. It enables GitHub, Playwright, and
Sequential Thinking; Context7, Memory, and the remote Exa endpoint are commented out as
opt-ins. Each `npx` server auto-installs from npm and Exa sends queries to a remote
third party — enable deliberately.

## Multi-Agent Support

- Explorer: read-only evidence gathering
- Reviewer: correctness, security, and regression review
- Docs researcher: API and release-note verification

## Conventions

Absolute imports, snake_case files/functions, PascalCase classes, pytest in `tests/`.
Route model calls through `agents/llm.py` (LiteLLM); select the model via `BENCH_MODEL`.
