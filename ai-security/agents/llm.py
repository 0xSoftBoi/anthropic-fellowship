"""
Provider-agnostic LLM access for BRIDGE-bench, via LiteLLM.

ONE call path for every model the benchmark evaluates — Anthropic, DeepSeek,
Kimi (Moonshot), Qwen, MiniMax, GLM, and any local OpenAI-compatible server
(vLLM / Ollama / SGLang). LiteLLM is an MIT-licensed translation layer, NOT a
hosted router: there is no per-token markup and requests go straight to the
provider — or to a local endpoint you control. Nothing sits in the data path.

Why this matters for a security tool: point LLM_BASE_URL at a model running
inside your own infrastructure and the contract source NEVER leaves your
network. That is the on-prem story competitors who only offer a hosted API
cannot match.

Configuration (all via environment):

    BENCH_MODEL    A short alias from MODELS below (e.g. "deepseek", "kimi"),
                   or a full LiteLLM model id (e.g. "deepseek/deepseek-chat").
                   Defaults to the committed Sonnet baseline.
    LLM_BASE_URL   Optional. An OpenAI-compatible endpoint, e.g.
                   "http://localhost:8000/v1" for a local vLLM/Ollama server.
                   Maps to LiteLLM's api_base.
    LLM_API_KEY    Optional. The key for the endpoint. Omit for keyless local
                   servers (a dummy value is sent so the client is satisfied).
                   For hosted providers you may instead rely on LiteLLM's
                   standard per-provider vars (ANTHROPIC_API_KEY,
                   DEEPSEEK_API_KEY, MOONSHOT_API_KEY, ...).

Apples-to-apples note: every model is driven through the *same* OpenAI-format
tool loop here, so differences in measured F1 reflect the model, not the
harness.
"""

import os

# Short alias -> LiteLLM model id.
#
# The Anthropic ids reproduce the committed baseline exactly. The open-weight
# ids point at each provider's hosted API by default; to self-host any of them,
# set LLM_BASE_URL to your local server and use BENCH_MODEL=local (or the
# "openai/<served-name>" form). Provider id strings move over time — adjust the
# right-hand side to whatever your provider/endpoint actually serves.
MODELS = {
    # --- Anthropic (hosted) — the committed baselines ---
    "sonnet": "anthropic/claude-sonnet-4-6",
    "opus": "anthropic/claude-opus-4-8",
    "haiku": "anthropic/claude-haiku-4-5-20251001",
    "fable": "anthropic/claude-fable-5",
    # --- Open-weight / cheaper candidates (hosted ids; override api_base to self-host) ---
    "deepseek": "deepseek/deepseek-chat",          # DeepSeek V4 (chat)
    "deepseek-pro": "deepseek/deepseek-reasoner",   # DeepSeek V4 Pro (reasoner)
    "kimi": "moonshot/kimi-k2-0711-preview",        # Moonshot Kimi K2
    "qwen": "openai/qwen-max",                       # via LLM_BASE_URL (DashScope/local)
    "minimax": "openai/MiniMax-M2",                  # via LLM_BASE_URL
    "glm": "openai/glm-4.6",                         # via LLM_BASE_URL (Z.ai/local)
    # --- Generic local escape hatch: BENCH_MODEL=local + LLM_BASE_URL + LOCAL_MODEL ---
    "local": "openai/" + os.environ.get("LOCAL_MODEL", "local-model"),
}


def litellm_model() -> str:
    """Resolve BENCH_MODEL to a full LiteLLM model id (with provider prefix)."""
    raw = os.environ.get("BENCH_MODEL", "")
    return MODELS.get(raw, raw or MODELS["sonnet"])


def model_tag() -> str:
    """
    Bare model name (no "provider/" prefix) used for stamping result filenames.
    Keeps the committed Sonnet baseline naming stable (-> "claude-sonnet-4-6").
    """
    return litellm_model().split("/", 1)[-1]


def has_credentials() -> bool:
    """
    True if we have *some* way to reach a model: a local endpoint (keyless ok),
    an explicit LLM_API_KEY, or a recognised per-provider key in the env.
    Lets a DeepSeek/local run proceed without ANTHROPIC_API_KEY being set.
    """
    if os.environ.get("LLM_BASE_URL") or os.environ.get("LLM_API_KEY"):
        return True
    provider_keys = (
        "ANTHROPIC_API_KEY",
        "DEEPSEEK_API_KEY",
        "MOONSHOT_API_KEY",
        "OPENAI_API_KEY",
        "DASHSCOPE_API_KEY",
        "GEMINI_API_KEY",
    )
    return any(os.environ.get(k) for k in provider_keys)


def _supports_temperature(model: str) -> bool:
    # Some models reject an explicit temperature override and require the
    # default (e.g. Fable, Opus 4.8 with extended thinking). Keep temperature=0
    # for everything else so static-vs-LLM comparisons stay reproducible.
    return not any(s in model for s in ("fable", "opus-4-8"))


# --- Prompt caching -------------------------------------------------------
# Caching the static prefix (system + tools + contract source) is the single
# biggest cost lever for a multi-turn agent: it is re-sent on every turn, and
# cached reads cost ~90% less. Anthropic/Bedrock/Gemini need an explicit
# cache_control marker (LiteLLM passes it through); DeepSeek/OpenAI cache
# automatically, so for those we leave content as a plain string.

def supports_explicit_cache(model: str) -> bool:
    return any(p in model for p in ("anthropic", "claude", "bedrock", "vertex_ai", "gemini"))


def cacheable(text: str, model: str | None = None) -> "str | list":
    """
    Return message content for `text`, marked as a cache breakpoint when the
    target model supports explicit prompt caching. Use for large, static chunks
    that repeat across turns (the system prompt, the contract source). For
    auto-caching providers it returns the plain string unchanged.
    """
    model = model or litellm_model()
    if supports_explicit_cache(model):
        return [{"type": "text", "text": text, "cache_control": {"type": "ephemeral"}}]
    return text


def cached_tokens(response) -> int:
    """Best-effort count of input tokens served from cache (0 if unavailable)."""
    usage = getattr(response, "usage", None)
    if usage is None:
        return 0
    # Anthropic-style fields surfaced by LiteLLM, plus OpenAI-style details.
    direct = getattr(usage, "cache_read_input_tokens", None)
    if direct:
        return int(direct)
    details = getattr(usage, "prompt_tokens_details", None)
    if details is not None:
        cached = getattr(details, "cached_tokens", None)
        if cached:
            return int(cached)
    return 0


def to_openai_tools(anthropic_tools: list[dict]) -> list[dict]:
    """
    Convert Anthropic-native tool schemas ({name, description, input_schema})
    to OpenAI function-tool schemas. Lets us keep one TOOLS definition and run
    it across every provider via LiteLLM.
    """
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
            },
        }
        for t in anthropic_tools
    ]


def completion(
    messages: list[dict],
    *,
    model: str | None = None,
    max_tokens: int = 4096,
    tools: list[dict] | None = None,
    temperature: float | None = 0,
):
    """
    Single entry point for a chat completion, in OpenAI format, through LiteLLM.

    Returns LiteLLM's OpenAI-style response object:
        resp.choices[0].message        -> .content, .tool_calls
        resp.choices[0].finish_reason  -> "stop" | "tool_calls" | ...
        resp.usage                     -> .prompt_tokens, .completion_tokens, .total_tokens
    """
    import litellm  # lazy import — keep module load cheap when unused

    model = model or litellm_model()
    kwargs: dict = dict(model=model, messages=messages, max_tokens=max_tokens)

    base = os.environ.get("LLM_BASE_URL")
    if base:
        kwargs["api_base"] = base
    key = os.environ.get("LLM_API_KEY")
    if key:
        kwargs["api_key"] = key
    elif base:
        # Keyless local server — most OpenAI-compatible servers ignore the key
        # but the client still requires a non-empty value.
        kwargs["api_key"] = "sk-local"

    if tools:
        kwargs["tools"] = tools
    if temperature is not None and _supports_temperature(model):
        kwargs["temperature"] = temperature

    # Reliability: LiteLLM retries transient errors (429/5xx) with exponential
    # backoff internally, so high concurrency is safe and a single blip doesn't
    # lose a contract's run. Tunable via env.
    kwargs["num_retries"] = int(os.environ.get("LLM_NUM_RETRIES", "3"))
    kwargs["timeout"] = float(os.environ.get("LLM_TIMEOUT", "120"))

    return litellm.completion(**kwargs)
