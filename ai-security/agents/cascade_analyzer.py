"""
Cascade analyzer — cost-accuracy frontier for BRIDGE-bench.

Most tokens are spent by a CHEAP model doing a wide first pass; the EXPENSIVE
model is then pointed only at the suspicious surface (the functions the cheap
pass and the free static pre-screen flagged), with the cheap findings handed
over as context. This spends strong-model tokens where they matter instead of
re-reading the whole contract.

Pipeline per contract:
  1. Tier 1 (cheap, e.g. DeepSeek): run the agentic analyzer over the full
     (extracted) source -> candidate findings + flagged locations.
  2. Escalation surface = functions named in tier-1 findings UNION functions
     the static pre-screen flags. The static net protects recall when the cheap
     model is silent on a genuinely risky contract.
  3. Tier 2 (strong, e.g. Opus): if the surface is non-empty, re-run the agent
     on JUST those function bodies, with tier-1 findings as a context hint.
     If the surface is empty, skip tier 2 and trust the cheap pass (big saving
     on clean contracts).
  4. Merge: union of tier-1 + tier-2 findings, deduped by (type, location);
     strong-tier wins on overlap.

Config (env):
  CASCADE_CHEAP_MODEL    alias/id for tier 1 (default "deepseek")
  CASCADE_STRONG_MODEL   alias/id for tier 2 (default "opus")
  CASCADE_ALWAYS_ESCALATE  "1" to always run tier 2 (recall over cost)
  CASCADE_MAX_TURNS      per-tier agent turns (default 8)
"""

import os
import re
from dataclasses import dataclass, field

from agents import llm
from agents.agentic_analyzer import run_agent, AgentFinding
from agents.claude_analyzer import static_prescreen, BRIDGE_RISK_PATTERNS
from agents.static_analyzer_v2 import _extract_function_body


@dataclass
class CascadeAudit:
    contract_name: str
    findings: list = field(default_factory=list)
    # Cost/score fields named to match AgentAudit so the runner can score it the same way.
    total_tokens: int = 0
    cached_tokens: int = 0
    tool_calls_made: int = 0
    # Cascade-specific provenance
    cheap_model: str = ""
    strong_model: str = ""
    cheap_tokens: int = 0
    strong_tokens: int = 0
    escalated: bool = False
    escalated_functions: list = field(default_factory=list)


def _resolve(alias_or_id: str) -> str:
    return llm.MODELS.get(alias_or_id, alias_or_id)


_FUNC_NAME_RE = re.compile(r"[A-Za-z_]\w*")
_ALL_FUNCS_RE = re.compile(r"function\s+([A-Za-z_]\w*)\s*\(")


def _functions_in_source(source: str) -> set:
    return set(_ALL_FUNCS_RE.findall(source))


def _flagged_function_names(findings, source: str) -> list:
    """Pull plausible function names out of tier-1 finding locations.

    Locations are free-form ("processWithdrawal", "processWithdrawal()", "L330,
    transfer loop"); keep only identifier tokens that are actually declared as
    functions in the source.
    """
    declared = _functions_in_source(source)
    names = []
    for f in findings:
        loc = getattr(f, "location", "") or ""
        for tok in _FUNC_NAME_RE.findall(loc):
            if tok in declared and tok not in names:
                names.append(tok)
    return names


def _static_risky_functions(source: str) -> list:
    """Function names matching the static risk patterns — a free recall net."""
    names = []
    for pat in BRIDGE_RISK_PATTERNS:
        for m in re.finditer(pat, source):
            fm = re.search(r"function\s+([A-Za-z_]\w*)", source[m.start():m.start() + 80])
            if fm and fm.group(1) not in names:
                names.append(fm.group(1))
    return names


def _focus_source(source: str, func_names: list, contract_name: str) -> str | None:
    """Build a reduced source containing only the named function bodies."""
    bodies = []
    for name in func_names:
        body = _extract_function_body(source, name)
        if body and 30 < len(body) < 12_000:
            bodies.append(body)
    if not bodies:
        return None
    header = (f"// {contract_name} — {len(bodies)} flagged function(s) escalated "
              f"for deep analysis (cheap-tier triage + static pre-screen)\n\n")
    # dedupe while preserving order
    seen, uniq = set(), []
    for b in bodies:
        if b not in seen:
            seen.add(b)
            uniq.append(b)
    return header + "\n\n// ===== NEXT FUNCTION =====\n\n".join(uniq)


def _context_hint(findings) -> str:
    if not findings:
        return ""
    lines = ["A cheaper first-pass model flagged the following candidate issues. "
             "Confirm or refute each, find any it missed, and report precise findings:"]
    for f in findings:
        vt = getattr(f, "vuln_type", "?")
        loc = getattr(f, "location", "?")
        if vt and vt != "none":
            lines.append(f"  - {vt} @ {loc}")
    return "\n".join(lines)


def _norm(s: str) -> str:
    return re.sub(r"[\s\-/]+", "_", (s or "").strip().lower())


def _merge_findings(cheap, strong) -> list:
    """Union deduped by (normalized type, normalized location); strong wins."""
    merged = {}
    for f in cheap:
        merged[(_norm(f.vuln_type), _norm(f.location))] = f
    for f in strong:  # strong overwrites on key collision
        merged[(_norm(f.vuln_type), _norm(f.location))] = f
    return [f for f in merged.values() if _norm(f.vuln_type) != "none"]


def run_cascade(source: str, contract_name: str, max_turns: int | None = None) -> CascadeAudit:
    cheap = os.environ.get("CASCADE_CHEAP_MODEL", "deepseek")
    strong = os.environ.get("CASCADE_STRONG_MODEL", "opus")
    cheap_id, strong_id = _resolve(cheap), _resolve(strong)
    turns = max_turns if max_turns is not None else int(os.environ.get("CASCADE_MAX_TURNS", "8"))
    always = os.environ.get("CASCADE_ALWAYS_ESCALATE", "") == "1"

    audit = CascadeAudit(contract_name=contract_name, cheap_model=cheap_id, strong_model=strong_id)

    # --- Tier 1: cheap wide net ---
    t1 = run_agent(source, contract_name, max_turns=turns, model=cheap_id)
    audit.cheap_tokens = t1.total_tokens
    audit.cached_tokens += getattr(t1, "cached_tokens", 0)
    audit.tool_calls_made += t1.tool_calls_made

    # --- Escalation surface: tier-1 flags UNION static risky functions ---
    surface = _flagged_function_names(t1.findings, source)
    for n in _static_risky_functions(source):
        if n not in surface:
            surface.append(n)
    audit.escalated_functions = surface

    focused = _focus_source(source, surface, contract_name) if surface else None

    # --- Tier 2: strong, focused deep-dive (gated on a non-empty surface) ---
    if always or focused:
        # If we somehow have no focused source but are forced to escalate, fall
        # back to the full source so the strong model still gets a look.
        t2_source = focused or source
        t2 = run_agent(t2_source, contract_name, max_turns=turns,
                       model=strong_id, context_hint=_context_hint(t1.findings))
        audit.strong_tokens = t2.total_tokens
        audit.cached_tokens += getattr(t2, "cached_tokens", 0)
        audit.tool_calls_made += t2.tool_calls_made
        audit.escalated = True
        audit.findings = _merge_findings(t1.findings, t2.findings)
    else:
        # Clean contract per cheap tier + static net — trust tier 1, save strong $.
        audit.findings = _merge_findings(t1.findings, [])

    audit.total_tokens = audit.cheap_tokens + audit.strong_tokens
    return audit


def format_cascade(audit: CascadeAudit) -> str:
    lines = [
        f"{'=' * 60}",
        f"CASCADE AUDIT: {audit.contract_name}",
        f"  cheap={audit.cheap_model} ({audit.cheap_tokens:,} tok) -> "
        f"strong={audit.strong_model} ({audit.strong_tokens:,} tok)"
        f"{' [escalated]' if audit.escalated else ' [no escalation]'}",
        f"  escalated functions: {', '.join(audit.escalated_functions) or 'none'}",
        f"  findings: {len(audit.findings)}",
        "",
    ]
    for i, f in enumerate(audit.findings, 1):
        lines.append(f"[{i}] {f.vuln_type} ({f.severity}) @ {f.location} — {f.confidence:.0%}")
    return "\n".join(lines)
