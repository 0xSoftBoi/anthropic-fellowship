"""
Self-consistency analyzer for BRIDGE-bench.

Run the agentic analyzer k times and keep findings that recur across samples.
A finding reported in many independent passes is far more likely real than a
one-off; voting filters hallucinated/unstable findings (precision ↑) at a k×
token cost.

Diversity across samples comes from two sources so it works on every model:
  - a per-sample prompt nonce ("independent pass i of k, reason from first
    principles") — induces variation even at temperature 0;
  - a non-zero temperature when the model accepts one (SC_TEMPERATURE).

Merge: findings are keyed by (normalized type, normalized location); a key is
kept when its vote count >= SC_MIN_VOTES (default majority). The kept finding's
fields come from its highest-confidence sample, and its confidence is set to the
vote fraction (votes / k) so downstream consumers see the agreement level.

Config (env):
  SC_SAMPLES       number of passes k (default 3)
  SC_MIN_VOTES     votes required to keep a finding (default majority = k//2 + 1)
  SC_TEMPERATURE   sampling temperature when supported (default 0.7)
"""

import os
import re
from dataclasses import dataclass, field

from agents.agentic_analyzer import run_agent, AgentFinding


@dataclass
class SelfConsistencyAudit:
    contract_name: str
    findings: list = field(default_factory=list)
    # AgentAudit-compatible fields so the runner scores it identically.
    total_tokens: int = 0
    cached_tokens: int = 0
    tool_calls_made: int = 0
    # Provenance
    samples: int = 0
    min_votes: int = 0
    per_sample_findings: list = field(default_factory=list)


def _norm(s: str) -> str:
    return re.sub(r"[\s\-/]+", "_", (s or "").strip().lower())


def _merge_by_vote(sample_findings: list, k: int, min_votes: int) -> list:
    """Keep findings whose (type, location) appears in >= min_votes samples."""
    votes: dict = {}      # key -> count
    best: dict = {}       # key -> finding with highest confidence seen
    for findings in sample_findings:
        seen_this_sample = set()
        for f in findings:
            if _norm(f.vuln_type) == "none":
                continue
            key = (_norm(f.vuln_type), _norm(f.location))
            if key in seen_this_sample:
                continue  # one vote per sample per key
            seen_this_sample.add(key)
            votes[key] = votes.get(key, 0) + 1
            if key not in best or f.confidence > best[key].confidence:
                best[key] = f

    kept = []
    for key, count in votes.items():
        if count >= min_votes:
            f = best[key]
            kept.append(AgentFinding(
                vuln_type=f.vuln_type,
                severity=f.severity,
                location=f.location,
                description=f.description,
                exploit_scenario=f.exploit_scenario,
                suggested_fix=f.suggested_fix,
                confidence=round(count / k, 3),  # agreement level
            ))
    # Strongest agreement first.
    kept.sort(key=lambda x: x.confidence, reverse=True)
    return kept


def run_self_consistent(source: str, contract_name: str,
                        model: str | None = None) -> SelfConsistencyAudit:
    k = max(1, int(os.environ.get("SC_SAMPLES", "3")))
    min_votes = int(os.environ.get("SC_MIN_VOTES", str(k // 2 + 1)))
    temperature = float(os.environ.get("SC_TEMPERATURE", "0.7"))

    audit = SelfConsistencyAudit(contract_name=contract_name, samples=k, min_votes=min_votes)
    sample_findings = []
    for i in range(k):
        hint = (f"Independent analysis pass {i + 1} of {k}. Reason from first "
                f"principles; do not assume any prior pass is correct or complete.")
        a = run_agent(source, contract_name, model=model,
                      context_hint=hint, temperature=temperature)
        audit.total_tokens += a.total_tokens
        audit.cached_tokens += getattr(a, "cached_tokens", 0)
        audit.tool_calls_made += a.tool_calls_made
        sample_findings.append(a.findings)
        audit.per_sample_findings.append([f.vuln_type for f in a.findings])

    audit.findings = _merge_by_vote(sample_findings, k, min_votes)
    return audit


def format_self_consistent(audit: SelfConsistencyAudit) -> str:
    lines = [
        f"{'=' * 60}",
        f"SELF-CONSISTENCY AUDIT: {audit.contract_name}",
        f"  {audit.samples} samples, keep >= {audit.min_votes} votes; "
        f"{len(audit.findings)} consensus findings ({audit.total_tokens:,} tok)",
        "",
    ]
    for i, f in enumerate(audit.findings, 1):
        lines.append(f"[{i}] {f.vuln_type} ({f.severity}) @ {f.location} — agreement {f.confidence:.0%}")
    return "\n".join(lines)
