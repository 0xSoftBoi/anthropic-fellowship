"""
Tests for the prompt-leakage sanitizer.

Two things must hold, and both are load-bearing for the contamination experiment:

  1. SAFETY — sanitizing must not change what the code does. If it did, a drop in F1
     would be the sanitizer breaking contracts rather than leakage being removed, and
     the whole measurement would be worthless.
  2. EFFICACY — sanitizing must actually remove the leaked answer.

These are pure-CPU (no API key, no model calls) so they run in CI on every push.

    python -m pytest tests/test_sanitize.py -q
"""
import re

import pytest

from benchmarks.sanitize import (
    LEVELS,
    anonymize,
    code_tokens,
    injected_header,
    leakage_scan,
    sanitize,
    strip_comments,
    structural_fingerprint,
    verify,
    _load_all,
)


# ── comment stripping must not corrupt string literals ───────────────────────

def test_strip_preserves_url_in_string():
    src = 'contract C { string u = "https://example.com/x"; }'
    assert "https://example.com/x" in strip_comments(src)


def test_strip_preserves_comment_markers_inside_strings():
    src = 'contract C { string a = "/* not a comment */"; string b = "// nor this"; }'
    out = strip_comments(src)
    assert "/* not a comment */" in out
    assert "// nor this" in out


def test_strip_removes_line_and_block_comments():
    src = "// secret\ncontract C { /* also secret */ uint x; }"
    out = strip_comments(src)
    assert "secret" not in out
    assert "uint x" in out


def test_strip_handles_escaped_quote_in_string():
    src = r'contract C { string s = "a\"// b"; uint y; }'
    out = strip_comments(src)
    assert "uint y" in out  # parser did not get stuck inside the string


# ── the safety invariant on the real corpus ─────────────────────────────────

def _corpus():
    return list(_load_all())


def test_corpus_is_nonempty():
    assert len(_corpus()) >= 20


@pytest.mark.parametrize("level", [lv for lv in LEVELS if lv != "raw"])
def test_sanitize_preserves_program_structure(level):
    """Every contract, every level: verify() must report no problems."""
    failures = []
    for _dom, c in _corpus():
        text, rep = sanitize(c["source"], level, c["name"], c.get("metadata"))
        probs = verify(c["source"], text, level, rep)
        if probs:
            failures.append(f"{c['name']} [{level}]: {probs}")
    assert not failures, "sanitizer altered program semantics:\n" + "\n".join(failures)


def test_stripping_is_token_identical():
    """L1 removes only comments — the code token stream must be untouched."""
    for _dom, c in _corpus():
        stripped, _ = sanitize(c["source"], "stripped", c["name"])
        assert code_tokens(c["source"]) == code_tokens(stripped), c["name"]


def test_anon_preserves_control_flow_counts():
    """L2 renames identifiers; control flow and call structure must not move."""
    for _dom, c in _corpus():
        anon, _ = sanitize(c["source"], "anon", c["name"], c.get("metadata"))
        a = structural_fingerprint(c["source"])
        b = structural_fingerprint(anon)
        for k in ("function", "if", "for", "while", "require", "revert",
                  "return", "semicolons", "braces"):
            assert a[k] == b[k], f"{c['name']}: {k} moved {a[k]} -> {b[k]}"


def test_anon_does_not_corrupt_bytes32_literals():
    """
    Regression: the address-neutralizing regex once matched the first 40 hex chars of a
    64-char bytes32 literal (function selectors, keccak constants) and silently rewrote
    it — which would have changed dispatch behavior. Caught by verify() in development.
    """
    src = (
        "contract C {\n"
        "  bytes32 constant S = 0x23b872dd00000000000000000000000000000000000000000000000000000000;\n"
        "  address a = 0x1111111111111111111111111111111111111111;\n"
        "}\n"
    )
    out, _rep = anonymize(src, "someprotocol")
    assert "0x23b872dd00000000000000000000000000000000000000000000000000000000" in out
    assert "0x1111111111111111111111111111111111111111" not in out


# ── efficacy: leakage is actually removed ───────────────────────────────────

def test_raw_corpus_leaks_and_sanitized_does_not():
    """
    The headline measurement: raw prompts leak the answer; L1/L2 do not.
    This is the finding the reframe rests on, so it is pinned by a test.
    """
    sev = {"raw": 0, "stripped": 0, "anon": 0}
    for _dom, c in _corpus():
        gt = [v["type"] for v in c["ground_truth"]["vulnerabilities"]]
        for level in LEVELS:
            text, _ = sanitize(c["source"], level, c["name"], c.get("metadata"))
            if leakage_scan(text, gt, c["name"], c.get("metadata"))["severity"] == "SEVERE":
                sev[level] += 1
    assert sev["raw"] >= 10, f"expected substantial raw leakage, saw {sev['raw']}"
    assert sev["stripped"] == 0, f"stripping left {sev['stripped']} leaking contracts"
    assert sev["anon"] == 0, f"anonymization left {sev['anon']} leaking contracts"


def test_anon_removes_protocol_identity():
    for _dom, c in _corpus():
        anon, _ = sanitize(c["source"], "anon", c["name"], c.get("metadata"))
        scan = leakage_scan(anon, [], c["name"], c.get("metadata"))
        assert not scan["identity"], f"{c['name']} still identifiable: {scan['identity']}"


def test_euler_header_states_the_answer_but_code_does_not_contain_the_function():
    """
    The case study: euler's header names the bug AND its ground-truth label, while the
    vulnerable function (`donateToReserves`) is absent from the committed source — so a
    correct-looking finding there could only have been read off the comment.
    """
    euler = [c for _d, c in _corpus() if c["name"] == "euler_finance_lending"]
    if not euler:
        pytest.skip("euler contract not present")
    src = euler[0]["source"]
    assert "missing_solvency_check" in injected_header(src)
    assert "donateToReserves" in injected_header(src)
    assert "donateToReserves" not in strip_comments(src)


def test_injected_header_excludes_body_comments():
    src = "// header line\n\ncontract C {\n  // body comment\n  uint x;\n}\n"
    h = injected_header(src)
    assert "header line" in h
    assert "body comment" not in h
