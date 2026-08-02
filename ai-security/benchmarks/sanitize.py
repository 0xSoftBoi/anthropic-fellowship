"""
Prompt-leakage sanitizer for BRIDGE-bench.

WHY THIS EXISTS
---------------
The committed `.sol` files carry a provenance header written for human auditability:
protocol name, verified address, exploit date, dollar loss — and, in 13 of 24 cases, a
prose description of the *bug itself*. Example (euler_finance_lending.sol):

    // Exploit 2023-03-13 (~$197M): EToken.donateToReserves had no account health/solvency
    // check; ... CORRECTED label: missing_solvency_check

The loader reads the file whole and the analyzer feeds it straight into the prompt, so the
model was being handed a prose statement of the answer (and in 2 cases the ground-truth
label verbatim) before it read a line of Solidity. Any F1 measured that way is partly a
reading-comprehension score, not a vulnerability-detection score.

This module removes that leakage so detection can actually be measured, at three levels:

    L0 "raw"       unchanged — what the committed numbers were produced with
    L1 "stripped"  all comments removed (provenance header, exploit narrative, NatSpec)
    L2 "anon"      L1 + protocol identity removed (identifier renaming, address and
                   string-literal neutralization) — also defeats name-triggered recall

L1 fixes prompt leakage. L2 additionally attacks the *memorization* confound: a model that
scores well on L2 is reading code, not recognizing "this is the Euler donateToReserves bug."
Δ(L0→L1) and Δ(L1→L2) are separately meaningful; see docs/CONTAMINATION.md.

SAFETY INVARIANT
----------------
Sanitizing must never change what the code *does*, or the experiment measures the wrong
thing. Two guarantees, both checked by `verify()` and locked down in tests/test_sanitize.py:

  1. Comment stripping is string-literal aware, so `"https://..."` and `"a /* b"` survive.
     The code-token stream is bit-identical before and after L1.
  2. Renaming is whole-word, applied uniformly across the file (so definitions and call
     sites move together), refuses to touch Solidity keywords/builtins, and aborts on any
     collision with an existing identifier. The token stream after L2 is identical to L1
     under the rename map — structure, control flow, and call graph are untouched.

There is no solc in this environment, so `verify()` performs structural equivalence, not
compilation. That is a stated limitation, not a claim of compile-safety.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

LEVELS = ("raw", "stripped", "anon")

# Identifiers that must never be renamed: renaming them would change semantics or break
# compilation. Not exhaustive for all of Solidity, but covers everything appearing in this
# corpus; `_is_renameable` additionally refuses anything not matching a normal identifier.
SOLIDITY_RESERVED = {
    # types / keywords
    "address", "bool", "string", "bytes", "byte", "int", "uint", "fixed", "ufixed",
    "contract", "interface", "library", "struct", "enum", "function", "modifier", "event",
    "constructor", "fallback", "receive", "returns", "return", "if", "else", "for", "while",
    "do", "break", "continue", "throw", "emit", "new", "delete", "using", "is", "as",
    "import", "pragma", "solidity", "abstract", "override", "virtual", "immutable",
    "constant", "payable", "memory", "storage", "calldata", "public", "private", "internal",
    "external", "view", "pure", "anonymous", "indexed", "try", "catch", "unchecked",
    "assembly", "let", "mapping", "type", "true", "false", "wei", "gwei", "ether",
    "seconds", "minutes", "hours", "days", "weeks",
    # globals / builtins
    "msg", "sender", "value", "data", "sig", "block", "timestamp", "number", "coinbase",
    "difficulty", "gaslimit", "chainid", "basefee", "tx", "origin", "gasprice", "now",
    "this", "super", "abi", "encode", "encodePacked", "encodeWithSelector",
    "encodeWithSignature", "decode", "require", "revert", "assert", "keccak256", "sha256",
    "ripemd160", "ecrecover", "addmod", "mulmod", "selfdestruct", "gasleft", "blockhash",
    "call", "delegatecall", "staticcall", "callcode", "transfer", "send", "balance",
    "code", "codehash", "length", "push", "pop", "add", "sub", "mul", "div", "mod",
}

# Common numeric/hex literals that are structural rather than identifying.
_ZERO_ADDR = "0x0000000000000000000000000000000000000000"


# ── comment stripping (string-literal aware) ─────────────────────────────────

def strip_comments(source: str) -> str:
    """
    Remove // and /* */ comments without corrupting string literals.

    A naive regex mangles `"https://x"` and `"/*"`; this walks the source tracking
    whether we are inside a single-quoted string, double-quoted string, line comment,
    or block comment. Newlines are preserved so line numbers stay comparable.
    """
    out = []
    i, n = 0, len(source)
    in_line = in_block = in_squote = in_dquote = False

    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""

        if in_line:
            if ch == "\n":
                in_line = False
                out.append(ch)
            i += 1
        elif in_block:
            if ch == "*" and nxt == "/":
                in_block = False
                i += 2
            else:
                if ch == "\n":
                    out.append(ch)  # keep line structure
                i += 1
        elif in_squote:
            out.append(ch)
            if ch == "\\" and nxt:
                out.append(nxt)
                i += 2
                continue
            if ch == "'":
                in_squote = False
            i += 1
        elif in_dquote:
            out.append(ch)
            if ch == "\\" and nxt:
                out.append(nxt)
                i += 2
                continue
            if ch == '"':
                in_dquote = False
            i += 1
        else:
            if ch == "/" and nxt == "/":
                in_line = True
                i += 2
            elif ch == "/" and nxt == "*":
                in_block = True
                i += 2
            elif ch == "'":
                in_squote = True
                out.append(ch)
                i += 1
            elif ch == '"':
                in_dquote = True
                out.append(ch)
                i += 1
            else:
                out.append(ch)
                i += 1

    # collapse the blank lines left behind by removed comment blocks
    text = "".join(out)
    text = re.sub(r"[ \t]+(\n)", r"\1", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip() + "\n"


# ── tokenization / structural verification ──────────────────────────────────

_TOKEN_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*|0x[0-9a-fA-F]+|\d+|[^\sA-Za-z0-9_$]")


def code_tokens(source: str) -> list[str]:
    """Token stream of comment-free code — the basis for structural comparison."""
    return _TOKEN_RE.findall(strip_comments(source))


def structural_fingerprint(source: str) -> dict:
    """
    Counts that must be invariant under sanitization. If any of these move, the
    sanitizer changed the program and the experiment is invalid.
    """
    code = strip_comments(source)
    toks = _TOKEN_RE.findall(code)
    def kw(k):
        return sum(1 for t in toks if t == k)
    return {
        "tokens": len(toks),
        "function": kw("function"),
        "if": kw("if"),
        "else": kw("else"),
        "for": kw("for"),
        "while": kw("while"),
        "require": kw("require"),
        "revert": kw("revert"),
        "return": kw("return"),
        "emit": kw("emit"),
        "modifier": kw("modifier"),
        "assembly": kw("assembly"),
        "call": kw("call"),
        "delegatecall": kw("delegatecall"),
        "transfer": kw("transfer"),
        "semicolons": sum(1 for t in toks if t == ";"),
        "braces": sum(1 for t in toks if t in "{}"),
    }


def _is_renameable(name: str) -> bool:
    if name in SOLIDITY_RESERVED:
        return False
    if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", name):
        return False
    return len(name) > 2


# ── protocol-identity anonymization (L2) ────────────────────────────────────

def protocol_tokens(contract_key: str, metadata: dict | None = None) -> list[str]:
    """
    Derive the identity-bearing words for a contract: the parts of its dataset key plus
    any protocol name in metadata. These are what make a contract *recognizable*.
    """
    stop = {
        "finance", "protocol", "bridge", "market", "pool", "swap", "router", "proxy",
        "chamber", "connector", "registry", "gateway", "validator", "manager", "vyper",
        "elastic", "lending", "reentrancy", "oracle", "drain", "approval", "multisig",
        "comptroller", "cerc", "immutable", "zap", "staking", "replica", "handler",
        "diamond", "july", "march", "token", "core", "v1", "v2", "v3", "v4",
    }
    words = [w for w in re.split(r"[_\-\s]+", contract_key) if w]
    toks = {w for w in words if w.lower() not in stop and len(w) > 2}
    if metadata:
        for key in ("protocol", "project", "name"):
            v = metadata.get(key)
            if isinstance(v, str):
                for w in re.split(r"[^A-Za-z0-9]+", v):
                    if w and w.lower() not in stop and len(w) > 2:
                        toks.add(w)
    return sorted(toks, key=len, reverse=True)


def anonymize(source: str, contract_key: str, metadata: dict | None = None) -> tuple[str, dict]:
    """
    L2: remove protocol identity from comment-free source.

    Renames identifiers containing a protocol token, neutralizes non-zero address
    literals, and blanks string literals that carry protocol names. Aborts (raises)
    on a rename collision rather than silently producing different code.
    """
    code = strip_comments(source)
    ptoks = protocol_tokens(contract_key, metadata)
    existing = set(re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", code))

    rename: dict[str, str] = {}
    for ident in sorted(existing, key=len, reverse=True):
        if not _is_renameable(ident):
            continue
        for p in ptoks:
            if p.lower() in ident.lower():
                # preserve the rest of the identifier; swap only the identifying part
                new = re.sub(re.escape(p), "Proto", ident, flags=re.I)
                if new == ident or not new:
                    continue
                if new in existing or new in rename.values():
                    new = f"{new}_x"
                if new in existing or new in rename.values():
                    raise ValueError(
                        f"{contract_key}: rename collision for {ident!r} -> {new!r}; "
                        "refusing to produce semantically different source"
                    )
                rename[ident] = new
                break

    for old, new in sorted(rename.items(), key=lambda kv: -len(kv[0])):
        code = re.sub(rf"(?<![A-Za-z0-9_$]){re.escape(old)}(?![A-Za-z0-9_$])", new, code)

    # Neutralize identifying addresses. The trailing lookahead is load-bearing: without it
    # this matches the first 40 hex chars of a 64-char bytes32 literal (function selectors,
    # keccak constants) and silently corrupts it — caught by verify() during development.
    addrs = {
        a for a in re.findall(r"0x[0-9a-fA-F]{40}(?![0-9a-fA-F])", code)
        if a.lower() != _ZERO_ADDR
    }
    addr_map = {}
    for idx, a in enumerate(sorted(addrs)):
        addr_map[a] = "0x" + f"{idx + 1:040x}"
        code = code.replace(a, addr_map[a])

    # blank string literals that still name the protocol
    def _blank(m):
        lit = m.group(0)
        return '""' if any(p.lower() in lit.lower() for p in ptoks) else lit

    code = re.sub(r'"[^"\n]*"', _blank, code)

    return code, {"renamed": rename, "addresses": addr_map, "protocol_tokens": ptoks}


# ── public API ───────────────────────────────────────────────────────────────

def sanitize(source: str, level: str, contract_key: str = "", metadata: dict | None = None):
    """
    Apply a sanitization level. Returns (text, report).

    level: "raw" | "stripped" | "anon"
    """
    if level not in LEVELS:
        raise ValueError(f"level must be one of {LEVELS}, got {level!r}")
    if level == "raw":
        return source, {"level": "raw"}
    if level == "stripped":
        return strip_comments(source), {"level": "stripped"}
    code, rep = anonymize(source, contract_key, metadata)
    rep["level"] = "anon"
    return code, rep


def verify(original: str, sanitized: str, level: str, report: dict | None = None) -> list[str]:
    """
    Check the safety invariant. Returns a list of problems (empty == OK).

    - "stripped": the code-token stream must be IDENTICAL to the original's.
    - "anon": structure must match, and the token stream must match under the rename +
      address map (i.e. a pure relabeling, no inserted/removed code).
    """
    problems = []
    a, b = structural_fingerprint(original), structural_fingerprint(sanitized)

    if level == "stripped":
        ta, tb = code_tokens(original), code_tokens(sanitized)
        if ta != tb:
            problems.append(
                f"token stream changed by comment stripping ({len(ta)} -> {len(tb)})"
            )
        return problems

    # anon: apply the recorded maps to the original token stream and compare
    rename = (report or {}).get("renamed", {})
    addr = (report or {}).get("addresses", {})
    ptoks = (report or {}).get("protocol_tokens", [])
    ta = [addr.get(t, rename.get(t, t)) for t in code_tokens(original)]
    tb = code_tokens(sanitized)
    if len(ta) != len(tb):
        problems.append(f"token count changed under anonymization ({len(ta)} -> {len(tb)})")
    else:
        # string-literal blanking legitimately changes string tokens; ignore those
        diffs = [
            (x, y) for x, y in zip(ta, tb)
            if x != y and not (y == '"' or x == '"' or any(p.lower() in str(x).lower() for p in ptoks))
        ]
        if diffs:
            problems.append(f"{len(diffs)} non-relabeling token differences, e.g. {diffs[:3]}")

    for k in ("function", "if", "for", "while", "require", "revert", "return", "semicolons", "braces"):
        if a[k] != b[k]:
            problems.append(f"structural drift: {k} {a[k]} -> {b[k]}")
    return problems


def injected_header(text: str) -> str:
    """
    The dataset author's preamble: the leading run of comment lines before any code.

    This is the leakage surface that matters, and the distinction is important for an
    honest measurement. Comments *inside* the contract body ship with the real verified
    source — a human auditor sees them too, and an OpenZeppelin `"ReentrancyGuard:
    reentrant call"` revert string or a `bithacks.html` link is not the benchmark handing
    over an answer. The header block, by contrast, was written by the benchmark author and
    often states the exploit, the loss, and the bug mechanism. Only that is scored as
    leakage; upstream prose is reported separately as context.
    """
    lines = []
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("//"):
            lines.append(s)
        elif not s:
            continue
        else:
            break
    return "\n".join(lines)


_MECHANISM_RE = (
    r"no |missing|lack|without|fail(s|ed)? to|unchecked|before .*update|reentran|"
    r"bypass|forge|spoof|arbitrary|unvalidat|not verif|incorrect|off-by|rounding|"
    r"truncat|does not"
)


def leakage_scan(text: str, gt_types: list[str], contract_key: str,
                 metadata: dict | None = None) -> dict:
    """
    Does this prompt leak the answer? Scored on the author-injected header (see above).

    - label_hits: ground-truth label strings stated verbatim in the header
    - narrative:  header describes an exploit (protocol, date, loss)
    - mechanism:  header also states *how* the bug works — the worst case, since it is a
                  prose statement of the finding the model is being scored on
    - identity:   protocol name still recoverable anywhere in the prompt (memorization cue)
    """
    header = injected_header(text)

    def _matches(hay, g):
        return g.lower() in hay.lower() or g.replace("_", " ").lower() in hay.lower()

    label_hits = [g for g in gt_types if _matches(header, g)]
    narrative = bool(re.search(r"exploit|hack|attacker|drain|post-?mortem|\$\d", header, re.I))
    mechanism = narrative and bool(re.search(_MECHANISM_RE, header, re.I))

    # Context only — not scored. Upstream comments/strings are part of the real contract.
    body = text[len(header):]
    upstream_prose = " ".join(
        re.findall(r"//[^\n]*", body) + re.findall(r"/\*.*?\*/", body, re.S)
        + re.findall(r'"[^"\n]*"', body))
    upstream_label_hits = [
        g for g in gt_types if g not in label_hits and _matches(upstream_prose, g)]

    ptoks = protocol_tokens(contract_key, metadata)
    identity = [p for p in ptoks if re.search(rf"(?i)(?<![A-Za-z0-9]){re.escape(p)}", text)]
    return {
        "label_hits": label_hits,
        "upstream_label_hits": upstream_label_hits,
        "narrative": narrative,
        "mechanism": mechanism,
        "identity": identity,
        "severity": ("SEVERE" if (mechanism or label_hits)
                     else "MODERATE" if narrative
                     else "IDENTITY" if identity
                     else "CLEAN"),
    }


def _load_all():
    from benchmarks.bridge_contracts_real import load_real_contracts
    from benchmarks.defi_contracts_real import load_defi_contracts
    from benchmarks.lending_contracts_real import load_lending_contracts
    for dom, loader in (("bridge", load_real_contracts), ("defi", load_defi_contracts),
                        ("lending", load_lending_contracts)):
        for c in loader():
            if (c.get("source") or "").strip():
                yield dom, c


def main():
    """Audit prompt leakage at each level and write the report + sanitized corpora."""
    import argparse
    ap = argparse.ArgumentParser(description="Audit and remove prompt leakage")
    ap.add_argument("--write", action="store_true",
                    help="write sanitized corpora to contracts_stripped/ and contracts_anon/")
    ap.add_argument("--out", default="benchmarks/leakage_report.json")
    args = ap.parse_args()

    root = Path(__file__).parent.parent
    rows, failures = [], []
    counts = {"raw": {}, "stripped": {}, "anon": {}}

    for dom, c in _load_all():
        key, src = c["name"], c["source"]
        gt = [v["type"] for v in c["ground_truth"]["vulnerabilities"]]
        meta = c.get("metadata", {})
        row = {"domain": dom, "contract": key, "n_labels": len(gt)}

        for level in LEVELS:
            try:
                text, rep = sanitize(src, level, key, meta)
            except ValueError as e:
                failures.append(str(e))
                continue
            probs = verify(src, text, level, rep)
            if probs:
                failures.append(f"{key} [{level}]: " + "; ".join(probs))
            scan = leakage_scan(text, gt, key, meta)
            row[level] = scan["severity"]
            row.setdefault("label_hits", {})[level] = scan["label_hits"]
            counts[level][scan["severity"]] = counts[level].get(scan["severity"], 0) + 1

            if args.write and level != "raw":
                d = root / "benchmarks" / f"contracts_{level}"
                d.mkdir(exist_ok=True)
                (d / f"{key}.sol").write_text(text)
        rows.append(row)

    print(f"{'domain':8}{'contract':34}{'raw':>10}{'stripped':>10}{'anon':>10}")
    print("-" * 72)
    for r in rows:
        print(f"{r['domain']:8}{r['contract'][:32]:34}"
              f"{r.get('raw',''):>10}{r.get('stripped',''):>10}{r.get('anon',''):>10}")
    print("-" * 72)
    for level in LEVELS:
        tot = sum(counts[level].values()) or 1
        sev = counts[level].get("SEVERE", 0)
        mod = counts[level].get("MODERATE", 0)
        print(f"{level:9} SEVERE {sev:2} ({sev/tot*100:3.0f}%)  MODERATE {mod:2}  "
              f"IDENTITY {counts[level].get('IDENTITY',0):2}  CLEAN {counts[level].get('CLEAN',0):2}")

    if failures:
        print("\n!! SAFETY-INVARIANT FAILURES (sanitizer changed the code — do not use):")
        for f in failures:
            print("   -", f)
    else:
        print("\n✓ safety invariant held for every contract at every level "
              "(structural equivalence; no solc available for a compile check)")

    out = root / args.out
    out.write_text(json.dumps({"rows": rows, "counts": counts, "failures": failures}, indent=2))
    print(f"\nwrote {out.relative_to(root)}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
