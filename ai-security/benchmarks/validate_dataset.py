"""
Dataset integrity validator for BRIDGE-bench.

Catches the classes of bug that silently degrade a benchmark run:
  - a registered contract whose ground-truth labels all got dropped (a typo'd
    vuln key that isn't in the domain taxonomy → contract scored on 0 labels);
  - a `.sol` filename that doesn't match its loader key (source never loads);
  - a ground-truth vuln type with no fuzzy-equivalence entry (the evaluator can
    only ever credit a verbatim string match for it);
  - empty-source placeholders, reported so a "partial" run is never mistaken
    for a complete one.

Run standalone (exits non-zero on hard errors, used in CI) or import `validate()`.

    python -m benchmarks.validate_dataset
"""
import sys
from pathlib import Path

from benchmarks.bridge_contracts_real import load_real_contracts
from benchmarks.defi_contracts_real import load_defi_contracts
from benchmarks.lending_contracts_real import load_lending_contracts
from benchmarks.live_contracts import load_live_contracts
from benchmarks.matched_contracts import load_matched_contracts
from benchmarks.dependency_registry import load_dependency_contracts

CONTRACTS_DIR = Path(__file__).parent / "contracts"
LIVE_DIR = Path(__file__).parent / "contracts_live"
MATCHED_DIR = Path(__file__).parent / "contracts_matched"
DEPS_DIR = Path(__file__).parent / "contracts_dependencies"
# Known empty-source placeholders (verified-only-on-Etherscan or off-chain hacks).
KNOWN_PLACEHOLDERS = {
    "poly_network_eth_cross_chain_manager", "ronin_bridge_validator",
    "orbit_chain_multisig", "lifi_protocol_diamond_march_2022",
}


def _type_equivalences():
    from agents.benchmark_runner import TYPE_EQUIVALENCES
    return TYPE_EQUIVALENCES


def validate():
    """Return (errors, warnings, stats). errors are hard failures."""
    errors, warnings = [], []
    stats = {}
    equiv = _type_equivalences()

    domains = [
        ("bridge", load_real_contracts()),
        ("defi", load_defi_contracts()),
        ("lending", load_lending_contracts()),
    ]
    for domain, contracts in domains:
        with_source = 0
        gt_total = 0
        for c in contracts:
            name = c["name"]
            src = (c.get("source") or "").strip()
            vulns = c["ground_truth"]["vulnerabilities"]
            gt_total += len(vulns)

            # 1. registered contract resolved to zero labels → labeling bug
            if not vulns:
                errors.append(f"[{domain}] {name}: 0 ground-truth vulns "
                              f"(typo'd key dropped by the taxonomy filter?)")

            # 2. source present and non-trivial, else must be a known placeholder
            if len(src) > 200:
                with_source += 1
            elif name not in KNOWN_PLACEHOLDERS:
                warnings.append(f"[{domain}] {name}: no committed source "
                                f"(not in KNOWN_PLACEHOLDERS) — run is partial")

            # 3. filename ↔ key
            if not (CONTRACTS_DIR / f"{name}.sol").exists() and name not in KNOWN_PLACEHOLDERS:
                errors.append(f"[{domain}] {name}: contracts/{name}.sol missing "
                              f"(loader key ≠ filename?)")

            # 4. every gt type should have a fuzzy-equivalence entry (else exact-only)
            for v in vulns:
                t = v["type"]
                if t not in equiv:
                    warnings.append(f"[{domain}] {name}: vuln '{t}' has no "
                                    f"TYPE_EQUIVALENCES entry (exact-match only)")
        stats[domain] = {"contracts": len(contracts), "with_source": with_source,
                         "gt_vulns": gt_total}

    # Live / negative-control domain — different invariants: 0 ground-truth vulns is
    # EXPECTED (that's what a negative control is), so it must not trip the exploit-domain
    # "0 vulns = labeling bug" check above. Validate the negative-control invariants instead.
    live = load_live_contracts()
    live_with_source = 0
    for c in live:
        name = c["name"]
        src = (c.get("source") or "").strip()
        if not c["metadata"].get("negative_control"):
            errors.append(f"[live] {name}: not marked negative_control")
        if c["ground_truth"]["vulnerabilities"]:
            errors.append(f"[live] {name}: negative control must have 0 ground-truth vulns")
        if len(src) > 200:
            live_with_source += 1
        elif c["metadata"].get("address") is not None:
            warnings.append(f"[live] {name}: no committed source but has an address")
        if src and not (LIVE_DIR / f"{name}.sol").exists():
            errors.append(f"[live] {name}: contracts_live/{name}.sol missing (key ≠ filename?)")
    stats["live"] = {"contracts": len(live), "with_source": live_with_source, "gt_vulns": 0}

    # Matched-pair domain — positives (must have labels + source + a live fixed counterpart).
    matched = load_matched_contracts()
    live_names = {c["name"] for c in live}
    m_with_source, m_gt = 0, 0
    for c in matched:
        name = c["name"]
        src = (c.get("source") or "").strip()
        vulns = c["ground_truth"]["vulnerabilities"]
        m_gt += len(vulns)
        if not vulns:
            errors.append(f"[matched] {name}: positive must have >=1 ground-truth vuln")
        if len(src) > 200:
            m_with_source += 1
        else:
            errors.append(f"[matched] {name}: no committed source (positive is unrunnable)")
        if not (MATCHED_DIR / f"{name}.sol").exists():
            errors.append(f"[matched] {name}: contracts_matched/{name}.sol missing (key ≠ filename?)")
        fixed = c["metadata"].get("fixed_counterpart")
        if fixed not in live_names:
            errors.append(f"[matched] {name}: fixed_counterpart '{fixed}' not in the live domain")
        for v in vulns:
            if v["type"] not in equiv:
                warnings.append(f"[matched] {name}: vuln '{v['type']}' has no TYPE_EQUIVALENCES entry (exact-match only)")
    stats["matched"] = {"contracts": len(matched), "with_source": m_with_source, "gt_vulns": m_gt}

    # External-dependency negative controls — same invariants as `live` (0 gt vulns EXPECTED).
    deps = load_dependency_contracts()
    deps_with_source = 0
    for c in deps:
        name = c["name"]
        if not c["metadata"].get("negative_control"):
            errors.append(f"[deps] {name}: not marked negative_control")
        if c["ground_truth"]["vulnerabilities"]:
            errors.append(f"[deps] {name}: negative control must have 0 ground-truth vulns")
        if (c.get("source") or "").strip():
            deps_with_source += 1
        else:
            errors.append(f"[deps] {name}: no committed source")
        if not (DEPS_DIR / f"{name}.sol").exists():
            errors.append(f"[deps] {name}: contracts_dependencies/{name}.sol missing (run fetch_dependencies)")
    stats["deps"] = {"contracts": len(deps), "with_source": deps_with_source, "gt_vulns": 0}

    return errors, warnings, stats


def main():
    errors, warnings, stats = validate()
    print("BRIDGE-bench dataset integrity\n" + "=" * 40)
    for d, s in stats.items():
        print(f"  {d:8} {s['with_source']:>2}/{s['contracts']:<2} with source, "
              f"{s['gt_vulns']:>3} ground-truth vulns")
    total = sum(s["with_source"] for s in stats.values())
    print(f"  {'TOTAL':8} {total} source-bearing contracts\n")

    for w in warnings:
        print(f"  warning: {w}")
    for e in errors:
        print(f"  ERROR:   {e}")

    if errors:
        print(f"\n✗ {len(errors)} error(s), {len(warnings)} warning(s)")
        sys.exit(1)
    print(f"\n✓ integrity OK ({len(warnings)} warning(s))")


if __name__ == "__main__":
    main()
