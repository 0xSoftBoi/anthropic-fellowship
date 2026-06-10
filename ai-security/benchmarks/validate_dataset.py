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

CONTRACTS_DIR = Path(__file__).parent / "contracts"
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
