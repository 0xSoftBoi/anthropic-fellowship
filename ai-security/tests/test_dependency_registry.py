"""Invariants for the Suwappu dependency registry (benchmarks/dependency_registry.py).

These lock in the "unhacked only", variety, and no-fabricated-address guarantees the dataset
was built to satisfy, so a future edit can't silently regress them.
"""
import re

from pathlib import Path

from benchmarks.dependency_registry import (
    DEPENDENCIES,
    by_tier,
    run_ready_targets,
    categories,
    load_dependency_contracts,
    slug,
    REPO_DATA_QUALITY_NOTES,
)

_DEPS_DIR = Path(__file__).parent.parent / "benchmarks" / "contracts_dependencies"

_EVM = re.compile(r"^0x[0-9a-fA-F]{40}$")
_FABRICATED_POLYMARKET_CTF = "0xE111180000d2663C0091e4f400237545B87B996B"


def test_run_ready_targets_are_evm_and_not_excluded():
    rr = run_ready_targets()
    assert len(rr) >= 10
    for e in rr:
        assert _EVM.match(e["address"]), f"{e['protocol']} address not a 42-char EVM address"
        assert e["tier"] in ("clean", "anchor", "caveat")


_NON_EXPLOIT_PHRASES = (
    "no contract", "no known contract", "no core exploit", "no production",
    "never hacked", "never exploited", "not exploited", "not broken",
    "no usdc contract", "no contract hack",
)


def test_no_hacked_contract_in_run_ready_set():
    # The whole point: every run-ready (clean/anchor/caveat) entry must AFFIRM that the
    # contract itself was not exploited. Anything with a real contract hack or a disclosed
    # critical drain vuln lives in `excluded`, not here.
    for e in run_ready_targets():
        hist = e["exploit_history"].lower()
        assert any(p in hist for p in _NON_EXPLOIT_PHRASES), \
            f"{e['protocol']} in run-ready set but exploit_history does not affirm non-exploitation: {e['exploit_history']!r}"


def test_reverification_moved_across_and_spendpermission_to_excluded():
    excluded = {e["protocol"] + "/" + e["contract_name"] for e in by_tier("excluded")}
    assert any("Across" in x for x in excluded), "Across (hacked Jul 2026) must be excluded"
    assert any("SpendPermissionManager" in x for x in excluded), "Coinbase SpendPermissionManager must be excluded"


def test_known_hacked_swaps_are_excluded_not_run_ready():
    run_ready_protocols = {e["protocol"] for e in run_ready_targets()}
    for hacked in ("Li.Fi", "KyberSwap", "OKX DEX", "Socket / Bungee", "Wormhole / Portal"):
        assert hacked not in run_ready_protocols, f"{hacked} is hacked and must not be run-ready"


def test_category_variety():
    cats = categories()
    assert len(cats) >= 7, f"want variety across >=7 categories, got {sorted(cats)}"
    for must_have in ("oracle", "bridge", "lending", "prediction_market"):
        assert must_have in cats, f"missing category {must_have}"


def test_fabricated_polymarket_exchange_not_present_anywhere():
    for e in DEPENDENCIES:
        assert e["address"].lower() != _FABRICATED_POLYMARKET_CTF.lower(), \
            "the fabricated Polymarket CTF exchange address must not be carried forward"


def test_uniswap_npm_address_is_full_42_chars():
    npm = [e for e in DEPENDENCIES if e["contract_name"].startswith("NonfungiblePositionManager")]
    assert npm and _EVM.match(npm[0]["address"]), "Uniswap v3 NPM must use the full 42-char address (not the repo's truncated 41)"


def test_run_ready_addresses_are_unique():
    addrs = [e["address"].lower() for e in run_ready_targets()]
    assert len(addrs) == len(set(addrs)), "duplicate address in run-ready set"


def test_data_quality_notes_recorded():
    assert len(REPO_DATA_QUALITY_NOTES) >= 3


# ── fetched-source negative-control domain ───────────────────────────────────

def test_dependency_contracts_load_as_negative_controls():
    ds = load_dependency_contracts()
    # Source is committed, so all run-ready targets should load.
    assert len(ds) >= 10
    for c in ds:
        assert (c.get("source") or "").strip(), f"{c['name']} has no source"
        assert c["ground_truth"]["vulnerabilities"] == [], "negative control must have empty ground truth"
        assert c["metadata"]["negative_control"] is True
        assert c["metadata"]["in_training_data_as_incident"] is False


# Words in the AUTHOR-INJECTED header that would leak the answer for a negative control
# ("nothing to find here"). Upstream NatSpec in the contract body is exempt (a human auditor
# sees it too) — we only scan the provenance header we prepend, before the first source marker.
_HEADER_LEAK_TOKENS = ("clean", "audit", "safe", "unexploited", "hardened",
                       "negative control", "no bug", "vulnerab", "exploit")


def test_committed_dependency_headers_do_not_leak_the_answer():
    sols = list(_DEPS_DIR.glob("*.sol"))
    assert sols, "no fetched dependency sources found (run benchmarks.fetch_dependencies)"
    for sol in sols:
        text = sol.read_text()
        header = text.split("// =====", 1)[0].lower()   # our provenance header only
        for tok in _HEADER_LEAK_TOKENS:
            assert tok not in header, f"{sol.name} header leaks '{tok}': {header!r}"


def test_fetched_files_match_registry_slugs():
    keys = {slug(e["protocol"], e["contract_name"]) for e in run_ready_targets()}
    on_disk = {p.stem for p in _DEPS_DIR.glob("*.sol")}
    missing = keys - on_disk
    assert not missing, f"registry targets with no fetched source: {missing}"
