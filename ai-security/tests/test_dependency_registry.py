"""Invariants for the Suwappu dependency registry (benchmarks/dependency_registry.py).

These lock in the "unhacked only", variety, and no-fabricated-address guarantees the dataset
was built to satisfy, so a future edit can't silently regress them.
"""
import re

from benchmarks.dependency_registry import (
    DEPENDENCIES,
    by_tier,
    run_ready_targets,
    categories,
    REPO_DATA_QUALITY_NOTES,
)

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
