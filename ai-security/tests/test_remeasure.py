"""Regression tests for the locked contamination remeasurement protocol."""

from agents.remeasure import (
    DEFAULT_INPUT_USD_PER_M,
    DEFAULT_OUTPUT_USD_PER_M,
    EXPECTED,
    _baseline_population,
    estimated_cost,
    locked_items,
)


def test_population_is_exactly_published_24_contract_baseline():
    pop = _baseline_population()
    assert {domain: len(names) for domain, names in pop.items()} == EXPECTED
    assert sum(len(names) for names in pop.values()) == 24
    assert len({name for names in pop.values() for name in names}) == 24


def test_every_locked_contract_still_has_real_source():
    items = locked_items()
    assert len(items) == 24
    assert all(len((item["contract"].get("source") or "").strip()) > 200 for item in items)


def test_opus_48_default_list_price_is_versioned_in_code():
    assert DEFAULT_INPUT_USD_PER_M == 5.0
    assert DEFAULT_OUTPUT_USD_PER_M == 25.0
    assert estimated_cost(1_000_000, 1_000_000) == 30.0
