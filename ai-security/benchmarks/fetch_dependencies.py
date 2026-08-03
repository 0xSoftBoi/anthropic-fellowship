"""
Keyless fetcher for the Suwappu dependency negative-control set.

Fetches verified source for the run-ready targets in dependency_registry.py from public
Blockscout v2 REST (no API key), with a Sourcify fallback, and writes each to
benchmarks/contracts_dependencies/<key>.sol with a PROVENANCE-ONLY header.

ANTI-LEAKAGE DISCIPLINE (same as contracts_live / contracts_matched):
the committed .sol carries provenance only — protocol, contract, address, chain, explorer.
It must NOT contain the words that would leak the expected answer for a negative control
("clean", "audited", "no bug", "safe", "negative control") or any category/exploit note.
All of that lives in the loader metadata / docs, never in the prompt. Enforced by a test.

Usage:  python -m benchmarks.fetch_dependencies            # fetch all run-ready targets
        python -m benchmarks.fetch_dependencies --list     # show targets, fetch nothing
"""
from __future__ import annotations

import argparse
import json
import os
import re
import time
from pathlib import Path

import requests

from benchmarks.dependency_registry import run_ready_targets, slug

OUT_DIR = Path(__file__).parent / "contracts_dependencies"

# Blockscout v2 REST host + Sourcify chain id per network. Keyless.
CHAIN = {
    "base":     {"host": "https://base.blockscout.com", "sourcify": 8453},
    "polygon":  {"host": "https://polygon.blockscout.com", "sourcify": 137},
    "ethereum": {"host": "https://eth.blockscout.com", "sourcify": 1},
}
# Concrete fetch chain for entries whose registry chain is generic.
CHAIN_OVERRIDE = {"all-evm": "base", "multi-evm": "ethereum", "multi": "ethereum"}


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "BRIDGE-bench-deps/1.0"})
    # Honor the environment's TLS-intercepting proxy if present.
    ca = os.environ.get("REQUESTS_CA_BUNDLE") or "/root/.ccr/ca-bundle.crt"
    if Path(ca).exists():
        s.verify = ca
    return s


def fetch_blockscout(session, host: str, address: str) -> str | None:
    """Blockscout v2: GET /api/v2/smart-contracts/{addr} -> source + additional_sources."""
    url = f"{host}/api/v2/smart-contracts/{address}"
    try:
        r = session.get(url, timeout=40)
        if r.status_code != 200:
            return None
        d = r.json()
        main = d.get("source_code") or ""
        if not main:
            return None
        parts = []
        name = d.get("name") or "Contract"
        parts.append(f"// ===== {name} (primary source) =====\n{main}")
        for extra in d.get("additional_sources") or []:
            fp = extra.get("file_path", "import")
            src = extra.get("source_code", "")
            if src:
                parts.append(f"// ===== {fp} =====\n{src}")
        return "\n\n".join(parts)
    except Exception as e:
        print(f"    blockscout error: {e}")
        return None


def fetch_sourcify(session, chain_id: int, address: str) -> str | None:
    url = f"https://sourcify.dev/server/files/any/{chain_id}/{address}"
    try:
        r = session.get(url, timeout=30)
        if r.status_code != 200:
            return None
        d = r.json()
        parts = []
        for f in d.get("files", []):
            if f.get("name", "").endswith(".sol"):
                parts.append(f"// ===== {f['name']} =====\n{f.get('content','')}")
        return "\n\n".join(parts) or None
    except Exception as e:
        print(f"    sourcify error: {e}")
        return None


def provenance_header(entry: dict, chain: str, source: str) -> str:
    """Provenance ONLY. No bug/audit/clean/category words — that would leak the answer."""
    return (
        f"// {entry['protocol']} — {entry['contract_name']}\n"
        f"// Source: {source} @ {chain}, {entry['address']}\n"
    )


def fetch_all(list_only: bool = False) -> dict:
    targets = run_ready_targets()
    if list_only:
        for e in targets:
            print(f"  {slug(e['protocol'], e['contract_name']):40} {e['chain']:10} {e['address']}")
        return {"total": len(targets)}

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    session = _session()
    stats = {"total": len(targets), "fetched": 0, "failed": []}

    for e in targets:
        key = slug(e["protocol"], e["contract_name"])
        chain = CHAIN_OVERRIDE.get(e["chain"], e["chain"])
        cfg = CHAIN.get(chain)
        print(f"\n📦 {key}  ({chain} {e['address']})")
        if not cfg:
            print(f"   ✗ no explorer config for chain {chain}")
            stats["failed"].append({"key": key, "reason": f"no chain config {chain}"})
            continue

        src = fetch_blockscout(session, cfg["host"], e["address"])
        time.sleep(0.3)
        explorer = f"Blockscout({chain})"
        if not src:
            print("   blockscout miss, trying Sourcify…")
            src = fetch_sourcify(session, cfg["sourcify"], e["address"])
            explorer = f"Sourcify({chain})"
            time.sleep(0.3)

        if not src:
            print("   ✗ no verified source")
            stats["failed"].append({"key": key, "reason": "no verified source"})
            continue

        body = provenance_header(e, chain, explorer) + "\n" + src
        (OUT_DIR / f"{key}.sol").write_text(body)
        # Sidecar provenance JSON (metadata; NOT read into the prompt).
        (OUT_DIR / f"{key}.json").write_text(json.dumps({
            "key": key, "protocol": e["protocol"], "contract_name": e["contract_name"],
            "address": e["address"], "chain": chain, "category": e["category"],
            "tier": e["tier"], "memorization_exposure": e["memorization_exposure"],
            "exploit_history": e["exploit_history"], "explorer": explorer,
        }, indent=2))
        stats["fetched"] += 1
        print(f"   ✓ {key}.sol ({len(body):,} chars) via {explorer}")

    print(f"\n{'='*60}\nfetched {stats['fetched']}/{stats['total']} to {OUT_DIR}/")
    for f in stats["failed"]:
        print(f"  ✗ {f['key']}: {f['reason']}")
    return stats


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Keyless fetch of Suwappu dependency negative controls")
    ap.add_argument("--list", action="store_true", help="list targets, fetch nothing")
    args = ap.parse_args()
    fetch_all(list_only=args.list)
