"""Post-process a completed BRIDGE-bench raw/stripped/anon run.

Consumes the immutable artifacts written by agents.remeasure and, when present,
the corresponding semantic-rescorer artifacts. Produces one machine-readable JSON
summary and one contract-level CSV suitable for figures and publication.

The bootstrap is paired at the contract level: the same resampled contract indices
are used for raw, stripped, and anon so uncertainty on deltas reflects the paired
design rather than three independent samples.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
from pathlib import Path

LEVELS = ("raw", "stripped", "anon")
DOMAINS = ("bridge", "defi", "lending")
BOOTSTRAP_SEED = 20260808
BOOTSTRAP_N = 20_000


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def _prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": p, "recall": r, "f1": f1, "tp": tp, "fp": fp, "fn": fn}


def _aggregate(rows: list[dict]) -> dict:
    return _prf(
        sum(int(r.get("tp", 0)) for r in rows),
        sum(int(r.get("fp", 0)) for r in rows),
        sum(int(r.get("fn", 0)) for r in rows),
    )


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    xs = sorted(values)
    pos = (len(xs) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(xs) - 1)
    w = pos - lo
    return xs[lo] * (1 - w) + xs[hi] * w


def _ci(values: list[float]) -> list[float]:
    return [_percentile(values, 0.025), _percentile(values, 0.975)]


def _flatten_exact(data: dict) -> dict[str, dict]:
    out = {}
    for domain in DOMAINS:
        section = data.get(f"{domain}_agentic", {})
        for name, rec in section.get("per_contract", {}).items():
            out[name] = {
                "domain": domain,
                **rec.get("metrics", {}),
            }
    return out


def _flatten_semantic(path: Path) -> dict[str, dict] | None:
    rescored = path.with_name(path.stem + "__rescored.json")
    if not rescored.exists():
        return None
    data = _load(rescored)
    out = {}
    for name, rec in data.get("per_contract", {}).items():
        out[name] = {
            "tp": int(rec.get("tp", 0)),
            "fp": int(rec.get("fp", 0)),
            "fn": int(rec.get("fn", 0)),
            "precision": float(rec.get("precision", 0.0)),
            "recall": float(rec.get("recall", 0.0)),
            "f1": float(rec.get("f1", 0.0)),
        }
    return out


def discover(result_dir: Path) -> tuple[str, dict[str, Path]]:
    runs: dict[str, dict[str, Path]] = {}
    starts: dict[str, str] = {}
    for path in result_dir.glob("*.json"):
        if path.name.endswith("__rescored.json"):
            continue
        try:
            data = _load(path)
        except Exception:
            continue
        meta = data.get("_run", {})
        run_id = meta.get("run_id")
        level = meta.get("condition")
        if not run_id or level not in LEVELS or not meta.get("completed"):
            continue
        runs.setdefault(run_id, {})[level] = path
        starts[run_id] = max(starts.get(run_id, ""), str(meta.get("started_at", "")))
    complete = [(starts.get(rid, ""), rid, files) for rid, files in runs.items() if set(files) == set(LEVELS)]
    if not complete:
        raise SystemExit("no complete raw/stripped/anon run found")
    _, run_id, files = max(complete)
    return run_id, files


def validate(files: dict[str, Path]) -> dict[str, dict]:
    data = {level: _load(path) for level, path in files.items()}
    metas = {level: d["_run"] for level, d in data.items()}
    keys = ("run_id", "model", "code_commit_sha", "population")
    for key in keys:
        vals = [json.dumps(m.get(key), sort_keys=True) for m in metas.values()]
        if len(set(vals)) != 1:
            raise SystemExit(f"paired-run invariant failed: {key} differs across conditions")
    for level, meta in metas.items():
        if not meta.get("completed"):
            raise SystemExit(f"{level} artifact is partial; refusing to score")
    names = {level: set(_flatten_exact(d)) for level, d in data.items()}
    if len({tuple(sorted(v)) for v in names.values()}) != 1:
        raise SystemExit("paired-run invariant failed: contract population differs across conditions")
    if len(next(iter(names.values()))) != 24:
        raise SystemExit("paired-run invariant failed: expected exactly 24 scored contracts")
    return data


def summarize(metric_rows: dict[str, dict[str, dict]], domains: dict[str, str]) -> dict:
    result = {}
    for level in LEVELS:
        rows = metric_rows[level]
        result[level] = {
            "overall": _aggregate(list(rows.values())),
            "by_domain": {
                domain: _aggregate([rec for name, rec in rows.items() if domains[name] == domain])
                for domain in DOMAINS
            },
        }
    return result


def paired_bootstrap(metric_rows: dict[str, dict[str, dict]], names: list[str], n: int = BOOTSTRAP_N) -> dict:
    rng = random.Random(BOOTSTRAP_SEED)
    f1_samples = {level: [] for level in LEVELS}
    deltas = {"raw_minus_stripped": [], "stripped_minus_anon": [], "raw_minus_anon": []}
    size = len(names)
    for _ in range(n):
        sampled = [names[rng.randrange(size)] for _ in range(size)]
        f = {}
        for level in LEVELS:
            agg = _aggregate([metric_rows[level][name] for name in sampled])
            f[level] = agg["f1"]
            f1_samples[level].append(f[level])
        deltas["raw_minus_stripped"].append(f["raw"] - f["stripped"])
        deltas["stripped_minus_anon"].append(f["stripped"] - f["anon"])
        deltas["raw_minus_anon"].append(f["raw"] - f["anon"])
    return {
        "seed": BOOTSTRAP_SEED,
        "replicates": n,
        "f1_95ci": {level: _ci(vals) for level, vals in f1_samples.items()},
        "delta_f1_95ci": {key: _ci(vals) for key, vals in deltas.items()},
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="results_remeasure")
    ap.add_argument("--out", default="results_remeasure/remeasure_summary.json")
    ap.add_argument("--csv", default="results_remeasure/remeasure_contracts.csv")
    ap.add_argument("--bootstrap", type=int, default=BOOTSTRAP_N)
    args = ap.parse_args()

    result_dir = Path(args.dir)
    run_id, files = discover(result_dir)
    data = validate(files)
    exact = {level: _flatten_exact(data[level]) for level in LEVELS}
    names = list(exact["raw"].keys())
    domains = {name: exact["raw"][name]["domain"] for name in names}

    exact_summary = summarize(exact, domains)
    exact_boot = paired_bootstrap(exact, names, args.bootstrap)

    semantic = {level: _flatten_semantic(files[level]) for level in LEVELS}
    semantic_complete = all(v is not None for v in semantic.values())
    semantic_summary = None
    semantic_boot = None
    if semantic_complete:
        semantic_rows = {level: semantic[level] for level in LEVELS}  # type: ignore[index]
        for level in LEVELS:
            if set(semantic_rows[level]) != set(names):
                raise SystemExit(f"semantic population mismatch for {level}")
        semantic_summary = summarize(semantic_rows, domains)
        semantic_boot = paired_bootstrap(semantic_rows, names, args.bootstrap)

    meta = data["raw"]["_run"]
    report = {
        "run_id": run_id,
        "model": meta.get("model"),
        "code_commit_sha": meta.get("code_commit_sha"),
        "population": meta.get("population"),
        "pricing": meta.get("pricing"),
        "conditions": {
            level: {
                "artifact": str(files[level]),
                "estimated_list_cost_usd": data[level]["_run"].get("estimated_list_cost_usd"),
            }
            for level in LEVELS
        },
        "exact": exact_summary,
        "exact_bootstrap": exact_boot,
        "exact_delta_f1": {
            "raw_minus_stripped": exact_summary["raw"]["overall"]["f1"] - exact_summary["stripped"]["overall"]["f1"],
            "stripped_minus_anon": exact_summary["stripped"]["overall"]["f1"] - exact_summary["anon"]["overall"]["f1"],
            "raw_minus_anon": exact_summary["raw"]["overall"]["f1"] - exact_summary["anon"]["overall"]["f1"],
        },
        "semantic_available": semantic_complete,
        "semantic": semantic_summary,
        "semantic_bootstrap": semantic_boot,
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n")

    csv_path = Path(args.csv)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["domain", "contract"]
    for level in LEVELS:
        fields += [f"{level}_exact_tp", f"{level}_exact_fp", f"{level}_exact_fn", f"{level}_exact_f1"]
        if semantic_complete:
            fields += [f"{level}_semantic_tp", f"{level}_semantic_fp", f"{level}_semantic_fn", f"{level}_semantic_f1"]
    with csv_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for name in names:
            row = {"domain": domains[name], "contract": name}
            for level in LEVELS:
                e = exact[level][name]
                row.update({
                    f"{level}_exact_tp": e.get("tp", 0),
                    f"{level}_exact_fp": e.get("fp", 0),
                    f"{level}_exact_fn": e.get("fn", 0),
                    f"{level}_exact_f1": e.get("f1", 0.0),
                })
                if semantic_complete:
                    s = semantic[level][name]  # type: ignore[index]
                    row.update({
                        f"{level}_semantic_tp": s.get("tp", 0),
                        f"{level}_semantic_fp": s.get("fp", 0),
                        f"{level}_semantic_fn": s.get("fn", 0),
                        f"{level}_semantic_f1": s.get("f1", 0.0),
                    })
            writer.writerow(row)

    print(json.dumps({
        "run_id": run_id,
        "exact_f1": {l: round(exact_summary[l]["overall"]["f1"], 4) for l in LEVELS},
        "semantic_available": semantic_complete,
        "semantic_f1": ({l: round(semantic_summary[l]["overall"]["f1"], 4) for l in LEVELS}
                        if semantic_summary else None),
        "wrote": [str(out), str(csv_path)],
    }, indent=2))


if __name__ == "__main__":
    main()
