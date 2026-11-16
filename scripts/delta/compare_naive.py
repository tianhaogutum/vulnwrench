#!/usr/bin/env python3
"""Run a labelled accuracy comparison and measure both in-memory comparators."""
import argparse
import json
from pathlib import Path
import platform
import statistics
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from vulnwrench.scandelta import compare
from corpus import cases


def naive(documents):
    """Baseline: raw (ID,name,version) set subtraction, without inventory or aliases."""
    def tuples(document):
        return {(v["VulnerabilityID"], v["PkgName"], v["InstalledVersion"])
                for result in document["Results"] for v in (result.get("Vulnerabilities") or [])}
    old, new = tuples(documents[0]), tuples(documents[1])
    labels = set()
    if old & new:
        labels.add("persistent")
    if new - old:
        labels.add("introduced")
    if old - new:
        labels.add("fixed_within_snapshot")
    return labels, len(old - new)


def evaluate():
    corpus = cases()
    rows = []
    for name, documents, expected in corpus:
        baseline, fixes = naive(documents)
        result = compare(*documents)
        actual = {t["classification"] for t in result["transitions"]}
        false_new = sum(t["fixed"] for t in result["transitions"]) if "fixed_within_snapshot" not in expected else 0
        rows.append(dict(case=name, expected=sorted(expected), baseline=sorted(baseline), actual=sorted(actual),
                         baseline_correct=baseline == expected, delta_correct=actual == expected,
                         baseline_false_fixed=fixes if "fixed_within_snapshot" not in expected else 0,
                         delta_false_fixed=false_new))
    # Timings cover normalization, aliasing, comparison, accounting and provenance (not import).
    # JSON parsing, disk I/O, rendering and scanner execution are outside both timings.
    timing = {}
    for name, function in (("raw_tuple_baseline", naive), ("vulnwrench_delta", lambda d: compare(*d))):
        samples = []
        for _ in range(7):
            start = time.perf_counter_ns()
            for _ in range(200):
                for _, documents, _ in corpus:
                    function(documents)
            samples.append((time.perf_counter_ns() - start) / 200 / 1_000_000)
        timing[name] = {"median_ms_per_14_case_corpus": round(statistics.median(samples), 6),
                        "samples": 7, "corpus_runs_per_sample": 200}
    summary = dict(cases=len(rows), baseline_correct=sum(r["baseline_correct"] for r in rows),
                   delta_correct=sum(r["delta_correct"] for r in rows),
                   baseline_false_fixed=sum(r["baseline_false_fixed"] for r in rows),
                   delta_false_fixed=sum(r["delta_false_fixed"] for r in rows))
    return dict(corpus="14 synthetic scenarios v1; exact expected classification-set accuracy per scenario",
                python=platform.python_version(), platform=platform.system() + " " + platform.machine(),
                summary=summary, timings=timing, cases=rows,
                timing_notice="Different work: vulnwrench delta also validates inventory and retains provenance. No speedup claim.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = evaluate()
    content = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(content, encoding="utf-8")
    else:
        print(content, end="")
    summary = result["summary"]
    return int(summary["delta_correct"] != summary["cases"] or summary["delta_false_fixed"] != 0)


if __name__ == "__main__":
    raise SystemExit(main())
