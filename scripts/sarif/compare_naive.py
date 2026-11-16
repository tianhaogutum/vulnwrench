#!/usr/bin/env python3
"""Measure decision correctness against independently stated synthetic expectations.

Baseline is deliberately ONLY explicit warning/error counting, not sarif-tools.
No timing or speedup claims. Every expected value is asserted on every run.
"""

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from vulnwrench.sarifgate import check_bytes  # noqa: E402


def compare() -> dict:
    corpus = json.loads((ROOT / "examples/sarif/corpus.json").read_text())
    rows = []
    for case in corpus:
        data = (ROOT / "examples" / "sarif" / case["file"]).read_bytes()
        document = json.loads(data)
        # Independent literal implementation of the specified baseline.
        baseline_count = sum(result.get("level") in ("warning", "error")
                             for run in document["runs"] for result in run.get("results", []))
        baseline_decision = "fail" if baseline_count else "pass"
        report = check_bytes(data)
        assert baseline_count == case["naiveCount"], case["file"]
        assert baseline_decision == case["naiveDecision"], case["file"]
        assert report["decision"] == case["decision"], case["file"]
        assert report["actionable"] == case["actionable"], case["file"]
        assert report["naive"]["explicitWarningErrorCount"] == baseline_count, case["file"]
        rows.append({"fixture": case["file"], "expected": case["decision"],
                     "baselineCount": baseline_count, "baselineDecision": baseline_decision,
                     "gateActionable": report["actionable"], "gateDecision": report["decision"]})
    return {"experiment": "synthetic decision correctness; not a speed benchmark",
            "cases": len(rows),
            "baselineCorrect": sum(r["baselineDecision"] == r["expected"] for r in rows),
            "gateCorrect": sum(r["gateDecision"] == r["expected"] for r in rows), "rows": rows}


if __name__ == "__main__":
    print(json.dumps(compare(), indent=2, sort_keys=True))
