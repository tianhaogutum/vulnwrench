#!/usr/bin/env python3
"""Reproducible CPU comparison including index construction and exact match sets."""
import argparse
from datetime import date
import json
from pathlib import Path
import platform
import statistics
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from vulnwrench.ignoreaudit import Finding, Rule, match_indexed, match_reference


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", type=int, default=10000)
    parser.add_argument("--rules", type=int, default=1000)
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args()
    if not (0 <= args.findings <= 1000000 and 1 <= args.rules <= 100000 and 1 <= args.repeat <= 10):
        parser.error("workload/repeat outside supported bounds")
    rules = [Rule(f"rule:{i}", f"SYNTH-{i}", date(2026, 12, 1), package=f"package-{i % 17}" if i % 3 == 0 else None)
             for i in range(args.rules)]
    findings = [Finding(f"SYNTH-{i % (args.rules * 2)}", f"package-{i % 17}", f"app-{i % 9}/lock", "npm", "1.0", f"finding:{i}")
                for i in range(args.findings)]
    outputs, measurements = {}, {}
    for name, fn in (("reference", match_reference), ("indexed", match_indexed)):
        times = []
        for _ in range(args.repeat):
            start = time.perf_counter()
            result = fn(rules, findings)
            times.append(time.perf_counter() - start)
        outputs[name] = result
        measurements[name] = {"operations": result[2], "seconds": times, "medianSeconds": statistics.median(times)}
    equal = outputs["reference"][:2] == outputs["indexed"][:2]
    result = {"schemaVersion": 1, "matchSetEqual": equal,
              "workload": {"findings": args.findings, "rules": args.rules, "repeat": args.repeat,
                           "description": "synthetic selective exact IDs; one third of rules also select package"},
              "machine": {"python": platform.python_version(), "system": platform.system(), "machine": platform.machine()},
              "operationDefinition": "reference: each rule/finding check; indexed: each posting insertion + candidate check (not all CPU operations)",
              "timingIncludes": "validation, full matching, index construction and result lists; excludes fixture generation and imports",
              "matchedPairs": sum(map(len, outputs["indexed"][0])),
              "reference": measurements["reference"], "indexed": measurements["indexed"]}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if equal else 1


if __name__ == "__main__":
    raise SystemExit(main())
