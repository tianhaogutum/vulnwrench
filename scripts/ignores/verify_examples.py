#!/usr/bin/env python3
"""Execute documented CLI examples; compare deterministic, committed real output."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="regenerate committed sample outputs by actually running the CLI")
    args = parser.parse_args()
    cases = [
        ("trivy", "expected-trivy.json", []),
        ("osv", "expected-osv.json", ["--metadata", "examples/ignores/osv-metadata.json"]),
        ("osv", "expected-osv-aliases.json", ["--alias-map", "examples/ignores/aliases.json"]),
        ("trivy", "expected-trivy.md", ["--metadata", "examples/ignores/trivy-metadata.json", "--output-format", "markdown"]),
    ]
    for format, filename, extra in cases:
        cmd = [sys.executable, "-m", "vulnwrench", "ignores", "audit", "--format", format, "--rules",
               "examples/ignores/.trivyignore" if format == "trivy" else "examples/ignores/osv-scanner.toml", "--report",
               f"examples/ignores/{format}.json", "--report-unfiltered", "--as-of", "2026-11-11", *extra]
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, timeout=60, text=True)
        if proc.returncode:
            raise AssertionError(f"{filename}: CLI failed with exit {proc.returncode}")
        if filename.endswith(".json"):
            result = json.loads(proc.stdout)
            assert result["rules"][0]["matchCount"] == 2
            assert "expired" in result["rules"][0]["status"]
            alias_row = result["rules"][-1]
            assert alias_row["matchCount"] == (2 if "--alias-map" in extra else 0)
            assert result["coverage"] == "asserted_unfiltered"
        path = ROOT / "examples" / "ignores" / filename
        if args.write:
            path.write_text(proc.stdout, encoding="utf-8")
        else:
            assert path.read_text(encoding="utf-8") == proc.stdout, f"{filename}: output changed"
        print(f"PASS {filename}")
    print(f"{len(cases)} CLI examples verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
