#!/usr/bin/env python3
"""Run real CLI examples and compare deterministic, committed output artifacts."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def cli(*args):
    return subprocess.run([sys.executable, "-m", "vulnwrench", "sarif", *args], cwd=ROOT,
                          capture_output=True, text=True, timeout=60)


def main():
    corpus = json.loads((ROOT / "examples/sarif/corpus.json").read_text())
    checks = 0
    for case in corpus:
        proc = cli("check", "examples/sarif/" + case["file"])
        assert proc.returncode == (1 if case["decision"] == "fail" else 0), case["file"]
        assert not proc.stderr, case["file"]
        report = json.loads(proc.stdout)
        assert report["decision"] == case["decision"], case["file"]
        assert report["actionable"] == case["actionable"], case["file"]
        original = json.loads((ROOT / "examples" / "sarif" / case["file"]).read_bytes())
        assert report["evidence"]["document"] == original, case["file"]
        checks += 1
    with tempfile.TemporaryDirectory() as directory:
        out = str(Path(directory) / "out.json")
        md = str(Path(directory) / "out.md")
        proc = cli("check", "examples/sarif/semgrep.sarif", "--level", "warning", "--output", out, "--markdown", md)
        assert proc.returncode == 0 and not proc.stdout and not proc.stderr
        assert Path(out).read_bytes() == (ROOT / "examples/sarif/expected/semgrep.json").read_bytes()
        assert Path(md).read_bytes() == (ROOT / "examples/sarif/expected/semgrep.md").read_bytes()
        checks += 1
    for fixture, flag, expected in [("unchanged", "--ignore-unchanged", 0),
                                    ("unknown-execution", "--require-execution-success", 1)]:
        proc = cli("check", f"examples/sarif/{fixture}.sarif", flag)
        assert proc.returncode == expected and not proc.stderr
        checks += 1
    proc = cli("check", "examples/sarif/invalid-version.sarif")
    assert proc.returncode == 2 and not proc.stdout and "2.1.0" in proc.stderr
    checks += 1
    proc = cli("check", "examples/sarif/locations/nested.sarif")
    assert proc.returncode == 1 and not proc.stderr
    paths = json.loads(proc.stdout)["results"][0]["resolvedLocations"]
    assert [(p["resolvedUri"], p["displayPath"]) for p in paths] == [
        ("file:///workspace/src/../lib/a%20b.py", "/workspace/src/../lib/a b.py"), ("plain.py", "plain.py")]
    checks += 1
    proc = cli("check", "examples/sarif/locations/cycle.sarif")
    assert proc.returncode == 2 and not proc.stdout and "cyclic" in proc.stderr
    checks += 1
    proc = subprocess.run([sys.executable, "scripts/sarif/compare_naive.py"], cwd=ROOT,
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, "comparison failed"
    assert proc.stdout.encode() == (ROOT / "examples/sarif/expected/comparison.json").read_bytes()
    checks += 1
    print(f"Verified {checks} CLI/artifact checks; {len(corpus)} synthetic SARIF cases.")


if __name__ == "__main__":
    main()
