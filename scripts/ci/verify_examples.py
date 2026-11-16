"""Rerun the `vulnwrench ci` example and check it against the recorded outputs.

Run from the repository root: python3 scripts/ci/verify_examples.py [--update]
Inputs are the synthetic fixtures in examples/ci (fictional packages and advisory IDs).
"""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "ci"
RECORDED = ROOT / "benchmarks" / "ci"
ARGS = ["--trivy", "trivy.json", "--grype", "grype.json", "--osv", "osv.json", "--baseline", "baseline.json",
        "--ignores", ".trivyignore", "--ignores", "osv-scanner.toml", "--epss", "epss.csv", "--kev", "kev.json",
        "--as-of", "2026-11-12", "--reports-unfiltered"]
OUTPUTS = {"text": "report.txt", "json": "report.json", "sarif": "report.sarif"}


def run(fmt):
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "NO_COLOR": "1"}
    result = subprocess.run([sys.executable, "-m", "vulnwrench", "ci", *ARGS, "--format", fmt],
                            cwd=EXAMPLE, env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 1, (fmt, result.returncode, result.stderr)
    return result.stdout


def baseline():
    """The saved baseline is `vulnwrench fuse merge` over examples/ci/baseline/*.json."""
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    result = subprocess.run([sys.executable, "-m", "vulnwrench", "fuse", "merge", "--trivy", "baseline/trivy.json",
                             "--grype", "baseline/grype.json", "--osv", "baseline/osv.json"],
                            cwd=EXAMPLE, env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    return result.stdout


def main():
    update = "--update" in sys.argv[1:]
    if (EXAMPLE / "baseline.json").read_text() != baseline():
        print("FAIL examples/ci/baseline.json differs from a fresh `vulnwrench fuse merge`")
        return 1
    print("PASS examples/ci/baseline.json")
    outputs = {fmt: run(fmt) for fmt in OUTPUTS}
    funnel = json.loads(outputs["json"])["funnel"]
    summary = {
        "claim": f"{funnel['rawFindings']} raw findings from {len(funnel['scanners'])} scanners -> "
                 f"{funnel['needAction']} that need action",
        "synthetic": True,
        "inputs": "examples/ci: fictional acme-* packages and fictional advisory IDs; not real vulnerability data",
        "command": "cd examples/ci && vulnwrench ci " + " ".join(ARGS),
        "exitCode": 1,
        "funnel": funnel,
        "removedByStage": {"fuse (duplicates across and within scanners)": funnel["rawFindings"] - funnel["fused"],
                           "baseline (already on the base branch)": funnel["baselineKnown"],
                           "exceptions (unexpired .trivyignore / osv-scanner.toml rules)": funnel["suppressed"],
                           "exploit (not in KEV, EPSS below 0.1)": funnel["low"],
                           "exploit (no exploit data, listed for review)": funnel["unknown"]},
        "recordedOutputs": [f"benchmarks/ci/{name}" for name in OUTPUTS.values()],
        "reproduce": "python3 scripts/ci/verify_examples.py",
    }
    outputs["summary"] = json.dumps(summary, indent=2) + "\n"
    names = {**OUTPUTS, "summary": "results.json"}
    failed = False
    for key, name in names.items():
        path = RECORDED / name
        if update:
            path.write_text(outputs[key])
            print(f"wrote {path.relative_to(ROOT)}")
        elif not path.exists() or path.read_text() != outputs[key]:
            print(f"FAIL {path.relative_to(ROOT)} differs from a fresh run")
            failed = True
        else:
            print(f"PASS {path.relative_to(ROOT)}")
    if not update:
        print(("FAILED" if failed else "Verified") + f": {summary['claim']}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
