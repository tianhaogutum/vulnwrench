#!/usr/bin/env python3
"""Execute documented examples offline, checking committed outputs and failures."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
# Run against this repository's sources even when vulnwrench is not installed.
ENV = {**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, [str(ROOT / "src"), os.environ.get("PYTHONPATH")]))}


def cli(*args):
    return subprocess.run([sys.executable, "-m", "vulnwrench", "fuse", *map(str, args)], cwd=ROOT,
                          env=ENV, text=True, capture_output=True, timeout=60)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    with tempfile.TemporaryDirectory(prefix="vulnwrench-fuse-examples-") as td:
        output, markdown = Path(td) / "out.json", Path(td) / "out.md"
        args = ["merge", "--trivy", "examples/fuse/trivy.json", "--grype", "examples/fuse/grype.json", "--osv", "examples/fuse/osv.json",
                "--output", output, "--markdown", markdown]
        result = cli(*args)
        require(result.returncode == 0, "three-format CLI example failed")
        for actual, expected in [(output, "merged.json"), (markdown, "merged.md")]:
            require(actual.read_bytes() == (ROOT / "examples" / "fuse" / "expected" / expected).read_bytes(), "example output differs from committed evidence")
        data = json.loads(output.read_text())
        require(data["findingCount"] == 4 and data["observationCount"] == 6, "unexpected example counts")
        require(sum(f["observationCount"] for f in data["findings"]) == 6, "observation conservation failed")
        require(sum(s["observationCount"] for s in data["inputs"]) == 6, "input count conservation failed")
        for source in data["inputs"]:
            require(source["sha256"] == hashlib.sha256((ROOT / source["input"]).read_bytes()).hexdigest(), "source digest mismatch")
        merged = next(f for f in data["findings"] if f["package"]["identity"] == "pkg:npm/demo@1.0")
        require(merged["ids"] == ["CVE-2025-0001", "GHSA-demo-0001", "OSV-DEMO-0001"], "transitive aliases not preserved")
        require(merged["severityConflict"] and merged["fixConflict"], "expected conflicts not exposed")
        require(merged["observedBy"] == ["grype", "osv", "trivy"], "missing scanner evidence")
        print("PASS three-format CLI: 6 observations -> 4 findings; transitive aliases; severity/fix conflicts")
        print("PASS committed JSON and Markdown match executed outputs; source SHA-256 and counts verified")
        before = output.read_bytes(), markdown.read_bytes()
        require(cli(*args).returncode == 0, "repeat merge failed")
        require(before == (output.read_bytes(), markdown.read_bytes()), "output is not deterministic")
        print("PASS deterministic repeat: byte-identical JSON and Markdown")
        empty = cli("merge", "--trivy", "examples/fuse/trivy-empty.json", "--grype", "examples/fuse/grype-empty.json", "--osv", "examples/fuse/osv-empty.json")
        require(empty.returncode == 0 and json.loads(empty.stdout)["observationCount"] == 0, "empty reports failed")
        print("PASS recognized empty reports: 0 observations, 0 findings")
        coverage = subprocess.run([sys.executable, "-m", "vulnwrench", "fuse", "merge", "--trivy", "trivy.json",
                                  "--grype", "grype-empty.json", "--osv", "osv-empty.json",
                                  "--coverage-manifest", "coverage.json"], cwd=ROOT / "examples" / "fuse",
                                 env=ENV,
                                 text=True, capture_output=True, timeout=60)
        require(coverage.returncode == 0, "coverage manifest example failed")
        covered = json.loads(coverage.stdout)
        require((covered["observationCount"], covered["findingCount"]) == (2, 2), "coverage lost findings")
        scanners = {s["sourceId"]: s["scanner"] for s in covered["inputs"]}
        for finding in covered["findings"]:
            assessments = finding["absenceAssessments"]
            require({scanners[sid]: a["reasonCodes"] for sid, a in assessments.items()} == {
                "grype": ["target-mismatch"], "osv": ["database-timestamp-missing", "scan-incomplete"]},
                "coverage reasons differ from expected")
            require(all(not a["canEstablishFixed"] for a in assessments.values()), "absence claimed a fix")
        require(all(s["coverage"]["reasonCodes"] == ["manifest-not-supplied"] for s in data["inputs"]),
                "no-manifest coverage is not unknown")
        print("PASS coverage manifest: target mismatch, incomplete scan and missing date; 2 findings retained; no fix inferred")
        policy = subprocess.run([sys.executable, "-m", "vulnwrench", "fuse", "merge", "--trivy", "found.json",
                                "--trivy", "suppressed.json", "--coverage-manifest", "coverage.json"],
                               cwd=ROOT / "examples/fuse/policy", env=ENV,
                               text=True, capture_output=True, timeout=60)
        require(policy.returncode == 0, "scan policy example failed")
        policies = json.loads(policy.stdout)
        require((policies["inputCount"], policies["observationCount"], policies["findingCount"]) == (2, 1, 1),
                "scan policy example lost finding or inputs")
        require(policies["coverageAssessment"] == {"status": "incomparable", "reasonCodes": ["scan-policy-mismatch"]},
                "scan policy mismatch not exposed")
        absence, = policies["findings"][0]["absenceAssessments"].values()
        require(absence["status"] == "incomparable" and absence["reasonCodes"] == ["scan-policy-mismatch"]
                and absence["canEstablishFixed"] is False, "scan policy absence claimed comparability or a fix")
        require(policies["findings"][0]["ids"] == ["CVE-POLICY-1"], "scan policy example changed advisory")
        for source in policies["inputs"]:
            entry = policies["coverageManifest"]["rawManifest"]["inputs"][int(source["coverage"]["manifestPointer"].split("/")[-1])]
            require(source["sha256"] == entry["sha256"] == hashlib.sha256(
                    (ROOT / "examples/fuse/policy" / source["input"]).read_bytes()).hexdigest(), "scan policy binding differs")
            require(source["coverage"]["scanPolicyIdentity"] == entry["scanPolicyIdentity"], "scan policy provenance lost")
        print("PASS scan policy: same target/database, different suppression declarations; 1 finding retained; no fix inferred")
        database = subprocess.run([sys.executable, "-m", "vulnwrench", "fuse", "merge", "--trivy", "found.json",
                                  "--trivy", "absent.json", "--coverage-manifest", "coverage.json"],
                                 cwd=ROOT / "examples/fuse/database", env=ENV,
                                 text=True, capture_output=True, timeout=60)
        require(database.returncode == 0, "database snapshot example failed")
        snapshots = json.loads(database.stdout)
        require((snapshots["inputCount"], snapshots["observationCount"], snapshots["findingCount"]) == (2, 1, 1),
                "database snapshot example lost finding or inputs")
        expected = {"status": "incomparable", "reasonCodes": ["database-identity-mismatch"]}
        require(snapshots["coverageAssessment"] == expected, "database snapshot mismatch not exposed")
        absence, = snapshots["findings"][0]["absenceAssessments"].values()
        require(all(absence[k] == v for k, v in expected.items()) and absence["canEstablishFixed"] is False,
                "database snapshot absence claimed comparability or a fix")
        require(all(all(c[k] == v for k, v in expected.items()) for c in absence["comparedTo"]),
                "database snapshot comparison lost mismatch")
        require(snapshots["findings"][0]["ids"] == ["CVE-SNAPSHOT-1"], "database snapshot changed advisory")
        provenance = snapshots["coverageManifest"]
        raw = (ROOT / "examples/fuse/database/coverage.json").read_bytes()
        require(provenance["sha256"] == hashlib.sha256(raw).hexdigest() and provenance["byteCount"] == len(raw)
                and provenance["rawManifest"] == json.loads(raw), "database manifest provenance lost")
        for source in snapshots["inputs"]:
            entry = provenance["rawManifest"]["inputs"][int(source["coverage"]["manifestPointer"].split("/")[-1])]
            raw = (ROOT / "examples/fuse/database" / source["input"]).read_bytes()
            require(source["sha256"] == entry["sha256"] == hashlib.sha256(raw).hexdigest()
                    and source["rawReport"] == json.loads(raw), "database report evidence lost")
            require(source["coverage"]["databaseIdentity"] == entry["databaseIdentity"], "database label lost")
        print("PASS database snapshots: same target/policy/time, different identities; 1 finding retained; no fix inferred")
        explain_args = ["explain", "--trivy", "examples/fuse/explain/trivy.json", "--grype", "examples/fuse/explain/grype.json",
                        "--osv", "examples/fuse/explain/osv.json", "--advisory", "OSV-EXPLAIN-1",
                        "--package", "pkg:npm/demo@1.0#apps/api"]
        explained = cli(*explain_args)
        require(explained.returncode == 0, "explain example failed")
        require(explained.stdout.encode() == (ROOT / "examples/fuse/expected/explanation.json").read_bytes(),
                "explanation differs from committed evidence")
        explanation = json.loads(explained.stdout)
        require(explanation["finding"]["observationCount"] == 2 and explanation["finding"]["fixVersions"] == ["1.1", "1.2"],
                "explanation mixed unrelated package or advisory evidence")
        require(len(explanation["aliasLinks"]) == 2 and len(explanation["evidence"]) == 3,
                "explanation lost global alias provenance")
        require(explanation["remediationAssessment"] == "not-evaluated", "explanation invented a remediation verdict")
        require(cli(*explain_args).stdout == explained.stdout, "explanation is not deterministic")
        output.write_text("sentinel")
        ambiguous = cli(*explain_args[:-2], "--output", output)
        require(ambiguous.returncode == 2 and not ambiguous.stdout and output.read_text() == "sentinel",
                "ambiguous explanation did not preserve output")
        print("PASS explanation: 2 alias links; 2 contributing observations; external alias evidence isolated; ambiguous selection exit 2")
        saved = cli("explain", "--merged", "examples/fuse/explain/merged.json", *explain_args[-4:])
        require(saved.returncode == 0 and saved.stdout == explained.stdout, "saved explanation differs")
        saved_merge_args = ["merge", *explain_args[1:-4]]
        generated = cli(*saved_merge_args)
        require(generated.returncode == 0 and generated.stdout.encode() ==
                (ROOT / "examples/fuse/explain/merged.json").read_bytes(), "saved merge fixture is stale")
        broken = json.loads((ROOT / "examples/fuse/explain/dangling-alias.json").read_text())
        require(broken["aliasEdges"][0]["observationId"] == "s9999#/synthetic-secret-dangling", "dangling fixture changed")
        broken["aliasEdges"][0]["observationId"] = json.loads(generated.stdout)["aliasEdges"][0]["observationId"]
        require(broken == json.loads(generated.stdout), "dangling fixture changes unrelated evidence")
        failed = cli("explain", "--merged", "examples/fuse/explain/dangling-alias.json", *explain_args[-4:], "--output", output)
        require(failed.returncode == 2 and not failed.stdout and output.read_text() == "sentinel"
                and "synthetic-secret" not in failed.stderr, "dangling alias did not safely preserve output")
        print("PASS saved explanation: identical evidence; dangling alias reference exit 2; output preserved")
        for args in [("merge", "--osv", "examples/fuse/unsupported.json"),
                     ("merge", "--trivy", Path(td) / "missing.json")]:
            failed = cli(*args)
            require(failed.returncode == 2 and not failed.stdout and "Traceback" not in failed.stderr, "invalid input did not fail cleanly")
        invalid = Path(td) / "invalid.json"
        invalid.write_text('{"private":"synthetic-secret-should-not-be-echoed"')
        failed = cli("merge", "--grype", invalid)
        require(failed.returncode == 2 and "synthetic-secret" not in failed.stderr and not failed.stdout, "invalid JSON error was unsafe")
        print("PASS unsupported schema, unreadable path and invalid JSON: exit 2; no content echoed")
        print("Verified all examples offline; no scanner or network access used.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Example verification failed: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(1)
