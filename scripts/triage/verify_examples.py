#!/usr/bin/env python3
"""Run real CLI subprocesses offline, parse native formats and check snapshots."""
from __future__ import annotations

import argparse
from datetime import date
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tests.triage.schema_subset import validate_openvex

# The compiler refuses symlinked path components (macOS: /var -> /private/var).
tempfile.tempdir = os.path.realpath(tempfile.gettempdir())
# Run the CLI from this clone, installed or not.
ENV = {**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, (str(ROOT / "src"), os.environ.get("PYTHONPATH"))))}

PRODUCT_ID = "urn:example:demo-product:1.0"
COMMON = ["--as-of", "2026-11-11", "--author", "Synthetic Example Team",
          "--product-id", PRODUCT_ID, "--timestamp", "2026-11-11T12:00:00Z"]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh", action="store_true", help="intentionally replace checked-in synthetic snapshots")
    args = parser.parse_args()
    runs = 0

    def cli(source, output, *, allow=True, expect=0, code=None, metadata=True):
        nonlocal runs
        command = [sys.executable, "-m", "vulnwrench", "triage", "compile", str(source), "--out-dir", str(output)]
        if metadata:
            command += COMMON
        if allow:
            command.append("--allow-scope-loss")
        result = subprocess.run(command, cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=60)
        runs += 1
        require(result.returncode == expect, f"unexpected CLI exit: {result.returncode}")
        if code:
            require(code in result.stderr, "expected diagnostic code missing")
        if expect != 0:
            require(not output.exists(), "failed compilation wrote an output directory")
        return result

    with tempfile.TemporaryDirectory(prefix="vulnwrench-triage-examples-") as tmp:
        work = Path(tmp)
        for name, counts in (("decisions", (1, 1, 1, 1)), ("mixed-decisions", (5, 6, 6, 4))):
            source = ROOT / "examples" / "triage" / f"{name}.json"
            cli(source, work / f"{name}-denied", allow=False, expect=2, code="E_SCOPE_LOSS")
            output = work / name
            result = cli(source, output)
            report = json.loads((output / "conversion-report.json").read_bytes())
            require(report["counts"] == dict(zip(("decisions", "trivyEntries", "osvEntries", "vexStatements"), counts)), "incorrect projection counts")
            require(json.loads(result.stdout)["counts"] == report["counts"], "CLI summary mismatch")
            records = json.loads(source.read_bytes())["decisions"]
            expected_entries = []
            expected_vex = {}
            for record in records:
                for primary in record["ids"]:
                    ids = [primary, *record.get("aliases", {}).get(primary, [])]
                    for id_ in ids:
                        expected_entries.append((id_, record["package"], record["reason"], record["expiresOn"]))
                    if record["status"] != "accepted_risk":
                        expected_vex[primary] = record
            # JSON flow-style is valid YAML 1.1/1.2; parse without a YAML dependency.
            trivy = json.loads((output / ".trivyignore.yaml").read_bytes())
            actual = [(r["id"], r["purls"][0], r["statement"], r["expired_at"]) for r in trivy["vulnerabilities"]]
            require(sorted(actual) == sorted(expected_entries), "Trivy fields not preserved")
            osv = tomllib.loads((output / "osv-scanner.toml").read_text())
            require(sorted((r["id"], r["reason"], r["effectiveUntil"]) for r in osv["IgnoredVulns"]) ==
                    sorted((id_, reason, date.fromisoformat(expiry)) for id_, _, reason, expiry in expected_entries), "OSV fields not preserved")
            vex = json.loads((output / "openvex.json").read_bytes())
            validate_openvex(vex)
            require(len(vex["statements"]) == len(expected_vex), "incorrect VEX statement count")
            for statement in vex["statements"]:
                record = expected_vex[statement["vulnerability"]["name"]]
                require(statement["status"] == record["status"], "VEX status changed")
                require(statement["products"] == [{"@id": PRODUCT_ID, "subcomponents": [{"@id": record["package"]}]}], "VEX product mapping incorrect")
                require(statement["vulnerability"].get("aliases", []) == record.get("aliases", {}).get(statement["vulnerability"]["name"], []), "inferred or lost alias")
                for field in ("justification", "impact_statement", "action_statement"):
                    require(statement.get(field) == record.get(field), "VEX status explanation changed")
            actual_files = {p.name: p.read_bytes() for p in output.iterdir()}
            for filename, info in report["artifacts"].items():
                require(info["sha256"] == sha256(actual_files[filename]).hexdigest(), "artifact digest mismatch")
            second = work / f"{name}-repeat"
            cli(source, second)
            require(actual_files == {p.name: p.read_bytes() for p in second.iterdir()}, "generation was not deterministic")
            expected = ROOT / "examples/triage/expected" / name
            if args.refresh:
                expected.mkdir(parents=True, exist_ok=True)
                require(set(p.name for p in expected.iterdir()) <= set(actual_files), "unexpected existing snapshot files")
                for filename, data in actual_files.items():
                    (expected / filename).write_bytes(data)
            require(expected.is_dir(), "snapshots missing; run --refresh intentionally")
            require(actual_files == {p.name: p.read_bytes() for p in expected.iterdir()}, "checked-in snapshots differ")
            print(f"PASS {name}: {json.dumps(report['counts'], sort_keys=True)}")

        accepted_doc = json.loads((ROOT / "examples/triage/decisions.json").read_bytes())
        accepted_doc["decisions"][0]["status"] = "accepted_risk"
        accepted_file = work / "accepted.json"
        accepted_file.write_text(json.dumps(accepted_doc), encoding="utf-8")
        accepted_out = work / "accepted"
        cli(accepted_file, accepted_out)
        require(not (accepted_out / "openvex.json").exists(), "accepted risk incorrectly became VEX")
        accepted_report = json.loads((accepted_out / "conversion-report.json").read_bytes())
        require(accepted_report["counts"]["vexStatements"] == 0 and accepted_report["omittedArtifacts"], "VEX omission was not reported")

        expired = json.loads((ROOT / "examples/triage/decisions.json").read_bytes())
        expired["decisions"][0]["expiresOn"] = "2026-11-11"
        expired_file = work / "expired.json"
        expired_file.write_text(json.dumps(expired), encoding="utf-8")
        cli(expired_file, work / "expired", expect=2, code="E_EXPIRED")
        unknown_file = work / "unknown.json"
        unknown_file.write_text(json.dumps({"decisions": [], "SECRET_UNKNOWN_FIELD": "SECRET_VALUE"}), encoding="utf-8")
        failed = cli(unknown_file, work / "unknown", expect=2, code="E_INPUT")
        require("SECRET" not in failed.stderr, "diagnostic exposed input")
        cli(ROOT / "examples/triage/decisions.json", work / "missing-metadata", expect=2, code="E_ARGUMENT", metadata=False)
        cli(ROOT / "examples/triage/decisions.json", work / ".." / "forbidden-traversal", expect=2, code="E_OUTPUT")

        renewal = ROOT / "examples/triage/renewal"
        review_args = [sys.executable, "-m", "vulnwrench", "triage", "preview-renewal", str(renewal / "prior.json"),
                       "--prior-as-of", "2026-11-01", "--as-of", "2026-11-11", "--expiring-within-days", "7"]

        def review(extra, expect=0, code=None):
            nonlocal runs
            result = subprocess.run(review_args + extra, cwd=ROOT, env=ENV, capture_output=True, timeout=60)
            runs += 1
            require(result.returncode == expect, "unexpected review CLI exit")
            if code:
                require(code.encode() in result.stderr and result.stdout == b"", "review failure emitted a plan or wrong diagnostic")
            return result.stdout

        extra = ["--current", str(renewal / "current.json")]
        actual = review(extra)
        require(actual == review(extra), "review plan was not deterministic")
        plan = json.loads(actual)
        require([r["statuses"] for r in plan["decisions"]] == [
            ["expired"], ["expiring_soon"], ["owner_changed"],
            ["owner_missing"], ["scope_changed"], ["unchanged"]], "review findings differ")
        require(plan["counts"] == {"decisions": 6, "reviewRequired": 5} and plan["automaticActions"] == [], "review changed policy")
        if args.refresh:
            (renewal / "expected-plan.json").write_bytes(actual)
        require(actual == (renewal / "expected-plan.json").read_bytes(), "review snapshot differs")
        date_only = json.loads(review([]))
        require(date_only["counts"]["reviewRequired"] == 2, "date-only review changed decisions")
        review(["--as-of", "2026-10-31"], expect=2, code="E_DATE")
        null_file = work / "null-current.json"
        null_file.write_text("null\n", encoding="utf-8")
        review(["--current", str(null_file)], expect=2, code="E_INPUT")
        cli(renewal / "prior.json", work / "expired-renewal", expect=2, code="E_EXPIRED")
        print("PASS renewal preview: six distinct outcomes, date-only review, unchanged source references, no automatic actions, expired compilation refused")
    print(f"PASS {runs} real CLI runs; 2 compiled snapshot sets and 1 review-plan snapshot; native-format mappings, explicit scope loss, expiry, accepted-risk semantics and safe errors")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, AssertionError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"FAIL example verification: {type(exc).__name__}", file=sys.stderr)
        sys.exit(1)
