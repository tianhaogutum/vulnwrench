#!/usr/bin/env python3
"""Verify evidence-gate contracts with the source or installed console CLI."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FILES = ("before.json", "after.json", "before-bom.json", "after-bom.json", "scans.json")
FLAGS = ("--before", "--after", "--before-bom", "--after-bom", "--metadata")


def verify(command=None, cwd=ROOT):
    command = command or [sys.executable, "-m", "vulnwrench", "delta"]
    with tempfile.TemporaryDirectory(prefix="vulnwrench-delta-gates-") as folder:
        paths = [Path(folder) / name for name in FILES]
        output = Path(folder) / "matrix.json"

        def run(docs, expected, *extra, stdout=None):
            for path, doc in zip(paths, docs):
                path.write_text(json.dumps(doc), encoding="utf-8")
            args = [*command, "compare"]
            for flag, path in zip(FLAGS, paths):
                args.extend([flag, str(path)])
            streams = {"capture_output": True} if stdout is None else {"stdout": stdout, "stderr": subprocess.PIPE}
            result = subprocess.run(args + list(extra), cwd=cwd, text=True, timeout=60, **streams)
            assert result.returncode == expected, (result.returncode, result.stderr)
            if expected != 2:
                assert not result.stderr
            return result

        original = [json.loads((ROOT / "examples" / "delta" / name).read_text()) for name in FILES]
        expected = (ROOT / "examples/delta/expected.json").read_text()
        assert run(original, 0, "--fail-on-unknown").stdout == expected
        assert run(original, 1, "--fail-on", "introduced", "--fail-on-unknown").stdout == expected

        # Exact README example: disappeared finding with a changed snapshot.
        example_files = ("grype/trivy-before.json", "explain/absent-after.json",
                         "grype/before-bom.json", "grype/after-bom.json", "explain/changed-db.json")
        docs = [json.loads((ROOT / "examples" / "delta" / name).read_text()) for name in example_files]
        ungated = run(docs, 0).stdout
        output.write_text("previous output", encoding="utf-8")
        assert not run(docs, 3, "--fail-on-unknown", "--output", str(output)).stdout
        assert output.read_text() == ungated
        matrix = json.loads(ungated)
        assert matrix["summary"] == {"no_longer_reported": 1}
        assert not matrix["comparable"] and not matrix["transitions"][0]["fixed"]
        assert matrix["comparability_reasons"] == ["database_identity_changed"]
        markdown = run(docs, 0, "--format", "markdown").stdout
        assert not run(docs, 3, "--fail-on-unknown", "--format", "markdown", "--output", str(output)).stdout
        assert output.read_text() == markdown and "Full evidence and accounting" in markdown

        # The confirmed audit boundary: another after advisory contradicts removal.
        grype = [json.loads((ROOT / "examples/delta/grype" / name).read_text()) for name in FILES]
        docs = deepcopy(grype)
        docs[4]["aliases"] = {}
        docs[3]["components"] = []
        matrix = json.loads(run(docs, 3, "--fail-on", "introduced", "--fail-on-unknown").stdout)
        assert matrix["comparable"]
        assert matrix["summary"] == {"introduced": 1, "no_longer_reported": 1}
        assert all("report_inventory_conflict" in row["reasons"] for row in matrix["transitions"])

        docs = deepcopy(grype)
        docs[0]["matches"] = []
        docs[1]["matches"][0]["artifact"]["locations"] = []
        matrix = json.loads(run(docs, 3, "--fail-on-unknown").stdout)
        assert not matrix["transitions"] and len(matrix["unknown_findings"]["after"]) == 1
        assert matrix["accounting"]["after_findings"] == matrix["accounting"]["after_records_accounted"] == 1

        output.write_text("previous output", encoding="utf-8")
        docs[1]["descriptor"]["version"] = "SYNTHETIC_SECRET_UNSUPPORTED"
        failure = run(docs, 2, "--fail-on-unknown", "--output", str(output))
        assert output.read_text() == "previous output" and not failure.stdout
        assert "SYNTHETIC_SECRET" not in failure.stderr and "Traceback" not in failure.stderr
        # Incomparable evidence must not hide an output error behind exit 3.
        docs[1]["descriptor"]["version"] = "0.86.1"
        assert not run(docs, 2, "--fail-on-unknown", "--output", str(Path(folder) / "missing/out.json")).stdout
        assert not list(Path(folder).glob(".vulnwrench-delta-*"))

        # Buffered stdout must finish before exit 3 can report retained evidence.
        docs = [json.loads((ROOT / "examples" / "delta" / name).read_text()) for name in example_files]
        for doc in docs[:2]:
            doc["Results"][0]["Vulnerabilities"] = []
        for doc in docs[2:4]:
            doc["components"] = []
        for large in (False, True):
            if large:
                docs[1]["extension"] = "SYNTHETIC_OUTPUT_SECRET" * 1000
            for format in ("json", "markdown"):
                flags = ("--fail-on-unknown", "--format", format)
                working = run(docs, 3, *flags).stdout
                if not large:
                    assert len(working.encode()) < 8192
                assert working == run(docs, 0, "--format", format).stdout
                reader, writer = os.pipe()
                os.close(reader)
                try:
                    failure = run(docs, 2, *flags, stdout=writer)
                finally:
                    os.close(writer)
                assert failure.stderr == "vulnwrench delta: input/output or JSON structure error (values omitted)\n"
                if Path("/dev/full").exists():
                    with open("/dev/full", "wb") as sink:
                        failure = run(docs, 2, *flags, stdout=sink)
                    assert failure.stderr == "vulnwrench delta: input/output or JSON structure error (values omitted)\n"
    print("verified evidence gate: pass, introduced, incomparable JSON/Markdown, scope conflict, unknown-only, safe input/output failures, buffered/large stdout closed-pipe and full-device failures")


if __name__ == "__main__":
    verify()
