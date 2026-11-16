#!/usr/bin/env python3
"""Verify pinned synthetic Grype CLI examples, including installed console use."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "examples/delta/grype"
FILES = ("before.json", "after.json", "before-bom.json", "after-bom.json", "scans.json")
FLAGS = ("--before", "--after", "--before-bom", "--after-bom", "--metadata")


def verify(command=None, cwd=ROOT):
    command = command or [sys.executable, "-m", "vulnwrench", "delta"]
    original = [json.loads((FIXTURES / name).read_text()) for name in FILES]
    with tempfile.TemporaryDirectory(prefix="vulnwrench-delta-grype-") as folder:
        paths = [Path(folder) / name for name in FILES]

        def run(docs, expected=0, *extra):
            for path, doc in zip(paths, docs):
                path.write_text(json.dumps(doc), encoding="utf-8")
            args = [*command, "compare"]
            for flag, path in zip(FLAGS, paths):
                args.extend([flag, str(path)])
            result = subprocess.run(args + list(extra), cwd=cwd, capture_output=True, text=True, timeout=60)
            assert result.returncode == expected, result.stderr
            return result

        result = json.loads(run(original).stdout)
        assert result["summary"] == {"version_changed_still_affected": 1}
        assert result["transitions"][0]["package"]["path"] == "node_modules/demo"
        assert result["transitions"][0]["before_records"] == ["/before_report/matches/0"]
        trivy = deepcopy(original)
        for i, filename in ((0, "trivy-before.json"), (1, "trivy-after.json"), (4, "trivy-scans.json")):
            trivy[i] = json.loads((FIXTURES / filename).read_text())
        trivy_result = json.loads(run(trivy).stdout)
        def semantic(rows):
            return [{k: v for k, v in row.items() if k not in {"before_records", "after_records"}} for row in rows]
        assert semantic(result["transitions"]) == semantic(trivy_result["transitions"])
        markdown = run(original, 0, "--format", "markdown").stdout
        assert "version_changed_still_affected" in markdown and '"location_record"' in markdown
        docs = deepcopy(original)
        docs[1]["matches"] = []
        assert json.loads(run(docs).stdout)["summary"] == {"fixed_within_snapshot": 1}
        docs = deepcopy(original)
        docs[1]["matches"][0]["artifact"]["locations"].append({"path": "/ambiguous"})
        unknown = json.loads(run(docs).stdout)
        assert unknown["summary"] == {"no_longer_reported": 1}
        assert unknown["unknown_findings"]["after"][0]["reasons"] == ["ambiguous_package_location"]
        docs = deepcopy(original)
        docs[4]["aliases"] = {}
        docs[3]["components"] = []
        assert json.loads(run(docs).stdout)["summary"] == {"introduced": 1, "no_longer_reported": 1}
        docs = deepcopy(original)
        docs[0]["matches"] = []
        assert json.loads(run(docs, 1, "--fail-on", "introduced").stdout)["summary"] == {"introduced": 1}
        docs[1]["descriptor"]["version"] = "SYNTHETIC_SECRET_UNSUPPORTED"
        error = run(docs, 2)
        assert not error.stdout and "SYNTHETIC_SECRET" not in error.stderr and "Traceback" not in error.stderr
    print("verified 8 pinned Grype CLI checks (Trivy equivalence, provenance, Markdown, fix, unknown, contradiction, gate, safe failure)")


if __name__ == "__main__":
    verify()
