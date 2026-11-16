#!/usr/bin/env python3
"""Execute documented CLI examples and check committed, genuinely generated output."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BASE = [sys.executable, "-m", "vulnwrench", "delta", "compare", "--before", "examples/delta/before.json",
        "--after", "examples/delta/after.json", "--before-bom", "examples/delta/before-bom.json",
        "--after-bom", "examples/delta/after-bom.json", "--metadata", "examples/delta/scans.json"]


def run(command, expected=0):
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
    if result.returncode != expected:
        raise AssertionError(f"example exit code {result.returncode}, expected {expected}")
    return result


def main():
    checks = 0
    with tempfile.TemporaryDirectory(prefix="vulnwrench-delta-examples-") as directory:
        folder = Path(directory)
        output = folder / "result.json"
        run(BASE + ["--output", str(output)])
        expected = (ROOT / "examples/delta/expected.json").read_bytes()
        assert output.read_bytes() == expected, "committed JSON differs from actual CLI output"
        checks += 1
        result = json.loads(output.read_text())
        assert result["summary"] == {"introduced": 1, "persistent": 1, "package_removed": 1,
                                     "fixed_within_snapshot": 1, "version_changed_still_affected": 1}
        checks += 1
        assert next(t for t in result["transitions"] if t["package"]["name"] == "demo")["fixed"] is False
        checks += 1
        assert result["accounting"]["before_findings"] == result["accounting"]["before_records_accounted"] == 4
        assert result["accounting"]["after_findings"] == result["accounting"]["after_records_accounted"] == 3
        checks += 1
        run(BASE + ["--fail-on", "introduced", "--output", str(output)], expected=1)
        assert output.read_bytes() == expected
        checks += 1
        md = folder / "result.md"
        run(BASE + ["--format", "markdown", "--output", str(md)])
        assert md.read_bytes() == (ROOT / "examples/delta/expected.md").read_bytes()
        checks += 1
        bad_metadata = folder / "invalid.json"
        bad_metadata.write_text('{"schema_version": 99, "secret": "SYNTHETIC_REDACTION_CHECK"}')
        command = list(BASE)
        command[-1] = str(bad_metadata)
        failure = run(command, expected=2)
        assert "SYNTHETIC_REDACTION_CHECK" not in failure.stderr and not failure.stdout
        checks += 1
    print(f"verified {checks} example checks (real CLI JSON/Markdown, gate and failure paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
