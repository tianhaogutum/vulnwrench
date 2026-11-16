import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def cli(*args, data=None, cwd=ROOT):
    return subprocess.run([sys.executable, "-m", "vulnwrench", "sarif", *args], cwd=cwd, input=data,
                          capture_output=True, text=True, timeout=60)


class CliTests(unittest.TestCase):
    def test_parent_path_display_json_markdown_and_stdin(self):
        fixture = ROOT / "examples/sarif/locations/parent-segments.sarif"
        proc = cli("check", str(fixture))
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(proc.stderr, "")
        report = json.loads(proc.stdout)
        resolved = report["results"][0]["resolvedLocations"]
        self.assertEqual([r["resolvedUri"] for r in resolved], [
            "file:///workspace/link/../a.py", "link/../a.py",
            "file:///workspace/src/../lib/a%20b.py", "file:///link/../a.py",
            "file:///workspace/src/link/../a%20b.py", "file:///workspace/src/link/../a%20b.py",
            "link/%2E%2E/../a%2Fb%2520.py"])
        self.assertEqual(resolved[6]["displayPath"], "link/../../a/b%20.py")
        self.assertEqual(resolved[4]["artifactSourcePointer"], "/runs/0/artifacts/0/location")
        self.assertEqual(report["evidence"]["document"], json.loads(fixture.read_bytes()))
        self.assertEqual(cli("check", "-", data=fixture.read_text()).stdout, proc.stdout)
        md = cli("check", "-", "--format", "markdown", data=fixture.read_text())
        self.assertEqual(md.returncode, 1, md.stderr)
        self.assertIn("workspace&#47;link&#47;&#46;&#46;&#47;a&#46;py", md.stdout)

    def test_local_location_reporting_and_stdin_are_deterministic(self):
        args = ("check", "examples/sarif/locations/nested.sarif")
        proc = cli(*args)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report["results"][0]["resolvedLocations"][0]["displayPath"], "/workspace/src/../lib/a b.py")
        stdin = cli("check", "-", data=(ROOT / "examples/sarif/locations/nested.sarif").read_text())
        self.assertEqual(stdin.stdout, proc.stdout)
        md = cli(*args, "--format", "markdown")
        self.assertEqual(md.returncode, 1, md.stderr)
        self.assertIn("## Locations", md.stdout)
        self.assertIn("workspace&#47;src&#47;&#46;&#46;&#47;lib&#47;a b&#46;py", md.stdout)

    def test_invalid_locations_preserve_both_outputs_and_sanitize_diagnostics(self):
        valid = json.loads((ROOT / "examples/sarif/locations/nested.sarif").read_bytes())
        invalid = [json.loads((ROOT / "examples/sarif/locations/cycle.sarif").read_bytes())]
        for artifact in ({"uri": "a%SYNTHETIC_SECRET"}, {"uri": "https://SYNTHETIC_SECRET/a"},
                         {"uri": "a.py", "uriBaseId": "SYNTHETIC_SECRET"}):
            data = json.loads(json.dumps(valid))
            data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = artifact
            invalid.append(data)
        with tempfile.TemporaryDirectory() as directory:
            out, md = Path(directory) / "out.json", Path(directory) / "out.md"
            out.write_text("keep json")
            md.write_text("keep markdown")
            for data in invalid:
                proc = cli("check", "-", "--output", str(out), "--markdown", str(md), data=json.dumps(data))
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stdout, "")
                self.assertNotIn("SYNTHETIC_SECRET", proc.stderr)
                self.assertEqual(out.read_text(), "keep json")
                self.assertEqual(md.read_text(), "keep markdown")

    def test_help(self):
        for args in (("--help",), ("check", "--help")):
            proc = cli(*args)
            self.assertEqual(proc.returncode, 0)
            self.assertIn("SARIF", proc.stdout)

    def test_baseline_view_json_markdown_and_stdin(self):
        args = ("--baseline", "examples/sarif/baseline/before.sarif", "--fingerprint", "primary/v1")
        proc = cli("check", "examples/sarif/baseline/current.sarif", *args)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        view = json.loads(proc.stdout)["baselineComparison"]
        self.assertEqual(view["counts"], {"newly_observed": 1, "retained": 2, "absent": 1, "ambiguous": 0})
        stdin = cli("check", "-", *args, data=(ROOT / "examples/sarif/baseline/current.sarif").read_text())
        self.assertEqual(stdin.stdout, proc.stdout)
        md = cli("check", "examples/sarif/baseline/current.sarif", *args, "--format", "markdown")
        self.assertEqual(md.returncode, 1, md.stderr)
        self.assertIn("## Baseline comparison", md.stdout)
        self.assertIn("does not prove", md.stdout)

    def test_baseline_arguments_must_be_paired(self):
        for args in (("--baseline", "examples/sarif/clean.sarif"), ("--fingerprint", "primary/v1"),
                     ("--baseline", "examples/sarif/clean.sarif", "--fingerprint", "")):
            proc = cli("check", "examples/sarif/clean.sarif", *args)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(proc.stdout, "")

    def test_invalid_or_oversized_baseline_preserves_output(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory) / "baseline.sarif"
            target = Path(directory) / "output.json"
            target.write_text("keep")
            clean = (ROOT / "examples/sarif/clean.sarif").read_bytes()
            for data in (b'SYNTHETIC_SECRET', clean + b' ' * 2000):
                baseline.write_bytes(data)
                proc = cli("check", "examples/sarif/clean.sarif", "--baseline", str(baseline),
                           "--fingerprint", "primary/v1", "--max-bytes", str(len(clean) + 1),
                           "--output", str(target))
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stdout, "")
                self.assertNotIn("SYNTHETIC_SECRET", proc.stderr)
                self.assertEqual(target.read_text(), "keep")

    def test_baseline_must_not_be_overwritten_through_output_or_markdown_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline, link = Path(directory) / "baseline.sarif", Path(directory) / "alias"
            content = (ROOT / "examples/sarif/baseline/before.sarif").read_bytes()
            baseline.write_bytes(content)
            os.link(baseline, link)
            for destination in (baseline, link):
                for flag in ("--output", "--markdown"):
                    proc = cli("check", "examples/sarif/clean.sarif", "--baseline", str(baseline),
                               "--fingerprint", "primary/v1", flag, str(destination))
                    self.assertEqual(proc.returncode, 2)
                    self.assertEqual(baseline.read_bytes(), content)

    def test_failed_scan_cannot_produce_baseline_absence(self):
        proc = cli("check", "examples/sarif/baseline/failed.sarif", "--baseline",
                   "examples/sarif/baseline/before.sarif", "--fingerprint", "primary/v1")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report["baselineComparison"]["status"], "invalid")
        self.assertEqual(report["baselineComparison"]["counts"]["absent"], 0)
        self.assertEqual(report["actionable"], 0)
        self.assertEqual(report["totals"]["scanFailures"], 1)

    def test_semgrep_accepted_suppression_e2e(self):
        proc = cli("check", "examples/sarif/semgrep.sarif")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual((report["decision"], report["actionable"], report["acceptedSuppressions"]), ("pass", 0, 1))
        self.assertEqual(report["evidence"]["document"]["runs"][0]["tool"]["driver"]["name"], "Semgrep")

    def test_failed_scan_e2e(self):
        for name in ("failed-invocation", "error-notification"):
            proc = cli("check", f"examples/sarif/{name}.sarif")
            self.assertEqual(proc.returncode, 1, proc.stderr)
            report = json.loads(proc.stdout)
            self.assertEqual(report["actionable"], 0)
            self.assertEqual(report["decision"], "fail")
            self.assertEqual(report["totals"]["scanFailures"], 1)

    def test_output_and_markdown_files(self):
        with tempfile.TemporaryDirectory() as directory:
            out, md = Path(directory) / "report.json", Path(directory) / "report.md"
            proc = cli("check", "examples/sarif/rule-default.sarif", "--output", str(out), "--markdown", str(md))
            self.assertEqual(proc.returncode, 1, proc.stderr)
            self.assertEqual(proc.stdout, "")
            self.assertEqual(json.loads(out.read_text())["results"][0]["level"], "error")
            self.assertIn("Decision: **fail**", md.read_text())
            self.assertEqual(list(Path(directory).glob(".vulnwrench-sarif-*")), [])

    def test_markdown_stdout(self):
        proc = cli("check", "examples/sarif/clean.sarif", "--format", "markdown")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Decision: **pass**", proc.stdout)

    def test_explicit_policies(self):
        self.assertEqual(cli("check", "examples/sarif/unchanged.sarif").returncode, 1)
        self.assertEqual(cli("check", "examples/sarif/unchanged.sarif", "--ignore-unchanged").returncode, 0)
        self.assertEqual(cli("check", "examples/sarif/unknown-execution.sarif", "--require-execution-success").returncode, 1)
        self.assertEqual(cli("check", "examples/sarif/clean.sarif", "--require-execution-success").returncode, 0)

    def test_stdin_and_json_output(self):
        proc = cli("check", "-", data=(ROOT / "examples/sarif/semgrep.sarif").read_text())
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout)["decision"], "pass")

    def test_invalid_file_and_io_errors(self):
        for name in ("examples/sarif/invalid-version.sarif", "SYNTHETIC_SECRET_MISSING"):
            proc = cli("check", name)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(proc.stdout, "")
            self.assertNotIn("SYNTHETIC_SECRET", proc.stderr)
        with tempfile.TemporaryDirectory() as directory:
            proc = cli("check", "examples/sarif/clean.sarif", "--output", str(Path(directory) / "missing/secret.json"))
            self.assertEqual(proc.returncode, 2)
            self.assertNotIn("secret", proc.stderr)

    def test_invalid_data_errors_do_not_leak_values(self):
        for data in ('SYNTHETIC_SECRET', '{"version":"SYNTHETIC_SECRET","runs":[]}',
                     '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"demo"}},"results":[{"level":"SYNTHETIC_SECRET"}]}]}'):
            proc = cli("check", "-", data=data)
            self.assertEqual(proc.returncode, 2)
            self.assertNotIn("SYNTHETIC_SECRET", proc.stderr)
            self.assertEqual(proc.stdout, "")

    def test_invalid_arguments_are_sanitized(self):
        proc = cli("check", "examples/sarif/clean.sarif", "--level", "SYNTHETIC_SECRET")
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("SYNTHETIC_SECRET", proc.stderr)

    def test_byte_limit(self):
        proc = cli("check", "examples/sarif/clean.sarif", "--max-bytes", "5")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("byte limit", proc.stderr)
        self.assertEqual(cli("check", "-", "--max-bytes", "0", data="{}").returncode, 2)
        self.assertEqual(cli("check", "-", "--max-bytes", "99999999999999999999", data="{}").returncode, 2)

    def test_input_is_not_overwritten_even_with_hardlink(self):
        with tempfile.TemporaryDirectory() as directory:
            source, link = Path(directory) / "source.sarif", Path(directory) / "alias"
            content = (ROOT / "examples/sarif/semgrep.sarif").read_bytes()
            source.write_bytes(content)
            os.link(source, link)
            for destination in (source, link):
                proc = cli("check", str(source), "--output", str(destination))
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(source.read_bytes(), content)

    def test_destinations_must_differ(self):
        with tempfile.TemporaryDirectory() as directory:
            target = str(Path(directory) / "report")
            proc = cli("check", "examples/sarif/clean.sarif", "--output", target, "--markdown", target)
            self.assertEqual(proc.returncode, 2)
            self.assertFalse(Path(target).exists())

    def test_invalid_input_does_not_create_or_replace_output(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "report.json"
            target.write_text("keep")
            proc = cli("check", "examples/sarif/invalid-version.sarif", "--output", str(target))
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(target.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
