import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class CLITests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-m", "vulnwrench", "ignores", *args], cwd=ROOT, text=True, capture_output=True, timeout=60)

    def command(self, format="trivy"):
        return ["audit", "--format", format, "--rules", "examples/ignores/.trivyignore" if format == "trivy" else "examples/ignores/osv-scanner.toml",
                "--report", f"examples/ignores/{format}.json", "--report-unfiltered", "--as-of", "2026-11-11"]

    def test_help(self):
        proc = self.run_cli("--help")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("audit", proc.stdout)

    def test_both_native_formats_e2e(self):
        for format in ("trivy", "osv"):
            proc = self.run_cli(*self.command(format))
            with self.subTest(format=format):
                self.assertEqual(proc.returncode, 0, proc.stderr)
                result = json.loads(proc.stdout)
                self.assertEqual(result["rules"][0]["matchCount"], 2)
                self.assertIn("expired", result["rules"][0]["status"])
                self.assertEqual(result["summary"]["findingCount"], 3)
                self.assertEqual(len(result["provenance"]["reportSha256"]), 64)

    def test_alias_map_e2e(self):
        proc = self.run_cli(*self.command("osv"), "--alias-map", "examples/ignores/aliases.json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result["rules"][-1]["matchCount"], 2)
        self.assertIn("duplicate", result["rules"][-1]["status"])

    def test_metadata_and_markdown(self):
        proc = self.run_cli(*self.command(), "--metadata", "examples/ignores/trivy-metadata.json", "--output-format", "markdown")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("| line:2 | CVE-2025-0001 | 2 |", proc.stdout)
        self.assertNotIn("synthetic-team", proc.stdout)
        self.assertNotIn("Synthetic migration exception", proc.stdout)

    def test_failures_no_output(self):
        no_ack = self.command()
        no_ack.remove("--report-unfiltered")
        for command in (no_ack, self.command() + ["--as-of", "2026-02-30"], self.command() + ["--soon-days", "-1"],
                        self.command() + ["--rules", "does-not-exist-SECRET"], ["audit", "--format", "grype", "--rules", "rules.yml", "--report", "report.json"]):
            proc = self.run_cli(*command)
            with self.subTest(command=command):
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stdout, "")
                self.assertNotIn("SECRET", proc.stderr)
                self.assertNotIn("Traceback", proc.stderr)

    def test_invalid_report_and_glob_selector_e2e(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            report = Path(tmp, "report.json")
            report.write_text('{"SchemaVersion":2,"Results":[],"unknown":"SECRET"}')
            proc = self.run_cli(*self.command(), "--report", str(report))
            self.assertEqual(proc.returncode, 2)
            self.assertNotIn("SECRET", proc.stderr)
            rules = Path(tmp, "osv.toml")
            rules.write_text('[[IgnoredVulns]]\nid="CVE-1"\npaths=["app/*"]')
            proc = self.run_cli(*self.command("osv"), "--rules", str(rules))
            self.assertEqual(proc.returncode, 2)
            yaml = Path(tmp, "rules.yaml")
            yaml.write_text("vulnerabilities: []")
            proc = self.run_cli(*self.command(), "--rules", str(yaml))
            self.assertEqual(proc.returncode, 2)

    def test_file_output_and_no_input_mutation(self):
        before = (ROOT / "examples/ignores/.trivyignore").read_bytes()
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            output = Path(tmp, "out.json")
            proc = self.run_cli(*self.command(), "--output", str(output))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, "")
            self.assertEqual(json.loads(output.read_text())["summary"]["ruleCount"], 4)
        self.assertEqual(before, (ROOT / "examples/ignores/.trivyignore").read_bytes())
        proc = self.run_cli(*self.command(), "--output", "examples/ignores/.trivyignore")
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(before, (ROOT / "examples/ignores/.trivyignore").read_bytes())

    def test_hardlink_and_symlink_input_protection(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            output = Path(tmp, "out.json")
            output.symlink_to(ROOT / "examples/ignores/.trivyignore")
            proc = self.run_cli(*self.command(), "--output", str(output))
            self.assertEqual(proc.returncode, 2)
            output.unlink()
            output.hardlink_to(ROOT / "examples/ignores/.trivyignore")
            proc = self.run_cli(*self.command(), "--output", str(output))
            self.assertEqual(proc.returncode, 2)

    def test_local_osv_config_scope(self):
        proc = self.run_cli(*self.command("osv"), "--osv-config-dir", "app")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["rules"][0]["matchCount"], 2)
        proc = self.run_cli(*self.command("osv"), "--osv-config-dir", "other")
        self.assertEqual(json.loads(proc.stdout)["rules"][0]["matchCount"], 0)

    def test_incomplete_osv_observations_never_become_orphans(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp, "report.json")
            for state in ("absent", "null", "empty"):
                for grouped in (False, True):
                    package = {"package": {"name": "demo", "ecosystem": "npm"}}
                    if grouped:
                        package["groups"] = [{"ids": ["CVE-2025-9999"], "aliases": ["GHSA-synthetic-alias"]}]
                    if state != "absent":
                        package["vulnerabilities"] = None if state == "null" else []
                    # Preserve real observations even when a different package is incomplete.
                    complete = {"package": {"name": "known"}, "vulnerabilities": [{"id": "CVE-2025-0001"}]}
                    report.write_text(json.dumps({"results": [{"source": {"path": "app/lock"},
                                                              "packages": [package, complete]}]}))
                    proc = self.run_cli(*self.command("osv"), "--report", str(report))
                    with self.subTest(state=state, grouped=grouped):
                        self.assertEqual(proc.returncode, 0, proc.stderr)
                        result = json.loads(proc.stdout)
                        self.assertEqual(result["coverage"], "asserted_unfiltered" if state == "empty" else "unknown")
                        self.assertEqual(result["rules"][0]["matchCount"], 1)
                        self.assertEqual("orphan_candidate" in result["rules"][1]["status"], state == "empty")
                        if state != "empty":
                            self.assertIn("coverage_unknown", result["rules"][1]["status"])
                            self.assertIn("results[0].packages[0].vulnerabilities", " ".join(result["notes"]))

    def test_benchmark_real_work(self):
        proc = subprocess.run([sys.executable, "scripts/ignores/benchmark.py", "--findings", "100", "--rules", "10", "--repeat", "1"], cwd=ROOT, capture_output=True, timeout=60, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout)
        self.assertTrue(result["matchSetEqual"])
        self.assertEqual(result["reference"]["operations"], 1000)
        self.assertLess(result["indexed"]["operations"], 1000)
        self.assertGreater(result["matchedPairs"], 0)


if __name__ == "__main__":
    unittest.main()
