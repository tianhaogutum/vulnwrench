import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from vulnwrench.fuse import InputError, read_report

ROOT = Path(__file__).resolve().parents[2]


def run(*args, cwd=ROOT):
    return subprocess.run([sys.executable, "-m", "vulnwrench", "fuse", *map(str, args)], cwd=cwd,
                          capture_output=True, text=True, timeout=60)


class CLITests(unittest.TestCase):
    def test_three_format_cli_e2e_and_golden_outputs(self):
        with tempfile.TemporaryDirectory() as td:
            output, markdown = Path(td) / "merged.json", Path(td) / "merged.md"
            args = ["merge", "--trivy", "examples/fuse/trivy.json", "--grype", "examples/fuse/grype.json", "--osv", "examples/fuse/osv.json",
                    "--output", output, "--markdown", markdown]
            completed = run(*args)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "")
            result = json.loads(output.read_text())
            self.assertEqual(result["findingCount"], 4)
            self.assertEqual(result["observationCount"], 6)
            f = next(f for f in result["findings"] if f["package"]["identity"] == "pkg:npm/demo@1.0")
            self.assertEqual(f["ids"], ["CVE-2025-0001", "GHSA-demo-0001", "OSV-DEMO-0001"])
            self.assertEqual(f["observedBy"], ["grype", "osv", "trivy"])
            self.assertTrue(f["severityConflict"])
            self.assertTrue(f["fixConflict"])
            self.assertEqual(output.read_bytes(), (ROOT / "examples/fuse/expected/merged.json").read_bytes())
            self.assertEqual(markdown.read_bytes(), (ROOT / "examples/fuse/expected/merged.md").read_bytes())
            first_digest = hashlib.sha256(output.read_bytes()).hexdigest()
            self.assertEqual(run(*args).returncode, 0)
            self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(), first_digest)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_installed_cli_e2e_outside_repository(self):
        with tempfile.TemporaryDirectory() as td:
            executed = run("merge", "--trivy", ROOT / "examples/fuse/trivy.json",
                           "--grype", ROOT / "examples/fuse/grype.json", "--osv", ROOT / "examples/fuse/osv.json", cwd=td)
            self.assertEqual(executed.returncode, 0, executed.stderr)
            merged = json.loads(executed.stdout)
            self.assertEqual((merged["findingCount"], merged["observationCount"]), (4, 6))
            failed = run("merge", "--osv", ROOT / "examples/fuse/unsupported.json", cwd=td)
            self.assertEqual(failed.returncode, 2, failed.stderr)
            self.assertEqual(failed.stdout, "")

    def test_stdout_json_and_empty_reports(self):
        result = run("merge", "--trivy", "examples/fuse/trivy-empty.json", "--grype", "examples/fuse/grype-empty.json", "--osv", "examples/fuse/osv-empty.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["observationCount"], 0)

    def test_repeat_scanner_flags(self):
        result = run("merge", "--trivy", "examples/fuse/trivy.json", "--trivy", "examples/fuse/trivy.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual((data["inputCount"], data["findingCount"], data["observationCount"]), (2, 2, 4))

    def test_help_and_version(self):
        for args in [("--help",), ("merge", "--help"), ("--version",)]:
            with self.subTest(args=args):
                self.assertEqual(run(*args).returncode, 0)

    def test_bad_cli_arguments_do_not_echo_values(self):
        secret = "synthetic-secret-must-not-appear"
        for args in [("merge",), (), ("merge", "--" + secret), (secret,), ("merge", "--output")]:
            with self.subTest(args=args):
                result = run(*args)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn(secret, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_invalid_or_unsupported_inputs_have_no_partial_output(self):
        secret = "synthetic-secret-must-not-appear"
        malformed = ["{\"secret\":\"" + secret + "\"", '{"Results":[],"Results":[]}',
                     '{"Results":[],"other":NaN}', '{"Results":[],"other":Infinity}',
                     '{"Results":[],"other":1e999}', '[1,2,3]', '{"secret":"' + secret + '"}',
                     '{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"A","PkgName":"' + secret + '","InstalledVersion":12}]}]}']
        with tempfile.TemporaryDirectory() as td:
            report, output = Path(td) / "report.json", Path(td) / "output.json"
            for contents in malformed:
                report.write_text(contents)
                with self.subTest(contents=contents):
                    result = run("merge", "--trivy", report, "--output", output)
                    self.assertEqual(result.returncode, 2)
                    self.assertNotIn(secret, result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertFalse(output.exists())
                    self.assertEqual(result.stdout, "")
            report.write_bytes(b'\xff\xfe')
            self.assertEqual(run("merge", "--trivy", report).returncode, 2)

    def test_unreadable_paths_do_not_echo_path(self):
        result = run("merge", "--trivy", "synthetic-secret-path-does-not-exist")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("synthetic-secret-path", result.stderr)
        self.assertEqual(run("merge", "--trivy", ROOT / "examples" / "fuse").returncode, 2)

    @unittest.skipIf(os.geteuid() == 0, "root bypasses permissions")
    def test_permission_denied(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "private.json"
            path.write_text('{"Results":[]}')
            path.chmod(0)
            try:
                self.assertEqual(run("merge", "--trivy", path).returncode, 2)
            finally:
                path.chmod(0o600)

    def test_outputs_cannot_overwrite_inputs_including_links(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "in.json"
            source.write_text('{"Results":[]}')
            hardlink, symlink = Path(td) / "hard.json", Path(td) / "sym.json"
            os.link(source, hardlink)
            symlink.symlink_to(source)
            for dest in [source, hardlink, symlink]:
                with self.subTest(dest=dest):
                    result = run("merge", "--trivy", source, "--output", dest)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(source.read_text(), '{"Results":[]}')
            same_output = Path(td) / "same.json"
            self.assertEqual(run("merge", "--trivy", source, "--output", same_output, "--markdown", same_output).returncode, 2)
            self.assertFalse(same_output.exists())

    def test_failed_validation_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "output.json"
            output.write_text("sentinel")
            r = run("merge", "--trivy", "examples/fuse/trivy.json", "--osv", "examples/fuse/unsupported.json", "--output", output)
            self.assertEqual(r.returncode, 2)
            self.assertEqual(output.read_text(), "sentinel")

    def test_output_io_error_is_sanitized_and_temporary_files_removed(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td) / "secret-output"
            directory.mkdir()
            result = run("merge", "--trivy", "examples/fuse/trivy-empty.json", "--output", directory)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("secret-output", result.stderr)
            self.assertEqual(list(Path(td).glob(".vulnwrench-fuse-*")), [])
            result = run("merge", "--trivy", "examples/fuse/trivy-empty.json", "--output", directory / "missing" / "out.json")
            self.assertEqual(result.returncode, 2)

    def test_input_size_limit(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "report.json"
            path.write_bytes(b'{"Results":[]}')
            with patch("vulnwrench.fuse.core.MAX_INPUT_BYTES", 10), self.assertRaises(InputError):
                read_report("trivy", path)


if __name__ == "__main__":
    unittest.main()
