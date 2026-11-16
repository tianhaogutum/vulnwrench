"""Opt-in saved-byte checks must not change review semantics or apply artifacts."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import vulnwrench.triage as triage_bridge
from vulnwrench.triage import BridgeError, compile_decisions, preview_renewal, write_compilation
from vulnwrench.triage.compiler import json_bytes
from tests.triage.test_bridge import PARAMS, ROOT
from tests.triage.test_renewal import fixture


def compilation(*, accepted_only=False):
    document = fixture()
    if not accepted_only:
        document["decisions"][0]["status"] = "under_investigation"
    if accepted_only:
        for row in document["decisions"]:
            row["status"] = "accepted_risk"
    return compile_decisions(document, **(PARAMS | {
        "as_of": "2026-11-01", "timestamp": "2026-11-01T12:00:00Z"}))


def cli(report, directory=None, *, prior_format="conversion-report"):
    args = [sys.executable, "-m", "vulnwrench", "triage", "preview-renewal", str(report),
            "--prior-format", prior_format, "--as-of", "2026-11-11", "--expiring-within-days", "7"]
    if directory is not None:
        args += ["--verify-artifacts", str(directory)]
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=60)


class ArtifactVerificationTests(unittest.TestCase):
    def verify(self, report, directory):
        return triage_bridge.verify_report_artifacts(report, directory)

    def assert_rejected(self, report, directory, code="E_ARTIFACT"):
        with self.assertRaises(BridgeError) as error:
            self.verify(report, directory)
        self.assertEqual(error.exception.code, code)
        self.assertNotIn("SECRET", str(error.exception))

    def test_cli_opt_in_verifies_generated_bytes_and_preserves_review(self):
        result = compilation()
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "SECRET-bundle"
            write_compilation(result, bundle)
            report = result.report
            report["decisions"].reverse()
            report_file = Path(tmp) / "report.json"
            report_file.write_bytes(json_bytes(report))
            before = {p: p.read_bytes() for p in bundle.iterdir()}
            verified = cli(report_file, bundle)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            plan = json.loads(verified.stdout)
            self.assertEqual(plan.pop("artifactVerification"), {
                "status": "verified", "artifacts": report["artifacts"]})
            expected = preview_renewal(report, prior_format="conversion-report", as_of="2026-11-11",
                                       expiring_within_days=7)
            self.assertEqual(plan, expected)
            self.assertEqual(plan["decisions"][-1]["prior"]["source"]["decisionIndex"], 0)
            self.assertIn("expired", plan["decisions"][-1]["statuses"])
            self.assertEqual({p: p.read_bytes() for p in bundle.iterdir()}, before)
            self.assertEqual(report_file.read_bytes(), json_bytes(report))

    def test_missing_changed_truncated_and_oversized_each_payload_fail(self):
        result = compilation()
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            write_compilation(result, bundle)
            for name in result.report["artifacts"]:
                path = bundle / name
                original = path.read_bytes()
                for replacement in (None, b"!" + original[1:], original[:-1], original + b"!"):
                    with self.subTest(name=name, replacement=None if replacement is None else len(replacement)):
                        if replacement is None:
                            path.unlink()
                        else:
                            path.write_bytes(replacement)
                        self.assert_rejected(result.report, bundle)
                        path.write_bytes(original)

    def test_omitted_supported_payload_rejected_unrelated_entries_ignored(self):
        result = compilation(accepted_only=True)
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            write_compilation(result, bundle)
            (bundle / "unrelated-SECRET").symlink_to("missing")
            (bundle / "other-directory").mkdir()
            # The explicit report may live elsewhere; no implicit sibling read.
            (bundle / "conversion-report.json").unlink()
            self.assertEqual(self.verify(result.report, bundle), {
                "status": "verified", "artifacts": result.report["artifacts"]})
            extra = bundle / "openvex.json"
            for kind in ("file", "symlink", "directory"):
                if kind == "file":
                    extra.write_bytes(b"SECRET")
                elif kind == "symlink":
                    extra.symlink_to("missing-SECRET")
                else:
                    extra.mkdir()
                self.assert_rejected(result.report, bundle)
                extra.rmdir() if kind == "directory" else extra.unlink()

    def test_symlink_components_payload_links_and_nonregular_files_fail_cli(self):
        result = compilation()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "SECRET-bundle"
            write_compilation(result, bundle)
            report_file = root / "report.json"
            report_file.write_bytes(json_bytes(result.report))
            link = root / "SECRET-link"
            link.symlink_to(bundle, target_is_directory=True)
            bad_directories = [link, link / "child", bundle / ".." / bundle.name,
                               root / "SECRET-missing", report_file]
            for directory in bad_directories:
                failed = cli(report_file, directory)
                self.assertEqual(failed.returncode, 2)
                self.assertEqual(failed.stdout, "")
                self.assertIn("E_ARTIFACT", failed.stderr)
                self.assertNotIn("SECRET", failed.stderr)
            target = bundle / ".trivyignore.yaml"
            saved = root / "saved"
            target.rename(saved)
            for kind in ("symlink", "directory", "fifo"):
                if kind == "symlink":
                    target.symlink_to(saved)  # Matching bytes still unsafe.
                elif kind == "directory":
                    target.mkdir()
                else:
                    os.mkfifo(target)
                failed = cli(report_file, bundle)
                self.assertEqual(failed.returncode, 2, failed.stderr)
                self.assertEqual(failed.stdout, "")
                self.assertIn("E_ARTIFACT", failed.stderr)
                self.assertNotIn("SECRET", failed.stderr)
                self.assertNotIn("Traceback", failed.stderr)
                target.rmdir() if kind == "directory" else target.unlink()

    def test_cli_failures_are_redacted_and_standalone_still_works(self):
        result = compilation(accepted_only=True)
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "SECRET-bundle"
            write_compilation(result, bundle)
            report_file = bundle / "conversion-report.json"
            target = bundle / "osv-scanner.toml"
            original = target.read_bytes()
            if os.geteuid() != 0:
                target.chmod(0)
                try:
                    failed = cli(report_file, bundle)
                    self.assertEqual(failed.returncode, 2)
                    self.assertEqual(failed.stdout, "")
                    self.assertIn("E_ARTIFACT", failed.stderr)
                    self.assertNotIn("SECRET", failed.stderr)
                finally:
                    target.chmod(0o600)
            for replacement in (None, b"SECRET", original + b"SECRET"):
                if replacement is None:
                    target.unlink()
                else:
                    target.write_bytes(replacement)
                failed = cli(report_file, bundle)
                self.assertEqual(failed.returncode, 2)
                self.assertEqual(failed.stdout, "")
                self.assertIn("E_ARTIFACT", failed.stderr)
                self.assertNotIn("SECRET", failed.stderr)
                self.assertNotIn("Traceback", failed.stderr)
                target.write_bytes(original)
            (bundle / "openvex.json").write_bytes(b"SECRET")
            self.assertEqual(cli(report_file).returncode, 0)  # No implicit reads.
            failed = cli(report_file, bundle)
            self.assertEqual(failed.returncode, 2)
            self.assertEqual(failed.stdout, "")
            self.assertIn("E_ARTIFACT", failed.stderr)
            failed = cli(report_file, bundle, prior_format="decisions")
            self.assertEqual(failed.returncode, 2)
            self.assertEqual(failed.stdout, "")
            self.assertIn("E_ARGUMENT", failed.stderr)

    def test_report_validation_precedes_io_and_provenance_limit_remains(self):
        report = compilation().report
        invalid = deepcopy(report)
        invalid["artifacts"]["../SECRET"] = invalid["artifacts"].pop("openvex.json")
        with patch("vulnwrench.triage.io.os.open", side_effect=AssertionError("must validate first")):
            self.assert_rejected(invalid, "SECRET", code="E_REPORT")
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            write_compilation(compilation(), bundle)
            report["source"]["canonicalJsonSha256"] = "a" * 64
            before = deepcopy(report)
            self.assertEqual(self.verify(report, bundle)["status"], "verified")
            self.assertEqual(report, before)
            plan = preview_renewal(report, prior_format="conversion-report", as_of="2026-11-11")
            self.assertEqual(plan["sources"]["priorArchivedSourceCanonicalJsonSha256"], "a" * 64)
            self.assertIn("not authenticated provenance", " ".join(plan["warnings"]))

    def test_permission_read_errors_and_concurrent_changes_fail_closed(self):
        result = compilation()
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            write_compilation(result, bundle)
            real_open, real_read = os.open, os.read
            def denied(path, flags, *args, **kwargs):
                if path == "osv-scanner.toml":
                    raise PermissionError("SECRET")
                return real_open(path, flags, *args, **kwargs)
            with patch("vulnwrench.triage.io.os.open", side_effect=denied):
                self.assert_rejected(result.report, bundle)
            with patch("vulnwrench.triage.io.os.read", side_effect=OSError("SECRET")):
                self.assert_rejected(result.report, bundle)
            touched = False
            def change_after_read(fd, count):
                nonlocal touched
                raw = real_read(fd, count)
                if not touched:
                    touched = True
                    # Same-size replacement while old fd remains open.
                    replacement = bundle / "replacement"
                    replacement.write_bytes(result.files[".trivyignore.yaml"])
                    replacement.replace(bundle / ".trivyignore.yaml")
                return raw
            with patch("vulnwrench.triage.io.os.read", side_effect=change_after_read):
                self.assert_rejected(result.report, bundle)

    def test_streaming_reads_are_bounded_and_size_mismatch_reads_nothing(self):
        document = fixture()
        for row in document["decisions"]:
            row["reason"] = "\U0001f9ea" * 16000
        result = compile_decisions(document, **(PARAMS | {
            "as_of": "2026-11-01", "timestamp": "2026-11-01T12:00:00Z"}))
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            write_compilation(result, bundle)
            real_read = os.read
            requests = []
            def short_reads(fd, count):
                requests.append(count)
                return real_read(fd, min(count, 8191))
            with patch("vulnwrench.triage.io.os.read", side_effect=short_reads):
                self.assertEqual(self.verify(result.report, bundle)["status"], "verified")
            self.assertTrue(requests)
            self.assertLessEqual(max(requests), 65536)
            target = bundle / ".trivyignore.yaml"
            with target.open("ab") as stream:
                stream.truncate(20 * 1024 * 1024)  # Sparse; do not allocate giant input.
            with patch("vulnwrench.triage.io.os.read", side_effect=AssertionError("must check size first")):
                self.assert_rejected(result.report, bundle)
