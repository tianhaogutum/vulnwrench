"""Original input verification binds canonical content and archived compilation."""
from copy import deepcopy
import json
import os
import socket
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import vulnwrench.triage as triage_bridge
from vulnwrench.triage import BridgeError, compile_decisions, preview_renewal, write_compilation
from vulnwrench.triage.compiler import digest, json_bytes
from vulnwrench.triage.model import MAX_INPUT_BYTES
from tests.triage.test_bridge import PARAMS, ROOT
from tests.triage.test_renewal import fixture


ARCHIVED = PARAMS | {"as_of": "2026-11-01", "timestamp": "2026-11-01T12:00:00Z"}


def cli(report, source=None, *, extra=(), timeout=60):
    args = [sys.executable, "-m", "vulnwrench", "triage", "preview-renewal", str(report),
            "--prior-format", "conversion-report", "--as-of", "2026-11-11",
            "--expiring-within-days", "7"]
    if source is not None:
        args += ["--verify-source", str(source)]
    return subprocess.run([*args, *map(str, extra)], cwd=ROOT, capture_output=True,
                          text=True, timeout=timeout)


class SourceVerificationTests(unittest.TestCase):
    def assert_failed(self, result, code):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn(code, result.stderr)
        self.assertNotIn("SECRET", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def assert_rejected(self, report, document, code="E_SOURCE"):
        with self.assertRaises(BridgeError) as error:
            triage_bridge.verify_report_source(report, document)
        self.assertEqual(error.exception.code, code)
        self.assertNotIn("SECRET", str(error.exception))

    def test_cli_verifies_original_and_artifacts_preserving_review_and_indices(self):
        document = fixture()
        document["decisions"][0]["status"] = "under_investigation"
        result = compile_decisions(document, **ARCHIVED)
        report = result.report
        report["decisions"].reverse()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "bundle"
            write_compilation(result, bundle)
            report_file, source_file = root / "report.json", root / "SECRET-source.json"
            report_file.write_bytes(json_bytes(report))
            source_file.write_text(json.dumps(document, sort_keys=False, separators=(",", ":")), encoding="utf-8")
            before = {p: (p.read_bytes(), p.stat().st_mode) for p in [*bundle.iterdir(), report_file, source_file]}
            entries = set(root.iterdir())
            extra = ["--verify-artifacts", bundle, "--current", ROOT / "examples/triage/renewal/current.json"]
            checked = cli(report_file, source_file, extra=extra)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            plan = json.loads(checked.stdout)
            self.assertEqual(plan.pop("sourceVerification"), {
                "status": "verified", "canonicalJsonSha256": digest(json_bytes(document)),
                "decisionIndices": [5, 4, 3, 2, 1, 0]})
            self.assertEqual(plan.pop("artifactVerification"), {"status": "verified", "artifacts": report["artifacts"]})
            self.assertEqual(plan, preview_renewal(report, prior_format="conversion-report",
                as_of="2026-11-11", expiring_within_days=7, current=fixture("current")))
            self.assertIn("expired", plan["decisions"][-1]["statuses"])
            self.assertEqual(plan["decisions"][-1]["prior"]["source"]["archivedSourcePointer"], "/decisions/0")
            self.assertEqual(plan["automaticActions"], [])
            self.assertEqual({p: (p.read_bytes(), p.stat().st_mode) for p in before}, before)
            self.assertEqual(set(root.iterdir()), entries)

    def test_opt_ins_are_independent_and_standalone_is_unchanged(self):
        document = fixture()
        result = compile_decisions(document, **ARCHIVED)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "bundle"
            write_compilation(result, bundle)
            report_file = bundle / "conversion-report.json"
            source_file = root / "original.json"
            source_file.write_bytes(json_bytes(document))
            standalone = cli(report_file)
            artifact_only = cli(report_file, extra=["--verify-artifacts", bundle])
            self.assertEqual(artifact_only.returncode, 0, artifact_only.stderr)
            self.assertNotIn("sourceVerification", json.loads(artifact_only.stdout))
            (bundle / "osv-scanner.toml").unlink()
            source_only = cli(report_file, source_file)
            self.assertEqual(source_only.returncode, 0, source_only.stderr)
            plan = json.loads(source_only.stdout)
            plan.pop("sourceVerification")
            self.assertEqual(plan, json.loads(standalone.stdout))
            self.assertNotIn("artifactVerification", plan)
            self.assertEqual(plan["decisions"][0]["prior"], plan["decisions"][0]["current"])
            self.assert_failed(cli(report_file, source_file, extra=["--verify-artifacts", bundle]), "E_ARTIFACT")
            source_file.unlink()
            self.assertEqual(cli(report_file).stdout, standalone.stdout)
            self.assert_failed(cli(report_file, source_file), "E_IO")
            self.assert_failed(cli(report_file, source_file, extra=["--prior-format", "decisions"]), "E_ARGUMENT")

    def test_canonical_digest_ignores_text_layout_but_not_normalized_defaults(self):
        document = fixture()
        document["decisions"][0]["reason"] = "Synthetic \u00e9vidence"
        report = compile_decisions(document, **ARCHIVED).report
        with tempfile.TemporaryDirectory() as tmp:
            report_file, source = Path(tmp) / "report", Path(tmp) / "source"
            report_file.write_bytes(json_bytes(report))
            for raw in (json.dumps(document, ensure_ascii=True, sort_keys=False),
                        json.dumps(document, ensure_ascii=False, sort_keys=True, indent=4)):
                source.write_text(" \n" + raw + "\t ", encoding="utf-8")
                checked = cli(report_file, source)
                self.assertEqual(checked.returncode, 0, checked.stderr)
                self.assertEqual(json.loads(checked.stdout)["sourceVerification"]["canonicalJsonSha256"],
                                 report["source"]["canonicalJsonSha256"])
            # Semantically equivalent input is not necessarily the archived input.
            variants = [deepcopy(document) for _ in range(3)]
            variants[0]["decisions"][0]["aliases"] = {}
            variants[1].pop("schemaVersion")
            variants[2]["decisions"].reverse()
            for variant in variants:
                source.write_bytes(json_bytes(variant))
                self.assert_failed(cli(report_file, source), "E_SOURCE")
        # Absent schemaVersion is valid v1 when it really was the original.
        document.pop("schemaVersion")
        report = compile_decisions(document, **ARCHIVED).report
        self.assertEqual(triage_bridge.verify_report_source(report, document)["status"], "verified")

    def test_matching_digest_alone_cannot_substitute_archived_content(self):
        document = fixture()
        report = compile_decisions(document, **ARCHIVED).report
        mutations = [
            lambda d: d["decisions"][0].update(owner="SECRET-owner"),
            lambda d: d["decisions"][0].update(sourceRefs=["SECRET-ref"]),
            lambda d: d["decisions"].reverse(),
            lambda d: d["decisions"][0].update(decisionId="SECRET-identity"),
            lambda d: d["decisions"][0].update(reason="SECRET-reason"),
        ]
        for mutate in mutations:
            changed = deepcopy(document)
            mutate(changed)
            forged = deepcopy(report)
            forged["source"]["canonicalJsonSha256"] = digest(json_bytes(changed))
            # Standalone remains valid: source content is genuinely an extra check.
            preview_renewal(forged, prior_format="conversion-report", as_of="2026-11-11")
            self.assert_rejected(forged, changed)
        before = deepcopy((document, report))
        triage_bridge.verify_report_source(report, document)
        self.assertEqual((document, report), before)

    def test_strict_original_policy_is_checked_at_archived_date(self):
        document = fixture()
        report = compile_decisions(document, **ARCHIVED).report
        mutations = [
            lambda d: d["decisions"][0].pop("owner"),
            lambda d: d["decisions"][0].update(owner=None),
            lambda d: d["decisions"][0].update(status="not_affected"),
            lambda d: d["decisions"][0].update(status="affected"),
            lambda d: d["decisions"][0].update(expiresOn="2026-11-01"),
            lambda d: d["decisions"][0].update(package="SECRET-invalid"),
            lambda d: d["decisions"].append(deepcopy(d["decisions"][0])),
            lambda d: d.update(schemaVersion=2),
        ]
        for mutate in mutations:
            changed = deepcopy(document)
            mutate(changed)
            retargeted = deepcopy(report)
            retargeted["source"]["canonicalJsonSha256"] = digest(json_bytes(changed))
            self.assert_rejected(retargeted, changed)
        # Expired on review date is still valid at compilation date.
        self.assertEqual(triage_bridge.verify_report_source(report, document)["status"], "verified")

    def test_invalid_report_precedes_original_read_and_cannot_be_bypassed(self):
        document = fixture()
        report = compile_decisions(document, **ARCHIVED).report
        for mutate in (lambda r: r.update(toolVersion="SECRET-future"),
                       lambda r: r["counts"].update(decisions=1),
                       lambda r: r["decisions"][0].update(index=True),
                       lambda r: r["artifacts"]["osv-scanner.toml"].update(sha256="a" * 64)):
            invalid = deepcopy(report)
            mutate(invalid)
            self.assert_rejected(invalid, document, "E_REPORT")
            with tempfile.TemporaryDirectory() as tmp:
                report_file = Path(tmp) / "report.json"
                report_file.write_bytes(json_bytes(invalid))
                self.assert_failed(cli(report_file, Path(tmp) / "SECRET-missing"), "E_REPORT")

    def test_cli_input_byte_json_format_and_policy_boundaries(self):
        document = fixture()
        report = compile_decisions(document, **ARCHIVED).report
        with tempfile.TemporaryDirectory() as tmp:
            source, report_file = Path(tmp) / "SECRET-source", Path(tmp) / "report"
            report_file.write_bytes(json_bytes(report))
            raw = json_bytes(document)
            source.write_bytes(raw + b" " * (MAX_INPUT_BYTES - len(raw)))
            self.assertEqual(cli(report_file, source).returncode, 0)
            cases = [
                (raw + b" " * (MAX_INPUT_BYTES + 1 - len(raw)), "E_INPUT"),
                (b'{"decisions":[],"decisions":[],"SECRET":0}', "E_INPUT"),
                (b'{"decisions":[{"owner":"SECRET","owner":"SECRET"}]}', "E_INPUT"),
                (b'{"decisions":NaN}', "E_INPUT"),
                (b'{"decisions":Infinity}', "E_INPUT"),
                (b'\xffSECRET', "E_INPUT"),
                (b'[' * 100000 + b'0' + b']' * 100000, "E_INPUT"),
                (b'---\ndecisions: SECRET', "E_INPUT"),
                (b'{"schemaVersion":2,"decisions":[]}', "E_SOURCE"),
                (b'{"decisions":[' + b'null,' * 10000 + b'null]}', "E_SOURCE"),
                (b'{"decisions":[]}', "E_SOURCE"),
                (b'null', "E_SOURCE"),
                (json_bytes(report), "E_SOURCE"),
                (json_bytes(fixture("current")), "E_SOURCE"),
            ]
            invalid = deepcopy(document)
            invalid["decisions"][0].pop("owner")
            cases.append((json_bytes(invalid), "E_SOURCE"))
            wrong = deepcopy(document)
            wrong["decisions"][0]["owner"] = "SECRET-owner"
            cases.append((json_bytes(wrong), "E_SOURCE"))
            for raw, code in cases:
                with self.subTest(code=code, length=len(raw)):
                    source.write_bytes(raw)
                    self.assert_failed(cli(report_file, source), code)
            source.unlink()
            self.assert_failed(cli(report_file, source), "E_IO")
            source.mkdir()
            self.assert_failed(cli(report_file, source), "E_IO")
            source.rmdir()
            if os.geteuid() != 0:
                source.write_bytes(json_bytes(document))
                source.chmod(0)
                try:
                    self.assert_failed(cli(report_file, source), "E_IO")
                finally:
                    source.chmod(0o600)

    def test_cli_refuses_nonregular_original_without_waiting_for_fifo(self):
        report = compile_decisions(fixture(), **ARCHIVED).report
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_file = root / "report.json"
            report_file.write_bytes(json_bytes(report))
            fifo = root / "SECRET-fifo"
            os.mkfifo(fifo)
            fifo_link = root / "SECRET-fifo-link"
            fifo_link.symlink_to(fifo)
            directory = root / "SECRET-directory"
            directory.mkdir()
            dangling = root / "SECRET-dangling"
            dangling.symlink_to(root / "SECRET-missing")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                socket_path = root / "SECRET-socket"
                sock.bind(str(socket_path))
                for source in (fifo, fifo_link, directory, socket_path, Path(os.devnull), dangling):
                    with self.subTest(kind=source.name):
                        try:
                            result = cli(report_file, source, timeout=60)
                        except subprocess.TimeoutExpired:
                            self.fail("original source open/read blocked on a nonregular file")
                        self.assert_failed(result, "E_IO")
            # A peer preventing EOF must not make the FIFO a supported source.
            peer = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
            try:
                self.assert_failed(cli(report_file, fifo, timeout=60), "E_IO")
            finally:
                os.close(peer)
            self.assertEqual(report_file.read_bytes(), json_bytes(report))
            self.assertTrue(fifo.is_fifo())

    def test_source_regular_symlinks_preserve_verified_plan(self):
        document = fixture()
        report = compile_decisions(document, **ARCHIVED).report
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            saved = root / "saved"
            saved.mkdir()
            source = saved / "original.json"
            source.write_bytes(json_bytes(document))
            report_file = root / "report.json"
            report_file.write_bytes(json_bytes(report))
            file_link = root / "source-link"
            file_link.symlink_to(source)
            parent_link = root / "parent-link"
            parent_link.symlink_to(saved, target_is_directory=True)
            before = {p: (p.read_bytes(), p.stat().st_mode) for p in (source, report_file)}
            expected = cli(report_file, source)
            self.assertEqual(expected.returncode, 0, expected.stderr)
            for path in (file_link, parent_link / source.name):
                verified = cli(report_file, path)
                self.assertEqual(verified.returncode, 0, verified.stderr)
                self.assertEqual(verified.stdout, expected.stdout)
            self.assertEqual({p: (p.read_bytes(), p.stat().st_mode) for p in before}, before)
            self.assertTrue(file_link.is_symlink())
            self.assertTrue(parent_link.is_symlink())

    def test_regular_reader_closes_descriptors_on_success_and_refusals(self):
        real_open = os.open
        opened = []

        def capture_open(path, flags):
            self.assertTrue(flags & os.O_NONBLOCK)
            fd = real_open(path, flags)
            opened.append(fd)
            return fd

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.json"
            source.write_bytes(b'{}')
            fifo = Path(tmp) / "fifo"
            os.mkfifo(fifo)
            with patch("vulnwrench.triage.io.os.open", side_effect=capture_open):
                self.assertEqual(triage_bridge.load_document(source, regular_only=True), {})
                with self.assertRaises(BridgeError) as caught:
                    triage_bridge.load_document(fifo, regular_only=True)
                self.assertEqual(caught.exception.code, "E_IO")
                source.write_bytes(b'{SECRET')
                with self.assertRaises(BridgeError) as caught:
                    triage_bridge.load_document(source, regular_only=True)
                self.assertEqual(caught.exception.code, "E_INPUT")
                with patch("vulnwrench.triage.io.os.fstat", side_effect=OSError("SECRET")):
                    with self.assertRaises(BridgeError) as caught:
                        triage_bridge.load_document(source, regular_only=True)
                    self.assertEqual(caught.exception.code, "E_IO")
                    self.assertNotIn("SECRET", str(caught.exception))
            self.assertEqual(len(opened), 4)
            for fd in opened:
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_all_vex_statuses_normalize_indices_without_inventing_provenance(self):
        document = triage_bridge.load_document(ROOT / "examples/triage/mixed-decisions.json")
        for i, row in enumerate(document["decisions"]):
            row["decisionId"] = f"original-{i}"
        # Input ID/alias order normalizes only during compilation, not hashing.
        document["decisions"][0]["ids"] += ["SYNTHETIC-Z", "SYNTHETIC-A"]
        report = compile_decisions(document, **PARAMS).report
        report["decisions"] = report["decisions"][2:] + report["decisions"][:2]
        before = deepcopy((document, report))
        self.assertEqual(triage_bridge.verify_report_source(report, document), {
            "status": "verified", "canonicalJsonSha256": digest(json_bytes(document)),
            "decisionIndices": [2, 3, 4, 0, 1]})
        self.assertEqual((document, report), before)
