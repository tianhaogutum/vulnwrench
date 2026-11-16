"""The unsupported gate changes status only after the complete native draft is flushed."""
from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from vulnwrench.triage import import_trivy_ignore
from vulnwrench.triage.cli import main
from vulnwrench.triage.compiler import digest, json_bytes
from vulnwrench.triage.model import MAX_INPUT_BYTES
from tests.triage.test_bridge import ROOT
from tests.triage.test_import_trivy import FIXTURES, native


class ImportGateTests(unittest.TestCase):
    def cli(self, source, *extra):
        return subprocess.run([sys.executable, "-m", "vulnwrench", "triage", "import-trivy", str(source), *extra],
                              cwd=ROOT, capture_output=True, timeout=60)

    def assert_modes(self, source, expected):
        expected_bytes = json_bytes(expected)
        for flags in ((), ("--fail-on-unsupported",)):
            with self.subTest(flags=flags):
                result = self.cli(source, *flags)
                self.assertEqual(result.returncode, int(bool(flags) and expected["counts"]["unsupported"] != 0),
                                 result.stderr)
                self.assertEqual(result.stdout, expected_bytes)
                self.assertEqual(result.stderr, b"")
        self.assertEqual(expected["mode"], "review_only")
        self.assertEqual(expected["automaticActions"], [])
        for record, review in zip(expected["decisionDocument"]["decisions"], expected["reviews"]):
            self.assertIsNone(record["owner"])
            self.assertIsNone(record["status"])
            self.assertTrue(review["reviewRequired"])

    def assert_invalid(self, source, code, *extra):
        for flags in ((), ("--fail-on-unsupported",)):
            result = self.cli(source, *extra, *flags)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stdout, b"")
            self.assertIn(code.encode(), result.stderr)
            self.assertNotIn(b"SECRET", result.stderr)
            self.assertNotIn(b"Traceback", result.stderr)

    def test_supported_mixed_all_unsupported_and_empty_keep_exact_bytes(self):
        supported = native()
        mixed = {"vulnerabilities": [supported["vulnerabilities"][0], {"id": "CVE-2", "paths": []}]}
        cases = [(name, (FIXTURES / f"{name}.trivyignore.yaml").read_bytes())
                 for name in ("native", "supported", "unsupported")]
        cases += [("flow-supported", json_bytes(supported)), ("flow-mixed", json_bytes(mixed)),
                  ("flow-unsupported", json_bytes({"vulnerabilities": [{"id": "CVE-2", "paths": []}]})),
                  ("empty", b'{"vulnerabilities": []}')]
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "native"
            for name, raw in cases:
                with self.subTest(name=name):
                    source.write_bytes(raw)
                    before = source.stat()
                    expected = import_trivy_ignore(raw)
                    self.assertEqual(expected["source"]["rawSha256"], digest(raw))
                    if name == "native":
                        self.assertEqual(json_bytes(expected), (FIXTURES / "expected-draft.json").read_bytes())
                    if name == "flow-mixed":
                        self.assertEqual(expected["counts"], {"nativeEntries": 2, "draftDecisions": 1, "unsupported": 1})
                        self.assertEqual(expected["reviews"][0]["sourcePointer"], "/vulnerabilities/0")
                        self.assertEqual(expected["unsupported"][0]["pointer"], "/vulnerabilities/1/paths")
                    self.assert_modes(source, expected)
                    self.assertEqual(source.read_bytes(), raw)
                    self.assertEqual((source.stat().st_mode, source.stat().st_mtime_ns),
                                     (before.st_mode, before.st_mtime_ns))
                    self.assertEqual(list(Path(tmp).iterdir()), [source])

    def test_existing_findings_count_including_sections_not_native_entries(self):
        cases = [({"vulnerabilities": [{"id": "CVE-1", "paths": []}]}, "unsupported_paths"),
                 ({"vulnerabilities": [{"id": "CVE-1", "SECRET": "value"}]}, "unsupported_field"),
                 ({"vulnerabilities": [{"id": "CVE-1", "purls": ["pkg:npm/demo@1", "pkg:npm/demo"]}]}, "unsupported_purl"),
                 ({"vulnerabilities": [{"id": "CVE-1", "expired_at": "SECRET"}]}, "invalid_entry"),
                 ({"sec~/tion": []}, "unsupported_section"),
                 ({"sec~/tion": [{}, {}]}, "unsupported_section")]
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            for document, code in cases:
                with self.subTest(document=document):
                    raw = json_bytes(document)
                    source.write_bytes(raw)
                    expected = import_trivy_ignore(raw)
                    self.assertEqual(expected["counts"]["unsupported"], 1)
                    self.assertEqual(expected["counts"]["draftDecisions"], 0)
                    self.assertEqual(expected["unsupported"][0]["code"], code)
                    if "sec~/tion" in document:
                        self.assertEqual(expected["unsupported"][0]["pointer"], "/sec~0~1tion")
                    self.assert_modes(source, expected)

    def test_regular_final_and_ancestor_symlinks_in_both_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            saved = root / "saved"
            saved.mkdir()
            ancestor = root / "ancestor"
            ancestor.symlink_to(saved, target_is_directory=True)
            source = saved / "native"
            link = root / "final"
            link.symlink_to(source)
            for name in ("native", "unsupported"):
                raw = (FIXTURES / f"{name}.trivyignore.yaml").read_bytes()
                source.write_bytes(raw)
                expected = import_trivy_ignore(raw)
                entries = set(root.rglob("*"))
                for path in (source, link, ancestor / "native"):
                    self.assert_modes(path, expected)
                self.assertEqual(source.read_bytes(), raw)
                self.assertEqual(set(root.rglob("*")), entries)
                self.assertTrue(link.is_symlink())
                self.assertTrue(ancestor.is_symlink())

    def test_full_validation_precedes_gate_with_all_native_bounds(self):
        raw = b'{"vulnerabilities": [{"id": "CVE-1"}]}'
        exact = raw + b" " * (MAX_INPUT_BYTES - len(raw))
        # First finding cannot bypass a later expansion bound or malformed row.
        blocked = {"id": "CVE-2", "paths": []}
        invalid = [exact + b" ", b'\xffSECRET', b'{"SECRET":[],"SECRET":[]}',
                   b'{"SECRET":[NaN]}', b'{"SECRET":[Infinity]}',
                   b'{"SECRET":' + b'[' * 10000 + b'0' + b']' * 10000 + b'}',
                   b'vulnerabilities:\n  - id: &SECRET CVE-1\n',
                   b'{"vulnerabilities":[{"id":"CVE-2","paths":[]}, "SECRET"]}',
                   json_bytes({"vulnerabilities": [blocked] + [{"id": "CVE-1"}] * 10000}),
                   json_bytes({"vulnerabilities": [blocked, {"id": "CVE-1", "purls": ["pkg:npm/demo@1"] * 10001}]})]
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "SECRET-native"
            source.write_bytes(exact)
            self.assert_modes(source, import_trivy_ignore(exact))
            for data in invalid:
                with self.subTest(size=len(data), prefix=data[:60]):
                    source.write_bytes(data)
                    self.assert_invalid(source, "E_IMPORT")
            self.assertEqual(list(Path(tmp).iterdir()), [source])

    def test_nonregular_and_unreadable_refusals_precede_gate(self):
        with tempfile.TemporaryDirectory() as tmp, socket.socket(socket.AF_UNIX) as sock:
            root = Path(tmp)
            fifo = root / "SECRET-fifo"
            os.mkfifo(fifo)
            link = root / "SECRET-fifo-link"
            link.symlink_to(fifo)
            dangling = root / "SECRET-dangling"
            dangling.symlink_to(root / "SECRET-missing")
            socket_path = root / "SECRET-socket"
            sock.bind(str(socket_path))
            unreadable = root / "SECRET-unreadable"
            unreadable.write_bytes(b'{"vulnerabilities": []}')
            unreadable.chmod(0)
            entries = set(root.iterdir())
            try:
                for held in (False, True):
                    peer = os.open(fifo, os.O_RDWR | os.O_NONBLOCK) if held else None
                    try:
                        for path in (fifo, link):
                            self.assert_invalid(path, "E_IO")
                    finally:
                        if peer is not None:
                            os.close(peer)
                for path in (dangling, socket_path, root, Path(os.devnull), root / "SECRET-missing"):
                    self.assert_invalid(path, "E_IO")
                if os.geteuid() != 0:
                    self.assert_invalid(unreadable, "E_IO")
                self.assertEqual(set(root.iterdir()), entries)
                self.assertEqual(unreadable.stat().st_mode & 0o777, 0)
            finally:
                unreadable.chmod(0o600)

    def test_invalid_arguments_remain_redacted(self):
        for extra in (("--SECRET",), ("--fail-on-unsupported=SECRET",), ("SECRET-extra",)):
            self.assert_invalid("SECRET-nonexistent", "E_ARGUMENT", *extra)

    def test_write_and_flush_finish_before_count_and_errors_override_gate(self):
        for name in ("native", "unsupported"):
            source = FIXTURES / f"{name}.trivyignore.yaml"
            expected = import_trivy_ignore(source.read_bytes())
            for flags in ([], ["--fail-on-unsupported"]):
                for failure in (None, "write", "flush"):
                    with self.subTest(name=name, flags=flags, failure=failure):
                        events = []
                        class Output(io.StringIO):
                            def write(self, value):
                                events.append("write")
                                if failure == "write":
                                    raise BrokenPipeError("synthetic write failure")
                                return super().write(value)
                            def flush(self):
                                events.append("flush")
                                if failure == "flush":
                                    raise OSError("synthetic flush failure")
                        class Draft(dict):
                            def __getitem__(self, key):
                                if key == "counts":
                                    self_test.assertEqual(events, ["write", "flush"])
                                    events.append("count")
                                return super().__getitem__(key)
                        self_test = self
                        output, errors = Output(), io.StringIO()
                        with patch("vulnwrench.triage.cli.load_trivy_ignore", return_value=Draft(expected)) as load:
                            with redirect_stdout(output), redirect_stderr(errors):
                                if failure:
                                    with self.assertRaises(OSError):
                                        main(["import-trivy", str(source), *flags])
                                else:
                                    code = main(["import-trivy", str(source), *flags])
                                    self.assertEqual(code, int(bool(flags) and expected["counts"]["unsupported"] != 0))
                            load.assert_called_once_with(str(source), regular_only=True)
                        self.assertEqual(events, (["write"] if failure == "write" else ["write", "flush"])
                                         + (["count"] if flags and failure is None else []))
                        self.assertEqual(errors.getvalue(), "")
                        if failure != "write":
                            self.assertEqual(output.getvalue().encode(), json_bytes(expected))
