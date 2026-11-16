"""Native import opts into regular-file reads without changing library defaults."""
import os
import socket
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import vulnwrench.triage as triage_bridge
from vulnwrench.triage.compiler import json_bytes
from vulnwrench.triage.model import MAX_INPUT_BYTES

from tests.triage.test_bridge import ROOT


class ImportInputTests(unittest.TestCase):
    def cli(self, source, *, timeout=60):
        command = [sys.executable, "-m", "vulnwrench", "triage", "import-trivy", str(source)]
        with subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            try:
                stdout, stderr = child.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                child.kill()
                stdout, stderr = child.communicate()
                self.fail(f"import input blocked; killed/reaped pid={child.pid}, "
                          f"exit={child.returncode}, stdout={stdout!r}, stderr={stderr!r}")
            return subprocess.CompletedProcess(command, child.returncode, stdout, stderr)

    def assert_failed(self, result, code=b"E_IO"):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertIn(code, result.stderr)
        self.assertNotIn(b"SECRET", result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)

    def test_fifo_refused_with_or_without_held_peer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fifo = root / "SECRET-fifo"
            os.mkfifo(fifo)
            before = fifo.stat()
            for held_peer in (False, True):
                peer = os.open(fifo, os.O_RDWR | os.O_NONBLOCK) if held_peer else None
                try:
                    with self.subTest(held_peer=held_peer):
                        self.assert_failed(self.cli(fifo, timeout=60))
                finally:
                    if peer is not None:
                        os.close(peer)
            self.assertEqual(list(root.iterdir()), [fifo])
            self.assertEqual((fifo.stat().st_ino, fifo.stat().st_mode, fifo.stat().st_mtime_ns),
                             (before.st_ino, before.st_mode, before.st_mtime_ns))

    def test_other_nonregular_and_unreadable_inputs(self):
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
            paths = [link, dangling, socket_path, root, Path(os.devnull), root / "SECRET-missing"]
            try:
                if os.geteuid() != 0:
                    paths.append(unreadable)
                for source in paths:
                    with self.subTest(source=source.name):
                        self.assert_failed(self.cli(source))
                self.assertEqual(set(root.iterdir()), entries)
                self.assertEqual(unreadable.stat().st_mode & 0o777, 0)
            finally:
                unreadable.chmod(0o600)

    def test_regular_final_and_ancestor_symlinks_preserve_exact_drafts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            saved = root / "saved"
            saved.mkdir()
            parent = root / "parent"
            parent.symlink_to(saved, target_is_directory=True)
            fixtures = ROOT / "examples/triage/import-trivy"
            for name in ("native", "supported", "unsupported", "flow"):
                raw = ((fixtures / f"{name}.trivyignore.yaml").read_bytes() if name != "flow"
                       else b'{"vulnerabilities":[{"id":"CVE-1","purls":["pkg:npm/demo@1"]}]}')
                expected = json_bytes(triage_bridge.import_trivy_ignore(raw))
                if name == "native":
                    self.assertEqual(expected, (fixtures / "expected-draft.json").read_bytes())
                source = saved / name
                source.write_bytes(raw)
                link = root / name
                link.symlink_to(source)
                entries = set(root.iterdir())
                before = source.stat()
                for path in (source, link, parent / name):
                    with self.subTest(name=name, path=path):
                        result = self.cli(path)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stderr, b"")
                        self.assertEqual(result.stdout, expected)
                self.assertEqual(set(root.iterdir()), entries)
                self.assertEqual(source.read_bytes(), raw)
                self.assertEqual((source.stat().st_mode, source.stat().st_mtime_ns),
                                 (before.st_mode, before.st_mtime_ns))
                self.assertTrue(link.is_symlink())
            self.assertTrue(parent.is_symlink())

    def test_native_byte_syntax_and_record_bounds_remain_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "SECRET-native"
            raw = b'{"vulnerabilities": [{"id": "CVE-1"}]}'
            exact = raw + b" " * (MAX_INPUT_BYTES - len(raw))
            source.write_bytes(exact)
            result = self.cli(source)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, json_bytes(triage_bridge.import_trivy_ignore(exact)))
            invalid = [exact + b" ", b'\xffSECRET',
                       b'{"SECRET":[],"SECRET":[]}', b'{"SECRET":[NaN]}',
                       b'{"SECRET":[Infinity]}', b'{"SECRET":' + b'[' * 10000 + b'0' + b']' * 10000 + b'}',
                       b'vulnerabilities:\n  - id: &SECRET CVE-1\n',
                       json_bytes({"vulnerabilities": [{"id": "CVE-1"}] * 10001}),
                       json_bytes({"vulnerabilities": [{"id": "CVE-1", "purls": ["pkg:npm/demo@1"] * 10001}]})]
            for data in invalid:
                with self.subTest(size=len(data), prefix=data[:60]):
                    source.write_bytes(data)
                    self.assert_failed(self.cli(source), b"E_IMPORT")
            self.assertEqual(list(Path(tmp).iterdir()), [source])

    def test_library_default_and_explicit_reader_policy(self):
        source = Path("SECRET-source")
        raw = b'{"vulnerabilities": []}'
        expected = triage_bridge.import_trivy_ignore(raw)
        with patch("vulnwrench.triage.io._read_input", return_value=raw) as read:
            self.assertEqual(triage_bridge.load_trivy_ignore(source), expected)
            read.assert_called_once_with(source, regular_only=False)
            read.reset_mock()
            self.assertEqual(triage_bridge.load_trivy_ignore(source, regular_only=True), expected)
            read.assert_called_once_with(source, regular_only=True)
