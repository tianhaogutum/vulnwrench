"""Compile refuses nonregular inputs before any output publication."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

from vulnwrench.triage.compiler import json_bytes
from vulnwrench.triage.model import MAX_INPUT_BYTES
from tests.triage import test_bridge as bridge_tests
from tests.triage.test_bridge import ROOT, fixture


class CompileInputTests(unittest.TestCase):
    def cli(self, source, output, *, extra=(), scope=True, timeout=60):
        args = bridge_tests.CLITests().args(source, output)
        if scope:
            args.append("--allow-scope-loss")
        args.extend(extra)
        command = [sys.executable, "-m", "vulnwrench", "triage", *args]
        with subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True) as child:
            try:
                stdout, stderr = child.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                child.kill()
                stdout, stderr = child.communicate()
                self.fail(f"compile input blocked; killed/reaped pid={child.pid}, "
                          f"exit={child.returncode}, stdout={stdout!r}, stderr={stderr!r}")
            return subprocess.CompletedProcess(command, child.returncode, stdout, stderr)

    def assert_failed(self, result, code, output):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn(code, result.stderr)
        self.assertNotIn("SECRET", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(output.exists())

    def test_fifo_refused_with_or_without_held_peer(self):
        with tempfile.TemporaryDirectory() as tmp:
            fifo, output = Path(tmp) / "SECRET-fifo", Path(tmp) / "out"
            os.mkfifo(fifo)
            for held_peer in (False, True):
                peer = os.open(fifo, os.O_RDWR | os.O_NONBLOCK) if held_peer else None
                try:
                    with self.subTest(held_peer=held_peer):
                        self.assert_failed(self.cli(fifo, output, timeout=60), "E_IO", output)
                finally:
                    if peer is not None:
                        os.close(peer)
            self.assertTrue(fifo.is_fifo())

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
            unreadable.write_bytes(json_bytes(fixture()))
            unreadable.chmod(0)
            paths = [link, dangling, socket_path, root, Path(os.devnull), root / "SECRET-missing"]
            try:
                if os.geteuid() != 0:
                    paths.append(unreadable)
                for source in paths:
                    with self.subTest(source=source.name):
                        output = root / "out"
                        self.assert_failed(self.cli(source, output), "E_IO", output)
            finally:
                unreadable.chmod(0o600)

    def test_regular_final_and_ancestor_symlinks_preserve_exact_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            saved = root / "saved"
            saved.mkdir()
            parent = root / "parent"
            parent.symlink_to(saved, target_is_directory=True)
            for name in ("decisions", "mixed-decisions"):
                source = saved / f"{name}.json"
                raw = (ROOT / f"examples/triage/{name}.json").read_bytes()
                source.write_bytes(raw)
                link = root / source.name
                link.symlink_to(source)
                before = source.stat()
                expected = {p.name: p.read_bytes() for p in (ROOT / f"examples/triage/expected/{name}").iterdir()}
                stdout = None
                for index, path in enumerate((source, link, parent / source.name)):
                    output = root / f"{name}-{index}"
                    result = self.cli(path, output)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, "")
                    self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()}, expected)
                    if stdout is not None:
                        self.assertEqual(result.stdout, stdout)
                    stdout = result.stdout
                self.assertEqual(source.read_bytes(), raw)
                self.assertEqual((source.stat().st_mode, source.stat().st_mtime_ns),
                                 (before.st_mode, before.st_mtime_ns))
                self.assertTrue(link.is_symlink())
            self.assertTrue(parent.is_symlink())

    def test_bounded_strict_json_and_policy_fail_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, output = Path(tmp) / "SECRET-input", Path(tmp) / "out"
            raw = json_bytes(fixture())
            source.write_bytes(raw + b" " * (MAX_INPUT_BYTES - len(raw)))
            accepted = self.cli(source, output)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            # Use a fresh output to distinguish input failure from create-only refusal.
            output = Path(tmp) / "absent"
            invalid = [(raw + b" " * (MAX_INPUT_BYTES + 1 - len(raw)), "E_INPUT"),
                       (b'{"SECRET":0,"SECRET":1}', "E_INPUT"),
                       (b'{"SECRET":NaN}', "E_INPUT"), (b'{"SECRET":Infinity}', "E_INPUT"),
                       (b'\xffSECRET', "E_INPUT"),
                       (b'[' * 100000 + b'0' + b']' * 100000, "E_INPUT")]
            for field, value, code in (("owner", None, "E_INPUT"), ("status", "SECRET", "E_STATUS"),
                                       ("expiresOn", "2026-11-11", "E_EXPIRED")):
                document = fixture()
                document["decisions"][0][field] = value
                invalid.append((json_bytes(document), code))
            for data, code in invalid:
                with self.subTest(code=code, size=len(data)):
                    source.write_bytes(data)
                    self.assert_failed(self.cli(source, output), code, output)
            source.write_bytes(raw)
            self.assert_failed(self.cli(source, output, scope=False), "E_SCOPE_LOSS", output)
            self.assert_failed(self.cli(source, output, extra=("--as-of", "SECRET-date")), "E_DATE", output)
            self.assert_failed(self.cli(source, output, extra=("--timestamp", "2026-11-12T12:00:00Z")),
                               "E_DATE", output)

    def test_input_then_semantics_then_create_only_writer_precedence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, output = root / "SECRET-input", root / "absent-parent/out"
            os.mkfifo(source)
            self.assert_failed(self.cli(source, output, extra=("--as-of", "SECRET-date")), "E_IO", output)
            source.unlink()
            source.write_bytes(b'{SECRET')
            self.assert_failed(self.cli(source, output, extra=("--as-of", "SECRET-date")), "E_INPUT", output)
            source.write_bytes(json_bytes(fixture()))
            self.assert_failed(self.cli(source, output, scope=False), "E_SCOPE_LOSS", output)
            self.assert_failed(self.cli(source, output), "E_OUTPUT", output)
            existing = root / "existing"
            existing.mkdir()
            marker = existing / "marker"
            marker.write_bytes(b"untouched")
            result = self.cli(source, existing)
            self.assertEqual(result.returncode, 2)
            self.assertIn("E_OUTPUT", result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(list(existing.iterdir()), [marker])
            self.assertEqual(marker.read_bytes(), b"untouched")
