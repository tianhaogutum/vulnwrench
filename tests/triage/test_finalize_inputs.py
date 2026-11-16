"""Finalization opts all three inputs into the existing regular descriptor policy."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import vulnwrench.triage as triage_bridge
from vulnwrench.triage.compiler import json_bytes
from vulnwrench.triage.model import MAX_INPUT_BYTES
from tests.triage.test_bridge import ROOT
from tests.triage.test_finalize_import import inputs
from tests.triage.test_finalize_exclusions import exclusion_inputs


class FinalizeInputTests(unittest.TestCase):
    def cli(self, paths, *, as_of="2026-11-11", timeout=60):
        command = [sys.executable, "-m", "vulnwrench", "triage", "finalize-import", str(paths[0]),
                   "--source", str(paths[1]), "--review", str(paths[2]), "--as-of", as_of]
        with subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            try:
                stdout, stderr = child.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                child.kill()
                stdout, stderr = child.communicate()
                self.fail(f"finalize input blocked; killed/reaped pid={child.pid}, "
                          f"exit={child.returncode}, stdout={stdout!r}, stderr={stderr!r}")
            return subprocess.CompletedProcess(command, child.returncode, stdout, stderr)

    def save(self, root, data=None):
        raw, draft, review = inputs() if data is None else data
        paths = [root / name for name in ("draft.json", "source.yaml", "review.json")]
        for path, content in zip(paths, (json_bytes(draft), raw, json_bytes(review))):
            path.write_bytes(content)
        return paths, json_bytes(triage_bridge.finalize_import(draft, source=raw, review=review,
                                                              as_of="2026-11-11"))

    def snapshot(self, root):
        result = {}
        for path in root.rglob("*"):
            info = path.lstat()
            result[str(path)] = (info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns,
                                 info.st_ctime_ns, path.read_bytes() if path.is_file() and not path.is_symlink()
                                 and info.st_mode & 0o444 else None)
        return result

    def assert_failed(self, result, code=b"E_IO"):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertIn(code, result.stderr)
        self.assertNotIn(b"SECRET", result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)
        self.assertNotIn(str(ROOT).encode(), result.stderr)

    def test_fifo_each_position_with_or_without_held_peer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths, _ = self.save(root)
            fifo = root / "SECRET-fifo"
            os.mkfifo(fifo)
            before = self.snapshot(root)
            for index in range(3):
                for held_peer in (False, True):
                    peer = os.open(fifo, os.O_RDWR | os.O_NONBLOCK) if held_peer else None
                    try:
                        with self.subTest(position=index, held_peer=held_peer):
                            changed = paths.copy()
                            changed[index] = fifo
                            self.assert_failed(self.cli(changed, timeout=60))
                    finally:
                        if peer is not None:
                            os.close(peer)
            self.assertEqual(self.snapshot(root), before)

    def test_other_nonregular_and_unreadable_each_position(self):
        with tempfile.TemporaryDirectory() as tmp, socket.socket(socket.AF_UNIX) as sock:
            root = Path(tmp)
            paths, _ = self.save(root)
            fifo = root / "SECRET-fifo"
            os.mkfifo(fifo)
            link = root / "SECRET-fifo-link"
            link.symlink_to(fifo)
            dangling = root / "SECRET-dangling"
            dangling.symlink_to(root / "SECRET-missing")
            socket_path = root / "SECRET-socket"
            sock.bind(str(socket_path))
            unreadable = root / "SECRET-unreadable"
            unreadable.write_bytes(b"SECRET")
            unreadable.chmod(0)
            before = self.snapshot(root)
            targets = [link, dangling, socket_path, root, Path(os.devnull), root / "SECRET-missing"]
            if os.geteuid() != 0:
                targets.append(unreadable)
            try:
                for index in range(3):
                    for target in targets:
                        with self.subTest(position=index, target=target.name):
                            changed = paths.copy()
                            changed[index] = target
                            self.assert_failed(self.cli(changed))
                self.assertEqual(self.snapshot(root), before)
            finally:
                unreadable.chmod(0o600)

    def test_regular_final_and_ancestor_symlinks_preserve_exact_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            saved = root / "saved"
            saved.mkdir()
            parent = root / "parent"
            parent.symlink_to(saved, target_is_directory=True)
            # Include filtering of draft 0; retained sourceRefs must still name original index 1.
            for data in (inputs(), exclusion_inputs()):
                paths, expected = self.save(saved, data)
                for path in paths:
                    link = root / path.name
                    if not link.is_symlink():
                        link.symlink_to(path)
                variants = [paths]
                for index, path in enumerate(paths):
                    for link in (root / path.name, parent / path.name):
                        changed = paths.copy()
                        changed[index] = link
                        variants.append(changed)
                variants.append([root / path.name for path in paths])
                before = self.snapshot(root)
                for variant in variants:
                    with self.subTest(excluded="decisionDispositions" in data[2], paths=variant):
                        result = self.cli(variant)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stderr, b"")
                        self.assertEqual(result.stdout, expected)
                self.assertEqual(self.snapshot(root), before)

    def test_exact_size_limits_each_position_and_source_byte_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths, expected = self.save(root)
            for index in (0, 2):
                original = paths[index].read_bytes()
                exact = original + b" " * (MAX_INPUT_BYTES - len(original))
                paths[index].write_bytes(exact)
                result = self.cli(paths)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)
                paths[index].write_bytes(exact + b" ")
                self.assert_failed(self.cli(paths), b"E_INPUT")
                paths[index].write_bytes(original)
            raw, _, review = inputs()
            exact = raw + b" " * (MAX_INPUT_BYTES - len(raw))
            paths, expected = self.save(root, (exact, triage_bridge.import_trivy_ignore(exact), review))
            result = self.cli(paths)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, expected)
            paths[1].write_bytes(exact + b" ")
            self.assert_failed(self.cli(paths), b"E_IMPORT")
            paths, _ = self.save(root)
            paths[1].write_bytes(raw + b"\n")
            self.assert_failed(self.cli(paths), b"E_FINALIZE")
            self.assertEqual(set(root.iterdir()), set(paths))

    def test_json_refusals_each_json_position(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths, _ = self.save(root)
            invalid = [b'\xffSECRET', b'{"SECRET":1,"SECRET":2}', b'{"SECRET":NaN}',
                       b'{"SECRET":Infinity}']
            for index in (0, 2):
                original = paths[index].read_bytes()
                for data in invalid:
                    with self.subTest(position=index, prefix=data[:30]):
                        paths[index].write_bytes(data)
                        self.assert_failed(self.cli(paths), b"E_INPUT")
                # CPython versions differ in where deep nesting is refused:
                # the JSON decoder or the pure finalizer's shape/canonicalization.
                paths[index].write_bytes(b"[" * 10000 + b"0" + b"]" * 10000)
                result = self.cli(paths)
                self.assert_failed(result, b"E_")
                self.assertTrue(b"E_INPUT" in result.stderr or b"E_FINALIZE" in result.stderr)
                paths[index].write_bytes(original)
            self.assertEqual(set(root.iterdir()), set(paths))

    def test_read_decode_then_pure_validation_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fifo = root / "SECRET-fifo"
            os.mkfifo(fifo)
            paths, _ = self.save(root)
            paths[0].write_bytes(b'{"SECRET":NaN}')
            self.assert_failed(self.cli([paths[0], fifo, fifo], as_of="SECRET"), b"E_INPUT")
            paths, _ = self.save(root)
            self.assert_failed(self.cli([paths[0], root, fifo], as_of="SECRET"), b"E_IO")
            # Native syntax/draft/date are not validated until review JSON is decoded.
            paths[1].write_bytes(b"SECRET unsupported native syntax")
            paths[2].write_bytes(b'{"SECRET":NaN}')
            self.assert_failed(self.cli(paths, as_of="SECRET"), b"E_INPUT")
            paths[2].write_bytes(b"{}")
            self.assert_failed(self.cli(paths, as_of="SECRET"), b"E_IMPORT")
            paths, _ = self.save(root)
            paths[0].write_bytes(b"{}")
            paths[2].write_bytes(b'{"SECRET":NaN}')
            self.assert_failed(self.cli(paths, as_of="SECRET"), b"E_INPUT")
            paths[2].write_bytes(b"{}")
            self.assert_failed(self.cli(paths, as_of="SECRET"), b"E_FINALIZE")
            paths, _ = self.save(root)
            self.assert_failed(self.cli(paths, as_of="SECRET"), b"E_DATE")
            self.assertEqual(set(root.iterdir()), {*paths, fifo})

    def test_library_loader_default_remains_explicit(self):
        raw = b'{"schemaVersion":1,"decisions":[]}'
        path = Path("SECRET-document")
        with patch("vulnwrench.triage.io._read_input", return_value=raw) as read:
            self.assertEqual(triage_bridge.load_document(path), {"schemaVersion": 1, "decisions": []})
            read.assert_called_once_with(path, regular_only=False)
            read.reset_mock()
            triage_bridge.load_document(path, regular_only=True)
            read.assert_called_once_with(path, regular_only=True)
