"""Renewal file inputs refuse streams before optional verification or stdout."""
from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import call, patch

from vulnwrench.triage import BridgeError
from vulnwrench.triage.cli import main
from vulnwrench.triage.compiler import json_bytes
from vulnwrench.triage.model import MAX_INPUT_BYTES
from tests.triage.test_bridge import ROOT


RENEWAL = ROOT / "examples/triage/renewal"


def arguments(prior=None, current=None, *, report=False):
    args = ["preview-renewal", str(prior if prior is not None else RENEWAL / (
        "conversion-report.json" if report else "prior.json")),
        "--prior-as-of", "2026-11-01", "--as-of", "2026-11-11", "--expiring-within-days", "7"]
    if report:
        args += ["--prior-format", "conversion-report"]
    if current is not None:
        args += ["--current", str(current)]
    return args


class RenewalInputTests(unittest.TestCase):
    def cli(self, args, *, timeout=60):
        try:
            return subprocess.run([sys.executable, "-m", "vulnwrench", "triage", *args],
                                  cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            self.fail("renewal input open/read blocked on a nonregular file")

    def assert_failed(self, result, code):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn(code, result.stderr)
        self.assertNotIn("SECRET", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_fifo_prior_and_current_refused_with_or_without_peer(self):
        with tempfile.TemporaryDirectory() as tmp:
            fifo = Path(tmp) / "SECRET-fifo"
            os.mkfifo(fifo)
            for held_peer in (False, True):
                peer = os.open(fifo, os.O_RDWR | os.O_NONBLOCK) if held_peer else None
                try:
                    for report in (False, True):
                        for position in ("prior", "current"):
                            with self.subTest(peer=held_peer, report=report, position=position):
                                args = arguments(**{position: fifo}, report=report)
                                if report:
                                    # Input refusal must win over both optional checks.
                                    args += ["--verify-source", str(Path(tmp) / "SECRET-missing"),
                                             "--verify-artifacts", str(Path(tmp) / "SECRET-missing-dir")]
                                self.assert_failed(self.cli(args, timeout=60), "E_IO")
                finally:
                    if peer is not None:
                        os.close(peer)
            self.assertTrue(fifo.is_fifo())

    def test_other_nonregular_and_unreadable_paths_are_redacted(self):
        with tempfile.TemporaryDirectory() as tmp, socket.socket(socket.AF_UNIX) as sock:
            root = Path(tmp)
            fifo = root / "SECRET-fifo"
            os.mkfifo(fifo)
            link = root / "SECRET-link"
            link.symlink_to(fifo)
            dangling = root / "SECRET-dangling"
            dangling.symlink_to(root / "SECRET-missing")
            socket_path = root / "SECRET-socket"
            sock.bind(str(socket_path))
            paths = [link, dangling, socket_path, root, Path(os.devnull), root / "SECRET-missing"]
            unreadable = root / "SECRET-unreadable"
            unreadable.write_bytes((RENEWAL / "prior.json").read_bytes())
            unreadable.chmod(0)
            if os.geteuid() != 0:
                paths.append(unreadable)
            try:
                for report in (False, True):
                    for position in ("prior", "current"):
                        for path in paths:
                            with self.subTest(report=report, position=position, path=path.name):
                                self.assert_failed(self.cli(arguments(**{position: path}, report=report)), "E_IO")
            finally:
                unreadable.chmod(0o600)

    def test_regular_and_symlink_inputs_preserve_plans_without_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            saved = root / "saved"
            saved.mkdir()
            for name in ("prior.json", "conversion-report.json", "current.json"):
                (saved / name).write_bytes((RENEWAL / name).read_bytes())
                (root / name).symlink_to(saved / name)
            (root / "parent").symlink_to(saved, target_is_directory=True)
            before = {p: (p.read_bytes(), p.stat().st_mode) for p in saved.iterdir()}
            entries = set(root.iterdir())
            for report in (False, True):
                name = "conversion-report.json" if report else "prior.json"
                for with_current in (False, True):
                    expected = self.cli(arguments(current=RENEWAL / "current.json" if with_current else None,
                                                  report=report))
                    self.assertEqual(expected.returncode, 0, expected.stderr)
                    for parent in (saved, root, root / "parent"):
                        actual = self.cli(arguments(parent / name, parent / "current.json" if with_current else None,
                                                    report=report))
                        self.assertEqual(actual.returncode, 0, actual.stderr)
                        self.assertEqual(actual.stdout, expected.stdout)
            self.assertEqual({p: (p.read_bytes(), p.stat().st_mode) for p in before}, before)
            self.assertEqual(set(root.iterdir()), entries)

    def test_json_size_and_date_validation_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "SECRET-input"
            for report in (False, True):
                for position in ("prior", "current"):
                    name = "conversion-report.json" if report and position == "prior" else "prior.json"
                    raw = (RENEWAL / name).read_bytes()
                    args = arguments(**{position: path}, report=report)
                    path.write_bytes(raw + b" " * (MAX_INPUT_BYTES - len(raw)))
                    result = self.cli(args)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    for invalid in (raw + b" " * (MAX_INPUT_BYTES + 1 - len(raw)),
                                    b'{"SECRET":0,"SECRET":1}', b'{"SECRET":NaN}',
                                    b'{"SECRET":Infinity}', b'\xffSECRET',
                                    b'[' * 100000 + b'0' + b']' * 100000):
                        with self.subTest(report=report, position=position, size=len(invalid)):
                            path.write_bytes(invalid)
                            self.assert_failed(self.cli(args), "E_INPUT")
                    path.write_bytes(raw)
                    self.assert_failed(self.cli(args + ["--as-of", "SECRET"]), "E_DATE")
                    self.assert_failed(self.cli(args + ["--as-of", "2026-10-31"]), "E_DATE")
            path.write_bytes(b'null')
            self.assert_failed(self.cli(arguments(current=path)), "E_INPUT")

    def test_input_policy_and_validation_order(self):
        # Keep this order explicit: reads precede semantic review validation;
        # source/artifact I/O occurs only after a valid review plan.
        import vulnwrench.triage.cli as cli
        prior, current, original = object(), object(), object()
        plan = {"mode": "review_only"}
        args = arguments("SECRET-prior", "SECRET-current", report=True)
        args += ["--verify-source", "SECRET-original", "--verify-artifacts", "SECRET-artifacts"]
        with patch.object(cli, "load_document") as load, patch.object(cli, "preview_renewal") as preview, \
                patch.object(cli, "verify_report_source") as source, \
                patch.object(cli, "verify_report_artifacts") as artifacts, \
                redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
            ordered = unittest.mock.Mock()
            for name, mock in (("load", load), ("preview", preview), ("source", source), ("artifacts", artifacts)):
                ordered.attach_mock(mock, name)
            load.side_effect = [prior, current, original]
            preview.return_value = plan
            source.return_value = {"status": "verified"}
            artifacts.return_value = {"status": "verified"}
            self.assertEqual(main(args), 0)
            self.assertEqual(ordered.mock_calls, [
                call.load("SECRET-prior", regular_only=True), call.load("SECRET-current", regular_only=True),
                call.preview(prior, prior_as_of="2026-11-01", as_of="2026-11-11",
                             prior_format="conversion-report", expiring_within_days=7, current=current),
                call.load("SECRET-original", regular_only=True), call.source(prior, original),
                call.artifacts(prior, "SECRET-artifacts")])
            self.assertEqual(stdout.getvalue(), json_bytes(plan).decode())
            for results, review_error, expected_code in (
                    ([BridgeError("E_IO", "refused")], None, "E_IO"),
                    ([prior, BridgeError("E_INPUT", "invalid")], None, "E_INPUT"),
                    ([prior, current], BridgeError("E_REPORT", "invalid"), "E_REPORT"),
                    ([prior, current], BridgeError("E_DATE", "invalid"), "E_DATE")):
                ordered.reset_mock()
                stdout.seek(0)
                stdout.truncate()
                load.side_effect = results
                preview.side_effect = review_error
                self.assertEqual(main(args), 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertIn(expected_code, stderr.getvalue())
                source.assert_not_called()
                artifacts.assert_not_called()
                self.assertLessEqual(load.call_count, 2)
            ordered.reset_mock()
            with self.assertRaises(SystemExit) as caught:
                main(arguments("SECRET-prior") + ["--verify-source", "SECRET-original"])
            self.assertEqual(caught.exception.code, 2)
            load.assert_not_called()
            self.assertNotIn("SECRET", stderr.getvalue())
