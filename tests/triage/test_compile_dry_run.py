"""Dry-run validates the same compilation and flushes its exact report without publication."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from vulnwrench.triage import compile_decisions
from vulnwrench.triage.cli import main
from vulnwrench.triage.compiler import json_bytes
from vulnwrench.triage.model import MAX_INPUT_BYTES, MAX_DECISIONS
from tests.triage.test_bridge import ROOT, PARAMS, fixture


def arguments(source):
    return ["compile", str(source), "--as-of", PARAMS["as_of"], "--author", PARAMS["author"],
            "--product-id", PARAMS["product_id"], "--timestamp", PARAMS["timestamp"]]


class CompileDryRunTests(unittest.TestCase):
    def cli(self, source, *extra, scope=True):
        args = arguments(source) + ["--dry-run", *extra]
        if scope:
            args.append("--allow-scope-loss")
        return subprocess.run([sys.executable, "-m", "vulnwrench", "triage", *args], cwd=ROOT,
                              capture_output=True, timeout=60)

    def assert_refused(self, result, code):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertIn(code.encode(), result.stderr)
        self.assertNotIn(b"SECRET", result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)

    def test_exact_report_matches_published_single_mixed_and_accepted_risk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("decisions", "mixed-decisions", "accepted-risk"):
                with self.subTest(name=name):
                    document = (json.loads((ROOT / f"examples/triage/{name}.json").read_bytes())
                                if name != "accepted-risk" else fixture())
                    if name == "accepted-risk":
                        document["decisions"][0]["status"] = "accepted_risk"
                    # Retain normalized review metadata and Unicode in the full report.
                    document["decisions"][0].update(decisionId="synthetic-id", sourceRefs=["urn:example:review:1"])
                    document["decisions"][0]["reason"] += " 制品 😀"
                    source = root / f"{name}.json"
                    source.write_bytes(json_bytes(document))
                    output = root / f"published-{name}"
                    saved = subprocess.run([sys.executable, "-m", "vulnwrench", "triage", *arguments(source),
                                            "--allow-scope-loss", "--out-dir", str(output)],
                                           cwd=ROOT, capture_output=True, timeout=60)
                    self.assertEqual(saved.returncode, 0, saved.stderr)
                    expected = compile_decisions(document, **PARAMS)
                    self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()}, expected.files)
                    summary = {"files": sorted(expected.files), "counts": expected.report["counts"],
                               "losses": len(expected.report["losses"])}
                    self.assertEqual(saved.stdout, (json.dumps(summary, sort_keys=True) + "\n").encode())
                    before = {p: (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
                              for p in [source, *output.iterdir()]}
                    entries = set(root.rglob("*"))
                    dry = self.cli(source)
                    self.assertEqual(dry.returncode, 0, dry.stderr)
                    self.assertEqual(dry.stderr, b"")
                    self.assertEqual(dry.stdout, (output / "conversion-report.json").read_bytes())
                    self.assertEqual(set(root.rglob("*")), entries)
                    self.assertEqual({p: (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
                                      for p in before}, before)

    def test_exactly_one_compiler_no_writer_complete_write_and_flush(self):
        document = fixture()
        expected = compile_decisions(document, **PARAMS)
        for failure in (None, "write", "flush"):
            with self.subTest(failure=failure):
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
                output, errors = Output(), io.StringIO()
                with patch("vulnwrench.triage.cli.load_document", return_value=document) as load, \
                     patch("vulnwrench.triage.cli.compile_decisions", wraps=compile_decisions) as compile_, \
                     patch("vulnwrench.triage.cli.write_compilation") as write:
                    with redirect_stdout(output), redirect_stderr(errors):
                        if failure:
                            with self.assertRaises(OSError):
                                main(arguments("SECRET-source") + ["--dry-run", "--allow-scope-loss"])
                        else:
                            self.assertEqual(main(arguments("SECRET-source") + ["--dry-run", "--allow-scope-loss"]), 0)
                    load.assert_called_once_with("SECRET-source", regular_only=True)
                    compile_.assert_called_once_with(document, **PARAMS)
                    write.assert_not_called()
                self.assertEqual(events, ["write"] if failure == "write" else ["write", "flush"])
                self.assertEqual(errors.getvalue(), "")
                if failure != "write":
                    self.assertEqual(output.getvalue().encode(), expected.files["conversion-report.json"])

    def test_output_mode_and_required_metadata_refused_before_reads(self):
        base = arguments("SECRET-nonregular")
        cases = [base, base + ["--dry-run", "--out-dir", "SECRET-out"],
                 base + ["--out-dir", "SECRET-out", "--dry-run"],
                 base + ["--dry-run", "--SECRET-unknown"]]
        for option in ("--as-of", "--author", "--product-id", "--timestamp"):
            index = base.index(option)
            cases.append(base[:index] + base[index + 2:] + ["--dry-run"])
        for args in cases:
            with self.subTest(args=args), patch("vulnwrench.triage.cli.load_document") as load, \
                 patch("vulnwrench.triage.cli.compile_decisions") as compile_, \
                 patch("vulnwrench.triage.cli.write_compilation") as write:
                output, errors = io.StringIO(), io.StringIO()
                with redirect_stdout(output), redirect_stderr(errors), self.assertRaises(SystemExit) as error:
                    main(args)
                self.assertEqual(error.exception.code, 2)
                self.assertEqual(output.getvalue(), "")
                self.assertIn("E_ARGUMENT", errors.getvalue())
                self.assertNotIn("SECRET", errors.getvalue())
                load.assert_not_called()
                compile_.assert_not_called()
                write.assert_not_called()
        with tempfile.TemporaryDirectory() as tmp:
            fifo, output = Path(tmp) / "SECRET-fifo", Path(tmp) / "SECRET-out"
            os.mkfifo(fifo)
            self.assert_refused(self.cli(fifo, "--out-dir", str(output)), "E_ARGUMENT")
            self.assertEqual(set(Path(tmp).iterdir()), {fifo})

    def test_scope_policy_evidence_alias_overlap_and_metadata_refusals(self):
        cases = []
        for field, value, code in (("owner", None, "E_INPUT"), ("status", "SECRET", "E_STATUS"),
                                   ("expiresOn", "2026-11-11", "E_EXPIRED"),
                                   ("status", "not_affected", "E_STATUS"),
                                   ("package", "pkg:npm/SECRET", "E_PURL"),
                                   ("decisionId", "", "E_INPUT"), ("sourceRefs", ["SECRET", "SECRET"], "E_INPUT")):
            doc = fixture()
            doc["decisions"][0][field] = value
            cases.append((doc, code))
        doc = fixture()
        doc["decisions"].append(deepcopy(doc["decisions"][0]))
        cases.append((doc, "E_CONFLICT"))
        doc = fixture()
        doc["decisions"][0]["aliases"] = {doc["decisions"][0]["ids"][0]: ["GHSA-synthetic"]}
        other = deepcopy(doc["decisions"][0])
        other.update(package="pkg:npm/other@1", ids=["GHSA-synthetic"])
        other.pop("aliases")
        doc["decisions"].append(other)
        cases.append((doc, "E_CONFLICT"))
        doc = fixture()
        other = deepcopy(doc["decisions"][0])
        other.update(package="pkg:npm/other@1", reason="SECRET-different")
        doc["decisions"].append(other)
        cases.append((doc, "E_CONFLICT"))
        cases += [(fixture() | {"SECRET": 1}, "E_INPUT"),
                  (fixture() | {"schemaVersion": 2}, "E_INPUT"),
                  ({"schemaVersion": 1, "decisions": [fixture()["decisions"][0]] * (MAX_DECISIONS + 1)}, "E_INPUT")]
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "SECRET-input"
            for doc, code in cases:
                with self.subTest(code=code, doc=str(doc)[:100]):
                    source.write_bytes(json_bytes(doc))
                    self.assert_refused(self.cli(source), code)
                    self.assertEqual(list(Path(tmp).iterdir()), [source])
            source.write_bytes(json_bytes(fixture()))
            self.assert_refused(self.cli(source, scope=False), "E_SCOPE_LOSS")
            for args, code in [(["--as-of", "SECRET"], "E_DATE"),
                               (["--timestamp", "2026-11-12T12:00:00Z"], "E_DATE"),
                               (["--product-id", "SECRET-relative"], "E_INPUT"),
                               (["--author", ""], "E_INPUT")]:
                self.assert_refused(self.cli(source, *args), code)
            self.assertEqual(list(Path(tmp).iterdir()), [source])

    def test_bounded_strict_json_and_validation_order(self):
        raw = json_bytes(fixture())
        invalid = [raw + b" " * (MAX_INPUT_BYTES + 1 - len(raw)), b'{SECRET',
                   b'{"SECRET":0,"SECRET":1}', b'{"SECRET":NaN}', b'{"SECRET":Infinity}',
                   b'\xffSECRET', b'[' * 100000 + b'0' + b']' * 100000]
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "SECRET-input"
            source.write_bytes(raw + b" " * (MAX_INPUT_BYTES - len(raw)))
            result = self.cli(source)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, compile_decisions(fixture(), **PARAMS).files["conversion-report.json"])
            for data in invalid:
                with self.subTest(size=len(data)):
                    source.write_bytes(data)
                    self.assert_refused(self.cli(source, "--as-of", "SECRET-date"), "E_INPUT")
                    self.assertEqual(list(Path(tmp).iterdir()), [source])

    def test_nonregular_unreadable_inputs_and_read_precedence(self):
        with tempfile.TemporaryDirectory() as tmp, socket.socket(socket.AF_UNIX) as sock:
            root = Path(tmp)
            fifo = root / "SECRET-fifo"
            os.mkfifo(fifo)
            for held_peer in (False, True):
                peer = os.open(fifo, os.O_RDWR | os.O_NONBLOCK) if held_peer else None
                try:
                    self.assert_refused(self.cli(fifo, "--as-of", "SECRET-date"), "E_IO")
                finally:
                    if peer is not None:
                        os.close(peer)
            link = root / "SECRET-link"
            link.symlink_to(fifo)
            dangling = root / "SECRET-dangling"
            dangling.symlink_to(root / "SECRET-missing")
            socket_path = root / "SECRET-socket"
            sock.bind(str(socket_path))
            unreadable = root / "SECRET-unreadable"
            unreadable.write_bytes(json_bytes(fixture()))
            unreadable.chmod(0)
            paths = [fifo, link, dangling, socket_path, root, Path(os.devnull), root / "SECRET-missing"]
            if os.geteuid() != 0:
                paths.append(unreadable)
            before = set(root.iterdir())
            try:
                for source in paths:
                    with self.subTest(source=source):
                        self.assert_refused(self.cli(source), "E_IO")
                        self.assertEqual(set(root.iterdir()), before)
            finally:
                unreadable.chmod(0o600)

    def test_regular_final_and_ancestor_symlinks_without_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            saved = root / "saved"
            saved.mkdir()
            ancestor = root / "ancestor"
            ancestor.symlink_to(saved, target_is_directory=True)
            source = saved / "input"
            link = root / "final"
            link.symlink_to(source)
            for name in ("decisions", "mixed-decisions"):
                raw = (ROOT / f"examples/triage/{name}.json").read_bytes()
                source.write_bytes(raw)
                before = source.stat()
                entries = set(root.rglob("*"))
                expected = (ROOT / f"examples/triage/expected/{name}/conversion-report.json").read_bytes()
                for path in (source, link, ancestor / source.name):
                    dry = self.cli(path)
                    self.assertEqual(dry.returncode, 0, dry.stderr)
                    self.assertEqual(dry.stdout, expected)
                    self.assertEqual(dry.stderr, b"")
                    self.assertEqual(set(root.rglob("*")), entries)
                self.assertEqual(source.read_bytes(), raw)
                self.assertEqual((source.stat().st_mode, source.stat().st_mtime_ns),
                                 (before.st_mode, before.st_mtime_ns))
