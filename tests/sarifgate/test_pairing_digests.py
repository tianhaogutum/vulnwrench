"""A run-index assertion can optionally bind the exact two SARIF inputs."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from vulnwrench import sarifgate as sarif_gate
from .test_baseline import KEY

ROOT = Path(__file__).resolve().parents[2]
MISMATCH = "run_pairing_input_digest_mismatch"


def bound_manifest(baseline, current):
    manifest = json.loads((ROOT / "examples/sarif/baseline/run-pairing.json").read_bytes())
    manifest["inputSha256"] = {side: hashlib.sha256(data).hexdigest()
                               for side, data in (("baseline", baseline), ("current", current))}
    return manifest


def malformed_digests(valid):
    maps = [None, [], "SYNTHETIC_SECRET", 1, True, {},
            {"baseline": valid["baseline"]}, {"current": valid["current"]},
            {**valid, "SYNTHETIC_SECRET": valid["current"]}]
    for side in ("baseline", "current"):
        for value in (None, [], {}, 1, True, "", "a" * 63, "a" * 65, "A" * 64,
                      "g" * 64, "a" * 63 + " ", "a" * 64 + "\n", "SYNTHETIC_SECRET"):
            maps.append({**valid, side: value})
    return maps


class PairingDigestTests(unittest.TestCase):
    def setUp(self):
        self.baseline = (ROOT / "examples/sarif/baseline/multi-before.sarif").read_bytes()
        self.current = (ROOT / "examples/sarif/baseline/multi-current.sarif").read_bytes()
        self.manifest = bound_manifest(self.baseline, self.current)

    def compare(self, baseline=None, current=None, manifest=None, **kwargs):
        return sarif_gate.compare_bytes(self.current if current is None else current,
                                        self.baseline if baseline is None else baseline,
                                        fingerprint=KEY, run_pairing=self.manifest if manifest is None else manifest,
                                        **kwargs)

    def assert_mismatch(self, report, baseline, current, status="ambiguous"):
        view = report["baselineComparison"]
        self.assertEqual(view["status"], status)
        self.assertFalse(view["runPairing"]["applied"])
        self.assertIn(MISMATCH, view["issues"])
        self.assertEqual(sum(view["counts"][s] for s in ("newly_observed", "retained", "absent")), 0)
        for entry in view["entries"]:
            self.assertEqual(entry["state"], "ambiguous")
            self.assertIsNone(entry["pairId"])
            self.assertIn(MISMATCH, entry["reasons"])
        for side, data in (("baseline", baseline), ("current", current)):
            expected = [f"/runs/{ri}/results/{i}" for ri, run in enumerate(json.loads(data)["runs"])
                        for i in range(len(run["results"]))]
            actual = [trace["sourcePointer"] for e in view["entries"] for trace in e[side]]
            self.assertCountEqual(actual, expected)
        gate = {k: v for k, v in report.items() if k != "baselineComparison"}
        self.assertEqual(gate, sarif_gate.check_bytes(current))

    def test_matching_digests_preserve_pairing_and_audit_evidence(self):
        snapshot = copy.deepcopy(self.manifest)
        self.assertEqual(snapshot, json.loads((ROOT / "examples/sarif/baseline/run-pairing-bound.json").read_bytes()))
        report = self.compare()
        view = report["baselineComparison"]
        self.assertEqual(view["status"], "compared")
        self.assertEqual(view["counts"], {"newly_observed": 1, "retained": 2, "absent": 1, "ambiguous": 0})
        self.assertEqual(view["runPairing"], {"document": snapshot, "applied": True})
        for side, evidence in (("baseline", view["baselineEvidence"]), ("current", report["evidence"])):
            self.assertEqual(evidence["sha256"], snapshot["inputSha256"][side])
            self.assertEqual(evidence["digestKind"], "input_bytes")
        self.assertEqual(self.manifest, snapshot)
        unbound = copy.deepcopy(self.manifest)
        del unbound["inputSha256"]
        unbound_view = self.compare(manifest=unbound)["baselineComparison"]
        self.assertEqual(view["entries"], unbound_view["entries"])
        self.assertEqual(view["counts"], unbound_view["counts"])
        self.manifest["inputSha256"]["current"] = "0" * 64
        self.assertEqual(view["runPairing"]["document"], snapshot)

    def test_exact_byte_reformatting_or_stale_run_indexes_taint_both_sides(self):
        for side in ("baseline", "current"):
            original = getattr(self, side)
            doc = json.loads(original)
            for change in ("whitespace", "reorder"):
                changed = (b" \n" + original if change == "whitespace" else
                           json.dumps({**doc, "runs": list(reversed(doc["runs"]))}).encode())
                # The whitespace case has exactly equal parsed JSON, yet different bytes.
                if change == "whitespace":
                    self.assertEqual(json.loads(changed), doc)
                inputs = {"baseline": self.baseline, "current": self.current, side: changed}
                with self.subTest(side=side, change=change):
                    self.assert_mismatch(self.compare(**inputs), **inputs)

    def test_mismatch_is_visible_for_empty_runs_and_zero_runs(self):
        for count in (0, 1, 2):
            doc = json.loads(self.current)
            doc["runs"] = doc["runs"][:count]
            for run in doc["runs"]:
                run["results"] = []
            data = json.dumps(doc).encode()
            manifest = bound_manifest(data, data)
            for side in ("baseline", "current"):
                manifest[side] = [{"runIndex": i, "pairId": str(i)} for i in range(count)]
            matching = self.compare(baseline=data, current=data, manifest=manifest)["baselineComparison"]
            self.assertTrue(matching["runPairing"]["applied"])
            self.assertEqual(matching["status"], "compared" if count else "ambiguous")
            for side in ("baseline", "current"):
                inputs = {"baseline": data, "current": data, side: data + b"\n"}
                with self.subTest(count=count, side=side):
                    report = self.compare(manifest=manifest, **inputs)
                    self.assert_mismatch(report, **inputs)
                    self.assertEqual(report["baselineComparison"]["counts"],
                                     dict.fromkeys(("newly_observed", "retained", "absent", "ambiguous"), 0))

    def test_failed_execution_and_malformed_assignments_keep_existing_precedence(self):
        doc = json.loads(self.current)
        doc["runs"][0]["invocations"][0]["executionSuccessful"] = False
        data = json.dumps(doc).encode()
        report = self.compare(current=data)
        self.assert_mismatch(report, self.baseline, data, status="invalid")
        self.assertIn("current_execution_failed", report["baselineComparison"]["issues"])
        self.manifest["baseline"][0]["runIndex"] = True
        with self.assertRaises(sarif_gate.InputError):
            self.compare(current=data)

    def test_malformed_digest_maps_raise_sanitized_input_errors(self):
        for value in malformed_digests(self.manifest["inputSha256"]):
            manifest = {**self.manifest, "inputSha256": value}
            with self.subTest(value=value), self.assertRaises(sarif_gate.InputError) as caught:
                self.compare(manifest=manifest)
            self.assertNotIn("SYNTHETIC_SECRET", str(caught.exception))


class PairingDigestCliTests(unittest.TestCase):
    def invoke(self, directory, data, manifest, *, stdin=False, level="warning"):
        directory = Path(directory)
        baseline = (ROOT / "examples/sarif/baseline/multi-before.sarif").read_bytes()
        (directory / "baseline.sarif").write_bytes(baseline)
        (directory / "current.sarif").write_bytes(data)
        (directory / "manifest.json").write_text(json.dumps(manifest))
        args = [sys.executable, "-m", "vulnwrench", "sarif", "check", "-" if stdin else str(directory / "current.sarif"),
                "--baseline", str(directory / "baseline.sarif"), "--fingerprint", KEY,
                "--run-pairing", str(directory / "manifest.json"), "--level", level,
                "--output", str(directory / "out.json"), "--markdown", str(directory / "out.md")]
        return subprocess.run(args, cwd=ROOT, input=data if stdin else None,
                              capture_output=True, timeout=60)

    def test_matching_and_stale_exact_stdin_bytes_keep_gate_independent(self):
        baseline = (ROOT / "examples/sarif/baseline/multi-before.sarif").read_bytes()
        current = (ROOT / "examples/sarif/baseline/multi-current.sarif").read_bytes()
        # CRLF must reach the byte hash without universal-newline translation.
        data = current.replace(b"\n", b"\r\n")
        manifest = bound_manifest(baseline, data)
        with tempfile.TemporaryDirectory() as directory:
            for stdin in (False, True):
                for stale in (False, True):
                    for level, code in (("warning", 1), ("error", 0)):
                        with self.subTest(stdin=stdin, stale=stale, level=level):
                            proc = self.invoke(directory, data + (b" " if stale else b""), manifest,
                                               stdin=stdin, level=level)
                            self.assertEqual(proc.returncode, code, proc.stderr)
                            self.assertEqual(proc.stdout + proc.stderr, b"")
                            report = json.loads((Path(directory) / "out.json").read_bytes())
                            view = report["baselineComparison"]
                            self.assertEqual(view["runPairing"]["document"], manifest)
                            self.assertEqual(view["runPairing"]["applied"], not stale)
                            if stale:
                                self.assertIn(MISMATCH, view["issues"])
                                self.assertEqual(sum(view["counts"][s] for s in ("newly_observed", "retained", "absent")), 0)
                                self.assertIn(MISMATCH, (Path(directory) / "out.md").read_text())
                            else:
                                self.assertEqual(view["counts"], {"newly_observed": 1, "retained": 2, "absent": 1, "ambiguous": 0})
                                self.assertEqual(view["status"], "compared")

    def test_malformed_digests_exit_two_and_preserve_both_outputs(self):
        baseline = (ROOT / "examples/sarif/baseline/multi-before.sarif").read_bytes()
        current = (ROOT / "examples/sarif/baseline/multi-current.sarif").read_bytes()
        manifest = bound_manifest(baseline, current)
        with tempfile.TemporaryDirectory() as directory:
            out, md = [Path(directory) / name for name in ("out.json", "out.md")]
            out.write_bytes(b"keep json")
            md.write_bytes(b"keep markdown")
            for value in malformed_digests(manifest["inputSha256"]):
                with self.subTest(value=value):
                    proc = self.invoke(directory, current, {**manifest, "inputSha256": value}, stdin=True)
                    self.assertEqual(proc.returncode, 2)
                    self.assertEqual(proc.stdout, b"")
                    self.assertIn(b"runPairing/inputSha256", proc.stderr)
                    self.assertNotIn(b"SYNTHETIC_SECRET", proc.stderr)
                    self.assertEqual(out.read_bytes(), b"keep json")
                    self.assertEqual(md.read_bytes(), b"keep markdown")
