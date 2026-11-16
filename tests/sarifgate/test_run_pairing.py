"""Explicit per-side correspondence; ambiguity must never imply absence."""

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from vulnwrench import sarifgate as sarif_gate
from .test_baseline import KEY, finding
from .test_cli import cli

ROOT = Path(__file__).resolve().parents[2]
CLI_ARGS = ("--baseline", "examples/sarif/baseline/multi-before.sarif", "--fingerprint", KEY)
CURRENT = "examples/sarif/baseline/multi-current.sarif"
MANIFEST = "examples/sarif/baseline/run-pairing.json"


class RunPairingTests(unittest.TestCase):
    def setUp(self):
        self.baseline = json.loads((ROOT / "examples/sarif/baseline/multi-before.sarif").read_bytes())
        self.current = json.loads((ROOT / "examples/sarif/baseline/multi-current.sarif").read_bytes())
        self.manifest = json.loads((ROOT / "examples/sarif/baseline/run-pairing.json").read_bytes())

    def compare(self, manifest=None):
        return sarif_gate.compare_bytes(json.dumps(self.current).encode(), json.dumps(self.baseline).encode(),
                                        fingerprint=KEY, run_pairing=self.manifest if manifest is None else manifest)

    def test_reordered_same_tool_runs_with_reused_fingerprints(self):
        report = self.compare()
        view = report["baselineComparison"]
        self.assertEqual(view["status"], "compared")
        self.assertEqual(view["counts"], {"newly_observed": 1, "retained": 2, "absent": 1, "ambiguous": 0})
        self.assertEqual(view["runPairing"], {"document": self.manifest, "applied": True})
        api = next(e for e in view["entries"] if e["pairId"] == "api" and e["fingerprint"] == "A")
        self.assertEqual(api["baseline"][0]["sourcePointer"], "/runs/0/results/0")
        self.assertEqual(api["current"][0]["sourcePointer"], "/runs/1/results/1")
        self.assertEqual(api["baseline"][0]["suppressions"][0]["status"], "accepted")
        self.assertTrue(api["current"][0]["blocking"])
        # Comparison does not change the gate or carry suppressions across sides.
        del report["baselineComparison"]
        self.assertEqual(report, sarif_gate.check_bytes(json.dumps(self.current).encode()))

    def test_without_manifest_same_tool_runs_remain_ambiguous(self):
        report = sarif_gate.compare_bytes(json.dumps(self.current).encode(), json.dumps(self.baseline).encode(),
                                         fingerprint=KEY)
        self.assertEqual(report["baselineComparison"]["status"], "ambiguous")
        self.assertIn("tool_run_collision", report["baselineComparison"]["issues"])
        self.assertNotIn("runPairing", report["baselineComparison"])

    def test_manifest_and_input_are_unchanged_and_output_is_deterministic(self):
        snapshot = copy.deepcopy((self.current, self.baseline, self.manifest))
        report = self.compare()
        self.assertEqual((self.current, self.baseline, self.manifest), snapshot)
        reordered = copy.deepcopy(self.manifest)
        for side in reordered:
            reordered[side].reverse()
        self.assertEqual(report["baselineComparison"]["entries"], self.compare(reordered)["baselineComparison"]["entries"])
        self.assertEqual(sarif_gate.dumps(report), sarif_gate.dumps(self.compare()))
        self.manifest["baseline"][0]["pairId"] = "mutated"
        self.assertEqual(report["baselineComparison"]["runPairing"]["document"], snapshot[2])

    def test_duplicate_incomplete_and_unpaired_mappings_taint_whole_view(self):
        for side in ("baseline", "current"):
            for kind, reason in (("duplicate_run", "run_pairing_duplicate_run"),
                                 ("duplicate_id", "run_pairing_duplicate_pair_id"),
                                 ("missing", "run_pairing_incomplete"),
                                 ("unpaired", "run_pairing_unpaired_id"),
                                 ("empty", "run_pairing_incomplete")):
                manifest = copy.deepcopy(self.manifest)
                entries = manifest[side]
                if kind == "duplicate_run":
                    entries.append(copy.deepcopy(entries[0]))
                elif kind == "duplicate_id":
                    entries[1]["pairId"] = entries[0]["pairId"]
                elif kind == "missing":
                    entries.pop()
                elif kind == "empty":
                    entries.clear()
                else:
                    entries[0]["pairId"] = "no-counterpart"
                with self.subTest(side=side, kind=kind):
                    view = self.compare(manifest)["baselineComparison"]
                    self.assertEqual(view["status"], "ambiguous")
                    self.assertFalse(view["runPairing"]["applied"])
                    self.assertIn(reason, view["issues"])
                    self.assertTrue(all(e["state"] == "ambiguous" for e in view["entries"]))
                    self.assertEqual(sum(view["counts"][s] for s in ("newly_observed", "retained", "absent")), 0)
                    for source in ("baseline", "current"):
                        pointers = [t["sourcePointer"] for e in view["entries"] for t in e[source]]
                        self.assertEqual(len(pointers), 3)
                        self.assertEqual(len(set(pointers)), 3)

    def test_malformed_manifest_raises_sanitized_input_error(self):
        malformed = [[], {}, {"baseline": []}, {"baseline": [], "current": [], "extra": "SECRET"}]
        for field, values in (("runIndex", [True, False, -1, 2, 0.0, "SECRET", None]),
                              ("pairId", ["", [], 1, None])):
            for value in values:
                manifest = copy.deepcopy(self.manifest)
                manifest["baseline"][0][field] = value
                malformed.append(manifest)
        for assignment in ({"runIndex": 0}, {"pairId": "SECRET"}, [],
                           {"runIndex": 0, "pairId": "api", "extra": "SECRET"}):
            malformed.append({"baseline": [assignment], "current": []})
        malformed.append({"baseline": None, "current": []})
        for manifest in malformed:
            with self.subTest(manifest=manifest):
                with self.assertRaises(sarif_gate.InputError) as caught:
                    self.compare(manifest)
                self.assertNotIn("SECRET", str(caught.exception))

    def test_tool_changes_and_fingerprint_collisions_still_ambiguous(self):
        self.current["runs"][1]["tool"]["driver"]["version"] = "2.0.0"
        view = self.compare()["baselineComparison"]
        self.assertIn("tool_identity_unpaired", view["issues"])
        self.assertTrue(all(e["state"] == "ambiguous" for e in view["entries"] if e["pairId"] == "api"))
        self.assertEqual(view["counts"]["retained"], 1)  # Independent web pair.
        self.current["runs"][1]["tool"]["driver"]["version"] = "1.0.0"
        self.current["runs"][1]["results"].append(finding("A"))
        view = self.compare()["baselineComparison"]
        collision = next(e for e in view["entries"] if e["pairId"] == "api" and e["fingerprint"] == "A")
        self.assertIn("fingerprint_collision", collision["reasons"])
        self.assertEqual(len(collision["current"]), 2)

    def test_execution_and_identity_uncertainty_cannot_be_overridden(self):
        for change, reason, status in (("failed", "current_execution_failed", "invalid"),
                                       ("unknown", "current_execution_unknown", "ambiguous"),
                                       ("missing_results", "current_results_missing", "ambiguous"),
                                       ("missing_fingerprint", "fingerprint_missing", "ambiguous")):
            original = copy.deepcopy(self.current)
            run = self.current["runs"][1]
            if change == "failed":
                run["invocations"][0]["executionSuccessful"] = False
            elif change == "unknown":
                run["invocations"] = []
            elif change == "missing_results":
                del run["results"]
            else:
                run["results"][0]["fingerprints"] = {}
            with self.subTest(change=change):
                view = self.compare()["baselineComparison"]
                self.assertEqual(view["status"], status)
                self.assertIn(reason, view["issues"])
                self.assertEqual(view["counts"]["absent"], 0)
            self.current = original

    def test_empty_paired_runs_can_prove_observational_absence(self):
        self.current["runs"][1]["results"] = []
        view = self.compare()["baselineComparison"]
        self.assertEqual(view["counts"], {"newly_observed": 0, "retained": 1, "absent": 2, "ambiguous": 0})
        self.baseline["runs"][0]["results"] = []
        self.assertEqual(self.compare()["baselineComparison"]["status"], "compared")
        self.manifest["current"].pop(0)
        view = self.compare()["baselineComparison"]
        self.assertEqual(view["status"], "ambiguous")
        self.assertIn("run_pairing_incomplete", view["issues"])

    def test_markdown_pair_labels_are_escaped(self):
        payload = '<script>|[pair](bad)\x1b'
        for side in self.manifest:
            self.manifest[side][0]["pairId"] = payload
        markdown = sarif_gate.markdown_summary(self.compare())
        self.assertIn("| Pair |", markdown)
        self.assertNotIn(payload, markdown)
        self.assertIn("&#60;script&#62;", markdown)


class RunPairingCliTests(unittest.TestCase):
    def test_manifest_json_markdown_and_stdin(self):
        proc = cli("check", CURRENT, *CLI_ARGS, "--run-pairing", MANIFEST)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        view = json.loads(proc.stdout)["baselineComparison"]
        self.assertEqual(view["counts"], {"newly_observed": 1, "retained": 2, "absent": 1, "ambiguous": 0})
        self.assertEqual(view["status"], "compared")
        stdin = cli("check", "-", *CLI_ARGS, "--run-pairing", MANIFEST, data=(ROOT / CURRENT).read_text())
        self.assertEqual(stdin.stdout, proc.stdout)
        markdown = cli("check", CURRENT, *CLI_ARGS, "--run-pairing", MANIFEST, "--format", "markdown")
        self.assertEqual(markdown.returncode, 1, markdown.stderr)
        self.assertIn("| Pair |", markdown.stdout)
        self.assertIn("api", markdown.stdout)

    def test_incomplete_manifest_reports_ambiguity_even_for_passing_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            manifest.write_text('{"baseline": [], "current": []}')
            proc = cli("check", "examples/sarif/clean.sarif", "--baseline", "examples/sarif/clean.sarif",
                       "--fingerprint", KEY, "--run-pairing", str(manifest))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            view = json.loads(proc.stdout)["baselineComparison"]
            self.assertEqual(view["status"], "ambiguous")
            self.assertFalse(view["runPairing"]["applied"])
            self.assertIn("run_pairing_incomplete", view["issues"])

    def test_invalid_manifests_preserve_outputs_and_sanitize_errors(self):
        invalid = [b'SYNTHETIC_SECRET', b'\xff', b'null', b'[]', b'{}',
                   b'{"baseline":[],"current":[],"baseline":[]}',
                   b'{"baseline":[],"current":[],"SYNTHETIC_SECRET":0}',
                   b'{"baseline":[{"runIndex":true,"pairId":"SYNTHETIC_SECRET"}],"current":[]}',
                   b'{"baseline":[{"runIndex":2,"pairId":"SYNTHETIC_SECRET"}],"current":[]}']
        with tempfile.TemporaryDirectory() as directory:
            manifest, out, md = [Path(directory) / n for n in ("manifest.json", "out.json", "out.md")]
            out.write_text("keep json")
            md.write_text("keep markdown")
            for data in invalid:
                manifest.write_bytes(data)
                with self.subTest(data=data):
                    proc = cli("check", CURRENT, *CLI_ARGS, "--run-pairing", str(manifest),
                               "--output", str(out), "--markdown", str(md))
                    self.assertEqual(proc.returncode, 2)
                    self.assertEqual(proc.stdout, "")
                    self.assertNotIn("SYNTHETIC_SECRET", proc.stderr)
                    self.assertEqual(out.read_text(), "keep json")
                    self.assertEqual(md.read_text(), "keep markdown")

    def test_manifest_size_limit_and_output_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, alias, out = [Path(directory) / n for n in ("manifest.json", "alias", "out")]
            content = (ROOT / MANIFEST).read_bytes()
            manifest.write_bytes(content)
            os.link(manifest, alias)
            for path in (manifest, alias):
                for flag in ("--output", "--markdown"):
                    proc = cli("check", CURRENT, *CLI_ARGS, "--run-pairing", str(manifest), flag, str(path))
                    self.assertEqual(proc.returncode, 2)
                    self.assertEqual(manifest.read_bytes(), content)
            manifest.write_bytes(content + b' ' * 4096)
            out.write_text("keep")
            proc = cli("check", CURRENT, *CLI_ARGS, "--run-pairing", str(manifest), "--max-bytes", "2048",
                       "--output", str(out))
            self.assertEqual(proc.returncode, 2)
            self.assertIn("runPairing: byte limit exceeded", proc.stderr)
            self.assertEqual(out.read_text(), "keep")

    def test_manifest_requires_baseline_and_fingerprint(self):
        for args in ((), ("--fingerprint", KEY), ("--baseline", "examples/sarif/clean.sarif")):
            proc = cli("check", CURRENT, "--run-pairing", MANIFEST, *args)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(proc.stdout, "")
