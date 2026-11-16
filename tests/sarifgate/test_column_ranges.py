"""Explicit source columns decorate only resolved paths with source lines."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulnwrench.sarifgate import InputError, Policy, compare_bytes, evaluate, markdown_summary
from .test_cli import cli
from .test_line_ranges import MISSING, entry, ranged
from .test_primary_messages import ESCAPED, PAYLOAD

ROOT = Path(__file__).resolve().parents[2]


class ColumnRangeTests(unittest.TestCase):
    def test_explicit_columns_and_sparse_endpoints_with_provenance(self):
        cases = [
            ({"startLine": 7, "startColumn": 3}, ":7 (startColumn=3)"),
            ({"startLine": 7, "endColumn": 5}, ":7 (endColumn=5)"),
            ({"startLine": 7, "startColumn": 3, "endColumn": 5}, ":7 (startColumn=3, endColumn=5)"),
            ({"startLine": 7, "startColumn": 3, "endColumn": 3}, ":7 (startColumn=3, endColumn=3)"),
            ({"startLine": 7, "endLine": 7, "startColumn": 3, "endColumn": 3},
             ":7-7 (startColumn=3, endColumn=3)"),
            ({"startLine": 7, "endLine": 9, "startColumn": 30, "endColumn": 1},
             ":7-9 (startColumn=30, endColumn=1)"),
            ({"startLine": 7, "endLine": 9, "startColumn": 3}, ":7-9 (startColumn=3)"),
            ({"startLine": 7, "endLine": 9, "endColumn": 5}, ":7-9 (endColumn=5)"),
            ({"startLine": 1, "startColumn": 1, "endColumn": 2**64},
             f":1 (startColumn=1, endColumn={2**64})"),
        ]
        for collection in ("locations", "relatedLocations"):
            for mode in ("inline", "index", "dual"):
                for region, suffix in cases:
                    with self.subTest(collection=collection, mode=mode, region=region):
                        data = ranged(region, collection, mode)
                        data["runs"][0]["results"][0][collection][0]["message"] = {
                            "text": PAYLOAD, "markdown": "DO_NOT_RENDER"}
                        report = evaluate(data)
                        resolved = entry(report, collection)
                        self.assertEqual(resolved["sourceColumnRange"],
                                         {k: v for k, v in region.items() if k.endswith("Column")})
                        self.assertEqual(resolved["sourceLineRange"],
                                         {k: v for k, v in region.items() if k.endswith("Line")})
                        pointer = f"/runs/0/results/0/{collection}/0"
                        self.assertEqual(resolved["regionSourcePointer"], pointer + "/physicalLocation/region")
                        self.assertEqual(resolved["sourcePointer"], pointer + "/physicalLocation/artifactLocation")
                        self.assertEqual(resolved.get("artifactSourcePointer"),
                                         "/runs/0/artifacts/0/location" if mode != "inline" else None)
                        self.assertEqual(resolved["messageSourcePointer"], pointer + "/message/text")
                        self.assertEqual(resolved["message"], PAYLOAD)
                        self.assertEqual(resolved["resolvedUri"],
                                         "file:///workspace/link/../a%3Cscript%3E%7C%5Bclick%5D.py")
                        self.assertEqual(resolved["displayPath"], "/workspace/link/../a<script>|[click].py")
                        # Assert literal rendering independently of the production escape helper.
                        safe_suffix = suffix.translate(str.maketrans({
                            ":": "&#58;", "-": "&#45;", "(": "&#40;", ")": "&#41;",
                            "=": "&#61;", ",": "&#44;"}))
                        md = markdown_summary(report)
                        self.assertIn("&#46;py" + safe_suffix + " |", md)
                        self.assertIn("| " + ESCAPED + " |", md)
                        self.assertNotIn("<script>", md)
                        self.assertNotIn("DO_NOT_RENDER", md)
                        self.assertEqual(report["evidence"]["document"], data)

    def test_absent_columns_and_line_free_regions_preserve_display(self):
        for collection in ("locations", "relatedLocations"):
            for mode in ("inline", "index", "dual"):
                for region in (MISSING, {}, {"startLine": 7}, {"startLine": 7, "endLine": 9}):
                    report = evaluate(ranged(region, collection, mode))
                    self.assertNotIn("sourceColumnRange", entry(report, collection))
                    self.assertNotIn("Column", markdown_summary(report))
                expected = evaluate(ranged(collection=collection, mode=mode))
                for region in ({"startColumn": False, "endColumn": -1},
                               {"startColumn": 3, "endColumn": 5, "charOffset": -1},
                               {"endColumn": "SYNTHETIC_SECRET", "charOffset": -1}):
                    report = evaluate(ranged(region, collection, mode))
                    self.assertEqual(entry(report, collection), entry(expected, collection))
                    self.assertEqual(markdown_summary(report), markdown_summary(expected))
                    self.assertEqual(report["evidence"]["document"]["runs"][0]["results"][0]
                                     [collection][0]["physicalLocation"]["region"], region)

    def test_invalid_consumed_columns_have_fixed_diagnostics(self):
        for collection in ("locations", "relatedLocations"):
            for mode in ("inline", "index", "dual"):
                for key in ("startColumn", "endColumn"):
                    for value in (False, True, 0, -1, 3.0, "SYNTHETIC_SECRET", None, [], {}):
                        with self.subTest(collection=collection, mode=mode, key=key, value=value):
                            with self.assertRaises(InputError) as caught:
                                evaluate(ranged({"startLine": 7, key: value}, collection, mode))
                            self.assertEqual(str(caught.exception),
                                             f"/runs/0/results/0/{collection}/0/physicalLocation/region/{key}: "
                                             "expected positive integer")
                for lines in ({"startLine": 7}, {"startLine": 7, "endLine": 7}):
                    with self.assertRaises(InputError) as caught:
                        evaluate(ranged({**lines, "startColumn": 5, "endColumn": 3}, collection, mode))
                    self.assertEqual(str(caught.exception),
                                     f"/runs/0/results/0/{collection}/0/physicalLocation/region/endColumn: "
                                     "must be at least startColumn on the same line")
                # Existing line contract takes precedence; columns never rescue bad lines.
                with self.assertRaisesRegex(InputError, "/endLine: requires startLine$"):
                    evaluate(ranged({"endLine": 9, "startColumn": 3}, collection, mode))
                with self.assertRaisesRegex(InputError, "/startLine: expected positive integer$"):
                    evaluate(ranged({"startLine": False, "startColumn": 3}, collection, mode))

    def test_no_io_conversion_or_context_traversal_and_raw_evidence(self):
        for collection in ("locations", "relatedLocations"):
            for units in ("utf16CodeUnits", "unicodeCodePoints", None):
                data = ranged({"startLine": 7, "startColumn": 3, "endColumn": 5,
                               "charLength": "raw", "byteLength": -1,
                               "snippet": {"text": "DO_NOT_RENDER_😀"}}, collection, "index")
                run = data["runs"][0]
                if units is not None:
                    run["columnKind"] = units
                run["artifacts"][0]["region"] = {"startLine": 1, "startColumn": False}
                result = run["results"][0]
                result[collection][0]["physicalLocation"]["contextRegion"] = {"startLine": 1, "startColumn": False}
                result[collection].append({"message": {"id": "raw"}, "physicalLocation": {
                    "region": {"startLine": 1, "startColumn": False}}})
                result["codeFlows"] = [{"threadFlows": [{"locations": [{"location": {
                    "physicalLocation": {"artifactLocation": {"uri": "https://invalid"},
                                         "region": {"startLine": 1, "startColumn": False}}}}]}]}]
                original = copy.deepcopy(data)
                with patch("builtins.open", side_effect=AssertionError("file access")), \
                        patch("os.open", side_effect=AssertionError("file access")), \
                        patch("os.stat", side_effect=AssertionError("file access")), \
                        patch("os.getcwd", side_effect=AssertionError("CWD access")), \
                        patch("socket.socket", side_effect=AssertionError("network access")):
                    report = evaluate(data)
                    md = markdown_summary(report)
                self.assertEqual(entry(report, collection)["sourceColumnRange"], {"startColumn": 3, "endColumn": 5})
                self.assertEqual(data, original)
                self.assertEqual(report["evidence"]["document"], original)
                self.assertNotIn("DO_NOT_RENDER", md)
                self.assertEqual(report["results"][0]["hasLocation"], collection == "locations")
                self.assertEqual(report["totals"]["unlocated"], int(collection != "locations"))

    def test_columns_preserve_policy_component_fingerprint_and_digest_pairing(self):
        for collection in ("locations", "relatedLocations"):
            for suppressed in (False, True):
                before = ranged({"startLine": 7, "endLine": 9}, collection, "dual")
                run = before["runs"][0]
                run["tool"]["extensions"] = [{"name": "Pack", "rules": [
                    {"id": "R1", "defaultConfiguration": {"level": "error"}}]}]
                result = run["results"][0]
                result["rule"] = {"index": 0, "toolComponent": {"index": 0}}
                result["baselineState"] = "unchanged"
                result[collection][0]["message"] = {"markdown": PAYLOAD}
                if suppressed:
                    result["suppressions"] = [{"kind": "external", "status": "accepted"}]
                current = copy.deepcopy(before)
                current["runs"][0]["results"][0][collection][0]["physicalLocation"]["region"].update(
                    startColumn=30, endColumn=1)
                for policy in (Policy(), Policy(level="error"), Policy(ignore_unchanged=True),
                               Policy(require_execution_success=True)):
                    old, new = evaluate(before, policy), evaluate(current, policy)
                    self.assertEqual(old["totals"], new["totals"])
                    self.assertEqual(old["decision"], new["decision"])
                    trace = copy.deepcopy(new["results"][0])
                    del trace["resolvedLocations" if collection == "locations" else
                              "resolvedRelatedLocations"][0]["sourceColumnRange"]
                    self.assertEqual(trace, old["results"][0])
                old, new = (json.dumps(d).encode() for d in (before, current))
                manifest = {side: [{"runIndex": 0, "pairId": "only"}] for side in ("baseline", "current")}
                manifest["inputSha256"] = {"baseline": hashlib.sha256(old).hexdigest(),
                                           "current": hashlib.sha256(new).hexdigest()}
                report = compare_bytes(new, old, fingerprint="primary/v1", run_pairing=manifest)
                self.assertTrue(report["baselineComparison"]["runPairing"]["applied"])
                self.assertEqual(report["baselineComparison"]["counts"],
                                 {"retained": 1, "newly_observed": 0, "absent": 0, "ambiguous": 0})
                stale = compare_bytes(new + b" ", old, fingerprint="primary/v1", run_pairing=manifest)
                self.assertFalse(stale["baselineComparison"]["runPairing"]["applied"])
                self.assertEqual(stale["baselineComparison"]["counts"]["retained"], 0)

    def test_cli_column_fixture_json_stdin_and_markdown(self):
        fixture = ROOT / "examples/sarif/locations/column-ranges.sarif"
        raw = fixture.read_text()
        proc = cli("check", str(fixture))
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(proc.stderr, "")
        report = json.loads(proc.stdout)
        self.assertEqual(report["evidence"]["document"], json.loads(raw))
        self.assertEqual(entry(report, "locations")["sourceColumnRange"], {"startColumn": 3, "endColumn": 5})
        self.assertEqual(entry(report, "relatedLocations")["sourceColumnRange"], {"startColumn": 30, "endColumn": 1})
        stdin = cli("check", "-", data=raw)
        self.assertEqual(stdin.returncode, 1, stdin.stderr)
        self.assertEqual(stdin.stdout, proc.stdout)
        md = cli("check", "-", "--format", "markdown", data=raw)
        self.assertEqual(md.returncode, 1, md.stderr)
        self.assertIn("&#58;7 &#40;startColumn&#61;3&#44; endColumn&#61;5&#41;", md.stdout)
        self.assertIn("&#58;11&#45;13 &#40;startColumn&#61;30&#44; endColumn&#61;1&#41;", md.stdout)
        self.assertNotIn("DO_NOT_RENDER", md.stdout)

    def test_cli_invalid_columns_preserve_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            out, md = Path(directory) / "out.json", Path(directory) / "out.md"
            for collection in ("locations", "relatedLocations"):
                for columns in ({"startColumn": True}, {"endColumn": 0}, {"endColumn": "SYNTHETIC_SECRET"},
                                {"startColumn": 5, "endColumn": 3}):
                    out.write_text("keep json")
                    md.write_text("keep markdown")
                    proc = cli("check", "-", "--output", str(out), "--markdown", str(md),
                               data=json.dumps(ranged({"startLine": 7, **columns}, collection, "index")))
                    self.assertEqual(proc.returncode, 2)
                    self.assertEqual(proc.stdout, "")
                    self.assertIn(f"/{collection}/0/physicalLocation/region/", proc.stderr)
                    self.assertNotIn("SYNTHETIC_SECRET", proc.stderr)
                    self.assertEqual(out.read_text(), "keep json")
                    self.assertEqual(md.read_text(), "keep markdown")


if __name__ == "__main__":
    unittest.main()
