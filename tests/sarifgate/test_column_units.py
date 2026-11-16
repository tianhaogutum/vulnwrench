"""Only explicit run declarations label resolved source columns; no conversion."""

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
from .test_primary_messages import PAYLOAD, ESCAPED

UNITS = ("utf16CodeUnits", "unicodeCodePoints")
INVALID = (None, True, False, 0, 1.5, [], {}, "", "UTF16CodeUnits", "SYNTHETIC_SECRET<script>|\n")
ERROR = "expected one of unicodeCodePoints, utf16CodeUnits"


class ColumnUnitTests(unittest.TestCase):
    def test_declared_units_only_on_columns_with_run_provenance(self):
        for collection in ("locations", "relatedLocations"):
            for mode in ("inline", "index", "dual"):
                for unit in UNITS:
                    for columns in ({"startColumn": 3}, {"endColumn": 5},
                                    {"startColumn": 30, "endColumn": 1}):
                        with self.subTest(collection=collection, mode=mode, unit=unit, columns=columns):
                            data = ranged({"startLine": 7, "endLine": 9, **columns}, collection, mode)
                            data["runs"][0]["results"][0][collection][0]["message"] = {"text": PAYLOAD}
                            absent = evaluate(data)
                            data["runs"][0]["columnKind"] = unit
                            report = evaluate(data)
                            resolved = copy.deepcopy(entry(report, collection))
                            self.assertEqual(resolved.pop("sourceColumnUnit", None), unit)
                            self.assertEqual(resolved.pop("columnKindSourcePointer", None), "/runs/0/columnKind")
                            self.assertEqual(resolved, entry(absent, collection))
                            self.assertNotIn("/runs/0/columnKind", report["evidence"]["uninterpretedFields"])
                            self.assertEqual(report["evidence"]["document"], data)
                            self.assertEqual(report["totals"], absent["totals"])
                            md = markdown_summary(report)
                            self.assertIn("| Column unit | Unit source pointer | Message |", md)
                            self.assertIn(f"| {unit} | &#47;runs&#47;0&#47;columnKind | {ESCAPED} |", md)
                            self.assertNotIn("<script>", md)

    def test_omission_and_unconsumed_declarations_across_runs(self):
        for value in (*UNITS, *INVALID):
            for collection in ("locations", "relatedLocations"):
                for region in (MISSING, {}, {"startLine": 7}, {"startColumn": False}):
                    data = ranged(region, collection)
                    absent = evaluate(data)
                    run = data["runs"][0]
                    run["columnKind"] = value
                    result = run["results"][0]
                    result[collection].append({"physicalLocation": {"region": {
                        "startLine": 1, "startColumn": 3}}, "message": {"id": "raw"}})
                    run["artifacts"][0]["region"] = {"startLine": 1, "endColumn": 4}
                    result[collection][0]["physicalLocation"]["contextRegion"] = {
                        "startLine": 1, "startColumn": 4}
                    result["codeFlows"] = [{"columnKind": value, "region": {"startLine": 1, "startColumn": 4}}]
                    # A different run consumes a valid declaration; it cannot
                    # validate or label this run's uninterpreted metadata.
                    other = ranged({"startLine": 1, "endColumn": 4})["runs"][0]
                    other["columnKind"] = "utf16CodeUnits"
                    data["runs"].append(other)
                    original = copy.deepcopy(data)
                    with patch("builtins.open", side_effect=AssertionError("file access")), \
                            patch("os.open", side_effect=AssertionError("file access")), \
                            patch("os.stat", side_effect=AssertionError("file access")), \
                            patch("os.getcwd", side_effect=AssertionError("CWD access")), \
                            patch("socket.socket", side_effect=AssertionError("network access")):
                        report = evaluate(data)
                        md = markdown_summary(report)
                    self.assertEqual(entry(report, collection), entry(absent, collection))
                    self.assertIn("/runs/0/columnKind", report["evidence"]["uninterpretedFields"])
                    self.assertNotIn("/runs/1/columnKind", report["evidence"]["uninterpretedFields"])
                    self.assertEqual(report["results"][1]["resolvedLocations"][0]["columnKindSourcePointer"],
                                     "/runs/1/columnKind")
                    self.assertEqual(data, original)
                    self.assertEqual(report["evidence"]["document"], original)
                    self.assertNotIn("SYNTHETIC_SECRET", md)
        # Omitted declaration with explicit columns adds no unit or table columns.
        report = evaluate(ranged({"startLine": 1, "startColumn": 3}))
        self.assertNotIn("sourceColumnUnit", entry(report, "locations"))
        self.assertNotIn("Column unit", markdown_summary(report))
        for results in ([], MISSING):
            data = ranged()
            run = data["runs"][0]
            run["columnKind"] = {"raw": True}
            if results is MISSING:
                del run["results"]
            else:
                run["results"] = results
            self.assertIn("/runs/0/columnKind", evaluate(data)["evidence"]["uninterpretedFields"])

    def test_invalid_consumed_declarations_are_sanitized(self):
        for collection in ("locations", "relatedLocations"):
            for mode in ("inline", "index", "dual"):
                for value in INVALID:
                    with self.subTest(collection=collection, mode=mode, value=value):
                        data = ranged({"startLine": 7, "endColumn": 5}, collection, mode)
                        data["runs"][0]["columnKind"] = value
                        with self.assertRaises(InputError) as caught:
                            evaluate(data)
                        self.assertEqual(str(caught.exception), "/runs/0/columnKind: " + ERROR)

    def test_markdown_mixed_rows_runs_and_escaping(self):
        data = ranged({"startLine": 7, "startColumn": 3})
        run = data["runs"][0]
        run["columnKind"] = UNITS[0]
        location = run["results"][0]["locations"][0]
        run["results"][0]["locations"].append(copy.deepcopy(location))
        del run["results"][0]["locations"][1]["physicalLocation"]["region"]["startColumn"]
        run["results"][0]["relatedLocations"] = [copy.deepcopy(location)]
        for unit in (UNITS[1], MISSING):
            other = copy.deepcopy(run)
            if unit is MISSING:
                del other["columnKind"]
            else:
                other["columnKind"] = unit
            data["runs"].append(other)
        report = evaluate(data)
        md = markdown_summary(report)
        self.assertEqual(md.count("| Column unit | Unit source pointer |"), 2)
        for i, unit in enumerate(UNITS):
            for field in ("resolvedLocations", "resolvedRelatedLocations"):
                resolved = report["results"][i][field][0]
                self.assertEqual(resolved["sourceColumnUnit"], unit)
                self.assertEqual(resolved["columnKindSourcePointer"], f"/runs/{i}/columnKind")
        self.assertIn(" |  |  |", md)
        # Defense in depth: even hand-built reports use the plain-text escaper.
        entry(report, "locations")["sourceColumnUnit"] = "<b>|[unit]\n"
        rendered = markdown_summary(report)
        self.assertIn("&#60;b&#62;&#124;&#91;unit&#93; ", rendered)
        self.assertNotIn("<b>", rendered)

    def test_units_preserve_policy_component_fingerprints_and_digest_pairing(self):
        for collection in ("locations", "relatedLocations"):
            for suppressed in (False, True):
                before = ranged({"startLine": 7, "startColumn": 3}, collection, "dual")
                run = before["runs"][0]
                run["tool"]["extensions"] = [{"name": "Pack", "rules": [
                    {"id": "R1", "defaultConfiguration": {"level": "error"}}]}]
                result = run["results"][0]
                result["rule"] = {"index": 0, "toolComponent": {"index": 0}}
                result["baselineState"] = "unchanged"
                if suppressed:
                    result["suppressions"] = [{"kind": "external", "status": "accepted"}]
                after = copy.deepcopy(before)
                after["runs"][0]["columnKind"] = UNITS[0]
                for policy in (Policy(), Policy(level="error"), Policy(ignore_unchanged=True),
                               Policy(require_execution_success=True)):
                    old, new = evaluate(before, policy), evaluate(after, policy)
                    self.assertEqual(old["totals"], new["totals"])
                    self.assertEqual(old["decision"], new["decision"])
                    resolved = entry(new, collection)
                    del resolved["sourceColumnUnit"], resolved["columnKindSourcePointer"]
                    self.assertEqual(old["results"], new["results"])
                old, new = (json.dumps(d).encode() for d in (before, after))
                manifest = {side: [{"runIndex": 0, "pairId": "only"}] for side in ("baseline", "current")}
                manifest["inputSha256"] = {"baseline": hashlib.sha256(old).hexdigest(),
                                           "current": hashlib.sha256(new).hexdigest()}
                report = compare_bytes(new, old, fingerprint="primary/v1", run_pairing=manifest)
                self.assertTrue(report["baselineComparison"]["runPairing"]["applied"])
                self.assertEqual(report["baselineComparison"]["counts"],
                                 {"retained": 1, "newly_observed": 0, "absent": 0, "ambiguous": 0})
                stale = compare_bytes(new + b" ", old, fingerprint="primary/v1", run_pairing=manifest)
                self.assertFalse(stale["baselineComparison"]["runPairing"]["applied"])

    def test_cli_invalid_units_preserve_both_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            out, md = Path(directory) / "out.json", Path(directory) / "out.md"
            for collection in ("locations", "relatedLocations"):
                for value in INVALID:
                    data = ranged({"startLine": 7, "startColumn": 3}, collection)
                    data["runs"][0]["columnKind"] = value
                    out.write_text("keep json")
                    md.write_text("keep markdown")
                    proc = cli("check", "-", "--output", str(out), "--markdown", str(md), data=json.dumps(data))
                    self.assertEqual(proc.returncode, 2)
                    self.assertEqual(proc.stdout, "")
                    self.assertEqual(proc.stderr, "vulnwrench sarif: /runs/0/columnKind: " + ERROR + "\n")
                    self.assertEqual(out.read_text(), "keep json")
                    self.assertEqual(md.read_text(), "keep markdown")


if __name__ == "__main__":
    unittest.main()
