"""Only explicit source lines decorate resolved primary and related paths."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulnwrench.sarifgate import InputError, Policy, compare_bytes, evaluate, markdown_summary
from .test_cli import cli
from .test_locations import document

ROOT = Path(__file__).resolve().parents[2]
MISSING = object()


def ranged(region=MISSING, collection="locations", mode="inline"):
    artifact = {"uri": "./link/../a%3Cscript%3E%7C%5Bclick%5D.py", "uriBaseId": "ROOT"}
    data = document(artifact, {"ROOT": {"uri": "file:///workspace/"}})
    run = data["runs"][0]
    run["artifacts"] = [{"location": copy.deepcopy(artifact)}]
    result = run["results"][0]
    location = result.pop("locations")[0]
    result[collection] = [location]
    physical = location["physicalLocation"]
    if mode != "inline":
        physical["artifactLocation"] = {"index": 0, **(artifact if mode == "dual" else {})}
    if region is not MISSING:
        physical["region"] = region
    return data


def entry(report, collection):
    return report["results"][0]["resolvedLocations" if collection == "locations" else
                                 "resolvedRelatedLocations"][0]


class LineRangeTests(unittest.TestCase):
    def test_explicit_ranges_inline_indexed_primary_and_related(self):
        for collection in ("locations", "relatedLocations"):
            for mode in ("inline", "index", "dual"):
                for region in ({"startLine": 7}, {"startLine": 7, "endLine": 9},
                               {"startLine": 7, "endLine": 7}, {"startLine": 1, "endLine": 2**64}):
                    with self.subTest(collection=collection, mode=mode, region=region):
                        data = ranged(region, collection, mode)
                        resolved = entry(evaluate(data), collection)
                        self.assertEqual(resolved["sourceLineRange"], region)
                        prefix = f"/runs/0/results/0/{collection}/0/physicalLocation"
                        self.assertEqual(resolved["regionSourcePointer"], prefix + "/region")
                        self.assertEqual(resolved["sourcePointer"], prefix + "/artifactLocation")
                        self.assertEqual(resolved.get("artifactSourcePointer"),
                                         "/runs/0/artifacts/0/location" if mode != "inline" else None)
                        self.assertEqual(resolved["resolvedUri"],
                                         "file:///workspace/link/../a%3Cscript%3E%7C%5Bclick%5D.py")
                        self.assertEqual(resolved["displayPath"], "/workspace/link/../a<script>|[click].py")

    def test_absent_lines_preserve_output_and_unconsumed_regions_stay_raw(self):
        for collection in ("locations", "relatedLocations"):
            expected = evaluate(ranged(collection=collection))
            for region in ({}, {"startColumn": False, "endColumn": -1, "charLength": "raw",
                                "snippet": {"text": "DO_NOT_RENDER"}}):
                data = ranged(region, collection)
                report = evaluate(data)
                self.assertEqual(entry(report, collection), entry(expected, collection))
                self.assertEqual(markdown_summary(report), markdown_summary(expected))
                self.assertEqual(report["evidence"]["document"], data)
            data = ranged(collection=collection, mode="index")
            result = data["runs"][0]["results"][0]
            result[collection].append({"physicalLocation": {"region": {"startLine": False},
                                                            "address": {"absoluteAddress": 1}}})
            result[collection][0]["physicalLocation"]["contextRegion"] = {"startLine": False}
            result["codeFlows"] = [{"region": {"startLine": False}}]
            data["runs"][0]["artifacts"][0]["region"] = {"startLine": False}
            report = evaluate(data)
            self.assertNotIn("sourceLineRange", entry(report, collection))
            self.assertEqual(report["evidence"]["document"], data)

    def test_invalid_consumed_region_contract_has_fixed_diagnostics(self):
        cases = [(v, "", "expected object") for v in (None, [], True, "SYNTHETIC_SECRET")]
        for field in ("startLine", "endLine"):
            for value in (False, True, 0, -1, 7.0, "SYNTHETIC_SECRET", None, [], {}):
                cases.append(({"startLine": 7, field: value}, "/" + field, "expected positive integer"))
        cases.extend([({"endLine": 9}, "/endLine", "requires startLine"),
                      ({"startLine": 7, "endLine": 6}, "/endLine", "must be at least startLine")])
        for collection in ("locations", "relatedLocations"):
            for mode in ("inline", "index", "dual"):
                for region, suffix, message in cases:
                    with self.subTest(collection=collection, mode=mode, region=region):
                        with self.assertRaises(InputError) as caught:
                            evaluate(ranged(region, collection, mode))
                        self.assertEqual(str(caught.exception),
                                         f"/runs/0/results/0/{collection}/0/physicalLocation/region{suffix}: {message}")

    def test_raw_evidence_no_io_or_snippet_rendering(self):
        for collection in ("locations", "relatedLocations"):
            data = ranged({"startLine": 7, "endLine": 9,
                           "byteLength": -1, "snippet": {"text": "DO_NOT_RENDER"}}, collection, "index")
            data["runs"][0]["results"][0][collection][0]["physicalLocation"]["contextRegion"] = {
                "startLine": 7, "startColumn": False}
            original = copy.deepcopy(data)
            with patch("builtins.open", side_effect=AssertionError("file access")), \
                    patch("os.open", side_effect=AssertionError("file access")), \
                    patch("os.stat", side_effect=AssertionError("file access")), \
                    patch("os.getcwd", side_effect=AssertionError("CWD access")), \
                    patch("socket.socket", side_effect=AssertionError("network access")):
                report = evaluate(data)
                md = markdown_summary(report)
            self.assertEqual(data, original)
            self.assertEqual(report["evidence"]["document"], original)
            self.assertEqual(entry(report, collection)["sourceLineRange"], {"startLine": 7, "endLine": 9})
            self.assertIn("&#60;script&#62;&#124;&#91;click&#93;&#46;py&#58;7&#45;9", md)
            self.assertNotIn("DO_NOT_RENDER", md)
            self.assertNotIn("<script>", md)
            self.assertEqual(report["results"][0]["hasLocation"], collection == "locations")
            self.assertEqual(report["totals"]["unlocated"], int(collection != "locations"))

    def test_ranges_preserve_policy_identity_and_digest_bound_pairing(self):
        for collection in ("locations", "relatedLocations"):
            before = ranged(collection=collection)
            run = before["runs"][0]
            run["tool"]["extensions"] = [{"name": "Pack", "rules": [
                {"id": "R1", "defaultConfiguration": {"level": "error"}}]}]
            result = run["results"][0]
            result["rule"] = {"index": 0, "toolComponent": {"index": 0}}
            result["baselineState"] = "unchanged"
            result["suppressions"] = [{"kind": "external", "status": "accepted"}]
            current = copy.deepcopy(before)
            current["runs"][0]["results"][0][collection][0]["physicalLocation"]["region"] = {
                "startLine": 7, "endLine": 9}
            for policy in (Policy(), Policy(level="error"), Policy(ignore_unchanged=True),
                           Policy(require_execution_success=True)):
                old, new = evaluate(before, policy), evaluate(current, policy)
                self.assertEqual(old["totals"], new["totals"])
                self.assertEqual(old["decision"], new["decision"])
                trace = copy.deepcopy(new["results"][0])
                loc = trace["resolvedLocations" if collection == "locations" else "resolvedRelatedLocations"][0]
                del loc["sourceLineRange"], loc["regionSourcePointer"]
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

    def test_cli_range_example_and_escaped_markdown(self):
        fixture = ROOT / "examples/sarif/locations/line-ranges.sarif"
        raw = fixture.read_text()
        proc = cli("check", str(fixture))
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(proc.stderr, "")
        report = json.loads(proc.stdout)
        self.assertEqual(report["evidence"]["document"], json.loads(raw))
        trace = report["results"][0]
        self.assertEqual(trace["resolvedLocations"][0]["sourceLineRange"], {"startLine": 7, "endLine": 9})
        self.assertEqual(trace["resolvedLocations"][1]["sourceLineRange"], {"startLine": 7})
        self.assertEqual(trace["resolvedRelatedLocations"][0]["sourceLineRange"], {"startLine": 11, "endLine": 11})
        stdin = cli("check", "-", data=raw)
        self.assertEqual(stdin.returncode, 1, stdin.stderr)
        self.assertEqual(stdin.stdout, proc.stdout)
        md = cli("check", "-", "--format", "markdown", data=raw)
        self.assertEqual(md.returncode, 1, md.stderr)
        self.assertIn("&#46;py&#58;7&#45;9", md.stdout)
        self.assertIn("&#46;py&#58;11&#45;11", md.stdout)
        self.assertNotIn("DO_NOT_RENDER", md.stdout)

    def test_cli_invalid_ranges_preserve_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            out, md = Path(directory) / "out.json", Path(directory) / "out.md"
            out.write_text("keep json")
            md.write_text("keep markdown")
            for collection in ("locations", "relatedLocations"):
                for region in (None, {"startLine": True}, {"startLine": 0}, {"startLine": "SYNTHETIC_SECRET"},
                               {"startLine": 7, "endLine": 6}, {"endLine": 9}):
                    proc = cli("check", "-", "--output", str(out), "--markdown", str(md),
                               data=json.dumps(ranged(region, collection, "index")))
                    self.assertEqual(proc.returncode, 2)
                    self.assertEqual(proc.stdout, "")
                    self.assertIn(f"/{collection}/0/physicalLocation/region", proc.stderr)
                    self.assertNotIn("SYNTHETIC_SECRET", proc.stderr)
                    self.assertEqual(out.read_text(), "keep json")
                    self.assertEqual(md.read_text(), "keep markdown")


if __name__ == "__main__":
    unittest.main()
