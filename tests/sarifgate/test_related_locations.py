"""Related local paths are separate display evidence, never primary locations."""

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


def related(artifact=None):
    data = document(bases={"ROOT": {"uri": "file:///workspace/"}})
    result = data["runs"][0]["results"][0]
    result.pop("locations")
    result["relatedLocations"] = [{
        "id": 3, "message": {"text": "related evidence"},
        "physicalLocation": {"artifactLocation": {"uri": "link/../a%20b.py", "uriBaseId": "ROOT"}
                             if artifact is None else artifact,
                             "region": {"startLine": 7, "snippet": {"text": "raw"}}},
        "relationships": [{"target": 3, "kinds": ["relevant"]}]}]
    return data


def resolved(uri, display, index=None, run=0, position=0, line=7, message="related evidence"):
    entry = {"sourcePointer": f"/runs/{run}/results/0/relatedLocations/{position}/physicalLocation/artifactLocation",
             "resolvedUri": uri, "displayPath": display}
    if index is not None:
        entry["artifactSourcePointer"] = f"/runs/{run}/artifacts/{index}/location"
    if line is not None:
        entry["sourceLineRange"] = {"startLine": line}
        entry["regionSourcePointer"] = f"/runs/{run}/results/0/relatedLocations/{position}/physicalLocation/region"
    if message is not None:
        entry["message"] = message
        entry["messageSourcePointer"] = f"/runs/{run}/results/0/relatedLocations/{position}/message/text"
    return entry


class RelatedLocationTests(unittest.TestCase):
    def test_related_inline_indexed_and_based_parent_paths(self):
        cases = (
            ({"uri": "file://localhost/workspace/link/../a%20b.py"},
             "file:///workspace/link/../a%20b.py", "/workspace/link/../a b.py"),
            ({"uri": "./link/../a.py"}, "link/../a.py", "link/../a.py"),
            ({"uri": "link/../a%20b.py", "uriBaseId": "ROOT"},
             "file:///workspace/link/../a%20b.py", "/workspace/link/../a b.py"),
            ({"uri": "/link/../a.py", "uriBaseId": "ROOT"},
             "file:///link/../a.py", "/link/../a.py"),
            ({"uri": "link/%2e%2e/../a%2fb%2520.py"},
             "link/%2E%2E/../a%2Fb%2520.py", "link/../../a/b%20.py"))
        for artifact, uri, display in cases:
            for mode in ("inline", "index", "dual"):
                with self.subTest(artifact=artifact, mode=mode):
                    data = related(artifact if mode == "inline" else
                                   {"index": 0, **(artifact if mode == "dual" else {})})
                    data["runs"][0]["artifacts"] = [{"location": artifact}]
                    original = copy.deepcopy(data)
                    with patch("builtins.open", side_effect=AssertionError("file access")), \
                            patch("os.open", side_effect=AssertionError("file access")), \
                            patch("os.stat", side_effect=AssertionError("file access")), \
                            patch("os.getcwd", side_effect=AssertionError("CWD access")), \
                            patch("socket.socket", side_effect=AssertionError("network access")):
                        report = evaluate(data)
                    trace = report["results"][0]
                    self.assertEqual(trace["resolvedRelatedLocations"], [
                        resolved(uri, display, 0 if mode != "inline" else None)])
                    self.assertNotIn("resolvedLocations", trace)
                    self.assertFalse(trace["hasLocation"])
                    self.assertEqual(report["totals"]["unlocated"], 1)
                    self.assertEqual(report["evidence"]["document"], original)
                    self.assertEqual(data, original)

    def test_related_and_primary_provenance_and_run_scope_stay_separate(self):
        data = related({"index": 0})
        run = data["runs"][0]
        result = run["results"][0]
        result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": "primary.py"}}}]
        result["relatedLocations"].extend([
            {"logicalLocations": [{"name": "logical"}]},
            {"physicalLocation": {"address": {"absoluteAddress": 1}}},
            {"physicalLocation": {"artifactLocation": {"uri": "last.py"}}}])
        run["artifacts"] = [{"location": {"uri": "link/../a.py", "uriBaseId": "ROOT"}}]
        second = copy.deepcopy(run)
        second["originalUriBaseIds"]["ROOT"]["uri"] = "file:///two/"
        data["runs"].append(second)
        report = evaluate(data)
        for ri, root in enumerate(("workspace", "two")):
            trace = report["results"][ri]
            self.assertTrue(trace["hasLocation"])
            self.assertEqual(trace["resolvedLocations"][0]["sourcePointer"],
                             f"/runs/{ri}/results/0/locations/0/physicalLocation/artifactLocation")
            self.assertEqual(trace["resolvedRelatedLocations"], [
                resolved(f"file:///{root}/link/../a.py", f"/{root}/link/../a.py", 0, ri),
                resolved("last.py", "last.py", run=ri, position=3, line=None, message=None)])
        self.assertEqual(report["totals"]["unlocated"], 0)

    def test_absent_empty_and_pathless_related_collections(self):
        data = related()
        result = data["runs"][0]["results"][0]
        for value in ([], [{"logicalLocations": [{"name": "module"}]}], [{}]):
            result["relatedLocations"] = value
            report = evaluate(data)
            trace = report["results"][0]
            self.assertEqual(trace.get("resolvedRelatedLocations"), [] if value else None)
            self.assertNotIn("## Related locations", markdown_summary(report))
            self.assertFalse(trace["hasLocation"])
        del result["relatedLocations"]
        self.assertNotIn("resolvedRelatedLocations", evaluate(data)["results"][0])

    def test_invalid_related_shapes_and_references_are_input_errors(self):
        invalid = []
        for value in (None, {}, "SYNTHETIC_SECRET", [None], [{"physicalLocation": []}],
                      [{"physicalLocation": {"artifactLocation": {}}}]):
            data = related()
            data["runs"][0]["results"][0]["relatedLocations"] = value
            invalid.append(data)
        for artifact in ({"uri": "https://SYNTHETIC_SECRET/a"}, {"uri": "a%2G.py"},
                         {"uri": "a%FF.py"}, {"uri": "a.py", "uriBaseId": "SYNTHETIC_SECRET"},
                         {"index": True}, {"index": -1}, {"index": 1}, {"index": 0, "uriBaseId": "ROOT"},
                         {"index": 0, "uri": "file:///workspace/a.py"},
                         {"index": 0, "uri": "file:///workspace/other/../a.py"},
                         {"index": 0, "uri": "file:///workspace/link/%2E%2E/a.py"}):
            data = related(artifact)
            data["runs"][0]["artifacts"] = [{"location": {"uri": "file:///workspace/link/../a.py"}}]
            invalid.append(data)
        for entry in ({}, {"location": {"index": 0}},
                      {"location": {"uri": "a.py", "index": 1}},
                      {"location": {"uri": "a.py"}, "parentIndex": 0}):
            data = related({"index": 0})
            data["runs"][0]["artifacts"] = [entry]
            invalid.append(data)
        for data in invalid:
            with self.subTest(data=data), self.assertRaises(InputError) as caught:
                evaluate(data)
            self.assertNotIn("SYNTHETIC_SECRET", str(caught.exception))
            self.assertRegex(str(caught.exception), r"/runs/0/(results/0/relatedLocations|artifacts)")

    def test_related_display_keeps_policy_component_identity_and_bound_pairing(self):
        before = related()
        run = before["runs"][0]
        run["tool"]["extensions"] = [{"name": "Pack", "rules": [
            {"id": "R1", "defaultConfiguration": {"level": "error"}}]}]
        result = run["results"][0]
        result["rule"] = {"index": 0, "toolComponent": {"index": 0}}
        del result["relatedLocations"]
        current = copy.deepcopy(before)
        current["runs"][0]["results"][0]["relatedLocations"] = related()["runs"][0]["results"][0]["relatedLocations"]
        for policy in (Policy(), Policy(level="error"), Policy(ignore_unchanged=True)):
            old, new = evaluate(before, policy), evaluate(current, policy)
            self.assertEqual(old["totals"], new["totals"])
            self.assertEqual(old["decision"], new["decision"])
            trace = dict(new["results"][0])
            trace.pop("resolvedRelatedLocations")
            self.assertEqual(old["results"][0], trace)
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

    def test_cli_related_json_stdin_and_escaped_markdown(self):
        fixture = ROOT / "examples/sarif/locations/related.sarif"
        raw = fixture.read_text()
        proc = cli("check", str(fixture))
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(proc.stderr, "")
        report = json.loads(proc.stdout)
        self.assertEqual(report["evidence"]["document"], json.loads(raw))
        trace = report["results"][0]
        self.assertFalse(trace["hasLocation"])
        self.assertEqual(report["totals"]["unlocated"], 1)
        self.assertEqual(len(trace["resolvedRelatedLocations"]), 3)
        self.assertEqual(trace["resolvedRelatedLocations"][1]["artifactSourcePointer"], "/runs/0/artifacts/0/location")
        stdin = cli("check", "-", data=raw)
        self.assertEqual(stdin.returncode, 1, stdin.stderr)
        self.assertEqual(stdin.stdout, proc.stdout)
        md = cli("check", "-", "--format", "markdown", data=raw)
        self.assertEqual(md.returncode, 1, md.stderr)
        self.assertIn("## Related locations", md.stdout)
        self.assertNotIn("## Locations\n", md.stdout)
        self.assertIn("workspace&#47;link&#47;&#46;&#46;&#47;a b&#46;py", md.stdout)
        self.assertIn("&#60;script&#62;&#124;&#91;click&#93;", md.stdout)
        self.assertNotIn("<script>", md.stdout)
        self.assertNotIn("[click]", md.stdout)

    def test_cli_related_errors_preserve_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            out, md = Path(directory) / "out.json", Path(directory) / "out.md"
            out.write_text("keep json")
            md.write_text("keep markdown")
            for artifact in ({"uri": "https://SYNTHETIC_SECRET/a"}, {"index": True},
                             {"index": 0, "uri": "file:///workspace/a.py"}):
                data = related(artifact)
                data["runs"][0]["artifacts"] = [{"location": {"uri": "file:///workspace/link/../a.py"}}]
                proc = cli("check", "-", "--output", str(out), "--markdown", str(md), data=json.dumps(data))
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stdout, "")
                self.assertIn("/relatedLocations/0/physicalLocation/artifactLocation", proc.stderr)
                self.assertNotIn("SYNTHETIC_SECRET", proc.stderr)
                self.assertEqual(out.read_text(), "keep json")
                self.assertEqual(md.read_text(), "keep markdown")


if __name__ == "__main__":
    unittest.main()
