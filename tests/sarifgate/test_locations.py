"""Local SARIF 2.1.0 URI display: synthetic integration and failure fixtures."""

import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from vulnwrench.sarifgate import InputError, Policy, check_bytes, compare_bytes, dumps, evaluate, markdown_summary

ROOT = Path(__file__).resolve().parents[2]


def document(artifact=None, bases=None):
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Synthetic"}},
        "originalUriBaseIds": {} if bases is None else bases,
        "invocations": [{"executionSuccessful": True}],
        "results": [{"ruleId": "R1", "message": {"text": "Synthetic"},
                     "fingerprints": {"primary/v1": "A"},
                     "locations": [{"physicalLocation": {"artifactLocation":
                                    {"uri": "plain.py"} if artifact is None else artifact}}]}]}]}


def location(data):
    return evaluate(data)["results"][0]["resolvedLocations"][0]


class LocationTests(unittest.TestCase):
    def test_parent_segments_survive_inline_indexed_and_based_resolution(self):
        bases = {"ROOT": {"uri": "file:///workspace/"},
                 "SRC": {"uri": "src/./", "uriBaseId": "ROOT"}}
        cases = (
            ({"uri": "file://localhost/workspace/link/../a.py"},
             "file:///workspace/link/../a.py", "/workspace/link/../a.py"),
            ({"uri": "./link/../a.py"}, "link/../a.py", "link/../a.py"),
            ({"uri": "../link/../../a.py"}, "../link/../../a.py", "../link/../../a.py"),
            ({"uri": "/link/../a.py"}, "/link/../a.py", "/link/../a.py"),
            ({"uri": "link/../a.py", "uriBaseId": "SRC"},
             "file:///workspace/src/link/../a.py", "/workspace/src/link/../a.py"),
            ({"uri": "/link/../a.py", "uriBaseId": "SRC"},
             "file:///link/../a.py", "/link/../a.py"),
            ({"uri": "/a/..//host/a", "uriBaseId": "ROOT"},
             "file:///a/..//host/a", "/a/..//host/a"),
            ({"uri": "link/%2e%2e/../a%2fb%2520.py"},
             "link/%2E%2E/../a%2Fb%2520.py", "link/../../a/b%20.py"),
            ({"uri": "./a/./../."}, "a/../", "a/../"),
            ({"uri": "./"}, "./", "./"),
            ({"uri": "."}, ".", "."),
            ({"uri": ".//link/../a.py"}, ".//link/../a.py", ".//link/../a.py"),
            ({"uri": "./a:b/../c.py"}, "./a:b/../c.py", "./a:b/../c.py"))
        for artifact, uri, display in cases:
            for indexed in (False, True):
                with self.subTest(artifact=artifact, indexed=indexed):
                    with patch("builtins.open", side_effect=AssertionError("file access")), \
                            patch("os.open", side_effect=AssertionError("file access")), \
                            patch("os.stat", side_effect=AssertionError("file access")), \
                            patch("os.getcwd", side_effect=AssertionError("CWD access")), \
                            patch("socket.socket", side_effect=AssertionError("network access")):
                        data = document({"index": 0} if indexed else artifact, bases)
                        if indexed:
                            data["runs"][0]["artifacts"] = [{"location": artifact}]
                        physical = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
                        physical["region"] = {"startLine": 7, "snippet": {"text": "raw"}}
                        original = copy.deepcopy(data)
                        report = evaluate(data)
                        resolved = report["results"][0]["resolvedLocations"][0]
                        self.assertEqual(resolved["resolvedUri"], uri)
                        self.assertEqual(resolved["displayPath"], display)
                        self.assertEqual(resolved["sourcePointer"],
                                         "/runs/0/results/0/locations/0/physicalLocation/artifactLocation")
                        self.assertEqual(resolved.get("artifactSourcePointer"),
                                         "/runs/0/artifacts/0/location" if indexed else None)
                        self.assertEqual(report["evidence"]["document"], original)
                        self.assertEqual(data, original)

    def test_parent_display_preserves_component_fingerprint_and_digest_pairing(self):
        before = document({"uri": "old.py"})
        run = before["runs"][0]
        run["tool"]["extensions"] = [{"name": "Pack", "rules": [
            {"id": "R1", "defaultConfiguration": {"level": "error"}}]}]
        run["results"][0]["rule"] = {"index": 0, "toolComponent": {"index": 0}}
        current = copy.deepcopy(before)
        current["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = {
            "uri": "file:///workspace/link/../a.py"}
        old, new = (json.dumps(d).encode() for d in (before, current))
        manifest = {side: [{"runIndex": 0, "pairId": "only"}] for side in ("baseline", "current")}
        manifest["inputSha256"] = {"baseline": hashlib.sha256(old).hexdigest(),
                                   "current": hashlib.sha256(new).hexdigest()}
        report = compare_bytes(new, old, fingerprint="primary/v1", run_pairing=manifest)
        view = report["baselineComparison"]
        self.assertTrue(view["runPairing"]["applied"])
        self.assertEqual(view["counts"], {"retained": 1, "newly_observed": 0, "absent": 0, "ambiguous": 0})
        self.assertEqual(report["decision"], "fail")
        trace = report["results"][0]
        for key in ("level", "levelSource", "levelSourcePointer", "ruleComponent", "ruleSourcePointer",
                    "blocking", "eligible", "reasons"):
            self.assertEqual(trace[key], evaluate(before)["results"][0][key])
        self.assertEqual(trace["resolvedLocations"][0]["displayPath"], "/workspace/link/../a.py")
        stale = compare_bytes(new + b" ", old, fingerprint="primary/v1", run_pairing=manifest)
        self.assertFalse(stale["baselineComparison"]["runPairing"]["applied"])

    def test_nested_example_and_raw_evidence(self):
        data = (ROOT / "examples/sarif/locations/nested.sarif").read_bytes()
        original = json.loads(data)
        report = check_bytes(data)
        self.assertEqual(report["evidence"]["document"], original)
        self.assertEqual(report["decision"], "fail")
        self.assertEqual(report["results"][0]["resolvedLocations"], [
            {"sourcePointer": "/runs/0/results/0/locations/0/physicalLocation/artifactLocation",
             "resolvedUri": "file:///workspace/src/../lib/a%20b.py", "displayPath": "/workspace/src/../lib/a b.py",
             "sourceLineRange": {"startLine": 7},
             "regionSourcePointer": "/runs/0/results/0/locations/0/physicalLocation/region"},
            {"sourcePointer": "/runs/0/results/0/locations/1/physicalLocation/artifactLocation",
             "resolvedUri": "plain.py", "displayPath": "plain.py"}])
        self.assertIn("workspace&#47;src&#47;&#46;&#46;&#47;lib&#47;a b&#46;py", markdown_summary(report))
        self.assertEqual(dumps(report), dumps(check_bytes(data)))

    def test_relative_paths_remain_relative_and_escapes_decode_once(self):
        for uri, resolved, display in (
                ("./src/../plain.py", "src/../plain.py", "src/../plain.py"),
                ("../../a.py", "../../a.py", "../../a.py"),
                ("a%2520b.py", "a%2520b.py", "a%20b.py"),
                ("a%23b%3fc.py", "a%23b%3Fc.py", "a#b?c.py"),
                ("src/%E2%98%83.py", "src/%E2%98%83.py", "src/☃.py"),
                ("a%2Fb.py", "a%2Fb.py", "a/b.py"),
                ("./%2e%2e/a.py", "%2E%2E/a.py", "../a.py"),
                ("./a:b.py", "./a:b.py", "./a:b.py"),
                ("src/../file:/a.py", "src/../file:/a.py", "src/../file:/a.py"),
                ("file://localhost/C:/src/../a%20b.py", "file:///C:/src/../a%20b.py", "/C:/src/../a b.py"),
                ("file:/src/a.py", "file:///src/a.py", "/src/a.py")):
            with self.subTest(uri=uri):
                resolved_location = location(document({"uri": uri}))
                self.assertEqual(resolved_location["resolvedUri"], resolved)
                self.assertEqual(resolved_location["displayPath"], display)

    def test_shared_nested_bases_are_order_independent_and_run_scoped(self):
        bases = {"SRC": {"uri": "src/", "uriBaseId": "ROOT"},
                 "ROOT": {"uri": "file:///one/"},
                 "TEST": {"uri": "tests/", "uriBaseId": "SRC"}}
        data = document({"uri": "a.py", "uriBaseId": "TEST"}, bases)
        second = copy.deepcopy(data["runs"][0])
        second["originalUriBaseIds"]["ROOT"]["uri"] = "file:///two/"
        data["runs"].append(second)
        original = copy.deepcopy(data)
        report = evaluate(data)
        self.assertEqual([r["resolvedLocations"][0]["displayPath"] for r in report["results"]],
                         ["/one/src/tests/a.py", "/two/src/tests/a.py"])
        self.assertEqual(data, original)

    def test_long_base_chain_does_not_require_python_recursion(self):
        bases = {"B0": {"uri": "file:///root/"}}
        bases.update({f"B{i}": {"uri": "s/", "uriBaseId": f"B{i-1}"} for i in range(1, 1100)})
        self.assertEqual(location(document({"uri": "a.py", "uriBaseId": "B1099"}, bases))["displayPath"],
                         "/root/" + "s/" * 1099 + "a.py")

    def test_logical_and_address_only_locations_remain_located(self):
        data = document()
        data["runs"][0]["results"][0]["locations"] = [
            {"logicalLocations": [{"name": "module"}]}, {"physicalLocation": {"address": {"absoluteAddress": 1}}}]
        report = evaluate(data)
        self.assertTrue(report["results"][0]["hasLocation"])
        self.assertEqual(report["results"][0]["resolvedLocations"], [])
        self.assertEqual(report["totals"]["unlocated"], 0)

    def test_resolution_does_not_change_gate_or_baseline_matching(self):
        current = document({"uri": "moved.py"})
        before = document({"uri": "old.py"})
        encoded = lambda doc: json.dumps(doc).encode()
        view = compare_bytes(encoded(current), encoded(before), fingerprint="primary/v1")
        self.assertEqual(view["baselineComparison"]["counts"]["retained"], 1)
        for policy in (Policy(), Policy(level="error")):
            report = evaluate(current, policy)
            unlocated = copy.deepcopy(current)
            del unlocated["runs"][0]["results"][0]["locations"]
            expected = evaluate(unlocated, policy)
            for key in ("level", "levelSource", "blocking", "eligible", "reasons"):
                self.assertEqual(report["results"][0][key], expected["results"][0][key])
        current["runs"][0]["results"][0]["suppressions"] = [{"kind": "external", "status": "accepted"}]
        self.assertEqual(evaluate(current)["decision"], "pass")

    def test_no_file_or_network_access_during_resolution(self):
        data = document({"uri": "file:///definitely-not-present/a.py"})
        with patch("builtins.open", side_effect=AssertionError("file access")), \
                patch("os.open", side_effect=AssertionError("file access")), \
                patch("os.stat", side_effect=AssertionError("file access")), \
                patch("socket.socket", side_effect=AssertionError("network access")):
            self.assertEqual(location(data)["displayPath"], "/definitely-not-present/a.py")
            with self.assertRaises(InputError):
                evaluate(document({"uri": "https://example.invalid/a.py"}))

    def test_markdown_path_is_plain_escaped_text(self):
        report = evaluate(document({"uri": "a%3Cscript%3E%7C%5Bclick%5D.py"}))
        markdown = markdown_summary(report)
        self.assertIn("a&#60;script&#62;&#124;&#91;click&#93;&#46;py", markdown)
        self.assertNotIn("<script>", markdown)
        self.assertNotIn("[click]", markdown)

    def assert_invalid(self, data):
        with self.assertRaises(InputError) as caught:
            evaluate(data)
        self.assertNotIn("SYNTHETIC_SECRET", str(caught.exception))

    def test_cycles_missing_or_redacted_bases_fail(self):
        self.assert_invalid(json.loads((ROOT / "examples/sarif/locations/cycle.sarif").read_bytes()))
        for bases in ({}, {"A": {}}, {"A": {"uri": "src/"}},
                      {"A": {"uri": "src/", "uriBaseId": "A"}},
                      {"A": {"uri": "src/", "uriBaseId": "missing"}}):
            with self.subTest(bases=bases):
                self.assert_invalid(document({"uri": "a.py", "uriBaseId": "A"}, bases))

    def test_invalid_base_shapes_and_directory_references_fail_even_if_unused(self):
        for bases in (None, [], "SYNTHETIC_SECRET", {"SYNTHETIC_SECRET": None},
                      {"SYNTHETIC_SECRET": {"uri": "file:///root"}},
                      {"A": {"uri": "file:///root//"}},
                      {"A": {"uri": "/src/", "uriBaseId": "ROOT"}, "ROOT": {"uri": "file:///"}},
                      {"A": {"uri": "file:///a/../"}},
                      {"A": {"uri": "file:///root/?q"}},
                      {"A": {"uri": "file:///root/", "uriBaseId": "B"}},
                      {"A": {"uri": "https://example.invalid/"}},
                      {"A": {"uri": "file:///root/", "index": 0}}):
            data = document()
            data["runs"][0]["originalUriBaseIds"] = bases
            with self.subTest(bases=bases):
                self.assert_invalid(data)

    def test_unsupported_and_malformed_artifact_references_fail(self):
        for uri in ("https://SYNTHETIC_SECRET/a", "ftp://host/a", "data:text/plain,a", "urn:example:a",
                    "file://host/a", "//host/a", "file:relative", "file:/.//host/a", "C:\\a.py", "a b.py", "a\\b.py",
                    "a%", "a%2G.py", "a%FF.py", "a%00.py", "a\n.py", "a?query", "a#fragment",
                    "a[0].py", "☃.py", "", None):
            with self.subTest(uri=uri):
                self.assert_invalid(document({"uri": uri}))
        for artifact in (None, [], {}, {"index": 0}, {"uri": "a.py", "index": 0},
                         {"uri": "a.py", "uriBaseId": None}, {"uri": "a.py", "uriBaseId": []},
                         {"uri": "file:///a.py", "uriBaseId": "ROOT"}):
            data = document()
            data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = artifact
            with self.subTest(artifact=artifact):
                self.assert_invalid(data)


if __name__ == "__main__":
    unittest.main()
