"""Explicit run-local primary artifact indexes; synthetic reports, no source I/O."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulnwrench.sarifgate import InputError, Policy, check_bytes, compare_bytes, dumps, evaluate, markdown_summary
from .test_cli import cli
from .test_locations import document, location

ROOT = Path(__file__).resolve().parents[2]


def indexed(primary=None, entry=None):
    data = document({"index": 0} if primary is None else primary,
                    {"ROOT": {"uri": "file:///workspace/"},
                     "SRC": {"uri": "lib/", "uriBaseId": "ROOT"}})
    data["runs"][0]["artifacts"] = [
        {"location": {"uri": "a%20b.py", "uriBaseId": "SRC", "index": 0}}
        if entry is None else entry]
    return data


class ArtifactIndexTests(unittest.TestCase):
    def assert_invalid(self, data):
        with self.assertRaises(InputError) as caught:
            evaluate(data)
        self.assertNotIn("SYNTHETIC_SECRET", str(caught.exception))

    def test_index_only_and_inline_agreement_example(self):
        raw = (ROOT / "examples/sarif/locations/indexed.sarif").read_bytes()
        report = check_bytes(raw)
        self.assertEqual(report["decision"], "fail")
        for i, resolved in enumerate(report["results"][0]["resolvedLocations"]):
            expected = {
                "sourcePointer": f"/runs/0/results/0/locations/{i}/physicalLocation/artifactLocation",
                "artifactSourcePointer": "/runs/0/artifacts/0/location",
                "resolvedUri": "file:///workspace/lib/a%20b.py",
                "displayPath": "/workspace/lib/a b.py"}
            if i == 0:
                expected["sourceLineRange"] = {"startLine": 7}
                expected["regionSourcePointer"] = "/runs/0/results/0/locations/0/physicalLocation/region"
            self.assertEqual(resolved, expected)
        self.assertEqual(report["evidence"]["document"], json.loads(raw))
        self.assertEqual(dumps(report), dumps(check_bytes(raw)))
        self.assertIn("workspace&#47;lib&#47;a b&#46;py", markdown_summary(report))

    def test_lookup_is_run_scoped_and_preserves_input(self):
        data = indexed()
        data["runs"].append(copy.deepcopy(data["runs"][0]))
        data["runs"][1]["originalUriBaseIds"]["ROOT"]["uri"] = "file:///other/"
        original = copy.deepcopy(data)
        report = evaluate(data)
        self.assertEqual(data, original)
        self.assertEqual([r["resolvedLocations"][0]["displayPath"] for r in report["results"]],
                         ["/workspace/lib/a b.py", "/other/lib/a b.py"])
        self.assertEqual(report["results"][1]["resolvedLocations"][0]["artifactSourcePointer"],
                         "/runs/1/artifacts/0/location")
        data["runs"][1]["artifacts"] = []
        self.assert_invalid(data)  # Never borrow the first run's catalog.

    def test_relative_catalog_and_nonzero_index(self):
        data = indexed({"uri": "./a%2fb.py", "index": 1})
        data["runs"][0]["artifacts"] = [None, {"location": {"uri": "a%2Fb.py", "index": 1}}]
        result = location(data)
        self.assertEqual(result["resolvedUri"], "a%2Fb.py")
        self.assertEqual(result["displayPath"], "a/b.py")
        self.assertEqual(result["artifactSourcePointer"], "/runs/0/artifacts/1/location")

    def test_agreement_uses_each_locations_own_base(self):
        for primary in ({"index": 0, "uri": "lib/a%20b.py", "uriBaseId": "ROOT"},
                        {"index": 0, "uri": "file://localhost/workspace/lib/./a%20b.py"}):
            self.assertEqual(location(indexed(primary))["resolvedUri"],
                             "file:///workspace/lib/a%20b.py")
        for primary in ({"index": 0, "uri": "other.py", "uriBaseId": "SRC"},
                        {"index": 0, "uri": "a%20b.py", "uriBaseId": "ROOT"},
                        {"index": 0, "uri": "a%20b.py"},
                        {"index": 0, "uriBaseId": "SRC"},
                        {"index": 0, "uri": None},
                        {"index": 0, "uri": "file:///workspace/lib/A%20b.py"}):
            with self.subTest(primary=primary):
                self.assert_invalid(indexed(primary))

    def test_parent_segments_cannot_falsely_establish_agreement(self):
        # A symlink at /workspace/link could make these different artifacts.
        data = indexed({"index": 0, "uri": "file:///workspace/a.py"},
                       {"location": {"uri": "file:///workspace/link/../a.py"}})
        self.assert_invalid(data)
        data = indexed({"index": 0, "uri": "file:///workspace/other/../a.py"},
                       {"location": {"uri": "file:///workspace/link/../a.py"}})
        self.assert_invalid(data)
        data = indexed({"index": 0, "uri": "file:///workspace/link/../a.py"},
                       {"location": {"uri": "link/../a.py", "uriBaseId": "ROOT"}})
        self.assertEqual(location(data)["displayPath"], "/workspace/link/../a.py")
        # Index-only display also preserves parent segments.
        self.assertEqual(location(indexed(entry={"location": {"uri": "link/../a.py"}}))
                         ["displayPath"], "link/../a.py")

    def test_comparison_does_not_use_display_decoding_for_equivalence(self):
        for uri in ("a/b.py", "a%252Fb.py", "a%2F./b.py", "%61%2Fb.py"):
            with self.subTest(uri=uri):
                self.assert_invalid(indexed({"uri": uri, "index": 0},
                                            {"location": {"uri": "a%2Fb.py"}}))

    def test_dot_only_agreement_keeps_relative_root_and_directory_boundaries(self):
        for primary, catalog, agrees in (
                ("./link/./../a.py", "link/../a.py", True),
                ("/link/../a.py", "link/../a.py", False),
                (".//link/../a.py", "/link/../a.py", False),
                ("link/../a.py", "link/%2E%2E/a.py", False),
                ("link/../a.py", "link%2F../a.py", False),
                ("link/../a.py", "./link/./../a.py", True),
                ("link/../dir/.", "link/../dir/", True),
                ("link/../dir/.", "link/../dir", False)):
            data = indexed({"index": 0, "uri": primary}, {"location": {"uri": catalog}})
            with self.subTest(primary=primary, catalog=catalog):
                if agrees:
                    self.assertIn("..", location(data)["resolvedUri"])
                else:
                    self.assert_invalid(data)

    def test_invalid_indexes_catalogs_and_selected_locations(self):
        for index in (True, False, -1, -2, 1, 1.0, "0", None):
            with self.subTest(index=index):
                self.assert_invalid(indexed({"index": index}))
                self.assert_invalid(indexed({"uri": "file:///workspace/lib/a%20b.py", "index": index}))
        for catalog in (None, {}, "SYNTHETIC_SECRET", [], [None], [[]], [{}],
                        [{"location": None}], [{"location": {}}], [{"location": {"index": 0}}],
                        [{"location": {"uri": "a%SYNTHETIC_SECRET"}}],
                        [{"location": {"uri": "https://SYNTHETIC_SECRET/a"}}],
                        [{"location": {"uri": "a.py", "uriBaseId": "SYNTHETIC_SECRET"}}]):
            data = indexed()
            data["runs"][0]["artifacts"] = catalog
            with self.subTest(catalog=catalog):
                self.assert_invalid(data)
        data = indexed()
        del data["runs"][0]["artifacts"]
        self.assert_invalid(data)

    def test_catalog_self_index_is_checked_without_recursion(self):
        for index in (True, -1, 1, "0", None):
            with self.subTest(index=index):
                self.assert_invalid(indexed(entry={"location": {"uri": "a.py", "index": index}}))
        data = indexed(entry={"location": {"uri": "a.py", "index": 1}})
        data["runs"][0]["artifacts"].append({"location": {"uri": "a.py", "index": 0}})
        self.assert_invalid(data)
        self.assertEqual(location(indexed(entry={"location": {"uri": "a.py", "index": 0}}))["resolvedUri"],
                         "a.py")

    def test_selected_container_or_byte_offset_semantics_are_rejected(self):
        for key in ("parentIndex", "offset", "length"):
            for value in (0, -1, None, "SYNTHETIC_SECRET"):
                data = indexed()
                data["runs"][0]["artifacts"][0][key] = value
                with self.subTest(key=key, value=value):
                    self.assert_invalid(data)
                    data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "file:///workspace/lib/a%20b.py"
                    self.assert_invalid(data)

    def test_unselected_entries_and_inline_only_catalogs_remain_evidence(self):
        data = indexed(entry={"location": {"uri": "plain.py"}, "contents": {"text": "retained"}})
        data["runs"][0]["artifacts"].append({"parentIndex": 0, "location": {"index": 99}})
        self.assertEqual(location(data)["resolvedUri"], "plain.py")
        data = document()
        data["runs"][0]["artifacts"] = "unconsumed"
        self.assertEqual(location(data)["resolvedUri"], "plain.py")

    def test_no_file_or_network_access_and_baseline_identity_unchanged(self):
        current, before = indexed(), document({"uri": "old.py"})
        raw = json.dumps(current).encode()
        with patch("builtins.open", side_effect=AssertionError("file access")), \
                patch("os.open", side_effect=AssertionError("file access")), \
                patch("os.stat", side_effect=AssertionError("file access")), \
                patch("socket.socket", side_effect=AssertionError("network access")):
            report = check_bytes(raw)
            self.assertEqual(report["results"][0]["resolvedLocations"][0]["displayPath"], "/workspace/lib/a b.py")
            self.assertEqual(compare_bytes(raw, json.dumps(before).encode(), fingerprint="primary/v1")
                             ["baselineComparison"]["counts"]["retained"], 1)
            self.assert_invalid(indexed({"index": 99}))
        for policy in (Policy(), Policy(level="error")):
            a, b = evaluate(current, policy), evaluate(before, policy)
            for key in ("decision", "actionable", "totals"):
                self.assertEqual(a[key], b[key])
        current["runs"][0]["results"][0]["suppressions"] = [{"kind": "external", "status": "accepted"}]
        self.assertEqual(evaluate(current)["decision"], "pass")


class ArtifactIndexCliTests(unittest.TestCase):
    def test_json_markdown_and_stdin(self):
        raw = (ROOT / "examples/sarif/locations/indexed.sarif").read_text()
        proc = cli("check", "examples/sarif/locations/indexed.sarif")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(proc.stderr, "")
        self.assertEqual(json.loads(proc.stdout)["results"][0]["resolvedLocations"][0]["displayPath"],
                         "/workspace/lib/a b.py")
        self.assertEqual(cli("check", "-", data=raw).stdout, proc.stdout)
        md = cli("check", "-", "--format", "markdown", data=raw)
        self.assertEqual(md.returncode, 1, md.stderr)
        self.assertIn("workspace&#47;lib&#47;a b&#46;py", md.stdout)

    def test_negative_contract_preserves_both_outputs(self):
        invalid = [indexed({"index": True}), indexed({"index": 9}),
                   indexed({"uri": "SYNTHETIC_SECRET.py", "index": 0}),
                   indexed(entry={"location": {"index": 0}}),
                   json.loads((ROOT / "examples/sarif/locations/indexed-container.sarif").read_bytes())]
        for uri in ("file:///workspace/a.py", "file:///workspace/other/../a.py"):
            invalid.append(indexed({"index": 0, "uri": uri},
                                   {"location": {"uri": "file:///workspace/link/../a.py"}}))
        with tempfile.TemporaryDirectory() as directory:
            out, md = Path(directory) / "out.json", Path(directory) / "out.md"
            out.write_text("keep json")
            md.write_text("keep markdown")
            for data in invalid:
                proc = cli("check", "-", "--output", str(out), "--markdown", str(md), data=json.dumps(data))
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stdout, "")
                self.assertNotIn("SYNTHETIC_SECRET", proc.stderr)
                self.assertEqual(out.read_text(), "keep json")
                self.assertEqual(md.read_text(), "keep markdown")
