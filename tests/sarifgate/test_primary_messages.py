"""Optional primary messages use the existing literal-only display contract."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulnwrench.sarifgate import InputError, Policy, compare_bytes, evaluate, markdown_summary
from .test_cli import cli
from .test_line_ranges import ranged

ROOT = Path(__file__).resolve().parents[2]
PREFIX = "/runs/0/results/0/locations/0/message"
PAYLOAD = "<script>|[click](https://invalid)\nnext\rline\t{0} & &#124;"
ESCAPED = ("&#60;script&#62;&#124;&#91;click&#93;&#40;https&#58;&#47;&#47;invalid&#41;"
           " next line &#123;0&#125; &#38; &#38;&#35;124&#59;")


def with_message(message, mode="inline", region=None):
    data = ranged({"startLine": 7, "endLine": 9} if region is None else region,
                  "locations", mode)
    data["runs"][0]["results"][0]["locations"][0]["message"] = message
    return data


def entry(report):
    return report["results"][0]["resolvedLocations"][0]


class PrimaryMessageTests(unittest.TestCase):
    def test_literals_preference_provenance_and_escaping(self):
        for mode in ("inline", "index", "dual"):
            for message, selected in (({"text": PAYLOAD}, "text"),
                                      ({"markdown": PAYLOAD}, "markdown"),
                                      ({"text": PAYLOAD, "markdown": "DO_NOT_RENDER",
                                        "id": "ignored", "arguments": ["DO_NOT_EXPAND"]}, "text")):
                with self.subTest(mode=mode, selected=selected, message=message):
                    data = with_message(message, mode)
                    original = copy.deepcopy(data)
                    with patch("builtins.open", side_effect=AssertionError("file access")), \
                            patch("os.open", side_effect=AssertionError("file access")), \
                            patch("os.stat", side_effect=AssertionError("file access")), \
                            patch("os.getcwd", side_effect=AssertionError("CWD access")), \
                            patch("socket.socket", side_effect=AssertionError("network access")):
                        report = evaluate(data)
                        md = markdown_summary(report)
                    resolved = entry(report)
                    self.assertEqual(resolved["message"], PAYLOAD)
                    self.assertEqual(resolved["messageSourcePointer"], PREFIX + "/" + selected)
                    self.assertEqual(resolved["sourceLineRange"], {"startLine": 7, "endLine": 9})
                    self.assertEqual(resolved["regionSourcePointer"], PREFIX.removesuffix("message") +
                                     "physicalLocation/region")
                    self.assertEqual(resolved.get("artifactSourcePointer"),
                                     "/runs/0/artifacts/0/location" if mode != "inline" else None)
                    self.assertEqual(resolved["resolvedUri"],
                                     "file:///workspace/link/../a%3Cscript%3E%7C%5Bclick%5D.py")
                    self.assertIn("| Run/result | Path | Source pointer | Message |", md)
                    self.assertIn("| " + ESCAPED + " |", md)
                    self.assertNotIn("<script>", md)
                    self.assertNotIn("DO_NOT_RENDER", md)
                    self.assertNotIn("DO_NOT_EXPAND", md)
                    self.assertEqual(data, original)
                    self.assertEqual(report["evidence"]["document"], original)

    def test_absent_messages_keep_legacy_output_and_mixed_rows_stay_aligned(self):
        data = ranged(collection="locations")
        result = data["runs"][0]["results"][0]
        first = result["locations"][0]
        report = evaluate(data)
        self.assertNotIn("message", entry(report))
        self.assertNotIn("messageSourcePointer", entry(report))
        md = markdown_summary(report)
        self.assertIn("| Run/result | Path | Source pointer |\n| --- | --- | --- |", md)
        first["message"] = {"markdown": "indexed"}
        result["locations"].insert(0, {"logicalLocations": [], "message": {"id": "raw"}})
        result["locations"].append({"physicalLocation": {"artifactLocation": {"uri": "bare.py"}}})
        result["relatedLocations"] = [{"physicalLocation": {"artifactLocation": {"uri": "related.py"}},
                                       "message": {"text": "RELATED_LITERAL"}}]
        report = evaluate(data)
        self.assertEqual(entry(report)["messageSourcePointer"], PREFIX.replace("/0/message", "/1/message") +
                         "/markdown")
        self.assertNotIn("sourceLineRange", entry(report))
        self.assertEqual(report["results"][0]["resolvedRelatedLocations"][0]["message"], "RELATED_LITERAL")
        md = markdown_summary(report)
        self.assertIn("RELATED&#95;LITERAL", md)
        table = md.split("## Locations\n", 1)[1].split("## Related locations", 1)[0]
        rows = [line for line in table.splitlines() if line.startswith("| ")]
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(line.count("|") == 5 for line in rows))
        self.assertTrue(rows[-1].endswith(" |  |"))
        del first["message"]
        # Other unconsumed data and a pathless id-only message add no Message column.
        primary_table = markdown_summary(evaluate(data)).split("## Locations\n", 1)[1].split("## Related locations", 1)[0]
        self.assertNotIn("| Source pointer | Message |", primary_table)

    def test_invalid_consumed_messages_have_fixed_diagnostics(self):
        cases = [(v, "", "expected object") for v in (None, [], True, "SYNTHETIC_SECRET")]
        cases += [(v, "", "text or markdown required; id-only messages are unsupported")
                  for v in ({}, {"id": "SYNTHETIC_SECRET"}, {"arguments": ["raw"]})]
        for field in ("text", "markdown", "id"):
            for value in (None, [], {}, True, 7, ""):
                cases.append(({"text": "valid", "markdown": "valid", field: value},
                              "/" + field, "expected nonempty string"))
        for mode in ("inline", "index", "dual"):
            for message, suffix, reason in cases:
                with self.subTest(mode=mode, message=message):
                    with self.assertRaises(InputError) as caught:
                        evaluate(with_message(message, mode))
                    self.assertEqual(str(caught.exception), PREFIX + suffix + ": " + reason)
        self.assertEqual(entry(evaluate(with_message({"text": " \n\t"})))["message"], " \n\t")

    def test_pathless_messages_remain_unconsumed(self):
        for message in (None, {}, {"id": "raw"}, {"text": False}):
            data = ranged()
            result = data["runs"][0]["results"][0]
            result["locations"] = [{"message": message},
                {"message": message, "physicalLocation": {"region": {"startLine": False}}}]
            report = evaluate(data)
            self.assertEqual(report["results"][0]["resolvedLocations"], [])
            self.assertNotIn("## Locations", markdown_summary(report))
            self.assertTrue(report["results"][0]["hasLocation"])
            self.assertEqual(report["totals"]["unlocated"], 0)
            self.assertEqual(report["evidence"]["document"], data)

    def test_messages_preserve_policy_identity_and_digest_bound_pairing(self):
        before = ranged({"startLine": 7, "endLine": 9}, "locations", "index")
        run = before["runs"][0]
        run["tool"]["extensions"] = [{"name": "Pack", "rules": [
            {"id": "R1", "defaultConfiguration": {"level": "error"}}]}]
        result = run["results"][0]
        result["rule"] = {"index": 0, "toolComponent": {"index": 0}}
        result["suppressions"] = [{"kind": "external", "status": "accepted"}]
        current = copy.deepcopy(before)
        current["runs"][0]["results"][0]["locations"][0]["message"] = {"text": PAYLOAD}
        for policy in (Policy(), Policy(level="error"), Policy(ignore_unchanged=True),
                       Policy(require_execution_success=True)):
            old, new = evaluate(before, policy), evaluate(current, policy)
            self.assertEqual(old["totals"], new["totals"])
            self.assertEqual(old["decision"], new["decision"])
            trace = copy.deepcopy(new["results"][0])
            trace["resolvedLocations"][0].pop("message")
            trace["resolvedLocations"][0].pop("messageSourcePointer")
            self.assertEqual(old["results"][0], trace)
            self.assertTrue(new["results"][0]["hasLocation"])
            self.assertEqual(new["totals"]["unlocated"], 0)
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

    def test_message_pointers_follow_source_run_result_and_location_indexes(self):
        data = with_message({"markdown": "literal"}, "dual", {})
        run = data["runs"][0]
        result = run["results"][0]
        result["locations"].insert(0, {"message": {"id": "pathless"}})
        run["results"].insert(0, {"message": {"text": "unlocated"}})
        data["runs"].insert(0, {"tool": {"driver": {"name": "Empty"}}, "results": []})
        report = evaluate(data)
        resolved = report["results"][1]["resolvedLocations"][0]
        self.assertEqual(resolved["messageSourcePointer"], "/runs/1/results/1/locations/1/message/markdown")
        self.assertEqual(resolved["artifactSourcePointer"], "/runs/1/artifacts/0/location")
        self.assertNotIn("sourceLineRange", resolved)
        self.assertEqual(report["totals"]["unlocated"], 1)
        self.assertIn("literal", markdown_summary(report))

    def test_cli_json_stdin_and_literal_markdown(self):
        fixture = ROOT / "examples/sarif/locations/primary-messages.sarif"
        raw = fixture.read_text()
        proc = cli("check", str(fixture))
        self.assertEqual(proc.returncode, 1, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(entry(report)["message"], json.loads(raw)["runs"][0]["results"][0]
                         ["locations"][0]["message"]["text"])
        self.assertEqual(report["evidence"]["document"], json.loads(raw))
        stdin = cli("check", "-", data=raw)
        self.assertEqual(stdin.returncode, 1, stdin.stderr)
        self.assertEqual(stdin.stdout, proc.stdout)
        md = cli("check", "-", "--format", "markdown", data=raw)
        self.assertEqual(md.returncode, 1, md.stderr)
        self.assertIn("&#60;b&#62;primary&#60;&#47;b&#62;&#124;&#91;inline&#93; next", md.stdout)
        self.assertIn("&#42;&#42;indexed&#42;&#42;&#124;&#91;plain&#93;  next", md.stdout)
        self.assertNotIn("<b>", md.stdout)

    def test_cli_invalid_messages_preserve_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            out, md = Path(directory) / "out.json", Path(directory) / "out.md"
            for message in (None, {"id": "SYNTHETIC_SECRET"}, {"text": "ok", "markdown": []}):
                out.write_text("keep json")
                md.write_text("keep markdown")
                proc = cli("check", "-", "--output", str(out), "--markdown", str(md),
                           data=json.dumps(with_message(message, "index")))
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stdout, "")
                self.assertIn(PREFIX, proc.stderr)
                self.assertNotIn("SYNTHETIC_SECRET", proc.stderr)
                self.assertEqual(out.read_text(), "keep json")
                self.assertEqual(md.read_text(), "keep markdown")


if __name__ == "__main__":
    unittest.main()
