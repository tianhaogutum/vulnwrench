"""Inline numeric rule-component contracts; all reports are synthetic."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from vulnwrench.sarifgate import InputError, Policy, compare_bytes, evaluate

ROOT = Path(__file__).resolve().parents[2]


def fixture():
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Synthetic", "rules": [
            {"id": "shared", "guid": "driver-rule", "defaultConfiguration": {"level": "error"}}]},
            "extensions": [{"name": "Pack", "version": "1", "rules": [
                {"id": "shared", "guid": "pack-rule", "defaultConfiguration": {"level": "note"}},
                {"id": "other"}]}]},
        "invocations": [{"executionSuccessful": True}],
        "results": [{"rule": {"index": 0, "toolComponent": {"index": 0}},
                     "message": {"text": "Extension default"}, "fingerprints": {"primary/v1": "A"}},
                    {"ruleIndex": 0, "rule": {"index": 0, "toolComponent": {"index": 0}},
                     "level": "error", "message": {"text": "Explicit error"}}]}]}


def invalid_references():
    for bad in (True, False, 0.0, "0", None, [], {}, -2, 2):
        yield {"rule": {"index": bad, "toolComponent": {"index": 0}}}
    for bad in (True, False, 0.0, "0", None, [], {}, -2, 1):
        yield {"rule": {"index": 0, "toolComponent": {"index": bad}}}
    for bad in (None, [], "SYNTHETIC_SECRET"):
        yield {"rule": bad}
        yield {"rule": {"index": 0, "toolComponent": bad}}
    yield {"ruleIndex": 1, "rule": {"index": 0}}
    yield {"ruleIndex": -1, "rule": {"index": 0}}
    yield {"ruleIndex": True, "rule": {"index": 0}}
    yield {"ruleIndex": 0, "rule": {"index": -1}}
    yield {"ruleId": "shared", "rule": {"id": "shared/sub", "index": 0}}
    for bad_id in ("SYNTHETIC_SECRET", "sharedish", "shared/sub/deep", None, 4):
        yield {"rule": {"id": bad_id, "index": 0}}
    yield {"rule": {"index": 0, "toolComponent": {"index": 0, "name": "SYNTHETIC_SECRET"}}}
    yield {"rule": {"index": 0, "toolComponent": {"name": "Pack"}}}
    for reference in ({}, {"id": "shared"}, {"toolComponent": {"index": 0}}):
        yield {"rule": reference}
    for reference in ({"guid": "SYNTHETIC_SECRET"}, {"index": 0, "guid": "SYNTHETIC_SECRET"},
                      {"index": 0, "toolComponent": {"guid": "SYNTHETIC_SECRET"}},
                      {"index": 0, "toolComponent": {"index": 0, "guid": "SYNTHETIC_SECRET"}}):
        yield {"rule": reference}


class RuleComponentTests(unittest.TestCase):
    def test_extension_default_and_explicit_error_are_isolated_from_driver(self):
        data = fixture()
        before = copy.deepcopy(data)
        first = copy.deepcopy(data)
        first["runs"][0]["results"] = first["runs"][0]["results"][:1]
        report = evaluate(first, Policy(level="warning"))
        self.assertEqual((report["decision"], report["actionable"]), ("pass", 0))
        trace = report["results"][0]
        self.assertEqual((trace["ruleId"], trace["ruleIndex"], trace["level"], trace["levelSource"]),
                         ("shared", 0, "note", "rule.defaultConfiguration.level"))
        self.assertEqual(trace["ruleComponent"], {"kind": "extension", "index": 0, "name": "Pack",
                                                "sourcePointer": "/runs/0/tool/extensions/0"})
        self.assertEqual(trace["ruleSourcePointer"], "/runs/0/tool/extensions/0/rules/0")
        self.assertEqual(trace["levelSourcePointer"], "/runs/0/tool/extensions/0/rules/0/defaultConfiguration/level")
        report = evaluate(data)
        self.assertEqual((report["decision"], report["actionable"], report["totals"]["belowThreshold"]), ("fail", 1, 1))
        self.assertEqual(report["results"][1]["levelSourcePointer"], "/runs/0/results/1/level")
        self.assertEqual(report["results"][1]["levelSource"], "result.level")
        self.assertEqual(data, before)
        self.assertEqual(report["evidence"]["document"], before)

    def test_driver_default_component_and_inherited_indexes(self):
        for reference in ({"rule": {"index": 0}}, {"ruleIndex": 0, "rule": {}},
                          {"ruleIndex": 0, "rule": {"index": 0, "id": "shared"}},
                          {"rule": {"index": 0, "toolComponent": {}}},
                          {"rule": {"index": 0, "toolComponent": {"name": "Synthetic"}}},
                          {"rule": {"index": 0, "toolComponent": {"index": -1}}},
                          {"ruleIndex": 0}, {"ruleId": "shared"}):
            with self.subTest(reference=reference):
                data = fixture()
                data["runs"][0]["results"] = [{"message": {"text": "Driver"}, **reference}]
                trace = evaluate(data)["results"][0]
                self.assertEqual(trace["level"], "error")
                self.assertEqual(trace["ruleComponent"]["kind"], "driver")
                self.assertIsNone(trace["ruleComponent"]["index"])
                self.assertEqual(trace["ruleSourcePointer"], "/runs/0/tool/driver/rules/0")
        data = fixture()
        result = data["runs"][0]["results"][0]
        result["rule"].pop("index")
        result["ruleIndex"] = 0
        self.assertEqual(evaluate(data)["results"][0]["level"], "note")

    def test_redundant_ids_allow_exact_or_one_hierarchical_component(self):
        for rule_id in ("shared", "shared/sub", "shared/"):
            for fields in ({"ruleId": rule_id}, {"id": rule_id}, {"ruleId": rule_id, "id": rule_id}):
                data = fixture()
                result = data["runs"][0]["results"][0]
                if "ruleId" in fields:
                    result["ruleId"] = fields["ruleId"]
                if "id" in fields:
                    result["rule"]["id"] = fields["id"]
                result["rule"]["toolComponent"]["name"] = "Pack"
                trace = evaluate(data)["results"][0]
                self.assertEqual(trace["ruleId"], rule_id)
                self.assertEqual(trace["level"], "note")

    def test_missing_default_is_warning_and_catalog_is_run_scoped(self):
        data = fixture()
        data["runs"][0]["results"][0]["rule"]["index"] = 1
        other = copy.deepcopy(data["runs"][0])
        other["tool"]["extensions"][0]["rules"][1]["defaultConfiguration"] = {"level": "none"}
        data["runs"].append(other)
        report = evaluate(data)
        self.assertEqual(report["results"][0]["levelSource"], "sarif_default")
        self.assertIsNone(report["results"][0]["levelSourcePointer"])
        self.assertEqual(report["results"][2]["level"], "none")
        self.assertEqual(report["results"][2]["ruleSourcePointer"], "/runs/1/tool/extensions/0/rules/1")

    def test_suppressions_baseline_states_thresholds_and_scan_status(self):
        data = fixture()
        result = data["runs"][0]["results"][0]
        data["runs"][0]["results"] = [result]
        for status in ("accepted", "rejected", "underReview", None):
            result["suppressions"] = [{"kind": "external", **({"status": status} if status else {})}]
            report = evaluate(data, Policy(level="note"))
            self.assertEqual(report["actionable"], int(status != "accepted"))
        result.pop("suppressions")
        result["baselineState"] = "unchanged"
        self.assertEqual(evaluate(data, Policy(level="note", ignore_unchanged=True))["actionable"], 0)
        result["baselineState"] = "absent"
        self.assertEqual(evaluate(data, Policy(level="note"))["actionable"], 0)
        data["runs"][0]["invocations"][0]["executionSuccessful"] = False
        self.assertEqual(evaluate(data)["decision"], "fail")
        data["runs"][0]["invocations"] = []
        self.assertEqual(evaluate(data)["decision"], "pass")
        self.assertEqual(evaluate(data, Policy(require_execution_success=True))["decision"], "fail")

    def test_invalid_and_unsupported_references_are_never_clean(self):
        for reference in invalid_references():
            with self.subTest(reference=reference):
                data = fixture()
                data["runs"][0]["results"] = [{"message": {"text": "Invalid"}, **reference,
                    "suppressions": [{"kind": "external", "status": "accepted"}]}]
                with self.assertRaises(InputError) as context:
                    evaluate(data)
                self.assertNotIn("SYNTHETIC_SECRET", str(context.exception))

    def test_catalog_validation_and_no_extension_inference(self):
        for bad in (None, {}, [None], [{"rules": []}], [{"name": "Pack", "rules": None}],
                    [{"name": "Pack", "rules": [{"id": "a"}, {"id": "a"}]}],
                    [{"name": "Pack", "rules": [{"id": "a", "defaultConfiguration": {"level": "SYNTHETIC_SECRET"}}]}]):
            data = fixture()
            data["runs"][0]["tool"]["extensions"] = bad
            with self.subTest(bad=bad), self.assertRaises(InputError):
                evaluate(data)
        data = fixture()
        data["runs"][0]["tool"]["driver"]["rules"] = []
        data["runs"][0]["results"] = [{"ruleId": "shared", "message": {"text": "Unlisted"}}]
        trace = evaluate(data)["results"][0]
        self.assertEqual((trace["level"], trace["ruleResolution"]), ("warning", "unlisted"))
        self.assertIsNone(trace["ruleSourcePointer"])
        data["runs"][0]["results"][0]["rule"] = {"id": "shared"}
        self.assertEqual(evaluate(data)["results"][0]["ruleResolution"], "unlisted")

    def test_unsupported_effective_configuration_remains_rejected(self):
        for key in ("inlineExternalProperties", "externalPropertyFileReferences"):
            data = fixture()
            data["runs"][0][key] = {}
            with self.subTest(key=key), self.assertRaises(InputError):
                evaluate(data)
        for key in ("ruleConfigurationOverrides", "notificationConfigurationOverrides"):
            data = fixture()
            data["runs"][0]["invocations"][0][key] = []
            with self.subTest(key=key), self.assertRaises(InputError):
                evaluate(data)
        data = fixture()
        data["runs"][0]["results"][0]["message"] = {"id": "SYNTHETIC_SECRET"}
        with self.assertRaises(InputError):
            evaluate(data)
        data = fixture()
        data["runs"][0]["tool"]["extensions"][0].pop("rules")
        with self.assertRaises(InputError):
            evaluate(data)

    def test_baseline_uses_selected_catalog_and_stable_component_identity(self):
        before = fixture()
        before["runs"][0]["results"] = before["runs"][0]["results"][:1]
        before["runs"][0]["tool"]["extensions"].append({"name": "Other", "rules": []})
        current = copy.deepcopy(before)
        current["runs"][0]["tool"]["extensions"].reverse()
        current["runs"][0]["tool"]["extensions"][1]["rules"].reverse()
        current["runs"][0]["results"][0]["rule"] = {"index": 1, "toolComponent": {"index": 1}}
        def compare():
            return compare_bytes(json.dumps(current).encode(), json.dumps(before).encode(), fingerprint="primary/v1")["baselineComparison"]
        view = compare()
        self.assertEqual(view["counts"]["retained"], 1)
        identity = view["entries"][0]["current"][0]["ruleIdentity"]
        self.assertEqual(identity["guid"], "pack-rule")
        self.assertEqual(identity["toolComponent"], {"name": "Pack", "version": "1"})
        current["runs"][0]["tool"]["extensions"][1]["version"] = "2"
        self.assertEqual(compare()["status"], "ambiguous")
        current = copy.deepcopy(before)
        current["runs"][0]["results"][0]["rule"].pop("toolComponent")
        self.assertEqual(compare()["status"], "ambiguous")
        current = copy.deepcopy(before)
        current["runs"][0]["tool"]["extensions"][0]["rules"][0]["guid"] = "changed"
        self.assertEqual(compare()["status"], "ambiguous")
        current = copy.deepcopy(before)
        current["runs"][0]["tool"]["extensions"].append(copy.deepcopy(current["runs"][0]["tool"]["extensions"][0]))
        view = compare()
        self.assertEqual(view["status"], "ambiguous")
        self.assertIn("rule_component_identity_ambiguous", view["issues"])


class RuleComponentCliTests(unittest.TestCase):
    def test_fixture_file_and_stdin(self):
        path = ROOT / "examples/sarif/rule-components.sarif"
        proc = subprocess.run([sys.executable, "-m", "vulnwrench", "sarif", "check", str(path)], capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report["actionable"], 1)
        self.assertEqual([r["level"] for r in report["results"]], ["note", "error"])
        data = json.loads(path.read_bytes())
        data["runs"][0]["results"] = data["runs"][0]["results"][:1]
        proc = subprocess.run([sys.executable, "-m", "vulnwrench", "sarif", "check", "-"], input=json.dumps(data), capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["actionable"], 0)

    def test_invalid_references_preserve_outputs_and_sanitize(self):
        with tempfile.TemporaryDirectory() as directory:
            out, md = Path(directory) / "out.json", Path(directory) / "out.md"
            out.write_text("keep json")
            md.write_text("keep md")
            for reference in invalid_references():
                data = fixture()
                data["runs"][0]["results"] = [{"message": {"text": "Invalid"}, **reference}]
                proc = subprocess.run([sys.executable, "-m", "vulnwrench", "sarif", "check", "-", "--output", str(out), "--markdown", str(md)],
                                      input=json.dumps(data), capture_output=True, text=True, timeout=60)
                self.assertEqual(proc.returncode, 2, reference)
                self.assertFalse(proc.stdout)
                self.assertNotIn("SYNTHETIC_SECRET", proc.stderr)
                self.assertIn("/runs/0/results/0/rule", proc.stderr)
                self.assertEqual(out.read_text(), "keep json")
                self.assertEqual(md.read_text(), "keep md")


if __name__ == "__main__":
    unittest.main()
