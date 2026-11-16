import copy
import hashlib
import json
from pathlib import Path
import unittest

from vulnwrench.sarifgate import InputError, Policy, check_bytes, dumps, evaluate, markdown_summary, parse_document

ROOT = Path(__file__).resolve().parents[2]


def finding(**kwargs):
    return {"message": {"text": "Synthetic"}, **kwargs}


def document(results=None, rules=None, invocations=None):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Synthetic", "rules": rules or []}},
            "results": results or [], "invocations": invocations if invocations is not None else [{"executionSuccessful": True}]}]}


class GateTests(unittest.TestCase):
    def test_explicit_level_overrides_rule_default(self):
        report = evaluate(document([finding(ruleId="a", level="note")],
                                   [{"id": "a", "defaultConfiguration": {"level": "error"}}]))
        self.assertEqual(report["decision"], "pass")
        self.assertEqual(report["results"][0]["levelSource"], "result.level")

    def test_rule_default_by_index_and_id(self):
        rules = [{"id": "a", "defaultConfiguration": {"level": "error"}}]
        for reference in ({"ruleIndex": 0}, {"ruleId": "a"}, {"ruleIndex": 0, "ruleId": "a"}):
            with self.subTest(reference=reference):
                trace = evaluate(document([finding(**reference)], rules))["results"][0]
                self.assertEqual((trace["level"], trace["ruleId"], trace["ruleIndex"]), ("error", "a", 0))
                self.assertEqual(trace["levelSource"], "rule.defaultConfiguration.level")

    def test_warning_default_and_negative_one_index(self):
        for result in (finding(), finding(ruleId="unlisted", ruleIndex=-1)):
            trace = evaluate(document([result]))["results"][0]
            self.assertEqual((trace["level"], trace["levelSource"]), ("warning", "sarif_default"))
            self.assertTrue(trace["blocking"])

    def test_rule_without_default_level(self):
        trace = evaluate(document([finding(ruleIndex=0)], [{"id": "a"}]))["results"][0]
        self.assertEqual(trace["level"], "warning")

    def test_all_thresholds_and_levels(self):
        for threshold in ("note", "warning", "error"):
            levels = ["none", "note", "warning", "error"]
            report = evaluate(document([finding(level=lv) for lv in levels]), Policy(threshold))
            self.assertEqual(report["actionable"], len(levels) - levels.index(threshold))
            self.assertEqual(report["totals"]["results"], 4)

    def test_suppression_states(self):
        for status in ("accepted", "rejected", "underReview", None):
            suppression = {"kind": "inSource"}
            if status:
                suppression["status"] = status
            with self.subTest(status=status):
                report = evaluate(document([finding(suppressions=[suppression])]))
                self.assertEqual(report["actionable"], int(status != "accepted"))
                self.assertEqual(report["acceptedSuppressions"], int(status == "accepted"))
                self.assertEqual(len(report["results"]), 1)
                self.assertEqual(report["results"][0]["suppressions"][0]["status"], status or "unspecified")

    def test_one_accepted_of_multiple_suppressions_excludes_result_once(self):
        suppressions = [{"kind": "external", "status": s} for s in ("rejected", "accepted", "accepted")]
        report = evaluate(document([finding(suppressions=suppressions)]))
        self.assertEqual(report["acceptedSuppressions"], 1)
        self.assertEqual(len(report["results"][0]["suppressions"]), 3)
        self.assertEqual(report["decision"], "pass")

    def test_baseline_states_and_explicit_unchanged_policy(self):
        for baseline in (None, "new", "updated", "unchanged", "absent"):
            for ignore in (False, True):
                with self.subTest(baseline=baseline, ignore=ignore):
                    result = finding(**({"baselineState": baseline} if baseline else {}))
                    trace = evaluate(document([result]), Policy(ignore_unchanged=ignore))["results"][0]
                    self.assertEqual(trace["blocking"], baseline != "absent" and not (ignore and baseline == "unchanged"))

    def test_unlocated_findings_are_retained(self):
        report = evaluate(document([finding(), finding(locations=[]), finding(locations=[{"logicalLocations": [{"name": "module"}]}])]))
        self.assertEqual(report["totals"]["unlocated"], 2)
        self.assertEqual(report["actionable"], 3)
        self.assertEqual([r["hasLocation"] for r in report["results"]], [False, False, True])

    def test_unknown_evidence_is_lossless_and_input_not_mutated(self):
        original = document([finding(properties={"custom": [1, None, {"a": "b"}]}, **{"x/new~key": {"opaque": True}})])
        original["properties"] = {"anything": 9}
        original["runs"][0]["invocations"][0]["workingDirectory"] = {"uri": "file:///synthetic"}
        before = copy.deepcopy(original)
        report = evaluate(original)
        self.assertEqual(original, before)
        self.assertEqual(report["evidence"]["document"], before)
        self.assertIn("/runs/0/results/0/x~1new~0key", report["evidence"]["uninterpretedFields"])
        self.assertIn("/properties", report["evidence"]["uninterpretedFields"])
        original["properties"]["anything"] = 10
        self.assertEqual(report["evidence"]["document"], before)

    def test_failed_invocation_is_never_clean(self):
        report = evaluate(document(invocations=[{"executionSuccessful": False}]))
        self.assertEqual((report["decision"], report["actionable"], report["totals"]["scanFailures"]), ("fail", 0, 1))
        self.assertEqual(report["naive"]["decision"], "pass")

    def test_error_notification_even_if_execution_successful(self):
        notifications = [{"message": {"text": "Synthetic error"}, "level": "error"},
                         {"message": {"text": "Synthetic warning"}}]
        report = evaluate(document(invocations=[{"executionSuccessful": True, "toolExecutionNotifications": notifications}]))
        self.assertEqual(report["decision"], "fail")
        self.assertEqual(report["totals"]["errorNotifications"], 1)
        self.assertEqual(report["runs"][0]["invocations"][0]["notifications"][1]["level"], "warning")

    def test_warning_notification_does_not_fail(self):
        report = evaluate(document(invocations=[{"executionSuccessful": True,
                          "toolExecutionNotifications": [{"message": {"text": "Synthetic"}, "level": "warning"}]}]))
        self.assertEqual(report["decision"], "pass")

    def test_mixed_invocations_failure_and_unknown(self):
        report = evaluate(document(invocations=[{"executionSuccessful": True}, {}, {"executionSuccessful": False}]))
        self.assertEqual(report["decision"], "fail")
        self.assertEqual(report["totals"]["unknownExecutionInvocations"], 1)
        self.assertEqual(report["runs"][0]["executionStatus"], "failed")

    def test_missing_execution_is_explicit_unknown(self):
        for invocations in ([], [{}]):
            report = evaluate(document(invocations=invocations))
            self.assertEqual(report["decision"], "pass")
            self.assertEqual(report["runs"][0]["executionStatus"], "unknown")
            self.assertEqual(evaluate(document(invocations=invocations), Policy(require_execution_success=True))["decision"], "fail")

    def test_zero_runs_strict_policy(self):
        self.assertEqual(evaluate({"version": "2.1.0", "runs": []})["decision"], "pass")
        self.assertEqual(evaluate({"version": "2.1.0", "runs": []}, Policy(require_execution_success=True))["decision"], "fail")

    def test_missing_results_is_explicit(self):
        data = document()
        del data["runs"][0]["results"]
        report = evaluate(data)
        self.assertFalse(report["runs"][0]["resultsPresent"])
        self.assertEqual(report["decision"], "pass")

    def test_multirun_is_not_early_return_on_suppression(self):
        data = document([finding(suppressions=[{"kind": "inSource", "status": "accepted"}])])
        data["runs"].extend(document([finding()])["runs"])
        report = evaluate(data)
        self.assertEqual((report["decision"], report["totals"]["results"], report["actionable"]), ("fail", 2, 1))
        self.assertEqual(report["results"][1]["sourcePointer"], "/runs/1/results/0")

    def test_deterministic_json_and_exact_digest(self):
        data = b'{"version":"2.1.0", "runs":[]}\n'
        report = check_bytes(data)
        self.assertEqual(report["evidence"]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(report["evidence"]["digestKind"], "input_bytes")
        self.assertEqual(dumps(report), dumps(check_bytes(data)))
        self.assertEqual(evaluate(json.loads(data))["evidence"]["digestKind"], "canonical_json")

    def test_markdown_and_json_escape_untrusted_text(self):
        payload = '<script>alert(1)</script> | [click](javascript:bad) ![image](https://invalid) `code`\n# title\x1b'
        report = evaluate(document([finding(ruleId=payload, message={"markdown": payload})]))
        markdown = markdown_summary(report)
        self.assertNotIn("<script>", markdown)
        self.assertNotIn("[click]", markdown)
        self.assertNotIn("\x1b", markdown)
        self.assertNotIn("\n# title", markdown)
        self.assertIn("&#60;script&#62;", markdown)
        self.assertNotIn("<script>", dumps(report))
        self.assertEqual(json.loads(dumps(report))["results"][0]["message"], payload)

    def test_reference_corpus(self):
        for case in json.loads((ROOT / "examples/sarif/corpus.json").read_text()):
            with self.subTest(file=case["file"]):
                report = check_bytes((ROOT / "examples" / "sarif" / case["file"]).read_bytes())
                self.assertEqual(report["decision"], case["decision"])
                self.assertEqual(report["actionable"], case["actionable"])
                self.assertEqual(report["naive"]["explicitWarningErrorCount"], case["naiveCount"])


class InvalidInputTests(unittest.TestCase):
    def assert_invalid(self, data):
        with self.assertRaises(InputError) as context:
            evaluate(data)
        self.assertNotIn("SYNTHETIC_SECRET", str(context.exception))

    def test_unsupported_version_and_root(self):
        for data in ([], {}, {"version": "SYNTHETIC_SECRET", "runs": []}, {"version": "2.1.0", "runs": None}):
            with self.subTest(data=data):
                self.assert_invalid(data)

    def test_invalid_rule_indexes(self):
        for index in (-2, 1, 100, True, False, "0", 0.0, None, [], {}):
            with self.subTest(index=index):
                self.assert_invalid(document([finding(ruleIndex=index)], [{"id": "a"}]))
        self.assert_invalid(document([finding(ruleIndex=0)]))

    def test_conflicting_or_missing_rule_ids(self):
        self.assert_invalid(document([finding(ruleIndex=0, ruleId="SYNTHETIC_SECRET")], [{"id": "a"}]))
        self.assert_invalid(document([finding(ruleId="SYNTHETIC_SECRET")], [{"id": "a"}]))
        self.assert_invalid(document([finding(ruleId=None)]))

    def test_duplicate_rule_id(self):
        self.assert_invalid(document(rules=[{"id": "a"}, {"id": "a"}]))

    def test_malformed_levels(self):
        for level in ("SYNTHETIC_SECRET", None, 1, [], {}):
            with self.subTest(level=level):
                self.assert_invalid(document([finding(level=level)]))
                self.assert_invalid(document(rules=[{"id": "a", "defaultConfiguration": {"level": level}}]))
                self.assert_invalid(document(invocations=[{"executionSuccessful": True,
                    "toolExecutionNotifications": [{"level": level, "message": {"text": "Synthetic"}}]}]))

    def test_invalid_suppression(self):
        for suppression in ({"kind": "inSource", "status": "unspecified"}, {"kind": "external", "status": None},
                            {"kind": "SYNTHETIC_SECRET"}, {"status": "accepted"}, {"kind": "inSource", "status": []}, None):
            with self.subTest(suppression=suppression):
                self.assert_invalid(document([finding(suppressions=[suppression])]))

    def test_invalid_invocation_boolean(self):
        for success in (0, 1, "false", None, [], {}):
            with self.subTest(success=success):
                self.assert_invalid(document(invocations=[{"executionSuccessful": success}]))

    def test_invalid_baseline_and_kind(self):
        self.assert_invalid(document([finding(baselineState="SYNTHETIC_SECRET")]))
        self.assert_invalid(document([finding(kind="pass")]))

    def test_bad_structure(self):
        for key, bad in (("results", None), ("results", {}), ("invocations", {}), ("tool", [])):
            data = document()
            data["runs"][0][key] = bad
            with self.subTest(key=key, bad=bad):
                self.assert_invalid(data)
        for field in ({"suppressions": None}, {"locations": "SYNTHETIC_SECRET"}, {"locations": [None]}, {"message": {"id": "SYNTHETIC_SECRET"}}):
            self.assert_invalid(document([finding(**field)]))

    def test_unsupported_semantics_fail_explicitly(self):
        data = document()
        data["inlineExternalProperties"] = []
        self.assert_invalid(data)
        for field in ("externalPropertyFileReferences", "inlineExternalProperties"):
            data = document()
            data["runs"][0][field] = {}
            self.assert_invalid(data)
        data = document()
        data["runs"][0]["tool"]["extensions"] = [{"name": "SYNTHETIC_SECRET", "rules": None}]
        self.assert_invalid(data)
        self.assert_invalid(document([finding(rule={"index": 0})]))
        self.assert_invalid(document(invocations=[{"executionSuccessful": True, "ruleConfigurationOverrides": []}]))

    def test_invalid_json_duplicate_keys_and_nonfinite_numbers(self):
        for data in (b'not json SYNTHETIC_SECRET', b'\xff', b'{"runs":[],"runs":[]}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e999}'):
            with self.subTest(data=data):
                with self.assertRaises(InputError) as context:
                    parse_document(data)
                self.assertNotIn("SYNTHETIC_SECRET", str(context.exception))

    def test_utf8_bom(self):
        self.assertEqual(check_bytes(b'\xef\xbb\xbf{"version":"2.1.0","runs":[]}')["decision"], "pass")

    def test_invalid_policy(self):
        for kwargs in ({"level": "none"}, {"level": []}, {"ignore_unchanged": "true"}, {"require_execution_success": 1}):
            with self.assertRaises(InputError):
                Policy(**kwargs)

    def test_library_rejects_non_json_trees(self):
        for bad in ({1: "coerced key"}, {"tuple": (1, 2)}, {"bad": float("nan")}, {"bad": object()}):
            data = document()
            data["properties"] = bad
            self.assert_invalid(data)

    def test_suppression_cannot_hide_invalid_other_result(self):
        self.assert_invalid(document([
            finding(suppressions=[{"kind": "inSource", "status": "accepted"}]),
            finding(level="SYNTHETIC_SECRET")]))

    def test_deep_json_is_sanitized(self):
        with self.assertRaises(InputError):
            parse_document(b'[' * 1500 + b'0' + b']' * 1500)


if __name__ == "__main__":
    unittest.main()
