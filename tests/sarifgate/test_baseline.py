"""Synthetic SARIF 2.1.0 two-report integration and ambiguity regressions."""

import copy
import hashlib
import json
from pathlib import Path
import unittest

from vulnwrench import sarifgate as sarif_gate

ROOT = Path(__file__).resolve().parents[2]
KEY = "primary/v1"


def finding(value, **kwargs):
    return {"ruleId": "R1", "message": {"text": "Synthetic"},
            "fingerprints": {KEY: value}, **kwargs}


def document(results=()):
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Synthetic", "version": "1.0.0"}},
        "invocations": [{"executionSuccessful": True}], "results": list(results)}]}


def compare(current, baseline, policy=None):
    return sarif_gate.compare_bytes(json.dumps(current).encode(), json.dumps(baseline).encode(),
                                   fingerprint=KEY, policy=policy)


class BaselineTests(unittest.TestCase):
    def test_explicit_example_and_evidence(self):
        before = (ROOT / "examples/sarif/baseline/before.sarif").read_bytes()
        current = (ROOT / "examples/sarif/baseline/current.sarif").read_bytes()
        report = sarif_gate.compare_bytes(current, before, fingerprint=KEY)
        view = report["baselineComparison"]
        self.assertEqual(view["status"], "compared")
        self.assertEqual(view["counts"], {"newly_observed": 1, "retained": 2, "absent": 1, "ambiguous": 0})
        self.assertEqual(report["decision"], "fail")
        self.assertEqual(report["actionable"], 1)
        self.assertEqual(report["acceptedSuppressions"], 1)
        self.assertEqual(view["baselineEvidence"]["document"], json.loads(before))
        self.assertEqual(view["baselineEvidence"]["sha256"], hashlib.sha256(before).hexdigest())
        self.assertEqual(report["evidence"]["sha256"], hashlib.sha256(current).hexdigest())
        accepted = next(e for e in view["entries"] if e["fingerprint"] == "A")
        for side in ("baseline", "current"):
            self.assertEqual(accepted[side][0]["suppressions"][0]["status"], "accepted")
            self.assertFalse(accepted[side][0]["blocking"])
        self.assertIn("does not prove", view["notice"])

    def test_reordering_results_rules_and_runs_matches(self):
        baseline = document([finding("A", ruleIndex=0), finding("B", ruleIndex=1, ruleId="R2")])
        baseline["runs"][0]["tool"]["driver"]["rules"] = [{"id": "R1"}, {"id": "R2"}]
        other = document([finding("X")])["runs"][0]
        other["tool"]["driver"]["name"] = "Other"
        baseline["runs"].append(other)
        current = copy.deepcopy(baseline)
        run = current["runs"][0]
        run["tool"]["driver"]["rules"].reverse()
        run["results"].reverse()
        for i, result in enumerate(run["results"]):
            result["ruleIndex"] = i
            result["message"]["text"] = "Changed display text"
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": "moved.py"}}}]
        current["runs"].reverse()
        view = compare(current, baseline)["baselineComparison"]
        self.assertEqual(view["counts"], {"newly_observed": 0, "retained": 3, "absent": 0, "ambiguous": 0})

    def test_comparison_does_not_exclude_retained_or_apply_baseline_suppression(self):
        baseline = document([finding("A", suppressions=[{"kind": "external", "status": "accepted"}])])
        current = document([finding("A")])
        for policy in (None, sarif_gate.Policy(ignore_unchanged=True)):
            report = compare(current, baseline, policy)
            self.assertEqual(report["decision"], "fail")
            self.assertEqual(report["actionable"], 1)
            self.assertEqual(report["baselineComparison"]["counts"]["retained"], 1)
            self.assertEqual(report["results"][0]["baselineState"], "unspecified")

    def test_absent_is_observational_and_does_not_apply_baseline_gate(self):
        report = compare(document(), document([finding("B")]))
        self.assertEqual(report["decision"], "pass")
        self.assertEqual(report["baselineComparison"]["counts"]["absent"], 1)
        self.assertNotIn("resolved", report["baselineComparison"]["counts"])

    def assert_uncertain(self, current, baseline, reason, status="ambiguous"):
        view = compare(current, baseline)["baselineComparison"]
        self.assertEqual(view["status"], status)
        self.assertEqual(view["counts"]["absent"], 0)
        self.assertEqual(view["counts"]["newly_observed"], 0)
        self.assertEqual(view["counts"]["retained"], 0)
        self.assertIn(reason, view["issues"])
        self.assertTrue(all(e["state"] == "ambiguous" for e in view["entries"]))
        return view

    def test_collisions_on_either_side_cannot_be_matched_or_absent(self):
        for current, baseline in ((document([finding("A")]), document([finding("A"), finding("A")])),
                                  (document([finding("A"), finding("A")]), document([finding("A")])),
                                  (document(), document([finding("A"), finding("A")]))):
            with self.subTest(current=current):
                self.assert_uncertain(current, baseline, "fingerprint_collision")

    def test_changed_tool_identity(self):
        for field in ("name", "guid", "version", "semanticVersion"):
            current = document([finding("A")])
            current["runs"][0]["tool"]["driver"][field] = (
                "00000000-0000-4000-8000-000000000001" if field == "guid" else "2.0.0")
            self.assert_uncertain(current, document([finding("A")]), "tool_identity_unpaired")

    def test_changed_rule_identity_with_same_fingerprint(self):
        current = document([finding("A", ruleId="R2")])
        self.assert_uncertain(current, document([finding("A")]), "rule_identity_changed")
        baseline = document([finding("A", ruleIndex=0)])
        baseline["runs"][0]["tool"]["driver"]["rules"] = [{"id": "R1", "guid": "00000000-0000-4000-8000-000000000001"}]
        current = copy.deepcopy(baseline)
        current["runs"][0]["tool"]["driver"]["rules"][0]["guid"] = "00000000-0000-4000-8000-000000000002"
        self.assert_uncertain(current, baseline, "rule_identity_changed")

    def test_duplicate_tool_runs_are_ambiguous(self):
        current = document([finding("A")])
        current["runs"].append(copy.deepcopy(current["runs"][0]))
        self.assert_uncertain(current, document([finding("A")]), "tool_run_collision")

    def test_failed_scans_and_error_notifications_invalidate_comparison(self):
        for side in ("current", "baseline"):
            for failure in ({"executionSuccessful": False},
                            {"executionSuccessful": True, "toolExecutionNotifications": [
                                {"level": "error", "message": {"text": "Synthetic failure"}}]}):
                docs = {"baseline": document([finding("A")]), "current": document()}
                docs[side]["runs"][0]["invocations"] = [failure]
                view = self.assert_uncertain(docs["current"], docs["baseline"],
                                             side + "_execution_failed", "invalid")
                self.assertEqual(view["execution"][side]["status"], "failed")
                self.assertTrue(view["execution"][side]["scanFailures"])
                report = compare(docs["current"], docs["baseline"])
                self.assertEqual(report["decision"], "fail" if side == "current" else "pass")

    def test_unknown_execution_does_not_prove_absence_even_under_permissive_gate(self):
        for invocations in ([], [{}], [{"executionSuccessful": True}, {}]):
            for side in ("current", "baseline"):
                docs = {"baseline": document([finding("A")]), "current": document()}
                docs[side]["runs"][0]["invocations"] = invocations
                self.assert_uncertain(docs["current"], docs["baseline"], side + "_execution_unknown")

    def test_strict_gate_failure_does_not_turn_unknown_execution_into_failed_evidence(self):
        current = document()
        current["runs"][0]["invocations"] = [{}]
        report = compare(current, document([finding("A")]), sarif_gate.Policy(require_execution_success=True))
        self.assertEqual(report["decision"], "fail")
        self.assertEqual(report["baselineComparison"]["status"], "ambiguous")
        self.assertEqual(report["baselineComparison"]["execution"]["current"]["status"], "unknown")
        self.assertEqual(report["baselineComparison"]["execution"]["current"]["scanFailures"], [])
        self.assertEqual(report["baselineComparison"]["counts"]["absent"], 0)

    def test_cross_rule_collision_retains_all_traces_and_does_not_poison_unique_matches(self):
        baseline = document([finding("A"), finding("A", ruleId="R2"), finding("B")])
        current = document([finding("A"), finding("B")])
        view = compare(current, baseline)["baselineComparison"]
        self.assertEqual(view["counts"], {"newly_observed": 0, "retained": 1, "absent": 0, "ambiguous": 1})
        collision = next(e for e in view["entries"] if e["fingerprint"] == "A")
        self.assertEqual(len(collision["baseline"]), 2)
        self.assertEqual(len(collision["current"]), 1)
        self.assertIn("fingerprint_collision", collision["reasons"])

    def test_missing_results_and_zero_runs_do_not_prove_absence(self):
        current = document()
        del current["runs"][0]["results"]
        self.assert_uncertain(current, document([finding("A")]), "current_results_missing")
        self.assert_uncertain({"version": "2.1.0", "runs": []}, document([finding("A")]), "current_no_runs")

    def test_missing_fingerprint_or_rule_identity_taints_unmatched_findings(self):
        for changes in ({"fingerprints": {}}, {"partialFingerprints": {KEY: "A"}, "fingerprints": {}},
                        {"ruleId": None}):
            current = document([finding("A"), finding("C")])
            current["runs"][0]["results"][0].update(changes)
            if changes.get("ruleId", "present") is None:
                del current["runs"][0]["results"][0]["ruleId"]
                reason = "rule_identity_missing"
            else:
                reason = "fingerprint_missing"
            self.assert_uncertain(current, document([finding("A"), finding("B")]), reason)

    def test_explicit_absent_records_are_not_observed_findings(self):
        for side in ("current", "baseline"):
            docs = {"baseline": document([finding("A")]), "current": document([finding("A")])}
            docs[side]["runs"][0]["results"][0]["baselineState"] = "absent"
            self.assert_uncertain(docs["current"], docs["baseline"], "report_marks_absent")

    def test_malformed_comparison_fields_are_sanitized_input_errors(self):
        for value in (None, [], "SYNTHETIC_SECRET", {KEY: 3}, {KEY: ""}):
            data = document([finding("A", fingerprints=value)])
            with self.subTest(value=value), self.assertRaises(sarif_gate.InputError) as caught:
                compare(data, document())
            self.assertNotIn("SYNTHETIC_SECRET", str(caught.exception))
        for key in (None, "", []):
            with self.assertRaises(sarif_gate.InputError):
                sarif_gate.compare_bytes(b'{}', b'{}', fingerprint=key)
        data = document()
        data["runs"][0]["tool"]["driver"]["version"] = []
        with self.assertRaises(sarif_gate.InputError):
            compare(data, document())

    def test_markdown_comparison_escapes_fingerprints_and_keeps_execution_separate(self):
        payload = '<script>|[click](bad)\x1b'
        report = compare(document([finding(payload)]), document([finding(payload)]))
        markdown = sarif_gate.markdown_summary(report)
        self.assertIn("## Baseline comparison", markdown)
        self.assertIn("retained", markdown)
        self.assertIn("Baseline execution: successful; current execution: successful", markdown)
        self.assertNotIn(payload, markdown)
        self.assertIn("&#60;script&#62;", markdown)

    def test_comparison_is_deterministic_and_original_gate_report_is_unchanged(self):
        data = json.dumps(document([finding("A")])).encode()
        report = sarif_gate.compare_bytes(data, data, fingerprint=KEY)
        self.assertEqual(sarif_gate.dumps(report), sarif_gate.dumps(sarif_gate.compare_bytes(data, data, fingerprint=KEY)))
        del report["baselineComparison"]
        self.assertEqual(report, sarif_gate.check_bytes(data))


if __name__ == "__main__":
    unittest.main()
