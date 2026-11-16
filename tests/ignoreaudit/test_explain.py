from datetime import date
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from vulnwrench.ignoreaudit import Finding, InputError, Report, Rule

ROOT = Path(__file__).resolve().parents[2]
ASOF = date(2026, 11, 11)


class ExplainTests(unittest.TestCase):
    def run_cli(self, *extra, key="IgnoredVulns:2"):
        return subprocess.run([sys.executable, "-m", "vulnwrench", "ignores", "explain", "--format", "osv",
                               "--rules", "examples/ignores/osv-scanner.toml", "--report", "examples/ignores/explain-osv.json",
                               "--report-unfiltered", "--as-of", ASOF.isoformat(), "--rule-key", key, *extra],
                              cwd=ROOT, capture_output=True, timeout=60, text=True)

    def result(self, *extra, **kwargs):
        proc = self.run_cli(*extra, **kwargs)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def check(self, evidence, selector):
        return next(check for check in evidence["checks"] if check["selector"] == selector)

    def test_alias_only_requires_explicit_map_and_is_deterministic(self):
        exact = self.result()
        self.assertEqual(exact["rule"]["matchCount"], 0)
        self.assertEqual([e["decision"] for e in exact["evidence"]], ["no_match"] * 4)
        self.assertEqual(self.check(exact["evidence"][0], "advisory")["outcome"], "mismatch")
        self.assertEqual(exact["evidence"][0]["reasons"], ["advisory_mismatch"])
        self.assertEqual(exact["provenance"]["aliases"], "exact_ids_only")
        self.assertIn("unmatched aliases are not proof", " ".join(exact["notes"]))
        mapped = self.result("--alias-map", "examples/ignores/aliases.json")
        self.assertEqual(mapped["matchedEvidenceIds"], ["finding:0", "finding:1", "finding:3"])
        self.assertEqual([e["decision"] for e in mapped["evidence"]], ["match", "match", "no_match", "match"])
        self.assertEqual(self.check(mapped["evidence"][0], "advisory")["outcome"], "explicit_alias")
        self.assertEqual(mapped["evidence"][0]["finding"], {
            "advisory": "CVE-2025-0001", "package": "demo-a", "version": "1.0.0",
            "ecosystem": "npm", "path": "app/package-lock.json"})
        self.assertEqual(mapped["evidence"][0]["locator"], "results[0].packages[0].vulnerabilities[0]")
        self.assertEqual(self.run_cli("--alias-map", "examples/ignores/aliases.json").stdout,
                         self.run_cli("--alias-map", "examples/ignores/aliases.json").stdout)

    def test_report_alias_hint_contract_separate_from_explicit_equivalence(self):
        exact = self.result()
        hint = {"aliases": ["GHSA-synthetic-alias"],
                "locator": "results[0].packages[0].vulnerabilities[0].aliases",
                "trust": "untrusted", "affectsMatching": False, "ruleAdvisoryListed": True}
        self.assertEqual(exact["evidence"][0]["reportAliasHints"], [hint])
        self.assertEqual([e["reportAliasHints"] for e in exact["evidence"][1:]], [[], [], []])
        self.assertEqual(self.check(exact["evidence"][0], "advisory")["acceptedIds"], ["GHSA-synthetic-alias"])
        self.assertEqual(exact["rule"]["matchCount"], 0)
        self.assertEqual(exact["matchedEvidenceIds"], [])
        self.assertEqual(exact["unknownEvidenceIds"], [])
        self.assertIn("orphan_candidate", exact["rule"]["status"])
        self.assertFalse(exact["unusedRuleAssertionAllowed"])
        mapped = self.result("--alias-map", "examples/ignores/aliases.json")
        self.assertEqual(mapped["evidence"][0]["reportAliasHints"], [hint])
        self.assertEqual(mapped["rule"]["matchCount"], 3)
        self.assertEqual(self.check(mapped["evidence"][0], "advisory")["outcome"], "explicit_alias")
        self.assertFalse(mapped["unusedRuleAssertionAllowed"])

    def test_group_hints_are_observation_local_and_never_transitive(self):
        from vulnwrench.ignoreaudit import explain, load_report
        payload = {"results": [{"source": {"path": "app/lock"}, "packages": [
            {"package": {"name": "demo"}, "groups": [
                {"ids": ["CVE-1", "CVE-2"], "aliases": ["GHSA-local", "GHSA-local"]},
                {"ids": ["GHSA-local"], "aliases": ["GHSA-transitive"]},
                {"aliases": ["GHSA-unbound"]}],
             "vulnerabilities": [{"id": "CVE-1", "aliases": ["GHSA-direct"]},
                                 {"id": "CVE-2"}, {"id": "CVE-3"}]},
            {"package": {"name": "other"}, "vulnerabilities": [{"id": "CVE-1"}]}]}]}
        report = load_report(json.dumps(payload).encode(), "osv", report_unfiltered=True)
        rule = Rule("selected", "GHSA-local")
        result = explain([rule], report, rule.key, as_of=ASOF, report_unfiltered=True)
        hints = [e["reportAliasHints"] for e in result["evidence"]]
        group_hint = {"aliases": ["GHSA-local", "GHSA-local"],
                      "locator": "results[0].packages[0].groups[0].aliases",
                      "trust": "untrusted", "affectsMatching": False, "ruleAdvisoryListed": True}
        self.assertEqual(hints[0], [
            {"aliases": ["GHSA-direct"], "locator": "results[0].packages[0].vulnerabilities[0].aliases",
             "trust": "untrusted", "affectsMatching": False, "ruleAdvisoryListed": False}, group_hint])
        self.assertEqual(hints[1], [group_hint])
        self.assertEqual(hints[2:], [[], []])
        self.assertEqual([e["decision"] for e in result["evidence"]], ["no_match"] * 4)
        transitive = explain([Rule("selected", "GHSA-transitive")], report, "selected",
                             as_of=ASOF, report_unfiltered=True)
        self.assertFalse(any(h["ruleAdvisoryListed"] for e in transitive["evidence"] for h in e["reportAliasHints"]))
        self.assertEqual(transitive["rule"]["matchCount"], 0)

    def test_hints_cannot_change_matching_scope_coverage_or_cleanup(self):
        from vulnwrench.ignoreaudit import audit, explain, load_report, match_indexed, match_reference
        from vulnwrench.ignoreaudit.cleanup import cleanup_plan
        payload = {"results": [{"source": {}, "packages": [
            {"package": {"name": "demo"}, "vulnerabilities": [
                {"id": "CVE-1", "aliases": ["GHSA-local"]}]},
            {"package": {"name": "incomplete"}, "groups": [
                {"ids": ["CVE-1"], "aliases": ["GHSA-local"]}]}]}]}
        hinted = load_report(json.dumps(payload).encode(), "osv", report_unfiltered=True)
        del payload["results"][0]["packages"][0]["vulnerabilities"][0]["aliases"]
        del payload["results"][0]["packages"][1]["groups"]
        plain = load_report(json.dumps(payload).encode(), "osv", report_unfiltered=True)
        rules = [Rule("alias", "GHSA-local", source_dir="app"), Rule("exact", "CVE-1", path="app/lock"),
                 Rule("global", "CVE-1")]
        explicit = {ident: {"CVE-1", "GHSA-local"} for ident in ("CVE-1", "GHSA-local")}
        for mapping in (None, explicit):
            for matcher in (match_indexed, match_reference):
                self.assertEqual(matcher(rules, hinted.findings, mapping), matcher(rules, plain.findings, mapping))
            audits = [audit(rules, report, as_of=ASOF, report_unfiltered=True, aliases=mapping)
                      for report in (hinted, plain)]
            self.assertEqual(audits[0]["rules"], audits[1]["rules"])
            self.assertEqual(audits[0]["rules"][2]["matchCount"], 1)
            for result in audits:
                result["provenance"] = {}
                plan = cleanup_plan(result, b"", "osv")
                self.assertEqual(plan["groups"]["report_local_orphans"], [])
                self.assertFalse(plan["unusedRuleAssertionAllowed"])
            for report in (hinted, plain):
                result = explain(rules, report, "alias", as_of=ASOF, report_unfiltered=True, aliases=mapping)
                self.assertEqual(result["coverage"], "unknown")
                self.assertNotIn("orphan_candidate", result["rule"]["status"])
                self.assertFalse(result["unusedRuleAssertionAllowed"])
                self.assertEqual(result["matchedEvidenceIds"], [])
                self.assertEqual(result["unknownEvidenceIds"], ["finding:0"] if mapping else [])
        # Known empty observations with only groups still cannot manufacture evidence.
        payload["results"][0]["packages"] = [{"package": {}, "vulnerabilities": [], "groups": [
            {"ids": ["CVE-1"], "aliases": ["GHSA-local"]}]}]
        empty = load_report(json.dumps(payload).encode(), "osv", report_unfiltered=True)
        result = explain(rules, empty, "alias", as_of=ASOF, report_unfiltered=True)
        self.assertEqual(result["evidence"], [])
        self.assertEqual(result["rule"]["matchCount"], 0)
        self.assertFalse(result["unusedRuleAssertionAllowed"])

    def test_absent_and_empty_alias_arrays_emit_no_hints(self):
        from vulnwrench.ignoreaudit import explain, load_report
        for vulnerability in ({"id": "CVE-1"}, {"id": "CVE-1", "aliases": []}):
            payload = {"results": [{"source": {}, "packages": [{"package": {},
                "groups": [{"ids": ["CVE-1"], "aliases": []}], "vulnerabilities": [vulnerability]}]}]}
            report = load_report(json.dumps(payload).encode(), "osv", report_unfiltered=True)
            result = explain([Rule("exact", "CVE-1")], report, "exact", as_of=ASOF, report_unfiltered=True)
            self.assertEqual(result["evidence"][0]["reportAliasHints"], [])
            self.assertEqual(result["rule"]["matchCount"], 1)

    def test_malformed_alias_hints_fail_without_touching_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            report, output = Path(tmp, "report.json"), Path(tmp, "out.json")
            output.write_text("keep")
            for bad in (None, {}, "GHSA-SECRET", [None], [17], ["GHSA-SECRET\n"], ["GHSA-*"]):
                for location in ("vulnerability", "group"):
                    package = {"package": {}, "vulnerabilities": [{"id": "CVE-1"}]}
                    if location == "vulnerability":
                        package["vulnerabilities"][0]["aliases"] = bad
                    else:
                        package["groups"] = [{"ids": ["CVE-1"], "aliases": bad}]
                    report.write_text(json.dumps({"results": [{"source": {}, "packages": [package]}]}))
                    with self.subTest(location=location, bad=bad):
                        output.write_text("keep")
                        proc = self.run_cli("--report", str(report), "--output", str(output))
                        self.assertEqual(proc.returncode, 2)
                        self.assertEqual(proc.stdout, "")
                        self.assertNotIn("SECRET", proc.stderr)
                        self.assertNotIn("Traceback", proc.stderr)
                        self.assertEqual(output.read_text(), "keep")

    def test_expired_global_rule_still_matches_all_paths(self):
        result = self.result(key="IgnoredVulns:0")
        self.assertEqual(result["scope"]["mode"], "global")
        self.assertEqual(result["rule"]["matchCount"], 3)
        self.assertEqual(result["expiry"]["state"], "expired")
        self.assertEqual(result["expiry"]["daysUntilExpiry"], -1)
        self.assertFalse(result["expiry"]["affectsAuditMatching"])
        self.assertEqual(self.check(result["evidence"][0], "advisory")["outcome"], "exact_id")
        self.assertEqual(self.check(result["evidence"][3], "source_dir")["outcome"], "unrestricted")
        self.assertNotIn("Synthetic migration exception", json.dumps(result))

    def test_explicit_directory_is_nonrecursive_and_missing_paths_unknown(self):
        result = self.result("--alias-map", "examples/ignores/aliases.json", "--osv-config-dir", "app")
        self.assertEqual(result["scope"]["mode"], "local_config_directory")
        self.assertEqual(result["scope"]["directoryMatching"], "exact_parent_nonrecursive")
        self.assertEqual(result["matchedEvidenceIds"], ["finding:0"])
        self.assertEqual(result["unknownEvidenceIds"], ["finding:3"])
        self.assertEqual([e["decision"] for e in result["evidence"]], ["match", "no_match", "no_match", "unknown"])
        self.assertEqual(self.check(result["evidence"][1], "source_dir"), {
            "selector": "source_dir", "expected": "app", "actual": "app/sub", "outcome": "mismatch"})
        self.assertEqual(result["evidence"][3]["reasons"], ["source_dir_evidence_unknown"])
        self.assertEqual(result["rule"]["unknownMatchCount"], 1)

    def test_incomplete_report_cannot_assert_orphan(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "report.json")
            for payload in ({}, {"results": None}, {"results": [{"source": {"path": "app/lock"}, "packages": [
                {"package": {"name": "unknown"}, "groups": [{"ids": ["CVE-2025-9999"]}]},
                {"package": {"name": "known"}, "vulnerabilities": [{"id": "CVE-2025-0001"}]}]}]}):
                path.write_text(json.dumps(payload))
                result = self.result("--report", str(path), key="IgnoredVulns:1")
                self.assertEqual(result["coverage"], "unknown")
                self.assertIn("coverage_unknown", result["rule"]["status"])
                self.assertNotIn("orphan_candidate", result["rule"]["status"])
                self.assertFalse(result["unusedRuleAssertionAllowed"])
                self.assertIn("caller assertion", " ".join(result["coverageAssumptions"]))

    def test_bad_selection_and_input_fail_without_touching_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp, "out.json")
            output.write_text("keep")
            for extra in ([], ["--report", "does-not-exist-SECRET"], ["--as-of", "2026-02-30"]):
                proc = self.run_cli(*extra, "--output", str(output), key="SECRET")
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stdout, "")
                self.assertNotIn("SECRET", proc.stderr)
                self.assertNotIn("Traceback", proc.stderr)
                self.assertEqual(output.read_text(), "keep")
        proc = self.run_cli("--output", "examples/ignores/explain-osv.json")
        self.assertEqual(proc.returncode, 2)

    def test_trivy_selected_by_physical_line(self):
        result = self.result("--format", "trivy", "--rules", "examples/ignores/.trivyignore", "--report", "examples/ignores/trivy.json",
                             key="line:2")
        self.assertEqual(result["matchedEvidenceIds"], ["finding:0", "finding:1"])
        self.assertEqual(result["evidence"][0]["locator"], "Results[0].Vulnerabilities[0]")
        self.assertEqual(result["evidence"][0]["finding"]["package"], "demo-a")
        self.assertTrue(all(e["reportAliasHints"] == [] for e in result["evidence"]))

    def test_library_selectors_mismatch_overrides_unknown(self):
        from vulnwrench.ignoreaudit import explain
        rule = Rule("selected", "CVE-1", package="demo", path="app/lock", ecosystem="npm", version="1")
        findings = (Finding("CVE-1", "demo", "app/./lock", "npm", "1"),
                    Finding("CVE-1", "demo", None, "npm", "1"),
                    Finding("CVE-1", "other", None, "npm", "1"),
                    Finding("CVE-2", "demo", None, "npm", "1"))
        result = explain([rule], Report(findings, "asserted_unfiltered"), "selected", as_of=ASOF, report_unfiltered=True)
        self.assertEqual([e["decision"] for e in result["evidence"]], ["match", "unknown", "no_match", "no_match"])
        self.assertEqual(result["matchedEvidenceIds"], ["finding:0"])
        self.assertEqual(result["unknownEvidenceIds"], ["finding:1"])
        self.assertEqual(result["evidence"][2]["reasons"], ["package_mismatch"])
        self.assertEqual(result["evidence"][3]["reasons"], ["advisory_mismatch"])
        self.assertEqual(self.check(result["evidence"][0], "path")["actual"], "app/lock")
        self.assertEqual(result["expiry"]["state"], "no_expiry")
        with self.assertRaises(InputError):
            explain([rule], Report(findings, "unknown"), "missing", as_of=ASOF, report_unfiltered=True)

    def test_expiry_boundaries_and_duplicate_observation_ids(self):
        from vulnwrench.ignoreaudit import explain
        finding = Finding("CVE-1", "demo", "lock", locator="same-locator")
        for expires, state in ((ASOF, "soon_expiring"), (date(2026, 12, 12), "active")):
            rules = [Rule("selected", "CVE-1", expires=expires), Rule("duplicate", "CVE-1")]
            result = explain(rules, Report((finding, finding), "asserted_unfiltered"), "selected",
                             as_of=ASOF, report_unfiltered=True)
            self.assertEqual(result["expiry"]["state"], state)
            self.assertEqual(result["matchedEvidenceIds"], ["finding:0", "finding:1"])
            self.assertEqual(result["rule"]["duplicateOf"], ["duplicate"])
            self.assertFalse(result["unusedRuleAssertionAllowed"])


if __name__ == "__main__":
    unittest.main()
