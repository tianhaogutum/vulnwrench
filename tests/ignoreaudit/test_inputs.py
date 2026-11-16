import json
from datetime import date
from pathlib import Path
import unittest

from vulnwrench.ignoreaudit import InputError, load_aliases, load_report, load_rules
from vulnwrench.ignoreaudit.inputs import apply_metadata, digest, parse_date

ROOT = Path(__file__).resolve().parents[2]


def raw(value):
    return json.dumps(value).encode()


class InputTests(unittest.TestCase):
    def trivy(self, result=None):
        return {"SchemaVersion": 2, "Results": [] if result is None else [result]}

    def test_native_trivy(self):
        rules = load_rules((ROOT / "examples/ignores/.trivyignore").read_bytes(), "trivy")
        report = load_report((ROOT / "examples/ignores/trivy.json").read_bytes(), "trivy", report_unfiltered=True)
        self.assertEqual(rules[0].key, "line:2")
        self.assertEqual(rules[0].expires, date(2026, 11, 10))
        self.assertEqual(len(report.findings), 3)
        self.assertEqual(report.findings[0].path, "app/package-lock.json")
        self.assertIn("Results[].Vulnerabilities[].Severity", report.uninterpreted_fields)

    def test_native_osv_date_and_string(self):
        rules = load_rules((ROOT / "examples/ignores/osv-scanner.toml").read_bytes(), "osv")
        report = load_report((ROOT / "examples/ignores/osv.json").read_bytes(), "osv", report_unfiltered=True)
        self.assertEqual(rules[1].expires, date(2026, 12, 1))
        self.assertEqual(report.findings[0].ecosystem, "npm")
        self.assertEqual(len(report.findings), 3)

    def test_acknowledgment(self):
        for format in ("trivy", "osv"):
            with self.subTest(format=format), self.assertRaises(InputError):
                load_report(b"{}", format)

    def test_empty_vs_unknown_coverage(self):
        for format, known, unknown in (("trivy", self.trivy(), {"SchemaVersion": 2}),
                                       ("osv", {"results": []}, {})):
            with self.subTest(format=format):
                self.assertEqual(load_report(raw(known), format, report_unfiltered=True).coverage, "asserted_unfiltered")
                self.assertEqual(load_report(raw(unknown), format, report_unfiltered=True).coverage, "unknown")

    def test_bad_dates(self):
        for value in ("2026-02-29", "2026-1-01", "20261111", "2026-11-11T00:00:00Z", "", 1, True):
            with self.subTest(value=value), self.assertRaises(InputError):
                parse_date(value)
        for content in (b"CVE-1 exp:not-a-date", b"CVE-1 exp:2026-02-30"):
            with self.assertRaises(InputError):
                load_rules(content, "trivy")
        with self.assertRaises(InputError):
            load_rules(b'[[IgnoredVulns]]\nid="CVE-1"\neffectiveUntil=2026-11-11T12:00:00Z', "osv")

    def test_unsupported_rules(self):
        for content in (b"CVE-1 paths:src/*", b"vulnerabilities:\n - id: CVE-1", b"CVE-*", b"CVE-1 exp:2026-01-01 another"):
            with self.subTest(content=content), self.assertRaises(InputError):
                load_rules(content, "trivy")
        for content in (b'[[IgnoredVulns]]\nid="CVE-1"\npaths=["src/*"]', b'[[PackageOverrides]]\nname="demo"\nignore=true', b'ScanGoModVersion=true'):
            with self.subTest(content=content), self.assertRaises(InputError):
                load_rules(content, "osv")
        with self.assertRaises(InputError):
            load_rules(b"ignore: []", "grype")

    def test_strict_json_and_no_secret_errors(self):
        for content in (b'{"SchemaVersion":2,"Results":[],"secret":"DO-NOT-LEAK"}',
                        b'{"results":[],"results":[]}', b'{"results":NaN}', b'[]', b'not-json-DO-NOT-LEAK', b'\xff'):
            with self.subTest(content=content):
                with self.assertRaises(InputError) as ctx:
                    load_report(content, "osv", report_unfiltered=True)
                self.assertNotIn("DO-NOT-LEAK", str(ctx.exception))

    def test_structural_types_never_coerced(self):
        for bad in ({}, "", 0, False):
            for report in (self.trivy({"Vulnerabilities": bad}), self.trivy({"Secrets": bad})):
                with self.subTest(report=report), self.assertRaises(InputError):
                    load_report(raw(report), "trivy", report_unfiltered=True)
        for version in (1, 3, True, "2"):
            with self.assertRaises(InputError):
                load_report(raw({"SchemaVersion": version, "Results": []}), "trivy", report_unfiltered=True)

    def test_unknown_report_field_and_suppressed(self):
        for result in ({"Target": "app", "NewSelector": []}, {"Secrets": [{"RuleID": "redacted"}]},
                       {"ExperimentalModifiedFindings": [{"Type": "vulnerability"}]}):
            with self.assertRaises(InputError):
                load_report(raw(self.trivy(result)), "trivy", report_unfiltered=True)
        with self.assertRaises(InputError):
            load_report(raw({"results": [], "experimental_config": {"ignore": True}}), "osv", report_unfiltered=True)

    def test_metadata_bound_to_rules(self):
        content = b"CVE-1\n"
        rules = load_rules(content, "trivy")
        sidecar = {"schemaVersion": 1, "rulesSha256": digest(content), "rules": {"line:1": {"owner": "team", "reason": "reviewed"}}}
        result = apply_metadata(rules, raw(sidecar), digest(content))
        self.assertEqual(result[0].owner, "team")
        with self.assertRaises(InputError):
            apply_metadata(rules, raw(sidecar), digest(b"changed"))
        sidecar["rules"]["line:1"]["selectors"] = {"path": "*"}
        with self.assertRaises(InputError):
            apply_metadata(rules, raw(sidecar), digest(content))

    def test_metadata_native_reason_conflict_and_stale_locator(self):
        rules = load_rules(b'[[IgnoredVulns]]\nid="CVE-1"\nreason="native"', "osv")
        sidecar = {"schemaVersion": 1, "rulesSha256": "hash", "rules": {"IgnoredVulns:0": {"reason": "different"}}}
        with self.assertRaises(InputError):
            apply_metadata(rules, raw(sidecar), "hash")
        sidecar["rules"] = {"line:999": {"owner": "team"}}
        with self.assertRaises(InputError):
            apply_metadata(rules, raw(sidecar), "hash")

    def test_alias_map_validation(self):
        mapping = load_aliases(raw({"schemaVersion": 1, "groups": [["CVE-1", "GHSA-a"]]}))
        self.assertEqual(mapping["CVE-1"], {"CVE-1", "GHSA-a"})
        for groups in ([["CVE-1"]], [["CVE-1", "CVE-1"]], [["CVE-1", "GHSA-a"], ["GHSA-a", "OTHER"]]):
            with self.assertRaises(InputError):
                load_aliases(raw({"schemaVersion": 1, "groups": groups}))

    def test_source_dir_rejects_globs(self):
        for path in ("src/*", "src/../other", "C:\\path"):
            with self.assertRaises(InputError):
                load_rules(b"", "osv", path)
        with self.assertRaises(InputError):
            load_rules(b"", "trivy", "app")

    def test_result_class_and_experimental_config_types(self):
        for value in ({}, [], False, "secret", "config", "future-class"):
            with self.subTest(value=value), self.assertRaises(InputError):
                load_report(raw(self.trivy({"Class": value})), "trivy", report_unfiltered=True)
        for value in (False, [], "", None):
            with self.subTest(value=value), self.assertRaises(InputError):
                load_report(raw({"results": [], "experimental_config": value}), "osv", report_unfiltered=True)

    def test_native_empty_optional_strings_are_unknown(self):
        report = load_report(raw(self.trivy({"Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "", "PkgPath": ""}]})),
                             "trivy", report_unfiltered=True)
        self.assertIsNone(report.findings[0].package)
        self.assertIsNone(report.findings[0].path)
        self.assertIsNone(load_rules(b'[[IgnoredVulns]]\nid="CVE-1"\nreason=""', "osv")[0].reason)


if __name__ == "__main__":
    unittest.main()
