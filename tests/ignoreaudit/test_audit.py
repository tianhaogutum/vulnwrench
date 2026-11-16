from datetime import date
import random
import unittest

from vulnwrench.ignoreaudit import Finding, InputError, Report, Rule, audit, match_indexed, match_reference
from vulnwrench.ignoreaudit.audit import markdown

ASOF = date(2026, 11, 11)


class AuditTests(unittest.TestCase):
    def run_audit(self, rules, findings=(), coverage="asserted_unfiltered", **kwargs):
        return audit(rules, Report(tuple(findings), coverage), as_of=ASOF, report_unfiltered=True, **kwargs)

    def test_duplicates_and_expiry_boundaries(self):
        rules = [Rule("a", "CVE-1", date(2026, 11, 10)), Rule("b", "CVE-1", ASOF),
                 Rule("c", "CVE-2", date(2026, 12, 11)), Rule("d", "CVE-3", date(2026, 12, 12))]
        rows = self.run_audit(rules, [Finding("CVE-1", "a", "app/lock")])["rules"]
        self.assertIn("expired", rows[0]["status"])
        self.assertIn("soon_expiring", rows[1]["status"])
        self.assertNotIn("expired", rows[1]["status"])
        self.assertIn("soon_expiring", rows[2]["status"])
        self.assertNotIn("soon_expiring", rows[3]["status"])
        self.assertEqual(rows[0]["matchCount"], 1)  # expired still matches for audit
        self.assertEqual(rows[0]["duplicateOf"], ["b"])

    def test_empty_report_known_vs_unknown(self):
        rule = Rule("a", "CVE-1")
        self.assertIn("orphan_candidate", self.run_audit([rule])["rules"][0]["status"])
        self.assertNotIn("orphan_candidate", self.run_audit([rule], coverage="unknown")["rules"][0]["status"])
        self.assertIn("coverage_unknown", self.run_audit([rule], coverage="unknown")["rules"][0]["status"])

    def test_aliases_require_explicit_map(self):
        rule = Rule("a", "GHSA-alias")
        finding = Finding("CVE-1", "demo", "lock")
        self.assertEqual(self.run_audit([rule], [finding])["rules"][0]["matchCount"], 0)
        aliases = {"GHSA-alias": {"CVE-1", "GHSA-alias"}, "CVE-1": {"CVE-1", "GHSA-alias"}}
        self.assertEqual(self.run_audit([rule], [finding], aliases=aliases)["rules"][0]["matchCount"], 1)

    def test_exact_selectors_and_missing_evidence(self):
        rules = [Rule("a", "CVE-1", package="demo", path="app/lock", ecosystem="npm", version="1"),
                 Rule("b", "CVE-1", package="other"), Rule("c", "CVE-1", path="unknown")]
        findings = [Finding("CVE-1", "demo", "app/lock", "npm", "1"), Finding("CVE-1", "demo", None, "npm", "1")]
        rows = self.run_audit(rules, findings)["rules"]
        self.assertEqual((rows[0]["matchCount"], rows[0]["unknownMatchCount"]), (1, 1))
        self.assertIn("orphan_candidate", rows[1]["status"])
        self.assertIn("coverage_unknown", rows[2]["status"])
        self.assertNotIn("orphan_candidate", rows[2]["status"])

    def test_osv_local_config_not_recursive(self):
        rule = Rule("a", "CVE-1", source_dir="app")
        findings = [Finding("CVE-1", "a", "app/lock"), Finding("CVE-1", "a", "app/sub/lock"),
                    Finding("CVE-1", "a", "another/lock")]
        self.assertEqual(self.run_audit([rule], findings)["rules"][0]["matchCount"], 1)

    def test_package_breadth(self):
        findings = [Finding("CVE-1", "demo-a", "a", "npm", "1"), Finding("CVE-1", "demo-a", "b", "npm", "2"),
                    Finding("CVE-1", "demo-b", "c", "npm", "1"), Finding("CVE-1", None, "d")]
        row = self.run_audit([Rule("a", "CVE-1")], findings)["rules"][0]
        self.assertEqual(row["matchCount"], 4)
        self.assertEqual(len(row["matchedPackages"]), 2)
        self.assertIn("overly_broad", row["status"])
        self.assertIn("package_breadth_unknown", row["status"])

    def test_owner_and_reason_not_echoed(self):
        row = self.run_audit([Rule("a", "CVE-1", reason="SECRET-REASON", owner="SECRET-OWNER")])["rules"][0]
        self.assertTrue(row["hasReason"])
        self.assertTrue(row["hasOwner"])
        self.assertNotIn("SECRET", str(row))
        self.assertNotIn("missing_owner", row["status"])

    def test_observation_counts_not_collapsed(self):
        findings = [Finding("CVE-1", "a", "lock"), Finding("CVE-1", "a", "lock")]
        self.assertEqual(self.run_audit([Rule("a", "CVE-1")], findings)["rules"][0]["matchedFindings"], ["finding:0", "finding:1"])

    def test_globs_fail_and_locators_unique(self):
        for rule in (Rule("a", "CVE-1", package="demo*"), Rule("a", "CVE-1", path="app/?"), Rule("a", "CVE-1", path="app/../lock")):
            with self.assertRaises(InputError):
                self.run_audit([rule])
        with self.assertRaises(InputError):
            self.run_audit([Rule("a", "CVE-1"), Rule("a", "CVE-2")])

    def test_input_api_constraints(self):
        with self.assertRaises(InputError):
            audit([], Report((), "asserted_unfiltered"), as_of=ASOF)
        with self.assertRaises(InputError):
            self.run_audit([], soon_days=-1)
        with self.assertRaises(InputError):
            self.run_audit([], coverage="complete")

    def test_equivalence_generated(self):
        # Vary sizes, aliases, absent selector evidence, duplicates, and zero cases.
        for seed in range(60):
            rng = random.Random(seed)
            findings = [Finding(f"CVE-{rng.randrange(12)}", rng.choice([None, "a", "b", "c"]),
                                rng.choice([None, "app/lock", "sub/lock"]), rng.choice([None, "npm", "PyPI"]),
                                rng.choice([None, "1", "2"]), f"finding:{i}") for i in range(rng.randrange(50))]
            rules = [Rule(f"rule:{i}", f"CVE-{rng.randrange(12)}", package=rng.choice([None, "a", "b"]),
                          path=rng.choice([None, "app/lock", "sub/lock"]), ecosystem=rng.choice([None, "npm"]),
                          version=rng.choice([None, "1"]), source_dir=rng.choice([None, "app"])) for i in range(rng.randrange(30))]
            aliases = {"CVE-0": {"CVE-0", "CVE-1"}, "CVE-1": {"CVE-0", "CVE-1"}} if seed % 2 else None
            with self.subTest(seed=seed):
                self.assertEqual(match_reference(rules, findings, aliases)[:2], match_indexed(rules, findings, aliases)[:2])
                baseline = self.run_audit(rules, findings, aliases=aliases, matcher="reference")
                indexed = self.run_audit(rules, findings, aliases=aliases)
                baseline.pop("matcher")
                indexed.pop("matcher")
                self.assertEqual(baseline, indexed)

    def test_markdown_escapes_injected_content(self):
        result = self.run_audit([Rule("a|<b>", "CVE-1")])
        content = markdown(result)
        self.assertIn("a&#124;&lt;b&gt;", content)
        self.assertNotIn("a|<b>", content)

    def test_iterators_match_and_invalid_aliases_fail_closed(self):
        rules = [Rule("a", "CVE-1")]
        findings = [Finding("CVE-1", "a", "lock")]
        self.assertEqual(match_reference(iter(rules), iter(findings))[:2], match_indexed(iter(rules), iter(findings))[:2])
        for aliases in ([], {"CVE-1": "CVE-2"}, {"CVE-1": {"CVE-2"}}, {"CVE-1": {"CVE-1", "CVE-2"}}):
            with self.subTest(aliases=aliases), self.assertRaises(InputError):
                match_indexed(rules, findings, aliases)


if __name__ == "__main__":
    unittest.main()
