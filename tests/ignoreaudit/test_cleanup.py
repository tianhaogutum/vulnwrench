"""Synthetic native-format contracts for a strictly review-only cleanup export."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


class CleanupPlanTests(unittest.TestCase):
    def run_cli(self, rules, report, *extra, format="trivy"):
        return subprocess.run([sys.executable, "-m", "vulnwrench", "ignores", "cleanup-plan", "--format", format,
                               "--rules", str(rules), "--report", str(report), "--report-unfiltered",
                               "--as-of", "2026-11-11", *extra], cwd=ROOT, text=True, capture_output=True, timeout=60)

    def result(self, *args, **kwargs):
        proc = self.run_cli(*args, **kwargs)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def fixture(self, tmp):
        rules, report = Path(tmp, ".trivyignore"), Path(tmp, "report.json")
        # Comments, CRLF, duplicate IDs, whitespace and final unterminated line
        # must remain resolvable from the exact source, never reconstructed text.
        rules.write_bytes(b"# private comment\r\n CVE-1 exp:2026-11-10 # private note\r\nCVE-2\r\nCVE-1")
        report.write_text(json.dumps({"SchemaVersion": 2, "Results": [{"Target": "app/lock", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "PkgName": "demo-a"},
            {"VulnerabilityID": "CVE-1", "PkgName": "demo-b"}]}]}))
        return rules, report

    def assert_source(self, candidate, raw, key, format):
        ref = candidate["sourceReference"]
        self.assertEqual(ref["rulesSha256"], sha256(raw).hexdigest())
        self.assertEqual(ref["rulesByteLength"], len(raw))
        self.assertEqual(ref["locator"], key)
        self.assertEqual(ref["format"], format)
        self.assertEqual(candidate["rule"]["key"], key)
        self.assertTrue(candidate["assumptions"])
        self.assertTrue(candidate["suggestedManualAction"])
        self.assertFalse(candidate["definiteRemovalRecommended"])

    def test_groups_actions_lossless_sources_and_determinism(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules, report = self.fixture(tmp)
            originals = {p: p.read_bytes() for p in (rules, report)}
            raw = originals[rules]
            metadata = Path(tmp, "metadata.json")
            metadata.write_text(json.dumps({"schemaVersion": 1, "rulesSha256": sha256(raw).hexdigest(),
                                           "rules": {"line:2": {"owner": "PRIVATE-TEAM", "reason": "PRIVATE-REASON"}}}))
            result = self.result(rules, report, "--metadata", str(metadata))
            self.assertEqual(result["command"], "cleanup-plan")
            self.assertTrue(result["reviewOnly"])
            self.assertFalse(result["automaticChangesAllowed"])
            self.assertFalse(result["unusedRuleAssertionAllowed"])
            expected = {"expired": ["line:2"], "ownerless": ["line:3", "line:4"],
                        "broad": ["line:2", "line:4"], "report_local_orphans": ["line:3"]}
            self.assertEqual({group: [c["rule"]["key"] for c in candidates]
                              for group, candidates in result["groups"].items()}, expected)
            self.assertEqual(result["summary"]["candidateRuleCount"], 3)
            self.assertEqual(result["summary"]["groupCounts"], {group: len(keys) for group, keys in expected.items()})
            for group in result["groups"].values():
                for candidate in group:
                    self.assert_source(candidate, raw, candidate["rule"]["key"], "trivy")
                    line = int(candidate["sourceReference"]["locator"].split(":")[1])
                    self.assertIn(candidate["rule"]["rule"], raw.decode().splitlines()[line - 1])
            self.assertEqual(result["groups"]["broad"][0]["rule"]["matchCount"], 2)
            orphan = result["groups"]["report_local_orphans"][0]
            self.assertIn("alias", " ".join(orphan["assumptions"]).lower())
            self.assertIn("report", orphan["suggestedManualAction"].lower())
            self.assertEqual(result["excludedFromOrphanReview"], [])
            serialized = json.dumps(result)
            for private in ("private comment", "private note", "PRIVATE-TEAM", "PRIVATE-REASON"):
                self.assertNotIn(private, serialized)
            self.assertEqual(self.run_cli(rules, report, "--metadata", str(metadata)).stdout,
                             self.run_cli(rules, report, "--metadata", str(metadata)).stdout)
            self.assertEqual(originals, {p: p.read_bytes() for p in originals})

    def test_incomplete_coverage_blocks_orphan_review_but_retains_other_groups(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules, report = Path(tmp, "osv.toml"), Path(tmp, "report.json")
            raw = ('# retained source: café\n[[IgnoredVulns]]\nid="CVE-1"\neffectiveUntil=2026-11-10\n'
                   'reason="""private reason"""\n\n[[IgnoredVulns]]\nid="CVE-2"\n').encode()
            rules.write_bytes(raw)
            for state in ("absent", "null", "empty"):
                package = {"package": {"name": "demo"}, "groups": [{"ids": ["CVE-2"]}]}
                if state != "absent":
                    package["vulnerabilities"] = None if state == "null" else []
                report.write_text(json.dumps({"results": [{"source": {"path": "app/lock"}, "packages": [package]}]}))
                result = self.result(rules, report, format="osv")
                with self.subTest(state=state):
                    candidates = result["groups"]["report_local_orphans"]
                    self.assertEqual(len(candidates), 2 if state == "empty" else 0)
                    self.assertEqual(len(result["excludedFromOrphanReview"]), 0 if state == "empty" else 2)
                    self.assertEqual(len(result["groups"]["expired"]), 1)
                    self.assertEqual(len(result["groups"]["ownerless"]), 2)
                    for candidate in result["groups"]["ownerless"]:
                        key = candidate["rule"]["key"]
                        self.assert_source(candidate, raw, key, "osv")
                        index = int(key.split(":")[1])
                        self.assertEqual(tomllib.loads(raw.decode())["IgnoredVulns"][index]["id"], candidate["rule"]["rule"])
                    self.assertNotIn("private reason", json.dumps(result))
                    if state != "empty":
                        self.assertEqual(result["coverage"], "unknown")
                        self.assertTrue(all("coverage_unknown" in c["reasons"] for c in result["excludedFromOrphanReview"]))

    def test_unknown_scope_excluded_and_expiry_boundary_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules, report = Path(tmp, "osv.toml"), Path(tmp, "report.json")
            rules.write_text('[[IgnoredVulns]]\nid="CVE-1"\neffectiveUntil=2026-11-11\n')
            report.write_text(json.dumps({"results": [{"source": {}, "packages": [
                {"package": {"name": "demo"}, "vulnerabilities": [{"id": "CVE-1"}]}]}]}))
            result = self.result(rules, report, "--osv-config-dir", "app", format="osv")
            self.assertEqual(result["coverage"], "asserted_unfiltered")
            self.assertEqual(result["groups"]["expired"], [])
            self.assertEqual(result["groups"]["report_local_orphans"], [])
            self.assertIn("selector_evidence_unknown", result["excludedFromOrphanReview"][0]["reasons"])
            self.assertEqual(result["groups"]["ownerless"][0]["rule"]["unknownMatchCount"], 1)

    def test_empty_and_fully_annotated_matched_rules_have_no_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules, report = self.fixture(tmp)
            rules.write_bytes(b"")
            self.assertTrue(all(not group for group in self.result(rules, report)["groups"].values()))
            rules.write_bytes(b"CVE-1\n")
            report.write_text('{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"demo"}]}]}')
            metadata = Path(tmp, "metadata.json")
            metadata.write_text(json.dumps({"schemaVersion": 1, "rulesSha256": sha256(rules.read_bytes()).hexdigest(),
                                           "rules": {"line:1": {"owner": "team", "reason": "reviewed"}}}))
            result = self.result(rules, report, "--metadata", str(metadata))
            self.assertEqual(result["summary"]["candidateRuleCount"], 0)
            self.assertTrue(all(not group for group in result["groups"].values()))

    def test_explicit_alias_map_changes_orphan_group_using_existing_matcher(self):
        rules, report = ROOT / "examples/ignores/osv-scanner.toml", ROOT / "examples/ignores/osv.json"
        exact = self.result(rules, report, format="osv")
        mapped = self.result(rules, report, "--alias-map", str(ROOT / "examples/ignores/aliases.json"), format="osv")
        self.assertEqual([c["rule"]["key"] for c in exact["groups"]["report_local_orphans"]],
                         ["IgnoredVulns:1", "IgnoredVulns:2"])
        self.assertEqual([c["rule"]["key"] for c in mapped["groups"]["report_local_orphans"]], ["IgnoredVulns:1"])
        self.assertEqual([c["rule"]["key"] for c in mapped["groups"]["broad"]], ["IgnoredVulns:0", "IgnoredVulns:2"])
        self.assertEqual(mapped["provenance"]["aliases"], "explicit_local_groups")

    def test_missing_root_coverage_excludes_orphans_in_both_formats(self):
        with tempfile.TemporaryDirectory() as tmp:
            for format, content, root in (("trivy", b"CVE-1", {"SchemaVersion": 2}),
                                           ("osv", b'[[IgnoredVulns]]\nid="CVE-1"', {})):
                rules, report = Path(tmp, "rules.txt"), Path(tmp, "report.json")
                rules.write_bytes(content)
                report.write_text(json.dumps(root))
                with self.subTest(format=format):
                    result = self.result(rules, report, format=format)
                    self.assertEqual(result["groups"]["report_local_orphans"], [])
                    self.assertEqual(result["summary"]["orphanReviewExcludedCount"], 1)
                    self.assertEqual(result["coverage"], "unknown")

    def test_file_export_and_failures_preserve_inputs_and_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules, report = self.fixture(tmp)
            output = Path(tmp, "plan.json")
            metadata, aliases = Path(tmp, "metadata.json"), Path(tmp, "aliases.json")
            metadata.write_text(json.dumps({"schemaVersion": 1, "rulesSha256": sha256(rules.read_bytes()).hexdigest(), "rules": {}}))
            aliases.write_text('{"schemaVersion":1,"groups":[]}')
            options = ["--metadata", str(metadata), "--alias-map", str(aliases)]
            originals = {p: p.read_bytes() for p in (rules, report, metadata, aliases)}
            proc = self.run_cli(rules, report, *options, "--output", str(output))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, "")
            self.assertTrue(json.loads(output.read_text())["reviewOnly"])
            no_ack = proc.args.copy()
            no_ack.remove("--report-unfiltered")
            output.write_text("retain previous output")
            proc = subprocess.run(no_ack, cwd=ROOT, text=True, capture_output=True, timeout=60)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(proc.stdout, "")
            self.assertEqual(output.read_text(), "retain previous output")
            for extra in (["--as-of", "2026-02-30"], ["--soon-days", "-1"], ["--report", "missing-PRIVATE"],
                          ["--output-format", "html"]):
                output.write_text("retain previous output")
                proc = self.run_cli(rules, report, *options, "--output", str(output), *extra)
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stdout, "")
                self.assertEqual(output.read_text(), "retain previous output")
                self.assertNotIn("missing-PRIVATE", proc.stderr)
            for input_path in originals:
                for mode in ("direct", "symlink", "hardlink"):
                    dest = input_path
                    if mode != "direct":
                        dest = Path(tmp, "alias-output")
                        if mode == "symlink":
                            dest.symlink_to(input_path)
                        else:
                            dest.hardlink_to(input_path)
                    proc = self.run_cli(rules, report, *options, "--output", str(dest))
                    self.assertEqual(proc.returncode, 2, proc.stderr)
                    if mode != "direct":
                        dest.unlink()
                    self.assertEqual(originals, {p: p.read_bytes() for p in originals})
            report.write_text('{"SchemaVersion":2,"Results":"PRIVATE"}')
            output.write_text("retain previous output")
            proc = self.run_cli(rules, report, "--output", str(output))
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(proc.stdout, "")
            self.assertNotIn("PRIVATE", proc.stderr)
            self.assertEqual(output.read_text(), "retain previous output")


if __name__ == "__main__":
    unittest.main()
