"""Markdown exports preserve the JSON plan's review evidence and exclusions."""
from hashlib import sha256
from html import unescape
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class CleanupMarkdownTests(unittest.TestCase):
    def run_cli(self, rules, report, *extra, format="trivy"):
        return subprocess.run([sys.executable, "-m", "vulnwrench", "ignores", "cleanup-plan", "--format", format,
                               "--rules", str(rules), "--report", str(report), "--report-unfiltered",
                               "--as-of", "2026-11-11", *extra], cwd=ROOT, text=True, capture_output=True, timeout=60)

    def assert_parity(self, rules, report, *extra, format="trivy"):
        json_proc = self.run_cli(rules, report, *extra, format=format)
        self.assertEqual(json_proc.returncode, 0, json_proc.stderr)
        plan = json.loads(json_proc.stdout)
        proc = self.run_cli(rules, report, *extra, "--output-format", "markdown", format=format)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        text = proc.stdout
        self.assertTrue(text.startswith("# Ignore cleanup plan\n"))
        sections = {unescape(k): v for k, v in re.findall(r"^## ([^\n]+)\n(.*?)(?=^## |\Z)", text, re.M | re.S)}
        context = json.loads(re.search(r"```json\n(.*?)\n```", sections["Context"], re.S)[1])
        self.assertEqual(context, {k: v for k, v in plan.items()
                                   if k not in {"groups", "excludedFromOrphanReview", "sourceResolution"}})
        self.assertIn(plan["sourceResolution"], unescape(sections["Source resolution"]))

        def check_entries(section, entries, excluded=False):
            headings = re.findall(r"^### (.+)$", section, re.M)
            self.assertEqual(len(headings), len(entries))
            bodies = re.split(r"^### .+\n", section, flags=re.M)[1:]
            if not entries:
                self.assertIn("None.", section)
            for heading, body, entry in zip(headings, bodies, entries):
                ref = entry["sourceReference"]
                self.assertEqual(unescape(heading), entry["key"] if excluded else entry["rule"]["key"] + " — " + entry["rule"]["rule"])
                plain = unescape(body)
                self.assertIn("sha256:" + ref["rulesSha256"] + "#" + ref["locator"], plain)
                self.assertIn(str(ref["rulesByteLength"]) + " bytes", plain)
                self.assertIn(ref["format"], plain)
                self.assertIn(ref["locatorConvention"], plain)
                self.assertIn("Suggested manual action: " + entry["suggestedManualAction"], plain)
                self.assertIn("definiteRemovalRecommended: false", plain)
                for assumption in entry["assumptions"]:
                    self.assertIn("- " + assumption, plain)
                if excluded:
                    self.assertIn("Reasons: " + ", ".join(entry["reasons"]), plain)
                else:
                    evidence = json.loads(re.search(r"```json\n(.*?)\n```", body, re.S)[1])
                    self.assertEqual(evidence, entry["rule"])

        for group, entries in plan["groups"].items():
            check_entries(sections[f"{group} ({len(entries)})"], entries)
        excluded = plan["excludedFromOrphanReview"]
        check_entries(sections[f"excludedFromOrphanReview ({len(excluded)})"], excluded, excluded=True)
        self.assertEqual(len(sections), 7)
        self.assertTrue(plan["reviewOnly"])
        self.assertFalse(plan["automaticChangesAllowed"])
        self.assertFalse(plan["unusedRuleAssertionAllowed"])
        return plan, text

    def test_markdown_group_contract_matches_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules, report = Path(tmp, ".trivyignore"), Path(tmp, "report.json")
            raw = b"# private comment\r\n CVE-1 exp:2026-11-10 # private note\r\nCVE-2\r\nCVE-1"
            rules.write_bytes(raw)
            report.write_text(json.dumps({"SchemaVersion": 2, "Results": [{"Target": "app/lock", "Vulnerabilities": [
                {"VulnerabilityID": "CVE-1", "PkgName": "demo-a"},
                {"VulnerabilityID": "CVE-1", "PkgName": "demo-b"}]}]}))
            originals = {p: p.read_bytes() for p in (rules, report)}
            plan, text = self.assert_parity(rules, report)
            self.assertEqual({g: [c["rule"]["key"] for c in cs] for g, cs in plan["groups"].items()},
                             {"expired": ["line:2"], "ownerless": ["line:2", "line:3", "line:4"],
                              "broad": ["line:2", "line:4"], "report_local_orphans": ["line:3"]})
            self.assertEqual(plan["summary"]["candidateRuleCount"], 3)
            self.assertIn(sha256(raw).hexdigest(), text)
            self.assertNotIn("private comment", text)
            self.assertNotIn("private note", text)
            metadata = Path(tmp, "metadata.json")
            metadata.write_text(json.dumps({"schemaVersion": 1, "rulesSha256": sha256(raw).hexdigest(),
                                           "rules": {"line:2": {"owner": "PRIVATE-OWNER", "reason": "PRIVATE-REASON"}}}))
            _, annotated = self.assert_parity(rules, report, "--metadata", str(metadata))
            self.assertNotIn("PRIVATE-", annotated)
            output = Path(tmp, "plan.md")
            proc = self.run_cli(rules, report, "--output-format", "markdown", "--output", str(output))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, "")
            self.assertEqual(output.read_bytes(), text.encode("utf-8"))
            self.assertEqual(originals, {p: p.read_bytes() for p in originals})

    def test_markdown_coverage_and_selector_exclusions_match_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules, report = Path(tmp, "osv.toml"), Path(tmp, "report.json")
            rules.write_bytes('# café\r\n[[IgnoredVulns]]\r\nid="CVE-1"\r\neffectiveUntil=2026-11-10\r\n'
                              'reason="private reason"\r\n[[IgnoredVulns]]\r\nid="CVE-2"'.encode())
            for state in ("absent", "null", "empty"):
                incomplete = {"package": {"name": "demo"}, "groups": [{"ids": ["CVE-2"]}]}
                if state != "absent":
                    incomplete["vulnerabilities"] = None if state == "null" else []
                report.write_text(json.dumps({"results": [{"source": {"path": "app/lock"}, "packages": [incomplete,
                    {"package": {"name": "known"}, "vulnerabilities": [{"id": "CVE-1"}]}]}]}))
                with self.subTest(state=state):
                    plan, text = self.assert_parity(rules, report, format="osv")
                    self.assertEqual(plan["coverage"], "asserted_unfiltered" if state == "empty" else "unknown")
                    self.assertEqual(len(plan["groups"]["report_local_orphans"]), 1 if state == "empty" else 0)
                    self.assertEqual(len(plan["excludedFromOrphanReview"]), 0 if state == "empty" else 1)
                    self.assertEqual(len(plan["groups"]["expired"]), 1)
                    self.assertNotIn("private reason", text)
            report.write_text('{"results":[{"source":{},"packages":[{"package":{},"vulnerabilities":[{"id":"CVE-1"}]}]}]}')
            plan, _ = self.assert_parity(rules, report, "--osv-config-dir", "app", format="osv")
            self.assertEqual([c["rule"]["key"] for c in plan["groups"]["report_local_orphans"]], ["IgnoredVulns:1"])
            self.assertEqual(plan["excludedFromOrphanReview"][0]["key"], "IgnoredVulns:0")
            self.assertIn("selector_evidence_unknown", plan["excludedFromOrphanReview"][0]["reasons"])
            rules.write_bytes(b"")
            plan, _ = self.assert_parity(rules, report, format="osv")
            self.assertEqual(plan["summary"]["candidateRuleCount"], 0)
            self.assertEqual(plan["excludedFromOrphanReview"], [])

    def test_markdown_alias_map_parity_and_report_text_cannot_break_fences(self):
        for extra in ((), ("--alias-map", str(ROOT / "examples/ignores/aliases.json"))):
            with self.subTest(extra=extra):
                self.assert_parity(ROOT / "examples/ignores/osv-scanner.toml", ROOT / "examples/ignores/osv.json", *extra, format="osv")
        with tempfile.TemporaryDirectory() as tmp:
            rules, report = Path(tmp, "rules.txt"), Path(tmp, "report.json")
            rules.write_bytes(b"CVE-1")
            report.write_text(json.dumps({"SchemaVersion": 2, "Results": [{"Vulnerabilities": [
                {"VulnerabilityID": "CVE-1", "PkgName": "```<script>alert(1)</script>[click](https://invalid.example)|*é*"}]}]}))
            _, text = self.assert_parity(rules, report)
            self.assertNotIn("<script>", text)
            self.assertNotIn("```\\n", text)
            # All report data remains literal JSON, never new Markdown blocks.
            self.assertEqual(text.count("```json\n"), 2)
            self.assertEqual(text.count("\n```\n"), 2)

    def test_markdown_failures_preserve_inputs_and_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules, report = Path(tmp, "rules.txt"), Path(tmp, "report.json")
            rules.write_bytes(b"CVE-1")
            report.write_text('{"SchemaVersion":2,"Results":[]}')
            metadata, aliases = Path(tmp, "metadata.json"), Path(tmp, "aliases.json")
            metadata.write_text(json.dumps({"schemaVersion": 1, "rulesSha256": sha256(rules.read_bytes()).hexdigest(), "rules": {}}))
            aliases.write_text('{"schemaVersion":1,"groups":[]}')
            options = ["--output-format", "markdown", "--metadata", str(metadata), "--alias-map", str(aliases)]
            originals = {p: p.read_bytes() for p in (rules, report, metadata, aliases)}
            output = Path(tmp, "plan.md")
            for extra in (["--as-of", "2026-02-30"], ["--soon-days", "-1"], ["--report", "missing-PRIVATE"],
                          ["--output-format", "html"]):
                output.write_text("keep")
                proc = self.run_cli(rules, report, *options, "--output", str(output), *extra)
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stdout, "")
                self.assertEqual(output.read_text(), "keep")
                self.assertNotIn("missing-PRIVATE", proc.stderr)
            # Missing acknowledgment is a supported-option validation error too.
            command = [sys.executable, "-m", "vulnwrench", "ignores", "cleanup-plan", "--format", "trivy",
                       "--rules", str(rules), "--report", str(report), *options, "--output", str(output)]
            proc = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=60)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(proc.stdout, "")
            self.assertEqual(output.read_text(), "keep")
            for input_path in originals:
                for mode in ("direct", "symlink", "hardlink"):
                    dest = input_path if mode == "direct" else Path(tmp, "alias-output")
                    if mode == "symlink":
                        dest.symlink_to(input_path)
                    elif mode == "hardlink":
                        dest.hardlink_to(input_path)
                    proc = self.run_cli(rules, report, *options, "--output", str(dest))
                    self.assertEqual(proc.returncode, 2, proc.stderr)
                    self.assertEqual(proc.stdout, "")
                    if mode != "direct":
                        dest.unlink()
                    self.assertEqual(originals, {p: p.read_bytes() for p in originals})
            report.write_text('{"SchemaVersion":2,"Results":"PRIVATE"}')
            proc = self.run_cli(rules, report, *options, "--output", str(output))
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(proc.stdout, "")
            self.assertNotIn("PRIVATE", proc.stderr)
            self.assertEqual(output.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
