"""Focused explanations using local synthetic scanner structures, no scanner runs."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import vulnwrench.fuse as vf

ROOT = Path(__file__).resolve().parents[2]
API = "pkg:npm/demo@1.0#apps/api"
WORKER = "pkg:npm/demo@1.0#apps/worker"
ADVISORY = "OSV-EXPLAIN-1"


def reports():
    return [vf.read_report(s, f"examples/fuse/explain/{s}.json") for s in ("trivy", "grype", "osv")]


def args():
    return [part for s in ("trivy", "grype", "osv") for part in ("--" + s, f"examples/fuse/explain/{s}.json")]


def cli(*arguments):
    return subprocess.run([sys.executable, "-m", "vulnwrench", "fuse", *map(str, arguments)], cwd=ROOT,
                          text=True, capture_output=True, timeout=60)


def resolve(value, pointer):
    for token in pointer.split("/")[1:]:
        token = token.replace("~1", "/").replace("~0", "~")
        value = value[int(token)] if isinstance(value, list) else value[token]
    return value


class ExplainTests(unittest.TestCase):
    def test_cli_selects_one_identity_with_exact_global_alias_links_and_conflicts(self):
        completed = cli("explain", *args(), "--advisory", ADVISORY, "--package", API)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["schemaVersion"], "vulnfuse-explain-1")
        finding = result["finding"]
        self.assertEqual(finding["package"]["identity"], API)
        self.assertEqual(finding["ids"], ["CVE-EXPLAIN-1", "GHSA-explain-1", "OSV-EXPLAIN-1"])
        self.assertEqual(finding["observationCount"], 2)
        self.assertEqual(finding["severityValues"], ["CRITICAL", "HIGH"])
        self.assertEqual(finding["fixVersions"], ["1.1", "1.2"])
        self.assertTrue(finding["severityConflict"])
        self.assertTrue(finding["fixVersionConflict"])
        self.assertFalse(finding["fixStateConflict"])
        self.assertNotIn("9.9", finding["fixVersions"])
        self.assertNotIn("8.8", finding["fixVersions"])
        self.assertEqual({(e["from"], e["to"], e["basis"]) for e in result["aliasLinks"]}, {
            ("GHSA-explain-1", "CVE-EXPLAIN-1", "grype-relatedVulnerabilities"),
            ("OSV-EXPLAIN-1", "GHSA-explain-1", "osv-aliases")})
        self.assertEqual(len(result["evidence"]), 3)
        external = [e for e in result["evidence"] if not e["contributesToFinding"]]
        self.assertEqual(len(external), 1)
        self.assertEqual(external[0]["observation"]["package"]["identity"], WORKER)
        self.assertEqual(result["remediationAssessment"], "not-evaluated")
        self.assertTrue(all(not a["canEstablishFixed"] for a in finding["absenceAssessments"].values()))
        self.assertEqual(result, vf.explain_finding(vf.merge_reports(reports()), advisory=ADVISORY, package=API))
        self.assertEqual(completed.stdout, (ROOT / "examples/fuse/expected/explanation.json").read_text())

    def test_every_pointer_resolves_to_original_bytes_and_package_path_evidence(self):
        merged = vf.merge_reports(reports())
        result = vf.explain_finding(merged, advisory=ADVISORY, package=API)
        sources = {s["sourceId"]: s for s in merged["inputs"]}
        self.assertEqual(result["inputs"], [{k: v for k, v in s.items() if k != "rawReport"} for s in merged["inputs"]])
        for source in result["inputs"]:
            self.assertEqual(source["sha256"], hashlib.sha256((ROOT / source["input"]).read_bytes()).hexdigest())
        for evidence in result["evidence"]:
            obs = evidence["observation"]
            raw = sources[obs["sourceId"]]["rawReport"]
            self.assertEqual(resolve(raw, obs["pointer"]), evidence["rawObservation"])
            for field in evidence["packageEvidence"] + evidence["pathEvidence"]:
                self.assertEqual(resolve(raw, field["pointer"]), field["value"])
        for edge in result["aliasLinks"]:
            raw = sources[edge["sourceId"]]["rawReport"]
            self.assertEqual(resolve(raw, edge["pointer"]), edge["to"])
            self.assertEqual(resolve(raw, edge["primaryIdPointer"]), edge["from"])
        path_fields = {(f["pointer"], f["value"]) for e in result["evidence"] for f in e["pathEvidence"]}
        self.assertIn(("/matches/0/artifact/locations/0/accessPath", "apps/api/node_modules/demo"), path_fields)
        self.assertIn(("/matches/0/artifact/locations/0/realPath", "/workspace/apps/api/node_modules/demo"), path_fields)
        self.assertIn(("/Results/0/Vulnerabilities/0/PkgPath", "apps/api/node_modules/demo"), path_fields)
        self.assertIn(("/Results/0/Target", "apps/api/package-lock.json"), path_fields)
        self.assertIn(("/results/0/source/path", "apps/worker/package-lock.json"), path_fields)

    def test_unlinked_advisory_and_same_name_other_subpath_stay_separate(self):
        merged = vf.merge_reports(reports())
        self.assertEqual((merged["findingCount"], merged["observationCount"]), (3, 5))
        worker = vf.explain_finding(merged, advisory="CVE-EXPLAIN-1", package=WORKER)
        self.assertEqual(worker["finding"]["fixVersions"], ["9.9"])
        self.assertFalse(worker["finding"]["severityConflict"])
        unlinked = vf.explain_finding(merged, advisory="UNLINKED-EXPLAIN-1", package=API)
        self.assertEqual(unlinked["finding"]["observationCount"], 1)
        self.assertEqual(unlinked["finding"]["ids"], ["UNLINKED-EXPLAIN-1"])
        self.assertEqual(unlinked["aliasLinks"], [])
        self.assertEqual(len(unlinked["evidence"]), 1)

    def test_determinism_selection_and_no_mutation(self):
        items = reports()
        merged = vf.merge_reports(items)
        before = vf.dumps(merged)
        result = vf.explain_finding(merged, advisory=ADVISORY, package=API)
        self.assertEqual(vf.dumps(result), vf.dumps(vf.explain_finding(vf.merge_reports(reversed(items)), advisory=ADVISORY, package=API)))
        self.assertEqual(result, vf.explain_finding(merged, finding_id=result["finding"]["findingId"]))
        self.assertEqual(before, vf.dumps(merged))
        result["finding"]["observations"].clear()
        result["evidence"][0]["rawObservation"].clear()
        self.assertEqual(before, vf.dumps(merged))

    def test_unknown_packages_are_selectable_only_by_unambiguous_finding(self):
        doc = {"Results": [{"Type": "vendor-unknown", "Vulnerabilities": [
            {"VulnerabilityID": "A", "PkgName": "demo", "InstalledVersion": "1"},
            {"VulnerabilityID": "A", "PkgName": "demo", "InstalledVersion": "1"}]}]}
        merged = vf.merge_reports([vf.Report.from_document("trivy", doc)])
        self.assertEqual(merged["findingCount"], 2)
        with self.assertRaises(vf.InputError):
            vf.explain_finding(merged, advisory="A")
        for finding in merged["findings"]:
            explained = vf.explain_finding(merged, finding_id=finding["findingId"])
            self.assertFalse(explained["finding"]["package"]["known"])
            self.assertEqual(len(explained["evidence"]), 1)
            self.assertEqual(explained["aliasLinks"], [])

    def test_scanner_paths_alone_do_not_split_a_known_package(self):
        doc = {"Results": [{"Type": "npm", "Vulnerabilities": [
            {"VulnerabilityID": "A", "PkgName": "demo", "InstalledVersion": "1", "PkgPath": p}
            for p in ("first/demo", "second/demo")]}]}
        merged = vf.merge_reports([vf.Report.from_document("trivy", doc)])
        result = vf.explain_finding(merged, advisory="A", package="pkg:npm/demo@1")
        self.assertEqual(result["finding"]["paths"], ["first/demo", "second/demo"])
        self.assertEqual(len(result["evidence"]), 2)
        self.assertEqual(result["groupingRules"]["scannerPaths"], "provenance-only")

    def test_duplicate_alias_assertions_and_repeated_inputs_retain_locations(self):
        doc = {"matches": [{"artifact": {"name": "demo", "version": "1", "type": "npm", "locations": [{"path": "demo"}]},
            "vulnerability": {"id": "A"}, "relatedVulnerabilities": [{"id": "B"}, {"id": "B"}, {"id": "A"}]}]}
        report = vf.Report.from_document("grype", doc)
        merged = vf.merge_reports([report, report])
        result = vf.explain_finding(merged, advisory="B")
        self.assertEqual(result["finding"]["observationCount"], 2)
        self.assertEqual(len(result["aliasLinks"]), 4)
        self.assertEqual({e["pointer"] for e in result["aliasLinks"]}, {
            "/matches/0/relatedVulnerabilities/0/id", "/matches/0/relatedVulnerabilities/1/id"})
        self.assertEqual(len({e["sourceId"] for e in result["aliasLinks"]}), 2)
        self.assertEqual(result["finding"]["fixVersions"], [])
        self.assertEqual(result["remediationAssessment"], "not-evaluated")
        self.assertEqual(result["evidence"][0]["pathEvidence"], [{"pointer": "/matches/0/artifact/locations/0/path", "value": "demo"}])

    def test_missing_ambiguous_or_invalid_selectors_fail_before_output(self):
        bad_selectors = [[], ["--package", API], ["--advisory", ADVISORY], ["--advisory", "synthetic-secret"],
            ["--finding", "synthetic-secret"], ["--finding", "f0001", "--advisory", ADVISORY],
            ["--advisory", ADVISORY, "--package", "synthetic-secret"], ["--finding", "f0001", "--package", API]]
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "output.json"
            for selectors in bad_selectors:
                output.write_text("sentinel")
                with self.subTest(selectors=selectors):
                    result = cli("explain", *args(), *selectors, "--output", output)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertNotIn("synthetic-secret", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertEqual(output.read_text(), "sentinel")
            for selectors in [{}, {"package": API}, {"finding_id": "f0001", "advisory": ADVISORY},
                              {"advisory": []}, {"finding_id": ""}]:
                with self.subTest(selectors=selectors), self.assertRaises(vf.InputError):
                    vf.explain_finding(vf.merge_reports(reports()), **selectors)

    def test_explain_output_protection_and_validation(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "source.json"
            source.write_bytes((ROOT / "examples/fuse/explain/trivy.json").read_bytes())
            original = source.read_bytes()
            hard, sym = Path(td) / "hard", Path(td) / "sym"
            hard.hardlink_to(source)
            sym.symlink_to(source)
            for output in (source, hard, sym):
                failed = cli("explain", "--trivy", source, "--advisory", "CVE-EXPLAIN-1", "--package", API, "--output", output)
                self.assertEqual(failed.returncode, 2)
                self.assertEqual(source.read_bytes(), original)
            output = Path(td) / "output.json"
            output.write_text("sentinel")
            failed = cli("explain", *args(), "--osv", "examples/fuse/unsupported.json", "--advisory", ADVISORY, "--package", API, "--output", output)
            self.assertEqual(failed.returncode, 2)
            self.assertEqual(output.read_text(), "sentinel")

    def test_installed_explain_e2e_outside_repository(self):
        with tempfile.TemporaryDirectory() as td:
            arguments = []
            for s in ("trivy", "grype", "osv"):
                (Path(td) / (s + ".json")).write_bytes((ROOT / f"examples/fuse/explain/{s}.json").read_bytes())
                arguments.extend(["--" + s, s + ".json"])
            command = [sys.executable, "-m", "vulnwrench", "fuse", "explain", *arguments, "--advisory", ADVISORY, "--package", API]
            first = subprocess.run(command, cwd=td, text=True, capture_output=True, timeout=60)
            self.assertEqual(first.returncode, 0, first.stderr)
            explained = json.loads(first.stdout)
            self.assertEqual(explained["finding"]["fixVersions"], ["1.1", "1.2"])
            self.assertEqual(len(explained["aliasLinks"]), 2)
            self.assertEqual(first.stdout, subprocess.run(command, cwd=td, text=True, capture_output=True, timeout=60).stdout)
            output = Path(td) / "output.json"
            output.write_text("sentinel")
            command[command.index("--package") + 1] = WORKER + "-missing"
            failed = subprocess.run([*command, "--output", str(output)], cwd=td, text=True, capture_output=True, timeout=60)
            self.assertEqual(failed.returncode, 2)
            self.assertEqual(failed.stdout, "")
            self.assertEqual(output.read_text(), "sentinel")


if __name__ == "__main__":
    unittest.main()
