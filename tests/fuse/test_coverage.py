"""Synthetic report integration cases for byte-bound coverage declarations."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import vulnwrench.fuse as vf

ROOT = Path(__file__).resolve().parents[2]
DATE = "2026-11-10T12:00:00Z"
TARGET = "sha256:" + "a" * 64
POLICY = "synthetic:suppress:none"


def reports():
    return [vf.Report.from_document("trivy", {"Results": [{"Type": "node-pkg", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-SYN", "PkgName": "demo", "InstalledVersion": "1.0"}]}]}, "found.json"),
        vf.Report.from_document("grype", {"matches": []}, "empty.json")]


def manifest_document(items):
    return {"schemaVersion": "vulnfuse-coverage-1", "inputs": [
        {"scanner": r.scanner, "input": r.input_name, "sha256": r.sha256,
         "targetIdentity": TARGET, "scanComplete": True, "databaseTimestamp": DATE,
         "scanPolicyIdentity": POLICY, "databaseIdentity": "synthetic:snapshot:common"} for r in items]}


def assessment(result):
    absent = next(s for s in result["inputs"] if s["scanner"] == "grype")
    return result["findings"][0]["absenceAssessments"][absent["sourceId"]]


class CoverageTests(unittest.TestCase):
    def test_scan_policy_mismatch_retains_same_target_database_finding(self):
        items = reports()
        doc = manifest_document(items)
        for entry, policy in zip(doc["inputs"], ["synthetic:suppress:none", "synthetic:suppress:CVE-SYN"]):
            entry["scanPolicyIdentity"] = policy
        manifest = vf.CoverageManifest.from_document(doc)
        result = vf.merge_reports(items, coverage_manifest=manifest)
        expected = {"status": "incomparable", "reasonCodes": ["scan-policy-mismatch"]}
        self.assertEqual(result["coverageAssessment"], expected)
        a = assessment(result)
        self.assertEqual({k: a[k] for k in expected}, expected)
        self.assertEqual(a["comparedTo"], [{"sourceId": result["findings"][0]["observations"][0]["sourceId"], **expected}])
        self.assertFalse(a["canEstablishFixed"])
        self.assertEqual((result["findingCount"], result["observationCount"]), (1, 1))
        for source in result["inputs"]:
            index = int(source["coverage"]["manifestPointer"].split("/")[-1])
            self.assertEqual(source["coverage"]["scanPolicyIdentity"], doc["inputs"][index]["scanPolicyIdentity"])
        self.assertIn("scan-policy-mismatch", vf.render_markdown(result))
        self.assertEqual(vf.dumps(result), vf.dumps(vf.merge_reports(reversed(items), coverage_manifest=manifest)))
        explained = vf.explain_finding(result, advisory="CVE-SYN")
        self.assertEqual(explained["coverageAssessment"], expected)
        self.assertEqual(explained["finding"]["absenceAssessments"], result["findings"][0]["absenceAssessments"])
        self.assertEqual(explained["remediationAssessment"], "not-evaluated")

    def test_scan_policy_missing_is_unknown_and_equal_labels_are_not_a_fix(self):
        for policy in [None, POLICY, "Synthetic:suppress:none", "synthetic:suppress:none é"]:
            for sides in [(0,), (1,), (0, 1)]:
                for omitted in (False, True) if policy is None else (False,):
                    with self.subTest(policy=policy, sides=sides, omitted=omitted):
                        items = reports()
                        doc = manifest_document(items)
                        for side in sides:
                            if omitted:
                                del doc["inputs"][side]["scanPolicyIdentity"]
                            else:
                                doc["inputs"][side]["scanPolicyIdentity"] = policy
                        result = vf.merge_reports(items, coverage_manifest=vf.CoverageManifest.from_document(doc))
                        if policy is None:
                            expected = {"status": "unknown", "reasonCodes": ["scan-policy-identity-missing"]}
                        elif policy == POLICY or len(sides) == 2:
                            expected = {"status": "comparable", "reasonCodes": []}
                        else:
                            expected = {"status": "incomparable", "reasonCodes": ["scan-policy-mismatch"]}
                        self.assertEqual(result["coverageAssessment"], expected)
                        a = assessment(result)
                        self.assertEqual({k: a[k] for k in expected}, expected)
                        self.assertFalse(a["canEstablishFixed"])
                        for source in result["inputs"]:
                            index = int(source["coverage"]["manifestPointer"].split("/")[-1])
                            self.assertEqual(source["coverage"]["scanPolicyIdentity"], doc["inputs"][index].get("scanPolicyIdentity"))

    def test_without_manifest_keeps_findings_with_explicit_unknown_coverage(self):
        result = vf.merge_reports(reports())
        self.assertEqual((result["findingCount"], result["observationCount"]), (1, 1))
        self.assertEqual(result["findings"][0]["scannerPresence"]["grype"], "not_observed")
        self.assertIsNone(result["coverageManifest"])
        self.assertTrue(all(s["coverage"]["scanPolicyIdentity"] is None for s in result["inputs"]))
        self.assertTrue(all(s["coverage"]["reasonCodes"] == ["manifest-not-supplied"] for s in result["inputs"]))
        self.assertEqual(assessment(result)["status"], "unknown")
        self.assertEqual(assessment(result)["reasonCodes"], ["manifest-not-supplied"])
        self.assertFalse(assessment(result)["canEstablishFixed"])
        self.assertIn("Coverage: unknown", vf.render_markdown(result))

    def test_blocking_and_unknown_reasons_never_discard_findings_or_prove_fixed(self):
        cases = [
            ({"targetIdentity": "sha256:" + "b" * 64}, "incomparable", ["target-mismatch"]),
            ({"scanComplete": False}, "incomparable", ["scan-incomplete"]),
            ({"databaseTimestamp": None}, "unknown", ["database-timestamp-missing"]),
            ({"databaseTimestamp": "2026-11-09T12:00:00Z"}, "incomparable", ["database-timestamp-mismatch"]),
            ({"targetIdentity": None}, "unknown", ["target-identity-missing"]),
            ({"scanComplete": None}, "unknown", ["scan-completion-unknown"]),
            ({"scanPolicyIdentity": "other", "databaseTimestamp": None}, "incomparable",
             ["database-timestamp-missing", "scan-policy-mismatch"]),
            ({"targetIdentity": "different", "scanComplete": False, "databaseTimestamp": None}, "incomparable",
             ["database-timestamp-missing", "scan-incomplete", "target-mismatch"]),
        ]
        for changed, status, reasons in cases:
            for side in (0, 1):
                with self.subTest(changed=changed, side=side):
                    items = reports()
                    doc = manifest_document(items)
                    doc["inputs"][side].update(changed)
                    result = vf.merge_reports(items, coverage_manifest=vf.CoverageManifest.from_document(doc))
                    a = assessment(result)
                    self.assertEqual(a["status"], status)
                    self.assertEqual(a["reasonCodes"], reasons)
                    self.assertFalse(a["canEstablishFixed"])
                    self.assertEqual(result["findings"][0]["observations"][0]["originalId"], "CVE-SYN")
                    self.assertEqual(len(a["comparedTo"]), 1)

    def test_compatible_metadata_is_not_proof_of_remediation(self):
        items = reports()
        doc = manifest_document(items)
        doc["inputs"][1]["databaseTimestamp"] = "2026-11-10T13:00:00.000000+01:00"
        result = vf.merge_reports(items, coverage_manifest=vf.CoverageManifest.from_document(doc))
        self.assertEqual(assessment(result)["status"], "comparable")
        self.assertEqual(assessment(result)["reasonCodes"], [])
        self.assertFalse(assessment(result)["canEstablishFixed"])
        self.assertIn("comparable", vf.render_markdown(result))

    def test_partial_manifest_and_omitted_fields_are_unknown(self):
        items = reports()
        doc = manifest_document(items)
        doc["inputs"].pop()
        result = vf.merge_reports(items, coverage_manifest=vf.CoverageManifest.from_document(doc))
        self.assertEqual(assessment(result)["reasonCodes"], ["manifest-entry-missing"])
        for field, reason in [("targetIdentity", "target-identity-missing"), ("scanComplete", "scan-completion-unknown"),
                              ("databaseTimestamp", "database-timestamp-missing"),
                              ("scanPolicyIdentity", "scan-policy-identity-missing")]:
            doc = manifest_document(items)
            del doc["inputs"][1][field]
            with self.subTest(field=field):
                result = vf.merge_reports(items, coverage_manifest=vf.CoverageManifest.from_document(doc))
                self.assertEqual(assessment(result)["status"], "unknown")
                self.assertEqual(assessment(result)["reasonCodes"], [reason])

    def test_empty_or_fully_observed_reports_still_surface_mismatches(self):
        for documents in [({"Results": []}, {"matches": []}), (reports()[0].document, reports()[0].document)]:
            for field, reason in [("targetIdentity", "target-mismatch"), ("scanPolicyIdentity", "scan-policy-mismatch")]:
                with self.subTest(documents=documents, field=field):
                    # Empty merges and complete presence have no absence assessments.
                    scanner = "grype" if "matches" in documents[1] else "trivy"
                    items = [vf.Report.from_document("trivy", documents[0], "first.json"),
                             vf.Report.from_document(scanner, documents[1], "second.json")]
                    doc = manifest_document(items)
                    doc["inputs"][1][field] = "another-value"
                    result = vf.merge_reports(items, coverage_manifest=vf.CoverageManifest.from_document(doc))
                    self.assertTrue(all(not f["absenceAssessments"] for f in result["findings"]))
                    self.assertEqual(result["coverageAssessment"], {"status": "incomparable", "reasonCodes": [reason]})
                    self.assertIn(reason, vf.render_markdown(result))

    def test_all_observed_sources_participate_and_repeat_order_is_stable(self):
        items = reports()
        second = vf.Report.from_document("osv", {"results": [{"packages": [{
            "package": {"name": "demo", "version": "1.0", "ecosystem": "npm"},
            "vulnerabilities": [{"id": "CVE-SYN"}]}]}]}, "second.json")
        items.extend([second, items[0]])
        doc = manifest_document(items[:3])
        doc["inputs"][2]["scanPolicyIdentity"] = "synthetic:suppress:other"
        manifest = vf.CoverageManifest.from_document(doc)
        result = vf.merge_reports(items, coverage_manifest=manifest)
        self.assertEqual(vf.dumps(result), vf.dumps(vf.merge_reports(reversed(items), coverage_manifest=manifest)))
        self.assertEqual(result["observationCount"], 3)
        self.assertEqual(assessment(result)["status"], "incomparable")
        self.assertEqual(assessment(result)["reasonCodes"], ["scan-policy-mismatch"])
        self.assertEqual(len(assessment(result)["comparedTo"]), 3)
        self.assertEqual({a["status"] for a in assessment(result)["comparedTo"]}, {"comparable", "incomparable"})

    def test_invalid_schema_types_dates_and_bindings_reject_manifest(self):
        items = reports()
        changes = [
            lambda d: d.update(schemaVersion="unknown"),
            lambda d: d.update(extra="typo"),
            lambda d: d.update(inputs={}),
            lambda d: d["inputs"].append(d["inputs"][0].copy()),
            lambda d: d["inputs"][0].update(sha256="0" * 64),
            lambda d: d["inputs"][0].update(input="other.json"),
            lambda d: d["inputs"][0].update(scanner="unknown"),
            lambda d: d["inputs"][0].update(targetIdentity=""),
            lambda d: d["inputs"][0].update(scanComplete=1),
            lambda d: d["inputs"][0].update(databaseTimestamp=12),
            lambda d: d["inputs"][0].update(databaseTimestamp="2026-11-10"),
            lambda d: d["inputs"][0].update(databaseTimestamp="2026-11-10T12:00:00"),
            lambda d: d["inputs"][0].update(databaseTimestamp="2026-02-30T12:00:00Z"),
            lambda d: d["inputs"][0].update(databaseTimestamp="2026-11-10T12:00:00+24:00"),
            lambda d: d["inputs"][0].update(scanCompleted=True),
        ]
        for change in changes:
            doc = manifest_document(items)
            change(doc)
            with self.subTest(doc=doc), self.assertRaises(vf.InputError):
                vf.merge_reports(items, coverage_manifest=vf.CoverageManifest.from_document(doc))

    def test_file_byte_and_entry_provenance_with_cli_and_markdown(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            items = reports()
            for r in items:
                (base / r.input_name).write_text(vf.dumps(r.document))
            items = [vf.read_report(r.scanner, base / r.input_name) for r in items]
            doc = manifest_document(items)
            doc["inputs"][1].update(targetIdentity="<img>|different", scanComplete=False, databaseTimestamp=None)
            for entry in doc["inputs"]:
                entry["scanPolicyIdentity"] = "<policy>|synthetic"
            path = base / "coverage.json"
            path.write_text(json.dumps(doc, indent=3) + "\n")
            md = base / "summary.md"
            completed = subprocess.run([sys.executable, "-m", "vulnwrench", "fuse", "merge", "--trivy", items[0].input_name,
                "--grype", items[1].input_name, "--coverage-manifest", str(path), "--markdown", str(md)],
                cwd=ROOT, text=True, capture_output=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result, vf.merge_reports(items, coverage_manifest=vf.read_coverage_manifest(path)))
            manifest = result["coverageManifest"]
            self.assertEqual(manifest["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(manifest["byteCount"], len(path.read_bytes()))
            self.assertEqual(manifest["digestKind"], "file-bytes")
            self.assertEqual(manifest["rawManifest"], doc)
            for source in result["inputs"]:
                index = int(source["coverage"]["manifestPointer"].split("/")[-1])
                self.assertEqual(doc["inputs"][index]["sha256"], source["sha256"])
                self.assertEqual(source["sha256"], hashlib.sha256(Path(source["input"]).read_bytes()).hexdigest())
            self.assertEqual(assessment(result)["reasonCodes"], ["database-timestamp-missing", "scan-incomplete", "target-mismatch"])
            self.assertIn("target-mismatch", md.read_text())
            self.assertNotIn("<img>", md.read_text())
            self.assertNotIn("<policy>", md.read_text())
            self.assertIn("scan policy: &lt;policy&gt;&#124;synthetic", md.read_text())
            # Stale hashes and malformed manifests fail before replacing output.
            out = base / "out.json"
            out.write_text("sentinel")
            original = path.read_bytes()
            for contents in [b'{"schemaVersion":1,"schemaVersion":2}', b'\xff', b'{"inputs":NaN}',
                             b'{"inputs":1e999}', b'[]', original.replace(items[0].sha256.encode(), b"0" * 64)]:
                path.write_bytes(contents)
                failed = subprocess.run([sys.executable, "-m", "vulnwrench", "fuse", "merge", "--trivy", items[0].input_name,
                    "--grype", items[1].input_name, "--coverage-manifest", str(path), "--output", str(out)],
                    cwd=ROOT, text=True, capture_output=True, timeout=60)
                self.assertEqual(failed.returncode, 2, failed.stderr)
                self.assertEqual(failed.stdout, "")
                self.assertNotIn("Traceback", failed.stderr)
                self.assertNotIn(str(path), failed.stderr)
                self.assertEqual(out.read_text(), "sentinel")
            path.write_bytes(original)
            for flag in ["--output", "--markdown"]:
                for kind in ["same", "hard", "sym"]:
                    dest = base / (flag[2:] + kind)
                    if kind == "hard":
                        dest.hardlink_to(path)
                    elif kind == "sym":
                        dest.symlink_to(path)
                    else:
                        dest = path
                    failed = subprocess.run([sys.executable, "-m", "vulnwrench", "fuse", "merge", "--trivy", items[0].input_name,
                        "--grype", items[1].input_name, "--coverage-manifest", str(path), flag, str(dest)],
                        cwd=ROOT, text=True, capture_output=True, timeout=60)
                    self.assertEqual(failed.returncode, 2)
                    self.assertEqual(path.read_bytes(), original)

    def test_invalid_scan_policy_rejects_before_cli_output_replacement(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            items = reports()
            for r in items:
                (base / r.input_name).write_text(vf.dumps(r.document))
            items = [vf.read_report(r.scanner, base / r.input_name) for r in items]
            path, output, markdown = base / "coverage.json", base / "out.json", base / "out.md"
            for value in ["", " ", " policy", "policy ", "private-policy\nvalue", "private-policy\x00value",
                          "private-policy\x7fvalue", "private-policy\ud800value", 0, True, [], {}]:
                doc = manifest_document(items)
                doc["inputs"][1]["scanPolicyIdentity"] = value
                with self.subTest(value=value):
                    with self.assertRaises(vf.InputError):
                        vf.merge_reports(items, coverage_manifest=vf.CoverageManifest.from_document(doc))
                    path.write_text(json.dumps(doc))
                    output.write_text("json sentinel")
                    markdown.write_text("markdown sentinel")
                    failed = subprocess.run([sys.executable, "-m", "vulnwrench", "fuse", "merge", "--trivy", items[0].input_name,
                        "--grype", items[1].input_name, "--coverage-manifest", str(path), "--output", str(output),
                        "--markdown", str(markdown)], cwd=ROOT, text=True, capture_output=True, timeout=60)
                    self.assertEqual(failed.returncode, 2)
                    self.assertEqual(failed.stdout, "")
                    self.assertNotIn("private-policy", failed.stderr)
                    self.assertNotIn(str(path), failed.stderr)
                    self.assertNotIn("Traceback", failed.stderr)
                    self.assertEqual(output.read_text(), "json sentinel")
                    self.assertEqual(markdown.read_text(), "markdown sentinel")

    def test_installed_scan_policy_fixture_outside_repository(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            for name in ["found.json", "suppressed.json", "coverage.json"]:
                (base / name).write_bytes((ROOT / "examples/fuse/policy" / name).read_bytes())
            command = [sys.executable, "-m", "vulnwrench", "fuse", "merge", "--trivy", "found.json", "--trivy", "suppressed.json",
                       "--coverage-manifest", "coverage.json"]
            executed = subprocess.run(command, cwd=td, capture_output=True, text=True, timeout=60)
            self.assertEqual(executed.returncode, 0, executed.stderr)
            result = json.loads(executed.stdout)
            self.assertEqual((result["inputCount"], result["observationCount"], result["findingCount"]), (2, 1, 1))
            self.assertEqual(result["coverageAssessment"], {"status": "incomparable", "reasonCodes": ["scan-policy-mismatch"]})
            a, = result["findings"][0]["absenceAssessments"].values()
            self.assertEqual(a["reasonCodes"], ["scan-policy-mismatch"])
            self.assertEqual(a["status"], "incomparable")
            self.assertFalse(a["canEstablishFixed"])
            self.assertEqual(result["findings"][0]["ids"], ["CVE-POLICY-1"])
            self.assertEqual(result["coverageManifest"]["sha256"], hashlib.sha256((base / "coverage.json").read_bytes()).hexdigest())
            self.assertEqual(executed.stdout, subprocess.run(command, cwd=td, capture_output=True, text=True, timeout=60).stdout)
            for source in result["inputs"]:
                self.assertEqual(source["sha256"], hashlib.sha256((base / source["input"]).read_bytes()).hexdigest())
            output = base / "out.json"
            output.write_text("sentinel")
            (base / "suppressed.json").write_bytes((base / "suppressed.json").read_bytes() + b"\n")
            failed = subprocess.run([*command, "--output", str(output)], cwd=td, capture_output=True, text=True, timeout=60)
            self.assertEqual(failed.returncode, 2)
            self.assertEqual(failed.stdout, "")
            self.assertEqual(output.read_text(), "sentinel")

    def test_installed_cli_coverage_example_outside_repository(self):
        with tempfile.TemporaryDirectory() as td:
            # Manifest input names are the exact CLI arguments, relative to this cwd.
            for name in ["trivy.json", "grype-empty.json", "osv-empty.json", "coverage.json"]:
                (Path(td) / name).write_bytes((ROOT / "examples" / "fuse" / name).read_bytes())
            executed = subprocess.run([sys.executable, "-m", "vulnwrench", "fuse", "merge", "--trivy", "trivy.json", "--grype", "grype-empty.json",
                "--osv", "osv-empty.json", "--coverage-manifest", "coverage.json"], cwd=td,
                capture_output=True, text=True, timeout=60)
            self.assertEqual(executed.returncode, 0, executed.stderr)
            result = json.loads(executed.stdout)
            self.assertEqual((result["observationCount"], result["findingCount"]), (2, 2))
            for finding in result["findings"]:
                reasons = {result["inputs"][int(sid[1:]) - 1]["scanner"]: a["reasonCodes"]
                           for sid, a in finding["absenceAssessments"].items()}
                self.assertEqual(reasons, {"grype": ["target-mismatch"], "osv": ["database-timestamp-missing", "scan-incomplete"]})
                self.assertTrue(all(not a["canEstablishFixed"] for a in finding["absenceAssessments"].values()))


if __name__ == "__main__":
    unittest.main()
