from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import vulnwrench.triage as triage_bridge
from vulnwrench.triage import BridgeError, compile_decisions
from vulnwrench.triage.compiler import digest, json_bytes
from vulnwrench.triage.model import MAX_INPUT_BYTES
from tests.triage.test_bridge import PARAMS, ROOT


FIXTURES = ROOT / "examples/triage/import-trivy"


def native(**changes):
    return {"vulnerabilities": [{"id": "CVE-2099-0062", "purls": ["pkg:npm/triage-demo@1.0"],
                                 "statement": 'Synthetic "reason"\nUnicode: café\tend',
                                 "expired_at": "2026-12-01"} | changes]}


class ImportTrivyTests(unittest.TestCase):
    def import_doc(self, doc):
        return triage_bridge.import_trivy_ignore(json_bytes(doc))

    def assert_bad(self, raw, code="E_IMPORT"):
        with self.assertRaises(BridgeError) as error:
            triage_bridge.import_trivy_ignore(raw)
        self.assertEqual(error.exception.code, code)

    def test_block_fixture_preserves_fields_and_requires_review(self):
        raw = (FIXTURES / "native.trivyignore.yaml").read_bytes()
        plan = triage_bridge.import_trivy_ignore(raw)
        self.assertEqual(plan["mode"], "review_only")
        self.assertEqual(plan["automaticActions"], [])
        self.assertEqual(plan["source"]["rawSha256"], digest(raw))
        self.assertEqual(plan["counts"], {"nativeEntries": 2, "draftDecisions": 3, "unsupported": 0})
        records = plan["decisionDocument"]["decisions"]
        self.assertEqual([r["ids"] for r in records], [["CVE-2099-0062"], ["CVE-2099-0062"], ["GHSA-demo-0062-0001"]])
        self.assertEqual([r["package"] for r in records], ["pkg:npm/triage-demo@1.0", "pkg:npm/triage-demo@2.0", None])
        self.assertEqual(records[0]["reason"], "Investigation: synthetic fixture")
        self.assertEqual(records[0]["expiresOn"], "2026-12-01")
        self.assertIsNone(records[2]["expiresOn"])
        for record, review in zip(records, plan["reviews"]):
            self.assertIsNone(record["owner"])
            self.assertIsNone(record["status"])
            self.assertEqual(review["requiredFields"], [key for key, value in record.items() if value is None])
            self.assertIn("package", review["reviewFields"])
            self.assertTrue(review["reviewRequired"])
        self.assertEqual(plan, triage_bridge.load_trivy_ignore(FIXTURES / "native.trivyignore.yaml"))

    def test_flow_roundtrip_after_explicit_evidence(self):
        doc = native(purls=["pkg:npm/triage-demo@1.0", "pkg:npm/triage-demo@2.0"])
        before = deepcopy(doc)
        plan = self.import_doc(doc)
        draft = plan["decisionDocument"]
        for candidate in (plan, draft):
            with self.assertRaises(BridgeError):
                compile_decisions(candidate, **PARAMS)
        for record in draft["decisions"]:
            record["owner"] = "synthetic-reviewer"
            record["status"] = "accepted_risk"
        result = compile_decisions(draft, **PARAMS)
        trivy = json.loads(result.files[".trivyignore.yaml"])
        expected = [doc["vulnerabilities"][0] | {"purls": [purl]} for purl in doc["vulnerabilities"][0]["purls"]]
        self.assertEqual(trivy, {"vulnerabilities": expected})
        self.assertNotIn("openvex.json", result.files)
        self.assertEqual(doc, before)
        self.assertEqual(triage_bridge.import_trivy_ignore(result.files[".trivyignore.yaml"])["decisionDocument"],
                         self.import_doc(trivy)["decisionDocument"])

    def test_supported_block_fixture_matches_reviewed_example(self):
        draft = triage_bridge.load_trivy_ignore(FIXTURES / "supported.trivyignore.yaml")
        reviewed = json.loads((FIXTURES / "reviewed-decisions.json").read_bytes())
        self.assertEqual(draft["decisionDocument"], {"schemaVersion": 1, "decisions": [
            record | {"owner": None, "status": None} for record in reviewed["decisions"]]})
        trivy = json.loads(compile_decisions(reviewed, **PARAMS).files[".trivyignore.yaml"])
        self.assertEqual(trivy["vulnerabilities"], [
            {"id": row["ids"][0], "purls": [row["package"]], "statement": row["reason"], "expired_at": row["expiresOn"]}
            for row in reviewed["decisions"]])

    def test_missing_evidence_never_becomes_actionable(self):
        draft = self.import_doc({"vulnerabilities": [{"id": "CVE-2099-0062"}]})["decisionDocument"]
        record = draft["decisions"][0]
        self.assertEqual(record, {"ids": ["CVE-2099-0062"], "package": None, "owner": None,
                                  "reason": None, "expiresOn": None, "status": None})
        complete = record | {"package": "pkg:npm/triage-demo@1.0", "owner": "reviewer", "reason": "Reviewed",
                             "expiresOn": "2026-12-01", "status": "accepted_risk"}
        for field in ("package", "owner", "reason", "expiresOn", "status"):
            with self.subTest(field=field), self.assertRaises(BridgeError):
                compile_decisions({"decisions": [complete | {field: None}]}, **PARAMS)
        complete["status"] = "not_affected"
        with self.assertRaises(BridgeError) as error:
            compile_decisions({"decisions": [complete]}, **PARAMS)
        self.assertEqual(error.exception.code, "E_STATUS")

    def test_unsupported_selectors_block_entire_entry(self):
        for changes, code in [({"paths": ["app/lock"]}, "unsupported_paths"),
                              ({"paths": []}, "unsupported_paths"),
                              ({"purls": ["pkg:npm/triage-demo"]}, "unsupported_purl"),
                              ({"purls": ["pkg:npm/triage-demo@*"]}, "unsupported_purl"),
                              ({"purls": ["pkg:npm/triage-demo@1.0", "pkg:npm/triage-demo"]}, "unsupported_purl"),
                              ({"futureSelector": "secret-value"}, "unsupported_field")]:
            with self.subTest(changes=changes):
                plan = self.import_doc(native(**changes))
                self.assertEqual(plan["decisionDocument"]["decisions"], [])
                self.assertEqual(plan["reviews"], [])
                self.assertEqual(plan["unsupported"][0]["code"], code)
                self.assertTrue(plan["unsupported"][0]["pointer"].startswith("/vulnerabilities/0"))
        plan = triage_bridge.load_trivy_ignore(FIXTURES / "unsupported.trivyignore.yaml")
        self.assertEqual(plan["counts"]["draftDecisions"], 0)
        plan = self.import_doc(native() | {"secrets": [{"id": "synthetic-secret"}]})
        self.assertEqual(len(plan["decisionDocument"]["decisions"]), 1)
        self.assertEqual(plan["unsupported"][0]["pointer"], "/secrets")

    def test_invalid_native_fields_and_expired_dates_are_not_repaired(self):
        for changes in ({"id": "bad id"}, {"statement": " padded "}, {"expired_at": "2026-02-30"},
                        {"purls": None}, {"purls": "pkg:npm/demo@1"}, {"purls": [1]},
                        {"statement": False}, {"expired_at": None}):
            with self.subTest(changes=changes):
                plan = self.import_doc(native(**changes))
                self.assertEqual(plan["counts"]["draftDecisions"], 0)
                self.assertTrue(plan["unsupported"])
        for date in ("2026-11-10", "2026-11-11"):
            draft = self.import_doc(native(expired_at=date))["decisionDocument"]
            draft["decisions"][0].update(owner="reviewer", status="accepted_risk")
            with self.assertRaises(BridgeError) as error:
                compile_decisions(draft, **PARAMS)
            self.assertEqual(error.exception.code, "E_EXPIRED")

    def test_duplicates_remain_visible_and_compiler_refuses_overlap(self):
        doc = native()
        doc["vulnerabilities"] *= 2
        draft = self.import_doc(doc)["decisionDocument"]
        self.assertEqual(len(draft["decisions"]), 2)
        for record in draft["decisions"]:
            record.update(owner="reviewer", status="accepted_risk")
        with self.assertRaises(BridgeError) as error:
            compile_decisions(draft, **PARAMS)
        self.assertEqual(error.exception.code, "E_CONFLICT")

    def test_fail_closed_syntax_size_and_shape(self):
        for raw in (b'{"vulnerabilities": [], "vulnerabilities": []}', b'{"vulnerabilities": [NaN]}',
                    b"vulnerabilities:\n  - id: CVE-1\n    id: CVE-2\n", b"vulnerabilities:\n  - id: &name CVE-1\n",
                    b"vulnerabilities:\n  - id: *name\n", b"vulnerabilities:\n  - id: CVE-1\n    statement: |\n      text\n",
                    b"vulnerabilities:\n  - id: CVE-1\n---\nsecrets: []\n", b"vulnerabilities:\n\t- id: CVE-1\n",
                    b"vulnerabilities:\n  - id: yes\n", b"vulnerabilities:\n  - id: CVE-1 # comment\n",
                    b"vulnerabilities:\n  - <<: *merge\n", b"vulnerabilities:\n  - id: !!str CVE-1\n", b"\xff",
                    b"vulnerabilities:\n  - id: y\n", b"vulnerabilities:\n  - id: CVE-1\n    purls:\n",
                    b"vulnerabilities:\n  - id: CVE-1\n    statement: reason:\n",
                    "vulnerabilities:\n  - id: CVE-1\n    statement: first\u2028second\n".encode(),
                    b'{"\\ud800": []}',
                    b'{"vulnerabilities": {}}', b'{"vulnerabilities": [1]}', b"[]", b"null", b"{}",
                    b" " * (MAX_INPUT_BYTES + 1)):
            with self.subTest(raw=raw[:90]):
                self.assert_bad(raw)
        many = {"vulnerabilities": [native()["vulnerabilities"][0]] * 10001}
        self.assert_bad(json_bytes(many))
        expanded = native(purls=["pkg:npm/demo@1"] * 10001)
        self.assert_bad(json_bytes(expanded))

    def test_block_scalar_profile_and_empty_scope(self):
        raw = b"vulnerabilities:\r\n  - id: 'CVE-2099-0062'\r\n    statement: 'Reviewer''s reason'\r\n    purls: []\r\n"
        plan = triage_bridge.import_trivy_ignore(raw)
        record = plan["decisionDocument"]["decisions"][0]
        self.assertEqual(record["reason"], "Reviewer's reason")
        self.assertIsNone(record["package"])
        self.assertEqual(plan["reviews"][0]["nativeScope"], "all_packages")

    def test_cli_snapshot_no_files_and_failure_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = [sys.executable, "-m", "vulnwrench", "triage", "import-trivy"]
            result = subprocess.run(base + [str(FIXTURES / "native.trivyignore.yaml")], cwd=ROOT,
                                    capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, (FIXTURES / "expected-draft.json").read_bytes())
            bad = Path(tmp) / "secret-input.yaml"
            bad.write_text("vulnerabilities:\n  - id: &SECRET_VALUE CVE-1\n")
            result = subprocess.run(base + [str(bad)], cwd=ROOT, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"E_IMPORT", result.stderr)
            self.assertNotIn(b"SECRET", result.stderr)
            self.assertNotIn(b"secret-input", result.stderr)
