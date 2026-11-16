"""Explicit native review gates, provenance binding and refusal contracts."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import vulnwrench.triage as triage_bridge
from vulnwrench.triage import BridgeError, compile_decisions, import_trivy_ignore
from vulnwrench.triage.compiler import digest, json_bytes
from tests.triage.test_bridge import PARAMS, ROOT
from tests.triage.test_import_trivy import native


def inputs(document=None):
    raw = json_bytes(native() if document is None else document)
    draft = import_trivy_ignore(raw)
    completed = deepcopy(draft["decisionDocument"])
    for i, row in enumerate(completed["decisions"]):
        row.update(owner="synthetic-reviewer", status="accepted_risk", decisionId=f"review-{i}")
    review = {"schemaVersion": 1, "decisionDocument": completed,
              "approvedDecisionIndices": list(range(len(completed["decisions"]))),
              "unsupportedDispositions": [{"pointer": row["pointer"], "disposition": "exclude",
                  "reason": "Retain this synthetic entry in the original configuration for separate review."}
                  for row in draft["unsupported"]]}
    return raw, draft, review


class FinalizeImportTests(unittest.TestCase):
    def finalize(self, raw, draft, review, as_of="2026-11-11"):
        return triage_bridge.finalize_import(draft, source=raw, review=review, as_of=as_of)

    def assert_bad(self, raw, draft, review, code=None, **kwargs):
        with self.assertRaises(BridgeError) as error:
            self.finalize(raw, draft, review, **kwargs)
        if code:
            self.assertEqual(error.exception.code, code)
        self.assertNotIn("SECRET", str(error.exception))

    def test_completed_review_preserves_provenance_through_compile_and_renewal(self):
        raw, draft, review = inputs(native(purls=["pkg:npm/demo@1", "pkg:npm/demo@2"]))
        review["decisionDocument"]["decisions"][0]["sourceRefs"] = ["ticket:synthetic"]
        before = deepcopy((draft, review))
        output = self.finalize(raw, draft, review)
        self.assertEqual((draft, review), before)
        self.assertEqual(output, self.finalize(raw, draft, review))
        self.assertEqual(set(output), {"schemaVersion", "decisions"})
        for i, row in enumerate(output["decisions"]):
            self.assertEqual(row["sourceRefs"], (["ticket:synthetic"] if i == 0 else []) + [
                f"urn:triage-bridge:trivy-ignore:sha256:{digest(raw)}#/vulnerabilities/0",
                f"urn:triage-bridge:import-review:sha256:{digest(json_bytes(review))}#/decisionDocument/decisions/{i}"])
        compiled = compile_decisions(output, **PARAMS)
        self.assertNotIn("openvex.json", compiled.files)
        for row, saved in zip(output["decisions"], compiled.report["decisions"]):
            self.assertEqual(saved["record"]["sourceRefs"], row["sourceRefs"])
        plan = triage_bridge.preview_renewal(output, prior_as_of="2026-11-11", as_of="2026-11-12")
        self.assertEqual(plan["decisions"][0]["prior"]["record"]["sourceRefs"], output["decisions"][0]["sourceRefs"])
        with self.assertRaises(BridgeError) as error:
            compile_decisions(output, **(PARAMS | {"allow_scope_loss": False}))
        self.assertEqual(error.exception.code, "E_SCOPE_LOSS")

    def test_source_and_entire_draft_are_verified_before_binding_references(self):
        raw, draft, review = inputs()
        self.assert_bad(raw + b"\n", draft, review, "E_FINALIZE")
        for mutate in [lambda d: d["source"].update(rawSha256="a" * 64),
                       lambda d: d["reviews"][0].update(sourcePointer="/SECRET"),
                       lambda d: d["counts"].update(draftDecisions=True),
                       lambda d: d["decisionDocument"]["decisions"][0].update(status="accepted_risk"),
                       lambda d: d.update(schemaVersion=True),
                       lambda d: d.update(unknown="SECRET"),
                       lambda d: d.pop("warnings")]:
            bad = deepcopy(draft)
            mutate(bad)
            self.assert_bad(raw, bad, review, "E_FINALIZE")

    def test_every_scope_and_unsupported_finding_requires_explicit_disposition(self):
        doc = native() | {"secrets/legacy~section": [{"id": "synthetic-secret"}]}
        doc["vulnerabilities"].append(doc["vulnerabilities"][0] | {"paths": ["lock"]})
        raw, draft, review = inputs(doc)
        self.assertEqual([r["pointer"] for r in review["unsupportedDispositions"]],
                         ["/secrets~1legacy~0section", "/vulnerabilities/1/paths"])
        output = self.finalize(raw, draft, review)
        self.assertEqual(len(output["decisions"]), 1)
        changed = deepcopy(review)
        changed["unsupportedDispositions"][0]["reason"] = "A different explicit disposition reason."
        self.assertNotEqual(output, self.finalize(raw, draft, changed))
        mutations = [lambda r: r.pop("unsupportedDispositions"),
                     lambda r: r.update(unsupportedDispositions=[]),
                     lambda r: r["unsupportedDispositions"].append(r["unsupportedDispositions"][0]),
                     lambda r: r["unsupportedDispositions"][0].update(pointer="/SECRET"),
                     lambda r: r["unsupportedDispositions"][0].update(disposition="accept"),
                     lambda r: r["unsupportedDispositions"][0].update(reason=" "),
                     lambda r: r["unsupportedDispositions"][0].update(unknown="SECRET"),
                     lambda r: r.update(approvedDecisionIndices=[]),
                     lambda r: r.update(approvedDecisionIndices=[0, 0]),
                     lambda r: r.update(approvedDecisionIndices=[True]),
                     lambda r: r.update(approvedDecisionIndices=[1]),
                     lambda r: r.update(schemaVersion=True),
                     lambda r: r.update(unknown="SECRET")]
        for mutate in mutations:
            bad = deepcopy(review)
            mutate(bad)
            self.assert_bad(raw, draft, bad, "E_FINALIZE")

    def test_native_policy_cannot_be_rewritten_or_drafts_dropped_added_reordered(self):
        raw, draft, review = inputs(native(purls=["pkg:npm/demo@1", "pkg:npm/demo@2"]))
        for key, value in [("ids", ["CVE-SECRET"]), ("package", "pkg:npm/SECRET@1"),
                           ("reason", "SECRET"), ("expiresOn", "2099-12-01")]:
            bad = deepcopy(review)
            bad["decisionDocument"]["decisions"][0][key] = value
            self.assert_bad(raw, draft, bad, "E_FINALIZE")
        for mutate in [lambda rows: rows.pop(), lambda rows: rows.append(deepcopy(rows[0])),
                       lambda rows: rows.reverse()]:
            bad = deepcopy(review)
            mutate(bad["decisionDocument"]["decisions"])
            self.assert_bad(raw, draft, bad, "E_FINALIZE")

    def test_all_unresolved_fields_and_status_specific_evidence_are_refused(self):
        raw, draft, review = inputs({"vulnerabilities": [{"id": "CVE-2099-0062"}]})
        complete = review["decisionDocument"]["decisions"][0]
        complete.update(package="pkg:npm/demo@1", reason="Synthetic assessment", expiresOn="2026-12-01")
        self.assertEqual(self.finalize(raw, draft, review)["decisions"][0]["package"], complete["package"])
        for key in ("package", "owner", "reason", "expiresOn", "status"):
            for remove in (True, False):
                bad = deepcopy(review)
                if remove:
                    bad["decisionDocument"]["decisions"][0].pop(key)
                else:
                    bad["decisionDocument"]["decisions"][0][key] = None
                self.assert_bad(raw, draft, bad)
        for status, evidence in [("not_affected", {"justification": "vulnerable_code_not_present"}),
                                 ("affected", {"action_statement": "Synthetic remediation"})]:
            bad = deepcopy(review)
            bad["decisionDocument"]["decisions"][0]["status"] = status
            self.assert_bad(raw, draft, bad, "E_STATUS")
            bad["decisionDocument"]["decisions"][0].update(evidence)
            self.assertEqual(self.finalize(raw, draft, bad)["decisions"][0]["status"], status)

    def test_expiry_overlap_empty_output_and_invalid_dates_fail(self):
        raw, draft, review = inputs()
        self.assert_bad(raw, draft, review, "E_EXPIRED", as_of="2026-12-01")
        self.assert_bad(raw, draft, review, "E_EXPIRED", as_of="2026-12-02")
        self.assert_bad(raw, draft, review, "E_DATE", as_of="SECRET")
        self.assertEqual(len(self.finalize(raw, draft, review, as_of="2026-11-30")["decisions"]), 1)
        duplicate = native()
        duplicate["vulnerabilities"] *= 2
        self.assert_bad(*inputs(duplicate), "E_CONFLICT")
        self.assert_bad(*inputs(native(paths=["lock"])), "E_INPUT")

    def test_cli_outputs_decisions_only_and_redacts_failures_without_writes(self):
        raw, draft, review = inputs()
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            source_path, draft_path, review_path = [work / name for name in ("source.yaml", "draft.json", "review.json")]
            source_path.write_bytes(raw)
            draft_path.write_bytes(json_bytes(draft))
            review_path.write_bytes(json_bytes(review))
            argv = [sys.executable, "-m", "vulnwrench", "triage", "finalize-import", str(draft_path),
                    "--source", str(source_path), "--review", str(review_path), "--as-of", "2026-11-11"]
            before = {p.name: p.read_bytes() for p in work.iterdir()}
            success = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=60)
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertEqual(success.stderr, b"")
            self.assertEqual(json.loads(success.stdout), self.finalize(raw, draft, review))
            self.assertEqual({p.name: p.read_bytes() for p in work.iterdir()}, before)
            for data, code in [(b'{"SECRET":1,"SECRET":2}', b"E_INPUT"),
                               (b'\xffSECRET', b"E_INPUT"),
                               (b'{"SECRET":NaN}', b"E_INPUT"),
                               (b" " * (2 * 1024 * 1024 + 1), b"E_INPUT"),
                               (json_bytes(review | {"approvedDecisionIndices": []}), b"E_FINALIZE"),
                               (json_bytes(review | {"decisionDocument": draft["decisionDocument"]}), b"E_INPUT")]:
                review_path.write_bytes(data)
                failed = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=60)
                self.assertEqual(failed.returncode, 2)
                self.assertEqual(failed.stdout, b"")
                self.assertIn(code, failed.stderr)
                self.assertNotIn(b"SECRET", failed.stderr)
                self.assertNotIn(str(work).encode(), failed.stderr)
            review_path.unlink()
            failed = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=60)
            self.assertEqual(failed.returncode, 2)
            self.assertEqual(failed.stdout, b"")
            self.assertIn(b"E_IO", failed.stderr)
