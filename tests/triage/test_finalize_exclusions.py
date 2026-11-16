"""Reasoned draft exclusion resolves duplicates without losing original positions."""
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
from tests.triage.test_bridge import PARAMS, ROOT
from tests.triage.test_finalize_import import inputs
from tests.triage.test_import_trivy import native


def exclusion_inputs(document=None, excluded=(0,)):
    if document is None:
        document = native()
        document["vulnerabilities"] *= 2
    raw, draft, review = inputs(document)
    review.pop("approvedDecisionIndices")
    review["decisionDispositions"] = []
    for i in range(len(draft["decisionDocument"]["decisions"])):
        if i in excluded:
            review["decisionDocument"]["decisions"][i] = deepcopy(draft["decisionDocument"]["decisions"][i])
            disposition = {"decisionIndex": i, "disposition": "exclude", "reason": "Repeated synthetic entry; approve the other record."}
        else:
            disposition = {"decisionIndex": i, "disposition": "approve"}
        review["decisionDispositions"].append(disposition)
    return raw, draft, review


def finalize(raw, draft, review, as_of="2026-11-11"):
    return triage_bridge.finalize_import(draft, source=raw, review=review, as_of=as_of)


class FinalizeExclusionTests(unittest.TestCase):
    def assert_bad(self, raw, draft, review, code="E_FINALIZE", **kwargs):
        with self.assertRaises(BridgeError) as caught:
            finalize(raw, draft, review, **kwargs)
        self.assertEqual(caught.exception.code, code)
        self.assertNotIn("SECRET", str(caught.exception))

    def test_exclude_first_duplicate_retains_original_positions_and_bound_reason(self):
        raw, draft, review = exclusion_inputs()
        before = deepcopy((draft, review))
        output = finalize(raw, draft, review)
        self.assertEqual((draft, review), before)
        self.assertEqual(output, finalize(raw, draft, review))
        self.assertEqual(len(output["decisions"]), 1)
        row = output["decisions"][0]
        self.assertEqual(row["decisionId"], "review-1")
        self.assertEqual(row["sourceRefs"], [
            f"urn:triage-bridge:trivy-ignore:sha256:{digest(raw)}#/vulnerabilities/1",
            f"urn:triage-bridge:import-review:sha256:{digest(json_bytes(review))}#/decisionDocument/decisions/1"])
        compiled = compile_decisions(output, **PARAMS)
        self.assertEqual(len(json.loads(compiled.files[".trivyignore.yaml"])["vulnerabilities"]), 1)
        self.assertNotIn("openvex.json", compiled.files)
        self.assertEqual(compiled.report["decisions"][0]["record"]["sourceRefs"], row["sourceRefs"])
        plan = triage_bridge.preview_renewal(output, prior_as_of="2026-11-11", as_of="2026-11-12")
        self.assertEqual(plan["decisions"][0]["prior"]["record"]["sourceRefs"], row["sourceRefs"])
        changed = deepcopy(review)
        changed["decisionDispositions"][0]["reason"] = "A different reason for excluding this entry."
        changed_row = finalize(raw, draft, changed)["decisions"][0]
        self.assertEqual(changed_row["sourceRefs"][0], row["sourceRefs"][0])
        self.assertNotEqual(changed_row["sourceRefs"][1], row["sourceRefs"][1])
        reordered = json.loads(json.dumps(review, sort_keys=True))
        self.assertEqual(finalize(raw, draft, reordered), output)

    def test_expanded_purls_and_disposition_order_do_not_renumber_records(self):
        raw, draft, review = exclusion_inputs(native(purls=["pkg:npm/demo@1", "pkg:npm/demo@2", "pkg:npm/demo@3"]))
        review["decisionDispositions"].reverse()
        review["decisionDocument"]["decisions"][1]["sourceRefs"] = ["ticket:synthetic"]
        rows = finalize(raw, draft, review)["decisions"]
        self.assertEqual([r["package"] for r in rows], ["pkg:npm/demo@2", "pkg:npm/demo@3"])
        self.assertEqual(rows[0]["sourceRefs"][0], "ticket:synthetic")
        for index, row in enumerate(rows, 1):
            self.assertTrue(row["sourceRefs"][-2].endswith("#/vulnerabilities/0"))
            self.assertTrue(row["sourceRefs"][-1].endswith(f"#/decisionDocument/decisions/{index}"))

    def invalid_reviews(self, review):
        for value in (None, {}, [], [0], [True], "SECRET"):
            yield review | {"decisionDispositions": value}
        rows = review["decisionDispositions"]
        yield review | {"approvedDecisionIndices": [0, 1]}
        yield {k: v for k, v in review.items() if k != "decisionDispositions"}
        for value in (rows[:1], [rows[0], rows[0]], [rows[0], {"decisionIndex": 0, "disposition": "approve"}],
                      rows + [rows[0]], rows + [{"decisionIndex": 0, "disposition": "approve"}]):
            yield review | {"decisionDispositions": value}
        for value in (-1, 2, True, 0.0, "0", None):
            yield review | {"decisionDispositions": [rows[0] | {"decisionIndex": value}, rows[1]]}
        for key in ("decisionIndex", "disposition", "reason"):
            bad = deepcopy(review)
            bad["decisionDispositions"][0].pop(key)
            yield bad
        bad = deepcopy(review)
        bad["decisionDispositions"][1].pop("disposition")
        yield bad
        for value in (None, "", " ", " padded", "SECRET\x00", "x" * 16385, "\ud800"):
            yield review | {"decisionDispositions": [rows[0] | {"reason": value}, rows[1]]}
        for changes in ({"disposition": "accept"}, {"unknown": "SECRET"}, {"disposition": None}):
            yield review | {"decisionDispositions": [rows[0] | changes, rows[1]]}
        yield review | {"decisionDispositions": [rows[0], rows[1] | {"reason": "SECRET"}]}
        yield review | {"schemaVersion": 2}
        yield review | {"schemaVersion": True}
        yield review | {"unknown": "SECRET"}

    def test_each_original_index_needs_exactly_one_strict_disposition(self):
        raw, draft, review = exclusion_inputs()
        for n, bad in enumerate(self.invalid_reviews(review)):
            with self.subTest(case=n):
                self.assert_bad(raw, draft, bad)

    def test_no_exclusion_can_rewrite_source_draft_or_slots(self):
        raw, draft, review = exclusion_inputs()
        self.assert_bad(raw + b"\n", draft, review)
        forged = deepcopy(draft)
        forged["reviews"][1]["sourcePointer"] = "/SECRET"
        self.assert_bad(raw, forged, review)
        for index in (0, 1):
            for key, value in (("ids", ["CVE-SECRET"]), ("package", "pkg:npm/SECRET@1"),
                               ("reason", "SECRET"), ("expiresOn", "2099-12-01")):
                bad = deepcopy(review)
                bad["decisionDocument"]["decisions"][index][key] = value
                self.assert_bad(raw, draft, bad)
        for changes in ({"owner": "SECRET"}, {"unknown": "SECRET"}):
            bad = deepcopy(review)
            bad["decisionDocument"]["decisions"][0].update(changes)
            self.assert_bad(raw, draft, bad)
        for action in (lambda r: r.pop(), lambda r: r.append(deepcopy(r[0])), lambda r: r.reverse()):
            bad = deepcopy(review)
            action(bad["decisionDocument"]["decisions"])
            self.assert_bad(raw, draft, bad)

    def test_approved_policy_evidence_overlap_and_expiry_remain_strict(self):
        raw, draft, review = exclusion_inputs()
        for changes, code in (({"owner": None}, "E_INPUT"), ({"status": "not_affected"}, "E_STATUS"),
                              ({"status": "affected"}, "E_STATUS"), ({"status": "SECRET"}, "E_STATUS"),
                              ({"aliases": {"CVE-SECRET": []}}, "E_INPUT")):
            bad = deepcopy(review)
            bad["decisionDocument"]["decisions"][1].update(changes)
            self.assert_bad(raw, draft, bad, code)
        self.assert_bad(raw, draft, review, "E_EXPIRED", as_of="2026-12-01")
        self.assert_bad(raw, draft, review, "E_DATE", as_of="SECRET")
        self.assert_bad(*exclusion_inputs(excluded=()), "E_CONFLICT")
        self.assert_bad(*exclusion_inputs(excluded=(0, 1)), "E_INPUT")
        self.assert_bad(*exclusion_inputs(native(paths=["lock"])), "E_INPUT")
        bad = deepcopy(review)
        bad["decisionDocument"]["schemaVersion"] = True
        self.assert_bad(raw, draft, bad, "E_INPUT")
        # Missing all-package fields are required on approval but can remain null on exclusion.
        doc = native()
        doc["vulnerabilities"].insert(0, {"id": "CVE-2099-OTHER"})
        self.assertEqual(len(finalize(*exclusion_inputs(doc))["decisions"]), 1)
        raw, draft, review = exclusion_inputs(doc, excluded=())
        self.assert_bad(raw, draft, review, "E_INPUT")

    def test_unsupported_findings_remain_separate_and_cannot_be_salvaged(self):
        doc = native()
        doc["vulnerabilities"] *= 2
        doc["vulnerabilities"].append(doc["vulnerabilities"][0] | {"paths": ["lock"]})
        raw, draft, review = exclusion_inputs(doc)
        self.assertEqual(len(finalize(raw, draft, review)["decisions"]), 1)
        for value in ([], [review["unsupportedDispositions"][0] | {"disposition": "approve"}]):
            self.assert_bad(raw, draft, review | {"unsupportedDispositions": value})
        self.assert_bad(raw, draft, review | {"decisionDispositions": review["decisionDispositions"] + [
            {"decisionIndex": 2, "disposition": "approve"}]})

    def test_cli_positive_and_invalid_dispositions_exit_two_with_empty_stdout(self):
        raw, draft, review = exclusion_inputs()
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            source, draft_file, review_file = [work / name for name in ("native.yaml", "draft.json", "review.json")]
            source.write_bytes(raw)
            draft_file.write_bytes(json_bytes(draft))
            review_file.write_bytes(json_bytes(review))
            before = {p.name: p.read_bytes() for p in work.iterdir()}
            argv = [sys.executable, "-m", "vulnwrench", "triage", "finalize-import", str(draft_file),
                    "--source", str(source), "--review", str(review_file), "--as-of", "2026-11-11"]
            result = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), finalize(raw, draft, review))
            self.assertEqual(result.stderr, b"")
            self.assertEqual({p.name: p.read_bytes() for p in work.iterdir()}, before)
            for n, bad in enumerate(self.invalid_reviews(review)):
                with self.subTest(case=n):
                    review_file.write_text(json.dumps(bad), encoding="utf-8")
                    result = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=60)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, b"")
                    self.assertIn(b"E_FINALIZE", result.stderr)
                    self.assertNotIn(b"SECRET", result.stderr)
                    self.assertNotIn(str(work).encode(), result.stderr)
            self.assertEqual(set(p.name for p in work.iterdir()), set(before))
