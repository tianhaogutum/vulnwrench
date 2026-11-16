from copy import deepcopy
import json
import subprocess
import sys
import unittest

import vulnwrench.triage as triage_bridge
from vulnwrench.triage import BridgeError, compile_decisions, load_document
from vulnwrench.triage.compiler import digest, json_bytes
from tests.triage.test_bridge import PARAMS, ROOT


def fixture(name="prior"):
    return load_document(ROOT / "examples/triage/renewal" / (name + ".json"))


class RenewalTests(unittest.TestCase):
    def preview(self, prior=None, current=None, **params):
        return triage_bridge.preview_renewal(
            fixture() if prior is None else prior,
            **({"current": current} if current is not None else {}),
            **(dict(prior_as_of="2026-11-01", as_of="2026-11-11",
                    expiring_within_days=7) | params))

    def assert_bad(self, prior=None, current=None, code="E_INPUT", **params):
        with self.assertRaises(BridgeError) as error:
            self.preview(prior, current, **params)
        self.assertEqual(error.exception.code, code)

    def test_explicit_review_plan_and_preserved_identity(self):
        prior, current = fixture(), fixture("current")
        before = deepcopy((prior, current))
        plan = self.preview(prior, current)
        self.assertEqual([r["statuses"] for r in plan["decisions"]], [
            ["expired"], ["expiring_soon"], ["owner_changed"],
            ["owner_missing"], ["scope_changed"], ["unchanged"]])
        self.assertEqual([r["reviewRequired"] for r in plan["decisions"]],
                         [True, True, True, True, True, False])
        self.assertEqual(plan["counts"], {"decisions": 6, "reviewRequired": 5})
        self.assertEqual(plan["automaticActions"], [])
        self.assertEqual(plan["mode"], "review_only")
        for i, entry in enumerate(plan["decisions"]):
            self.assertEqual(entry["decisionId"], prior["decisions"][i]["decisionId"])
            self.assertEqual(entry["prior"]["record"]["ids"], prior["decisions"][i]["ids"])
            self.assertEqual(entry["prior"]["record"]["sourceRefs"], prior["decisions"][i]["sourceRefs"])
            self.assertEqual(entry["current"]["record"]["sourceRefs"], current["decisions"][i]["sourceRefs"])
            self.assertEqual(entry["prior"]["source"], {
                "canonicalJsonSha256": digest(json_bytes(prior)),
                "pointer": f"/decisions/{i}", "decisionIndex": i})
        self.assertEqual((prior, current), before)
        self.assertEqual(plan, self.preview(prior, current))

    def test_exact_utc_days_and_inclusive_horizon(self):
        for as_of, expected in [("2026-11-10", "expiring_soon"),
                                ("2026-11-11", "expired"),
                                ("2026-11-12", "expired")]:
            self.assertEqual(self.preview(as_of=as_of)["decisions"][0]["expiryStatus"], expected)
        self.assertEqual(self.preview(expiring_within_days=6)["decisions"][1]["statuses"], ["unchanged"])
        self.assertEqual(self.preview(expiring_within_days=0)["decisions"][0]["statuses"], ["expired"])
        self.assert_bad(as_of="2026-11-11T00:00:00Z", code="E_DATE")
        self.assert_bad(as_of="2026-10-31", code="E_DATE")
        for days in (-1, True, "7", 3661):
            self.assert_bad(expiring_within_days=days)

    def test_no_renewal_or_vex_assertion_even_when_candidate_extends_expiry(self):
        current = fixture()
        current["decisions"][0]["expiresOn"] = "2027-01-01"
        plan = self.preview(current=current)
        entry = plan["decisions"][0]
        self.assertEqual(entry["statuses"], ["expired", "policy_changed"])
        self.assertEqual(entry["expiryStatus"], "expired")
        self.assertEqual(entry["currentExpiryStatus"], "active")
        self.assertIn("review_expired_exception", entry["actions"])
        self.assertNotIn("statements", plan)
        self.assertNotIn("artifacts", plan)
        self.assertNotIn("not_affected", json.dumps(plan))
        with self.assertRaises(BridgeError) as error:
            compile_decisions(fixture(), **PARAMS)
        self.assertEqual(error.exception.code, "E_EXPIRED")
        with self.assertRaises(BridgeError):
            compile_decisions(plan, **PARAMS)

    def test_missing_owner_preview_is_distinct_and_compile_stays_strict(self):
        for missing in (None, "", " ", "\t"):
            current = fixture()
            current["decisions"][5]["owner"] = missing
            entry = self.preview(current=current)["decisions"][5]
            self.assertEqual(entry["statuses"], ["owner_missing"])
            with self.assertRaises(BridgeError) as error:
                compile_decisions(current, **PARAMS)
            self.assertEqual(error.exception.code, "E_INPUT")
        for invalid in ("\x00", "\r", "\x1f", " " * 16385, 17, " trailing "):
            current = fixture()
            current["decisions"][5]["owner"] = invalid
            self.assert_bad(current=current)

    def test_candidate_shortening_cannot_hide_utc_expiry(self):
        for expires, status in [("2026-11-11", "current_expired"),
                                ("2026-11-18", "current_expiring_soon")]:
            current = fixture()
            current["decisions"][5]["expiresOn"] = expires
            entry = self.preview(current=current)["decisions"][5]
            self.assertEqual(entry["expiryStatus"], "active")
            self.assertEqual(entry["statuses"], [status, "policy_changed"])
            self.assertTrue(entry["reviewRequired"])

    def test_explicit_vex_evidence_remains_source_data_only(self):
        prior = fixture()
        prior["decisions"][5].update(status="not_affected", justification="component_not_present")
        plan = self.preview(prior)
        entry = plan["decisions"][5]
        self.assertEqual(entry["statuses"], ["unchanged"])
        self.assertEqual(entry["prior"]["record"]["status"], "not_affected")
        self.assertNotIn("statements", plan)
        current = deepcopy(prior)
        del current["decisions"][5]["justification"]
        self.assert_bad(prior, current, code="E_STATUS")

    def test_null_current_document_is_invalid_instead_of_reusing_prior(self):
        with self.assertRaises(BridgeError) as error:
            triage_bridge.preview_renewal(fixture(), prior_as_of="2026-11-01",
                                         as_of="2026-11-11", current=None)
        self.assertEqual(error.exception.code, "E_INPUT")

    def test_scope_tracks_ids_aliases_and_package_without_guessing_matches(self):
        for field, value in [("ids", ["SYNTHETIC-REPLACED"]),
                             ("aliases", {"SYNTHETIC-UNCHANGED": ["SYNTHETIC-ALIAS"]}),
                             ("package", "pkg:npm/demo-unchanged@2.0")]:
            current = fixture()
            current["decisions"][5][field] = value
            self.assertEqual(self.preview(current=current)["decisions"][5]["statuses"], ["scope_changed"])
        current = fixture()
        current["decisions"].reverse()
        self.assertEqual(self.preview(current=current)["decisions"][5]["statuses"], ["unchanged"])
        current["decisions"][0]["sourceRefs"].append("urn:example:additional-review")
        self.assertEqual(self.preview(current=current)["decisions"][5]["statuses"], ["source_refs_changed"])
        self.assertEqual(self.preview(current=current)["decisions"][5]["current"]["source"]["pointer"], "/decisions/0")

    def test_combined_changes_added_and_removed_are_never_hidden(self):
        current = fixture()
        current["decisions"][0].update(owner="other", package="pkg:npm/other@1.0")
        current["decisions"].pop(5)
        added = deepcopy(current["decisions"][0])
        added.update(decisionId="exception-added", ids=["SYNTHETIC-ADDED"],
                     package="pkg:npm/added@1.0", expiresOn="2026-12-31")
        current["decisions"].append(added)
        entries = self.preview(current=current)["decisions"]
        self.assertEqual(entries[0]["statuses"], ["expired", "owner_changed", "scope_changed"])
        self.assertEqual(entries[5]["statuses"], ["removed"])
        self.assertIsNone(entries[5]["current"])
        self.assertEqual(entries[6]["statuses"], ["added"])
        self.assertIsNone(entries[6]["prior"])

    def test_stable_ids_required_unique_and_references_validated(self):
        prior = fixture()
        del prior["decisions"][0]["decisionId"]
        self.assert_bad(prior, code="E_RENEWAL_ID")
        self.assert_bad(current=prior, code="E_RENEWAL_ID")
        prior = fixture()
        prior["decisions"][1]["decisionId"] = prior["decisions"][0]["decisionId"]
        self.assert_bad(prior, code="E_CONFLICT")
        for refs in ("urn:example:ref", [""], ["x", "x"], [1]):
            prior = fixture()
            prior["decisions"][0]["sourceRefs"] = refs
            self.assert_bad(prior)
        prior = fixture()
        prior["decisions"][0]["unexpected"] = "SECRET"
        self.assert_bad(prior)

    def test_compiler_preserves_optional_review_metadata(self):
        prior = fixture()
        compiled = compile_decisions(prior, **(PARAMS | {
            "as_of": "2026-11-01", "timestamp": "2026-11-01T12:00:00Z"}))
        record = compiled.report["decisions"][0]["record"]
        self.assertEqual(record["decisionId"], "exception-expired")
        self.assertEqual(record["sourceRefs"], ["urn:example:review:expired"])
        self.assertNotIn("openvex.json", compiled.files)
        self.assertIn("review_metadata_not_native", {r["code"] for r in compiled.report["losses"]})

    def test_cli_plan_and_failure_emit_no_scanner_files(self):
        args = [sys.executable, "-m", "vulnwrench", "triage", "preview-renewal",
                str(ROOT / "examples/triage/renewal/prior.json"),
                "--current", str(ROOT / "examples/triage/renewal/current.json"),
                "--prior-as-of", "2026-11-01", "--as-of", "2026-11-11",
                "--expiring-within-days", "7"]
        result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), self.preview(current=fixture("current")))
        failed = subprocess.run(args + ["--as-of", "SECRET"], cwd=ROOT,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(failed.returncode, 2)
        self.assertEqual(failed.stdout, "")
        self.assertIn("E_DATE", failed.stderr)
        self.assertNotIn("SECRET", failed.stderr)
        self.assertNotIn("Traceback", failed.stderr)
