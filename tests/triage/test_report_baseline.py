"""Saved compilation reports are validated review baselines, never policy inputs."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from vulnwrench.triage import BridgeError, compile_decisions, load_document, preview_renewal
from vulnwrench.triage.compiler import digest, json_bytes
from tests.triage.test_bridge import PARAMS, ROOT
from tests.triage.test_renewal import fixture


def archive():
    return compile_decisions(fixture(), **(PARAMS | {
        "as_of": "2026-11-01", "timestamp": "2026-11-01T12:00:00Z"})).report


class ReportBaselineTests(unittest.TestCase):
    def preview(self, report=None, **kwargs):
        return preview_renewal(archive() if report is None else report,
                               prior_format="conversion-report", as_of="2026-11-11",
                               expiring_within_days=7, **kwargs)

    def test_saved_report_replaces_source_document_and_retains_provenance(self):
        report = archive()
        before = deepcopy(report)
        plan = self.preview(report, current=fixture("current"))
        expected = preview_renewal(fixture(), current=fixture("current"),
                                   prior_as_of="2026-11-01", as_of="2026-11-11",
                                   expiring_within_days=7)
        self.assertEqual(plan["counts"], {"decisions": 6, "reviewRequired": 5})
        self.assertEqual(plan["parameters"], expected["parameters"])
        self.assertEqual([e["statuses"] for e in plan["decisions"]],
                         [e["statuses"] for e in expected["decisions"]])
        self.assertEqual(plan["sources"]["priorCanonicalJsonSha256"], digest(json_bytes(report)))
        self.assertEqual(plan["sources"]["priorArchivedSourceCanonicalJsonSha256"],
                         report["source"]["canonicalJsonSha256"])
        for i, row in enumerate(plan["decisions"]):
            self.assertEqual(row["prior"]["record"], report["decisions"][i]["record"])
            self.assertEqual(row["prior"]["source"], {
                "canonicalJsonSha256": digest(json_bytes(report)), "decisionIndex": i,
                "pointer": f"/decisions/{i}/record",
                "archivedSourceCanonicalJsonSha256": report["source"]["canonicalJsonSha256"],
                "archivedSourcePointer": f"/decisions/{i}"})
            self.assertEqual(row["current"], expected["decisions"][i]["current"])
        self.assertEqual(report, before)
        self.assertEqual(plan["automaticActions"], [])
        self.assertNotIn("artifacts", plan)
        self.assertNotIn("statements", plan)
        with self.assertRaises(BridgeError):
            compile_decisions(plan, **PARAMS)

    def test_archived_indices_are_not_reassigned_when_report_rows_are_reordered(self):
        report = archive()
        report["decisions"].reverse()
        plan = self.preview(report)
        self.assertEqual([e["decisionId"] for e in plan["decisions"]],
                         [r["record"]["decisionId"] for r in report["decisions"]])
        for pos, row in enumerate(plan["decisions"]):
            source = row["prior"]["source"]
            self.assertEqual(source["decisionIndex"], 5 - pos)
            self.assertEqual(source["pointer"], f"/decisions/{pos}/record")
            self.assertEqual(source["archivedSourcePointer"], f"/decisions/{5 - pos}")
            self.assertEqual(row["current"], row["prior"])
        self.assertEqual(plan["sources"]["currentCanonicalJsonSha256"], digest(json_bytes(report)))

    def test_archived_source_digest_is_retained_without_claiming_authentication(self):
        report = archive()
        normalized = {"schemaVersion": 1, "decisions": [r["record"] for r in report["decisions"]]}
        # Normalization adds fields such as aliases; the original document hash
        # cannot be recomputed from these records alone.
        self.assertNotEqual(report["source"]["canonicalJsonSha256"], digest(json_bytes(normalized)))
        report["source"]["canonicalJsonSha256"] = "a" * 64
        plan = self.preview(report)
        self.assertEqual(plan["sources"]["priorArchivedSourceCanonicalJsonSha256"], "a" * 64)
        self.assertIn("not authenticated provenance", " ".join(plan["warnings"]))

    def test_baseline_date_is_archived_and_cannot_be_overridden(self):
        self.assertEqual(self.preview(prior_as_of="2026-11-01"), self.preview())
        for params in ({"prior_as_of": "2026-11-02"}, {"prior_as_of": "SECRET"}):
            with self.assertRaises(BridgeError) as error:
                self.preview(**params)
            self.assertEqual(error.exception.code, "E_DATE")
        with self.assertRaises(BridgeError) as error:
            preview_renewal(archive(), prior_format="conversion-report", as_of="2026-10-31")
        self.assertEqual(error.exception.code, "E_DATE")
        with self.assertRaises(BridgeError):
            preview_renewal(fixture(), as_of="2026-11-11")

    def test_all_current_compiler_statuses_and_legacy_metadata(self):
        document = load_document(ROOT / "examples/triage/mixed-decisions.json")
        for i, row in enumerate(document["decisions"]):
            row["decisionId"] = f"exception-{i}"
        report = compile_decisions(document, **PARAMS).report
        plan = self.preview(report)
        self.assertEqual(len(plan["decisions"]), 5)
        self.assertEqual([r["prior"]["record"]["status"] for r in plan["decisions"]],
                         [r["record"]["status"] for r in report["decisions"]])
        legacy = load_document(ROOT / "examples/triage/expected/decisions/conversion-report.json")
        with self.assertRaises(BridgeError) as error:
            self.preview(legacy)
        self.assertEqual(error.exception.code, "E_RENEWAL_ID")
        # No identity guessing and no implicit wrapper detection on either side.
        for kwargs in ({"prior_format": "auto"}, {"current": archive()}):
            with self.assertRaises(BridgeError):
                preview_renewal(archive(), prior_as_of="2026-11-01", as_of="2026-11-11", **kwargs)

    def test_invalid_or_inconsistent_reports_fail_closed(self):
        mutations = [
            lambda r: r.update(schemaVersion=True),
            lambda r: r.update(schemaVersion=2),
            lambda r: r.update(tool="SECRET"),
            lambda r: r.update(toolVersion="999"),
            lambda r: r.update(unexpected="SECRET"),
            lambda r: r.pop("warnings"),
            lambda r: r["source"].update(canonicalJsonSha256="SECRET"),
            lambda r: r["source"].update(schemaVersion=True),
            lambda r: r["source"].update(extra=0),
            lambda r: r["parameters"].update(asOf="2026-11-11"),
            lambda r: r["parameters"].update(allowScopeLoss=False),
            lambda r: r["decisions"][0].update(index=True),
            lambda r: r["decisions"][0].update(index=-1),
            lambda r: r["decisions"][0].update(index=1),
            lambda r: r["decisions"][0].update(index=6),
            lambda r: r["decisions"][0].pop("record"),
            lambda r: r["decisions"][0].update(extra="SECRET"),
            lambda r: r["decisions"][0]["record"].update(owner=None),
            lambda r: r["decisions"][0]["record"].update(status="not_affected"),
            lambda r: r["decisions"][0]["record"].update(reason="SECRET"),
            lambda r: r["decisions"][0]["record"].update(expiresOn="2026-11-01"),
            lambda r: r["decisions"][1]["record"].update(decisionId="exception-expired"),
            lambda r: r["counts"].update(decisions=7),
            lambda r: r["mappings"][0].update(decisionIndex=True),
            lambda r: r["losses"][0].update(decisionIndices=[99]),
            lambda r: r["artifacts"][".trivyignore.yaml"].update(sha256="0" * 64),
            lambda r: r["artifacts"][".trivyignore.yaml"].update(bytes=0),
            lambda r: r.update(openvexId="urn:SECRET"),
            lambda r: r.update(omittedArtifacts=[]),
            lambda r: r.update(decisions=[]),
            lambda r: r.update(decisions=[None]),
            lambda r: r.update(parameters=None),
        ]
        for mutate in mutations:
            report = archive()
            mutate(report)
            with self.subTest(mutation=mutations.index(mutate)):
                with self.assertRaises(BridgeError) as error:
                    self.preview(report)
                self.assertEqual(error.exception.code, "E_REPORT")
                self.assertNotIn("SECRET", str(error.exception))
        for report in (None, [], {}, fixture()):
            with self.assertRaises(BridgeError) as error:
                self.preview(report) if report is not None else preview_renewal(
                    None, prior_format="conversion-report", as_of="2026-11-11")
            self.assertEqual(error.exception.code, "E_REPORT")

    def test_cli_direct_archive_review_and_redacted_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "report.json"
            path.write_bytes(json_bytes(archive()))
            args = [sys.executable, "-m", "vulnwrench", "triage", "preview-renewal", str(path),
                    "--prior-format", "conversion-report", "--as-of", "2026-11-11",
                    "--expiring-within-days", "7"]
            result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), self.preview())
            invalid_inputs = [b'{"tool":"SECRET","tool":"SECRET"}', b'\xff',
                              b'{"schemaVersion":NaN}', b'x' * (2 * 1024 * 1024 + 1)]
            malformed = archive()
            malformed["counts"]["decisions"] = "SECRET"
            invalid_inputs.append(json_bytes(malformed))
            for raw in invalid_inputs:
                path.write_bytes(raw)
                failed = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=60)
                self.assertEqual(failed.returncode, 2)
                self.assertEqual(failed.stdout, "")
                self.assertNotIn("SECRET", failed.stderr)
                self.assertNotIn("Traceback", failed.stderr)
            self.assertEqual(list(root.iterdir()), [path])
