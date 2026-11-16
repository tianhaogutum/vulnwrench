"""The CI gate changes only the exit status of a complete renewal review."""
from copy import deepcopy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from vulnwrench.triage import compile_decisions, preview_renewal, write_compilation
from vulnwrench.triage.cli import main
from vulnwrench.triage.compiler import json_bytes
from tests.triage.test_bridge import ROOT
from tests.triage.test_renewal import fixture
from tests.triage.test_renewal_inputs import arguments
from tests.triage.test_source_verification import ARCHIVED


class ReviewGateTests(unittest.TestCase):
    def cli(self, args):
        return subprocess.run([sys.executable, "-m", "vulnwrench", "triage", *map(str, args)],
                              cwd=ROOT, capture_output=True, timeout=60)

    def test_gate_keeps_complete_existing_plan_bytes(self):
        args = arguments(current=ROOT / "examples/triage/renewal/current.json")
        ordinary = self.cli(args)
        self.assertEqual(ordinary.returncode, 0, ordinary.stderr)
        gated = self.cli(args + ["--fail-on-review"])
        self.assertEqual(gated.returncode, 1, gated.stderr)
        self.assertEqual(gated.stderr, b"")
        expected = (ROOT / "examples/triage/renewal/expected-plan.json").read_bytes()
        self.assertEqual(ordinary.stdout, expected)
        self.assertEqual(gated.stdout, expected)

    def assert_plan(self, args, expected):
        ordinary = self.cli(args)
        gated = self.cli([*args, "--fail-on-review"])
        self.assertEqual(ordinary.returncode, 0, ordinary.stderr)
        self.assertEqual(gated.returncode, int(expected["counts"]["reviewRequired"] != 0), gated.stderr)
        self.assertEqual(ordinary.stderr, b"")
        self.assertEqual(gated.stderr, b"")
        self.assertEqual(ordinary.stdout, json_bytes(expected))
        self.assertEqual(gated.stdout, ordinary.stdout)
        self.assertEqual(expected["automaticActions"], [])

    def assert_invalid(self, args, code):
        # An invalid invocation must never become a review-gate failure.
        for flag in ([], ["--fail-on-review"]):
            result = self.cli([*args, *flag])
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stdout, b"")
            self.assertIn(code.encode(), result.stderr)
            self.assertNotIn(b"SECRET", result.stderr)
            self.assertNotIn(b"Traceback", result.stderr)

    def test_each_review_reason_and_combinations_use_existing_count(self):
        active = {"decisions": [fixture()["decisions"][-1]]}
        cases = []
        for expires, statuses in (("2026-11-11", ["expired"]),
                                  ("2026-11-18", ["expiring_soon"])):
            prior = deepcopy(active)
            prior["decisions"][0]["expiresOn"] = expires
            cases.append((prior, None, statuses))
        for updates, statuses in (({"owner": None}, ["owner_missing"]),
                ({"owner": "new-team"}, ["owner_changed"]),
                ({"package": "pkg:npm/changed@2"}, ["scope_changed"]),
                ({"reason": "Changed policy"}, ["policy_changed"]),
                ({"sourceRefs": ["urn:example:changed"]}, ["source_refs_changed"]),
                ({"expiresOn": "2026-11-11"}, ["current_expired", "policy_changed"]),
                ({"expiresOn": "2026-11-18"}, ["current_expiring_soon", "policy_changed"])):
            current = deepcopy(active)
            current["decisions"][0].update(updates)
            cases.append((active, current, statuses))
        expired = deepcopy(active)
        expired["decisions"][0]["expiresOn"] = "2026-11-11"
        extension = deepcopy(active)
        extension["decisions"][0].update(expiresOn="2027-01-01", owner=None,
            package="pkg:npm/changed@2", sourceRefs=["urn:example:changed"])
        cases.append((expired, extension,
            ["expired", "owner_missing", "scope_changed", "policy_changed", "source_refs_changed"]))
        with tempfile.TemporaryDirectory() as tmp:
            prior_path, current_path = Path(tmp) / "prior.json", Path(tmp) / "current.json"
            for prior, current, statuses in cases:
                with self.subTest(statuses=statuses):
                    prior_path.write_bytes(json_bytes(prior))
                    args = arguments(prior_path)
                    params = {}
                    if current is not None:
                        current_path.write_bytes(json_bytes(current))
                        args += ["--current", str(current_path)]
                        params["current"] = current
                    plan = preview_renewal(prior, prior_as_of="2026-11-01", as_of="2026-11-11",
                                           expiring_within_days=7, **params)
                    self.assertEqual(plan["decisions"][0]["statuses"], statuses)
                    self.assertEqual(plan["counts"], {"decisions": 1, "reviewRequired": 1})
                    self.assert_plan(args, plan)

    def test_added_removed_reordered_and_unchanged(self):
        prior = {"decisions": deepcopy(fixture()["decisions"][-2:])}
        reordered = {"decisions": list(reversed(prior["decisions"]))}
        replaced = deepcopy(prior)
        replaced["decisions"][0].update(decisionId="new-exception", ids=["NEW-ID"])
        replaced["decisions"].reverse()
        with tempfile.TemporaryDirectory() as tmp:
            p, c = Path(tmp) / "prior", Path(tmp) / "current"
            p.write_bytes(json_bytes(prior))
            for current, statuses, count in ((None, [["unchanged"], ["unchanged"]], 0),
                    (prior, [["unchanged"], ["unchanged"]], 0),
                    (reordered, [["unchanged"], ["unchanged"]], 0),
                    (replaced, [["removed"], ["unchanged"], ["added"]], 2)):
                with self.subTest(current=current):
                    params = {} if current is None else {"current": current}
                    plan = preview_renewal(prior, prior_as_of="2026-11-01", as_of="2026-11-11",
                                           expiring_within_days=7, **params)
                    self.assertEqual([d["statuses"] for d in plan["decisions"]], statuses)
                    self.assertEqual(plan["counts"]["reviewRequired"], count)
                    c.write_bytes(json_bytes(current))
                    self.assert_plan(arguments(p, None if current is None else c), plan)

    def test_horizon_zero_and_inclusive_utc_boundaries(self):
        prior = {"decisions": [fixture()["decisions"][-1]]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "prior"
            for expires, horizon, status in (("2026-11-10", 0, "expired"),
                    ("2026-11-11", 0, "expired"), ("2026-11-12", 0, "unchanged"),
                    ("2026-11-17", 7, "expiring_soon"), ("2026-11-18", 7, "expiring_soon"),
                    ("2026-11-19", 7, "unchanged")):
                with self.subTest(expires=expires, horizon=horizon):
                    prior["decisions"][0]["expiresOn"] = expires
                    path.write_bytes(json_bytes(prior))
                    plan = preview_renewal(prior, prior_as_of="2026-11-01", as_of="2026-11-11",
                                           expiring_within_days=horizon)
                    self.assertEqual(plan["decisions"][0]["statuses"], [status])
                    self.assert_plan(arguments(path) + ["--expiring-within-days", str(horizon)], plan)

    def test_report_baselines_independent_verification_and_no_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, document in (("review", fixture()),
                                   ("active", {"decisions": fixture()["decisions"][-2:]})):
                compiled = compile_decisions(document, **ARCHIVED)
                bundle = root / name
                write_compilation(compiled, bundle)
                source = root / (name + "-source.json")
                source.write_bytes(json_bytes(document))
                report = deepcopy(compiled.report)
                report["decisions"].reverse()
                baseline = root / (name + "-report.json")
                baseline.write_bytes(json_bytes(report))
                current = root / (name + "-current.json")
                candidate = deepcopy(document)
                candidate["decisions"].reverse()
                # Expiry extension must not clear the expired archived exception.
                if name == "review":
                    candidate["decisions"][-1]["expiresOn"] = "2027-01-01"
                current.write_bytes(json_bytes(candidate))
                before = {p: (p.read_bytes(), p.stat().st_mode) for p in root.rglob("*") if p.is_file()}
                entries = set(root.rglob("*"))
                for with_current in (False, True):
                    params = {"current": candidate} if with_current else {}
                    plan = preview_renewal(report, prior_format="conversion-report", as_of="2026-11-11",
                                           expiring_within_days=7, **params)
                    self.assertEqual(plan["counts"]["reviewRequired"], 2 if name == "review" else 0)
                    if name == "review":
                        self.assertIn("expired", plan["decisions"][-1]["statuses"])
                    for source_check, artifact_check in ((False, False), (True, False), (False, True), (True, True)):
                        with self.subTest(name=name, current=with_current, source=source_check, artifacts=artifact_check):
                            expected = deepcopy(plan)
                            args = arguments(baseline, current if with_current else None, report=True)
                            if source_check:
                                args += ["--verify-source", str(source)]
                                expected["sourceVerification"] = {"status": "verified",
                                    "canonicalJsonSha256": report["source"]["canonicalJsonSha256"],
                                    "decisionIndices": [r["index"] for r in report["decisions"]]}
                            if artifact_check:
                                args += ["--verify-artifacts", str(bundle)]
                                expected["artifactVerification"] = {"status": "verified", "artifacts": report["artifacts"]}
                            self.assert_plan(args, expected)
                self.assertEqual({p: (p.read_bytes(), p.stat().st_mode) for p in before}, before)
                self.assertEqual(set(root.rglob("*")), entries)

    def test_invalid_later_or_removed_records_and_report_metadata_cannot_be_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prior = fixture()  # First row requires review; validate every later row anyway.
            path, current = root / "SECRET-prior", root / "SECRET-current"
            missing = root / "SECRET-missing"
            bad = deepcopy(prior)
            bad["decisions"][-1]["SECRET-unknown"] = True
            path.write_bytes(json_bytes(bad))
            current.write_bytes(json_bytes({"decisions": [prior["decisions"][0]]}))
            self.assert_invalid(arguments(path, current), "E_INPUT")
            path.write_bytes(json_bytes(prior))
            current.write_bytes(json_bytes(bad))
            self.assert_invalid(arguments(path, current), "E_INPUT")
            for raw in (b'null', b'{"SECRET":0,"SECRET":1}', b'\xffSECRET'):
                current.write_bytes(raw)
                self.assert_invalid(arguments(path, current), "E_INPUT")
            current.write_bytes(json_bytes(prior))
            self.assert_invalid(arguments(path, current) + ["--as-of", "SECRET"], "E_DATE")
            self.assert_invalid(arguments(missing) + ["--verify-source", str(missing)], "E_ARGUMENT")
            self.assert_invalid(arguments(missing) + ["--verify-artifacts", str(missing)], "E_ARGUMENT")
            report = compile_decisions(prior, **ARCHIVED).report
            report["warnings"].append("SECRET-unknown")
            path.write_bytes(json_bytes(report))
            self.assert_invalid(arguments(path, report=True), "E_REPORT")
            # Current decoding still precedes semantic validation of the report.
            current.write_bytes(b'\xffSECRET')
            self.assert_invalid(arguments(path, current, report=True), "E_INPUT")

    def test_verification_errors_override_review_and_source_precedes_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            document = fixture()
            compiled = compile_decisions(document, **ARCHIVED)
            bundle = root / "bundle"
            write_compilation(compiled, bundle)
            source = root / "SECRET-source"
            baseline = bundle / "conversion-report.json"
            args = arguments(baseline, report=True)
            checks = ["--verify-source", str(source), "--verify-artifacts", str(root / "SECRET-missing")]
            source.write_bytes(b'{"SECRET":NaN}')
            self.assert_invalid(args + checks, "E_INPUT")
            changed = deepcopy(document)
            changed["decisions"][-1]["reason"] = "SECRET-changed"
            source.write_bytes(json_bytes(changed))
            self.assert_invalid(args + checks, "E_SOURCE")
            source.write_bytes(json_bytes(document))
            self.assert_invalid(args + checks, "E_ARTIFACT")
            (bundle / "osv-scanner.toml").write_bytes(b"SECRET-tampered")
            self.assert_invalid(args + ["--verify-artifacts", str(bundle)], "E_ARTIFACT")
            # Malformed unselected original file and broken artifacts aren't read without opt-ins.
            source.write_bytes(b'\xffSECRET')
            expected = preview_renewal(compiled.report, prior_format="conversion-report",
                                       as_of="2026-11-11", expiring_within_days=7)
            self.assert_plan(args, expected)

    def test_gate_retains_nonblocking_regular_file_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            fifo = Path(tmp) / "SECRET-fifo"
            os.mkfifo(fifo)
            for held_peer in (False, True):
                peer = os.open(fifo, os.O_RDWR | os.O_NONBLOCK) if held_peer else None
                try:
                    for report in (False, True):
                        for position in ("prior", "current"):
                            with self.subTest(peer=held_peer, report=report, position=position):
                                result = self.cli(arguments(**{position: fifo}, report=report) + ["--fail-on-review"])
                                self.assertEqual(result.returncode, 2, result.stderr)
                                self.assertEqual(result.stdout, b"")
                                self.assertIn(b"E_IO", result.stderr)
                                self.assertNotIn(b"SECRET", result.stderr)
                    self.assert_invalid(arguments(report=True) + ["--verify-source", str(fifo)], "E_IO")
                finally:
                    if peer is not None:
                        os.close(peer)

    def test_output_write_and_flush_failures_precede_gate_return(self):
        args = arguments(current=ROOT / "examples/triage/renewal/current.json")
        for flag in ([], ["--fail-on-review"]):
            for operation in ("write", "flush"):
                with self.subTest(flag=flag, operation=operation):
                    stdout = unittest.mock.Mock(fileno=unittest.mock.Mock(return_value=-1))  # not a tty for argparse 3.14
                    getattr(stdout, operation).side_effect = OSError("SECRET-stream")
                    with redirect_stdout(stdout), self.assertRaises(OSError):
                        main(args + flag)
                    stdout.write.assert_called_once_with((ROOT / "examples/triage/renewal/expected-plan.json").read_text())
                    self.assertEqual(stdout.flush.call_count, int(operation == "flush"))
            # Invalid input wins without even attempting output, despite a broken stream.
            stdout = unittest.mock.Mock(fileno=unittest.mock.Mock(return_value=-1))
            stdout.write.side_effect = OSError("SECRET-stream")
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(main(args + flag + ["--as-of", "SECRET"]), 2)
            stdout.write.assert_not_called()
            stdout.flush.assert_not_called()
            self.assertIn("E_DATE", stderr.getvalue())
            self.assertNotIn("SECRET", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
