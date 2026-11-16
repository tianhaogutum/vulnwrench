"""Small synthetic native-format evidence, library and real CLI regression tests."""

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulnwrench.scorecard import InputError, check, gate_exit_code, normalize_repository, render_markdown

ROOT = Path(__file__).resolve().parents[2]
PURL = "pkg:npm/demo@1.0"
REPO = "https://github.com/example/demo"


def snapshot(date="2026-11-10", score=8, name="github.com/example/demo"):
    return {"date": date, "repo": {"name": name, "commit": "1" * 40},
            "scorecard": {"version": "v5.0.0", "commit": "a" * 40},
            "score": 8.4, "checks": [{"name": "Code-Review", "score": score,
                                       "reason": "Synthetic evidence"}]}


def component(purl=PURL, ref="demo"):
    result = {"type": "library", "name": "demo", "bom-ref": ref}
    if purl is not None:
        result["purl"] = purl
    return result


class JoinTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                    "components": [component()]}
        self.mapping = {PURL: REPO}
        self.policy = {"checks": {"Code-Review": 7}, "maxAgeDays": 30, "missing": "unknown"}
        self.documents = {"demo.json": snapshot()}
        (self.root / "scorecards").mkdir()
        self.write()

    def write(self):
        for name, document in (("bom.json", self.bom), ("repos.json", self.mapping),
                               ("policy.json", self.policy)):
            (self.root / name).write_text(json.dumps(document), encoding="utf-8")
        for file in (self.root / "scorecards").iterdir():
            file.unlink()
        for name, document in self.documents.items():
            (self.root / "scorecards" / name).write_text(json.dumps(document), encoding="utf-8")

    def report(self, as_of="2026-11-11"):
        self.write()
        return self.read_report(as_of)

    def read_report(self, as_of="2026-11-11"):
        return check(self.root / "bom.json", self.root / "repos.json", self.root / "scorecards",
                     self.root / "policy.json", as_of)

    def cli(self, *extra):
        return subprocess.run([sys.executable, "-m", "vulnwrench", "scorecard", "check", str(self.root / "bom.json"),
                               "--map", str(self.root / "repos.json"), "--scorecards", str(self.root / "scorecards"),
                               "--policy", str(self.root / "policy.json"), "--as-of", "2026-11-11", *extra],
                              cwd=ROOT, capture_output=True, text=True, timeout=120)

    def test_native_field_mapping_and_provenance(self):
        report = self.report()
        row = report["components"][0]
        self.assertEqual((row["decision"], row["repository"], row["upstreamScore"], row["ageDays"]),
                         ("pass", REPO, 8.4, 1))
        self.assertEqual(row["checks"][0]["score"], 8)
        evidence = report["snapshots"][0]
        self.assertEqual(evidence["document"], self.documents["demo.json"])
        self.assertEqual(evidence["document"]["repo"]["commit"], "1" * 40)
        self.assertEqual(evidence["recordedDate"], "2026-11-10")
        self.assertTrue(evidence["sources"][0]["sha256"].startswith("sha256:"))
        self.assertEqual(gate_exit_code(report), 0)

    def test_all_cyclonedx_versions_cli_e2e(self):
        for version in ("1.4", "1.5", "1.6"):
            with self.subTest(version=version):
                self.bom["specVersion"] = version
                self.write()
                run = self.cli("--gate")
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(json.loads(run.stdout)["decision"], "pass")

    def test_repository_result_reused_across_packages(self):
        self.bom["components"].append(component("pkg:npm/helper@2", "helper"))
        self.mapping["pkg:npm/helper@2"] = "https://GitHub.com/EXAMPLE/Demo.git/"
        report = self.report()
        self.assertEqual(report["components"][0]["snapshotId"], report["components"][1]["snapshotId"])
        self.assertEqual(len(report["snapshots"]), 1)
        self.assertEqual(report["summary"]["selectedRepositories"], 1)
        self.assertEqual(report["summary"]["joinedComponents"], 2)

    def test_unmapped_missing_purl_nested_and_subject_all_retained(self):
        self.bom["components"] += [component("pkg:npm/unmapped@1", "other"), component(None, "file")]
        self.bom["components"][0]["components"] = [component("pkg:npm/nested@1", "nested")]
        self.bom["metadata"] = {"component": component(None, "root")}
        rows = self.report()["components"]
        self.assertEqual(len(rows), 5)
        self.assertEqual({row["bomRef"] for row in rows}, {"demo", "other", "file", "nested", "root"})
        self.assertEqual({row["reason"] for row in rows}, {"checks_passed", "unmapped_component", "missing_purl"})

    def test_pedigree_and_formulation_retained_with_roles(self):
        self.bom["components"][0]["pedigree"] = {"ancestors": [component(None, "ancestor")]}
        self.bom["formulation"] = [{"components": [component(None, "build-tool")]}]
        rows = self.report()["components"]
        self.assertEqual([(row["bomRef"], row["role"]) for row in rows],
                         [("demo", "inventory"), ("ancestor", "pedigree"), ("build-tool", "formulation")])

    def test_unknown_fields_checks_and_unused_mapping_preserved(self):
        self.bom["futureExtension"] = {"new": [1, 2]}
        self.documents["demo.json"]["extension"] = {"notDiscarded": True}
        self.documents["demo.json"]["checks"].append({"name": "Future-Check", "score": 3, "extension": "kept"})
        self.mapping["pkg:pypi/unused@1"] = "https://gitlab.com/org/unused"
        report = self.report()
        self.assertEqual(report["inputs"]["bom"]["document"], self.bom)
        self.assertEqual(report["snapshots"][0]["document"], self.documents["demo.json"])
        self.assertEqual(report["summary"]["unusedMappings"], ["pkg:pypi/unused@1"])
        self.assertEqual(report["decision"], "pass")

    def test_purl_is_exact_version_and_qualifiers_not_guessed(self):
        self.mapping = {"pkg:npm/demo@2.0": REPO, "pkg:npm/demo@1.0?arch=x86": REPO}
        self.assertEqual(self.report()["components"][0]["reason"], "unmapped_component")

    def test_missing_scorecard(self):
        self.documents.clear()
        row = self.report()["components"][0]
        self.assertEqual((row["decision"], row["reason"]), ("unknown", "missing_scorecard"))

    def test_negative_score_unknown_not_numeric_failure(self):
        self.documents["demo.json"]["checks"][0]["score"] = -1
        row = self.report()["components"][0]
        self.assertEqual((row["decision"], row["checks"][0]["observation"]), ("unknown", "negative_score"))
        self.assertEqual(row["upstreamScore"], 8.4)

    def test_absent_check_and_missing_or_null_scores_unknown(self):
        for checks, observation in (([], "missing_check"), ([{"name": "Code-Review"}], "missing_score"),
                                    ([{"name": "Code-Review", "score": None}], "missing_score")):
            with self.subTest(checks=checks):
                self.documents["demo.json"]["checks"] = checks
                row = self.report()["components"][0]
                self.assertEqual(row["decision"], "unknown")
                self.assertEqual(row["checks"][0]["observation"], observation)

    def test_missing_fail_policy_keeps_unknown_observation(self):
        self.policy["missing"] = "fail"
        self.documents["demo.json"]["checks"][0]["score"] = -1
        row = self.report()["components"][0]
        self.assertEqual(row["decision"], "fail")
        self.assertEqual(row["checks"][0]["observation"], "negative_score")
        self.assertEqual(row["checks"][0]["score"], -1)

    def test_fail_dominates_unknown_and_aggregate_not_recalculated(self):
        self.policy["checks"]["Security-Policy"] = 5
        self.documents["demo.json"]["checks"][0]["score"] = 6
        report = self.report()
        self.assertEqual(report["decision"], "fail")
        self.assertEqual(report["components"][0]["upstreamScore"], 8.4)
        self.assertEqual([item["decision"] for item in report["components"][0]["checks"]], ["fail", "unknown"])

    def test_stale_results_joined_with_values_but_unknown(self):
        self.documents["demo.json"]["date"] = "2026-10-11"
        report = self.report()
        row = report["components"][0]
        self.assertEqual((row["decision"], row["reason"], row["ageDays"]), ("unknown", "stale_snapshot", 31))
        self.assertIsNotNone(row["snapshotId"])
        self.assertEqual(row["checks"][0]["score"], 8)
        self.assertEqual(report["summary"]["staleComponents"], 1)
        self.assertEqual(report["summary"]["freshComponents"], 0)

    def test_age_boundary_calendar_days_in_utc(self):
        self.documents["demo.json"]["date"] = "2026-10-12T23:59:59Z"
        self.assertEqual(self.report()["decision"], "pass")
        self.documents["demo.json"]["date"] = "2026-10-12T00:01:00+02:00"
        self.assertEqual(self.report()["decision"], "unknown")

    def test_latest_not_filename_order_and_future_excluded(self):
        self.documents = {"z-old.json": snapshot("2026-11-09", 2),
                          "a-new.json": snapshot("2026-11-10", 8),
                          "b-future.json": snapshot("2026-11-12", 1)}
        report = self.report()
        self.assertEqual(report["decision"], "pass")
        index = report["repositoryIndex"][REPO]
        selected = next(item for item in report["snapshots"] if item["id"] == index["selectedSnapshot"])
        self.assertEqual(selected["recordedDate"], "2026-11-10")
        self.assertEqual(len(report["snapshots"]), 3)
        self.assertEqual(len(index["futureSnapshots"]), 1)

    def test_timestamp_fraction_order_and_inclusive_asof(self):
        self.documents = {"a.json": snapshot("2026-11-11T10:00:00Z", 1),
                          "b.json": snapshot("2026-11-11T10:00:00.100Z", 8)}
        self.assertEqual(self.report("2026-11-11T10:00:00.100Z")["decision"], "pass")
        self.assertEqual(self.report("2026-11-11T10:00:00Z")["decision"], "fail")
        self.assertEqual(self.report("2026-11-11")["decision"], "pass")

    def test_only_future_snapshot_explicit_unknown(self):
        self.documents["demo.json"]["date"] = "2026-11-12"
        report = self.report()
        self.assertEqual(report["components"][0]["reason"], "no_snapshot_as_of")
        self.assertEqual(report["summary"]["joinedComponents"], 0)

    def test_same_instant_conflicting_snapshots_rejected(self):
        for date in ("2026-11-10", "2026-11-10T01:00:00+01:00"):
            with self.subTest(date=date):
                self.documents["other.json"] = snapshot(date, 5, "https://GitHub.com/EXAMPLE/Demo.git")
                with self.assertRaisesRegex(InputError, "conflicting Scorecard"):
                    self.report()

    def test_identical_semantic_snapshot_deduplicated(self):
        self.write()
        (self.root / "scorecards" / "duplicate.json").write_text(
            json.dumps(self.documents["demo.json"], indent=4, sort_keys=True))
        report = self.read_report()
        self.assertEqual(len(report["snapshots"]), 1)
        self.assertEqual(len(report["snapshots"][0]["sources"]), 2)
        self.assertNotEqual(report["snapshots"][0]["sources"][0]["sha256"],
                            report["snapshots"][0]["sources"][1]["sha256"])

    def test_duplicate_mapping_key_rejected_even_if_same(self):
        for second in (REPO, "https://github.com/another/repo"):
            with self.subTest(second=second):
                (self.root / "repos.json").write_text('{"' + PURL + '":"' + REPO + '","' + PURL + '":"' + second + '"}')
                with self.assertRaisesRegex(InputError, "duplicate JSON key"):
                    self.read_report()

    def test_unknown_policy_check_and_invalid_threshold(self):
        for checks in ({"Code-Reveiw": 7}, {"Code-Review": "7"}, {"Code-Review": True},
                       {"Code-Review": -1}, {"Code-Review": 11}, {}):
            with self.subTest(checks=checks):
                self.policy["checks"] = checks
                with self.assertRaises(InputError):
                    self.report()

    def test_invalid_policy_fields(self):
        for key, value in (("maxAgeDays", -1), ("maxAgeDays", True), ("missing", "pass"),
                           ("maxAgeDay", 3), ("missing", []), ("checks", [])):
            with self.subTest(key=key, value=value):
                original = copy.deepcopy(self.policy)
                self.policy[key] = value
                with self.assertRaises(InputError):
                    self.report()
                self.policy = original

    def test_invalid_repository_in_mapping_and_snapshot(self):
        secret_url = "https://user:SECRET-TOKEN@github.com/example/demo?token=SECRET-TOKEN"
        self.mapping[PURL] = secret_url
        with self.assertRaises(InputError) as error:
            self.report()
        self.assertNotIn("SECRET-TOKEN", str(error.exception))
        self.mapping[PURL] = REPO
        self.documents["demo.json"]["repo"]["name"] = secret_url
        with self.assertRaises(InputError):
            self.report()

    def test_dates_missing_timezone_and_invalid_rejected(self):
        for date in (None, "2026-02-30", "2026-11-10T00:00:00", "2026-11-10T00:00:00+24:00", "2026-11-10T00:00:00+01:60"):
            with self.subTest(date=date):
                self.documents["demo.json"]["date"] = date
                with self.assertRaises(InputError):
                    self.report()
        with self.assertRaises(InputError):
            self.report("not-a-date")

    def test_unsupported_sbom_formats_and_versions(self):
        for key, value in (("bomFormat", "SPDX"), ("specVersion", "1.3"), ("specVersion", 1.6),
                           ("specVersion", "1.7"), ("version", True), ("version", 0)):
            with self.subTest(key=key, value=value):
                original = copy.deepcopy(self.bom)
                self.bom[key] = value
                with self.assertRaises(InputError):
                    self.report()
                self.bom = original

    def test_invalid_components_not_silently_skipped(self):
        for components in (None, [None], [{"name": "missing-type"}], [component("not-a-purl")],
                           [component(), component()], [dict(component(), components={})]):
            with self.subTest(components=components):
                self.bom["components"] = components
                with self.assertRaises(InputError):
                    self.report()

    def test_invalid_snapshot_shapes(self):
        for key, value in (("checks", {}), ("repo", "github.com/example/demo"), ("score", "8.4"),
                           ("checks", [{"name": "Code-Review", "score": 8.5}]),
                           ("checks", [{"name": "Code-Review", "score": -2}]),
                           ("checks", [{"name": "Code-Review", "score": True}]),
                           ("checks", [{"name": "Code-Review"}, {"name": "Code-Review"}])):
            with self.subTest(key=key, value=value):
                self.documents = {"demo.json": snapshot()}
                self.documents["demo.json"][key] = value
                with self.assertRaises(InputError):
                    self.report()

    def test_unrelated_invalid_snapshot_is_not_ignored(self):
        self.documents["unmapped.json"] = {"oops": "not a Scorecard report"}
        with self.assertRaises(InputError):
            self.report()

    def test_single_file_scorecard_input(self):
        report = check(self.root / "bom.json", self.root / "repos.json", self.root / "scorecards/demo.json",
                       self.root / "policy.json", "2026-11-11")
        self.assertEqual(report["decision"], "pass")

    def test_empty_inventory_is_unknown_and_gate_withheld(self):
        self.bom["components"] = []
        report = self.report()
        self.assertEqual(report["decision"], "unknown")
        self.assertEqual(gate_exit_code(report), 1)

    def test_unsupported_directory_entries_rejected(self):
        for name in ("evidence.jsonl", "readme.txt"):
            with self.subTest(name=name):
                self.write()
                (self.root / "scorecards" / name).write_text("not silently skipped")
                with self.assertRaises(InputError):
                    self.read_report()

    def test_nonfinite_json_numbers_and_duplicate_keys_rejected(self):
        for text in ('{"unknown": NaN}', '{"unknown": Infinity}', '{"unknown": 1e999}', '{"unknown":1,"unknown":2}'):
            with self.subTest(text=text):
                (self.root / "bom.json").write_text(text)
                with self.assertRaises(InputError):
                    self.read_report()

    def test_malformed_json_xml_and_encoding_errors(self):
        for raw in (b"{", b"<bom/>", b"[]", b"\xff", b'{"unknown":"\\ud800"}'):
            with self.subTest(raw=raw):
                (self.root / "bom.json").write_bytes(raw)
                with self.assertRaises(InputError):
                    self.read_report()

    def test_file_limit_and_missing_input(self):
        with patch("vulnwrench.scorecard.core.MAX_FILE_BYTES", 10):
            with self.assertRaisesRegex(InputError, "16 MiB"):
                self.read_report()
        (self.root / "bom.json").unlink()
        with self.assertRaisesRegex(InputError, "regular file"):
            self.read_report()

    def test_total_size_limit(self):
        with patch("vulnwrench.scorecard.core.MAX_TOTAL_BYTES", 10):
            with self.assertRaisesRegex(InputError, "128 MiB"):
                self.read_report()

    def test_deterministic_report_and_cli_bytes(self):
        self.assertEqual(self.report(), self.report())
        first, second = self.cli(), self.cli()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(json.loads(first.stdout), self.read_report())

    def test_gate_cli_exit_codes_match_report(self):
        for score in (8, 2, -1):
            with self.subTest(score=score):
                self.documents["demo.json"]["checks"][0]["score"] = score
                self.write()
                run = self.cli("--gate")
                report = json.loads(run.stdout)
                self.assertEqual(run.returncode, report["gate"]["exitCode"])
                self.assertEqual(self.cli().returncode, 0)

    def test_gate_still_writes_report(self):
        self.documents.clear()
        self.write()
        output = self.root / "out.json"
        run = self.cli("--gate", "--output", str(output))
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertEqual(json.loads(output.read_text())["decision"], "unknown")
        self.assertEqual(run.stdout, "")

    def test_invalid_cli_has_no_output_no_traceback_or_secret(self):
        (self.root / "repos.json").write_text('{"SECRET-TOKEN": "https://user:SECRET-TOKEN@example.com/o/r"}')
        output = self.root / "out.json"
        run = self.cli("--output", str(output))
        self.assertEqual(run.returncode, 2)
        self.assertFalse(output.exists())
        self.assertNotIn("SECRET-TOKEN", run.stderr)
        self.assertNotIn("Traceback", run.stderr)
        self.assertEqual(run.stdout, "")

    def test_failed_validation_preserves_existing_output(self):
        output = self.root / "out.json"
        output.write_text("previous report")
        (self.root / "bom.json").write_text("invalid")
        self.assertEqual(self.cli("--output", str(output)).returncode, 2)
        self.assertEqual(output.read_text(), "previous report")

    def test_output_cannot_overwrite_inputs_or_hardlinks(self):
        for source in (self.root / "bom.json", self.root / "repos.json", self.root / "policy.json",
                       self.root / "scorecards/demo.json"):
            with self.subTest(source=source.name):
                before = source.read_bytes()
                self.assertEqual(self.cli("--output", str(source)).returncode, 2)
                self.assertEqual(source.read_bytes(), before)
        alias = self.root / "hardlink.json"
        os.link(self.root / "bom.json", alias)
        self.assertEqual(self.cli("--output", str(alias)).returncode, 2)

    def test_output_symlink_and_missing_parent_rejected(self):
        alias = self.root / "alias.json"
        alias.symlink_to(self.root / "bom.json")
        for output in (alias, self.root / "absent/out.json"):
            with self.subTest(output=output):
                self.assertEqual(self.cli("--output", str(output)).returncode, 2)

    def test_markdown_cli_and_lossless_safe_appendix(self):
        self.bom["components"][0]["name"] = "untrusted | <script>alert(1)</script> ```"
        self.documents["demo.json"]["checks"][0]["reason"] = "````\n</details>"
        report = self.report()
        rendered = render_markdown(report)
        self.assertIn("# Scorecard join", rendered)
        self.assertNotIn("<script>", rendered)
        self.assertIn("`````json", rendered)
        appendix = rendered.split("`````json\n", 1)[1].rsplit("\n`````", 1)[0]
        self.assertEqual(json.loads(appendix), report)
        run = self.cli("--format", "markdown")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout, rendered)

    def test_no_external_reference_or_name_based_repository_guess(self):
        self.mapping.clear()
        self.bom["components"][0]["externalReferences"] = [{"type": "vcs", "url": REPO}]
        self.assertEqual(self.report()["components"][0]["reason"], "unmapped_component")

    def test_duplicate_purl_rows_are_not_collapsed(self):
        self.bom["components"].append(component(PURL, "second-occurrence"))
        report = self.report()
        self.assertEqual(report["summary"]["components"], 2)
        self.assertEqual(report["summary"]["pass"], 2)
        self.assertEqual(report["components"][0]["snapshotId"], report["components"][1]["snapshotId"])

    def test_component_without_purl_or_ref_gets_structural_identity(self):
        self.bom["components"] = [{"name": "unidentified", "type": "file"}]
        row = self.report()["components"][0]
        self.assertEqual(row["component"], "/components/0")
        self.assertEqual(row["decision"], "unknown")

    def test_equal_threshold_passes_and_stale_missing_fail(self):
        self.policy["checks"]["Code-Review"] = 8
        self.assertEqual(self.report()["decision"], "pass")
        self.policy["maxAgeDays"] = 0
        self.policy["missing"] = "fail"
        row = self.report()["components"][0]
        self.assertEqual((row["decision"], row["reason"]), ("fail", "stale_snapshot"))

    def test_malformed_missing_commit_rejected(self):
        self.documents["demo.json"]["repo"].pop("commit")
        with self.assertRaises(InputError):
            self.report()

    def test_symlink_and_subdirectory_in_snapshot_directory_rejected(self):
        symlink = self.root / "scorecards/link.json"
        symlink.symlink_to(self.root / "scorecards/demo.json")
        with self.assertRaises(InputError):
            self.read_report()
        symlink.unlink()
        (self.root / "scorecards/nested").mkdir()
        with self.assertRaises(InputError):
            self.read_report()

    def test_nonregular_input_does_not_block(self):
        path = self.root / "bom.json"
        path.unlink()
        os.mkfifo(path)
        run = self.cli()
        self.assertEqual(run.returncode, 2)
        self.assertIn("regular file", run.stderr)

    def test_cyclonedx14_formulation_explicitly_rejected(self):
        self.bom["specVersion"] = "1.4"
        self.bom["formulation"] = []
        with self.assertRaisesRegex(InputError, "formulation"):
            self.report()

    def test_help_and_bad_cli_arguments(self):
        run = subprocess.run([sys.executable, "-m", "vulnwrench", "scorecard", "--help"], cwd=ROOT,
                             capture_output=True, text=True, timeout=120)
        self.assertEqual(run.returncode, 0)
        self.assertIn("check", run.stdout)
        run = self.cli("--bad-SECRET-TOKEN")
        self.assertEqual(run.returncode, 2)
        self.assertNotIn("SECRET-TOKEN", run.stderr)


class RepositoryTests(unittest.TestCase):
    def test_normalization_is_explicit_and_host_aware(self):
        for value in ("github.com/Example/Demo", "https://GITHUB.com/Example/Demo.git/", REPO):
            with self.subTest(value=value):
                self.assertEqual(normalize_repository(value), REPO)
        self.assertEqual(normalize_repository("https://GitLab.com/org/sub/Case.git/"),
                         "https://gitlab.com/org/sub/Case")

    def test_reject_ambiguous_or_credentialed_urls(self):
        for value in ("example/demo", "git@github.com:example/demo", "http://github.com/example/demo",
                      "https://github.com/example/demo?q=secret", "https://github.com/example/demo#x",
                      "https://github.com:443/example/demo", "https://user@github.com/example/demo",
                      "https://github.com/example/demo/issues", "https://github.com/example//demo",
                      "https://github.com/example/%64emo", "https://github.com/example/..",
                      "https://bad..host/o/r", None):
            with self.subTest(value=value), self.assertRaises(InputError):
                normalize_repository(value)


if __name__ == "__main__":
    unittest.main()
