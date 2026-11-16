"""Pre-join lint regressions using explicit CycloneDX and exact mapping fixtures."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "examples/scorecard/lint-mappings"
PURL = "pkg:npm/demo@1.0"
REPO = "https://github.com/example/demo"


class MappingLintTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bom = self.root / "bom.json"
        self.mapping = self.root / "repos.json"
        self.bom.write_bytes((FIXTURE / "bom.json").read_bytes())
        self.mapping.write_bytes((FIXTURE / "repos.json").read_bytes())

    def cli(self, *extra):
        return subprocess.run([sys.executable, "-m", "vulnwrench", "scorecard", "lint-mappings",
                               str(self.bom), "--map", str(self.mapping), *map(str, extra)],
                              cwd=ROOT, capture_output=True, text=True, timeout=120)

    def read_report(self):
        run = self.cli()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stderr, "")
        return json.loads(run.stdout)

    def test_conflicting_fixture_reports_all_issues_without_repository_guesses(self):
        report = self.read_report()
        self.assertEqual(report["summary"], {
            "components": 4, "mappingEntries": 4, "mappedComponents": 1,
            "ambiguousComponents": 1, "unmappedComponents": 2,
            "unusedMappings": 1, "ambiguousMappings": 1,
            "duplicateRepositoryIdentifiers": 1, "duplicateMappings": 0,
        })
        self.assertEqual([row["mappingStatus"] for row in report["components"]],
                         ["ambiguous", "mapped", "unmapped", "missing_purl"])
        self.assertEqual([row["repository"] for row in report["components"]], [None, REPO, None, None])
        issues = {issue["code"]: issue for issue in report["issues"]}
        self.assertEqual(set(issues), {"ambiguous_mapping", "duplicate_repository_identifier",
                                       "unused_mapping", "unmapped_component", "missing_purl"})
        ambiguous = issues["ambiguous_mapping"]
        self.assertEqual(ambiguous["purl"], PURL)
        self.assertEqual(ambiguous["repositories"], [REPO, "https://github.com/example/other"])
        self.assertEqual(ambiguous["locations"], [
            {"file": "repos.json", "pointer": "/pkg:npm~1demo@1.0", "occurrence": 1},
            {"file": "repos.json", "pointer": "/pkg:npm~1demo@1.0", "occurrence": 2},
            {"file": "bom.json", "pointer": "/components/0"},
        ])
        self.assertEqual(issues["duplicate_repository_identifier"]["repository"], REPO)
        self.assertEqual(len(issues["duplicate_repository_identifier"]["locations"]), 3)
        self.assertEqual(issues["unused_mapping"]["purl"], "pkg:npm/demo@2.0")
        self.assertEqual(issues["unmapped_component"]["locations"],
                         [{"file": "bom.json", "pointer": "/components/2"}])
        self.assertTrue(all(issue["message"] for issue in report["issues"]))

    def test_strict_writes_same_complete_report_and_fails_on_ambiguity(self):
        advisory = self.read_report()
        run = self.cli("--strict")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertEqual(json.loads(run.stdout), advisory)
        output = self.root / "lint.json"
        run = self.cli("--strict", "--output", output)
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertEqual(run.stdout, "")
        self.assertEqual(json.loads(output.read_text()), advisory)

    def test_same_canonical_assignment_is_redundant_but_unambiguous(self):
        self.mapping.write_text('{"' + PURL + '": "' + REPO + '", "' + PURL +
                                '": "github.com/EXAMPLE/Demo.git"}')
        run = self.cli("--strict")
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["summary"]["ambiguousMappings"], 0)
        self.assertEqual(report["summary"]["duplicateMappings"], 1)
        self.assertEqual(report["components"][0]["repository"], REPO)
        self.assertIn("duplicate_mapping", [issue["code"] for issue in report["issues"]])

    def test_strict_rejects_ambiguity_even_when_mapping_is_unused(self):
        self.bom.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}')
        run = self.cli("--strict")
        self.assertEqual(run.returncode, 1, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["summary"]["components"], 0)
        self.assertEqual(report["summary"]["unusedMappings"], 3)
        self.assertEqual(report["summary"]["ambiguousMappings"], 1)

    def test_all_inventory_roles_and_exact_purls_have_locations(self):
        purls = [PURL, PURL + "?arch=x86", "pkg:npm/Demo@1.0", "pkg:npm/%64emo@1.0"]
        def component(purl):
            return {"type": "library", "name": "demo", "purl": purl}
        self.bom.write_text(json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [dict(component(purls[0]), components=[component(purls[1])],
                                pedigree={"ancestors": [component(purls[2])]})],
            "metadata": {"component": component(purls[0])},
            "formulation": [{"components": [component(purls[3])]}],
        }))
        self.mapping.write_text(json.dumps({PURL: REPO}))
        report = self.read_report()
        self.assertEqual([row["mappingStatus"] for row in report["components"]],
                         ["mapped", "unmapped", "unmapped", "mapped", "unmapped"])
        self.assertEqual([issue["locations"][0]["pointer"] for issue in report["issues"]], [
            "/components/0/components/0", "/components/0/pedigree/ancestors/0",
            "/formulation/0/components/0",
        ])

    def test_pointer_escaping_and_duplicate_identical_repository_identifiers(self):
        purl = "pkg:generic/a~b@1"
        self.mapping.write_text(json.dumps({purl: REPO, PURL: REPO}))
        report = self.read_report()
        unused = next(issue for issue in report["issues"] if issue["code"] == "unused_mapping")
        self.assertEqual(unused["locations"], [
            {"file": "repos.json", "pointer": "/pkg:generic~1a~0b@1", "occurrence": 1}])
        self.assertEqual(report["summary"]["duplicateRepositoryIdentifiers"], 1)

    def test_invalid_mapping_or_bom_is_fatal_and_preserves_output(self):
        output = self.root / "out.json"
        output.write_text("previous")
        for raw in ('[]', '{', '{"not-purl": "https://github.com/example/demo"}',
                    '{"pkg:npm/demo@1.0": "https://user:SECRET@github.com/example/demo"}',
                    '{"pkg:npm/demo@1.0": ["https://github.com/example/demo"]}',
                    '{"pkg:npm/demo@1.0": {"SECRET":1,"SECRET":2}}',
                    '{"pkg:npm/demo@1.0": "\\ud800"}', '{"pkg:npm/demo@1.0": NaN}'):
            with self.subTest(raw=raw):
                self.mapping.write_text(raw)
                run = self.cli("--output", output)
                self.assertEqual(run.returncode, 2)
                self.assertEqual(run.stdout, "")
                self.assertNotIn("SECRET", run.stderr)
                self.assertNotIn("Traceback", run.stderr)
                self.assertEqual(output.read_text(), "previous")
        self.mapping.write_text('{}')
        self.bom.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"version":2}')
        self.assertEqual(self.cli("--output", output).returncode, 2)
        self.assertEqual(output.read_text(), "previous")

    def test_lint_output_cannot_replace_inputs_or_aliases(self):
        for source in (self.bom, self.mapping):
            before = source.read_bytes()
            self.assertEqual(self.cli("--output", source).returncode, 2)
            self.assertEqual(source.read_bytes(), before)
        alias = self.root / "alias.json"
        os.link(self.mapping, alias)
        self.assertEqual(self.cli("--output", alias).returncode, 2)
        alias.unlink()
        alias.symlink_to(self.bom)
        self.assertEqual(self.cli("--output", alias).returncode, 2)

    def test_library_matches_deterministic_cli(self):
        from vulnwrench.scorecard import lint_mappings
        report = self.read_report()
        self.assertEqual(lint_mappings(self.bom, self.mapping), report)
        self.assertEqual(self.read_report(), report)

    def test_coverage_gate_exit_matrix_and_report_invariance(self):
        component = {"type": "library", "name": "demo", "purl": PURL}
        ambiguous = ('{"' + PURL + '":"' + REPO + '","' + PURL +
                     '":"https://github.com/example/other"}')
        # Expected statuses and exit codes are literal contracts, not computed
        # from the report: advisory, strict, coverage, combined.
        cases = [
            ("mapped_with_warnings", [component],
             '{"' + PURL + '":"' + REPO + '","' + PURL + '":"github.com/EXAMPLE/Demo.git",'
             '"pkg:npm/unused@1":"' + REPO + '"}', ["mapped"], (0, 0, 0, 0)),
            ("unmapped_exact_version", [dict(component, purl="pkg:npm/demo@2.0")],
             json.dumps({PURL: REPO}), ["unmapped"], (0, 0, 1, 1)),
            ("missing_purl", [{"type": "file", "name": "local"}],
             '{}', ["missing_purl"], (0, 0, 1, 1)),
            ("ambiguity_only", [component], ambiguous, ["ambiguous"], (0, 1, 0, 1)),
            ("both", [component, {"type": "file", "name": "local"}],
             ambiguous, ["ambiguous", "missing_purl"], (0, 1, 1, 1)),
            ("empty", [], '{}', [], (0, 0, 0, 0)),
            ("empty_unused_conflict", [], ambiguous, [], (0, 1, 0, 1)),
        ]
        flags = [(), ("--strict",), ("--fail-on-unmapped",),
                 ("--strict", "--fail-on-unmapped")]
        for name, components, mapping, statuses, codes in cases:
            self.bom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6",
                                            "version": 1, "components": components}))
            self.mapping.write_text(mapping)
            advisory = self.cli()
            self.assertEqual(advisory.returncode, 0, advisory.stderr)
            self.assertEqual([row["mappingStatus"] for row in json.loads(advisory.stdout)["components"]],
                             statuses)
            for arguments, code in zip(flags, codes):
                with self.subTest(case=name, flags=arguments):
                    run = self.cli(*arguments)
                    self.assertEqual(run.returncode, code, run.stderr)
                    self.assertEqual(run.stderr, "")
                    self.assertEqual(run.stdout, advisory.stdout)

    def test_coverage_gate_retains_all_component_occurrences_and_roles(self):
        mapped = {"type": "library", "name": "demo", "purl": PURL}
        missing = {"type": "file", "name": "local"}
        unmapped = dict(mapped, purl="pkg:npm/demo@2.0")
        self.bom.write_text(json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [dict(mapped, components=[unmapped], pedigree={"ancestors": [missing]}),
                           unmapped],
            "metadata": {"component": missing},
            "formulation": [{"components": [unmapped]}],
        }))
        self.mapping.write_text(json.dumps({PURL: REPO}))
        run = self.cli("--fail-on-unmapped")
        self.assertEqual(run.returncode, 1, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["summary"]["components"], 6)
        self.assertEqual(report["summary"]["unmappedComponents"], 5)
        self.assertEqual([row["path"] for row in report["components"]], [
            "/components/0", "/components/0/components/0", "/components/0/pedigree/ancestors/0",
            "/components/1", "/metadata/component", "/formulation/0/components/0",
        ])
        self.assertEqual([row["mappingStatus"] for row in report["components"]],
                         ["mapped", "unmapped", "missing_purl", "unmapped", "missing_purl", "unmapped"])

    def test_coverage_gate_writes_complete_report_on_failure(self):
        expected = (FIXTURE / "expected.json").read_bytes()
        for flags in [("--fail-on-unmapped",), ("--fail-on-unmapped", "--strict")]:
            with self.subTest(flags=flags):
                output = self.root / "coverage.json"
                output.write_text("previous report")
                run = self.cli(*flags, "--output", output)
                self.assertEqual(run.returncode, 1, run.stderr)
                self.assertEqual(run.stdout, "")
                self.assertEqual(run.stderr, "")
                self.assertEqual(output.read_bytes(), expected)

    def test_coverage_gate_invalid_inputs_preserve_output(self):
        output = self.root / "coverage.json"
        output.write_text("previous report")
        bom_bytes = self.bom.read_bytes()
        map_bytes = self.mapping.read_bytes()
        for target, raw in [(self.mapping, '{'), (self.bom, '{"bomFormat":"SPDX"}'),
                            (self.mapping, '{"pkg:npm/demo@1.0":"https://SECRET@github.com/a/b"}')]:
            for flags in [("--fail-on-unmapped",), ("--strict", "--fail-on-unmapped")]:
                with self.subTest(input=target.name, raw=raw, flags=flags):
                    self.bom.write_bytes(bom_bytes)
                    self.mapping.write_bytes(map_bytes)
                    target.write_text(raw)
                    run = self.cli(*flags, "--output", output)
                    self.assertEqual(run.returncode, 2)
                    self.assertEqual(run.stdout, "")
                    self.assertIn("vulnwrench scorecard:", run.stderr)
                    self.assertNotIn("SECRET", run.stderr)
                    self.assertNotIn("Traceback", run.stderr)
                    self.assertNotIn("invalid command-line arguments", run.stderr)
                    self.assertEqual(output.read_text(), "previous report")

    def test_coverage_gate_output_errors_take_precedence(self):
        alias = self.root / "alias.json"
        os.link(self.mapping, alias)
        symlink = self.root / "symlink.json"
        symlink.symlink_to(self.bom)
        bom_bytes = self.bom.read_bytes()
        map_bytes = self.mapping.read_bytes()
        outputs = [self.bom, self.mapping, alias, symlink, self.root / "absent" / "out.json"]
        for output in outputs:
            with self.subTest(output=output):
                run = self.cli("--fail-on-unmapped", "--strict", "--output", output)
                self.assertEqual(run.returncode, 2)
                self.assertEqual(run.stdout, "")
                self.assertIn("vulnwrench scorecard:", run.stderr)
                self.assertNotIn("invalid command-line arguments", run.stderr)
                self.assertNotIn("Traceback", run.stderr)
                self.assertEqual(self.bom.read_bytes(), bom_bytes)
                self.assertEqual(self.mapping.read_bytes(), map_bytes)
        self.assertTrue(symlink.is_symlink())
        self.assertEqual(alias.read_bytes(), map_bytes)

    def test_coverage_flag_rejects_arguments_and_is_lint_only(self):
        for arguments in [("--fail-on-unmapped=false",), ("--fail-on-unmapped", "yes")]:
            with self.subTest(arguments=arguments):
                run = self.cli(*arguments)
                self.assertEqual(run.returncode, 2)
                self.assertEqual(run.stdout, "")
        for command in ("check", "compare", "lint-mappings"):
            run = subprocess.run([sys.executable, "-m", "vulnwrench", "scorecard", command, "--help"],
                                 cwd=ROOT, capture_output=True, text=True, timeout=120)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual("--fail-on-unmapped" in run.stdout, command == "lint-mappings")


if __name__ == "__main__":
    unittest.main()
