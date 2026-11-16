"""Literal Markdown contracts and format-independent lint gate/error behavior."""

import contextlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulnwrench.scorecard.cli import main

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "examples/scorecard/lint-mappings"
PURL = "pkg:npm/demo@1.0"
REPO = "https://github.com/example/demo"
FLAGS = [(), ("--strict",), ("--fail-on-unmapped",), ("--strict", "--fail-on-unmapped")]


def evidence(markdown):
    match = re.search(r"(?m)^(`{3,})json\n([\s\S]*)\n\1\n\Z", markdown)
    if match is None:
        raise AssertionError("missing complete fenced JSON appendix")
    return json.loads(match[2])


class MappingLintMarkdownTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bom = self.root / "bom.json"
        self.mapping = self.root / "repos.json"
        self.bom.write_bytes((FIXTURE / "bom.json").read_bytes())
        self.mapping.write_bytes((FIXTURE / "repos.json").read_bytes())

    def args(self, *extra):
        return ["lint-mappings", str(self.bom), "--map", str(self.mapping), *map(str, extra)]

    def cli(self, *extra):
        return subprocess.run([sys.executable, "-m", "vulnwrench", "scorecard", *self.args(*extra)],
                              cwd=ROOT, capture_output=True, text=True, timeout=120)

    def test_markdown_literal_fixture_stdout_file_and_default_json_bytes(self):
        expected = (FIXTURE / "expected.md").read_text()
        expected_json = (FIXTURE / "expected.json").read_text()
        self.assertEqual(self.cli().stdout, expected_json)
        self.assertEqual(self.cli("--format", "json").stdout, expected_json)
        for flags, code in zip(FLAGS, (0, 1, 1, 1)):
            with self.subTest(flags=flags):
                run = self.cli("--format", "markdown", *flags)
                self.assertEqual(run.returncode, code, run.stderr)
                self.assertEqual(run.stderr, "")
                self.assertEqual(run.stdout, expected)
                self.assertEqual(evidence(run.stdout), json.loads(expected_json))
                output = self.root / "report.md"
                output.write_text("previous")
                run = self.cli("--format", "markdown", *flags, "--output", output)
                self.assertEqual(run.returncode, code, run.stderr)
                self.assertEqual(run.stdout, "")
                self.assertEqual(run.stderr, "")
                self.assertEqual(output.read_text(), expected)

    def test_markdown_and_json_gate_matrix_including_empty_and_ambiguity_only(self):
        component = {"type": "library", "name": "demo", "purl": PURL}
        ambiguous = '{"' + PURL + '":"' + REPO + '","' + PURL + '":"https://github.com/example/other"}'
        cases = [
            ("fully_mapped", [component], json.dumps({PURL: REPO}), ["mapped"], (0, 0, 0, 0)),
            ("mapped_warnings", [component], '{"' + PURL + '":"' + REPO + '","' + PURL +
             '":"github.com/EXAMPLE/Demo.git","pkg:npm/unused@1":"' + REPO + '"}',
             ["mapped"], (0, 0, 0, 0)),
            ("unmapped", [dict(component, purl=PURL + "1")], '{}', ["unmapped"], (0, 0, 1, 1)),
            ("missing", [{"type": "file", "name": "local"}], '{}', ["missing_purl"], (0, 0, 1, 1)),
            ("ambiguity_only", [component], ambiguous, ["ambiguous"], (0, 1, 0, 1)),
            ("both", [component, {"type": "file", "name": "local"}], ambiguous,
             ["ambiguous", "missing_purl"], (0, 1, 1, 1)),
            ("empty", [], '{}', [], (0, 0, 0, 0)),
            ("empty_unused_conflict", [], ambiguous, [], (0, 1, 0, 1)),
        ]
        for name, components, mapping, statuses, codes in cases:
            self.bom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6",
                                           "version": 1, "components": components}))
            self.mapping.write_text(mapping)
            json_report = self.cli()
            self.assertEqual(json_report.returncode, 0, json_report.stderr)
            report = json.loads(json_report.stdout)
            self.assertEqual([row["mappingStatus"] for row in report["components"]], statuses)
            markdown = None
            for flags, code in zip(FLAGS, codes):
                for format in ("json", "markdown"):
                    with self.subTest(case=name, flags=flags, format=format):
                        run = self.cli("--format", format, *flags)
                        self.assertEqual(run.returncode, code, run.stderr)
                        self.assertEqual(run.stderr, "")
                        if format == "json":
                            self.assertEqual(run.stdout, json_report.stdout)
                        else:
                            self.assertEqual(evidence(run.stdout), report)
                            if markdown is None:
                                markdown = run.stdout
                            self.assertEqual(run.stdout, markdown)
                            if name in ("fully_mapped", "empty"):
                                self.assertIn("\nNo issues.\n", run.stdout)

    def test_markdown_escapes_supplied_text_and_retains_lossless_evidence(self):
        self.bom = self.root / 'bom|[x]`\n.json'
        self.mapping = self.root / 'repos|[x]`\n.json'
        name = '<img src=x>|[click](url)*_`\\\u2028next\u2029line end & "é" ~~'
        purl = 'pkg:generic/a~b|[x]_*````\\@1'
        repo = 'https://code.example/Owner_Name/Repo~Name'
        self.bom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                                       "components": [{"type": "library", "name": name, "purl": purl}]}))
        # Conflicting repeated entries exercise both occurrences and both repositories.
        self.mapping.write_text('{'+json.dumps(purl)+':'+json.dumps(repo)+','+
                                json.dumps(purl)+':"https://code.example/Other/Repo"}')
        advisory = self.cli()
        self.assertEqual(advisory.returncode, 0, advisory.stderr)
        report = json.loads(advisory.stdout)
        run = self.cli("--format", "markdown", "--strict")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertEqual(run.stderr, "")
        self.assertEqual(evidence(run.stdout), report)
        human, appendix = run.stdout.split("## Evidence\n", 1)
        self.assertIn('&lt;img src=x&gt;&#124;&#91;click&#93;&#40;url&#41;&#42;&#95;&#96;&#92; next line end &amp; &quot;é&quot; &#126;&#126;', human)
        self.assertIn('pkg:generic/a&#126;b&#124;&#91;x&#93;&#95;&#42;&#96;&#96;&#96;&#96;&#92;@1', human)
        self.assertIn('https://code.example/Owner&#95;Name/Repo&#126;Name', human)
        self.assertIn('repos&#124;&#91;x&#93;&#96; .json | /pkg:generic&#126;1a&#126;0b&#124;&#91;x&#93;&#95;&#42;&#96;&#96;&#96;&#96;&#92;@1 | 2 |', human)
        self.assertIn('bom&#124;&#91;x&#93;&#96; .json | /components/0 |', human)
        self.assertNotIn('<img', run.stdout)
        self.assertNotIn('[click]', human)
        self.assertNotIn('````', human)
        self.assertIn('\n`````json\n', appendix)
        self.assertIn('\\u003cimg', appendix)
        self.assertIn('\\u0026', appendix)
        # Each supplied line-break/pipe stays within one table row with fixed columns.
        table_rows = [line for line in human.splitlines() if line.startswith('| ')]
        self.assertEqual([line.count('|') for line in table_rows], [7] * 3 + [8] * 5)
        self.assertEqual(report['components'][0]['name'], name)
        self.assertEqual([entry['location']['occurrence'] for entry in report['mappings']], [1, 2])

    def test_markdown_retains_all_component_occurrences_and_roles(self):
        mapped = {"type": "library", "name": "demo", "purl": PURL}
        missing = {"type": "file", "name": "local"}
        self.bom.write_text(json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [dict(mapped, components=[dict(mapped, purl=PURL+'1')],
                                pedigree={"ancestors": [missing]}), mapped],
            "metadata": {"component": missing}, "formulation": [{"components": [mapped]}],
        }))
        self.mapping.write_text(json.dumps({PURL: REPO}))
        run = self.cli("--format", "markdown", "--fail-on-unmapped")
        self.assertEqual(run.returncode, 1, run.stderr)
        report = evidence(run.stdout)
        self.assertEqual([row['mappingStatus'] for row in report['components']],
                         ['mapped', 'unmapped', 'missing_purl', 'mapped', 'missing_purl', 'mapped'])
        table = run.stdout.split('## Components\n', 1)[1].split('## Issues\n', 1)[0]
        for path in ('/components/0', '/components/0/components/0', '/components/0/pedigree/ancestors/0',
                     '/components/1', '/metadata/component', '/formulation/0/components/0'):
            self.assertIn(' | '+path+' |\n', table)
        self.assertEqual(len([line for line in table.splitlines() if line.startswith('| ')]), 8)
        self.assertEqual(report, json.loads(self.cli().stdout))

    def test_markdown_invalid_inputs_and_format_preserve_existing_output(self):
        output = self.root / "out.md"
        output.write_text("previous")
        bom_bytes, map_bytes = self.bom.read_bytes(), self.mapping.read_bytes()
        cases = [(self.mapping, '{'), (self.mapping, '[]'), (self.bom, '{"bomFormat":"SPDX"}'),
                 (self.mapping, '{"bad-purl":"https://github.com/example/demo"}'),
                 (self.mapping, '{"pkg:npm/demo@1.0":"https://SECRET@github.com/a/b"}'),
                 (self.bom, '{"bomFormat":"CycloneDX","version":1,"version":2}'),
                 (self.mapping, '{"pkg:npm/demo@1.0":NaN}')]
        for target, raw in cases:
            for format in ("json", "markdown"):
                with self.subTest(input=target.name, raw=raw, format=format):
                    self.bom.write_bytes(bom_bytes)
                    self.mapping.write_bytes(map_bytes)
                    target.write_text(raw)
                    run = self.cli("--format", format, "--strict", "--fail-on-unmapped", "--output", output)
                    self.assertEqual(run.returncode, 2)
                    self.assertEqual(run.stdout, "")
                    self.assertIn('vulnwrench scorecard:', run.stderr)
                    self.assertNotIn('invalid command-line arguments', run.stderr)
                    self.assertNotIn('SECRET', run.stderr)
                    self.assertNotIn('Traceback', run.stderr)
                    self.assertEqual(output.read_text(), "previous")
        run = self.cli("--format", "html", "--output", output)
        self.assertEqual(run.returncode, 2)
        self.assertEqual(run.stdout, "")
        self.assertIn('invalid command-line arguments', run.stderr)
        self.assertEqual(output.read_text(), "previous")

    def test_markdown_protected_and_failed_writes_override_gate_and_preserve_output(self):
        alias = self.root / "alias.json"
        os.link(self.mapping, alias)
        symlink = self.root / "symlink.json"
        symlink.symlink_to(self.bom)
        directory = self.root / "directory"
        directory.mkdir()
        sentinel = directory / "sentinel"
        sentinel.write_text("previous")
        bom_bytes, map_bytes = self.bom.read_bytes(), self.mapping.read_bytes()
        for format in ("json", "markdown"):
            for output in (self.bom, self.mapping, alias, symlink, directory, self.root / 'absent/out.md'):
                with self.subTest(format=format, output=output.name):
                    run = self.cli("--format", format, "--strict", "--fail-on-unmapped", "--output", output)
                    self.assertEqual(run.returncode, 2)
                    self.assertEqual(run.stdout, "")
                    self.assertIn('vulnwrench scorecard:', run.stderr)
                    self.assertNotIn('invalid command-line arguments', run.stderr)
                    self.assertNotIn('Traceback', run.stderr)
                    self.assertEqual(self.bom.read_bytes(), bom_bytes)
                    self.assertEqual(self.mapping.read_bytes(), map_bytes)
                    self.assertEqual(alias.read_bytes(), map_bytes)
                    self.assertTrue(symlink.is_symlink())
                    self.assertEqual(sentinel.read_text(), 'previous')
            output = self.root / 'out.md'
            output.write_text('previous')
            for operation in ('os.replace', 'tempfile.NamedTemporaryFile'):
                with self.subTest(format=format, failure=operation):
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with patch('vulnwrench.scorecard.cli.'+operation, side_effect=OSError('SECRET')), \
                            contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        code = main(self.args('--format', format, '--strict', '--fail-on-unmapped', '--output', output))
                    self.assertEqual(code, 2)
                    self.assertEqual(stdout.getvalue(), '')
                    self.assertIn('cannot write output file', stderr.getvalue())
                    self.assertNotIn('SECRET', stderr.getvalue())
                    self.assertEqual(output.read_text(), 'previous')
                    self.assertEqual(list(self.root.glob('.scorecard-join-*')), [])


if __name__ == '__main__':
    unittest.main()
