"""Saved-report contracts: validate the whole evidence graph before selecting."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import vulnwrench.fuse as vf

ROOT = Path(__file__).resolve().parents[2]
SAVED = ROOT / 'examples/fuse/explain/merged.json'
DANGLING = ROOT / 'examples/fuse/explain/dangling-alias.json'
API = 'pkg:npm/demo@1.0#apps/api'
SELECT = ['--advisory', 'OSV-EXPLAIN-1', '--package', API]


def cli(*args):
    return subprocess.run([sys.executable, '-m', 'vulnwrench', 'fuse', *map(str, args)], cwd=ROOT,
                          text=True, capture_output=True, timeout=60)


class SavedExplainTests(unittest.TestCase):
    def test_saved_report_matches_scanner_explanation(self):
        result = cli('explain', '--merged', SAVED, *SELECT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, (ROOT / 'examples/fuse/expected/explanation.json').read_text())
        by_id = cli('explain', '--merged', SAVED, '--finding', json.loads(result.stdout)['finding']['findingId'])
        self.assertEqual(by_id.stdout, result.stdout)
        self.assertEqual(by_id.returncode, 0, by_id.stderr)

    def assert_rejected(self, source, output, *selectors):
        output.write_text('sentinel')
        failed = cli('explain', '--merged', source, *(selectors or SELECT), '--output', output)
        self.assertEqual(failed.returncode, 2, failed.stderr)
        self.assertEqual(failed.stdout, '')
        self.assertEqual(output.read_text(), 'sentinel')
        self.assertNotIn('Traceback', failed.stderr)
        self.assertNotIn('synthetic-secret', failed.stderr)
        return failed

    def test_dangling_alias_fixture_rejected_before_selection(self):
        with tempfile.TemporaryDirectory() as td:
            failed = self.assert_rejected(DANGLING, Path(td) / 'output.json', '--finding', 'missing')
            self.assertIn('merged:', failed.stderr)
            self.assertNotIn('no finding', failed.stderr)

    def test_complete_graph_and_derived_fields_are_validated(self):
        original = json.loads(SAVED.read_text())
        mutations = [
            lambda d: d['inputs'][0].update(sourceId='s9999'),
            lambda d: d['inputs'].append(deepcopy(d['inputs'][0])),
            lambda d: d['findings'][0]['observations'][0].update(sourceId='s9999'),
            lambda d: d['findings'][0]['observations'][0].update(observationId='synthetic-secret'),
            lambda d: d['findings'][0]['observations'][0].update(pointer='/missing'),
            lambda d: d['findings'][0].update(ids=['synthetic-secret']),
            lambda d: d['findings'][0].update(fixVersions=['999']),
            lambda d: d['findings'][-1]['observations'].clear(),  # outside selected finding
            lambda d: d['aliasEdges'][0].update(to='synthetic-secret'),
            lambda d: d['aliasEdges'][0].update(basis='synthetic-secret'),
            lambda d: d['aliasEdges'].clear(),
            lambda d: d.update(observationCount=True),  # bool is not an integer count
            lambda d: d.update(coverageAssessment={'status': 'comparable', 'reasonCodes': []}),
            lambda d: d['inputs'][0]['rawReport'].clear(),
            lambda d: d['inputs'][0].update(sha256='synthetic-secret'),
            lambda d: d['inputs'][0].update(byteCount=True),
            lambda d: d['inputs'][0].update(digestKind='synthetic-secret'),
            lambda d: d.update(toolVersion='unsupported'),
            lambda d: d.update(schemaVersion='vulnfuse-explain-1'),
            lambda d: d.update(extra='unsupported'),
            lambda d: d.update(inputs=None),
            lambda d: d.update(inputs=[None]),
            lambda d: d['inputs'][0].update(input=None),
            lambda d: d['inputs'][0].update(scanner=[]),
            lambda d: d.update(coverageManifest=[]),
        ]
        with tempfile.TemporaryDirectory() as td:
            source, output = Path(td) / 'source.json', Path(td) / 'output.json'
            for i, mutate in enumerate(mutations):
                with self.subTest(mutation=i):
                    doc = deepcopy(original)
                    mutate(doc)
                    source.write_text(vf.dumps(doc))
                    self.assert_rejected(source, output)
                    with self.assertRaises(vf.InputError):
                        vf.read_merged(source)

    def test_strict_json_roots_and_size_limit(self):
        invalid = ['null', '[]', '{}', '{', '{"schemaVersion":1,"schemaVersion":2}',
                   '{"value":NaN}', '{"value":1e9999}', '"synthetic-secret"']
        with tempfile.TemporaryDirectory() as td:
            source, output = Path(td) / 'source.json', Path(td) / 'output.json'
            for raw in invalid:
                with self.subTest(raw=raw):
                    source.write_text(raw)
                    self.assert_rejected(source, output)
            source.write_bytes(b'\xff')
            self.assert_rejected(source, output)
            source.write_bytes(b' ' * (32 * 1024 * 1024 + 1))
            self.assert_rejected(source, output)
            self.assert_rejected(Path(td) / 'missing', output)

    def test_modes_selectors_and_output_alias_protection(self):
        with tempfile.TemporaryDirectory() as td:
            source, output = Path(td) / 'source.json', Path(td) / 'output.json'
            source.write_bytes(SAVED.read_bytes())
            for extras in [['--trivy', 'examples/fuse/trivy.json'], ['--coverage-manifest', 'examples/fuse/coverage.json'],
                           ['--markdown', output]]:
                self.assert_rejected(source, output, *SELECT, *extras)
            for selectors in [['--advisory', 'OSV-EXPLAIN-1'], ['--finding', 'missing'],
                              ['--finding', 'f0001', '--package', API]]:
                self.assert_rejected(source, output, *selectors)
            hard, sym = Path(td) / 'hard', Path(td) / 'sym'
            hard.hardlink_to(source)
            sym.symlink_to(source)
            for destination in (source, hard, sym):
                result = cli('explain', '--merged', source, *SELECT, '--output', destination)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(source.read_bytes(), SAVED.read_bytes())
            self.assertEqual(cli('merge', '--merged', source).returncode, 2)

    def test_library_roundtrip_empty_unknown_repeated_and_canonical_digests(self):
        cases = [vf.merge_reports([vf.Report.from_document('trivy', {'Results': []})]),
                 vf.merge_reports([vf.Report.from_document('trivy', {'Results': [{'Type': 'unknown', 'Vulnerabilities': [
                     {'VulnerabilityID': 'A', 'PkgName': 'demo', 'InstalledVersion': '1'}]}]})] * 2)]
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / 'saved.json'
            for merged in cases:
                source.write_text(vf.dumps(merged))
                restored = vf.read_merged(source)
                self.assertEqual(restored, merged)
                for finding in merged['findings']:
                    self.assertEqual(vf.explain_finding(restored, finding_id=finding['findingId']),
                                     vf.explain_finding(merged, finding_id=finding['findingId']))
                merged['inputs'][0]['sha256'] = '0' * 64
                source.write_text(vf.dumps(merged))
                with self.assertRaises(vf.InputError):
                    vf.read_merged(source)

    def test_original_input_names_are_preserved_without_reopening(self):
        with tempfile.TemporaryDirectory() as td:
            original = Path(td) / ' report with spaces.json '
            original.write_text('{"Results":[]}')
            saved = Path(td) / 'saved.json'
            merged = vf.merge_reports([vf.read_report('trivy', original)])
            saved.write_text(vf.dumps(merged))
            original.unlink()
            self.assertEqual(vf.read_merged(saved), merged)

    def test_coverage_manifest_is_reconstructed_and_validated(self):
        found = vf.Report.from_document('trivy', {'Results': [{'Type': 'npm', 'Vulnerabilities': [
            {'VulnerabilityID': 'A', 'PkgName': 'demo', 'InstalledVersion': '1'}]}]}, 'found')
        absent = vf.Report.from_document('trivy', {'Results': []}, 'absent')
        manifest = vf.CoverageManifest.from_document({'schemaVersion': 'vulnfuse-coverage-1', 'inputs': [
            {'scanner': 'trivy', 'input': r.input_name, 'sha256': r.sha256, 'targetIdentity': 'target',
             'scanComplete': True, 'databaseTimestamp': '2026-11-10T00:00:00Z', 'scanPolicyIdentity': p,
             'databaseIdentity': 'synthetic:snapshot:common'}
            for r, p in [(found, 'none'), (absent, 'suppress:A')]]})
        merged = vf.merge_reports([found, absent], coverage_manifest=manifest)
        with tempfile.TemporaryDirectory() as td:
            source, output = Path(td) / 'saved.json', Path(td) / 'output.json'
            source.write_text(vf.dumps(merged))
            loaded = vf.read_merged(source)
            self.assertEqual(loaded, merged)
            self.assertEqual(loaded['coverageAssessment']['reasonCodes'], ['scan-policy-mismatch'])
            for mutate in [lambda d: d['inputs'][0]['coverage'].update(manifestPointer='/inputs/999'),
                           lambda d: d['coverageManifest']['rawManifest']['inputs'][0].update(sha256='0' * 64),
                           lambda d: d['coverageManifest'].update(sha256='0' * 64),
                           lambda d: d['coverageManifest'].update(byteCount=False)]:
                doc = deepcopy(merged)
                mutate(doc)
                source.write_text(vf.dumps(doc))
                self.assert_rejected(source, output, '--advisory', 'A')

    def test_installed_saved_explain_without_original_files(self):
        with tempfile.TemporaryDirectory() as td:
            saved, bad, output = (Path(td) / n for n in ('saved.json', 'dangling.json', 'output.json'))
            saved.write_bytes(SAVED.read_bytes())
            bad.write_bytes(DANGLING.read_bytes())
            command = [sys.executable, '-m', 'vulnwrench', 'fuse', 'explain', '--merged', str(saved), *SELECT, '--output', str(output)]
            first = subprocess.run(command, cwd=td, text=True, capture_output=True, timeout=60)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(first.stdout, '')
            self.assertEqual(output.read_text(), (ROOT / 'examples/fuse/expected/explanation.json').read_text())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            expected = output.read_bytes()
            second = subprocess.run(command, cwd=td, text=True, capture_output=True, timeout=60)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(output.read_bytes(), expected)
            command[command.index('--merged') + 1] = str(bad)
            failed = subprocess.run(command, cwd=td, text=True, capture_output=True, timeout=60)
            self.assertEqual(failed.returncode, 2)
            self.assertEqual(failed.stdout, '')
            self.assertEqual(output.read_bytes(), expected)


if __name__ == '__main__':
    unittest.main()
