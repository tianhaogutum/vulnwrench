"""Compact coverage validation retains binding semantics without exposing evidence."""

from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import vulnwrench.fuse as vf
from .test_core import grype, osv, trivy, tv
from .test_coverage import manifest_document
from .test_saved_explain import cli


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def provenance(path):
    raw = path.read_bytes()
    return {'sha256': digest(raw), 'byteCount': len(raw), 'digestKind': 'file-bytes'}


class ValidateCoverageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.inputs = []
        for scanner, doc in [('trivy', trivy([tv('A')])), ('grype', {'matches': []}),
                             ('osv', osv([{'id': 'A', 'aliases': ['B']}, {'id': 'B'}]))]:
            doc['synthetic-secret'] = 'private evidence'
            path = self.base / ('synthetic-secret-' + scanner + '.json')
            path.write_text(vf.dumps(doc), encoding='utf-8')
            self.inputs.append((scanner, str(path)))
        self.manifest, self.output = self.base / 'synthetic-secret-coverage.json', self.base / 'output.json'
        self.write_manifest()

    def write_manifest(self, doc=None):
        if doc is None:
            doc = manifest_document([vf.read_report(s, p) for s, p in self.inputs])
        self.manifest.write_text(vf.dumps(doc), encoding='utf-8')
        return doc

    def args(self):
        return ['validate-coverage', '--coverage-manifest', self.manifest,
                *[v for s, p in self.inputs for v in ('--' + s, p)]]

    def pins(self):
        return [(s, p, digest(Path(p).read_bytes())) for s, p in self.inputs]

    def pin_args(self):
        return ['--coverage-manifest-sha256', digest(self.manifest.read_bytes()),
                *[v for pin in self.pins() for v in ('--expect-input-sha256', *pin)]]

    def api(self, **kwargs):
        return vf.validate_coverage(self.inputs, coverage_manifest=self.manifest, **kwargs)

    def assert_rejected(self, args):
        sentinel = b'private sentinel\x00\xff'
        for exists in (True, False):
            if exists:
                self.output.write_bytes(sentinel)
            elif self.output.exists():
                self.output.unlink()
            result = cli(*args, '--output', self.output)
            self.assertEqual((result.returncode, result.stdout), (2, ''), result.stderr)
            self.assertTrue(result.stderr.startswith('vulnwrench fuse: '))
            for secret in ('Traceback', 'synthetic-secret', str(self.base), '0' * 64):
                self.assertNotIn(secret, result.stderr)
            if exists:
                self.assertEqual(self.output.read_bytes(), sentinel)
            else:
                self.assertFalse(self.output.exists())
        return result

    def test_complete_bindings_exact_summary_and_determinism(self):
        expected = {
            'schemaVersion': 'vulnfuse-coverage-validation-1',
            'validation': 'profile-and-bindings-valid',
            'coverageManifest': provenance(self.manifest),
            'inputCount': 3, 'declarationCount': 3, 'declaredInputCount': 3, 'undeclaredInputCount': 0,
            'observationCount': 3, 'findingCount': 1,
            'coverageAssessment': {'status': 'comparable', 'reasonCodes': []},
            'canEstablishFixed': False,
            'inputs': [
                {'sourceId': f's{i:04d}', 'scanner': s, **provenance(Path(p)),
                 'observationCount': {'grype': 0, 'osv': 2, 'trivy': 1}[s],
                 'coverage': {'status': 'declared', 'reasonCodes': [],
                              'manifestPointer': f'/inputs/{self.inputs.index((s, p))}'}}
                for i, (s, p) in enumerate(sorted(self.inputs), 1)],
        }
        result = cli(*self.args())
        self.assertEqual((result.returncode, result.stderr), (0, ''), result.stderr)
        self.assertEqual(result.stdout, vf.dumps(expected))
        for extra in ([], self.pin_args(), self.pin_args()[:2], self.pin_args()[2:6]):
            self.assertEqual(cli(*self.args(), *extra).stdout, result.stdout)
        self.assertEqual(self.api(), expected)
        self.assertEqual(self.api(coverage_manifest_sha256=digest(self.manifest.read_bytes()),
                                  expect_input_sha256=self.pins()), expected)
        self.assertEqual(vf.validate_coverage(reversed(self.inputs), coverage_manifest=self.manifest), expected)
        for secret in ('synthetic-secret', str(self.base), 'rawReport', 'rawManifest', 'targetIdentity', 'private evidence'):
            self.assertNotIn(secret, result.stdout)
        written = cli(*self.args(), '--output', self.output)
        self.assertEqual((written.returncode, written.stdout, written.stderr), (0, '', ''))
        self.assertEqual(self.output.read_text(), result.stdout)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_partial_empty_and_repeated_declarations_count_occurrences(self):
        full = json.loads(self.manifest.read_text())
        for entries, declared, reasons in [
            (full['inputs'][:1], 2, ['manifest-entry-missing']),
            ([], 0, ['manifest-entry-missing']),
            ([{k: e[k] for k in ('scanner', 'input', 'sha256')} for e in full['inputs']], 4,
             ['database-identity-missing', 'database-timestamp-missing', 'scan-completion-unknown',
              'scan-policy-identity-missing', 'target-identity-missing']),
            (full['inputs'], 4, []),
        ]:
            # One entry and one expectation bind both repeated occurrences.
            self.inputs = self.inputs[:3] + [self.inputs[0]]
            self.write_manifest({'schemaVersion': 'vulnfuse-coverage-1', 'inputs': entries})
            pins = list(dict.fromkeys(self.pins()))
            result = self.api(expect_input_sha256=pins)
            self.assertEqual((result['inputCount'], result['declarationCount'], result['declaredInputCount'],
                              result['undeclaredInputCount'], result['observationCount'], result['findingCount']),
                             (4, len(entries), declared, 4 - declared, 4, 1))
            self.assertEqual(result['coverageAssessment'],
                             {'status': 'unknown' if reasons else 'comparable', 'reasonCodes': reasons})
            self.assertFalse(result['canEstablishFixed'])
            self.assertEqual(cli(*self.args()).stdout, vf.dumps(result))
            self.assertEqual(vf.validate_coverage(reversed(self.inputs), coverage_manifest=self.manifest), result)
            self.assertEqual(sum(s['coverage']['manifestPointer'] is not None for s in result['inputs']), declared)

    def test_empty_and_nonempty_profiles_all_scanners_keep_existing_reason_codes(self):
        for empty in (True, False):
            for s, p in self.inputs:
                document = ({'trivy': {'Results': None}, 'grype': {'matches': []},
                             'osv': {'results': [{'packages': []}]}}[s] if empty else
                            {'trivy': trivy([tv(), tv()]), 'grype': grype('CVE-DEMO'),
                             'osv': osv([{'id': 'CVE-DEMO'}])}[s])
                Path(p).write_text(vf.dumps(document))
            full = self.write_manifest()
            for field, value, reason, status in [
                (None, None, None, 'comparable'),
                ('targetIdentity', 'synthetic-secret-other-target', 'target-mismatch', 'incomparable'),
                ('scanComplete', False, 'scan-incomplete', 'incomparable'),
                ('scanComplete', None, 'scan-completion-unknown', 'unknown'),
                ('scanPolicyIdentity', 'other', 'scan-policy-mismatch', 'incomparable'),
                ('databaseIdentity', 'other', 'database-identity-mismatch', 'incomparable'),
                ('databaseTimestamp', None, 'database-timestamp-missing', 'unknown'),
                ('databaseTimestamp', '2026-11-09T12:00:00Z', 'database-timestamp-mismatch', 'incomparable'),
            ]:
                document = deepcopy(full)
                if field:
                    document['inputs'][0][field] = value
                self.write_manifest(document)
                result = cli(*self.args(), *self.pin_args())
                self.assertEqual((result.returncode, result.stderr), (0, ''), result.stderr)
                summary = json.loads(result.stdout)
                self.assertEqual((summary['observationCount'], summary['findingCount']), (0, 0) if empty else (4, 1))
                self.assertEqual(summary['coverageAssessment'],
                                 {'status': status, 'reasonCodes': [reason] if reason else []})
                self.assertFalse(summary['canEstablishFixed'])
        # Counts use existing package/alias isolation and ignore non-observations.
        scanner, path = self.inputs[0]
        document = trivy([tv('A'), tv('A', version='2.0'), tv('B')])
        document['Results'][0]['Secrets'] = [{'synthetic-secret': True}]
        Path(path).write_text(vf.dumps(document))
        self.write_manifest()
        self.assertEqual((self.api()['observationCount'], self.api()['findingCount']), (5, 4))

    def test_byte_formatting_and_self_consistent_rewrites_need_new_expectations(self):
        original_manifest = self.manifest.read_bytes()
        for raw in (original_manifest.replace(b'\n', b'\r\n'),
                    json.dumps(json.loads(original_manifest), separators=(',', ':')).encode()):
            self.manifest.write_bytes(raw)
            self.assert_rejected([*self.args(), '--coverage-manifest-sha256', digest(original_manifest)])
            result = self.api(coverage_manifest_sha256=digest(raw))
            self.assertEqual(result['coverageManifest'], provenance(self.manifest))
            self.assertEqual(json.loads(cli(*self.args(), *self.pin_args()).stdout), result)
        original_input = Path(self.inputs[0][1]).read_bytes()
        raw = original_input.replace(b'\n', b'\r\n')
        Path(self.inputs[0][1]).write_bytes(raw)
        # Rebind manifest to changed report bytes: old caller expectation still rejects.
        doc = self.write_manifest()
        doc['inputs'][0]['targetIdentity'] = 'synthetic-secret-new-target'
        self.write_manifest(doc)
        self.assert_rejected([*self.args(), '--expect-input-sha256', *self.inputs[0], digest(original_input)])
        result = self.api(expect_input_sha256=self.pins())
        self.assertEqual(result['coverageAssessment']['reasonCodes'], ['target-mismatch'])
        self.assertEqual(next(s for s in result['inputs'] if s['scanner'] == 'trivy')['sha256'], digest(raw))
        self.assertNotIn('synthetic-secret', vf.dumps(result))

    def test_malformed_mismatched_duplicate_and_unused_expectations(self):
        scanner, path = self.inputs[0]
        for expected in ('', 'a' * 63, 'a' * 65, 'A' * 64, 'g' * 64, '０' * 64,
                         'a' * 64 + '\n', ' ' + 'a' * 64, 'a' * 64 + ' ',
                         'sha256:' + 'a' * 64, 'synthetic-secret', '0' * 64):
            for flag in (['--coverage-manifest-sha256', expected],
                         ['--expect-input-sha256', scanner, path, expected]):
                self.assert_rejected([*self.args(), *flag])
            for kwargs in ({'coverage_manifest_sha256': expected},
                           {'expect_input_sha256': [(scanner, path, expected)]}):
                with self.assertRaises(vf.InputError):
                    self.api(**kwargs)
        for pins in (self.pins() + self.pins()[:1], [('osv', path, 'a' * 64)],
                     [('TRIVY', path, 'a' * 64)], [(scanner, path + '.unused', 'a' * 64)],
                     [(scanner, str(self.base) + '/./' + Path(path).name, 'a' * 64)]):
            self.assert_rejected([*self.args(), *[v for pin in pins for v in ('--expect-input-sha256', *pin)]])
            with self.assertRaises(vf.InputError):
                self.api(expect_input_sha256=pins)
        for kwargs in ({'coverage_manifest_sha256': False}, {'expect_input_sha256': None},
                       {'expect_input_sha256': [('trivy', path)]},
                       {'expect_input_sha256': [('trivy', path, False)]}):
            with self.assertRaises(vf.InputError):
                self.api(**kwargs)

    def test_matching_hash_invalid_manifest_schema_declarations_and_bindings(self):
        full = json.loads(self.manifest.read_text())
        mutations = [
            lambda d: d.update(schemaVersion='unknown'), lambda d: d.update(extra=True),
            lambda d: d.update(inputs={}), lambda d: d['inputs'].append(deepcopy(d['inputs'][0])),
            lambda d: d['inputs'][0].update(scanner='synthetic-secret'),
            lambda d: d['inputs'][0].update(input='synthetic-secret-unused'),
            lambda d: d['inputs'][0].update(sha256='0' * 64),
            lambda d: d['inputs'][0].update(sha256='A' * 64),
            lambda d: d['inputs'][0].update(scanComplete=1),
            lambda d: d['inputs'][0].update(targetIdentity=''),
            lambda d: d['inputs'][0].update(scanPolicyIdentity=[]),
            lambda d: d['inputs'][0].update(databaseIdentity=' private '),
            lambda d: d['inputs'][0].update(databaseTimestamp='2026-02-30T12:00:00Z'),
            lambda d: d['inputs'][0].update(scanCompleted=True),
        ]
        for mutation in mutations:
            doc = deepcopy(full)
            mutation(doc)
            self.write_manifest(doc)
            self.assert_rejected([*self.args(), *self.pin_args()])
            with self.assertRaises(vf.InputError):
                self.api(coverage_manifest_sha256=digest(self.manifest.read_bytes()), expect_input_sha256=self.pins())
        # Rewriting scanner bytes invalidates a formerly valid manifest, even when all byte pins match.
        self.write_manifest(full)
        Path(self.inputs[0][1]).write_bytes(Path(self.inputs[0][1]).read_bytes() + b' ')
        self.assert_rejected([*self.args(), *self.pin_args()])

    def test_matching_hash_full_scanner_validation_even_with_empty_declarations(self):
        for scanner, invalid in {
            'trivy': [{}, {'Results': [], 'matches': []}, {'Results': [{'Target': 123, 'Vulnerabilities': []}]},
                      trivy([tv(), tv(PkgIdentifier={'PURL': 'pkg:npm/demo@2.0'})])],
            'grype': [{'matches': None}, {'matches': [{}]},
                      {'matches': [*grype()['matches'], {'artifact': {}, 'vulnerability': {'id': 123}}]}],
            'osv': [{'results': [{}]}, {'results': [{'source': {'path': 123}, 'packages': []}]},
                    osv([{'id': 'A'}, {'id': 123}])],
        }.items():
            path = next(Path(p) for s, p in self.inputs if s == scanner)
            original = path.read_bytes()
            for document in invalid:
                path.write_text(vf.dumps(document))
                for empty in (False, True):
                    self.write_manifest({'schemaVersion': 'vulnfuse-coverage-1', 'inputs': []} if empty else None)
                    self.assert_rejected([*self.args(), *self.pin_args()])
                    with self.assertRaises(vf.InputError):
                        self.api(expect_input_sha256=self.pins())
            path.write_bytes(original)

    def test_strict_json_size_and_unreadable_inputs_for_manifest_and_scanner(self):
        source = Path(self.inputs[0][1])
        for target in (self.manifest, source):
            original = target.read_bytes()
            for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e9999}',
                        b'{"a":{"x":1,"x":2}}', b'\xff', b'{', b'null', b'[]',
                        b'[' * 2000 + b']' * 2000, b' ' * (32 * 1024 * 1024 + 1)):
                target.write_bytes(raw)
                self.assert_rejected([*self.args(), *self.pin_args()])
                with self.assertRaises(vf.InputError):
                    self.api(coverage_manifest_sha256=digest(self.manifest.read_bytes()), expect_input_sha256=self.pins())
            target.unlink()
            self.assert_rejected(self.args())
            target.mkdir()
            self.assert_rejected(self.args())
            target.rmdir()
            target.write_bytes(original)

    def test_modes_missing_operands_and_help(self):
        for args in (['validate-coverage'], ['validate-coverage', '--coverage-manifest', self.manifest],
                     ['validate-coverage', '--trivy', self.inputs[0][1]],
                     [*self.args(), '--coverage-manifest-sha256'],
                     [*self.args(), '--expect-input-sha256'],
                     [*self.args(), '--expect-input-sha256', 'trivy', self.inputs[0][1]]):
            self.assert_rejected(args)
        for option in ('--merged', '--merged-sha256', '--finding', '--advisory', '--package',
                       '--markdown', '--scanner', '--input', '--input-sha256'):
            self.assert_rejected([*self.args(), option, 'synthetic-secret'])
        result = cli('validate-coverage', '--help')
        self.assertEqual(result.returncode, 0)
        for option in ('--coverage-manifest', '--coverage-manifest-sha256', '--expect-input-sha256',
                       '--trivy', '--grype', '--osv', '--output'):
            self.assertIn(option, result.stdout)
        for inputs in ([], None, [('TRIVY', self.inputs[0][1])], [('trivy', None)], [('trivy',)]):
            with self.assertRaises(vf.InputError):
                vf.validate_coverage(inputs, coverage_manifest=self.manifest)
        with self.assertRaises(vf.InputError):
            vf.validate_coverage(self.inputs, coverage_manifest=None)

    def test_all_input_and_manifest_aliases_and_output_io(self):
        for source in (self.manifest, *(Path(p) for _, p in self.inputs)):
            raw = source.read_bytes()
            hard, sym = self.base / 'hard', self.base / 'sym'
            hard.hardlink_to(source)
            sym.symlink_to(source)
            for dest in (source, str(source.parent) + '/./' + source.name, hard, sym):
                result = cli(*self.args(), *self.pin_args(), '--output', dest)
                self.assertEqual((result.returncode, result.stdout), (2, ''), result.stderr)
                self.assertEqual(source.read_bytes(), raw)
            hard.unlink()
            sym.unlink()
        for dest in (self.base, self.base / 'synthetic-secret' / 'output.json'):
            result = cli(*self.args(), '--output', dest)
            self.assertEqual((result.returncode, result.stdout), (2, ''))
            self.assertNotIn('synthetic-secret', result.stderr)
            self.assertEqual(list(self.base.glob('.vulnwrench-fuse-*')), [])

    def test_one_bounded_read_per_occurrence_and_digest_checks_before_merge(self):
        from vulnwrench.fuse import core
        reads = []
        original_open = Path.open
        class Stream(io.BytesIO):
            def read(self, size=-1):
                reads.append(size)
                return super().read(size)
        def opened(path, *args, **kwargs):
            with original_open(path, 'rb') as f:
                return Stream(f.read())
        pins = self.pins()
        manifest_sha = digest(self.manifest.read_bytes())
        with patch.object(Path, 'open', autospec=True, side_effect=opened) as mocked:
            result = self.api(coverage_manifest_sha256=manifest_sha, expect_input_sha256=pins)
        self.assertEqual(mocked.call_count, 4)
        self.assertEqual(reads, [core.MAX_INPUT_BYTES + 1] * 4)
        self.assertEqual(result['inputCount'], 3)
        for kwargs in ({'coverage_manifest_sha256': 'synthetic-secret'},
                       {'expect_input_sha256': [(self.inputs[0][0], self.inputs[0][1], False)]}):
            with patch.object(core, '_read_input') as read:
                with self.assertRaises(vf.InputError):
                    self.api(**kwargs)
                read.assert_not_called()
        with patch.object(core, 'merge_reports') as merge:
            with self.assertRaises(vf.InputError):
                self.api(coverage_manifest_sha256='0' * 64)
            merge.assert_not_called()
        with patch.dict(core.ADAPTERS, {'trivy': ('Results', lambda root: self.fail('adapter ran'))}):
            with self.assertRaisesRegex(vf.InputError, 'SHA-256 mismatch'):
                self.api(expect_input_sha256=[(*self.inputs[0], '0' * 64)])


if __name__ == '__main__':
    unittest.main()
