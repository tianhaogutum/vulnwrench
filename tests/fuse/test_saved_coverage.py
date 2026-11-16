"""Saved coverage validates the complete archive without reopening recorded paths."""

from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import vulnwrench.fuse as vf
from .test_coverage import manifest_document
from .test_core import trivy, tv, osv
from .test_saved_explain import cli


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def recorded(value):
    return {**{k: value[k] for k in ('sha256', 'byteCount', 'digestKind')},
            'provenanceVerification': ('asserted-original-file-bytes' if value['digestKind'] == 'file-bytes'
                                       else 'recomputed-canonical-json-bytes')}


class SavedCoverageTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.source, self.output = self.base / 'saved.json', self.base / 'output.json'
        self.reports = [vf.Report.from_document(s, doc, 'synthetic-secret-' + s) for s, doc in (
            ('trivy', trivy([tv('A')])), ('grype', {'matches': []}),
            ('osv', osv([{'id': 'A', 'aliases': ['B']}, {'id': 'B'}])))]
        self.manifest = manifest_document(self.reports)

    def merge(self, document=None, reports=None, absent=False):
        return vf.merge_reports(self.reports if reports is None else reports, coverage_manifest=None if absent else
                                vf.CoverageManifest.from_document(self.manifest if document is None else document,
                                                                 'synthetic-secret-manifest'))

    def save(self, merged):
        raw = vf.dumps(merged).encode()
        self.source.write_bytes(raw)
        return raw

    def api(self, **kwargs):
        return vf.validate_saved_coverage(self.source, **kwargs)

    def args(self):
        return ['validate-coverage', '--merged', self.source]

    def reject(self, args=None):
        for exists in (True, False):
            self.output.unlink(missing_ok=True)
            if exists:
                self.output.write_bytes(b'private sentinel\x00\xff')
            result = cli(*(self.args() if args is None else args), '--output', self.output)
            self.assertEqual((result.returncode, result.stdout), (2, ''), result.stderr)
            self.assertTrue(result.stderr.startswith('vulnwrench fuse: '))
            for secret in ('Traceback', 'synthetic-secret', str(self.base)):
                self.assertNotIn(secret, result.stderr)
            if exists:
                self.assertEqual(self.output.read_bytes(), b'private sentinel\x00\xff')
            else:
                self.assertFalse(self.output.exists())

    def test_exact_summary_and_matching_container_hash(self):
        merged = self.merge()
        raw = self.save(merged)
        expected = {
            'schemaVersion': 'vulnfuse-saved-coverage-validation-1',
            'validatedSchemaVersion': 'vulnfuse-1', 'validation': 'internally-consistent',
            'container': {'sha256': digest(raw), 'byteCount': len(raw), 'digestKind': 'file-bytes'},
            'coverageManifest': recorded(merged['coverageManifest']),
            'inputCount': 3, 'declarationCount': 3, 'declaredInputCount': 3, 'undeclaredInputCount': 0,
            'observationCount': 3, 'findingCount': 1,
            'coverageAssessment': {'status': 'comparable', 'reasonCodes': []}, 'canEstablishFixed': False,
            'inputs': [{**{k: s[k] for k in ('sourceId', 'scanner', 'observationCount')}, **recorded(s),
                        'coverage': {'status': 'declared', 'reasonCodes': [],
                                     'manifestPointer': {'trivy': '/inputs/0', 'grype': '/inputs/1', 'osv': '/inputs/2'}[s['scanner']]}}
                       for s in merged['inputs']],
        }
        for pin in ([], ['--merged-sha256', digest(raw)]):
            result = cli(*self.args(), *pin)
            self.assertEqual((result.returncode, result.stderr), (0, ''), result.stderr)
            self.assertEqual(result.stdout, vf.dumps(expected))
        self.assertEqual(self.api(), expected)
        self.assertEqual(self.api(expected_sha256=digest(raw)), expected)
        for secret in ('synthetic-secret', 'rawReport', 'rawManifest', 'targetIdentity', 'databaseIdentity',
                       'scanPolicyIdentity', 'findings', 'input"', str(self.base)):
            self.assertNotIn(secret, result.stdout)
        result = cli(*self.args(), '--output', self.output)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))
        self.assertEqual(self.output.read_text(), vf.dumps(expected))
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_complete_partial_empty_absent_and_repeated_occurrences(self):
        reports = self.reports + [self.reports[0]]
        for document, absent, declared, reason in [
            (self.manifest, False, 4, None),
            ({**self.manifest, 'inputs': self.manifest['inputs'][:1]}, False, 2, 'manifest-entry-missing'),
            ({**self.manifest, 'inputs': []}, False, 0, 'manifest-entry-missing'),
            (None, True, 0, 'manifest-not-supplied'),
        ]:
            merged = self.merge(document, reports, absent)
            raw = self.save(merged)
            result = self.api(expected_sha256=digest(raw))
            self.assertEqual((result['inputCount'], result['declarationCount'], result['declaredInputCount'],
                              result['undeclaredInputCount'], result['observationCount'], result['findingCount']),
                             (4, 0 if absent else len(document['inputs']), declared, 4-declared, 4, 1))
            self.assertEqual(result['coverageManifest'] is None, absent)
            self.assertEqual(result['coverageAssessment'],
                             {'status': 'unknown' if reason else 'comparable', 'reasonCodes': [reason] if reason else []})
            self.assertFalse(result['canEstablishFixed'])
            self.assertEqual(cli(*self.args()).stdout, vf.dumps(result))
            self.save(self.merge(document, reversed(reports), absent))
            self.assertEqual(self.api(), result)

    def test_empty_profiles_and_all_existing_reasons(self):
        for empty in (False, True):
            reports = self.reports if not empty else [vf.Report.from_document(s, d) for s, d in
                      [('trivy', {'Results': None}), ('grype', {'matches': []}), ('osv', {'results': []})]]
            full = manifest_document(reports)
            cases = [(None, None, [], 'comparable'),
                     ('targetIdentity', 'other', ['target-mismatch'], 'incomparable'),
                     ('scanComplete', False, ['scan-incomplete'], 'incomparable'),
                     ('scanComplete', None, ['scan-completion-unknown'], 'unknown'),
                     ('databaseTimestamp', '2026-11-09T12:00:00Z', ['database-timestamp-mismatch'], 'incomparable'),
                     ('scanPolicyIdentity', 'other', ['scan-policy-mismatch'], 'incomparable'),
                     ('databaseIdentity', 'other', ['database-identity-mismatch'], 'incomparable')]
            for field, reason in [('targetIdentity', 'target-identity-missing'),
                                  ('databaseTimestamp', 'database-timestamp-missing'),
                                  ('scanPolicyIdentity', 'scan-policy-identity-missing'),
                                  ('databaseIdentity', 'database-identity-missing')]:
                cases.append((field, None, [reason], 'unknown'))
            for field, value, reasons, status in cases:
                document = deepcopy(full)
                if field:
                    document['inputs'][0][field] = value
                self.save(self.merge(document, reports))
                summary = self.api()
                self.assertEqual((summary['observationCount'], summary['findingCount']), (0, 0) if empty else (3, 1))
                self.assertEqual(summary['coverageAssessment'], {'status': status, 'reasonCodes': reasons})
                self.assertFalse(summary['canEstablishFixed'])

    def test_file_provenance_asserted_canonical_recomputed_and_originals_never_opened(self):
        live = []
        for report in self.reports:
            path = self.base / report.input_name
            path.write_text(vf.dumps(report.document))
            live.append(vf.read_report(report.scanner, path))
            path.unlink()
        path = self.base / 'synthetic-secret-manifest'
        path.write_text(vf.dumps(manifest_document(live)))
        manifest = vf.read_coverage_manifest(path)
        path.unlink()
        merged = vf.merge_reports(live, coverage_manifest=manifest)
        # File-byte provenance is an assertion: even changed plausible byte counts
        # cannot be checked against embedded decoded JSON or unavailable originals.
        for s in merged['inputs']:
            s['byteCount'] += 7
        merged['coverageManifest']['byteCount'] += 9
        self.save(merged)
        original_open = Path.open
        opened = []
        def open_only_saved(path, *args, **kwargs):
            opened.append(path)
            self.assertEqual(path, self.source)
            return original_open(path, *args, **kwargs)
        with patch.object(Path, 'open', open_only_saved):
            result = self.api()
        self.assertEqual(opened, [self.source])
        for value in [result['coverageManifest'], *result['inputs']]:
            self.assertEqual(value['provenanceVerification'], 'asserted-original-file-bytes')
        self.save(self.merge())
        canonical = self.api()
        for value in [canonical['coverageManifest'], *canonical['inputs']]:
            self.assertEqual(value['provenanceVerification'], 'recomputed-canonical-json-bytes')

    def test_formatting_and_self_consistent_rewrites_change_only_container_or_claims(self):
        merged = self.merge()
        raw = self.save(merged)
        original = self.api()
        for variant in (raw.replace(b'\n', b'\r\n'), json.dumps(merged, separators=(',', ':')).encode()):
            self.source.write_bytes(variant)
            self.reject([*self.args(), '--merged-sha256', digest(raw)])
            result = self.api(expected_sha256=digest(variant))
            self.assertEqual(result.pop('container'), {'sha256': digest(variant), 'byteCount': len(variant), 'digestKind': 'file-bytes'})
            self.assertEqual(result, {k: v for k, v in original.items() if k != 'container'})
        document = deepcopy(self.manifest)
        document['inputs'][0]['scanComplete'] = False
        rewritten = self.save(self.merge(document))
        self.reject([*self.args(), '--merged-sha256', digest(raw)])
        result = self.api(expected_sha256=digest(rewritten))
        self.assertEqual(result['coverageAssessment'], {'status': 'incomparable', 'reasonCodes': ['scan-incomplete']})
        self.assertFalse(result['canEstablishFixed'])

    def test_matching_hash_graph_manifest_and_canonical_tampering_rejects(self):
        merged = self.merge()
        mutations = [
            lambda d: d['aliasEdges'][0].update(observationId='missing'),
            lambda d: d['findings'][0]['observations'].clear(),
            lambda d: d.update(observationCount=True),
            lambda d: d['inputs'][0]['coverage'].update(manifestPointer='/inputs/999'),
            lambda d: d['coverageAssessment'].update(status='unknown'),
            lambda d: d['inputs'][0].update(sha256='0'*64),
            lambda d: d['inputs'][0].update(byteCount=d['inputs'][0]['byteCount']+1),
            lambda d: d['coverageManifest'].update(sha256='0'*64),
            lambda d: d['coverageManifest']['rawManifest']['inputs'][0].update(sha256='0'*64),
            lambda d: d['coverageManifest']['rawManifest']['inputs'][0].update(scanComplete='yes'),
        ]
        for mutate in mutations:
            doc = deepcopy(merged)
            mutate(doc)
            raw = self.save(doc)
            self.reject([*self.args(), '--merged-sha256', digest(raw)])
            with self.assertRaises(vf.InputError):
                self.api(expected_sha256=digest(raw))
        # Recomputed manifest hash does not bypass stale binding validation.
        doc = deepcopy(self.manifest)
        doc['inputs'][0]['sha256'] = '0'*64
        invalid = deepcopy(merged)
        m = vf.CoverageManifest.from_document(doc, 'synthetic-secret-manifest')
        invalid['coverageManifest'].update(rawManifest=m.document, sha256=m.sha256, byteCount=m.byte_count)
        raw = self.save(invalid)
        self.reject([*self.args(), '--merged-sha256', digest(raw)])

    def test_modes_expectations_and_output_preservation(self):
        self.save(self.merge())
        for option in ('--trivy', '--grype', '--osv', '--coverage-manifest', '--coverage-manifest-sha256',
                       '--finding', '--advisory', '--package', '--format', '--markdown', '--scanner', '--input', '--input-sha256'):
            self.reject([*self.args(), option, 'synthetic-secret'])
        self.reject([*self.args(), '--expect-input-sha256', 'trivy', 'synthetic-secret', '0'*64])
        for args in (['validate-coverage'], ['validate-coverage', '--merged-sha256', '0'*64],
                     [*self.args(), '--merged'], [*self.args(), '--merged-sha256']):
            self.reject(args)
        for pin in ('', 'A'*64, 'g'*64, 'a'*63, '０'*64, 'a'*64+'\n', '0'*64):
            self.reject([*self.args(), '--merged-sha256', pin])
            with self.assertRaises(vf.InputError):
                self.api(expected_sha256=pin)
        help_result = cli('validate-coverage', '--help')
        self.assertEqual(help_result.returncode, 0)
        self.assertIn('--merged-sha256', help_result.stdout)
        for dest in (self.source, self.base / '.' / 'saved.json', self.base / 'sym', self.base / 'hard'):
            if dest.name == 'sym':
                dest.symlink_to(self.source)
            if dest.name == 'hard':
                dest.hardlink_to(self.source)
            raw = self.source.read_bytes()
            result = cli(*self.args(), '--output', dest)
            self.assertEqual((result.returncode, result.stdout), (2, ''))
            self.assertEqual(self.source.read_bytes(), raw)
        for dest in (self.base, self.base / 'synthetic-secret' / 'out'):
            result = cli(*self.args(), '--output', dest)
            self.assertEqual((result.returncode, result.stdout), (2, ''))
            self.assertNotIn('synthetic-secret', result.stderr)
            self.assertFalse(list(self.base.glob('.vulnwrench-fuse-*')))

    def test_strict_bounded_read_missing_inputs_and_matching_hash(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{', b'null', b'\xff',
                    b' ' * (32*1024*1024+1)):
            self.source.write_bytes(raw)
            self.reject([*self.args(), '--merged-sha256', digest(raw)])
        self.source.unlink()
        self.reject()
        self.source.mkdir()
        self.reject()

    def test_single_bounded_read_and_expectations_before_reconstruction(self):
        raw = self.save(self.merge())
        reads, opens = [], []
        class Stream(io.BytesIO):
            def read(self, size=-1):
                reads.append(size)
                return super().read(size)
        def opened(path, *args, **kwargs):
            opens.append((path, args))
            return Stream(raw)
        with patch.object(Path, 'open', opened):
            result = self.api(expected_sha256=digest(raw))
        self.assertEqual(opens, [(self.source, ('rb',))])
        self.assertEqual(reads, [32*1024*1024+1])
        self.assertEqual(result['container']['sha256'], digest(raw))
        from vulnwrench.fuse import saved
        for invalid in (False, 123, [], {}, b'a'*64):
            with patch.object(saved, '_read_input') as read:
                with self.assertRaises(vf.InputError):
                    self.api(expected_sha256=invalid)
                read.assert_not_called()
        with patch.object(saved, 'merge_reports') as merge:
            with self.assertRaises(vf.InputError):
                self.api(expected_sha256='0'*64)
            merge.assert_not_called()


if __name__ == '__main__':
    unittest.main()
