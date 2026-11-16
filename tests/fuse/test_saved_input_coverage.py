"""Exact pair coverage is independent of findings and validates the whole archive."""

from copy import deepcopy
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import vulnwrench.fuse as vf
from .test_core import trivy, tv, osv
from .test_coverage import manifest_document
from .test_saved_coverage import digest, recorded
from .test_saved_explain import cli


class SavedInputCoverageTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.source, self.output = self.base / 'saved.json', self.base / 'out.json'
        self.reports = [vf.Report.from_document(s, doc, 'synthetic-secret-'+s) for s, doc in (
            ('grype', {'matches': []}), ('osv', {'results': []}), ('trivy', {'Results': None}))]
        self.manifest = manifest_document(self.reports)

    def merge(self, manifest=None, *, absent=False, reports=None):
        return vf.merge_reports(self.reports if reports is None else reports, coverage_manifest=None if absent else
            vf.CoverageManifest.from_document(self.manifest if manifest is None else manifest, 'synthetic-secret-manifest'))

    def save(self, merged):
        raw = vf.dumps(merged).encode()
        self.source.write_bytes(raw)
        return raw

    def api(self, a='s0001', b='s0002', **kwargs):
        return vf.compare_saved_input_coverage(self.source, source_a=a, source_b=b, **kwargs)

    def args(self, a='s0001', b='s0002'):
        return ['validate-coverage', '--merged', self.source, '--compare-inputs', a, b]

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

    def test_exact_pair_summary_cli_api_and_private_output_without_findings(self):
        manifest = deepcopy(self.manifest)
        manifest['inputs'][2]['databaseIdentity'] = 'synthetic-secret-other-snapshot'
        merged = self.merge(manifest)
        raw = self.save(merged)
        aggregate = vf.validate_saved_coverage(self.source)
        self.assertEqual(aggregate['findingCount'], 0)
        self.assertEqual(aggregate['coverageAssessment'], {
            'status': 'incomparable', 'reasonCodes': ['database-identity-mismatch']})
        # No finding-dependent matrix exists; local coverage is complete everywhere.
        self.assertEqual(merged['findings'], [])
        self.assertTrue(all(s['coverage']['reasonCodes'] == [] for s in aggregate['inputs']))
        expected = {
            'schemaVersion': 'vulnfuse-saved-input-coverage-comparison-1',
            'validatedSchemaVersion': 'vulnfuse-1', 'validation': 'internally-consistent',
            'container': {'sha256': digest(raw), 'byteCount': len(raw), 'digestKind': 'file-bytes'},
            'coverageManifest': recorded(merged['coverageManifest']),
            'inputs': [{**{k: s[k] for k in ('sourceId', 'scanner')}, **recorded(s)} for s in merged['inputs'][:2]],
            'coverageAssessment': {'status': 'comparable', 'reasonCodes': []},
            'canEstablishFixed': False,
        }
        for pin in ([], ['--merged-sha256', digest(raw)]):
            result = cli(*self.args(), *pin)
            self.assertEqual((result.returncode, result.stderr), (0, ''), result.stderr)
            self.assertEqual(result.stdout, vf.dumps(expected))
        self.assertEqual(self.api(), expected)
        self.assertEqual(self.api(expected_sha256=digest(raw)), expected)
        mismatch = self.api('s0001', 's0003')
        self.assertEqual(mismatch['coverageAssessment'], aggregate['coverageAssessment'])
        reversed_pair = self.api('s0002', 's0001')
        self.assertEqual(reversed_pair['inputs'], list(reversed(expected['inputs'])))
        self.assertEqual(reversed_pair['coverageAssessment'], expected['coverageAssessment'])
        for secret in ('synthetic-secret', 'rawReport', 'rawManifest', 'targetIdentity', 'databaseIdentity',
                       'scanPolicyIdentity', 'absenceAssessments', 'comparedTo', 'findings', 'manifestPointer', str(self.base)):
            self.assertNotIn(secret, result.stdout)
        result = cli(*self.args(), '--output', self.output)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))
        self.assertEqual(self.output.read_text(), vf.dumps(expected))
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_all_existing_reasons_precedence_and_utc_equivalence(self):
        changes = [({}, 'comparable', []),
            ({'databaseTimestamp': '2026-11-10T13:00:00+01:00'}, 'comparable', []),
            ({'targetIdentity': None}, 'unknown', ['target-identity-missing']),
            ({'scanComplete': None}, 'unknown', ['scan-completion-unknown']),
            ({'databaseTimestamp': None}, 'unknown', ['database-timestamp-missing']),
            ({'scanPolicyIdentity': None}, 'unknown', ['scan-policy-identity-missing']),
            ({'databaseIdentity': None}, 'unknown', ['database-identity-missing']),
            ({'scanComplete': False}, 'incomparable', ['scan-incomplete']),
            ({'targetIdentity': 'synthetic-secret-other'}, 'incomparable', ['target-mismatch']),
            ({'databaseTimestamp': '2026-11-10T12:00:01Z'}, 'incomparable', ['database-timestamp-mismatch']),
            ({'scanPolicyIdentity': 'Synthetic:suppress:none'}, 'incomparable', ['scan-policy-mismatch']),
            ({'databaseIdentity': 'Synthetic:snapshot:common'}, 'incomparable', ['database-identity-mismatch'])]
        for delta, status, reasons in changes:
            for side in (0, 1):
                for omit in ((False, True) if None in delta.values() else (False,)):
                    with self.subTest(delta=delta, side=side, omit=omit):
                        manifest = deepcopy(self.manifest)
                        if omit:
                            for key in delta:
                                del manifest['inputs'][side][key]
                        else:
                            manifest['inputs'][side].update(delta)
                        raw = self.save(self.merge(manifest))
                        result = self.api(expected_sha256=digest(raw))
                        self.assertEqual(result['coverageAssessment'], {'status': status, 'reasonCodes': reasons})
                        self.assertFalse(result['canEstablishFixed'])
        manifest = deepcopy(self.manifest)
        manifest['inputs'][0].update(targetIdentity=None, scanComplete=False,
                                    databaseTimestamp='2026-11-10T12:00:01Z',
                                    scanPolicyIdentity='synthetic-secret-policy', databaseIdentity='synthetic-secret-database')
        manifest['inputs'][1].update(databaseIdentity=None)
        self.save(self.merge(manifest))
        self.assertEqual(self.api()['coverageAssessment'], {'status': 'incomparable', 'reasonCodes': sorted([
            'target-identity-missing', 'scan-incomplete', 'database-timestamp-mismatch',
            'scan-policy-mismatch', 'database-identity-missing'])})

    def test_manifest_modes_repeated_occurrences_and_existing_absence_agreement(self):
        for manifest, absent, reasons in [(self.manifest, False, []),
                ({**self.manifest, 'inputs': self.manifest['inputs'][:1]}, False, ['manifest-entry-missing']),
                ({**self.manifest, 'inputs': []}, False, ['manifest-entry-missing']),
                (None, True, ['manifest-not-supplied'])]:
            self.save(self.merge(manifest, absent=absent))
            result = self.api()
            self.assertEqual(result['coverageAssessment'], {'status': 'unknown' if reasons else 'comparable', 'reasonCodes': reasons})
            self.assertEqual(result['coverageManifest'] is None, absent)
            self.save(self.merge(manifest, absent=absent, reports=reversed(self.reports)))
            self.assertEqual(self.api(), result)
        repeated = [self.reports[0], self.reports[0], self.reports[2]]
        manifest = manifest_document([self.reports[0], self.reports[2]])
        self.save(self.merge(manifest, reports=repeated))
        result = self.api()
        self.assertEqual([s['sourceId'] for s in result['inputs']], ['s0001', 's0002'])
        self.assertEqual(result['inputs'][0]['sha256'], result['inputs'][1]['sha256'])
        self.assertEqual(result['coverageAssessment'], {'status': 'comparable', 'reasonCodes': []})
        observed = [self.reports[0], vf.Report.from_document('trivy', trivy([tv('A')]), 'synthetic-secret-found'),
                    vf.Report.from_document('osv', osv([{'id': 'A'}]), 'synthetic-secret-osv')]
        manifest = manifest_document(observed)
        manifest['inputs'][0]['scanPolicyIdentity'] = 'synthetic-secret-suppression'
        merged = self.merge(manifest, reports=observed)
        self.save(merged)
        for absent_id, assessment in merged['findings'][0]['absenceAssessments'].items():
            for edge in assessment['comparedTo']:
                self.assertEqual(self.api(absent_id, edge['sourceId'])['coverageAssessment'],
                                 {k: edge[k] for k in ('status', 'reasonCodes')})

    def test_matching_hash_validates_unselected_graph_and_all_provenance_before_selection(self):
        observed = [*self.reports, vf.Report.from_document('trivy', trivy([tv('A'), tv('Z')]), 'synthetic-secret-found')]
        merged = self.merge(manifest_document(observed), reports=observed)
        mutations = [lambda d: d['inputs'][-1].update(sourceId='s9999'),
            lambda d: d['inputs'][-1].update(sha256='0'*64),
            lambda d: d['inputs'][-1].update(byteCount=True),
            lambda d: d['findings'][-1]['observations'][0].update(sourceId='missing'),
            lambda d: d['findings'][-1]['absenceAssessments'].clear(),
            lambda d: d['coverageManifest'].update(byteCount=1),
            lambda d: d.update(extra='synthetic-secret')]
        for mutate in mutations:
            doc = deepcopy(merged)
            mutate(doc)
            raw = self.save(doc)
            # Full validation precedes even an invalid/equal selector.
            for a, b in [('s0001', 's0002'), ('', ''), ('s9999', 's9999')]:
                with self.assertRaisesRegex(vf.InputError, 'merged:'):
                    self.api(a, b, expected_sha256=digest(raw))
            self.reject([*self.args(), '--merged-sha256', digest(raw)])
        doc = deepcopy(merged)
        doc['coverageManifest']['rawManifest']['inputs'][-1]['sha256'] = '0'*64
        m = vf.CoverageManifest.from_document(doc['coverageManifest']['rawManifest'], doc['coverageManifest']['input'])
        doc['coverageManifest'].update(sha256=m.sha256, byteCount=m.byte_count)
        raw = self.save(doc)
        with self.assertRaisesRegex(vf.InputError, 'merged:'):
            self.api(expected_sha256=digest(raw))
        self.reject([*self.args(), '--merged-sha256', digest(raw)])
        empty = self.merge()
        empty['inputs'][-1]['byteCount'] += 1
        raw = self.save(empty)
        self.reject([*self.args(), '--merged-sha256', digest(raw)])
        with self.assertRaises(vf.InputError):
            self.api(expected_sha256=digest(raw))

    def test_single_bounded_read_mixed_digest_trust_originals_unavailable_and_formatting(self):
        original = self.base / 'synthetic-secret-original'
        original.write_text(vf.dumps(self.reports[0].document))
        reports = [vf.read_report('grype', original), self.reports[1]]
        original.unlink()
        original.write_text(vf.dumps(manifest_document(reports)))
        manifest = vf.read_coverage_manifest(original)
        original.unlink()
        merged = vf.merge_reports(reports, coverage_manifest=manifest)
        merged['inputs'][0]['byteCount'] += 7  # Recorded file-byte counts remain assertions.
        merged['coverageManifest']['byteCount'] += 9
        raw = self.save(merged)
        opens, reads = [], []
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
        self.assertEqual([s['provenanceVerification'] for s in result['inputs']],
                         ['asserted-original-file-bytes', 'recomputed-canonical-json-bytes'])
        self.assertEqual(result['coverageManifest']['provenanceVerification'], 'asserted-original-file-bytes')
        self.assertEqual(cli(*self.args()).stdout, vf.dumps(result))
        variant = raw.replace(b'\n', b'\r\n')
        self.source.write_bytes(variant)
        changed = self.api(expected_sha256=digest(variant))
        self.assertNotEqual(changed.pop('container'), result.pop('container'))
        self.assertEqual(changed, result)
        self.reject([*self.args(), '--merged-sha256', digest(raw)])

    def test_invalid_ids_modes_pins_output_preservation_and_input_aliases(self):
        raw = self.save(self.merge())
        for invalid in ('', ' s0001', 's0001 ', 's0001\n', 'S0001', 's1', 's0000', 's9999', 'synthetic-secret', 's０００１'):
            for a, b in [(invalid, 's0002'), ('s0001', invalid)]:
                self.reject(self.args(a, b))
                with self.assertRaises(vf.InputError):
                    self.api(a, b)
        self.reject(self.args('s0001', 's0001'))
        for a, b in [('s0001', 's0001'), (None, 's0002'), ('s0001', False), ([], {}), (123, b's0002')]:
            with self.assertRaises(vf.InputError):
                self.api(a, b)
        for option in ('--trivy', '--grype', '--osv', '--coverage-manifest', '--coverage-manifest-sha256',
                       '--advisory', '--package', '--format', '--markdown', '--scanner', '--input', '--input-sha256', '--finding'):
            self.reject([*self.args(), option, 'synthetic-secret'])
        self.reject([*self.args(), '--list-findings'])
        self.reject([*self.args(), '--expect-input-sha256', 'trivy', 'synthetic-secret', '0'*64])
        for args in (['validate-coverage', '--compare-inputs', 's0001', 's0002'],
                     ['validate-coverage', '--trivy', self.source, '--coverage-manifest', self.source,
                      '--compare-inputs', 's0001', 's0002'],
                     ['validate-coverage', '--merged', self.source, '--compare-inputs', 's0001'],
                     [*self.args(), 's0003'], [*self.args(), '--merged-sha256']):
            self.reject(args)
        for pin in ('', 'A'*64, 'g'*64, 'a'*63, '０'*64, 'a'*64+'\n', '0'*64):
            self.reject([*self.args(), '--merged-sha256', pin])
            with self.assertRaises(vf.InputError):
                self.api(expected_sha256=pin)
        from vulnwrench.fuse import saved
        for invalid in (False, [], 123, b'a'*64):
            with patch.object(saved, '_read_input') as read:
                with self.assertRaises(vf.InputError):
                    self.api(expected_sha256=invalid)
                read.assert_not_called()
        for dest in (self.source, self.base / '.' / 'saved.json', self.base / 'sym', self.base / 'hard'):
            if dest.name == 'sym':
                dest.symlink_to(self.source)
            if dest.name == 'hard':
                dest.hardlink_to(self.source)
            result = cli(*self.args(), '--output', dest)
            self.assertEqual((result.returncode, result.stdout), (2, ''))
            self.assertEqual(self.source.read_bytes(), raw)
        # A valid one-input archive still cannot supply two distinct occurrences.
        self.save(self.merge(absent=True, reports=self.reports[:1]))
        self.reject()

    def test_strict_json_size_missing_saved_input_and_no_live_mode(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{', b'null', b'\xff', b' '*(32*1024*1024+1)):
            self.source.write_bytes(raw)
            self.reject([*self.args(), '--merged-sha256', digest(raw)])
            with self.assertRaises(vf.InputError):
                self.api(expected_sha256=digest(raw))
        self.source.unlink()
        self.reject()
        self.source.mkdir()
        self.reject()


if __name__ == '__main__':
    unittest.main()
