"""Selected saved coverage exposes validated comparisons without their evidence."""

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


class SavedFindingCoverageTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.source, self.output = self.base / 'saved.json', self.base / 'out.json'
        observed = vf.Report.from_document('trivy', trivy([tv('synthetic-secret-A'), tv('synthetic-secret-A')]),
                                           'synthetic-secret-observed')
        absent = vf.Report.from_document('grype', {'matches': []}, 'synthetic-secret-absent')
        self.reports = [observed, observed, absent, absent,
                        vf.Report.from_document('osv', osv([{'id': 'synthetic-secret-A'}]), 'synthetic-secret-osv')]
        self.manifest = manifest_document(self.reports[:1] + self.reports[2:3] + self.reports[4:])

    def merge(self, manifest=None, *, absent=False, reports=None):
        return vf.merge_reports(self.reports if reports is None else reports,
                                coverage_manifest=None if absent else vf.CoverageManifest.from_document(
                                    self.manifest if manifest is None else manifest, 'synthetic-secret-manifest'))

    def save(self, merged):
        raw = vf.dumps(merged).encode()
        self.source.write_bytes(raw)
        return raw

    def api(self, finding_id='f0001', **kwargs):
        return vf.validate_saved_finding_coverage(self.source, finding_id=finding_id, **kwargs)

    def args(self, finding='f0001'):
        return ['validate-coverage', '--merged', self.source, '--finding', finding]

    def reject(self, args):
        for exists in (True, False):
            self.output.unlink(missing_ok=True)
            if exists:
                self.output.write_bytes(b'private sentinel\x00\xff')
            result = cli(*args, '--output', self.output)
            self.assertEqual((result.returncode, result.stdout), (2, ''), result.stderr)
            self.assertTrue(result.stderr.startswith('vulnwrench fuse: '))
            for secret in ('Traceback', 'synthetic-secret', str(self.base)):
                self.assertNotIn(secret, result.stderr)
            if exists:
                self.assertEqual(self.output.read_bytes(), b'private sentinel\x00\xff')
            else:
                self.assertFalse(self.output.exists())

    def test_exact_selected_summary_cli_api_and_private_output(self):
        merged = self.merge()
        raw = self.save(merged)
        # Aggregate coverage cannot supply selected occurrence counts/comparisons.
        aggregate = vf.validate_saved_coverage(self.source)
        self.assertNotIn('absenceAssessments', aggregate)
        self.assertNotIn('findingId', aggregate)
        sources = merged['inputs']
        expected = {
            'schemaVersion': 'vulnfuse-saved-finding-coverage-validation-1',
            'validatedSchemaVersion': 'vulnfuse-1', 'validation': 'internally-consistent',
            'container': {'sha256': digest(raw), 'byteCount': len(raw), 'digestKind': 'file-bytes'},
            'coverageManifest': recorded(merged['coverageManifest']),
            'findingId': 'f0001', 'observationCount': 5,
            'inputCount': 5, 'observedInputCount': 3, 'absentInputCount': 2, 'canEstablishFixed': False,
            'inputs': [{**{k: s[k] for k in ('sourceId', 'scanner')}, **recorded(s),
                        'presence': 'not_observed' if s['scanner'] == 'grype' else 'observed',
                        'observationCount': {'grype': 0, 'osv': 1, 'trivy': 2}[s['scanner']]}
                       for s in sources],
            'absenceAssessments': {s['sourceId']: {
                'status': 'comparable', 'reasonCodes': [], 'canEstablishFixed': False,
                'comparedTo': [{'sourceId': o['sourceId'], 'status': 'comparable', 'reasonCodes': []}
                               for o in sources if o['scanner'] != 'grype']}
                for s in sources if s['scanner'] == 'grype'},
        }
        for pin in ([], ['--merged-sha256', digest(raw)]):
            result = cli(*self.args(), *pin)
            self.assertEqual((result.returncode, result.stderr), (0, ''), result.stderr)
            self.assertEqual(result.stdout, vf.dumps(expected))
        self.assertEqual(self.api(), expected)
        self.assertEqual(self.api(expected_sha256=digest(raw)), expected)
        for secret in ('synthetic-secret', 'rawReport', 'rawManifest', 'targetIdentity', 'databaseIdentity',
                       'scanPolicyIdentity', 'package', 'observations', 'manifestPointer', 'input"', str(self.base)):
            self.assertNotIn(secret, result.stdout)
        result = cli(*self.args(), '--output', self.output)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))
        self.assertEqual(self.output.read_text(), vf.dumps(expected))
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def check_selection(self, merged, finding):
        self.save(merged)
        result = self.api(finding['findingId'])
        self.assertEqual(result['absenceAssessments'], finding['absenceAssessments'])
        self.assertEqual(result['observationCount'], finding['observationCount'])
        self.assertEqual(sum(i['observationCount'] for i in result['inputs']), finding['observationCount'])
        observed = [s for s, presence in finding['inputPresence'].items() if presence == 'observed']
        self.assertEqual((result['inputCount'], result['observedInputCount'], result['absentInputCount']),
                         (len(merged['inputs']), len(observed), len(finding['absenceAssessments'])))
        for value in result['absenceAssessments'].values():
            self.assertFalse(value['canEstablishFixed'])
            self.assertEqual([e['sourceId'] for e in value['comparedTo']], observed)
        self.assertFalse(result['canEstablishFixed'])
        return result

    def test_partial_empty_absent_manifests_and_order(self):
        for manifest, absent, reason in [(self.manifest, False, None),
                ({**self.manifest, 'inputs': self.manifest['inputs'][:1]}, False, 'manifest-entry-missing'),
                ({**self.manifest, 'inputs': []}, False, 'manifest-entry-missing'),
                (None, True, 'manifest-not-supplied')]:
            merged = self.merge(manifest, absent=absent)
            result = self.check_selection(merged, merged['findings'][0])
            for value in result['absenceAssessments'].values():
                self.assertEqual(value['status'], 'unknown' if reason else 'comparable')
                self.assertEqual(value['reasonCodes'], [reason] if reason else [])
            self.assertEqual(result['coverageManifest'] is None, absent)
            self.save(self.merge(manifest, absent=absent, reports=reversed(self.reports)))
            self.assertEqual(self.api(), result)

    def test_existing_mismatch_missing_reason_precedence_and_edges(self):
        for field, value, reason, status in [
                ('targetIdentity', 'different', 'target-mismatch', 'incomparable'),
                ('scanComplete', False, 'scan-incomplete', 'incomparable'),
                ('databaseTimestamp', '2026-11-09T12:00:00Z', 'database-timestamp-mismatch', 'incomparable'),
                ('scanPolicyIdentity', 'different', 'scan-policy-mismatch', 'incomparable'),
                ('databaseIdentity', 'different', 'database-identity-mismatch', 'incomparable'),
                ('scanComplete', None, 'scan-completion-unknown', 'unknown'),
                ('databaseIdentity', None, 'database-identity-missing', 'unknown')]:
            manifest = deepcopy(self.manifest)
            manifest['inputs'][0][field] = value
            merged = self.merge(manifest)
            result = self.check_selection(merged, merged['findings'][0])
            for assessment in result['absenceAssessments'].values():
                self.assertEqual((assessment['status'], assessment['reasonCodes']), (status, [reason]))
                self.assertEqual(sum(e['status'] == status for e in assessment['comparedTo']), 2)
            # Missing metadata on the absent source combines with an observed
            # mismatch: incomparable wins; every existing reason/edge survives.
            manifest['inputs'][1]['targetIdentity'] = None
            mixed = self.merge(manifest)
            result = self.check_selection(mixed, mixed['findings'][0])
            if status == 'incomparable' and field != 'targetIdentity':
                for assessment in result['absenceAssessments'].values():
                    self.assertEqual(assessment['status'], 'incomparable')
                    self.assertEqual(assessment['reasonCodes'], sorted([reason, 'target-identity-missing']))

    def test_no_absences_unknown_identities_and_selected_counts(self):
        reports = [vf.Report.from_document('trivy', trivy([tv('A'), tv('Z')]), 'private')]
        merged = self.merge(absent=True, reports=reports)
        for finding in merged['findings']:
            result = self.check_selection(merged, finding)
            self.assertEqual((result['observationCount'], result['observedInputCount'], result['absentInputCount']), (1, 1, 0))
            self.assertEqual(result['absenceAssessments'], {})
        # Unknown package identities stay occurrence-specific and selectable.
        unknown = vf.Report.from_document('trivy', trivy([tv('A')], type_='unknown'), 'private')
        merged = self.merge(absent=True, reports=[unknown, unknown])
        self.assertEqual(len(merged['findings']), 2)
        for finding in merged['findings']:
            self.assertIsNone(finding['package']['identity'])
            result = self.check_selection(merged, finding)
            self.assertEqual((result['observationCount'], result['observedInputCount'], result['absentInputCount']), (1, 1, 1))

    def test_bad_ids_and_no_findings_preserve_outputs(self):
        self.save(self.merge())
        for finding in ('', ' f0001', 'f0001 ', 'F0001', 'f1', 'f9999', 'f0001\n', 'synthetic-secret', 'ｆ0001'):
            with self.assertRaises(vf.InputError):
                self.api(finding)
            self.reject(self.args(finding))
        for finding in (None, False, 1, [], {}, b'f0001'):
            with self.assertRaises(vf.InputError):
                self.api(finding)
        empty = self.merge(absent=True, reports=[vf.Report.from_document('grype', {'matches': []})])
        self.save(empty)
        self.reject(self.args())
        with self.assertRaises(vf.InputError):
            self.api()

    def test_matching_hash_validates_other_findings_graph_manifest_and_provenance(self):
        reports = self.reports + [vf.Report.from_document('trivy', trivy([tv('Z')]), 'private-other')]
        merged = self.merge(absent=True, reports=reports)
        mutations = [lambda d: d['findings'][1].update(observationCount=True),
                     lambda d: d['findings'][1]['observations'][0].update(sourceId='missing'),
                     lambda d: d['findings'][1]['absenceAssessments'].clear(),
                     lambda d: d['inputs'][0].update(sha256='0'*64),
                     lambda d: d['inputs'][0].update(byteCount=1)]
        for mutate in mutations:
            doc = deepcopy(merged)
            mutate(doc)
            raw = self.save(doc)
            self.reject([*self.args(), '--merged-sha256', digest(raw)])
            with self.assertRaisesRegex(vf.InputError, 'merged:'):
                self.api(expected_sha256=digest(raw))
            # Full graph validation precedes even an invalid selection.
            with self.assertRaisesRegex(vf.InputError, 'merged:'):
                self.api('missing', expected_sha256=digest(raw))
        doc = self.merge()
        doc['coverageManifest']['rawManifest']['inputs'][0]['sha256'] = '0'*64
        m = vf.CoverageManifest.from_document(doc['coverageManifest']['rawManifest'], doc['coverageManifest']['input'])
        doc['coverageManifest'].update(sha256=m.sha256, byteCount=m.byte_count)
        raw = self.save(doc)
        self.reject([*self.args(), '--merged-sha256', digest(raw)])

    def test_single_bounded_read_asserted_and_canonical_provenance(self):
        raw = self.save(self.merge())
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
        for value in [result['coverageManifest'], *result['inputs']]:
            self.assertEqual(value['provenanceVerification'], 'recomputed-canonical-json-bytes')
        live = []
        for i, report in enumerate(self.reports):
            path = self.base / f'synthetic-secret-{i}'
            path.write_text(vf.dumps(report.document))
            live.append(vf.read_report(report.scanner, path))
            path.unlink()
        path = self.base / 'synthetic-secret-manifest'
        path.write_text(vf.dumps(manifest_document(live)))
        manifest = vf.read_coverage_manifest(path)
        path.unlink()
        merged = vf.merge_reports(live, coverage_manifest=manifest)
        for value in [merged['coverageManifest'], *merged['inputs']]:
            value['byteCount'] += 7  # Original bytes unavailable: still asserted.
        self.save(merged)
        result = self.api()
        for value in [result['coverageManifest'], *result['inputs']]:
            self.assertEqual(value['provenanceVerification'], 'asserted-original-file-bytes')

    def test_modes_pins_and_output_aliases(self):
        raw = self.save(self.merge())
        for option in ('--trivy', '--grype', '--osv', '--coverage-manifest', '--coverage-manifest-sha256',
                       '--advisory', '--package', '--format', '--markdown', '--scanner', '--input', '--input-sha256'):
            self.reject([*self.args(), option, 'synthetic-secret'])
        self.reject([*self.args(), '--expect-input-sha256', 'trivy', 'synthetic-secret', '0'*64])
        for args in (['validate-coverage', '--finding', 'f0001'],
                     ['validate-coverage', '--trivy', self.source, '--coverage-manifest', self.source, '--finding', 'f0001'],
                     [*self.args(), '--merged-sha256'], ['validate-coverage', '--merged', self.source, '--finding']):
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

    def test_strict_json_size_and_missing_saved_input(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{', b'null', b'\xff', b' '*(32*1024*1024+1)):
            self.source.write_bytes(raw)
            self.reject([*self.args(), '--merged-sha256', digest(raw)])
        self.source.unlink()
        self.reject(self.args())
        self.source.mkdir()
        self.reject(self.args())


if __name__ == '__main__':
    unittest.main()
