"""Evidence-free discovery still validates the entire saved evidence archive."""

from copy import deepcopy
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import vulnwrench.fuse as vf
from .test_core import trivy, tv, osv
from .test_coverage import manifest_document
from .test_saved_coverage import digest
from .test_saved_explain import cli


class FindingCoverageIndexTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.source, self.output = self.base / 'saved.json', self.base / 'out.json'
        observed = vf.Report.from_document('trivy', trivy([tv('synthetic-secret-A'), tv('synthetic-secret-A'),
                                                         tv('synthetic-secret-Z')]), 'synthetic-secret-observed')
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

    def api(self, **kwargs):
        return vf.list_saved_finding_coverage(self.source, **kwargs)

    def args(self):
        return ['validate-coverage', '--merged', self.source, '--list-findings']

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

    def test_exact_index_cli_api_and_private_output(self):
        merged = self.merge()
        raw = self.save(merged)
        # Existing aggregate summary exposes no IDs; selected summary needs one.
        self.assertNotIn('findings', vf.validate_saved_coverage(self.source))
        expected = {
            'schemaVersion': 'vulnfuse-saved-finding-coverage-index-1',
            'validatedSchemaVersion': 'vulnfuse-1', 'validation': 'internally-consistent',
            'container': {'sha256': digest(raw), 'byteCount': len(raw), 'digestKind': 'file-bytes'},
            'inputCount': 5, 'findingCount': 2, 'observationCount': 7,
            'findings': [
                {'findingId': 'f0001', 'observationCount': 5, 'observedInputCount': 3, 'absentInputCount': 2},
                {'findingId': 'f0002', 'observationCount': 2, 'observedInputCount': 2, 'absentInputCount': 3},
            ],
            'canEstablishFixed': False,
        }
        for pin in ([], ['--merged-sha256', digest(raw)]):
            result = cli(*self.args(), *pin)
            self.assertEqual((result.returncode, result.stderr), (0, ''), result.stderr)
            self.assertEqual(result.stdout, vf.dumps(expected))
        self.assertEqual(self.api(), expected)
        self.assertEqual(self.api(expected_sha256=digest(raw)), expected)
        for secret in ('synthetic-secret', 'rawReport', 'rawManifest', 'targetIdentity', 'databaseIdentity',
                       'scanPolicyIdentity', 'absenceAssessments', 'comparedTo', 'inputs', 'coverageManifest',
                       'package', 'observations', 'manifestPointer', str(self.base)):
            self.assertNotIn(secret, result.stdout)
        result = cli(*self.args(), '--output', self.output)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))
        self.assertEqual(self.output.read_text(), vf.dumps(expected))
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def check_index(self, merged):
        raw = self.save(merged)
        index = self.api(expected_sha256=digest(raw))
        self.assertEqual(index['container'], {'sha256': digest(raw), 'byteCount': len(raw), 'digestKind': 'file-bytes'})
        self.assertFalse(index['canEstablishFixed'])
        for key in ('inputCount', 'findingCount', 'observationCount'):
            self.assertEqual(index[key], merged[key])
        self.assertEqual(len(index['findings']), merged['findingCount'])
        for entry, finding in zip(index['findings'], merged['findings']):
            selected = vf.validate_saved_finding_coverage(self.source, finding_id=finding['findingId'])
            self.assertEqual(entry, {k: selected[k] for k in
                                    ('findingId', 'observationCount', 'observedInputCount', 'absentInputCount')})
            self.assertEqual(entry['observationCount'], len(finding['observations']))
            self.assertEqual(entry['observedInputCount'], sum(p == 'observed' for p in finding['inputPresence'].values()))
            self.assertEqual(entry['absentInputCount'], len(finding['absenceAssessments']))
            self.assertEqual(entry['observedInputCount'] + entry['absentInputCount'], merged['inputCount'])
        self.assertEqual(sum(f['observationCount'] for f in index['findings']), merged['observationCount'])
        return index

    def test_manifest_modes_occurrences_order_and_selected_agreement(self):
        for manifest, absent in [(self.manifest, False),
                ({**self.manifest, 'inputs': self.manifest['inputs'][:1]}, False),
                ({**self.manifest, 'inputs': []}, False), (None, True)]:
            index = self.check_index(self.merge(manifest, absent=absent))
            self.assertEqual(cli(*self.args()).stdout, vf.dumps(index))
            self.save(self.merge(manifest, absent=absent, reports=reversed(self.reports)))
            self.assertEqual(self.api(), index)

    def test_unknown_identities_no_absences_and_empty_findings(self):
        observed = self.reports[0]
        merged = self.merge(absent=True, reports=[observed])
        index = self.check_index(merged)
        self.assertEqual([f['absentInputCount'] for f in index['findings']], [0, 0])
        unknown = vf.Report.from_document('trivy', trivy([tv('A')], type_='unknown'), 'synthetic-secret')
        merged = self.merge(absent=True, reports=[unknown, unknown])
        self.assertTrue(all(f['package']['identity'] is None for f in merged['findings']))
        index = self.check_index(merged)
        self.assertEqual([(f['observationCount'], f['observedInputCount'], f['absentInputCount'])
                          for f in index['findings']], [(1, 1, 1), (1, 1, 1)])
        empty = [vf.Report.from_document(s, doc) for s, doc in (
                 ('trivy', {'Results': None}), ('grype', {'matches': []}), ('osv', {'results': []}))]
        manifest = manifest_document(empty)
        for doc, absent in [(manifest, False), ({**manifest, 'inputs': manifest['inputs'][:1]}, False),
                            ({**manifest, 'inputs': []}, False), (None, True)]:
            merged = self.merge(doc, absent=absent, reports=empty)
            index = self.check_index(merged)
            self.assertEqual((index['findings'], index['findingCount'], index['observationCount']), ([], 0, 0))
            result = cli(*self.args())
            self.assertEqual((result.returncode, result.stderr, result.stdout), (0, '', vf.dumps(index)))
            # Empty findings cannot short-circuit canonical provenance or graph validation.
            merged['inputs'][0]['byteCount'] += 1
            raw = self.save(merged)
            with self.assertRaises(vf.InputError):
                self.api(expected_sha256=digest(raw))
            self.reject([*self.args(), '--merged-sha256', digest(raw)])

    def test_matching_hash_validates_every_finding_graph_manifest_and_provenance(self):
        merged = self.merge()
        mutations = [lambda d: d['findings'][-1].update(observationCount=True),
                     lambda d: d['findings'][-1]['observations'][0].update(sourceId='missing'),
                     lambda d: d['findings'][-1]['absenceAssessments'].clear(),
                     lambda d: d['findings'].reverse(),
                     lambda d: d['inputs'][0].update(sha256='0'*64),
                     lambda d: d['coverageManifest'].update(byteCount=1),
                     lambda d: d.update(extra='synthetic-secret')]
        for mutate in mutations:
            doc = deepcopy(merged)
            mutate(doc)
            raw = self.save(doc)
            with self.assertRaisesRegex(vf.InputError, 'merged:'):
                self.api(expected_sha256=digest(raw))
            self.reject([*self.args(), '--merged-sha256', digest(raw)])
        # Self-consistent canonical manifest provenance still requires valid bindings.
        doc = deepcopy(merged)
        doc['coverageManifest']['rawManifest']['inputs'][0]['sha256'] = '0'*64
        m = vf.CoverageManifest.from_document(doc['coverageManifest']['rawManifest'], doc['coverageManifest']['input'])
        doc['coverageManifest'].update(sha256=m.sha256, byteCount=m.byte_count)
        raw = self.save(doc)
        self.reject([*self.args(), '--merged-sha256', digest(raw)])
        with self.assertRaises(vf.InputError):
            self.api(expected_sha256=digest(raw))

    def test_single_bounded_read_no_originals_and_mixed_provenance(self):
        # File-byte originals disappear; canonical and asserted provenance coexist.
        path = self.base / 'synthetic-secret-original'
        path.write_text(vf.dumps(self.reports[0].document))
        live = vf.read_report('trivy', path)
        path.unlink()
        reports = [live, self.reports[2]]
        path.write_text(vf.dumps(manifest_document(reports)))
        manifest = vf.read_coverage_manifest(path)
        path.unlink()
        merged = vf.merge_reports(reports, coverage_manifest=manifest)
        merged['coverageManifest']['byteCount'] += 7  # File-byte counts remain assertions.
        next(s for s in merged['inputs'] if s['digestKind'] == 'file-bytes')['byteCount'] += 9
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
            index = self.api(expected_sha256=digest(raw))
        self.assertEqual(opens, [(self.source, ('rb',))])
        self.assertEqual(reads, [32*1024*1024+1])
        self.assertEqual(index['findingCount'], 2)
        # Formatting changes exact container provenance without changing the index entries.
        variant = raw.replace(b'\n', b'\r\n')
        self.source.write_bytes(variant)
        changed = self.api(expected_sha256=digest(variant))
        self.assertNotEqual(changed.pop('container'), index.pop('container'))
        self.assertEqual(changed, index)
        self.reject([*self.args(), '--merged-sha256', digest(raw)])

    def test_modes_pins_and_output_aliases(self):
        raw = self.save(self.merge())
        for option in ('--trivy', '--grype', '--osv', '--coverage-manifest', '--coverage-manifest-sha256',
                       '--advisory', '--package', '--format', '--markdown', '--scanner', '--input', '--input-sha256',
                       '--finding'):
            self.reject([*self.args(), option, 'synthetic-secret'])
        self.reject(['validate-coverage', '--merged', self.source, '--finding', 'f0001', '--list-findings'])
        self.reject([*self.args(), '--expect-input-sha256', 'trivy', 'synthetic-secret', '0'*64])
        for args in (['validate-coverage', '--list-findings'],
                     ['validate-coverage', '--trivy', self.source, '--coverage-manifest', self.source, '--list-findings'],
                     ['validate-coverage', '--list-findings', '--merged-sha256', digest(raw)],
                     [*self.args(), '--merged-sha256'], [*self.args(), 'synthetic-secret']):
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
            with self.assertRaises(vf.InputError):
                self.api(expected_sha256=digest(raw))
        self.source.unlink()
        self.reject()
        self.source.mkdir()
        self.reject()


if __name__ == '__main__':
    unittest.main()
