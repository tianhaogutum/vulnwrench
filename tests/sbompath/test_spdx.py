"""Synthetic integration cases for the bounded SPDX 2.3 projection."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from vulnwrench.sbompath import InputError, explain, to_markdown

ROOT = Path(__file__).resolve().parents[2]


def fixture(name):
    return json.loads((ROOT / 'examples' / 'path' / name).read_text())


class SpdxTests(unittest.TestCase):
    def setUp(self):
        self.bom = fixture('bom.spdx.json')
        self.grype = fixture('grype.json')

    def test_equivalent_cyclonedx_witness_and_original_spdx_evidence(self):
        report = explain(self.bom, self.grype)
        cdx = explain(fixture('bom.json'), self.grype)
        ids = {'SPDXRef-app': 'app', 'SPDXRef-a': 'a', 'SPDXRef-b': 'b'}
        result = report['results'][0]
        self.assertEqual(result['status'], cdx['results'][0]['status'])
        self.assertEqual(result['affectedRootCount'], 1)
        witness = result['affectedRoots'][0]
        self.assertEqual(ids[witness['root']], cdx['roots'][0])
        self.assertEqual([ids[ref] for ref in witness['path']], ['app', 'a', 'b'])
        self.assertEqual(result['join']['method'], 'exact-purl')
        self.assertEqual(report['graph']['edgeCount'], 2)
        self.assertEqual(report['provenance']['inferredEdges'], 0)
        self.assertEqual(report['provenance']['bomFormat'], 'SPDX')
        self.assertEqual(report['evidence']['bom'], self.bom)
        report['evidence']['bom']['packages'].clear()
        self.assertEqual(len(self.bom['packages']), 3)

    def test_describes_root_and_explicit_roots_override_union(self):
        self.bom['relationships'].append({'spdxElementId': 'SPDXRef-DOCUMENT',
            'relationshipType': 'DESCRIBES', 'relatedSpdxElement': 'SPDXRef-a'})
        report = explain(self.bom, self.grype)
        self.assertEqual(report['roots'], ['SPDXRef-a', 'SPDXRef-app'])
        self.assertEqual(report['results'][0]['affectedRootCount'], 2)
        del self.bom['documentDescribes']
        report = explain(self.bom, self.grype)
        self.assertEqual(report['results'][0]['affectedRoots'],
                         [{'root': 'SPDXRef-a', 'path': ['SPDXRef-a', 'SPDXRef-b']}])
        report = explain(self.bom, self.grype, roots=['SPDXRef-b'])
        self.assertEqual(report['provenance']['rootSelection'], 'explicit')
        self.assertEqual(report['results'][0]['affectedRoots'][0]['path'], ['SPDXRef-b'])

    def test_missing_root_is_unknown_and_no_indegree_root_inference(self):
        del self.bom['documentDescribes']
        for roots in (None, []):
            report = explain(self.bom, self.grype, roots=roots)
            self.assertEqual(report['roots'], [])
            self.assertEqual(report['results'][0]['status'], 'roots_unknown')
            self.assertIsNone(report['results'][0]['affectedRootCount'])
        with self.assertRaises(InputError):
            explain(self.bom, self.grype, roots=['SPDXRef-absent'])

    def test_dependency_markers_and_no_root_fixture_preserve_completeness_evidence(self):
        for name, status, count in (
            ('markers.spdx.json', 'reachable', 1),
            ('markers-no-roots.spdx.json', 'roots_unknown', None),
        ):
            with self.subTest(fixture=name):
                bom = fixture(name)
                report = explain(bom, self.grype)
                self.assertEqual(report['evidence']['bom'], bom)
                self.assertEqual(report['graph']['nodeCount'], 3)
                self.assertEqual(report['graph']['edgeCount'], 2)
                self.assertEqual(report['graph']['danglingDependencies'], [])
                self.assertEqual(report['graph']['missingDependencyDeclarations'], [])
                self.assertEqual(report['provenance']['inferredEdges'], 0)
                result = report['results'][0]
                self.assertEqual((result['status'], result['affectedRootCount']), (status, count))
                self.assertEqual(result['affectedRoots'], [
                    {'root': 'SPDXRef-app', 'path': ['SPDXRef-app', 'SPDXRef-a', 'SPDXRef-b']}
                ] if count else [])
                self.assertEqual(report['roots'], ['SPDXRef-app'] if count else [])
                diagnostics = [w for w in report['warnings'] if w['code'].startswith('spdx_dependency_')]
                self.assertEqual([(w['code'], w['relationshipIndex'], w['relationshipType'], w['from'], w['to'])
                                  for w in diagnostics], [
                    ('spdx_dependency_none', 2, 'DEPENDS_ON', 'SPDXRef-b', 'NONE'),
                    ('spdx_dependency_noassertion', 3, 'DEPENDS_ON', 'SPDXRef-app', 'NOASSERTION'),
                ])
                self.assertIn('asserts no dependencies', diagnostics[0]['message'])
                self.assertIn('unknown', diagnostics[1]['message'])
                md = to_markdown(report)
                self.assertIn('NONE', md)
                self.assertIn('NOASSERTION', md)

    def test_marker_only_declarations_never_create_edges_or_roots(self):
        for marker in ('NONE', 'NOASSERTION'):
            for rooted in (True, False):
                with self.subTest(marker=marker, rooted=rooted):
                    bom = copy.deepcopy(self.bom)
                    bom['relationships'] = [{'spdxElementId': 'SPDXRef-app',
                        'relationshipType': 'DEPENDS_ON', 'relatedSpdxElement': marker}]
                    if not rooted:
                        del bom['documentDescribes']
                    report = explain(bom, self.grype)
                    self.assertEqual(report['graph']['edgeCount'], 0)
                    self.assertEqual(report['provenance']['inferredEdges'], 0)
                    self.assertEqual(report['graph']['missingDependencyDeclarations'], ['SPDXRef-a', 'SPDXRef-b'])
                    result = report['results'][0]
                    self.assertEqual(result['status'], 'unreachable' if rooted else 'roots_unknown')
                    self.assertEqual(result['affectedRootCount'], 0 if rooted else None)
                    self.assertEqual(result['affectedRoots'], [])
                    self.assertEqual(report['roots'], ['SPDXRef-app'] if rooted else [])

    def test_markers_do_not_suppress_declared_edges_or_infer_completeness(self):
        before = explain(self.bom, self.grype)
        self.assertEqual(before['graph']['missingDependencyDeclarations'], ['SPDXRef-b'])
        # Even a NONE assertion must not delete an independently declared edge.
        for marker in ('NONE', 'NOASSERTION'):
            bom = copy.deepcopy(self.bom)
            bom['relationships'].insert(0, {'spdxElementId': 'SPDXRef-app',
                'relationshipType': 'DEPENDS_ON', 'relatedSpdxElement': marker})
            report = explain(bom, self.grype)
            self.assertEqual(report['results'], before['results'])
            self.assertEqual(report['graph'], before['graph'])
            bom['relationships'].reverse()
            self.assertEqual(explain(bom, self.grype)['results'], before['results'])

    def test_marker_acceptance_does_not_relax_endpoint_or_root_validation(self):
        for marker in ('NONE', 'NOASSERTION'):
            cases = [
                {'spdxElementId': source, 'relationshipType': 'DEPENDS_ON', 'relatedSpdxElement': marker}
                for source in (marker, 'SPDXRef-missing', 'SPDXRef-DOCUMENT', 'SPDXRef-file')
            ] + [
                {'spdxElementId': 'SPDXRef-app', 'relationshipType': 'DEPENDS_ON', 'relatedSpdxElement': target}
                for target in ('none', 'noassertion', ' NONE', 'NOASSERTION ', 'SPDXRef-NONE',
                               'SPDXRef-missing', 'DocumentRef-other:SPDXRef-a', None)
            ] + [
                {'spdxElementId': 'SPDXRef-DOCUMENT', 'relationshipType': 'DESCRIBES', 'relatedSpdxElement': marker},
            ]
            for relationship in cases:
                bom = copy.deepcopy(self.bom)
                bom['files'] = [{'SPDXID': 'SPDXRef-file'}]
                bom['relationships'] = [relationship]
                with self.subTest(relationship=relationship), self.assertRaises(InputError):
                    explain(bom, self.grype)
            bom = fixture('markers-no-roots.spdx.json')
            with self.assertRaises(InputError):
                explain(bom, self.grype, roots=[marker])
            bom['documentDescribes'] = [marker]
            with self.assertRaises(InputError):
                explain(bom, self.grype)

    def test_cli_marker_fixtures_and_invalid_source_preserve_output(self):
        args = [sys.executable, '-m', 'vulnwrench', 'path', 'explain']
        for name, status in (('markers.spdx.json', 'reachable'),
                             ('markers-no-roots.spdx.json', 'roots_unknown')):
            for format in ('json', 'markdown'):
                with self.subTest(fixture=name, format=format):
                    proc = subprocess.run(args + [str(ROOT / 'examples' / 'path' / name), '--grype',
                        'examples/path/grype.json', '--format', format], cwd=ROOT,
                        capture_output=True, text=True, timeout=60)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    if format == 'json':
                        self.assertEqual(json.loads(proc.stdout)['results'][0]['status'], status)
                    else:
                        self.assertIn(status.replace('_', r'\_'), proc.stdout)
                        self.assertIn('NOASSERTION', proc.stdout)
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            source, out = Path(directory) / 'bad.json', Path(directory) / 'out.json'
            bom = fixture('markers.spdx.json')
            bom['relationships'][2]['spdxElementId'] = 'SPDXRef-SECRET'
            source.write_text(json.dumps(bom))
            out.write_text('original')
            proc = subprocess.run(args + [str(source), '--grype', 'examples/path/grype.json',
                '--output', str(out)], cwd=ROOT, capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(proc.stdout, '')
            self.assertNotIn('SECRET', proc.stderr)
            self.assertIn('endpoint', proc.stderr)
            self.assertEqual(out.read_text(), 'original')

    def test_contains_marker_fixtures_preserve_witnesses_and_indexed_meaning(self):
        for name, rooted in (('contains-markers.spdx.json', True),
                             ('contains-markers-no-roots.spdx.json', False)):
            with self.subTest(fixture=name):
                bom = fixture(name)
                original = copy.deepcopy(bom)
                baseline = copy.deepcopy(bom)
                baseline['relationships'] = baseline['relationships'][1:3]
                before = explain(baseline, self.grype)
                report = explain(bom, self.grype)
                self.assertEqual(report['results'], before['results'])
                self.assertEqual(report['graph'], before['graph'])
                self.assertEqual(report['graph']['nodeCount'], 3)
                self.assertEqual(report['graph']['edgeCount'], 2)
                self.assertEqual(report['graph']['missingDependencyDeclarations'], ['SPDXRef-b'])
                self.assertEqual(report['provenance']['inferredEdges'], 0)
                self.assertEqual(report['roots'], ['SPDXRef-app'] if rooted else [])
                result = report['results'][0]
                self.assertEqual((result['status'], result['affectedRootCount']),
                                 ('reachable', 1) if rooted else ('roots_unknown', None))
                self.assertEqual(result['affectedRoots'], [{'root': 'SPDXRef-app',
                    'path': ['SPDXRef-app', 'SPDXRef-a', 'SPDXRef-b']}] if rooted else [])
                diagnostics = [w for w in report['warnings'] if w['code'] == 'spdx_relationship_not_projected']
                self.assertEqual([(w['relationshipIndex'], w['relationshipType'], w['from'], w['to'])
                                  for w in diagnostics], [
                    (0, 'CONTAINS', 'SPDXRef-app', 'NONE'),
                    (3, 'CONTAINS', 'SPDXRef-app', 'NOASSERTION'),
                ])
                self.assertIn('asserts no contained elements', diagnostics[0]['message'])
                self.assertIn('not independently verified', diagnostics[0]['message'])
                self.assertIn('unknown', diagnostics[1]['message'])
                self.assertFalse(any(w['code'].startswith('spdx_dependency_') for w in report['warnings']))
                self.assertEqual(report['evidence']['bom'], original)
                self.assertEqual(bom, original)
                bom['relationships'].reverse()
                self.assertEqual(explain(bom, self.grype)['results'], before['results'])

    def test_contains_marker_only_never_declares_dependencies_or_roots(self):
        for marker in ('NONE', 'NOASSERTION'):
            for rooted in (True, False):
                for source in ('SPDXRef-app', 'SPDXRef-DOCUMENT', 'SPDXRef-file', 'SPDXRef-snippet'):
                    with self.subTest(marker=marker, rooted=rooted, source=source):
                        bom = copy.deepcopy(self.bom)
                        bom['files'] = [{'SPDXID': 'SPDXRef-file'}]
                        bom['snippets'] = [{'SPDXID': 'SPDXRef-snippet'}]
                        bom['relationships'] = [{'spdxElementId': source,
                            'relationshipType': 'CONTAINS', 'relatedSpdxElement': marker}]
                        if not rooted:
                            del bom['documentDescribes']
                        report = explain(bom, self.grype)
                        self.assertEqual(report['graph']['edgeCount'], 0)
                        self.assertEqual(report['graph']['nodeCount'], 3)
                        self.assertEqual(report['graph']['danglingDependencies'], [])
                        self.assertEqual(report['graph']['missingDependencyDeclarations'],
                                         ['SPDXRef-a', 'SPDXRef-app', 'SPDXRef-b'])
                        self.assertEqual(report['provenance']['inferredEdges'], 0)
                        self.assertEqual(report['roots'], ['SPDXRef-app'] if rooted else [])
                        result = report['results'][0]
                        self.assertEqual((result['status'], result['affectedRootCount']),
                                         ('unreachable', 0) if rooted else ('roots_unknown', None))
                        self.assertEqual(result['affectedRoots'], [])

    def test_contains_markers_do_not_bypass_endpoint_or_inventory_validation(self):
        for marker in ('NONE', 'NOASSERTION'):
            cases = [
                {'spdxElementId': source, 'relationshipType': 'CONTAINS', 'relatedSpdxElement': marker}
                for source in (None, '', 'NONE', 'NOASSERTION', 'none', 'SPDXRef-missing',
                               'not-an-id', 'DocumentRef-other:SPDXRef-app')
            ] + [
                {'spdxElementId': 'SPDXRef-app', 'relationshipType': 'CONTAINS', 'relatedSpdxElement': target}
                for target in (None, '', 'none', 'noassertion', ' NONE', 'NOASSERTION ',
                               'SPDXRef-NONE', 'SPDXRef-missing', 'DocumentRef-other:SPDXRef-a')
            ] + [
                {'spdxElementId': 'SPDXRef-app', 'relationshipType': kind, 'relatedSpdxElement': marker}
                for kind in ('DEPENDENCY_OF', 'DESCRIBED_BY', 'BUILD_DEPENDENCY_OF', 'contains')
            ]
            for relationship in cases:
                bom = copy.deepcopy(self.bom)
                bom['relationships'] = [relationship]
                with self.subTest(relationship=relationship), self.assertRaises(InputError):
                    explain(bom, self.grype)
            for mutate in (
                lambda b: b['packages'].append(copy.deepcopy(b['packages'][0])),
                lambda b: b.update(files=[{'SPDXID': 'SPDXRef-app'}]),
                lambda b: b.update(snippets=[{}]),
                lambda b: b['packages'][0].update(SPDXID=marker),
            ):
                bom = fixture('contains-markers.spdx.json')
                mutate(bom)
                with self.subTest(marker=marker, mutation=mutate), self.assertRaises(InputError):
                    explain(bom, self.grype)

    def test_cli_contains_marker_pairs_match_api_json_and_markdown(self):
        args = [sys.executable, '-m', 'vulnwrench', 'path', 'explain']
        for name in ('contains-markers.spdx.json', 'contains-markers-no-roots.spdx.json'):
            for format in ('json', 'markdown'):
                with self.subTest(fixture=name, format=format):
                    proc = subprocess.run(args + [str(ROOT / 'examples' / 'path' / name), '--grype',
                        'examples/path/grype.json', '--format', format], cwd=ROOT,
                        capture_output=True, text=True, timeout=60)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    expected = explain(fixture(name), self.grype)
                    if format == 'json':
                        self.assertEqual(json.loads(proc.stdout), expected)
                    else:
                        self.assertEqual(proc.stdout, to_markdown(expected))
                        self.assertIn('NONE', proc.stdout)
                        self.assertIn('NOASSERTION', proc.stdout)
                        self.assertIn('unknown', proc.stdout)

    def test_cli_contains_invalid_endpoints_preserve_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            source, out = Path(directory) / 'bad.json', Path(directory) / 'out.json'
            for marker in ('NONE', 'NOASSERTION'):
                for field, value in (('spdxElementId', 'SPDXRef-SECRET'),
                                     ('spdxElementId', 'DocumentRef-SECRET:SPDXRef-app'),
                                     ('spdxElementId', marker),
                                     ('relatedSpdxElement', 'SPDXRef-SECRET'),
                                     ('relatedSpdxElement', 'DocumentRef-SECRET:SPDXRef-b')):
                    with self.subTest(marker=marker, field=field, value=value):
                        bom = fixture('contains-markers.spdx.json')
                        bom['relationships'][0]['relatedSpdxElement'] = marker
                        bom['relationships'][0][field] = value
                        source.write_text(json.dumps(bom))
                        out.write_text('original')
                        proc = subprocess.run([sys.executable, '-m', 'vulnwrench', 'path', 'explain',
                            str(source), '--grype', 'examples/path/grype.json', '--output', str(out)],
                            cwd=ROOT, capture_output=True, text=True, timeout=60)
                        self.assertEqual(proc.returncode, 2)
                        self.assertEqual(proc.stdout, '')
                        self.assertNotIn('SECRET', proc.stderr)
                        self.assertIn('endpoint', proc.stderr)
                        self.assertEqual(out.read_text(), 'original')

    def test_unsupported_relationships_are_indexed_diagnostics_not_edges(self):
        self.bom['relationships'] = [
            {'spdxElementId': 'SPDXRef-app', 'relationshipType': kind,
             'relatedSpdxElement': 'SPDXRef-b', 'comment': '<untrusted>|note'}
            for kind in ('CONTAINS', 'DEPENDENCY_OF', 'BUILD_DEPENDENCY_OF', 'DESCRIBED_BY')]
        report = explain(self.bom, self.grype)
        self.assertEqual(report['graph']['edgeCount'], 0)
        self.assertEqual(report['results'][0]['status'], 'unreachable')
        diagnostics = [w for w in report['warnings'] if w['code'] == 'spdx_relationship_not_projected']
        self.assertEqual([w['relationshipIndex'] for w in diagnostics], [0, 1, 2, 3])
        self.assertEqual([w['relationshipType'] for w in diagnostics],
                         ['CONTAINS', 'DEPENDENCY_OF', 'BUILD_DEPENDENCY_OF', 'DESCRIBED_BY'])
        self.assertIn('BUILD', to_markdown(report))
        self.assertEqual(report['evidence']['bom']['relationships'], self.bom['relationships'])

    def test_explicit_identity_mapping_without_purl_and_no_name_guessing(self):
        self.bom['packages'][2].pop('externalRefs')
        self.assertEqual(explain(self.bom, self.grype)['results'][0]['status'], 'unmapped')
        mapping = {'schemaVersion': 1, 'artifacts': {'grype-b': ['SPDXRef-b']}}
        result = explain(self.bom, self.grype, mapping=mapping)['results'][0]
        self.assertEqual(result['join']['method'], 'explicit-artifact-id')
        self.assertEqual(result['affectedRoots'][0]['path'], ['SPDXRef-app', 'SPDXRef-a', 'SPDXRef-b'])

    def test_equivalent_explicit_mappings_and_multiple_roots(self):
        cdx = fixture('bom.json')
        cdx['components'][1].pop('purl')
        self.bom['packages'][2].pop('externalRefs')
        cdx_report = explain(cdx, self.grype, roots=['app', 'a'],
            mapping={'schemaVersion': 1, 'artifacts': {'grype-b': ['b']}})
        spdx_report = explain(self.bom, self.grype, roots=['SPDXRef-app', 'SPDXRef-a'],
            mapping={'schemaVersion': 1, 'artifacts': {'grype-b': ['SPDXRef-b']}})
        ids = {'SPDXRef-app': 'app', 'SPDXRef-a': 'a', 'SPDXRef-b': 'b'}
        result = copy.deepcopy(spdx_report['results'][0])
        result['vulnerableRef'] = ids[result['vulnerableRef']]
        for entry in result['affectedRoots']:
            entry['root'] = ids[entry['root']]
            entry['path'] = [ids[ref] for ref in entry['path']]
        self.assertEqual(result, cdx_report['results'][0])

    def test_external_refs_only_use_package_manager_purl(self):
        package = self.bom['packages'][2]
        # Repeated identical identity assertions are harmless.
        package['externalRefs'].append(copy.deepcopy(package['externalRefs'][0]))
        self.assertEqual(explain(self.bom, self.grype)['results'][0]['status'], 'reachable')
        for external in package['externalRefs']:
            external['referenceCategory'] = 'OTHER'
        package['purl'] = 'pkg:npm/b@2.0'  # Not an SPDX identity field.
        report = explain(self.bom, self.grype)
        self.assertEqual(report['results'][0]['status'], 'unmapped')
        self.assertIn('SPDXRef-b', next(w['refs'] for w in report['warnings']
                                      if w['code'] == 'component_purls_missing'))

    def test_missing_relationships_warn_and_never_infer_from_package_order(self):
        del self.bom['relationships']
        report = explain(self.bom, self.grype)
        self.assertEqual(report['graph']['edgeCount'], 0)
        self.assertEqual(report['results'][0]['status'], 'unreachable')
        self.assertIn('spdx_relationships_absent', [w['code'] for w in report['warnings']])

    def test_duplicate_ids_including_nonpackage_inventory_are_rejected(self):
        for change in (
            lambda b: b['packages'].append(copy.deepcopy(b['packages'][0])),
            lambda b: b['packages'][0].update(SPDXID='SPDXRef-DOCUMENT'),
            lambda b: b.update(files=[{'SPDXID': 'SPDXRef-b'}]),
            lambda b: b.update(snippets=[{'SPDXID': 'SPDXRef-b'}]),
        ):
            bom = copy.deepcopy(self.bom)
            change(bom)
            with self.subTest(change=change), self.assertRaisesRegex(InputError, 'duplicate SPDXID'):
                explain(bom, self.grype)

    def test_missing_endpoints_do_not_bridge_packages(self):
        for index, field in ((0, 'relatedSpdxElement'), (1, 'spdxElementId'),
                             (2, 'relatedSpdxElement')):
            bom = copy.deepcopy(self.bom)
            bom['relationships'][index][field] = 'SPDXRef-missing'
            with self.subTest(index=index, field=field), self.assertRaisesRegex(InputError, 'endpoint'):
                explain(bom, self.grype)
        self.bom['documentDescribes'] = ['SPDXRef-missing']
        with self.assertRaisesRegex(InputError, 'root'):
            explain(self.bom, self.grype)

    def test_nonpackage_relationships_retained_without_traversal(self):
        self.bom['files'] = [{'SPDXID': 'SPDXRef-file', 'fileName': 'fixture.txt', 'checksums': []}]
        self.bom['relationships'].append({'spdxElementId': 'SPDXRef-app',
            'relationshipType': 'CONTAINS', 'relatedSpdxElement': 'SPDXRef-file'})
        report = explain(self.bom, self.grype)
        self.assertEqual(report['graph']['nodeCount'], 3)
        self.bom['relationships'][-1]['relationshipType'] = 'DEPENDS_ON'
        with self.assertRaisesRegex(InputError, 'package'):
            explain(self.bom, self.grype)

    def test_duplicate_edges_and_input_order_do_not_change_witnesses(self):
        first = explain(self.bom, self.grype)
        self.bom['relationships'].append(copy.deepcopy(self.bom['relationships'][0]))
        self.bom['relationships'].reverse()
        self.bom['packages'].reverse()
        second = explain(self.bom, self.grype)
        self.assertEqual(first['results'], second['results'])
        self.assertEqual(first['graph'], second['graph'])

    def test_malformed_projection_fields_and_ambiguous_purls(self):
        mutations = [
            lambda b: b.update(spdxVersion='SPDX-2.2'),
            lambda b: b.pop('SPDXID'),
            lambda b: b.update(packages={}),
            lambda b: b['packages'][0].pop('SPDXID'),
            lambda b: b['packages'][0].update(SPDXID='not-an-spdx-id'),
            lambda b: b.update(documentDescribes='SPDXRef-app'),
            lambda b: b.update(relationships=None),
            lambda b: b['relationships'][0].pop('relatedSpdxElement'),
            lambda b: b['relationships'][0].update(relationshipType=None),
            lambda b: b['relationships'][0].update(relatedSpdxElement='DocumentRef-other:SPDXRef-a'),
            lambda b: b['packages'][2].update(externalRefs={}),
            lambda b: b['packages'][2]['externalRefs'][0].update(referenceLocator='not-a-purl'),
            lambda b: b['packages'][2]['externalRefs'].append({'referenceCategory': 'PACKAGE-MANAGER',
                'referenceType': 'purl', 'referenceLocator': 'pkg:npm/different@1'}),
        ]
        for mutate in mutations:
            bom = copy.deepcopy(self.bom)
            mutate(bom)
            with self.subTest(mutation=mutate), self.assertRaises(InputError):
                explain(bom, self.grype)

    def test_cli_json_markdown_and_failure_preserves_output(self):
        args = [sys.executable, '-m', 'vulnwrench', 'path', 'explain', 'examples/path/bom.spdx.json',
                '--grype', 'examples/path/grype.json']
        proc = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report['results'][0]['affectedRoots'][0]['path'],
                         ['SPDXRef-app', 'SPDXRef-a', 'SPDXRef-b'])
        md = subprocess.run(args + ['--format', 'markdown'], cwd=ROOT,
                            capture_output=True, text=True, timeout=60)
        self.assertEqual(md.returncode, 0, md.stderr)
        self.assertIn('SPDXRef-app → SPDXRef-a → SPDXRef-b', md.stdout)
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            source, out = Path(directory) / 'bad.json', Path(directory) / 'out.json'
            self.bom['relationships'][0]['relatedSpdxElement'] = 'SPDXRef-SECRET'
            source.write_text(json.dumps(self.bom))
            out.write_text('original')
            proc = subprocess.run(args[:4] + [str(source)] + args[5:] + ['--output', str(out)],
                                  cwd=ROOT, capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(proc.stdout, '')
            self.assertNotIn('SECRET', proc.stderr)
            self.assertIn('endpoint', proc.stderr)
            self.assertEqual(out.read_text(), 'original')


if __name__ == '__main__':
    unittest.main()
