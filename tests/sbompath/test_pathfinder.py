import copy
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

from vulnwrench.sbompath import InputError, explain, to_dot, to_markdown

ROOT = Path(__file__).resolve().parents[2]


def fixture(name):
    return json.loads((ROOT / 'examples' / 'path' / name).read_text())


def findings(*purls):
    return {'matches': [{'vulnerability': {'id': f'CVE-2099-{i:04}'},
                         'artifact': {'id': f'artifact-{i}', 'purl': purl}}
                        for i, purl in enumerate(purls)]}


def graph(refs, edges, root=None):
    bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.5',
           'components': [{'bom-ref': ref, 'purl': f'pkg:generic/{ref}@1'} for ref in refs],
           'dependencies': [{'ref': ref, 'dependsOn': edges.get(ref, [])} for ref in refs]}
    if root is not None:
        component = next(item for item in bom['components'] if item['bom-ref'] == root)
        bom['components'].remove(component)
        bom['metadata'] = {'component': component}
    return bom


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.bom = fixture('bom.json')
        self.grype = fixture('grype.json')

    def test_supported_versions_and_simple_witness(self):
        for version in ('1.4', '1.5', '1.6'):
            with self.subTest(version=version):
                self.bom['specVersion'] = version
                report = explain(self.bom, self.grype)
                result = report['results'][0]
                self.assertEqual(result['affectedRoots'], [{'root': 'app', 'path': ['app', 'a', 'b']}])
                self.assertEqual(result['vulnerabilityId'], 'CVE-2099-0001')
                self.assertEqual(report['provenance']['inferredEdges'], 0)
                self.assertEqual(report['summary']['activeFindings'], 1)

    def test_diamond_cycle_two_roots_multiversion_and_unmapped(self):
        report = explain(fixture('graph.json'), fixture('graph-grype.json'),
                         roots=['worker', 'app'], mapping=fixture('mapping.json'))
        results = {result['artifactId']: result for result in report['results']}
        self.assertEqual(results['v1']['affectedRoots'], [
            {'root': 'app', 'path': ['app', 'left', 'lib-v1']},
            {'root': 'worker', 'path': ['worker', 'lib-v1']}])
        self.assertEqual(results['v2']['affectedRoots'], [{'root': 'worker', 'path': ['worker', 'lib-v2']}])
        self.assertEqual(results['orphan-id']['status'], 'unreachable')
        self.assertEqual(results['absent']['status'], 'unmapped')
        self.assertEqual(results['unknown-artifact']['status'], 'unknown_identity')
        self.assertEqual(results['local-artifact']['join']['method'], 'explicit-artifact-id')
        self.assertEqual(report['summary']['unmappedFindings'], 2)
        self.assertTrue(report['graph']['cycles']['detected'])
        self.assertEqual(report['graph']['cycles']['backEdges'], [{'from': 'lib-v1', 'to': 'left'}])
        self.assertEqual(len(report['graph']['danglingDependencies']), 3)
        self.assertIn('orphan', report['graph']['missingDependencyDeclarations'])

    def test_missing_roots_are_unknown_not_unreachable(self):
        del self.bom['metadata']
        result = explain(self.bom, self.grype)['results'][0]
        self.assertEqual(result['status'], 'roots_unknown')
        self.assertIsNone(result['affectedRootCount'])
        explicit = explain(self.bom, self.grype, roots=['a'])['results'][0]
        self.assertEqual(explicit['affectedRoots'][0]['path'], ['a', 'b'])

    def test_explicit_roots_replace_metadata(self):
        report = explain(self.bom, self.grype, roots=['b', 'b'])
        self.assertEqual(report['roots'], ['b'])
        self.assertEqual(report['results'][0]['affectedRoots'][0]['path'], ['b'])

    def test_caps_preserve_counts_and_finding_records(self):
        bom = graph(['r1', 'r2', 'r3', 'v'], {'r1': ['v'], 'r2': ['v'], 'r3': ['v']})
        grype = findings('pkg:generic/v@1', 'pkg:generic/v@1')
        report = explain(bom, grype, roots=['r3', 'r1', 'r2'], max_roots=2, max_paths=1)
        self.assertEqual(len(report['results']), 2)
        self.assertEqual(report['summary']['witnessPaths'], 1)
        self.assertEqual(report['summary']['rootsOmitted'], 2)
        self.assertEqual(report['summary']['pathsOmitted'], 3)
        for result in report['results']:
            self.assertEqual(result['affectedRootCount'], 3)
            self.assertEqual(len(result['affectedRoots']), 2)
            self.assertEqual(result['truncation']['rootsOmitted'], 1)
        self.assertEqual(report['results'][1]['affectedRoots'][0]['pathOmittedReason'], 'max_paths')
        self.assertIn('output_truncated', [w['code'] for w in report['warnings']])

    def test_duplicate_purl_occurrences_are_not_conflated(self):
        self.bom['components'].append({'bom-ref': 'b-copy', 'purl': 'pkg:npm/b@2.0'})
        report = explain(self.bom, self.grype)
        self.assertEqual([r['vulnerableRef'] for r in report['results']], ['b', 'b-copy'])
        self.assertEqual([r['status'] for r in report['results']], ['reachable', 'unreachable'])
        self.assertTrue(all(r['join']['candidateCount'] == 2 for r in report['results']))

    def test_exact_purl_no_name_or_version_guessing(self):
        self.grype['matches'][0]['artifact']['purl'] = 'pkg:npm/b@2.1'
        self.assertEqual(explain(self.bom, self.grype)['results'][0]['status'], 'unmapped')
        del self.grype['matches'][0]['artifact']['purl']
        self.assertEqual(explain(self.bom, self.grype)['results'][0]['status'], 'unknown_identity')

    def test_explicit_mapping_overrides_purl_and_reports_unused(self):
        mapping = {'schemaVersion': 1, 'artifacts': {'grype-b': ['a'], 'unused': ['b']}}
        report = explain(self.bom, self.grype, mapping=mapping)
        self.assertEqual(report['results'][0]['vulnerableRef'], 'a')
        self.assertEqual(report['results'][0]['join']['method'], 'explicit-artifact-id')
        self.assertIn('unused_mapping', [w['code'] for w in report['warnings']])

    def test_nested_component_containment_adds_no_edges(self):
        self.bom['metadata']['component']['components'] = [
            {'bom-ref': 'nested', 'purl': 'pkg:generic/nested@1'}]
        report = explain(self.bom, findings('pkg:generic/nested@1'))
        self.assertEqual(report['results'][0]['status'], 'unreachable')
        self.assertEqual(report['graph']['edgeCount'], 2)

    def test_absent_dependencies_and_absent_depends_on_warn(self):
        del self.bom['dependencies']
        report = explain(self.bom, self.grype)
        self.assertEqual(report['graph']['edgeCount'], 0)
        self.assertIn('dependencies_absent', [w['code'] for w in report['warnings']])
        self.bom['dependencies'] = [{'ref': 'app'}]
        report = explain(self.bom, self.grype)
        self.assertIn('depends_on_absent', [w['code'] for w in report['warnings']])

    def test_dangling_node_never_bridges_known_nodes(self):
        self.bom['dependencies'] = [{'ref': 'app', 'dependsOn': ['missing']},
                                    {'ref': 'missing', 'dependsOn': ['b']}]
        report = explain(self.bom, self.grype)
        self.assertEqual(report['results'][0]['status'], 'unreachable')
        self.assertEqual(report['graph']['edgeCount'], 0)
        self.assertEqual(len(report['graph']['danglingDependencies']), 3)

    def test_self_cycle_and_root_is_target(self):
        bom = graph(['v'], {'v': ['v']}, root='v')
        report = explain(bom, findings('pkg:generic/v@1'))
        self.assertTrue(report['graph']['cycles']['detected'])
        self.assertEqual(report['results'][0]['affectedRoots'][0]['path'], ['v'])

    def test_deep_graph_does_not_recurse(self):
        refs = [f'n{i:04}' for i in range(1500)]
        bom = graph(refs, {refs[i]: [refs[i+1]] for i in range(len(refs)-1)}, root=refs[0])
        report = explain(bom, findings(f'pkg:generic/{refs[-1]}@1'))
        self.assertEqual(report['results'][0]['affectedRoots'][0]['path'], refs)

    def test_reproducible_order_and_tiebreak(self):
        bom = fixture('graph.json')
        grype = fixture('graph-grype.json')
        first = explain(bom, grype, roots=['worker', 'app'])
        self.assertEqual(first, explain(bom, grype, roots=['app', 'worker']))
        bom['components'].reverse()
        bom['dependencies'].reverse()
        for dependency in bom['dependencies']:
            dependency['dependsOn'].reverse()
        second = explain(bom, grype, roots=['app', 'worker'])
        # Evidence and digests intentionally describe exact input array ordering.
        self.assertEqual(first['results'], second['results'])
        self.assertEqual(first['graph'], second['graph'])

    def test_evidence_is_lossless_and_independent(self):
        self.bom['vendor:unknown'] = {'anything': [1, None, True]}
        self.grype['matches'][0]['vendor:unknown'] = ['not discarded']
        self.grype['ignoredMatches'] = [{'arbitrary': 'retained, not traversed'}]
        report = explain(self.bom, self.grype)
        self.assertEqual(report['evidence']['bom'], self.bom)
        self.assertEqual(report['evidence']['grype'], self.grype)
        self.assertEqual(report['summary']['ignoredFindings'], 1)
        report['evidence']['bom']['components'].clear()
        self.assertEqual(len(self.bom['components']), 2)

    def test_empty_reports_are_valid_but_incomplete(self):
        report = explain({'bomFormat': 'CycloneDX', 'specVersion': '1.4'}, {'matches': []})
        self.assertEqual(report['results'], [])
        self.assertIn('no_roots', [w['code'] for w in report['warnings']])

    def test_markdown_includes_witness_unmapped_and_escapes_content(self):
        self.grype['matches'][0]['vulnerability']['id'] = '<script>|bad\nname'
        report = explain(self.bom, self.grype)
        md = to_markdown(report)
        self.assertIn('app → a → b', md)
        self.assertIn('&lt;script&gt;\\|bad&#10;name', md)
        self.assertNotIn('<script>', md)
        md = to_markdown(explain(fixture('graph.json'), fixture('graph-grype.json')))
        self.assertIn('unknown\\_identity', md)
        self.assertIn('unmapped', md)
        self.assertIn('missing-node', md)

    def test_shortest_paths_against_independent_simple_path_oracle(self):
        rng = random.Random(64)
        refs = ['a', 'b', 'c', 'd', 'e', 'f']
        for trial in range(30):
            edges = {ref: [other for other in refs if rng.random() < .25] for ref in refs}
            bom = graph(refs, edges)
            report = explain(bom, findings(*(f'pkg:generic/{ref}@1' for ref in refs)), roots=['a', 'b'])
            for result in report['results']:
                target = result['vulnerableRef']
                expected = []
                for root in ['a', 'b']:
                    simple_paths = []
                    stack = [[root]]
                    while stack:
                        path = stack.pop()
                        if path[-1] == target:
                            simple_paths.append(path)
                        else:
                            stack.extend(path + [child] for child in edges[path[-1]] if child not in path)
                    if simple_paths:
                        expected.append({'root': root, 'path': min(simple_paths, key=lambda p: (len(p), p))})
                self.assertEqual(result['affectedRoots'], expected, f'trial {trial}')


class MarkdownRootSelectionTests(unittest.TestCase):
    def test_explicit_empty_roots_differ_from_absent_roots_without_changing_results(self):
        for bom, grype in ((graph(['v'], {}), findings('pkg:generic/v@1')),
                           (fixture('markers-no-roots.spdx.json'), fixture('grype.json'))):
            with self.subTest(format=bom.get('spdxVersion', bom.get('bomFormat'))):
                absent = explain(bom, grype, finding_indexes=[0])
                explicit = explain(bom, grype, roots=[], finding_indexes=[0])
                before = copy.deepcopy(explicit)
                md = to_markdown(explicit)
                scope = 'Roots selected explicitly: (none).\n\n'
                self.assertEqual(md.count(scope), 1)
                self.assertEqual(md.replace(scope, ''), to_markdown(absent))
                self.assertIn('Roots: (unknown). Inferred edges: 0.', md)
                self.assertIn('Selected original finding indexes (Grype matches, zero-based): 0.', md)
                self.assertIn('finding 0: roots\\_unknown', md)
                self.assertNotIn('unreachable', md)
                self.assertEqual(explicit['results'], absent['results'])
                self.assertIsNone(explicit['results'][0]['affectedRootCount'])
                self.assertEqual(explicit['results'][0]['affectedRoots'], [])
                self.assertEqual(explicit['evidence'], absent['evidence'])
                self.assertEqual(explicit['provenance']['inputDigests'], absent['provenance']['inputDigests'])
                self.assertEqual(explicit, before)

    def test_explicit_roots_are_canonical_full_scope_under_caps_and_escape_refs(self):
        report = explain(fixture('graph.json'), fixture('graph-grype.json'),
                         roots=['worker', 'app', 'worker'], finding_indexes=[0, 1],
                         max_roots=1, max_paths=1)
        before = copy.deepcopy(report)
        md = to_markdown(report)
        scope = 'Roots selected explicitly: app, worker.'
        self.assertEqual(md.count(scope), 1)
        self.assertLess(md.index('Roots:'), md.index(scope))
        self.assertLess(md.index(scope), md.index('Selected original finding indexes'))
        self.assertLess(md.index(scope), md.index('| Vulnerability |'))
        self.assertIn('Finding 0: 1 affected roots omitted.', md)
        self.assertIn('Witness paths: 1; roots omitted: 1; paths omitted: 1.', md)
        self.assertEqual(report['results'][0]['affectedRootCount'], 2)
        self.assertEqual(report, before)
        hostile = '<r>|*`[x]\\\r\n'
        report = explain(graph([hostile], {}), {'matches': []}, roots=[hostile, hostile])
        escaped = '&lt;r&gt;\\|\\*\\`\\[x\\]\\\\&#13;&#10;'
        self.assertIn(f'Roots selected explicitly: {escaped}.\n\n', to_markdown(report))
        self.assertNotIn('<r>', to_markdown(report))

    def test_declared_roots_have_no_explicit_scope_even_with_finding_selection(self):
        for name in ('bom.json', 'bom.spdx.json'):
            with self.subTest(fixture=name):
                report = explain(fixture(name), fixture('grype.json'), finding_indexes=[])
                md = to_markdown(report)
                self.assertNotIn('Roots selected explicitly:', md)
                self.assertIn('Selected original finding indexes (Grype matches, zero-based): (none).', md)
                self.assertNotEqual(report['provenance']['rootSelection'], 'explicit')


class MarkdownSelectionTests(unittest.TestCase):
    def test_explicit_scope_uses_original_deduplicated_indexes_and_full_input_count(self):
        for indexes, selected, results in (([1], '1', 1), ([1, 1], '1', 1),
                                            ([1, 0, 1], '0, 1', 2)):
            with self.subTest(indexes=indexes):
                report = explain(fixture('graph.json'), fixture('graph-grype.json'),
                                 roots=['app', 'worker'], finding_indexes=indexes,
                                 max_roots=1, max_paths=1)
                before = copy.deepcopy(report)
                md = to_markdown(report)
                scope = (f'Selected original finding indexes (Grype matches, zero-based): {selected}. '
                         f'Total active input findings: 6; selected results: {results}.')
                self.assertEqual(md.count(scope), 1)
                self.assertLess(md.index('Roots:'), md.index(scope))
                self.assertLess(md.index(scope), md.index('| Vulnerability |'))
                self.assertEqual(report, before)
                if selected == '1':
                    self.assertIn('finding 1: reachable', md)
                    self.assertIn('worker → lib-v2', md)
                    self.assertNotIn('finding 0:', md)
                else:
                    self.assertEqual(report['results'][0]['affectedRootCount'], 2)
                    self.assertIn('Finding 0: 1 affected roots omitted.', md)
                    self.assertIn('Witness paths: 1; roots omitted: 1; paths omitted: 1.', md)
                for digest in report['provenance']['inputDigests'].values():
                    if digest:
                        self.assertIn(digest, md)

    def test_explicit_empty_finding_scope_preserves_explicit_root_example(self):
        bom, grype = fixture('graph.json'), fixture('graph-grype.json')
        default = explain(bom, grype, roots=['app', 'worker'], mapping=fixture('mapping.json'))
        self.assertEqual(to_markdown(default), (ROOT / 'examples/path/graph.md').read_text())
        self.assertNotIn('Selected original finding indexes', to_markdown(default))
        empty = explain(bom, grype, roots=['app', 'worker'], mapping=fixture('mapping.json'),
                        finding_indexes=[])
        md = to_markdown(empty)
        self.assertIn('Selected original finding indexes (Grype matches, zero-based): (none). '
                      'Total active input findings: 6; selected results: 0.', md)
        self.assertIn('Roots: app, worker.', md)
        self.assertNotIn('| finding ', md)
        self.assertNotIn('finding 0:', md)
        self.assertIn('Witness paths: 0; roots omitted: 0; paths omitted: 0.', md)
        self.assertEqual(empty['evidence'], default['evidence'])
        self.assertEqual(empty['provenance']['inputDigests'], default['provenance']['inputDigests'])

    def test_scope_counts_candidate_results_and_preserves_escaping(self):
        bom, grype = fixture('bom.json'), fixture('grype.json')
        bom['components'].append({'bom-ref': 'b-copy', 'purl': 'pkg:npm/b@2.0'})
        grype['matches'][0]['vulnerability']['id'] = '<script>|bad\nname'
        report = explain(bom, grype, finding_indexes=[0, 0], max_paths=1)
        before = copy.deepcopy(report)
        md = to_markdown(report)
        self.assertIn('Selected original finding indexes (Grype matches, zero-based): 0. '
                      'Total active input findings: 1; selected results: 2.', md)
        self.assertEqual(md.count('&lt;script&gt;\\|bad&#10;name'), 2)
        self.assertNotIn('<script>', md)
        self.assertIn('app → a → b', md)
        self.assertIn('unreachable', md)
        self.assertEqual(report, before)


class InvalidInputTests(unittest.TestCase):
    def setUp(self):
        self.bom = fixture('bom.json')
        self.grype = fixture('grype.json')

    def test_duplicate_ref(self):
        self.bom['components'].append({'bom-ref': 'app'})
        with self.assertRaisesRegex(InputError, 'duplicate bom-ref'):
            explain(self.bom, self.grype)

    def test_unsupported_version(self):
        self.bom['specVersion'] = '1.7'
        with self.assertRaisesRegex(InputError, 'unsupported'):
            explain(self.bom, self.grype)

    def test_root_absent(self):
        with self.assertRaisesRegex(InputError, 'root is absent'):
            explain(self.bom, self.grype, roots=['absent'])

    def test_malformed_containers_and_fields(self):
        mutations = [
            lambda b, g: b.update(dependencies={}),
            lambda b, g: b['dependencies'][0].update(dependsOn='a'),
            lambda b, g: b['dependencies'][0].update(dependsOn=[None]),
            lambda b, g: b.update(components=None),
            lambda b, g: b.update(metadata=None),
            lambda b, g: b['components'][0].pop('bom-ref'),
            lambda b, g: b['components'][0].update(purl=['pkg:npm/a@1']),
            lambda b, g: g.update(matches=None),
            lambda b, g: g['matches'][0].update(artifact=[]),
            lambda b, g: g['matches'][0]['vulnerability'].update(id=None),
            lambda b, g: g.update(ignoredMatches={}),
            lambda b, g: g.update(descriptor={'name': 'other-scanner'}),
            lambda b, g: b.update(bomFormat='SPDX'),
            lambda b, g: b.update(services=[{'bom-ref': 'service'}]),
            lambda b, g: b['dependencies'][0].update(provides=['b']),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                bom, grype = copy.deepcopy(self.bom), copy.deepcopy(self.grype)
                mutate(bom, grype)
                with self.assertRaises(InputError):
                    explain(bom, grype)

    def test_duplicate_dependency_declaration(self):
        self.bom['dependencies'].append({'ref': 'a', 'dependsOn': []})
        with self.assertRaisesRegex(InputError, 'duplicate dependency'):
            explain(self.bom, self.grype)

    def test_invalid_mappings(self):
        for mapping in ({}, {'schemaVersion': True, 'artifacts': {}},
                        {'schemaVersion': 1, 'artifacts': {'x': 'a'}},
                        {'schemaVersion': 1, 'artifacts': {'x': []}},
                        {'schemaVersion': 1, 'artifacts': {'x': ['missing']}}):
            with self.subTest(mapping=mapping), self.assertRaises(InputError):
                explain(self.bom, self.grype, mapping=mapping)

    def test_invalid_caps(self):
        for cap in (0, -1, True, 1.5, '2'):
            with self.subTest(cap=cap), self.assertRaises(InputError):
                explain(self.bom, self.grype, max_roots=cap)


class CliSelectionTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'path', *map(str, args)],
                              cwd=ROOT, capture_output=True, text=True, timeout=60)

    def setUp(self):
        self.args = ['explain', 'examples/path/graph.json', '--grype', 'examples/path/graph-grype.json',
                     '--mapping', 'examples/path/mapping.json', '--root', 'app', '--root', 'worker']
        self.bom, self.grype = fixture('graph.json'), fixture('graph-grype.json')

    def test_empty_selection_all_formats_match_api_and_keep_input_scope(self):
        expected = explain(self.bom, self.grype, mapping=fixture('mapping.json'),
                           roots=['app', 'worker'], finding_indexes=[], max_roots=1, max_paths=1)
        baseline = explain(self.bom, self.grype, mapping=fixture('mapping.json'),
                           roots=['app', 'worker'])
        self.assertEqual(expected['provenance']['selectedFindingIndexes'], [])
        self.assertEqual(expected['results'], [])
        self.assertEqual(expected['roots'], ['app', 'worker'])
        self.assertEqual(expected['summary'], dict(activeFindings=6, ignoredFindings=0, results=0,
            unmappedFindings=0, witnessPaths=0, rootsOmitted=0, pathsOmitted=0))
        for key in ('evidence', 'graph', 'warnings'):
            self.assertEqual(expected[key], baseline[key])
        self.assertEqual(expected['provenance']['inputDigests'], baseline['provenance']['inputDigests'])
        outputs = {'json': json.dumps(expected, sort_keys=True, indent=2, ensure_ascii=True,
                                      allow_nan=False) + '\n',
                   'markdown': to_markdown(expected), 'dot': to_dot(expected)}
        self.assertIn('Selected original finding indexes (Grype matches, zero-based): (none). '
                      'Total active input findings: 6; selected results: 0.', outputs['markdown'])
        self.assertIn('Roots: app, worker.', outputs['markdown'])
        from test_dot import parse_dot, refs_and_edges
        attrs, nodes, edges = parse_dot(outputs['dot'])
        self.assertEqual(refs_and_edges(nodes, edges), ({'app', 'worker'}, set()))
        self.assertEqual(json.loads(attrs['selected_findings']), [])
        self.assertEqual(json.loads(attrs['results_json']), [])
        self.assertEqual(attrs['truncated'], 'false')
        self.assertTrue(all(node['is_root'] == 'true' and node['is_affected'] == 'false'
                            for node in nodes.values()))
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            out = Path(directory) / 'report'
            for fmt, content in outputs.items():
                with self.subTest(format=fmt):
                    args = self.args + ['--format', fmt, '--no-findings',
                                        '--max-roots', '1', '--max-paths', '1']
                    proc = self.run_cli(*args)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertEqual(proc.stderr, '')
                    self.assertEqual(proc.stdout, content)
                    duplicate = self.run_cli(*args, '--no-findings')
                    self.assertEqual(duplicate.returncode, 0, duplicate.stderr)
                    self.assertEqual(duplicate.stdout, content)
                    out.write_text('original')
                    written = self.run_cli(*args, '--output', out)
                    self.assertEqual(written.returncode, 0, written.stderr)
                    self.assertEqual(written.stdout, '')
                    self.assertEqual(out.read_text(), content)

    def test_empty_selection_conflicts_and_dot_caps_preserve_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            out = Path(directory) / 'report'
            out.write_text('original')
            for fmt in ('json', 'markdown', 'dot'):
                cases = [(['--no-findings', '--finding-index', '1'], 'invalid command arguments'),
                         (['--finding-index', '1', '--no-findings'], 'invalid command arguments'),
                         (['--no-findings', '--no-findings', '--finding-index', '1',
                           '--finding-index', '1'], 'invalid command arguments'),
                         (['--no-findings', '--max-paths', '0'], 'invalid command arguments')]
                if fmt != 'dot':
                    cases.extend((['--no-findings', option, '1'], 'require DOT format')
                                 for option in ('--max-nodes', '--max-edges'))
                else:
                    cases.extend((['--no-findings', option, '0'], 'invalid command arguments')
                                 for option in ('--max-nodes', '--max-edges'))
                for options, error in cases:
                    with self.subTest(format=fmt, options=options):
                        proc = self.run_cli(*self.args, '--format', fmt, '--output', out, *options)
                        self.assertEqual(proc.returncode, 2)
                        self.assertEqual(proc.stdout, '')
                        self.assertIn(error, proc.stderr)
                        self.assertNotIn('Traceback', proc.stderr)
                        self.assertEqual(out.read_text(), 'original')
                        self.assertFalse(list(Path(directory).glob('.vulnwrench-path-*')))

    def test_empty_selection_still_validates_all_inputs(self):
        bad_grype = copy.deepcopy(self.grype)
        bad_grype['matches'][-1]['artifact'] = []
        bad_bom = copy.deepcopy(self.bom)
        bad_bom['dependencies'] = {}
        cases = [('--grype', bad_grype, 'grype.matches[5].artifact must be an object'),
                 ('--mapping', {'schemaVersion': 1, 'artifacts': {'absent': ['no-such-ref']}},
                  'mapping target is absent'),
                 ('bom', bad_bom, 'bom.dependencies must be an array'),
                 ('--grype', '{"matches":[],"matches":[]}', 'duplicate JSON object key')]
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            source, out = Path(directory) / 'bad.json', Path(directory) / 'report'
            out.write_text('original')
            for option, bad_input, error in cases:
                source.write_text(bad_input if isinstance(bad_input, str) else json.dumps(bad_input))
                args = list(self.args)
                if option == 'bom':
                    args[1] = source
                else:
                    args[args.index(option) + 1] = source
                for fmt in ('json', 'markdown', 'dot'):
                    with self.subTest(input=option, error=error, format=fmt):
                        proc = self.run_cli(*args, '--format', fmt, '--no-findings', '--output', out)
                        self.assertEqual(proc.returncode, 2)
                        self.assertEqual(proc.stdout, '')
                        self.assertIn(error, proc.stderr)
                        self.assertEqual(out.read_text(), 'original')
            for fmt in ('json', 'markdown', 'dot'):
                with self.subTest(root='invalid', format=fmt):
                    proc = self.run_cli(*self.args, '--format', fmt, '--no-findings',
                                        '--root', 'SECRET', '--output', out)
                    self.assertEqual(proc.returncode, 2)
                    self.assertIn('a selected root is absent', proc.stderr)
                    self.assertNotIn('SECRET', proc.stderr)
                    self.assertEqual(out.read_text(), 'original')

    def test_empty_selection_dot_caps_still_bound_root_context(self):
        expected = explain(self.bom, self.grype, mapping=fixture('mapping.json'),
                           roots=['app', 'worker'], finding_indexes=[])
        proc = self.run_cli(*self.args, '--format', 'dot', '--no-findings',
                            '--max-nodes', '1', '--max-edges', '1')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, to_dot(expected, max_nodes=1, max_edges=1))
        from test_dot import parse_dot, refs_and_edges
        attrs, nodes, edges = parse_dot(proc.stdout)
        self.assertEqual(refs_and_edges(nodes, edges), ({'app'}, set()))
        self.assertEqual(attrs['nodes_omitted'], '1')
        self.assertEqual(attrs['edges_omitted'], '0')
        self.assertEqual(attrs['truncated'], 'true')

    def test_later_selection_json_and_markdown_match_prebudget_api(self):
        expected = explain(self.bom, self.grype, mapping=fixture('mapping.json'),
                           roots=['app', 'worker'], finding_indexes=[1], max_paths=1)
        baseline = explain(self.bom, self.grype, mapping=fixture('mapping.json'),
                           roots=['app', 'worker'], max_paths=1)
        for fmt in ('json', 'markdown'):
            with self.subTest(format=fmt):
                args = self.args + ['--format', fmt, '--finding-index', '1', '--max-paths', '1']
                proc = self.run_cli(*args)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(proc.stderr, '')
                duplicate = self.run_cli(*args, '--finding-index', '1')
                self.assertEqual(duplicate.returncode, 0, duplicate.stderr)
                self.assertEqual(proc.stdout, duplicate.stdout)
                if fmt == 'markdown':
                    self.assertEqual(proc.stdout, to_markdown(expected))
                    self.assertIn('finding 1: reachable', proc.stdout)
                    self.assertIn('worker → lib-v2', proc.stdout)
                    self.assertNotIn('finding 0:', proc.stdout)
                    continue
                report = json.loads(proc.stdout)
                self.assertEqual(report, expected)
                self.assertEqual(report['provenance']['selectedFindingIndexes'], [1])
                self.assertEqual(report['evidence'], baseline['evidence'])
                self.assertEqual(report['provenance']['inputDigests'], baseline['provenance']['inputDigests'])
                self.assertEqual(report['summary'], dict(activeFindings=6, ignoredFindings=0, results=1,
                    unmappedFindings=0, witnessPaths=1, rootsOmitted=0, pathsOmitted=0))
                result, = report['results']
                self.assertEqual((result['findingIndex'], result['vulnerableRef'], result['status'],
                                  result['affectedRootCount']), (1, 'lib-v2', 'reachable', 1))
                self.assertEqual(result['affectedRoots'], [{'root': 'worker', 'path': ['worker', 'lib-v2']}])

    def test_selection_caps_keep_full_counts_and_share_one_budget(self):
        for indexes, max_roots, count, unmapped, roots_omitted, paths_omitted in (
                ([0, 0], 1, 1, 0, 1, 0), ([0, 1, 0], 100, 2, 0, 0, 2),
                ([1, 3, 5, 1], 100, 3, 2, 0, 0)):
            expected = explain(self.bom, self.grype, mapping=fixture('mapping.json'),
                               roots=['app', 'worker'], finding_indexes=indexes,
                               max_roots=max_roots, max_paths=1)
            for fmt in ('json', 'markdown'):
                with self.subTest(indexes=indexes, format=fmt):
                    options = [arg for index in indexes for arg in ('--finding-index', str(index))]
                    proc = self.run_cli(*self.args, '--format', fmt, '--max-roots', max_roots,
                                        '--max-paths', 1, *options)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    if fmt == 'markdown':
                        self.assertEqual(proc.stdout, to_markdown(expected))
                        continue
                    report = json.loads(proc.stdout)
                    self.assertEqual(report, expected)
                    self.assertEqual(report['summary'], dict(activeFindings=6, ignoredFindings=0,
                        results=count, unmappedFindings=unmapped, witnessPaths=1,
                        rootsOmitted=roots_omitted, pathsOmitted=paths_omitted))
                    if 0 in indexes:
                        self.assertEqual(report['results'][0]['affectedRootCount'], 2)

    def test_selection_invalid_indexes_and_dot_caps_preserve_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            out = Path(directory) / 'report'
            out.write_text('original')
            for fmt in ('json', 'markdown'):
                for options in (['--finding-index', '-1'], ['--finding-index', 'SECRET'],
                                ['--finding-index', '6'], ['--finding-index', '1', '--finding-index', '6'],
                                ['--finding-index', '1', '--max-nodes', '200'],
                                ['--finding-index', '1', '--max-edges', '400']):
                    with self.subTest(format=fmt, options=options):
                        proc = self.run_cli(*self.args, '--format', fmt, '--output', out, *options)
                        self.assertEqual(proc.returncode, 2)
                        self.assertEqual(proc.stdout, '')
                        self.assertNotIn('SECRET', proc.stderr)
                        self.assertNotIn('Traceback', proc.stderr)
                        self.assertEqual(out.read_text(), 'original')
                        self.assertFalse(list(Path(directory).glob('.vulnwrench-path-*')))

    def test_selection_still_validates_malformed_unselected_match(self):
        self.grype['matches'][0]['artifact'] = []
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            source, out = Path(directory) / 'grype.json', Path(directory) / 'report'
            source.write_text(json.dumps(self.grype))
            out.write_text('original')
            for fmt in ('json', 'markdown'):
                with self.subTest(format=fmt):
                    proc = self.run_cli(*self.args, '--grype', source, '--format', fmt,
                                        '--finding-index', '1', '--output', out)
                    self.assertEqual(proc.returncode, 2)
                    self.assertEqual(proc.stdout, '')
                    self.assertIn('grype.matches[0].artifact must be an object', proc.stderr)
                    self.assertEqual(out.read_text(), 'original')


class CliRootSelectionTests(unittest.TestCase):
    def setUp(self):
        self.bom, self.grype = fixture('graph.json'), fixture('graph-grype.json')
        self.args = ['explain', 'examples/path/graph.json', '--grype', 'examples/path/graph-grype.json',
                     '--mapping', 'examples/path/mapping.json']

    def run_cli(self, *args):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'path', *map(str, args)],
                              cwd=ROOT, capture_output=True, text=True, timeout=60)

    def rendered(self, report, fmt, **dot_caps):
        if fmt == 'json':
            return json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + '\n'
        return to_markdown(report) if fmt == 'markdown' else to_dot(report, **dot_caps)

    def test_markdown_explicit_root_scope_with_repeats_and_no_findings(self):
        for options, roots, indexes, scope in (
            (['--no-roots', '--no-roots', '--finding-index', '1'], [], [1], '(none)'),
            (['--no-roots', '--no-findings'], [], [], '(none)'),
            (['--root', 'worker', '--root', 'app', '--root', 'worker', '--finding-index', '1'],
             ['app', 'worker'], [1], 'app, worker'),
            (['--root', 'worker', '--root', 'app', '--no-findings'],
             ['app', 'worker'], [], 'app, worker')):
            with self.subTest(options=options):
                proc = self.run_cli(*self.args, *options, '--format', 'markdown',
                                    '--max-roots', '1', '--max-paths', '1')
                self.assertEqual((proc.returncode, proc.stderr), (0, ''))
                self.assertEqual(proc.stdout.count(f'Roots selected explicitly: {scope}.'), 1)
                expected = explain(self.bom, self.grype, mapping=fixture('mapping.json'),
                                   roots=roots, finding_indexes=indexes, max_roots=1, max_paths=1)
                self.assertEqual(proc.stdout, to_markdown(expected))
                selected = ', '.join(map(str, indexes)) or '(none)'
                self.assertIn(f'Selected original finding indexes (Grype matches, zero-based): {selected}.', proc.stdout)
                for digest in expected['provenance']['inputDigests'].values():
                    self.assertIn(digest, proc.stdout)

    def test_no_roots_all_formats_match_api_and_preserve_input_scope(self):
        expected = explain(self.bom, self.grype, mapping=fixture('mapping.json'), roots=[],
                           finding_indexes=[1], max_roots=1, max_paths=1)
        baseline = explain(self.bom, self.grype, mapping=fixture('mapping.json'), finding_indexes=[1])
        self.assertEqual(expected['roots'], [])
        self.assertEqual(expected['provenance']['rootSelection'], 'explicit')
        self.assertEqual(expected['provenance']['selectedFindingIndexes'], [1])
        self.assertIn('no_roots', [w['code'] for w in expected['warnings']])
        for key in ('evidence', 'graph'):
            self.assertEqual(expected[key], baseline[key])
        self.assertEqual(expected['provenance']['inputDigests'], baseline['provenance']['inputDigests'])
        result, = expected['results']
        self.assertEqual((result['findingIndex'], result['vulnerableRef'], result['status'],
                          result['affectedRootCount'], result['affectedRoots']),
                         (1, 'lib-v2', 'roots_unknown', None, []))
        self.assertEqual(expected['summary'], dict(activeFindings=6, ignoredFindings=0, results=1,
            unmappedFindings=0, witnessPaths=0, rootsOmitted=0, pathsOmitted=0))
        from test_dot import parse_dot, refs_and_edges
        _, nodes, edges = parse_dot(to_dot(expected))
        self.assertEqual(refs_and_edges(nodes, edges), ({'lib-v2'}, set()))
        self.assertTrue(all(n['is_root'] == 'false' for n in nodes.values()))
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            out = Path(directory) / 'report'
            for fmt in ('json', 'markdown', 'dot'):
                with self.subTest(format=fmt):
                    args = self.args + ['--no-roots', '--finding-index', '1', '--format', fmt,
                                        '--max-roots', '1', '--max-paths', '1']
                    content = self.rendered(expected, fmt)
                    for repeat in ([], ['--no-roots']):
                        proc = self.run_cli(*args, *repeat)
                        self.assertEqual(proc.returncode, 0, proc.stderr)
                        self.assertEqual(proc.stderr, '')
                        self.assertEqual(proc.stdout, content)
                    out.write_text('original')
                    proc = self.run_cli(*args, '--output', out)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertEqual(proc.stdout, '')
                    self.assertEqual(out.read_text(), content)

    def test_no_roots_all_or_no_findings_keeps_identity_and_dot_caps(self):
        from test_dot import parse_dot, refs_and_edges
        for indexes, options in ((None, []), ([], ['--no-findings'])):
            expected = explain(self.bom, self.grype, mapping=fixture('mapping.json'),
                               roots=[], finding_indexes=indexes)
            if indexes is None:
                by_index = {r['findingIndex']: r for r in expected['results']}
                self.assertEqual(by_index[3]['status'], 'unmapped')
                self.assertEqual(by_index[5]['status'], 'unknown_identity')
                self.assertEqual(by_index[4]['join']['method'], 'explicit-artifact-id')
                self.assertEqual(by_index[4]['status'], 'roots_unknown')
                self.assertTrue(all(r['affectedRootCount'] is None and not r['affectedRoots']
                                    for r in expected['results']))
            else:
                self.assertEqual(expected['results'], [])
                self.assertEqual(expected['provenance']['selectedFindingIndexes'], [])
            self.assertEqual(expected['summary']['activeFindings'], 6)
            for fmt in ('json', 'markdown', 'dot'):
                with self.subTest(indexes=indexes, format=fmt):
                    proc = self.run_cli(*self.args, '--no-roots', '--format', fmt, *options)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertEqual(proc.stdout, self.rendered(expected, fmt))
            proc = self.run_cli(*self.args, '--no-roots', '--format', 'dot', *options,
                                '--max-nodes', '1', '--max-edges', '1')
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, to_dot(expected, max_nodes=1, max_edges=1))
            attrs, nodes, edges = parse_dot(proc.stdout)
            self.assertFalse(edges)
            self.assertTrue(all(n['is_root'] == 'false' for n in nodes.values()))
            self.assertEqual(attrs['nodes_omitted'], '3' if indexes is None else '0')
            self.assertEqual(refs_and_edges(nodes, edges)[0], {'lib-v1'} if indexes is None else set())

    def test_no_roots_conflicts_and_invalid_options_preserve_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            out = Path(directory) / 'report'
            out.write_text('original')
            for fmt in ('json', 'markdown', 'dot'):
                cases = [(['--root', 'SECRET', '--no-roots'], 'invalid command arguments'),
                         (['--no-roots', '--root', 'SECRET'], 'invalid command arguments'),
                         (['--no-roots', '--no-roots', '--root', 'SECRET', '--root', 'SECRET'],
                          'invalid command arguments'),
                         (['--no-roots=SECRET'], 'invalid command arguments'),
                         (['--no-roots', '--root'], 'invalid command arguments'),
                         (['--no-roots', '--finding-index', '999'], 'a selected finding index is absent')]
                cases.extend((['--no-roots', cap, '0'], 'invalid command arguments')
                             for cap in ('--max-roots', '--max-paths', '--max-nodes', '--max-edges'))
                if fmt != 'dot':
                    cases.extend((['--no-roots', cap, '1'], 'require DOT format')
                                 for cap in ('--max-nodes', '--max-edges'))
                for options, error in cases:
                    with self.subTest(format=fmt, options=options):
                        proc = self.run_cli(*self.args, '--format', fmt, '--output', out, *options)
                        self.assertEqual(proc.returncode, 2)
                        self.assertEqual(proc.stdout, '')
                        self.assertIn(error, proc.stderr)
                        self.assertNotIn('SECRET', proc.stderr)
                        self.assertEqual(out.read_text(), 'original')
                        self.assertFalse(list(Path(directory).glob('.vulnwrench-path-*')))

    def test_no_roots_validates_inputs_and_protects_input_aliases(self):
        bad_grype = copy.deepcopy(self.grype)
        bad_grype['matches'][-1]['artifact'] = []
        bad_bom = copy.deepcopy(self.bom)
        bad_bom['dependencies'] = {}
        cases = [('--grype', bad_grype, 'grype.matches[5].artifact must be an object'),
                 ('--mapping', {'schemaVersion': 1, 'artifacts': {'unused': ['absent']}},
                  'mapping target is absent'),
                 ('bom', bad_bom, 'bom.dependencies must be an array'),
                 ('--grype', '{"matches":[],"matches":[]}', 'duplicate JSON object key')]
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            source, out = Path(directory) / 'input.json', Path(directory) / 'report'
            out.write_text('original')
            for option, value, error in cases:
                source.write_text(value if isinstance(value, str) else json.dumps(value))
                args = list(self.args)
                args[1 if option == 'bom' else args.index(option) + 1] = source
                for fmt in ('json', 'markdown', 'dot'):
                    for selection in (['--finding-index', '1'], ['--no-findings']):
                        with self.subTest(input=option, format=fmt, selection=selection):
                            proc = self.run_cli(*args, '--no-roots', '--format', fmt,
                                                *selection, '--output', out)
                            self.assertEqual(proc.returncode, 2)
                            self.assertEqual(proc.stdout, '')
                            self.assertIn(error, proc.stderr)
                            self.assertEqual(out.read_text(), 'original')
            source.write_text(json.dumps(self.bom))
            alias = Path(directory) / 'alias.json'
            os.link(source, alias)
            original = source.read_bytes()
            for fmt in ('json', 'markdown', 'dot'):
                for destination in (source, alias):
                    with self.subTest(format=fmt, destination=destination.name):
                        proc = self.run_cli('explain', source, '--grype', 'examples/path/graph-grype.json',
                                            '--no-roots', '--format', fmt, '--output', destination)
                        self.assertEqual(proc.returncode, 2)
                        self.assertIn('output must not overwrite an input', proc.stderr)
                        self.assertEqual(proc.stdout, '')
                        self.assertEqual(source.read_bytes(), original)
            self.assertFalse(list(Path(directory).glob('.vulnwrench-path-*')))


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'path', *map(str, args)],
                              cwd=ROOT, capture_output=True, text=True, timeout=60)

    def test_real_format_e2e_json_and_markdown(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            out = Path(directory) / 'report.json'
            proc = self.run_cli('explain', 'examples/path/bom.json', '--grype', 'examples/path/grype.json', '--output', out)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, '')
            result = json.loads(out.read_text())['results'][0]
            self.assertEqual(result['vulnerableRef'], 'b')
            self.assertEqual(result['affectedRoots'][0]['path'], ['app', 'a', 'b'])
            proc = self.run_cli('explain', 'examples/path/bom.json', '--grype', 'examples/path/grype.json', '--format', 'markdown')
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn('CVE-2099-0001', proc.stdout)
            self.assertIn('app → a → b', proc.stdout)

    def test_explicit_mapping_roots_and_truncation_e2e(self):
        args = ['explain', 'examples/path/graph.json', '--grype', 'examples/path/graph-grype.json',
                '--mapping', 'examples/path/mapping.json', '--root', 'app', '--root', 'worker',
                '--max-roots', '1', '--max-paths', '1']
        first, second = self.run_cli(*args), self.run_cli(*args)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        report = json.loads(first.stdout)
        self.assertEqual(report['summary']['witnessPaths'], 1)
        self.assertEqual(report['summary']['rootsOmitted'], 1)
        self.assertGreater(report['summary']['pathsOmitted'], 0)

    def test_invalid_file_does_not_echo_input_secrets(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / 'SECRET_FILENAME.json'
            for content in ('{"secret":"SUPER_SECRET",',
                            '{"matches":[],"matches":["SUPER_SECRET"]}',
                            '{"matches":[],"x":NaN}',
                            '{"matches":[{"vulnerability":{"id":"SUPER_SECRET"},"artifact":[]}]}'):
                path.write_text(content)
                proc = self.run_cli('explain', 'examples/path/bom.json', '--grype', path)
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stdout, '')
                self.assertNotIn('SECRET', proc.stderr)
                self.assertNotIn('Traceback', proc.stderr)

    def test_schema_errors_are_exit_two_and_do_not_create_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path, out = Path(directory) / 'bad.json', Path(directory) / 'out.json'
            for update in ({'dependencies': {}}, {'specVersion': '1.7'},
                           {'components': [{'bom-ref': 'app'}]}):
                bom = fixture('bom.json')
                bom.update(update)
                path.write_text(json.dumps(bom))
                proc = self.run_cli('explain', path, '--grype', 'examples/path/grype.json', '--output', out)
                self.assertEqual(proc.returncode, 2)
                self.assertFalse(out.exists())
            proc = self.run_cli('explain', 'examples/path/bom.json', '--grype', 'examples/path/grype.json', '--root', 'SECRET')
            self.assertEqual(proc.returncode, 2)
            self.assertNotIn('SECRET', proc.stderr)

    def test_io_errors_and_unsupported_text(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / 'input.xml'
            path.write_text('<bom>PRIVATE</bom>')
            cases = [self.run_cli('explain', path, '--grype', 'examples/path/grype.json'),
                     self.run_cli('explain', 'not-present', '--grype', 'examples/path/grype.json'),
                     self.run_cli('explain', 'examples/path/bom.json', '--grype', 'examples/path/grype.json', '--output', directory)]
            for proc in cases:
                self.assertEqual(proc.returncode, 2)
                self.assertNotIn('PRIVATE', proc.stderr)
                self.assertNotIn('Traceback', proc.stderr)
            self.assertFalse(list(Path(directory).glob('.vulnwrench-path-*')))

    def test_output_cannot_overwrite_input_or_hardlink(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / 'input.json'
            original = (ROOT / 'examples/path/bom.json').read_bytes()
            path.write_bytes(original)
            hardlink = Path(directory) / 'link.json'
            hardlink.hardlink_to(path)
            for out in (path, hardlink):
                proc = self.run_cli('explain', path, '--grype', 'examples/path/grype.json', '--output', out)
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(path.read_bytes(), original)

    def test_invalid_args_do_not_echo_values(self):
        for args in ([], ['explain', 'SECRET'],
                     ['explain', 'examples/path/bom.json', '--grype', 'examples/path/grype.json', '--max-paths', 'SECRET']):
            proc = self.run_cli(*args)
            self.assertEqual(proc.returncode, 2)
            self.assertNotIn('SECRET', proc.stderr)

    def test_input_size_and_depth_limits(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / 'oversize.json'
            with path.open('wb') as handle:
                handle.truncate(32 * 1024 * 1024 + 1)
            proc = self.run_cli('explain', path, '--grype', 'examples/path/grype.json')
            self.assertEqual(proc.returncode, 2)
            self.assertIn('32 MiB', proc.stderr)
            path.write_text('[' * 1500 + '0' + ']' * 1500)
            proc = self.run_cli('explain', path, '--grype', 'examples/path/grype.json')
            self.assertEqual(proc.returncode, 2)
            self.assertNotIn('Traceback', proc.stderr)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'requires POSIX FIFOs')
    def test_nonregular_input_is_rejected_without_waiting(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / 'input.fifo'
            os.mkfifo(path)
            proc = self.run_cli('explain', path, '--grype', 'examples/path/grype.json')
            self.assertEqual(proc.returncode, 2)
            self.assertIn('regular file', proc.stderr)

    def test_invalid_output_preserves_existing_file(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            source, out = Path(directory) / 'bad.json', Path(directory) / 'out.json'
            source.write_text('{invalid}')
            out.write_text('original output')
            proc = self.run_cli('explain', source, '--grype', 'examples/path/grype.json', '--output', out)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(out.read_text(), 'original output')
            self.assertFalse(list(Path(directory).glob('.vulnwrench-path-*')))

    def test_help_and_version(self):
        for args in (['--help'], ['explain', '--help'], ['--version']):
            self.assertEqual(self.run_cli(*args).returncode, 0)


if __name__ == '__main__':
    unittest.main()
