"""Synthetic DOT integration fixtures; no Graphviz/runtime dependency required."""
import copy
import json
import hashlib
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from vulnwrench.sbompath import InputError, explain
import vulnwrench.sbompath as sbom_pathfinder

ROOT = Path(__file__).resolve().parents[2]


def fixture(name):
    return json.loads((ROOT / 'examples' / 'path' / name).read_text())


def parse_dot(text):
    """Validate our strict DOT subset independently and decode quoted attributes.

    All IDs are generated identifiers, all values are quoted strings. Reject any
    unmatched syntax, raw newline/control in strings or injected statements.
    Decode label escapes separately from raw JSON metadata attributes, where
    Graphviz only removes escaped quotes. This is not a general-purpose parser.
    """
    quoted = r'"(?:[^"\\\x00-\x1f\x7f]|\\["\\nbfrtu])*"'
    pair = re.compile(r'([a-z_]+)=(' + quoted + r')(?:, |$)')
    statement = re.compile(r'  (graph|node|edge|n\d+(?: -> n\d+)?) \[(.*)\];')
    lines = text.splitlines()
    if lines[0] != 'digraph sbom_witnesses {' or lines[-1] != '}':
        raise AssertionError('invalid graph envelope')
    attrs, nodes, edges = {}, {}, []
    for line in lines[1:-1]:
        match = statement.fullmatch(line)
        if match is None:
            raise AssertionError('invalid statement: ' + line)
        target, body = match.groups()
        values = {}
        position = 0
        while position < len(body):
            attribute = pair.match(body, position)
            if attribute is None or attribute[1] in values:
                raise AssertionError('invalid attributes: ' + body)
            values[attribute[1]] = (attribute[2][1:-1].replace('\\"', '"')
                                    if attribute[1] in ('results_json', 'selected_roots_json', 'input_digests_json', 'dangling_dependencies_json', 'missing_dependency_declarations_json')
                                    else json.loads(attribute[2]))
            position = attribute.end()
        if target == 'graph':
            attrs.update(values)
        elif target in ('node', 'edge'):
            continue
        elif ' -> ' in target:
            edges.append((*target.split(' -> '), values))
        else:
            if target in nodes:
                raise AssertionError('duplicate node')
            nodes[target] = values
    if any(a not in nodes or b not in nodes for a, b, _ in edges):
        raise AssertionError('implicit nodes bypass output cap')
    return attrs, nodes, edges


def refs_and_edges(nodes, edges):
    return ({node['sbom_ref'] for node in nodes.values()},
            {(nodes[a]['sbom_ref'], nodes[b]['sbom_ref']) for a, b, _ in edges})


class DotTests(unittest.TestCase):
    def setUp(self):
        self.report = explain(fixture('graph.json'), fixture('graph-grype.json'),
                              roots=['worker', 'app'], mapping=fixture('mapping.json'))

    def render(self, report=None, **options):
        return sbom_pathfinder.to_dot(self.report if report is None else report, **options)

    def assert_finding_scope(self, text, indexes, active, count, emitted=None):
        attrs, nodes, edges = parse_dot(text)
        self.assertEqual(attrs.get('finding_selection'), 'explicit')
        self.assertEqual(json.loads(attrs['selected_finding_indexes_json']), indexes)
        self.assertEqual((attrs['active_findings'], attrs['selected_results']), (str(active), str(count)))
        display = ', '.join(map(str, indexes)) or '(none)'
        self.assertIn(f'Findings selected explicitly (zero-based): {display}. '
                      f'Total active input findings: {active}; selected results: {count}.', attrs['label'])
        self.assertEqual(len(json.loads(attrs['results_json'])), count)
        self.assertEqual(json.loads(attrs['selected_findings']), indexes if emitted is None else emitted)
        if emitted is not None and emitted != indexes:
            display = ', '.join(map(str, emitted)) or '(none)'
            self.assertIn(f'DOT findings emitted (zero-based): {display}.', attrs['label'])
        else:
            self.assertNotIn('DOT findings emitted', attrs['label'])
        return attrs, nodes, edges

    def test_finding_scope_original_indexes_empty_all_duplicates_and_default_contrast(self):
        bom, grype = fixture('graph.json'), fixture('graph-grype.json')
        for roots in (None, [], ['worker', 'app', 'worker']):
            default = explain(bom, grype, roots=roots)
            default_text = self.render(default)
            attrs, _, _ = parse_dot(default_text)
            for key in ('finding_selection', 'selected_finding_indexes_json', 'active_findings', 'selected_results'):
                self.assertNotIn(key, attrs)
            self.assertNotIn('Findings selected explicitly', attrs['label'])
            for indexes in ([1], [1, 1], [], [5, 3, 1, 0, 2, 4, 1]):
                with self.subTest(roots=roots, indexes=indexes):
                    report = explain(bom, grype, roots=roots, finding_indexes=indexes)
                    before = copy.deepcopy(report)
                    text = self.render(report)
                    self.assert_finding_scope(text, sorted(set(indexes)), 6, len(set(indexes)))
                    canonical = explain(bom, grype, roots=roots, finding_indexes=sorted(set(indexes)))
                    self.assertEqual(text, self.render(canonical))
                    self.assertEqual(text, self.render(report, finding_indexes=indexes))
                    self.assertNotEqual(text, default_text)
                    self.assertEqual(report['evidence'], default['evidence'])
                    self.assertEqual(report['provenance']['inputDigests'], default['provenance']['inputDigests'])
                    self.assertEqual(report, before)
        empty = explain(bom, {'matches': []}, finding_indexes=[])
        self.assert_finding_scope(self.render(empty), [], 0, 0)

    def test_finding_scope_formatter_filter_preserves_original_selection_and_counts_emitted(self):
        report = explain(fixture('graph.json'), fixture('graph-grype.json'), finding_indexes=[3, 0, 1, 0])
        before = copy.deepcopy(report)
        for indexes in ([1], [], [3, 1, 3]):
            with self.subTest(indexes=indexes):
                self.assert_finding_scope(self.render(report, finding_indexes=indexes),
                                          [0, 1, 3], 6, len(set(indexes)), sorted(set(indexes)))
        with self.assertRaises(InputError):
            self.render(report, finding_indexes=[2])
        self.assertEqual(report, before)
        # Without pre-budget selection, formatter-only scope uses its own explicit original indexes.
        for indexes in ([1, 1], []):
            self.assert_finding_scope(self.render(finding_indexes=indexes), sorted(set(indexes)), 6, len(set(indexes)))

    def test_finding_scope_counts_candidates_despite_node_root_path_caps(self):
        bom, grype = fixture('graph.json'), fixture('graph-grype.json')
        bom['components'].append({'bom-ref': 'lib-copy', 'purl': 'pkg:npm/lib@1.0'})
        # Use the exact fixture PURL, so both refs join one original finding.
        bom['components'][-1]['purl'] = grype['matches'][0]['artifact']['purl']
        for max_roots, max_paths in ((1, 1), (100, 1)):
            report = explain(bom, grype, roots=['worker', 'app'], finding_indexes=[0, 1],
                             max_roots=max_roots, max_paths=max_paths)
            before = copy.deepcopy(report)
            attrs, nodes, edges = self.assert_finding_scope(
                self.render(report, max_nodes=1, max_edges=1), [0, 1], 6, 3)
            self.assertEqual(json.loads(attrs['selected_roots_json']), ['app', 'worker'])
            self.assertEqual((len(nodes), edges), (1, []))
            results = json.loads(attrs['results_json'])
            self.assertEqual([(r['findingIndex'], r['status'], r['affectedRootCount']) for r in results],
                             [(0, 'unreachable', 0), (0, 'reachable', 2), (1, 'reachable', 1)])
            self.assertEqual(attrs['truncated'], 'true')
            attrs, _, _ = self.assert_finding_scope(self.render(report, finding_indexes=[1]),
                                                    [0, 1], 6, 1, [1])
            self.assertEqual(report, before)

    def test_finding_scope_preserves_unknowns_and_hostile_metadata(self):
        bom, grype = fixture('graph.json'), fixture('graph-grype.json')
        del bom['metadata']
        hostile = 'x"; injected -> node; //\\N\\n雪\x00\ud800'
        grype['matches'][0]['vulnerability']['id'] = hostile
        report = explain(bom, grype, roots=[], finding_indexes=[5, 3, 0])
        attrs, nodes, edges = self.assert_finding_scope(self.render(report, max_nodes=1), [0, 3, 5], 6, 3)
        results = json.loads(attrs['results_json'])
        self.assertEqual([(r['status'], r['affectedRootCount']) for r in results],
                         [('roots_unknown', None), ('unmapped', None), ('unknown_identity', None)])
        self.assertEqual(results[0]['vulnerabilityId'], hostile)
        self.assertEqual(json.loads(attrs['selected_roots_json']), [])
        self.assertEqual(edges, [])
        self.render(report).encode('utf-8')

    def test_branch_cycle_selection_highlights_witnesses_without_changing_report(self):
        before = copy.deepcopy(self.report)
        attrs, nodes, edges = parse_dot(self.render(finding_indexes=[0]))
        self.assertEqual(refs_and_edges(nodes, edges), (
            {'app', 'left', 'lib-v1', 'worker'},
            {('app', 'left'), ('left', 'lib-v1'), ('worker', 'lib-v1')}))
        by_ref = {node['sbom_ref']: node for node in nodes.values()}
        self.assertEqual(by_ref['app']['shape'], 'box')
        self.assertEqual(by_ref['worker']['is_root'], 'true')
        self.assertEqual(by_ref['lib-v1']['is_affected'], 'true')
        self.assertEqual(by_ref['lib-v1']['fillcolor'], 'mistyrose')
        self.assertTrue(all(edge['witness'] == 'true' and edge['style'] == 'bold' for _, _, edge in edges))
        self.assertEqual(attrs['input_cycles_detected'], 'true')
        self.assertIn('alternate paths not enumerated', attrs['witness_scope'])
        self.assertEqual(attrs['truncated'], 'false')
        result = json.loads(attrs['results_json'])[0]
        self.assertEqual((result['findingIndex'], result['vulnerableRef'], result['status'], result['affectedRootCount']),
                         (0, 'lib-v1', 'reachable', 2))
        self.assertEqual(self.report, before)

    def test_ordering_is_stable_under_graph_reordering_and_duplicate_selection(self):
        first = self.render(finding_indexes=[1, 0, 1])
        bom = fixture('graph.json')
        bom['components'].reverse()
        bom['dependencies'].reverse()
        for dependency in bom['dependencies']:
            dependency['dependsOn'].reverse()
        second = explain(bom, fixture('graph-grype.json'), roots=['app', 'worker'], mapping=fixture('mapping.json'))
        self.assertEqual(first, self.render(second, finding_indexes=[0, 1]))
        self.assertEqual(first, self.render(finding_indexes=[0, 1]))

    def test_node_cap_and_edge_cap_never_introduce_implicit_nodes(self):
        attrs, nodes, edges = parse_dot(self.render(finding_indexes=[0], max_nodes=2, max_edges=1))
        self.assertEqual(refs_and_edges(nodes, edges), ({'app', 'worker'}, set()))
        self.assertEqual((attrs['nodes_total'], attrs['nodes_omitted'], attrs['edges_total'], attrs['edges_omitted']),
                         ('4', '2', '3', '3'))
        self.assertEqual(attrs['truncated'], 'true')
        self.assertIn('Truncated: true', attrs['label'])
        self.assertEqual(json.loads(attrs['results_json'])[0]['affectedRootCount'], 2)
        attrs, nodes, edges = parse_dot(self.render(finding_indexes=[0], max_nodes=4, max_edges=1))
        self.assertEqual((len(nodes), len(edges), attrs['nodes_omitted'], attrs['edges_omitted']), (4, 1, '0', '2'))
        attrs, _, _ = parse_dot(self.render(finding_indexes=[0], max_nodes=4, max_edges=3))
        self.assertEqual(attrs['truncated'], 'false')

    def test_report_root_and_path_caps_are_propagated_for_selected_results_only(self):
        for max_roots, max_paths, omitted in ((1, 100, ('1', '0')), (100, 1, ('0', '1'))):
            report = explain(fixture('graph.json'), fixture('graph-grype.json'),
                             roots=['app', 'worker'], max_roots=max_roots, max_paths=max_paths)
            attrs, _, _ = parse_dot(self.render(report, finding_indexes=[0]))
            self.assertEqual((attrs['report_roots_omitted'], attrs['report_paths_omitted']), omitted)
            self.assertEqual(attrs['truncated'], 'true')
            self.assertEqual(json.loads(attrs['results_json'])[0]['affectedRootCount'], 2)
        # Formatting an already-capped report cannot recover omitted paths.
        # Select in explain() (as the CLI does) to reserve budget before allocation.
        attrs, _, edges = parse_dot(self.render(report, finding_indexes=[1]))
        self.assertEqual(attrs['report_paths_omitted'], '1')
        self.assertEqual(json.loads(attrs['results_json'])[0]['status'], 'reachable')
        self.assertEqual(edges, [])

    def test_unknown_unmapped_and_unreachable_are_retained_without_witness_edges(self):
        attrs, nodes, edges = parse_dot(self.render(finding_indexes=[2, 3, 5]))
        self.assertEqual([r['status'] for r in json.loads(attrs['results_json'])],
                         ['unreachable', 'unmapped', 'unknown_identity'])
        self.assertEqual(refs_and_edges(nodes, edges), ({'app', 'worker', 'orphan'}, set()))
        self.assertIn('unreachable', attrs['label'])
        self.assertIn('Unreachable does not mean safe', attrs['label'])
        bom = fixture('bom.json')
        del bom['metadata']
        report = explain(bom, fixture('grype.json'))
        attrs, _, edges = parse_dot(self.render(report))
        result = json.loads(attrs['results_json'])[0]
        self.assertEqual(result['status'], 'roots_unknown')
        self.assertIsNone(result['affectedRootCount'])
        self.assertEqual(edges, [])

    def test_explicit_empty_root_scope_differs_from_absent_without_changing_results(self):
        absent_bom = fixture('graph.json')
        del absent_bom['metadata']
        for bom, grype, index in ((absent_bom, fixture('graph-grype.json'), 1),
                                  (fixture('markers-no-roots.spdx.json'), fixture('grype.json'), 0)):
            with self.subTest(format=bom.get('bomFormat', 'SPDX')):
                default = explain(bom, grype, finding_indexes=[index])
                explicit = explain(bom, grype, roots=[], finding_indexes=[index])
                before = copy.deepcopy(explicit)
                old_attrs, old_nodes, old_edges = parse_dot(self.render(default))
                attrs, nodes, edges = parse_dot(self.render(explicit))
                self.assertEqual(attrs.get('root_selection'), 'explicit')
                self.assertEqual(json.loads(attrs['selected_roots_json']), [])
                scope = 'Roots selected explicitly: (none).\n'
                self.assertIn(scope, attrs['label'])
                attrs['label'] = attrs['label'].replace(scope, '')
                del attrs['root_selection'], attrs['selected_roots_json']
                self.assertEqual((attrs, nodes, edges), (old_attrs, old_nodes, old_edges))
                result = json.loads(attrs['results_json'])[0]
                self.assertEqual((result['findingIndex'], result['status'], result['affectedRootCount']),
                                 (index, 'roots_unknown', None))
                self.assertEqual(edges, [])
                self.assertEqual(explicit['results'][0]['affectedRoots'], [])
                self.assertEqual(explicit['evidence'], default['evidence'])
                self.assertEqual(explicit['provenance']['inputDigests'], default['provenance']['inputDigests'])
                self.assertEqual(explicit, before)

    def test_full_explicit_root_scope_survives_duplicates_and_all_caps(self):
        options = dict(finding_indexes=[0, 1], max_roots=1, max_paths=1)
        report = explain(fixture('graph.json'), fixture('graph-grype.json'),
                         roots=['worker', 'app', 'worker'], **options)
        before = copy.deepcopy(report)
        text = self.render(report, max_nodes=1, max_edges=1)
        canonical = explain(fixture('graph.json'), fixture('graph-grype.json'),
                            roots=['app', 'worker'], **options)
        self.assertEqual(text, self.render(canonical, max_nodes=1, max_edges=1))
        attrs, nodes, edges = parse_dot(text)
        self.assertEqual(attrs.get('root_selection'), 'explicit')
        self.assertEqual(json.loads(attrs['selected_roots_json']), ['app', 'worker'])
        self.assertIn('Roots selected explicitly: app, worker.\n', attrs['label'])
        self.assertEqual(refs_and_edges(nodes, edges), ({'app'}, set()))
        self.assertEqual((attrs['nodes_total'], attrs['nodes_omitted'], attrs['edges_total'],
                          attrs['edges_omitted'], attrs['report_roots_omitted'], attrs['report_paths_omitted']),
                         ('5', '4', '2', '2', '1', '1'))
        self.assertEqual([(r['findingIndex'], r['affectedRootCount'])
                          for r in json.loads(attrs['results_json'])], [(0, 2), (1, 1)])
        self.assertEqual(report['results'][0]['affectedRoots'][0]['path'], ['app', 'left', 'lib-v1'])
        self.assertEqual(report, before)

    def test_explicit_root_scope_is_independent_of_empty_finding_selection(self):
        for roots in ([], ['worker', 'app', 'worker']):
            for indexes in (None, []):
                with self.subTest(roots=roots, indexes=indexes):
                    # Exercise no input findings, pre-budget selection, and formatter-only filtering.
                    grype = {'matches': []} if indexes is None else fixture('graph-grype.json')
                    report = explain(fixture('graph.json'), grype, roots=roots, finding_indexes=indexes)
                    for candidate in (report, explain(fixture('graph.json'), fixture('graph-grype.json'), roots=roots)):
                        attrs, nodes, edges = parse_dot(self.render(candidate, finding_indexes=[], max_nodes=1))
                        self.assertEqual(attrs.get('root_selection'), 'explicit')
                        self.assertEqual(json.loads(attrs['selected_roots_json']), sorted(set(roots)))
                        scope = 'app, worker' if roots else '(none)'
                        self.assertIn(f'Roots selected explicitly: {scope}.', attrs['label'])
                        self.assertEqual(json.loads(attrs['results_json']), [])
                        self.assertEqual(refs_and_edges(nodes, edges), ({'app'} if roots else set(), set()))
                        self.assertEqual(attrs['nodes_omitted'], '1' if roots else '0')
                        self.assertEqual(attrs['report_roots_omitted'], '0')
                        self.assertEqual(attrs['report_paths_omitted'], '0')

    def test_default_declared_and_absent_roots_have_no_explicit_dot_scope(self):
        for name in ('graph.json', 'bom.spdx.json', 'markers-no-roots.spdx.json'):
            bom = fixture(name)
            for absent in (False, True):
                if absent and name != 'graph.json':
                    continue
                if absent:
                    del bom['metadata']
                with self.subTest(name=name, absent=absent):
                    report = explain(bom, fixture('grype.json'), finding_indexes=[])
                    attrs, _, _ = parse_dot(self.render(report))
                    self.assertNotIn('root_selection', attrs)
                    self.assertNotIn('selected_roots_json', attrs)
                    self.assertNotIn('Roots selected explicitly:', attrs['label'])

    def test_explicit_root_metadata_roundtrips_hostile_refs_without_injection(self):
        values = ['x"; injected -> node; //\\N\\G\\l\n\r\t\x00雪\ud800',
                  '\\', '"', '\\"', '\\\\"', '\\u0022', '\\u005c', '\\n', '\\\n', '\b\f']
        for value in values:
            with self.subTest(value=repr(value)):
                bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6',
                       'components': [{'bom-ref': value}],
                       'dependencies': [{'ref': value, 'dependsOn': []}]}
                report = explain(bom, {'matches': []}, roots=[value, value])
                before = copy.deepcopy(report)
                text = self.render(report)
                attrs, nodes, edges = parse_dot(text)
                self.assertEqual(attrs.get('root_selection'), 'explicit')
                self.assertEqual(json.loads(attrs['selected_roots_json']), [value])
                self.assertEqual((len(nodes), edges), (1, []))
                self.assertIn('Roots selected explicitly:', attrs['label'])
                self.assertNotIn('\x00', text)
                self.assertNotIn('\ud800', text)
                text.encode('utf-8')
                self.assertEqual(report, before)

    def test_selection_before_budget_preserves_later_index_full_counts_and_evidence(self):
        bom, grype = fixture('graph.json'), fixture('graph-grype.json')
        grype['matches'][1] = copy.deepcopy(grype['matches'][0])
        grype['matches'][1]['vulnerability']['id'] = 'ZZZ-later'
        before = copy.deepcopy((bom, grype))
        for max_roots, omissions in ((100, {'rootsOmitted': 0, 'pathsOmitted': 1}),
                                     (1, {'rootsOmitted': 1, 'pathsOmitted': 0})):
            report = explain(bom, grype, roots=['worker', 'app'], finding_indexes=[1, 1],
                             max_roots=max_roots, max_paths=1)
            self.assertEqual(len(report['results']), 1)
            result = report['results'][0]
            self.assertEqual((result['findingIndex'], result['status'], result['affectedRootCount']),
                             (1, 'reachable', 2))
            self.assertEqual(result['truncation'], omissions)
            self.assertEqual(result['affectedRoots'][0],
                             {'root': 'app', 'path': ['app', 'left', 'lib-v1']})
            self.assertEqual(report['summary']['activeFindings'], len(grype['matches']))
            self.assertEqual(report['summary']['results'], 1)
            self.assertEqual(report['summary']['unmappedFindings'], 0)
            self.assertEqual(report['summary']['witnessPaths'], 1)
            self.assertEqual(report['provenance']['selectedFindingIndexes'], [1])
            self.assertEqual(report['evidence']['grype'], grype)
            self.assertEqual(report['provenance']['inputDigests'],
                             explain(bom, grype, roots=['app', 'worker'])['provenance']['inputDigests'])
            attrs, nodes, edges = parse_dot(self.render(report))
            self.assertEqual(json.loads(attrs['selected_findings']), [1])
            self.assertEqual(json.loads(attrs['results_json'])[0]['affectedRootCount'], 2)
            self.assertEqual(refs_and_edges(nodes, edges), (
                {'app', 'worker', 'left', 'lib-v1'}, {('app', 'left'), ('left', 'lib-v1')}))
        self.assertEqual((bom, grype), before)

    def test_prebudget_selection_keeps_all_candidates_empty_and_unknown_states(self):
        bom, grype = fixture('bom.json'), fixture('grype.json')
        bom['components'].append({'bom-ref': 'b-copy', 'purl': 'pkg:npm/b@2.0'})
        grype['matches'].insert(0, copy.deepcopy(grype['matches'][0]))
        report = explain(bom, grype, finding_indexes=[1], max_paths=1)
        self.assertEqual([(r['findingIndex'], r['vulnerableRef'], r['status']) for r in report['results']],
                         [(1, 'b', 'reachable'), (1, 'b-copy', 'unreachable')])
        self.assertEqual(report['results'][0]['affectedRoots'][0]['path'], ['app', 'a', 'b'])
        self.assertTrue(all(r['join']['candidateCount'] == 2 for r in report['results']))
        empty = explain(bom, grype, finding_indexes=[])
        self.assertEqual(empty['results'], [])
        self.assertEqual(empty['summary']['witnessPaths'], 0)
        self.assertEqual(refs_and_edges(*parse_dot(self.render(empty))[1:]), ({'app'}, set()))
        bom = fixture('graph.json')
        del bom['metadata']
        report = explain(bom, fixture('graph-grype.json'), finding_indexes=[0, 2, 3, 5])
        self.assertEqual([(r['findingIndex'], r['status'], r['affectedRootCount']) for r in report['results']],
                         [(0, 'roots_unknown', None), (2, 'roots_unknown', None),
                          (3, 'unmapped', None), (5, 'unknown_identity', None)])

    def test_prebudget_selection_validates_indexes_and_unselected_input(self):
        for indexes in (0, 'SECRET', [True], [1.2], [-1], [999], ['SECRET']):
            with self.subTest(indexes=indexes):
                with self.assertRaises(InputError) as raised:
                    explain(fixture('bom.json'), fixture('grype.json'), finding_indexes=indexes)
                self.assertNotIn('SECRET', str(raised.exception))
        grype = fixture('grype.json')
        grype['matches'].append({'vulnerability': {'id': 'SECRET'}})
        for indexes in ([0], []):
            with self.subTest(indexes=indexes), self.assertRaises(InputError):
                explain(fixture('bom.json'), grype, finding_indexes=indexes)

    def test_root_affected_by_finding_has_both_roles_with_zero_edges(self):
        report = explain(fixture('bom.json'), fixture('grype.json'), roots=['b'])
        attrs, nodes, edges = parse_dot(self.render(report))
        node = next(iter(nodes.values()))
        self.assertEqual((node['is_root'], node['is_affected'], node['shape'], node['fillcolor']),
                         ('true', 'true', 'box', 'mistyrose'))
        self.assertEqual(edges, [])
        self.assertEqual(attrs['truncated'], 'false')

    def test_duplicate_purl_candidates_and_original_finding_index(self):
        bom, grype = fixture('bom.json'), fixture('grype.json')
        bom['components'].append({'bom-ref': 'b-copy', 'purl': 'pkg:npm/b@2.0'})
        grype['matches'].insert(0, {'vulnerability': {'id': 'ZZZ'}, 'artifact': {}})
        report = explain(bom, grype)
        attrs, nodes, _ = parse_dot(self.render(report, finding_indexes=[1]))
        self.assertEqual(json.loads(attrs['selected_findings']), [1])
        self.assertEqual([r['status'] for r in json.loads(attrs['results_json'])], ['reachable', 'unreachable'])
        self.assertTrue({'b', 'b-copy'} <= {node['sbom_ref'] for node in nodes.values()})
        self.assertNotIn('ZZZ', attrs['label'])

    def test_quotes_backslashes_controls_unicode_and_dot_injection_are_literal(self):
        unusual = 'x"; injected -> node; //\\N\\G\\l\\\n\r\t\x00雪\ud800'
        bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6',
               'metadata': {'component': {'bom-ref': unusual, 'purl': 'pkg:generic/odd@1'}},
               'dependencies': [{'ref': unusual, 'dependsOn': [unusual]}]}
        grype = {'matches': [{'vulnerability': {'id': unusual}, 'artifact': {'purl': 'pkg:generic/odd@1'}}]}
        text = self.render(explain(bom, grype))
        attrs, nodes, edges = parse_dot(text)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(edges, [])
        self.assertEqual(json.loads(attrs['results_json'])[0]['vulnerabilityId'], unusual)
        label = next(iter(nodes.values()))['label']
        self.assertIn('\\N\\G\\l', label)
        self.assertIn('雪', label)
        self.assertNotIn('\x00', text)
        self.assertNotIn('\ud800', text)
        text.encode('utf-8')

    def test_empty_findings_and_explicit_empty_selection(self):
        report = explain(fixture('bom.json'), {'matches': []})
        attrs, nodes, edges = parse_dot(self.render(report))
        self.assertEqual(json.loads(attrs['results_json']), [])
        self.assertEqual(refs_and_edges(nodes, edges), ({'app'}, set()))
        attrs, _, _ = parse_dot(self.render(finding_indexes=[]))
        self.assertEqual(json.loads(attrs['selected_findings']), [])

    def test_metadata_roundtrips_literal_escapes_and_backslash_quote_combinations(self):
        bom = fixture('bom.json')
        values = ['\\', '"', '\\"', '\\\\"', '\\\\\\"', '\\u0022', '\\u005c',
                  '\\n', '\\\n', '\b\f', '雪\ud800']
        for value in values:
            with self.subTest(value=repr(value)):
                grype = fixture('grype.json')
                grype['matches'][0]['vulnerability']['id'] = value
                report = explain(bom, grype)
                attrs, _, _ = parse_dot(self.render(report))
                self.assertEqual(json.loads(attrs['results_json'])[0]['vulnerabilityId'], value)

    def test_invalid_caps_and_selection_raise_safe_input_errors(self):
        for options in ({'max_nodes': 0}, {'max_edges': -1}, {'max_nodes': True},
                        {'max_edges': 1.2}, {'finding_indexes': [999]}, {'finding_indexes': [-1]},
                        {'finding_indexes': [True]}, {'finding_indexes': ['SECRET']}, {'finding_indexes': 0}):
            with self.subTest(options=options), self.assertRaises(InputError) as raised:
                self.render(**options)
            self.assertNotIn('SECRET', str(raised.exception))

    def test_long_witness_is_bounded_without_changing_reachability(self):
        refs = [f'n{i:04}' for i in range(1500)]
        bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6',
               'components': [{'bom-ref': ref} for ref in refs],
               'dependencies': [{'ref': ref, 'dependsOn': refs[i+1:i+2]} for i, ref in enumerate(refs)]}
        report = explain(bom, {'matches': [{'vulnerability': {'id': 'V'}, 'artifact': {'id': 'v'}}]},
                         roots=[refs[0]], mapping={'schemaVersion': 1, 'artifacts': {'v': [refs[-1]]}})
        attrs, nodes, edges = parse_dot(self.render(report, max_nodes=10, max_edges=3))
        self.assertEqual((len(nodes), len(edges)), (10, 3))
        self.assertEqual((attrs['nodes_total'], attrs['edges_total']), ('1500', '1499'))
        self.assertEqual((attrs['nodes_omitted'], attrs['edges_omitted']), ('1490', '1496'))
        self.assertEqual(json.loads(attrs['results_json'])[0]['status'], 'reachable')


DIGEST_SCOPE = ('Input digests: SHA-256 of canonical JSON for full original inputs '
                '(not the selected witness projection); mapping null means no explicit mapping input.')


class DotDigestTests(unittest.TestCase):
    def assert_digest_projection(self, report, **options):
        before = copy.deepcopy(report)
        plain = sbom_pathfinder.to_dot(report, **options)
        text = sbom_pathfinder.to_dot(report, include_input_digests=True, **options)
        attrs, nodes, edges = parse_dot(text)
        self.assertEqual(attrs.pop('digest_algorithm'), report['provenance']['digestAlgorithm'])
        self.assertEqual(json.loads(attrs.pop('input_digests_json')), report['provenance']['inputDigests'])
        self.assertIn(DIGEST_SCOPE + '\n', attrs['label'])
        attrs['label'] = attrs['label'].replace(DIGEST_SCOPE + '\n', '')
        self.assertEqual((attrs, nodes, edges), parse_dot(plain))
        self.assertEqual(plain, sbom_pathfinder.to_dot(report, include_input_digests=False, **options))
        self.assertEqual(report, before)
        return text

    def test_distinct_unselected_evidence_has_distinct_opt_in_full_input_digests(self):
        bom, grype = fixture('graph.json'), fixture('graph-grype.json')
        modified = copy.deepcopy(grype)
        secret = 'PRIVATE_UNSELECTED_INPUT_14'
        modified['matches'][0]['vulnerability']['description'] = secret + '\"; injected -> node; //\\N雪\x00\ud800'
        a = explain(bom, grype, finding_indexes=[1])
        b = explain(bom, modified, finding_indexes=[1])
        self.assertEqual(a['results'], b['results'])
        self.assertEqual(sbom_pathfinder.to_dot(a), sbom_pathfinder.to_dot(b))
        first, second = self.assert_digest_projection(a), self.assert_digest_projection(b)
        self.assertNotEqual(first, second)
        aa, an, ae = parse_dot(first)
        ba, bn, be = parse_dot(second)
        da, db = json.loads(aa.pop('input_digests_json')), json.loads(ba.pop('input_digests_json'))
        self.assertEqual((aa, an, ae), (ba, bn, be))
        self.assertEqual(da['bom'], db['bom'])
        self.assertIsNone(da['mapping'])
        self.assertNotEqual(da['grype'], db['grype'])
        for report, text in ((a, first), (b, second)):
            for name in ('bom', 'grype'):
                raw = json.dumps(report['evidence'][name], sort_keys=True, ensure_ascii=True,
                                 allow_nan=False, separators=(',', ':')).encode('utf-8')
                self.assertEqual(report['provenance']['inputDigests'][name], hashlib.sha256(raw).hexdigest())
            self.assertNotIn(secret, text)
            self.assertNotIn('description', text)
            text.encode('utf-8')

    def test_digest_scope_preserves_mapping_null_selections_formats_and_caps(self):
        for bname, gname, roots in (('graph.json', 'graph-grype.json', ['app', 'worker']),
                                   ('bom.spdx.json', 'grype.json', ['SPDXRef-app'])):
            bom, grype = fixture(bname), fixture(gname)
            mapping = {'schemaVersion': 1, 'artifacts': {grype['matches'][0]['artifact']['id']: [roots[0]]}}
            for m in (None, {'schemaVersion': 1, 'artifacts': {}}, mapping):
                for r in (None, [], roots):
                    for indexes in (None, [], [0]):
                        with self.subTest(format=bname, mapping=m, roots=r, indexes=indexes):
                            report = explain(bom, grype, mapping=m, roots=r, finding_indexes=indexes,
                                             max_roots=1, max_paths=1)
                            text = self.assert_digest_projection(report, max_nodes=1, max_edges=1)
                            digests = json.loads(parse_dot(text)[0]['input_digests_json'])
                            expected = (None if m is None else hashlib.sha256(json.dumps(
                                m, sort_keys=True, ensure_ascii=True, allow_nan=False,
                                separators=(',', ':')).encode('utf-8')).hexdigest())
                            self.assertEqual(digests['mapping'], expected)
                            self.assertEqual(parse_dot(text)[0]['digest_algorithm'], 'sha256-canonical-json')
        # Identity failures retain their null counts; full-input metadata survives no roots.
        report = explain(fixture('graph.json'), fixture('graph-grype.json'), roots=[], finding_indexes=[1, 3, 5])
        text = self.assert_digest_projection(report)
        self.assertEqual([(r['findingIndex'], r['status'], r['affectedRootCount'])
                          for r in json.loads(parse_dot(text)[0]['results_json'])],
                         [(1, 'roots_unknown', None), (3, 'unmapped', None), (5, 'unknown_identity', None)])

    def test_digest_scope_survives_formatter_filtering_and_canonical_object_order(self):
        bom, grype = fixture('graph.json'), fixture('graph-grype.json')
        report = explain(bom, grype, finding_indexes=[0, 1, 3], roots=['worker', 'app'], max_paths=1)
        for indexes in ([1], []):
            self.assert_digest_projection(report, finding_indexes=indexes, max_nodes=1)
        default = explain(bom, grype)
        self.assert_digest_projection(default, finding_indexes=[1])
        # Reformatting/reordering object keys does not change canonical digests or opt-in DOT.
        reordered = json.loads(json.dumps({'grype': grype, 'bom': bom}, sort_keys=True, indent=4))
        self.assertEqual(sbom_pathfinder.to_dot(default, include_input_digests=True),
                         sbom_pathfinder.to_dot(explain(reordered['bom'], reordered['grype']), include_input_digests=True))
        for invalid in (None, 0, 1, 'true', [], {}):
            with self.subTest(invalid=invalid), self.assertRaises(InputError):
                sbom_pathfinder.to_dot(default, include_input_digests=invalid)



DANGLING_SCOPE = ('Dangling dependency diagnostics (full input): {count} records; '
                  'unknown endpoint refs excluded from traversal; no nodes or edges added.')


class DotDanglingTests(unittest.TestCase):
    def assert_diagnostics(self, report, **options):
        before = copy.deepcopy(report)
        plain = sbom_pathfinder.to_dot(report, **options)
        self.assertEqual(plain, sbom_pathfinder.to_dot(report, include_dangling_dependencies=False, **options))
        text = sbom_pathfinder.to_dot(report, include_dangling_dependencies=True, **options)
        attrs, nodes, edges = parse_dot(text)
        records = report['graph']['danglingDependencies']
        self.assertEqual(json.loads(attrs.pop('dangling_dependencies_json')), records)
        self.assertEqual(attrs.pop('dangling_dependency_count'), str(len(records)))
        line = DANGLING_SCOPE.format(count=len(records))
        self.assertEqual(attrs['label'].count(line), 1)
        attrs['label'] = attrs['label'].replace(line + '\n', '')
        self.assertEqual((attrs, nodes, edges), parse_dot(plain))
        self.assertEqual(attrs['inferred_edges'], '0')
        self.assertEqual(text, sbom_pathfinder.to_dot(report, include_dangling_dependencies=True, **options))
        self.assertEqual(report, before)
        text.encode('utf-8')
        return parse_dot(text)

    def test_equal_witnesses_explain_changed_full_input_diagnostics(self):
        bom, grype = fixture('graph.json'), fixture('graph-grype.json')
        variant = copy.deepcopy(bom)
        next(d for d in variant['dependencies'] if d['ref'] == 'no-purl')['dependsOn'].append('another-missing-ref')
        a, b = [explain(x, grype, roots=['app', 'worker'], finding_indexes=[1]) for x in (bom, variant)]
        self.assertEqual(a['results'], b['results'])
        self.assertEqual(a['summary']['witnessPaths'], 1)
        self.assertEqual(sbom_pathfinder.to_dot(a), sbom_pathfinder.to_dot(b))
        self.assertEqual([len(r['graph']['danglingDependencies']) for r in (a, b)], [3, 4])
        aa, an, ae = self.assert_diagnostics(a)
        ba, bn, be = self.assert_diagnostics(b)
        self.assertNotEqual(aa['dangling_dependencies_json'], ba['dangling_dependencies_json'])
        self.assertEqual((an, ae), (bn, be))
        self.assertEqual(refs_and_edges(an, ae), ({'app', 'worker', 'lib-v2'}, {('worker', 'lib-v2')}))

    def test_full_diagnostics_survive_selection_caps_and_digest_composition(self):
        bom, grype = fixture('graph.json'), fixture('graph-grype.json')
        full = explain(bom, grype)['graph']['danglingDependencies']
        for roots in (None, [], ['worker', 'app']):
            for indexes in (None, [], [0, 1, 3, 5]):
                with self.subTest(roots=roots, indexes=indexes):
                    report = explain(bom, grype, roots=roots, finding_indexes=indexes, max_roots=1, max_paths=1)
                    self.assertEqual(report['graph']['danglingDependencies'], full)
                    self.assert_diagnostics(report, max_nodes=1, max_edges=1, include_input_digests=True)
                    # Formatter selection also cannot narrow full-input diagnostics.
                    attrs, nodes, edges = self.assert_diagnostics(report, finding_indexes=[], max_nodes=1)
                    self.assertEqual(json.loads(attrs['results_json']), [])
                    self.assertEqual(edges, [])
                    if roots == []:
                        self.assertEqual(nodes, {})
        no_matches = explain(bom, {'matches': []}, roots=[], finding_indexes=[])
        self.assert_diagnostics(no_matches)

    def test_hostile_missing_refs_and_null_declarations_roundtrip_without_nodes(self):
        bom, grype = fixture('graph.json'), fixture('graph-grype.json')
        source = 'source"; injected -> node; //\\N\\n\n雪\x00\ud800'
        target = 'target\\"\\u0022\t\r\x7f\x85\udfff'
        bom['dependencies'].extend([{'ref': source, 'dependsOn': [target, 'lib-v1']},
                                    {'ref': target}, {'ref': 'unknown-empty', 'dependsOn': []}])
        next(d for d in bom['dependencies'] if d['ref'] == 'no-purl')['dependsOn'].append(target)
        report = explain(bom, grype, roots=['app', 'worker'], finding_indexes=[0])
        attrs, nodes, edges = self.assert_diagnostics(report, max_nodes=2, max_edges=1)
        records = json.loads(attrs['dangling_dependencies_json'])
        self.assertIn({'from': source, 'to': None, 'missing': [source], 'kind': 'dependency_source'}, records)
        self.assertIn({'from': source, 'to': target, 'missing': sorted([source, target]), 'kind': 'edge'}, records)
        self.assertIn({'from': source, 'to': 'lib-v1', 'missing': [source], 'kind': 'edge'}, records)
        self.assertIn({'from': target, 'to': None, 'missing': [target], 'kind': 'dependency_source'}, records)
        self.assertIn({'from': 'unknown-empty', 'to': None, 'missing': ['unknown-empty'], 'kind': 'dependency_source'}, records)
        self.assertTrue({source, target, 'unknown-empty'}.isdisjoint(refs_and_edges(nodes, edges)[0]))
        # Identical dangling records in default root/no finding and no root scopes.
        for roots in (None, []):
            empty = explain(bom, grype, roots=roots, finding_indexes=[])
            self.assertEqual(empty['graph']['danglingDependencies'], records)
            self.assert_diagnostics(empty)

    def test_spdx_zero_diagnostics_strict_endpoints_and_boolean_option(self):
        bom, grype = fixture('bom.spdx.json'), fixture('grype.json')
        for roots in (None, [], ['SPDXRef-app']):
            report = explain(bom, grype, roots=roots)
            attrs, _, _ = self.assert_diagnostics(report, max_nodes=1)
            self.assertEqual(json.loads(attrs['dangling_dependencies_json']), [])
            self.assertEqual(attrs['dangling_dependency_count'], '0')
        for invalid in (None, 0, 1, 'true', [], {}):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(InputError, 'include_dangling_dependencies must be a boolean'):
                sbom_pathfinder.to_dot(report, include_dangling_dependencies=invalid)
        for source, target in [('SPDXRef-absent', 'SPDXRef-app'), ('SPDXRef-app', 'SPDXRef-absent')]:
            bad = copy.deepcopy(bom)
            bad['relationships'].append({'spdxElementId': source, 'relationshipType': 'DEPENDS_ON', 'relatedSpdxElement': target})
            with self.assertRaises(InputError):
                explain(bad, grype, roots=[], finding_indexes=[])



MISSING_DECLARATION_SCOPE = ('Missing dependency declarations (full input): {count} refs; '
                             'absence is not proof of no dependencies; no nodes or edges added.')


class DotMissingDeclarationTests(unittest.TestCase):
    def assert_diagnostics(self, report, **options):
        before = copy.deepcopy(report)
        plain = sbom_pathfinder.to_dot(report, **options)
        self.assertEqual(plain, sbom_pathfinder.to_dot(report, include_missing_dependency_declarations=False, **options))
        text = sbom_pathfinder.to_dot(report, include_missing_dependency_declarations=True, **options)
        attrs, nodes, edges = parse_dot(text)
        refs = report['graph']['missingDependencyDeclarations']
        self.assertEqual(json.loads(attrs.pop('missing_dependency_declarations_json')), refs)
        self.assertEqual(attrs.pop('missing_dependency_declaration_count'), str(len(refs)))
        line = MISSING_DECLARATION_SCOPE.format(count=len(refs))
        self.assertEqual(attrs['label'].count(line), 1)
        attrs['label'] = attrs['label'].replace(line + '\n', '')
        self.assertEqual((attrs, nodes, edges), parse_dot(plain))
        self.assertEqual(attrs['inferred_edges'], '0')
        self.assertEqual(text, sbom_pathfinder.to_dot(report, include_missing_dependency_declarations=True, **options))
        self.assertEqual(report, before)
        text.encode('utf-8')
        return parse_dot(text)

    def test_equal_witnesses_distinguish_absent_from_explicit_empty_declaration(self):
        bom, grype = fixture('graph.json'), fixture('graph-grype.json')
        variant = copy.deepcopy(bom)
        variant['dependencies'].append({'ref': 'orphan', 'dependsOn': []})
        a, b = [explain(x, grype, roots=['app', 'worker'], finding_indexes=[1]) for x in (bom, variant)]
        self.assertEqual(a['results'], b['results'])
        self.assertEqual(a['summary']['witnessPaths'], 1)
        for dangling in (False, True):
            self.assertEqual(sbom_pathfinder.to_dot(a, include_dangling_dependencies=dangling),
                             sbom_pathfinder.to_dot(b, include_dangling_dependencies=dangling))
        self.assertEqual([r['graph']['missingDependencyDeclarations'] for r in (a, b)], [['orphan'], []])
        aa, an, ae = self.assert_diagnostics(a)
        ba, bn, be = self.assert_diagnostics(b)
        self.assertNotEqual(aa['missing_dependency_declarations_json'], ba['missing_dependency_declarations_json'])
        self.assertEqual((an, ae), (bn, be))
        self.assertEqual(refs_and_edges(an, ae), ({'app', 'worker', 'lib-v2'}, {('worker', 'lib-v2')}))

    def test_full_refs_survive_selections_formatter_filters_caps_and_opt_in_composition(self):
        bom, grype = fixture('graph.json'), fixture('graph-grype.json')
        bom['components'].append({'bom-ref': 'unselected-no-declaration'})
        for roots in (None, [], ['worker', 'app']):
            for indexes in (None, [], [0, 1, 3, 5]):
                for caps in ({'max_roots': 1, 'max_paths': 100}, {'max_roots': 100, 'max_paths': 1}):
                    with self.subTest(roots=roots, indexes=indexes, caps=caps):
                        report = explain(bom, grype, roots=roots, finding_indexes=indexes, **caps)
                        self.assertEqual(report['graph']['missingDependencyDeclarations'], ['orphan', 'unselected-no-declaration'])
                        attrs, nodes, edges = self.assert_diagnostics(
                            report, max_nodes=1, max_edges=1, include_input_digests=True, include_dangling_dependencies=True)
                        self.assertLessEqual(len(nodes), 1)
                        self.assertEqual(edges, [])
                        attrs, nodes, edges = self.assert_diagnostics(report, finding_indexes=[], max_nodes=1)
                        self.assertEqual(json.loads(attrs['results_json']), [])
                        self.assertEqual(edges, [])
                        if roots == []:
                            self.assertEqual(nodes, {})
        report = explain(bom, grype, roots=[], finding_indexes=[1, 3, 5])
        attrs, _, _ = self.assert_diagnostics(report, finding_indexes=[1, 5])
        self.assertEqual([(r['findingIndex'], r['status'], r['affectedRootCount'])
                          for r in json.loads(attrs['results_json'])], [(1, 'roots_unknown', None), (5, 'unknown_identity', None)])
        self.assert_diagnostics(explain(bom, {'matches': []}, roots=[], finding_indexes=[]))

    def test_hostile_refs_roundtrip_outside_projection_without_implicit_nodes(self):
        bom = fixture('graph.json')
        refs = ['x"; injected -> node; //\\N\\G\\l\n\r\t\x00雪\ud800', '\\', '"', '\\"',
                '\\\\"', '\\u0022', '\\u005c', '\\n', '\\\n', '\b\f', '\udfff\x85\x7f']
        bom['components'].extend({'bom-ref': ref} for ref in refs)
        report = explain(bom, fixture('graph-grype.json'), roots=[], finding_indexes=[])
        attrs, nodes, edges = self.assert_diagnostics(report, max_nodes=1, max_edges=1)
        self.assertEqual(json.loads(attrs['missing_dependency_declarations_json']), sorted(refs + ['orphan']))
        self.assertEqual((nodes, edges), ({}, []))
        # An existing ref-only declaration is not absent: depends_on_absent remains a separate warning.
        bom['dependencies'].append({'ref': 'orphan'})
        report = explain(bom, fixture('graph-grype.json'), finding_indexes=[1])
        self.assertNotIn('orphan', report['graph']['missingDependencyDeclarations'])
        self.assertIn('depends_on_absent', [w['code'] for w in report['warnings']])
        self.assert_diagnostics(report)

    def test_spdx_markers_are_dependency_declarations_and_strict_validation_remains(self):
        bom, grype = fixture('bom.spdx.json'), fixture('grype.json')
        reports = []
        for marker in (None, 'NONE', 'NOASSERTION'):
            variant = copy.deepcopy(bom)
            if marker:
                variant['relationships'].append({'spdxElementId': 'SPDXRef-b', 'relationshipType': 'DEPENDS_ON',
                                                 'relatedSpdxElement': marker})
            report = explain(variant, grype, finding_indexes=[0])
            reports.append(report)
            self.assertEqual(report['graph']['missingDependencyDeclarations'], [] if marker else ['SPDXRef-b'])
            self.assert_diagnostics(report, include_dangling_dependencies=True)
            self.assert_diagnostics(explain(variant, grype, roots=[], finding_indexes=[]), max_nodes=1)
        self.assertTrue(all(r['results'] == reports[0]['results'] for r in reports))
        for marker in ('NONE', 'NOASSERTION'):
            variant = copy.deepcopy(bom)
            variant['relationships'].append({'spdxElementId': 'SPDXRef-b', 'relationshipType': 'CONTAINS',
                                             'relatedSpdxElement': marker})
            self.assertEqual(explain(variant, grype)['graph']['missingDependencyDeclarations'], ['SPDXRef-b'])
        for name in ('markers.spdx.json', 'markers-no-roots.spdx.json'):
            self.assert_diagnostics(explain(fixture(name), grype))
        for invalid in (None, 0, 1, 'true', [], {}):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(InputError, 'include_missing_dependency_declarations must be a boolean'):
                sbom_pathfinder.to_dot(reports[0], include_missing_dependency_declarations=invalid)
        bad = copy.deepcopy(bom)
        bad['relationships'].append({'spdxElementId': 'SPDXRef-b', 'relationshipType': 'DEPENDS_ON',
                                     'relatedSpdxElement': 'SPDXRef-unknown'})
        with self.assertRaises(InputError):
            explain(bad, grype, roots=[], finding_indexes=[])


class DotCliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'path', *map(str, args)],
                              cwd=ROOT, capture_output=True, text=True, timeout=60)



    def test_cli_missing_declarations_repeat_file_selections_and_formats(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            output = Path(directory) / 'out'
            for bname, gname in (('graph.json', 'graph-grype.json'), ('bom.spdx.json', 'grype.json'),
                                 ('markers.spdx.json', 'grype.json')):
                for selection in ([], ['--root', 'app', '--root', 'worker', '--finding-index', '1']
                                  if bname == 'graph.json' else ['--finding-index', '0'], ['--no-roots', '--no-findings']):
                    base = ['explain', 'examples/path/' + bname, '--grype', 'examples/path/' + gname,
                            '--format', 'dot', '--max-nodes', '1', '--max-edges', '1', '--max-roots', '1', '--max-paths', '1', *selection]
                    proc = self.run_cli(*base, '--include-missing-dependency-declarations',
                                        '--include-input-digests', '--include-dangling-dependencies')
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    attrs, _, _ = parse_dot(proc.stdout)
                    expected = explain(fixture(bname), fixture(gname))['graph']['missingDependencyDeclarations']
                    self.assertEqual(json.loads(attrs['missing_dependency_declarations_json']), expected)
                    self.assertEqual(attrs['missing_dependency_declaration_count'], str(len(expected)))
                    filed = self.run_cli(*base, '--include-missing-dependency-declarations',
                                         '--include-missing-dependency-declarations', '--include-input-digests',
                                         '--include-dangling-dependencies', '--output', output)
                    self.assertEqual((filed.returncode, filed.stdout), (0, ''), filed.stderr)
                    self.assertEqual(output.read_text(), proc.stdout)
                    plain = self.run_cli(*base)
                    self.assertEqual(plain.returncode, 0, plain.stderr)
                    self.assertNotIn('missing_dependency_declarations_json', parse_dot(plain.stdout)[0])

    def test_cli_missing_declarations_rejects_non_dot_and_retains_validation_and_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            output = Path(directory) / 'out'
            output.write_text('original')
            base = ['explain', 'examples/path/graph.json', '--grype', 'examples/path/graph-grype.json',
                    '--include-missing-dependency-declarations', '--output', output]
            for opts in ([], ['--format', 'json'], ['--format', 'markdown', '--no-roots', '--no-findings'],
                         ['--format', 'dot', '--finding-index', '999'], ['--format', 'dot', '--max-nodes', '0']):
                with self.subTest(opts=opts):
                    proc = self.run_cli(*base, *opts)
                    self.assertEqual((proc.returncode, proc.stdout), (2, ''), proc.stderr)
                    self.assertEqual(output.read_text(), 'original')
                    if '--format' not in opts or 'dot' not in opts:
                        self.assertIn('include-missing-dependency-declarations requires DOT format', proc.stderr)
            bom = Path(directory) / 'private-bom.json'
            bom.write_text(json.dumps(fixture('graph.json')))
            alias = Path(directory) / 'alias.json'
            alias.hardlink_to(bom)
            before = bom.read_bytes()
            proc = self.run_cli('explain', bom, '--grype', 'examples/path/graph-grype.json', '--format', 'dot',
                                '--include-missing-dependency-declarations', '--output', alias)
            self.assertEqual((proc.returncode, proc.stdout), (2, ''), proc.stderr)
            self.assertEqual((bom.read_bytes(), alias.read_bytes()), (before, before))
            bad = fixture('graph-grype.json')
            bad['matches'][0]['artifact'] = None
            path = Path(directory) / 'private-grype.json'
            path.write_text(json.dumps(bad))
            proc = self.run_cli('explain', bom, '--grype', path, '--format', 'dot', '--no-roots', '--no-findings',
                                '--include-missing-dependency-declarations', '--output', output)
            self.assertEqual((proc.returncode, proc.stdout), (2, ''), proc.stderr)
            self.assertEqual(output.read_text(), 'original')
            self.assertNotIn(str(path), proc.stderr)

    def test_cli_dangling_diagnostics_selection_repeat_file_and_spdx(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            output = Path(directory) / 'out.dot'
            for name, gn, options in [
                ('graph.json', 'graph-grype.json', ['--root', 'app', '--root', 'worker', '--finding-index', '1']),
                ('graph.json', 'graph-grype.json', ['--no-roots', '--no-findings', '--max-nodes', '1']),
                ('bom.spdx.json', 'grype.json', ['--max-nodes', '1', '--max-paths', '1'])]:
                with self.subTest(name=name, options=options):
                    base = ['explain', 'examples/path/' + name, '--grype', 'examples/path/' + gn, '--format', 'dot', *options]
                    proc = self.run_cli(*base, '--include-dangling-dependencies', '--include-input-digests')
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    attrs, _, _ = parse_dot(proc.stdout)
                    report = explain(fixture(name), fixture(gn))
                    self.assertEqual(json.loads(attrs['dangling_dependencies_json']), report['graph']['danglingDependencies'])
                    self.assertEqual(attrs['dangling_dependency_count'], str(len(report['graph']['danglingDependencies'])))
                    self.assertEqual(json.loads(attrs['input_digests_json']), report['provenance']['inputDigests'])
                    filed = self.run_cli(*base, '--include-input-digests', '--include-dangling-dependencies',
                                         '--include-dangling-dependencies', '--output', output)
                    self.assertEqual((filed.returncode, filed.stdout), (0, ''), filed.stderr)
                    self.assertEqual(output.read_text(), proc.stdout)
                    plain = self.run_cli(*base)
                    self.assertEqual(plain.returncode, 0, plain.stderr)
                    self.assertNotIn('dangling_dependencies_json', parse_dot(plain.stdout)[0])

    def test_cli_dangling_rejects_non_dot_bad_inputs_and_preserves_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            output = Path(directory) / 'out'
            output.write_text('original')
            base = ['explain', 'examples/path/graph.json', '--grype', 'examples/path/graph-grype.json',
                    '--include-dangling-dependencies', '--output', output]
            for options in ([], ['--format', 'json'], ['--format', 'markdown'],
                            ['--format', 'markdown', '--no-roots', '--no-findings'],
                            ['--format', 'dot', '--finding-index', '999'], ['--format', 'dot', '--max-nodes', '0']):
                with self.subTest(options=options):
                    proc = self.run_cli(*base, *options)
                    self.assertEqual((proc.returncode, proc.stdout), (2, ''), proc.stderr)
                    self.assertEqual(output.read_text(), 'original')
                    if 'dot' not in options:
                        self.assertIn('include-dangling-dependencies requires DOT format', proc.stderr)
            bom = Path(directory) / 'bom.json'
            bom.write_text(json.dumps(fixture('graph.json')))
            alias = Path(directory) / 'alias.json'
            alias.hardlink_to(bom)
            before = bom.read_bytes()
            proc = self.run_cli('explain', bom, '--grype', 'examples/path/graph-grype.json', '--format', 'dot',
                                '--include-dangling-dependencies', '--output', alias)
            self.assertEqual((proc.returncode, proc.stdout), (2, ''), proc.stderr)
            self.assertEqual((bom.read_bytes(), alias.read_bytes()), (before, before))
            # An opt-in diagnostic must not skip full validation or relax SPDX endpoints.
            bad = fixture('bom.spdx.json')
            bad['relationships'].append({'spdxElementId': 'SPDXRef-app', 'relationshipType': 'DEPENDS_ON',
                                         'relatedSpdxElement': 'SPDXRef-missing'})
            bom.write_text(json.dumps(bad))
            proc = self.run_cli('explain', bom, '--grype', 'examples/path/grype.json', '--format', 'dot',
                                '--no-roots', '--no-findings', '--include-dangling-dependencies', '--output', output)
            self.assertEqual((proc.returncode, proc.stdout), (2, ''), proc.stderr)
            self.assertEqual(output.read_text(), 'original')
            self.assertNotIn(str(bom), proc.stderr)
            bad = fixture('graph-grype.json')
            bad['matches'][0]['artifact'] = None
            grype = Path(directory) / 'grype.json'
            grype.write_text(json.dumps(bad))
            proc = self.run_cli('explain', 'examples/path/graph.json', '--grype', grype, '--format', 'dot',
                                '--no-findings', '--include-dangling-dependencies', '--output', output)
            self.assertEqual((proc.returncode, proc.stdout), (2, ''), proc.stderr)
            self.assertEqual(output.read_text(), 'original')

    def test_cli_opt_in_input_digests_formats_mapping_and_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            output = Path(directory) / 'out.dot'
            for bname, gname, opts, roots, indexes, mapping in (
                    ('graph.json', 'graph-grype.json', ['--finding-index', '1'], None, [1], None),
                    ('graph.json', 'graph-grype.json', ['--no-roots', '--no-findings'], [], [], None),
                    ('graph.json', 'graph-grype.json', ['--root', 'app', '--root', 'worker', '--mapping', 'examples/path/mapping.json'],
                     ['app', 'worker'], None, fixture('mapping.json')),
                    ('bom.spdx.json', 'grype.json', [], None, None, None)):
                with self.subTest(bname=bname, opts=opts):
                    base = ['explain', 'examples/path/' + bname, '--grype', 'examples/path/' + gname,
                            '--format', 'dot', '--max-nodes', '1', '--max-edges', '1',
                            '--max-roots', '1', '--max-paths', '1', *opts]
                    proc = self.run_cli(*base, '--include-input-digests', '--include-input-digests')
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    report = explain(fixture(bname), fixture(gname), roots=roots, mapping=mapping,
                                     finding_indexes=indexes, max_roots=1, max_paths=1)
                    self.assertEqual(proc.stdout, sbom_pathfinder.to_dot(report, include_input_digests=True,
                                                                        max_nodes=1, max_edges=1))
                    self.assertEqual(json.loads(parse_dot(proc.stdout)[0]['input_digests_json']), report['provenance']['inputDigests'])
                    filed = self.run_cli(*base, '--include-input-digests', '--output', output)
                    self.assertEqual((filed.returncode, filed.stdout), (0, ''), filed.stderr)
                    self.assertEqual(output.read_text(), proc.stdout)
                    plain = self.run_cli(*base)
                    self.assertEqual(plain.returncode, 0, plain.stderr)
                    self.assertNotIn('input_digests_json', parse_dot(plain.stdout)[0])

    def test_cli_input_digests_rejects_non_dot_and_preserves_output_and_inputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            output = Path(directory) / 'out'
            output.write_text('original')
            base = ['explain', 'examples/path/graph.json', '--grype', 'examples/path/graph-grype.json',
                    '--include-input-digests', '--output', output]
            for opts in ([], ['--format', 'json'], ['--format', 'markdown'],
                         ['--format', 'markdown', '--no-findings', '--no-roots'],
                         ['--format', 'dot', '--finding-index', '999'],
                         ['--format', 'dot', '--max-nodes', '0']):
                with self.subTest(opts=opts):
                    proc = self.run_cli(*base, *opts)
                    self.assertEqual((proc.returncode, proc.stdout), (2, ''), proc.stderr)
                    self.assertEqual(output.read_text(), 'original')
                    if '--format' not in opts or 'dot' not in opts:
                        self.assertIn('input-digests requires DOT format', proc.stderr)
            bom = Path(directory) / 'private-bom.json'
            bom.write_text(json.dumps(fixture('graph.json')))
            alias = Path(directory) / 'alias.json'
            alias.hardlink_to(bom)
            before = bom.read_bytes()
            proc = self.run_cli('explain', bom, '--grype', 'examples/path/graph-grype.json',
                                '--format', 'dot', '--include-input-digests', '--output', alias)
            self.assertEqual((proc.returncode, proc.stdout), (2, ''), proc.stderr)
            self.assertEqual(bom.read_bytes(), before)
            self.assertEqual(alias.read_bytes(), before)
            # Opt-in never skips validation of unselected evidence.
            bad = fixture('graph-grype.json')
            bad['matches'][0]['artifact'] = None
            path = Path(directory) / 'private-grype.json'
            path.write_text(json.dumps(bad))
            proc = self.run_cli('explain', bom, '--grype', path, '--format', 'dot',
                                '--no-findings', '--include-input-digests', '--output', output)
            self.assertEqual((proc.returncode, proc.stdout), (2, ''), proc.stderr)
            self.assertEqual(output.read_text(), 'original')
            self.assertNotIn(str(path), proc.stderr)

    def test_cli_finding_scope_explicit_empty_all_and_duplicates(self):
        base = ['explain', 'examples/path/graph.json', '--grype', 'examples/path/graph-grype.json', '--format', 'dot']
        default = self.run_cli(*base)
        self.assertEqual(default.returncode, 0, default.stderr)
        for indexes in ([1], [1, 1], [], list(range(6))):
            for roots in (None, [], ['worker', 'app']):
                with self.subTest(indexes=indexes, roots=roots):
                    options = (['--no-findings', '--no-findings'] if not indexes else
                               [arg for i in indexes for arg in ('--finding-index', str(i))])
                    options += ([] if roots is None else ['--no-roots'] if roots == [] else
                                [arg for root in roots for arg in ('--root', root)])
                    proc = self.run_cli(*base, *options, '--max-nodes', '1', '--max-roots', '1', '--max-paths', '1')
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    attrs, _, _ = parse_dot(proc.stdout)
                    self.assertEqual(attrs.get('finding_selection'), 'explicit')
                    self.assertEqual(json.loads(attrs['selected_finding_indexes_json']), sorted(set(indexes)))
                    self.assertEqual((attrs['active_findings'], attrs['selected_results']), ('6', str(len(set(indexes)))))
                    report = explain(fixture('graph.json'), fixture('graph-grype.json'), roots=roots,
                                     finding_indexes=indexes, max_roots=1, max_paths=1)
                    self.assertEqual(proc.stdout, sbom_pathfinder.to_dot(report, max_nodes=1))
        self.assertNotIn('finding_selection', parse_dot(default.stdout)[0])

    def test_cli_explicit_root_scope_empty_repeated_capped_and_no_findings(self):
        base = ['explain', 'examples/path/graph.json', '--grype', 'examples/path/graph-grype.json', '--format', 'dot']
        for options, roots, indexes in (
                (['--no-roots', '--no-roots', '--finding-index', '1'], [], [1]),
                (['--no-roots', '--no-findings'], [], []),
                (['--root', 'worker', '--root', 'app', '--root', 'worker', '--finding-index', '0'],
                 ['app', 'worker'], [0]),
                (['--root', 'worker', '--root', 'app', '--root', 'worker', '--no-findings'],
                 ['app', 'worker'], [])):
            with self.subTest(options=options):
                proc = self.run_cli(*base, *options, '--max-nodes', '1', '--max-roots', '1', '--max-paths', '1')
                self.assertEqual(proc.returncode, 0, proc.stderr)
                attrs, _, _ = parse_dot(proc.stdout)
                self.assertEqual(attrs.get('root_selection'), 'explicit')
                self.assertEqual(json.loads(attrs['selected_roots_json']), roots)
                self.assertEqual(json.loads(attrs['selected_findings']), indexes)
                scope = ', '.join(roots) or '(none)'
                self.assertIn(f'Roots selected explicitly: {scope}.', attrs['label'])
                report = explain(fixture('graph.json'), fixture('graph-grype.json'), roots=roots,
                                 finding_indexes=indexes, max_roots=1, max_paths=1)
                self.assertEqual(proc.stdout, sbom_pathfinder.to_dot(report, max_nodes=1))

    def test_cli_dot_selection_caps_and_spdx(self):
        args = ['explain', 'examples/path/graph.json', '--grype', 'examples/path/graph-grype.json',
                '--root', 'app', '--root', 'worker', '--format', 'dot', '--finding-index', '0']
        proc = self.run_cli(*args)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        expected = sbom_pathfinder.to_dot(explain(fixture('graph.json'), fixture('graph-grype.json'),
                                         roots=['app', 'worker']), finding_indexes=[0])
        self.assertEqual(proc.stdout, expected)
        capped = self.run_cli(*args, '--max-nodes', 2, '--max-edges', 1)
        self.assertEqual(capped.returncode, 0, capped.stderr)
        self.assertEqual(parse_dot(capped.stdout)[0]['truncated'], 'true')
        spdx = self.run_cli('explain', 'examples/path/bom.spdx.json', '--grype', 'examples/path/grype.json', '--format', 'dot')
        self.assertEqual(spdx.returncode, 0, spdx.stderr)
        attrs, nodes, edges = parse_dot(spdx.stdout)
        self.assertEqual(refs_and_edges(nodes, edges), (
            {'SPDXRef-app', 'SPDXRef-a', 'SPDXRef-b'},
            {('SPDXRef-app', 'SPDXRef-a'), ('SPDXRef-a', 'SPDXRef-b')}))

    def test_cli_failures_preserve_output_and_dot_options_are_not_silently_ignored(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            out = Path(directory) / 'out.dot'
            out.write_text('original')
            base = ['explain', 'examples/path/bom.json', '--grype', 'examples/path/grype.json', '--output', out]
            for options in (['--format', 'dot', '--finding-index', '999'],
                            ['--format', 'dot', '--max-nodes', '0'],
                            ['--format', 'dot', '--max-edges', 'SECRET'],
                            ['--format', 'dot', '--finding-index', '-1'],
                            ['--max-nodes', '2'], ['--format', 'markdown', '--max-nodes', '2']):
                proc = self.run_cli(*base, *options)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertEqual(proc.stdout, '')
                self.assertNotIn('SECRET', proc.stderr)
                self.assertEqual(out.read_text(), 'original')
            proc = self.run_cli(*base, '--format', 'dot', '--finding-index', '0')
            self.assertEqual(proc.returncode, 0, proc.stderr)
            parse_dot(out.read_text())

    def test_cli_later_finding_gets_budget_before_dot_projection(self):
        args = ['explain', 'examples/path/graph.json', '--grype', 'examples/path/graph-grype.json',
                '--root', 'app', '--root', 'worker', '--format', 'dot', '--finding-index', '1',
                '--max-paths', '1']
        proc = self.run_cli(*args)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        attrs, nodes, edges = parse_dot(proc.stdout)
        self.assertEqual(refs_and_edges(nodes, edges),
                         ({'app', 'worker', 'lib-v2'}, {('worker', 'lib-v2')}))
        self.assertEqual(attrs['report_paths_omitted'], '0')
        self.assertEqual(attrs['truncated'], 'false')
        result = json.loads(attrs['results_json'])[0]
        self.assertEqual((result['findingIndex'], result['status'], result['affectedRootCount']),
                         (1, 'reachable', 1))
        self.assertEqual(proc.stdout, self.run_cli(*args, '--finding-index', '1').stdout)


if __name__ == '__main__':
    unittest.main()
