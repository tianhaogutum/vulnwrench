from copy import deepcopy
import json
from pathlib import Path
import unittest

from vulnwrench.layers import InputError, explain

ROOT = Path(__file__).resolve().parents[2]
A, B, C, D, E = ('sha256:' + c * 64 for c in 'abcde')


def fixture(name):
    return json.loads((ROOT / 'examples' / 'layers' / name).read_text())


class AttributionTests(unittest.TestCase):
    def setUp(self):
        self.report = fixture('trivy.json')
        self.base = fixture('base.json')
        self.image = fixture('image.json')

    def run_explain(self, **kwargs):
        return explain(self.report, self.base, self.image, **kwargs)

    def one(self, layer):
        finding = {'VulnerabilityID': 'DEMO', 'PkgName': 'openssl'}
        if layer is not None:
            finding['Layer'] = layer
        self.report['Results'][0]['Vulnerabilities'] = [finding]

    def test_groups_preserve_all_findings_and_extensions(self):
        originals = deepcopy((self.report, self.base, self.image))
        result = self.run_explain()
        self.assertEqual(result['counts'], {'base': 1, 'app': 2, 'unknown': 5, 'total': 8})
        self.assertEqual(result['provenance']['report'], self.report)
        self.assertTrue(result['provenance']['report']['SyntheticExtension']['preserve'])
        seen = {(f['source']['resultIndex'], f['source']['findingIndex']): f['finding']
                for group in result['groups'].values() for f in group}
        self.assertEqual(len(seen), 8)
        for j, finding in enumerate(self.report['Results'][0]['Vulnerabilities']):
            self.assertEqual(seen[0, j], finding)
        result['provenance']['report']['Results'].clear()
        self.assertEqual((self.report, self.base, self.image), originals)

    def test_name_collision_is_app_with_exact_evidence(self):
        finding = self.run_explain()['groups']['app'][0]
        self.assertEqual(finding['finding']['PkgName'], 'openssl')
        self.assertEqual((finding['origin'], finding['proof'], finding['diffId']),
                         ('app', 'exact_diff_id', B))

    def test_empty_history_is_ignored(self):
        result = self.run_explain()
        base = result['groups']['base'][0]
        app = result['groups']['app'][0]
        self.assertEqual(base['history'], [{'layerIndex': 0, 'historyIndex': 1,
                                           'createdBy': 'ADD synthetic base files /'}])
        self.assertEqual(app['history'][0]['historyIndex'], 3)
        self.assertEqual(app['history'][0]['createdBy'], 'COPY synthetic app upgrade /app')

    def test_missing_and_unmapped_digest_are_unknown(self):
        result = self.run_explain()
        reasons = {f['finding']['VulnerabilityID']: f['reason'] for f in result['groups']['unknown']}
        self.assertEqual(reasons['DEMO-MISSING-BASE-NAME'], 'missing_layer_evidence')
        self.assertEqual(reasons['DEMO-DIGEST-IS-NOT-DIFFID'], 'unmapped_compressed_digest')
        self.assertEqual(reasons['DEMO-UNMATCHED'], 'diff_id_not_in_image')

    def test_explicit_digest_mapping(self):
        result = self.run_explain(digest_map=fixture('digest-map.json'))
        finding = result['groups']['app'][-1]
        self.assertEqual(result['counts']['unknown'], 4)
        self.assertEqual((finding['diffId'], finding['proof']), (C, 'explicit_digest_mapping'))
        self.assertEqual(finding['digest'], D)

    def test_conflicting_mapping_is_unknown_even_with_diffid(self):
        self.one({'DiffID': A, 'Digest': D})
        result = self.run_explain(digest_map={D: B}, gate='app')
        self.assertEqual(result['groups']['unknown'][0]['reason'], 'conflicting_layer_evidence')
        self.assertEqual(result['gate']['status'], 'failed')

    def test_gate_disabled_by_default(self):
        self.assertEqual(self.run_explain()['gate'],
                         {'mode': 'none', 'status': 'disabled', 'blockingFindings': 0})

    def test_app_gate_keeps_base_and_unknown(self):
        result = self.run_explain(gate='app')
        self.assertEqual(result['gate']['blockingFindings'], 7)
        self.assertEqual(result['counts']['total'], 8)
        self.assertEqual(len(result['groups']['base']), 1)

    def test_base_only_app_gate_passes_all_gate_fails(self):
        self.one({'DiffID': A})
        self.assertEqual(self.run_explain(gate='app')['gate']['status'], 'passed')
        self.assertEqual(self.run_explain(gate='all')['gate']['status'], 'failed')

    def test_unknown_only_fails_app_gate(self):
        self.one(None)
        self.assertEqual(self.run_explain(gate='app')['gate']['status'], 'failed')

    def test_clean_report(self):
        for results in ([], None):
            with self.subTest(results=results):
                self.report['Results'] = results
                result = self.run_explain(gate='app')
                self.assertEqual(result['counts']['total'], 0)
                self.assertEqual(result['gate']['status'], 'passed')
        del self.report['Results']
        self.assertEqual(self.run_explain()['counts']['total'], 0)

    def test_multiple_targets_and_duplicate_vuln_ids_are_not_deduplicated(self):
        self.one({'DiffID': A})
        self.report['Results'].append(deepcopy(self.report['Results'][0]))
        self.report['Results'][1]['Target'] = 'another target'
        result = self.run_explain()
        self.assertEqual(result['counts']['base'], 2)
        self.assertEqual(result['groups']['base'][1]['source']['resultIndex'], 1)

    def test_history_mismatch_preserves_attribution_but_no_guessed_command(self):
        self.image['history'].pop(1)
        result = self.run_explain()
        self.assertEqual(result['counts']['app'], 2)
        self.assertIn('history_count_mismatch', [w['code'] for w in result['warnings']])
        for group in result['groups'].values():
            for finding in group:
                for history in finding['history']:
                    self.assertIsNone(history['createdBy'])
                    self.assertIsNone(history['historyIndex'])

    def test_history_absent_and_missing_command(self):
        del self.image['history']
        result = self.run_explain()
        self.assertIn('history_missing', [w['code'] for w in result['warnings']])
        self.image['history'] = [{}, {}, {}]
        result = self.run_explain()
        self.assertIn('history_command_missing', [w['code'] for w in result['warnings']])

    def test_base_history_mismatch_and_command_disagreement_warn(self):
        self.base['history'][-1]['created_by'] = 'different description'
        self.assertIn('base_image_history_commands_differ', [w['code'] for w in self.run_explain()['warnings']])
        self.base['history'] = []
        self.assertIn({'code': 'history_count_mismatch', 'source': 'base',
                       'diffIdCount': 1, 'nonEmptyHistoryCount': 0}, self.run_explain()['warnings'])

    def test_nonprefix_and_longer_base_are_rejected(self):
        for ids in ([B], [A, B, C, D], [B, A]):
            with self.subTest(ids=ids):
                self.base['rootfs']['diff_ids'] = ids
                with self.assertRaisesRegex(InputError, 'exact prefix'):
                    self.run_explain()

    def test_empty_base_is_valid(self):
        self.base = {'rootfs': {'type': 'layers', 'diff_ids': []}, 'history': []}
        result = self.run_explain()
        self.assertEqual(result['counts']['base'], 0)
        self.assertEqual(result['counts']['app'], 3)

    def test_repeated_diffid_crossing_boundary_is_unknown(self):
        self.image['rootfs']['diff_ids'].append(A)
        self.image['history'].append({'created_by': 'repeat base contents'})
        self.report['Metadata']['DiffIDs'].append(A)
        result = self.run_explain()
        finding = result['groups']['unknown'][0]
        self.assertEqual(finding['reason'], 'diff_id_crosses_base_boundary')
        self.assertEqual(finding['layerIndices'], [0, 3])
        self.assertEqual(finding['warnings'], ['repeated_diff_id'])

    def test_repeated_diffid_in_same_origin_retains_all_history(self):
        self.image['rootfs']['diff_ids'].append(B)
        self.image['history'].append({'created_by': 'same app content'})
        self.report['Metadata']['DiffIDs'].append(B)
        finding = self.run_explain()['groups']['app'][0]
        self.assertEqual(finding['layerIndices'], [1, 3])
        self.assertEqual(len(finding['history']), 2)
        self.assertIn('repeated_diff_id', finding['warnings'])

    def test_report_binding_mismatch_makes_every_finding_unknown(self):
        self.report['Metadata']['DiffIDs'] = [A, B]
        result = self.run_explain(gate='app')
        self.assertEqual(result['counts']['unknown'], 8)
        self.assertEqual(result['counts']['base'], 0)
        self.assertTrue(all(f['reason'] == 'report_config_mismatch' for f in result['groups']['unknown']))

    def test_report_binding_missing_is_explicit(self):
        del self.report['Metadata']['DiffIDs']
        result = self.run_explain()
        self.assertEqual(result['ancestry']['reportConfigBinding'], 'unverified')
        self.assertIn('report_config_binding_unverified', [w['code'] for w in result['warnings']])

    def test_report_imageconfig_binding(self):
        del self.report['Metadata']['DiffIDs']
        self.report['Metadata']['ImageConfig'] = deepcopy(self.image)
        self.assertEqual(self.run_explain()['ancestry']['reportConfigBinding'], 'diff_ids_consistent')
        self.report['Metadata']['ImageConfig']['rootfs']['diff_ids'] = [A]
        self.assertEqual(self.run_explain()['counts']['unknown'], 8)

    def test_both_binding_sequences_must_match(self):
        self.report['Metadata']['ImageConfig'] = deepcopy(self.base)
        self.assertEqual(self.run_explain()['counts']['unknown'], 8)

    def test_empty_layer_objects_are_missing_evidence(self):
        for layer in (None, {}, {'DiffID': '', 'Digest': ''}, {'FutureLayerField': 'retained'}):
            with self.subTest(layer=layer):
                self.one(layer)
                finding = self.run_explain()['groups']['unknown'][0]
                self.assertEqual(finding['reason'], 'missing_layer_evidence')
                self.assertEqual(finding['finding'], self.report['Results'][0]['Vulnerabilities'][0])

    def test_malformed_diffids_rejected_without_value_echo(self):
        for value in ('sha256:aaa', 'sha512:' + 'a' * 128, 'sha256:' + 'A' * 64, 'SECRET-TEST', 123, None):
            with self.subTest(value=value):
                self.one({'DiffID': value})
                with self.assertRaises(InputError) as caught:
                    self.run_explain()
                self.assertNotIn('SECRET-TEST', str(caught.exception))
                self.base['rootfs']['diff_ids'] = [value]
                with self.assertRaises(InputError):
                    self.run_explain()
                self.base = fixture('base.json')

    def test_invalid_mapping_is_rejected(self):
        for mapping in ([], {D: E}, {'bad': A}, {D: 'bad'}):
            with self.subTest(mapping=mapping):
                with self.assertRaises(InputError):
                    self.run_explain(digest_map=mapping)

    def test_unsupported_report_schemas(self):
        for field, value in (('SchemaVersion', 1), ('SchemaVersion', True), ('ArtifactType', 'filesystem'),
                             ('ArtifactType', 'repository'), ('Results', {}), ('Metadata', [])):
            with self.subTest(field=field, value=value):
                self.report = fixture('trivy.json')
                self.report[field] = value
                with self.assertRaises(InputError):
                    self.run_explain()

    def test_other_finding_families_rejected(self):
        for family in ('Secrets', 'Misconfigurations', 'Licenses', 'CustomResources'):
            with self.subTest(family=family):
                self.report = fixture('trivy.json')
                self.report['Results'][0][family] = [{'arbitrary': 'data'}]
                with self.assertRaisesRegex(InputError, 'unsupported finding family'):
                    self.run_explain()

    def test_malformed_empty_finding_families_are_rejected(self):
        for value in ({}, "", 0, False):
            with self.subTest(value=value):
                self.report['Results'][0]['Secrets'] = value
                with self.assertRaises(InputError):
                    self.run_explain()

    def test_invalid_structures_rejected(self):
        invalid = [
            ('base', 'rootfs', None), ('base', 'rootfs', {'type': 'not-layers', 'diff_ids': []}),
            ('base', 'rootfs', {'type': 'layers', 'diff_ids': 'bad'}),
            ('image', 'history', 'bad'), ('image', 'history', [None]),
            ('image', 'history', [{'empty_layer': 1}]), ('image', 'history', [{'created_by': 3}]),
        ]
        for source, key, value in invalid:
            with self.subTest(source=source, key=key, value=value):
                self.base, self.image = fixture('base.json'), fixture('image.json')
                getattr(self, source)[key] = value
                with self.assertRaises(InputError):
                    self.run_explain()

    def test_invalid_vulnerability_structures(self):
        for value in ('bad', [None], [{}], [{'PkgName': 'a', 'VulnerabilityID': 'b', 'Layer': []}]):
            with self.subTest(value=value):
                self.report['Results'][0]['Vulnerabilities'] = value
                with self.assertRaises(InputError):
                    self.run_explain()

    def test_invalid_gate(self):
        with self.assertRaises(InputError):
            self.run_explain(gate='typo')


if __name__ == '__main__':
    unittest.main()
