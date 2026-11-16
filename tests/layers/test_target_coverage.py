"""Map-only target coverage, independent of vulnerability observation.

targetCoverage lists distinct before names in report order, then unclaimed after
names. status=paired uses match=explicit_map or exact_name; unmatched entries use
before_only/after_only and match=null. beforeTarget/afterTarget retain original
names (null for absence); before/after retain ALL original report Results pointers.
Repeated names are not positional result pairs, even with unequal repeat counts or
different Class/Type. Omitted/null/empty vulnerability arrays still supply targets.
Empty map enables coverage; omitted map preserves legacy bytes. No completeness,
remediation, new finding rows/counts, or rewritten snapshots may be inferred.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import unittest

from vulnwrench.layers import InputError, compare, explain

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    return json.loads((ROOT / 'examples' / 'layers' / name).read_bytes())


def resolve(document, pointer):
    value = document
    for part in pointer.removeprefix('#/').split('/'):
        part = part.replace('~1', '/').replace('~0', '~')
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def entry(old, new, match, before, after):
    return {'status': 'paired' if old is not None and new is not None else
            'before_only' if old is not None else 'after_only',
            'match': match, 'beforeTarget': old, 'afterTarget': new,
            'before': [f'#/snapshots/before/provenance/report/Results/{i}' for i in before],
            'after': [f'#/snapshots/after/provenance/report/Results/{i}' for i in after]}


class TargetCoverageTests(unittest.TestCase):
    def setUp(self):
        self.before = load('target-coverage-before.json')
        self.after = load('target-coverage-after.json')
        self.mapping = load('target-map.json')
        self.base = load('base.json')
        self.image = load('image.json')

    def compare(self, **options):
        return compare(self.before, self.base, self.image, self.after, self.base, self.image,
                       **options)

    def assert_references(self, output):
        for side in ('before', 'after'):
            refs = [ref for item in output['targetCoverage'] for ref in item[side]]
            report = output['snapshots'][side]['provenance']['report']
            self.assertCountEqual(refs, [f'#/snapshots/{side}/provenance/report/Results/{i}'
                                        for i in range(len(report.get('Results') or []))])
            self.assertEqual(len(refs), len(set(refs)))
            for item in output['targetCoverage']:
                for ref in item[side]:
                    self.assertEqual(resolve(output, ref)['Target'], item[side + 'Target'])

    def test_zero_finding_pairs_exact_unlisted_and_unmatched_keep_every_result(self):
        original = deepcopy((self.before, self.after, self.mapping))
        result = self.compare(target_map=self.mapping)
        self.assertEqual(result['targetCoverage'], [
            entry('synthetic-upgrade', 'synthetic-upgrade:v2', 'explicit_map', [0, 3], [2]),
            entry('stable/packages~1', 'stable/packages~1', 'exact_name', [1], [1]),
            entry('old-only', None, None, [2], []),
            entry(None, 'new-only', None, [], [0])])
        self.assertEqual(result['rows'], [])
        self.assertEqual(result['counts'], dict(attribution_changed=0, unknown=0, unchanged=0,
                                              before_only=0, after_only=0, total=0))
        self.assert_references(result)
        self.assertEqual(result, self.compare(target_map=self.mapping))
        self.assertEqual(result['snapshots'], self.compare()['snapshots'])
        result['targetCoverage'][0]['before'].clear()
        result['snapshots']['before']['provenance']['report'].clear()
        result['targetMap'].clear()
        self.assertEqual((self.before, self.after, self.mapping), original)

    def test_empty_map_and_missing_null_or_empty_results(self):
        result = self.compare(target_map={})
        self.assertEqual(result['targetCoverage'], [
            entry('synthetic-upgrade', None, None, [0, 3], []),
            entry('stable/packages~1', 'stable/packages~1', 'exact_name', [1], [1]),
            entry('old-only', None, None, [2], []),
            entry(None, 'new-only', None, [], [0]),
            entry(None, 'synthetic-upgrade:v2', None, [], [2])])
        for side in ('before', 'after'):
            for state in ('omitted', None, []):
                with self.subTest(side=side, state=state):
                    self.setUp()
                    document = getattr(self, side)
                    document.pop('Results')
                    if state != 'omitted':
                        document['Results'] = state
                    result = self.compare(target_map={})
                    self.assertTrue(all(not item[side] for item in result['targetCoverage']))
                    self.assert_references(result)
        self.before['Results'] = self.after['Results'] = []
        self.assertEqual(self.compare(target_map={})['targetCoverage'], [])

    def test_explicit_swaps_chains_self_maps_and_unclaimed_names(self):
        for old, new, mapping, expected in [
            (['b', 'a'], ['a', 'b'], {'a': 'b', 'b': 'a'},
             [entry('b', 'a', 'explicit_map', [0], [0]),
              entry('a', 'b', 'explicit_map', [1], [1])]),
            (['a', 'b'], ['a', 'b', 'c'], {'a': 'b', 'b': 'c'},
             [entry('a', 'b', 'explicit_map', [0], [1]),
              entry('b', 'c', 'explicit_map', [1], [2]), entry(None, 'a', None, [], [0])]),
            (['a'], ['a'], {'a': 'a'}, [entry('a', 'a', 'explicit_map', [0], [0])]),
            (['a'], ['a', 'b'], {'a': 'b'},
             [entry('a', 'b', 'explicit_map', [0], [1]), entry(None, 'a', None, [], [0])])]:
            with self.subTest(mapping=mapping):
                self.before['Results'] = [{'Target': name} for name in old]
                self.after['Results'] = [{'Target': name} for name in new]
                result = self.compare(target_map=mapping)
                self.assertEqual(result['targetCoverage'], expected)
                self.assertEqual(result['targetCoverage'], self.compare(
                    target_map=dict(reversed(list(mapping.items()))))['targetCoverage'])
                self.assert_references(result)

    def test_repeated_names_retain_all_per_side_results_without_positional_pairing(self):
        self.after['Results'].extend([
            {'Target': 'synthetic-upgrade:v2', 'Class': 'unrelated', 'Vulnerabilities': []},
            {'Target': 'synthetic-upgrade:v2', 'Type': 'different'}])
        result = self.compare(target_map=self.mapping)
        self.assertEqual(result['targetCoverage'][0], entry(
            'synthetic-upgrade', 'synthetic-upgrade:v2', 'explicit_map', [0, 3], [2, 3, 4]))
        self.assert_references(result)
        self.assertEqual(result['counts']['total'], 0)

    def test_target_pair_is_independent_of_finding_identity_and_duplicate_ambiguity(self):
        self.before, self.after = load('upgrade-before.json'), load('upgrade-renamed-after.json')
        self.before['Results'].append(deepcopy(self.before['Results'][0]))
        self.before['Results'][1]['Vulnerabilities'] = []
        # Two occurrences of the same finding remain ambiguous; coverage adds no rows.
        self.after['Results'][0]['Vulnerabilities'].append(
            deepcopy(self.after['Results'][0]['Vulnerabilities'][0]))
        result = self.compare(target_map=self.mapping)
        self.assertEqual(result['counts']['total'], 2)
        self.assertEqual(result['rows'][0]['reason'], 'ambiguous_finding_identity')
        self.assertEqual(result['targetCoverage'], [entry(
            'synthetic-upgrade', 'synthetic-upgrade:v2', 'explicit_map', [0, 1], [0])])
        self.assert_references(result)
        self.after['Results'][0]['Class'] = 'different'
        result = self.compare(target_map=self.mapping)
        self.assertEqual(result['counts']['before_only'], 2)
        self.assertEqual(result['targetCoverage'][0]['status'], 'paired')
        self.assertEqual(result['snapshots']['before'], explain(self.before, self.base, self.image))
        self.assertEqual(result['snapshots']['after'], explain(self.after, self.base, self.image))

    def test_map_coverage_preserves_pinned_manifest_snapshot_evidence(self):
        raw = (ROOT / 'examples/layers/upgraded-base-manifest.json').read_bytes()
        pin = 'sha256:' + hashlib.sha256(raw).hexdigest()
        base = (ROOT / 'examples/layers/upgraded-base.json').read_bytes()
        image = load('upgraded-image.json')
        mapping = load('upgraded-base-digest-map.json')
        options = {f'{side}_{key}': value for side in ('before', 'after') for key, value in
                   dict(base_manifest=raw, base_manifest_sha256=pin, base_digest_map=mapping).items()}
        plain = compare(self.before, base, image, self.after, base, image, **options)
        mapped = compare(self.before, base, image, self.after, base, image,
                         target_map=self.mapping, **options)
        self.assertEqual(mapped['snapshots'], plain['snapshots'])
        self.assertEqual(len(mapped['targetCoverage']), 4)
        for snapshot in mapped['snapshots'].values():
            self.assertEqual(snapshot['ancestry']['baseManifestBinding']['manifestDigest'], pin)
            self.assertEqual(snapshot['provenance']['baseManifest'], json.loads(raw))

    def test_zero_findings_do_not_relax_invalid_maps_or_input_validation(self):
        for mapping in ([], {'': 'synthetic-upgrade:v2'}, {'SECRET': 'new-only'},
                        {'old-only': 'SECRET'}, {'old-only': None},
                        {'synthetic-upgrade': 'new-only', 'old-only': 'new-only'},
                        {'old-only': 'stable/packages~1'}):
            with self.subTest(mapping=mapping):
                with self.assertRaises(InputError) as caught:
                    self.compare(target_map=mapping)
                self.assertNotIn('SECRET', str(caught.exception))
        self.after['Results'][0]['Vulnerabilities'] = {}
        with self.assertRaises(InputError):
            self.compare(target_map=self.mapping)

    def test_no_map_uses_existing_byte_exact_comparison_golden(self):
        result = compare(load('upgrade-before.json'), self.base, self.image,
                         load('upgrade-after.json'), load('upgraded-base.json'),
                         load('upgraded-image.json'))
        content = json.dumps(result, sort_keys=True, indent=2, ensure_ascii=True,
                             allow_nan=False) + '\n'
        self.assertEqual(content.encode(), (ROOT / 'examples/layers/upgrade-expected.json').read_bytes())
        self.assertNotIn('targetCoverage', self.compare())
        self.assertEqual(self.compare(), self.compare(target_map=None))


if __name__ == '__main__':
    unittest.main()
