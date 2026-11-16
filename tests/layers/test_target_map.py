"""Explicit partial target bijection: no inferred renames or lost evidence.

Contract: target_map maps nonempty before Target strings to existing after Targets.
Unlisted targets still match themselves. The effective relation must be injective,
including these implicit matches. Unknown endpoints, malformed objects/strings and
colliding destinations reject the whole comparison. A valid map only substitutes
Target in matching: all other fields stay exact and duplicates stay ambiguous.
Rows retain their original identity plus beforeTarget/afterTarget; targetMap records
only the caller's assertions. Both complete snapshots and proof pointers survive.
CLI errors return 2 with no stdout and preserve outputs and all map input aliases.
"""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from vulnwrench.layers import InputError, compare
from vulnwrench.layers.cli import main

ROOT = Path(__file__).resolve().parents[2]
A, B, C = ('sha256:' + c * 64 for c in 'abc')


def config(ids):
    return {'rootfs': {'type': 'layers', 'diff_ids': ids}}


def report(*targets):
    return {'SchemaVersion': 2, 'ArtifactType': 'container_image', 'Results': [
        {'Target': target, 'Class': 'os-pkgs', 'Type': 'debian', 'Vulnerabilities': [
            {'VulnerabilityID': 'MOVED', 'PkgName': 'shared', 'InstalledVersion': '1',
             'Layer': {'DiffID': B}},
            {'VulnerabilityID': 'LOST', 'PkgName': 'shared', 'InstalledVersion': '1',
             'Layer': {'DiffID': C}}]} for target in targets]}


def resolve(document, ref):
    value = document
    for part in ref.removeprefix('#/').split('/'):
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


class TargetMapTests(unittest.TestCase):
    def setUp(self):
        self.before = report('image:old')
        self.after = report('image:new')
        del self.after['Results'][0]['Vulnerabilities'][1]['Layer']
        self.mapping = {'image:old': 'image:new'}

    def run_compare(self, **kwargs):
        return compare(self.before, config([A]), config([A, B, C]),
                       self.after, config([A, B]), config([A, B, C]), **kwargs)

    def test_explicit_tag_change_matches_and_preserves_original_evidence(self):
        original = deepcopy((self.before, self.after, self.mapping))
        unmatched = self.run_compare()
        self.assertEqual((unmatched['counts']['before_only'], unmatched['counts']['after_only']), (2, 2))
        result = self.run_compare(target_map=self.mapping)
        self.assertEqual(result['counts'], {'attribution_changed': 1, 'unknown': 1,
                         'unchanged': 0, 'before_only': 0, 'after_only': 0, 'total': 2})
        self.assertEqual(result['targetMap'], self.mapping)
        self.assertEqual(result['snapshots'], unmatched['snapshots'])
        self.assertEqual(result, self.run_compare(target_map=self.mapping))
        self.assertIn({'code': 'target_map_is_caller_assertion'}, result['warnings'])
        self.assertNotIn({'code': 'exact_identity_matching_only'}, result['warnings'])
        for row in result['rows']:
            self.assertEqual((row['identity']['Target'], row['beforeTarget'], row['afterTarget']),
                             ('image:old', 'image:old', 'image:new'))
            for side, target in [('before', 'image:old'), ('after', 'image:new')]:
                record = resolve(result, row[side][0])
                self.assertEqual(record['source']['target'], target)
                self.assertIn('proof', record)
        result['targetMap'].clear()
        result['snapshots']['before']['provenance']['report'].clear()
        self.assertEqual((self.before, self.after, self.mapping), original)

    def test_unlisted_targets_match_exactly_and_empty_map_infers_nothing(self):
        self.before = report('image:old', 'stable', 'old-only')
        self.after = report('image:new', 'stable', 'new-only')
        mapped = self.run_compare(target_map=self.mapping)
        self.assertEqual(mapped['counts'], {'attribution_changed': 2, 'unknown': 0,
                         'unchanged': 2, 'before_only': 2, 'after_only': 2, 'total': 8})
        for row in mapped['rows']:
            if row['status'] == 'before_only':
                self.assertEqual((row['beforeTarget'], row['afterTarget']), ('old-only', None))
            if row['status'] == 'after_only':
                self.assertEqual((row['beforeTarget'], row['afterTarget']), (None, 'new-only'))
        empty = self.run_compare(target_map={})
        plain = self.run_compare()
        self.assertEqual(empty['counts'], plain['counts'])
        self.assertEqual(empty['snapshots'], plain['snapshots'])
        self.assertEqual(self.run_compare(target_map=None), plain)
        self.assertNotIn('targetMap', plain)
        self.assertNotIn('beforeTarget', plain['rows'][0])

    def test_swaps_chains_self_maps_and_unclaimed_after_name_do_not_cross_match(self):
        for old, new, mapping, pairs in [
            (['a', 'b'], ['a', 'b'], {'a': 'b', 'b': 'a'}, [('a', 'b'), ('b', 'a')]),
            (['a', 'b'], ['a', 'b', 'c'], {'a': 'b', 'b': 'c'},
             [('a', 'b'), ('b', 'c'), (None, 'a')]),
            (['a'], ['a'], {'a': 'a'}, [('a', 'a')]),
            (['a'], ['a', 'b'], {'a': 'b'}, [('a', 'b'), (None, 'a')])]:
            with self.subTest(mapping=mapping):
                self.before, self.after = report(*old), report(*new)
                result = self.run_compare(target_map=mapping)
                self.assertEqual([(r['beforeTarget'], r['afterTarget']) for r in result['rows'][::2]], pairs)
                self.assertEqual(result['counts']['before_only'], 0)
                self.assertEqual(result['counts']['after_only'], 2 if None in pairs[-1] else 0)

    def test_all_other_identity_fields_remain_exact(self):
        for section, field in [('result', 'Class'), ('result', 'Type'),
                               ('finding', 'VulnerabilityID'), ('finding', 'PkgName'),
                               ('finding', 'InstalledVersion'), ('finding', 'PkgPath'), ('finding', 'PkgID')]:
            with self.subTest(field=field):
                self.setUp()
                target = self.after['Results'][0]
                if section == 'finding':
                    target = target['Vulnerabilities'][0]
                target[field] = 'changed'
                result = self.run_compare(target_map=self.mapping)
                count = 2 if section == 'result' else 1
                self.assertEqual(result['counts']['before_only'], count)
                self.assertEqual(result['counts']['after_only'], count)

    def test_duplicate_identities_remain_unknown_and_every_occurrence_is_referenced(self):
        for side in ('before', 'after'):
            with self.subTest(side=side):
                self.setUp()
                entries = getattr(self, side)['Results'][0]['Vulnerabilities']
                entries.append(deepcopy(entries[0]))
                result = self.run_compare(target_map=self.mapping)
                row = result['rows'][0]
                self.assertEqual((row['status'], row['reason']), ('unknown', 'ambiguous_finding_identity'))
                self.assertEqual(len(row[side]), 2)
                for snapshot in ('before', 'after'):
                    refs = [ref for row in result['rows'] for ref in row[snapshot]]
                    self.assertEqual(len(refs), result['snapshots'][snapshot]['counts']['total'])
                    self.assertEqual(len(refs), len(set(refs)))
                    for ref in refs:
                        self.assertIn('finding', resolve(result, ref))

    def test_invalid_mapping_shape_strings_and_unknown_endpoints_reject_quietly(self):
        for mapping in ([], 'SECRET', 1, False, {1: 'image:new'}, {'': 'image:new'},
                        {'image:old': ''}, {'image:old': None}, {'image:old': []},
                        {'SECRET': 'image:new'}, {'image:old': 'SECRET'},
                        {'image:new': 'image:old'}):
            with self.subTest(mapping=mapping):
                with self.assertRaises(InputError) as caught:
                    self.run_compare(target_map=mapping)
                self.assertNotIn('SECRET', str(caught.exception))

    def test_many_to_one_and_implicit_identity_collisions_are_rejected(self):
        self.before, self.after = report('a', 'b'), report('b', 'c')
        for mapping in ({'a': 'c', 'b': 'c'}, {'a': 'b'}):
            with self.subTest(mapping=mapping):
                with self.assertRaisesRegex(InputError, 'non-bijective'):
                    self.run_compare(target_map=mapping)
        # Validation applies to target names even without any findings.
        for doc in (self.before, self.after):
            for result in doc['Results']:
                result['Vulnerabilities'] = []
        with self.assertRaisesRegex(InputError, 'non-bijective'):
            self.run_compare(target_map={'a': 'b'})
        self.assertEqual(self.run_compare(target_map={'a': 'b', 'b': 'c'})['counts']['total'], 0)

    def test_empty_results_can_be_mapped_but_absent_targets_cannot(self):
        for doc in (self.before, self.after):
            doc['Results'][0].pop('Vulnerabilities')
        self.assertEqual(self.run_compare(target_map=self.mapping)['counts']['total'], 0)
        self.before['Results'] = []
        with self.assertRaisesRegex(InputError, 'absent from before'):
            self.run_compare(target_map=self.mapping)


class TargetMapCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.before, self.after = report('image:old'), report('image:new')
        del self.after['Results'][0]['Vulnerabilities'][1]['Layer']
        self.command = ['compare']
        for name, doc in {'before-report': self.before, 'after-report': self.after,
                          'before-base-config': config([A]), 'after-base-config': config([A, B]),
                          'before-image-config': config([A, B, C]),
                          'after-image-config': config([A, B, C])}.items():
            path = self.directory / (name + '.json')
            path.write_text(json.dumps(doc))
            self.command.extend(['--' + name, str(path)])
        self.mapping = self.directory / 'target-map.json'
        self.mapping.write_text(json.dumps({'image:old': 'image:new'}))
        self.command.extend(['--target-map', str(self.mapping)])

    def invoke(self, *args):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'layers', *self.command, *args],
                              cwd=ROOT, capture_output=True, text=True, timeout=60)

    def test_cli_map_contract_and_determinism(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        doc = json.loads(result.stdout)
        self.assertEqual(doc['counts']['attribution_changed'], 1)
        self.assertEqual(doc['counts']['unknown'], 1)
        self.assertEqual(doc['counts']['total'], 2)
        self.assertEqual(doc['targetMap'], {'image:old': 'image:new'})
        self.assertEqual(result.stdout, self.invoke().stdout)
        output = self.directory / 'output.json'
        result = self.invoke('--output', str(output))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(), self.invoke().stdout)

    def test_bad_maps_strict_json_and_io_errors_preserve_output(self):
        output = self.directory / 'output.json'
        output.write_text('preserved')
        for raw, error in [(b'{"image:old":"image:new","image:old":"SECRET"}', 'duplicate object keys'),
                           (b'{"image:old":"SECRET"}', 'absent from after'),
                           (b'{"SECRET":"image:new"}', 'absent from before'),
                           (b'{"image:old":null}', 'nonempty string'),
                           (b'[]', 'expected JSON object'), (b'{"x":NaN}', 'non-finite'),
                           (b'\xff', 'invalid UTF-8 JSON')]:
            with self.subTest(error=error):
                self.mapping.write_bytes(raw)
                result = self.invoke('--output', str(output))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(error, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertNotIn('SECRET', result.stderr)
                self.assertNotIn('Traceback', result.stderr)
                self.assertEqual(output.read_text(), 'preserved')
        self.mapping.unlink()
        result = self.invoke('--output', str(output))
        self.assertEqual(result.returncode, 2)
        self.assertIn('target map: unable to read input', result.stderr)
        self.assertEqual(output.read_text(), 'preserved')

    def test_cli_rejects_nonbijective_maps_including_empty_results(self):
        before, after = report('a', 'b'), report('b', 'c')
        for doc in (before, after):
            for result in doc['Results']:
                result['Vulnerabilities'] = []
        (self.directory / 'before-report.json').write_text(json.dumps(before))
        (self.directory / 'after-report.json').write_text(json.dumps(after))
        output = self.directory / 'output.json'
        output.write_text('preserved')
        for mapping in ({'a': 'c', 'b': 'c'}, {'a': 'b'}):
            self.mapping.write_text(json.dumps(mapping))
            result = self.invoke('--output', str(output))
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('non-bijective', result.stderr)
            self.assertEqual(result.stdout, '')
            self.assertEqual(output.read_text(), 'preserved')

    def test_map_input_direct_symlink_and_hardlink_outputs_are_protected(self):
        original = self.mapping.read_bytes()
        symlink, hardlink = self.directory / 'symlink.json', self.directory / 'hardlink.json'
        symlink.symlink_to(self.mapping)
        hardlink.hardlink_to(self.mapping)
        for alias in (self.mapping, symlink, hardlink):
            with self.subTest(alias=alias.name):
                result = self.invoke('--output', str(alias))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('must not replace an input', result.stderr)
                self.assertEqual(self.mapping.read_bytes(), original)

    def test_map_uses_bounded_input_reader(self):
        # All other fixture inputs are shorter than the deliberately padded map.
        self.mapping.write_text(' ' * 4096 + self.mapping.read_text())
        output = self.directory / 'output.json'
        output.write_text('preserved')
        with patch('vulnwrench.layers.cli.MAX_INPUT_BYTES', 4096), \
             patch('sys.stderr') as stderr:
            self.assertEqual(main([*self.command, '--output', str(output)]), 2)
        self.assertIn('target map: input exceeds 32 MiB', stderr.write.call_args_list[0].args[0])
        self.assertEqual(output.read_text(), 'preserved')


if __name__ == '__main__':
    unittest.main()
