"""Synthetic integration contract for independent base-upgrade attribution."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import vulnwrench.layers as api

ROOT = Path(__file__).resolve().parents[2]
A, B, C = ('sha256:' + c * 64 for c in 'abc')


def config(ids):
    return {'rootfs': {'type': 'layers', 'diff_ids': ids}}


def report():
    return {'SchemaVersion': 2, 'ArtifactType': 'container_image',
            'Metadata': {'DiffIDs': [A, B, C]}, 'Results': [
                {'Target': 'synthetic', 'Class': 'os-pkgs', 'Type': 'debian',
                 'Vulnerabilities': [
                     {'VulnerabilityID': 'DEMO-MOVED', 'PkgName': 'shared',
                      'InstalledVersion': '1', 'Layer': {'DiffID': B}},
                     {'VulnerabilityID': 'DEMO-LOST-EVIDENCE', 'PkgName': 'shared',
                      'InstalledVersion': '1', 'Layer': {'DiffID': C}}]}]}


def resolve(document, ref):
    value = document
    for part in ref.removeprefix('#/').split('/'):
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.before = report()
        self.after = report()
        del self.after['Results'][0]['Vulnerabilities'][1]['Layer']
        self.old_base = config([A])
        self.new_base = config([A, B])
        self.image = config([A, B, C])

    def compare(self, **kwargs):
        return api.compare(self.before, self.old_base, self.image,
                           self.after, self.new_base, self.image, **kwargs)

    def test_prefix_change_and_missing_evidence_are_separate_with_resolvable_proofs(self):
        original = deepcopy((self.before, self.after, self.old_base, self.new_base, self.image))
        result = self.compare()
        self.assertEqual(result['basePrefixChange'], {'changed': True,
                         'before': [A], 'after': [A, B]})
        self.assertEqual(result['counts'], {'attribution_changed': 1, 'unknown': 1,
                         'unchanged': 0, 'before_only': 0, 'after_only': 0, 'total': 2})
        moved, unknown = result['rows']
        self.assertEqual(moved['status'], 'attribution_changed')
        self.assertEqual([resolve(result, moved[side][0])['origin'] for side in ('before', 'after')],
                         ['app', 'base'])
        self.assertEqual(unknown['status'], 'unknown')
        self.assertEqual(resolve(result, unknown['after'][0])['reason'], 'missing_layer_evidence')
        for row in result['rows']:
            for side in ('before', 'after'):
                for ref in row[side]:
                    evidence = resolve(result, ref)
                    self.assertIn('proof', evidence)
                    self.assertIn('source', evidence)
                    self.assertIn('finding', evidence)
        self.assertNotIn('remediated', json.dumps(result))
        self.assertEqual(result, self.compare())
        result['snapshots']['before']['provenance']['report'].clear()
        self.assertEqual((self.before, self.after, self.old_base, self.new_base, self.image), original)

    def test_both_snapshots_are_independently_attributed_and_keep_manifest_evidence(self):
        self.after['Metadata']['DiffIDs'] = [B, A, C]
        result = self.compare()
        self.assertEqual(result['counts']['unknown'], 2)
        self.assertEqual(result['snapshots']['before']['counts']['app'], 2)
        self.assertEqual(result['snapshots']['after']['counts']['unknown'], 2)
        self.assertEqual(result['snapshots']['after']['ancestry']['reportConfigBinding'], 'mismatch')
        raw = (ROOT / 'examples/layers/image.json').read_bytes()
        manifest = json.loads((ROOT / 'examples/layers/image-manifest.json').read_text())
        mapping = json.loads((ROOT / 'examples/layers/manifest-digest-map.json').read_text())
        result = api.compare(report(), self.old_base, raw, report(), self.new_base, raw,
                             before_image_manifest=manifest, after_image_manifest=manifest,
                             before_digest_map=mapping, after_digest_map=mapping)
        for snapshot in result['snapshots'].values():
            self.assertEqual(snapshot['ancestry']['imageManifestBinding']['status'], 'verified_local')
            self.assertFalse(snapshot['ancestry']['imageManifestBinding']['layerContentVerified'])
            self.assertEqual(snapshot['provenance']['imageManifest'], manifest)

    def test_duplicates_are_ambiguous_without_arbitrary_pairing_or_lost_occurrences(self):
        self.before['Results'][0]['Vulnerabilities'].append(
            deepcopy(self.before['Results'][0]['Vulnerabilities'][0]))
        result = self.compare()
        row = result['rows'][0]
        self.assertEqual((row['status'], row['reason']), ('unknown', 'ambiguous_finding_identity'))
        self.assertEqual(len(row['before']), 2)
        self.assertEqual(len(row['after']), 1)
        for side in ('before', 'after'):
            refs = [ref for row in result['rows'] for ref in row[side]]
            self.assertEqual(len(refs), result['snapshots'][side]['counts']['total'])
            self.assertEqual(len(refs), len(set(refs)))

    def test_versions_targets_and_package_paths_are_not_silently_merged(self):
        for section, field in (('finding', 'InstalledVersion'), ('finding', 'PkgPath'),
                               ('finding', 'PkgID'), ('result', 'Target'),
                               ('result', 'Class'), ('result', 'Type')):
            with self.subTest(field=field):
                self.setUp()
                target = self.after['Results'][0]
                if section == 'finding':
                    target = target['Vulnerabilities'][0]
                target[field] = 'different'
                result = self.compare()
                self.assertEqual(result['counts']['before_only'], 1 if section == 'finding' else 2)
                self.assertEqual(result['counts']['after_only'], 1 if section == 'finding' else 2)
                self.assertNotIn('remediated', json.dumps(result))

    def test_unchanged_reverse_move_and_empty_reports(self):
        self.after = deepcopy(self.before)
        self.new_base = deepcopy(self.old_base)
        result = self.compare()
        self.assertEqual(result['counts']['unchanged'], 2)
        self.assertFalse(result['basePrefixChange']['changed'])
        self.old_base, self.new_base = config([A, B]), config([A])
        result = self.compare()
        moved = result['rows'][0]
        self.assertEqual([resolve(result, moved[side][0])['origin'] for side in ('before', 'after')],
                         ['base', 'app'])
        self.before['Results'] = self.after['Results'] = []
        self.assertEqual(self.compare()['counts']['total'], 0)

    def test_unknown_to_known_and_unknown_to_unknown_stay_unknown(self):
        self.before['Results'][0]['Vulnerabilities'][0].pop('Layer')
        self.before['Results'][0]['Vulnerabilities'][1].pop('Layer')
        result = self.compare()
        self.assertEqual(result['counts']['unknown'], 2)
        self.assertEqual(result['rows'][0]['beforeOrigin'], 'unknown')
        self.assertEqual(result['rows'][0]['afterOrigin'], 'base')
        self.assertEqual(result['rows'][1]['afterOrigin'], 'unknown')

    def test_maps_and_image_sequences_are_independent(self):
        d = 'sha256:' + 'd' * 64
        compressed = 'sha256:' + 'e' * 64
        self.before['Results'][0]['Vulnerabilities'] = [
            {'VulnerabilityID': 'MAPPED', 'PkgName': 'shared', 'Layer': {'Digest': compressed}}]
        self.after = deepcopy(self.before)
        self.after['Metadata']['DiffIDs'] = [d, B, C]
        result = api.compare(self.before, config([A]), config([A, B, C]),
                             self.after, config([d, B]), config([d, B, C]),
                             before_digest_map={compressed: B}, after_digest_map={compressed: d})
        self.assertEqual(result['rows'][0]['status'], 'attribution_changed')
        self.assertEqual(resolve(result, result['rows'][0]['before'][0])['diffId'], B)
        self.assertEqual(resolve(result, result['rows'][0]['after'][0])['diffId'], d)
        result = api.compare(self.before, config([A]), config([A, B, C]),
                             self.after, config([d, B]), config([d, B, C]),
                             after_digest_map={compressed: d})
        self.assertEqual(result['rows'][0]['status'], 'unknown')
        self.assertEqual(resolve(result, result['rows'][0]['before'][0])['reason'],
                         'unmapped_compressed_digest')

    def test_invalid_either_snapshot_or_identity_is_rejected(self):
        for side in ('before', 'after'):
            with self.subTest(side=side):
                self.setUp()
                getattr(self, side)['ArtifactType'] = 'filesystem'
                with self.assertRaises(api.InputError):
                    self.compare()
        self.setUp()
        self.new_base = config([B])
        with self.assertRaisesRegex(api.InputError, 'exact prefix'):
            self.compare()
        self.setUp()
        self.after['Results'][0]['Vulnerabilities'][0]['PkgPath'] = {'SECRET': 1}
        with self.assertRaises(api.InputError) as caught:
            self.compare()
        self.assertNotIn('SECRET', str(caught.exception))


class ComparisonCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        before, after = report(), report()
        del after['Results'][0]['Vulnerabilities'][1]['Layer']
        docs = {'before-report': before, 'after-report': after,
                'before-base-config': config([A]), 'after-base-config': config([A, B]),
                'before-image-config': config([A, B, C]), 'after-image-config': config([A, B, C])}
        self.command = ['compare']
        for name, doc in docs.items():
            path = self.directory / (name + '.json')
            path.write_text(json.dumps(doc))
            self.command.extend(['--' + name, str(path)])

    def invoke(self, *args):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'layers', *self.command, *args],
                              cwd=ROOT, capture_output=True, text=True, timeout=60)

    def test_cli_deterministic_output(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['counts']['attribution_changed'], 1)
        self.assertEqual(json.loads(result.stdout)['counts']['unknown'], 1)
        self.assertEqual(result.stdout, self.invoke().stdout)
        output = self.directory / 'comparison.json'
        result = self.invoke('--output', str(output))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(), self.invoke().stdout)

    def test_cli_manifest_options_and_optional_input_aliases(self):
        manifest = self.directory / 'manifest.json'
        manifest.write_bytes((ROOT / 'examples/layers/image-manifest.json').read_bytes())
        mapping = self.directory / 'mapping.json'
        mapping.write_bytes((ROOT / 'examples/layers/manifest-digest-map.json').read_bytes())
        for side in ('before', 'after'):
            extra = ['--' + side + '-image-config', str(ROOT / 'examples/layers/image.json'),
                     '--' + side + '-image-manifest', str(manifest),
                     '--' + side + '-digest-map', str(mapping)]
            result = self.invoke(*extra)
            self.assertEqual(result.returncode, 0, result.stderr)
            doc = json.loads(result.stdout)
            self.assertEqual(doc['snapshots'][side]['ancestry']['imageManifestBinding']['status'],
                             'verified_local')
            for source in (manifest, mapping):
                original = source.read_bytes()
                alias = self.directory / (side + source.name)
                alias.hardlink_to(source)
                result = self.invoke(*extra, '--output', str(alias))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(source.read_bytes(), original)
            output = self.directory / 'preserved.json'
            output.write_text('preserved')
            result = self.invoke(*extra, '--' + side + '-digest-map', str(ROOT / 'examples/layers/digest-map.json'),
                                 '--output', str(output))
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('missing layer mapping', result.stderr)
            self.assertEqual(output.read_text(), 'preserved')

    def test_invalid_inputs_preserve_output_and_aliases_are_rejected(self):
        output = self.directory / 'out.json'
        output.write_text('preserved')
        source = self.directory / 'after-report.json'
        original = source.read_bytes()
        alias = self.directory / 'alias.json'
        alias.symlink_to(source)
        result = self.invoke('--output', str(alias))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(source.read_bytes(), original)
        for raw in (b'{"SECRET":1,"SECRET":2}', b'{}'):
            source.write_bytes(raw)
            result = self.invoke('--output', str(output))
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, '')
            self.assertNotIn('SECRET', result.stderr)
            self.assertNotIn('Traceback', result.stderr)
            self.assertEqual(output.read_text(), 'preserved')


if __name__ == '__main__':
    unittest.main()
