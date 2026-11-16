"""Base boundary verification: exact bytes, ordered descriptors, independent maps."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from vulnwrench.layers import InputError, compare, explain

ROOT = Path(__file__).resolve().parents[2]
A, B, C, D, E, F = ('sha256:' + c * 64 for c in 'abcdef')


def manifest_for(raw, digests):
    return {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
            'config': {'mediaType': 'application/vnd.oci.image.config.v1+json',
                       'digest': 'sha256:' + hashlib.sha256(raw).hexdigest(), 'size': len(raw)},
            'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip',
                        'digest': digest, 'size': 100} for digest in digests]}


class BaseManifestTests(unittest.TestCase):
    def setUp(self):
        self.raw = (ROOT / 'examples/layers/upgraded-base.json').read_bytes()
        self.image = json.loads((ROOT / 'examples/layers/upgraded-image.json').read_bytes())
        self.manifest = manifest_for(self.raw, [E, F])
        self.mapping = {E: D, F: B}
        self.report = {'SchemaVersion': 2, 'ArtifactType': 'container_image', 'Results': [
            {'Target': 'synthetic', 'Vulnerabilities': [
                {'VulnerabilityID': 'BASE', 'PkgName': 'shared', 'Layer': {'DiffID': B}},
                {'VulnerabilityID': 'APP', 'PkgName': 'shared', 'Layer': {'DiffID': C}},
                {'VulnerabilityID': 'UNMAPPED', 'PkgName': 'shared', 'Layer': {'Digest': E}}]}]}

    def run_explain(self, **extra):
        return explain(self.report, self.raw, self.image, base_manifest=self.manifest,
                       base_digest_map=self.mapping, **extra)

    def test_verified_boundary_preserves_inputs_and_does_not_map_report_digests(self):
        original = deepcopy((self.report, self.manifest, self.mapping, self.image))
        result = self.run_explain()
        self.assertEqual(result['counts'], {'base': 1, 'app': 1, 'unknown': 1, 'total': 3})
        self.assertEqual(result['ancestry']['baseManifestBinding'], {
            'status': 'verified_local', 'configDigest': self.manifest['config']['digest'],
            'orderedLayerCount': 2, 'layerContentVerified': False})
        self.assertEqual(result['ancestry']['reportConfigBinding'], 'unverified')
        self.assertNotIn('imageManifestBinding', result['ancestry'])
        self.assertEqual(result['groups']['unknown'][0]['reason'], 'unmapped_compressed_digest')
        self.assertEqual(result['provenance']['baseConfig'], json.loads(self.raw))
        self.assertEqual(result['provenance']['baseDigestMap'], self.mapping)
        self.assertEqual(result['provenance']['baseManifest'], self.manifest)
        result['provenance']['baseManifest']['layers'].clear()
        result['provenance']['baseDigestMap'].clear()
        self.assertEqual((self.report, self.manifest, self.mapping, self.image), original)

    def test_same_length_tampering_rejected_before_accepting_prefix(self):
        self.raw = self.raw.replace(b'amd64', b'arm64')
        # rootfs remains an exact prefix; parsed objects would miss this tampering.
        with self.assertRaisesRegex(InputError, 'base_manifest: config digest mismatch'):
            self.run_explain()

    def test_reordered_descriptors_rejected_before_prefix_validation(self):
        self.manifest['layers'].reverse()
        self.image['rootfs']['diff_ids'] = [A, B, C]  # also not a prefix
        with self.assertRaisesRegex(InputError, 'base_manifest: ordered layer mapping mismatch'):
            self.run_explain()

    def test_verified_manifest_does_not_waive_exact_prefix(self):
        self.image['rootfs']['diff_ids'] = [A, B, C]
        with self.assertRaisesRegex(InputError, 'exact prefix'):
            self.run_explain()

    def test_size_and_whitespace_are_exact(self):
        self.raw += b'\n'
        with self.assertRaisesRegex(InputError, 'base_manifest: config size mismatch'):
            self.run_explain()
        self.manifest['config']['size'] = len(self.raw)
        with self.assertRaisesRegex(InputError, 'base_manifest: config digest mismatch'):
            self.run_explain()

    def test_missing_extra_wrong_and_final_only_map_entries_rejected(self):
        for mapping, message in [(None, 'missing layer mapping'), ({}, 'missing layer mapping'),
                                 ({E: D}, 'missing layer mapping'),
                                 ({E: B, F: D}, 'ordered layer mapping mismatch'),
                                 ({E: D, F: B, A: D}, 'absent from manifest'),
                                 ({E: D, F: C}, 'absent from base rootfs')]:
            with self.subTest(mapping=mapping):
                self.mapping = mapping
                with self.assertRaisesRegex(InputError, message):
                    self.run_explain()

    def test_final_map_is_not_a_fallback_and_report_mismatch_stays_unknown(self):
        self.mapping = None
        with self.assertRaisesRegex(InputError, 'base_manifest: missing layer mapping'):
            self.run_explain(digest_map={E: D, F: B})
        self.mapping = {E: D, F: B}
        self.report['Metadata'] = {'DiffIDs': [A, B, C]}
        result = self.run_explain()
        self.assertEqual(result['counts']['unknown'], 3)
        self.assertTrue(all(entry['reason'] == 'report_config_mismatch'
                            for entry in result['groups']['unknown']))

    def test_hash_check_precedes_strict_base_parsing(self):
        self.raw = b'!' * len(self.raw)
        with self.assertRaisesRegex(InputError, 'base_manifest: config digest mismatch'):
            self.run_explain()

    def test_raw_bytes_required_and_orphan_map_rejected(self):
        with self.assertRaisesRegex(InputError, 'raw config bytes'):
            explain(self.report, json.loads(self.raw), self.image,
                    base_manifest=self.manifest, base_digest_map=self.mapping)
        with self.assertRaisesRegex(InputError, 'requires base_manifest'):
            explain(self.report, json.loads(self.raw), self.image, base_digest_map={})
        with self.assertRaises(InputError):
            explain(self.report, self.raw, self.image)

    def test_strict_base_byte_parsing_and_limit(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'\xff', b'[]'):
            with self.subTest(raw=raw):
                with self.assertRaises(InputError):
                    explain(self.report, raw, self.image,
                            base_manifest=manifest_for(raw, []), base_digest_map={})
        with patch('vulnwrench.layers.core.MAX_INPUT_BYTES', len(self.raw) - 1):
            with self.assertRaisesRegex(InputError, 'base config: input exceeds 32 MiB'):
                self.run_explain()

    def test_invalid_base_descriptor_and_layer_count(self):
        original = deepcopy(self.manifest)
        for field, value in [('size', True), ('size', -1), ('digest', 'SECRET'),
                             ('mediaType', 'unsupported')]:
            for section in ('config', 'layer'):
                with self.subTest(field=field, section=section):
                    self.manifest = deepcopy(original)
                    descriptor = self.manifest['config'] if section == 'config' else self.manifest['layers'][0]
                    descriptor[field] = value
                    with self.assertRaises(InputError) as caught:
                        self.run_explain()
                    self.assertNotIn('SECRET', str(caught.exception))
        self.manifest = original
        self.manifest['layers'].pop()
        with self.assertRaisesRegex(InputError, 'base_manifest: layer count mismatch'):
            self.run_explain()

    def test_base_and_final_maps_can_differ_and_remain_independent(self):
        # The first layer uses a different compressed descriptor in the final image.
        image_raw = json.dumps(self.image).encode()
        self.report['Results'][0]['Vulnerabilities'][2]['Layer'] = {'Digest': A}
        result = explain(self.report, self.raw, image_raw, base_manifest=self.manifest,
                         base_digest_map=self.mapping, image_manifest=manifest_for(image_raw, [A, F, C]),
                         digest_map={A: D, F: B, C: C})
        self.assertEqual(result['counts'], {'base': 2, 'app': 1, 'unknown': 0, 'total': 3})
        self.assertEqual(result['groups']['base'][1]['proof'], 'explicit_digest_mapping')
        self.assertEqual(result['ancestry']['imageManifestBinding']['orderedLayerCount'], 3)
        self.assertEqual(result['ancestry']['baseManifestBinding']['orderedLayerCount'], 2)

    def test_conflicting_base_and_final_assertions_rejected(self):
        for verify_image in (False, True):
            with self.subTest(verify_image=verify_image):
                raw = json.dumps(self.image).encode()
                extra = {'image_manifest': manifest_for(raw, [A, F, E])} if verify_image else {}
                with self.assertRaisesRegex(InputError, 'base_digest_map: conflicts with digest_map'):
                    explain(self.report, self.raw, raw if verify_image else self.image,
                            base_manifest=self.manifest, base_digest_map=self.mapping,
                            digest_map={A: D, F: B, E: C}, **extra)

    def test_empty_base_manifest_and_repeated_boundary_remain_conservative(self):
        empty = b'{"rootfs":{"type":"layers","diff_ids":[]},"history":[]}'
        result = explain(self.report, empty, self.image, base_manifest=manifest_for(empty, []))
        self.assertEqual(result['ancestry']['baseManifestBinding']['orderedLayerCount'], 0)
        self.image['rootfs']['diff_ids'].append(B)
        result = self.run_explain()
        self.assertEqual(result['groups']['unknown'][0]['reason'], 'diff_id_crosses_base_boundary')
        self.assertEqual(result['groups']['unknown'][0]['layerIndices'], [1, 3])

    def test_compare_verifies_base_independently_on_each_side(self):
        old_raw = (ROOT / 'examples/layers/base.json').read_bytes()
        old_image = json.loads((ROOT / 'examples/layers/image.json').read_bytes())
        kwargs = dict(before_base_manifest=manifest_for(old_raw, [E]), before_base_digest_map={E: A},
                      after_base_manifest=self.manifest, after_base_digest_map=self.mapping)
        result = compare(self.report, old_raw, old_image, self.report, self.raw, self.image, **kwargs)
        for side, count in [('before', 1), ('after', 2)]:
            self.assertEqual(result['snapshots'][side]['ancestry']['baseManifestBinding']['orderedLayerCount'], count)
        with self.assertRaisesRegex(InputError, 'config digest mismatch'):
            compare(self.report, old_raw, old_image, self.report,
                    self.raw.replace(b'amd64', b'arm64'), self.image, **kwargs)
        del kwargs['before_base_digest_map']
        with self.assertRaisesRegex(InputError, 'missing layer mapping'):
            compare(self.report, old_raw, old_image, self.report, self.raw, self.image, **kwargs)


class BaseManifestCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.raw = (ROOT / 'examples/layers/upgraded-base.json').read_bytes()
        self.manifest = self.directory / 'manifest.json'
        self.manifest.write_text(json.dumps(manifest_for(self.raw, [E, F])))
        self.mapping = self.directory / 'map.json'
        self.mapping.write_text(json.dumps({E: D, F: B}))
        self.command = ['explain', '--report', str(ROOT / 'examples/layers/upgrade-after.json'),
                        '--base-config', str(ROOT / 'examples/layers/upgraded-base.json'),
                        '--image-config', str(ROOT / 'examples/layers/upgraded-image.json'),
                        '--base-manifest', str(self.manifest), '--base-digest-map', str(self.mapping)]

    def invoke(self, *extra, command=None):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'layers',
                               *(command or self.command), *extra], cwd=ROOT,
                              capture_output=True, text=True, timeout=60)

    def test_cli_contract_and_gate(self):
        result = self.invoke('--gate', 'app')
        self.assertEqual(result.returncode, 1, result.stderr)
        doc = json.loads(result.stdout)
        self.assertEqual(doc['counts'], {'base': 1, 'app': 0, 'unknown': 1, 'total': 2})
        self.assertEqual(doc['ancestry']['baseManifestBinding']['status'], 'verified_local')
        self.assertEqual(result.stdout, self.invoke('--gate', 'app').stdout)

    def test_tamper_reorder_missing_map_and_invalid_json_preserve_output(self):
        tampered = self.directory / 'tampered.json'
        tampered.write_bytes(self.raw.replace(b'amd64', b'arm64'))
        reordered = manifest_for(self.raw, [F, E])
        order_path = self.directory / 'reordered.json'
        order_path.write_text(json.dumps(reordered))
        missing = self.directory / 'missing.json'
        missing.write_text('{}')
        invalid = self.directory / 'invalid.json'
        invalid.write_bytes(b'{"SECRET":1,"SECRET":2}')
        output = self.directory / 'output.json'
        output.write_text('preserved')
        for option, path, error in [('base-config', tampered, 'config digest mismatch'),
                                    ('base-manifest', order_path, 'ordered layer mapping mismatch'),
                                    ('base-digest-map', missing, 'missing layer mapping'),
                                    ('base-manifest', invalid, 'duplicate object keys')]:
            with self.subTest(option=option):
                result = self.invoke('--' + option, str(path), '--output', str(output))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertIn(error, result.stderr)
                self.assertNotIn('SECRET', result.stderr)
                self.assertEqual(output.read_text(), 'preserved')

    def test_new_inputs_and_aliases_cannot_be_overwritten(self):
        for source in (self.manifest, self.mapping):
            before = source.read_bytes()
            for kind in ('symlink', 'hardlink'):
                alias = self.directory / (kind + source.name)
                if kind == 'symlink':
                    alias.symlink_to(source)
                else:
                    alias.hardlink_to(source)
                result = self.invoke('--output', str(alias))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('must not replace an input', result.stderr)
                self.assertEqual(source.read_bytes(), before)

    def test_compare_cli_routes_each_base_option_and_rejects_invalid_side(self):
        command = ['compare']
        for side in ('before', 'after'):
            for index in range(1, len(self.command), 2):
                command.extend(['--' + side + '-' + self.command[index][2:], self.command[index + 1]])
        result = self.invoke(command=command)
        self.assertEqual(result.returncode, 0, result.stderr)
        for snapshot in json.loads(result.stdout)['snapshots'].values():
            self.assertEqual(snapshot['ancestry']['baseManifestBinding']['status'], 'verified_local')
        output = self.directory / 'output.json'
        output.write_text('preserved')
        for side in ('before', 'after'):
            result = self.invoke('--' + side + '-base-digest-map', str(ROOT / 'examples/layers/digest-map.json'),
                                 '--output', str(output), command=command)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stdout, '')
            self.assertEqual(output.read_text(), 'preserved')
        result = self.invoke('--output', str(self.manifest), command=command)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('must not replace an input', result.stderr)


if __name__ == '__main__':
    unittest.main()
