"""Offline OCI v1.1.1 manifest/config binding regression fixtures."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from vulnwrench.layers import InputError, explain

ROOT = Path(__file__).resolve().parents[2]
A, B, C, D, E, F = ('sha256:' + c * 64 for c in 'abcdef')


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.raw = (ROOT / 'examples/layers/image.json').read_bytes()
        self.base = json.loads((ROOT / 'examples/layers/base.json').read_bytes())
        self.manifest = {
            'schemaVersion': 2,
            'mediaType': 'application/vnd.oci.image.manifest.v1+json',
            'config': {'mediaType': 'application/vnd.oci.image.config.v1+json',
                       'digest': 'sha256:' + hashlib.sha256(self.raw).hexdigest(),
                       'size': len(self.raw)},
            'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip',
                        'digest': digest, 'size': 100} for digest in (D, E, F)],
        }
        self.mapping = {D: A, E: B, F: C}
        self.report = {'SchemaVersion': 2, 'ArtifactType': 'container_image', 'Results': [
            {'Target': 'synthetic', 'Vulnerabilities': [
                {'VulnerabilityID': 'DEMO-BASE', 'PkgName': 'shared', 'Layer': {'Digest': D}},
                {'VulnerabilityID': 'DEMO-APP', 'PkgName': 'shared', 'Layer': {'Digest': E}},
            ]}]}

    def run_explain(self):
        return explain(self.report, self.base, self.raw, image_manifest=self.manifest,
                       digest_map=self.mapping)

    def test_matching_bytes_verify_only_local_binding(self):
        originals = deepcopy((self.report, self.base, self.manifest, self.mapping))
        result = self.run_explain()
        self.assertEqual(result['counts'], {'base': 1, 'app': 1, 'unknown': 0, 'total': 2})
        binding = result['ancestry']['imageManifestBinding']
        self.assertEqual(binding, {'status': 'verified_local',
                                  'configDigest': self.manifest['config']['digest'],
                                  'orderedLayerCount': 3,
                                  'layerContentVerified': False})
        self.assertEqual(result['ancestry']['reportConfigBinding'], 'unverified')
        self.assertEqual(result['groups']['app'][0]['proof'], 'explicit_digest_mapping')
        self.assertIn('report_config_binding_unverified', [w['code'] for w in result['warnings']])
        self.assertEqual(result['provenance']['imageManifest'], self.manifest)
        self.assertEqual(result['provenance']['imageConfig'], json.loads(self.raw))
        result['provenance']['imageManifest']['layers'].clear()
        self.assertEqual((self.report, self.base, self.manifest, self.mapping), originals)

    def test_same_length_config_tampering_rejected(self):
        self.raw = self.raw.replace(b'amd64', b'arm64')
        with self.assertRaisesRegex(InputError, 'config digest mismatch'):
            self.run_explain()

    def test_whitespace_and_wrong_config_size_rejected(self):
        self.raw += b'\n'
        with self.assertRaisesRegex(InputError, 'config size mismatch'):
            self.run_explain()
        self.manifest['config']['size'] = len(self.raw)
        with self.assertRaisesRegex(InputError, 'config digest mismatch'):
            self.run_explain()

    def test_reordered_descriptors_rejected(self):
        self.manifest['layers'].reverse()
        with self.assertRaisesRegex(InputError, 'ordered layer mapping mismatch'):
            self.run_explain()

    def test_missing_map_or_entry_cannot_bind_even_direct_findings(self):
        self.report['Results'][0]['Vulnerabilities'][0]['Layer']['DiffID'] = A
        for mapping in (None, {}, {D: A, E: B}):
            with self.subTest(mapping=mapping):
                self.mapping = mapping
                with self.assertRaisesRegex(InputError, 'missing layer mapping'):
                    self.run_explain()

    def test_map_outside_manifest_rejected(self):
        self.mapping[A] = A
        with self.assertRaisesRegex(InputError, 'absent from manifest'):
            self.run_explain()

    def test_equal_digest_text_does_not_infer_mapping(self):
        self.manifest['layers'][0]['digest'] = A
        del self.mapping[D]
        with self.assertRaisesRegex(InputError, 'missing layer mapping'):
            self.run_explain()

    def test_layer_count_and_wrong_order_mapping_rejected(self):
        self.manifest['layers'].pop()
        with self.assertRaisesRegex(InputError, 'layer count mismatch'):
            self.run_explain()
        self.setUp()
        self.mapping[D], self.mapping[E] = B, A
        with self.assertRaisesRegex(InputError, 'ordered layer mapping mismatch'):
            self.run_explain()

    def test_malformed_manifest_subset_rejected(self):
        original = deepcopy(self.manifest)
        cases = [[], {'schemaVersion': True}, {'schemaVersion': 1}, {'mediaType': 'Docker'},
                 {'layers': {}}, {'config': None}]
        for changes in cases:
            with self.subTest(changes=changes):
                self.manifest = deepcopy(original)
                if isinstance(changes, dict):
                    self.manifest.update(changes)
                else:
                    self.manifest = changes
                with self.assertRaises(InputError):
                    self.run_explain()
        for section in ('config', 'layer'):
            for field, value in [('digest', 'SECRET'), ('digest', 'sha512:' + 'a' * 128),
                                 ('mediaType', 'unsupported'), ('mediaType', []), ('mediaType', {}),
                                 ('size', True), ('size', -1),
                                 ('size', 2**63), ('size', 1.5), ('size', None)]:
                with self.subTest(section=section, field=field, value=value):
                    self.manifest = deepcopy(original)
                    descriptor = self.manifest['config'] if section == 'config' else self.manifest['layers'][0]
                    descriptor[field] = value
                    with self.assertRaises(InputError) as caught:
                        self.run_explain()
                    self.assertNotIn('SECRET', str(caught.exception))

    def test_raw_bytes_required_and_not_accepted_without_manifest(self):
        self.raw = json.loads(self.raw)
        with self.assertRaisesRegex(InputError, 'raw config bytes'):
            self.run_explain()
        with self.assertRaises(InputError):
            explain(self.report, self.base, b'{}')

    def test_strict_raw_config_parsing_after_hash_check(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'\xff', b'[]'):
            with self.subTest(raw=raw):
                self.raw = raw
                self.manifest['config']['digest'] = 'sha256:' + hashlib.sha256(raw).hexdigest()
                self.manifest['config']['size'] = len(raw)
                with self.assertRaises(InputError):
                    self.run_explain()

    def test_existing_mismatch_and_conflict_rules_still_apply(self):
        self.report['Metadata'] = {'DiffIDs': [B, A, C]}
        self.assertEqual(self.run_explain()['counts']['unknown'], 2)
        del self.report['Metadata']
        self.report['Results'][0]['Vulnerabilities'][0]['Layer']['DiffID'] = B
        self.assertEqual(self.run_explain()['groups']['unknown'][0]['reason'], 'conflicting_layer_evidence')

    def test_raw_config_limit_applies_to_library_before_hashing(self):
        with patch('vulnwrench.layers.core.MAX_INPUT_BYTES', len(self.raw) - 1):
            with self.assertRaisesRegex(InputError, '32 MiB limit'):
                self.run_explain()

    def test_repeated_descriptors_do_not_resolve_cross_boundary_ambiguity(self):
        config = json.loads(self.raw)
        config['rootfs']['diff_ids'] = [A, B, A]
        self.raw = json.dumps(config).encode()
        self.manifest['config']['size'] = len(self.raw)
        self.manifest['config']['digest'] = 'sha256:' + hashlib.sha256(self.raw).hexdigest()
        self.manifest['layers'][2] = deepcopy(self.manifest['layers'][0])
        del self.mapping[F]
        result = self.run_explain()
        self.assertEqual(result['groups']['unknown'][0]['reason'], 'diff_id_crosses_base_boundary')
        self.assertEqual(result['groups']['unknown'][0]['layerIndices'], [0, 2])

    def test_uncompressed_descriptor_still_requires_explicit_mapping(self):
        self.manifest['layers'][0].update(mediaType='application/vnd.oci.image.layer.v1.tar', digest=A)
        del self.mapping[D]
        with self.assertRaisesRegex(InputError, 'missing layer mapping'):
            self.run_explain()
        self.mapping[A] = A
        self.assertEqual(self.run_explain()['ancestry']['imageManifestBinding']['status'], 'verified_local')

    def test_empty_layer_sequences_can_bind_and_optional_manifest_type(self):
        self.raw = b'{"rootfs":{"type":"layers","diff_ids":[]}}'
        self.base = json.loads(self.raw)
        self.manifest['config']['size'] = len(self.raw)
        self.manifest['config']['digest'] = 'sha256:' + hashlib.sha256(self.raw).hexdigest()
        self.manifest['layers'] = []
        del self.manifest['mediaType']
        self.mapping = {}
        self.assertEqual(self.run_explain()['counts']['unknown'], 2)


if __name__ == '__main__':
    unittest.main()
