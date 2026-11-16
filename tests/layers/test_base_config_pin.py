"""Base-config pin contracts: immutable bytes, bounded hash before strict parse.

Only local provenance is added; manifest binding and layer evidence are independent.
"""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from vulnwrench.layers import InputError, compare, explain
from vulnwrench.layers.cli import main
from test_base_manifest import A, B, C, D, E, F, manifest_for

ROOT = Path(__file__).resolve().parents[2]


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


class BaseConfigPinTests(unittest.TestCase):
    def setUp(self):
        self.raw = (ROOT / 'examples/layers/upgraded-base.json').read_bytes()
        self.base = json.loads(self.raw)
        self.image = json.loads((ROOT / 'examples/layers/upgraded-image.json').read_bytes())
        self.report = json.loads((ROOT / 'examples/layers/upgrade-after.json').read_bytes())
        self.pin = digest(self.raw)
        self.manifest = manifest_for(self.raw, [E, F])
        self.mapping = {E: D, F: B}

    def run_explain(self, **changes):
        return explain(**(dict(report=self.report, base_config=self.raw,
                               image_config=self.image, base_config_sha256=self.pin) | changes))

    def test_original_bytes_add_only_provenance_with_and_without_manifest(self):
        original = deepcopy((self.report, self.base, self.image, self.manifest, self.mapping))
        for bound in (False, True):
            options = dict(base_manifest=self.manifest, base_digest_map=self.mapping) if bound else {}
            result = self.run_explain(**options)
            self.assertEqual(result['provenance'].pop('baseConfigDigest'), self.pin)
            self.assertEqual(result['provenance'].pop('baseConfigPinAgreement'), 'matched_local')
            baseline = self.run_explain(base_config=self.raw if bound else self.base,
                                         base_config_sha256=None, **options)
            self.assertEqual(result, baseline)
            self.assertEqual(result['counts'], dict(base=1, app=0, unknown=1, total=2))
            if bound:
                self.assertEqual(result['ancestry']['baseManifestBinding']['status'], 'verified_local')
                self.assertFalse(result['ancestry']['baseManifestBinding']['layerContentVerified'])
            else:
                self.assertNotIn('baseManifestBinding', result['ancestry'])
                self.assertNotIn('verified_local', json.dumps(result))
            result['provenance']['baseConfig'].clear()
        self.assertEqual((self.report, self.base, self.image, self.manifest, self.mapping), original)

    def test_same_length_architecture_history_and_whitespace_edits_reject(self):
        for raw in (self.raw.replace(b'amd64', b'arm64'),
                    self.raw.replace(b'synthetic', b'changed!!'), self.raw.replace(b': ', b' :')):
            self.assertEqual(len(raw), len(self.raw))
            self.assertEqual(json.loads(raw)['rootfs'], self.base['rootfs'])
            self.run_explain(base_config=json.loads(raw), base_config_sha256=None)
            for options in ({}, dict(base_manifest=manifest_for(raw, [E, F]), base_digest_map=self.mapping)):
                with self.subTest(options=options), self.assertRaisesRegex(InputError, 'base_config: config digest mismatch'):
                    self.run_explain(base_config=raw, **options)

    def test_malformed_missing_and_immutable_original_bytes_contract(self):
        for pin in ('', self.pin[7:], self.pin.upper(), self.pin + '\n', self.pin[:-1],
                    'sha512:' + 'a' * 128, 'SECRET', True, 1, {}, b'abc'):
            with self.subTest(pin=pin), self.assertRaisesRegex(InputError, 'base_config_sha256: expected lowercase sha256') as err:
                self.run_explain(base_config=b'bad', base_config_sha256=pin)
            self.assertNotIn('SECRET', str(err.exception))
        with self.assertRaisesRegex(InputError, 'base_config_sha256: requires base_config'):
            self.run_explain(base_config=None)
        for value in (self.base, self.raw.decode(), bytearray(self.raw), memoryview(self.raw)):
            with self.subTest(type=type(value)), self.assertRaisesRegex(InputError, 'requires raw config bytes'):
                self.run_explain(base_config=value)
        with self.assertRaisesRegex(InputError, 'expected JSON object'):
            self.run_explain(base_config_sha256=None)

    def test_size_before_hash_hash_before_config_parse_and_both_bindings(self):
        with patch('vulnwrench.layers.core.MAX_INPUT_BYTES', len(self.raw)):
            self.run_explain()
        with patch('vulnwrench.layers.core.MAX_INPUT_BYTES', len(self.raw) - 1), \
             patch('vulnwrench.layers.core.hashlib.sha256') as hashed:
            with self.assertRaisesRegex(InputError, 'base config: input exceeds 32 MiB limit'):
                self.run_explain()
            hashed.assert_not_called()
        for options in ({}, dict(base_manifest=self.manifest, base_digest_map=self.mapping)):
            with patch('vulnwrench.layers.core.parse_json') as parse:
                with self.assertRaisesRegex(InputError, 'base_config: config digest mismatch'):
                    self.run_explain(base_config=b'not JSON', **options)
                parse.assert_not_called()
        # A matching caller pin cannot waive the manifest's original-byte checks.
        for field, value, error in [('size', len(self.raw) + 1, 'config size mismatch'),
                                     ('digest', A, 'config digest mismatch')]:
            manifest = deepcopy(self.manifest); manifest['config'][field] = value
            with patch('vulnwrench.layers.core.parse_json') as parse:
                with self.assertRaisesRegex(InputError, 'base_manifest: ' + error):
                    self.run_explain(base_manifest=manifest, base_digest_map=self.mapping)
                parse.assert_not_called()

    def test_matching_pin_retains_strict_json_config_digest_and_history_checks(self):
        for raw, error in [(b'{"x":1,"x":2}', 'duplicate object keys'),
                           (b'{"x":NaN}', 'non-finite'), (b'\xff', 'invalid UTF-8 JSON'),
                           (b'[]', 'expected JSON object'), (b'bad', 'invalid UTF-8 JSON')]:
            with self.subTest(raw=raw), self.assertRaisesRegex(InputError, error):
                self.run_explain(base_config=raw, base_config_sha256=digest(raw))
        for config, error in [({}, 'base.rootfs'),
                              (dict(rootfs=dict(type='other', diff_ids=[])), 'only layers'),
                              (dict(rootfs=dict(type='layers', diff_ids=['SECRET'])), 'expected lowercase sha256'),
                              (self.base | dict(history=[dict(empty_layer=1)]), 'expected boolean'),
                              (self.base | dict(history=[dict(created_by=1)]), 'expected string')]:
            raw = json.dumps(config).encode()
            with self.subTest(error=error), self.assertRaisesRegex(InputError, error) as err:
                self.run_explain(base_config=raw, base_config_sha256=digest(raw))
            self.assertNotIn('SECRET', str(err.exception))

    def test_matching_pin_retains_prefix_report_map_and_evidence_checks(self):
        image = deepcopy(self.image); image['rootfs']['diff_ids'] = [A, B, C]
        with self.assertRaisesRegex(InputError, 'exact prefix'):
            self.run_explain(image_config=image)
        report = deepcopy(self.report); report['SchemaVersion'] = 1
        with self.assertRaisesRegex(InputError, 'only Trivy JSON schema 2'):
            self.run_explain(report=report)
        with self.assertRaisesRegex(InputError, 'absent from image rootfs'):
            self.run_explain(digest_map={E: A})
        with self.assertRaisesRegex(InputError, 'missing layer mapping'):
            self.run_explain(base_manifest=self.manifest)
        with self.assertRaisesRegex(InputError, 'conflicts with digest_map'):
            self.run_explain(base_manifest=self.manifest, base_digest_map=self.mapping, digest_map={E: B})
        report = deepcopy(self.report); report['Metadata'] = {'DiffIDs': [A, B, C]}
        self.assertEqual(self.run_explain(report=report)['counts']['unknown'], 2)
        report = deepcopy(self.report); report['Results'][0]['Vulnerabilities'][0]['Layer'] = {'Digest': E}
        result = self.run_explain(report=report, base_manifest=self.manifest, base_digest_map=self.mapping)
        self.assertTrue(any(row['reason'] == 'unmapped_compressed_digest' for row in result['groups']['unknown']))
        report['Results'][0]['Vulnerabilities'][0]['Layer']['DiffID'] = B
        result = self.run_explain(report=report, digest_map={E: D})
        self.assertTrue(any(row['reason'] == 'conflicting_layer_evidence' for row in result['groups']['unknown']))

    def test_thirteen_pins_and_compare_sides_are_independent(self):
        source = dict(report=json.dumps(self.report).encode(), base_config=self.raw,
                      image_config=json.dumps(self.image).encode(),
                      base_manifest=json.dumps(self.manifest).encode(),
                      base_digest_map=json.dumps(self.mapping).encode(),
                      digest_map=json.dumps({E: D, F: B, A: C}).encode())
        source['image_manifest'] = json.dumps(manifest_for(source['image_config'], [E, F, A])).encode()
        fields = ('report', 'base_config', 'base_manifest', 'image_manifest', 'digest_map', 'base_digest_map')
        options = dict(target_map=b'{}', target_map_sha256=digest(b'{}'))
        for side, padding in [('before', b''), ('after', b'\n')]:
            for key, raw in source.items():
                options[side + '_' + key] = raw + padding if key in fields else raw
            # Padded config needs the corresponding manifest to retain its independent binding.
            options[side + '_base_manifest'] = json.dumps(manifest_for(options[side + '_base_config'], [E, F])).encode() + padding
            for key in fields:
                name = side + '_' + key; options[name + '_sha256'] = digest(options[name])
        result = compare(**options)
        baseline = compare(**{k:v for k,v in options.items() if not k.endswith('base_config_sha256')})
        for side in ('before', 'after'):
            prov = result['snapshots'][side]['provenance']
            self.assertEqual(prov.pop('baseConfigDigest'), options[side + '_base_config_sha256'])
            self.assertEqual(prov.pop('baseConfigPinAgreement'), 'matched_local')
            other = 'after' if side == 'before' else 'before'
            for field in fields:
                key = side + '_' + field
                with self.subTest(key=key), self.assertRaisesRegex(InputError, 'digest mismatch'):
                    compare(**(options | {key + '_sha256': digest(options[other + '_' + field])}))
            key = side + '_base_config'
            mixed = compare(**(options | {key + '_sha256': None}))
            self.assertNotIn('baseConfigDigest', mixed['snapshots'][side]['provenance'])
            self.assertIn('baseConfigDigest', mixed['snapshots'][other]['provenance'])
        self.assertEqual(result, baseline)
        with self.assertRaisesRegex(InputError, 'target map digest mismatch'):
            compare(**(options | dict(target_map=b'{ }')))
        raw = b'{"absent":"absent"}'
        with self.assertRaisesRegex(InputError, 'absent from before'):
            compare(**(options | dict(target_map=raw, target_map_sha256=digest(raw))))
        report = deepcopy(self.report); report['Results'][0]['Vulnerabilities'][0]['InstalledVersion'] = 1
        raw = json.dumps(report).encode()
        with self.assertRaisesRegex(InputError, 'comparison identity fields'):
            compare(**(options | dict(after_report=raw, after_report_sha256=digest(raw))))
        # No-manifest comparisons can pin just one side; unpinned sides stay dicts.
        for side in ('before', 'after'):
            options = {s+'_'+k:v for s in ('before','after') for k,v in
                       dict(report=self.report, base_config=self.base, image_config=self.image).items()}
            options.update({side+'_base_config': self.raw, side+'_base_config_sha256': self.pin})
            snaps = compare(**options)['snapshots']
            self.assertIn('baseConfigDigest', snaps[side]['provenance'])
            self.assertNotIn('baseManifestBinding', snaps[side]['ancestry'])


class BaseConfigPinCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.path = self.directory / 'base.json'
        self.raw = (ROOT / 'examples/layers/upgraded-base.json').read_bytes(); self.path.write_bytes(self.raw)
        self.pin = digest(self.raw)
        self.command = ['explain', '--report', str(ROOT / 'examples/layers/upgrade-after.json'),
                        '--base-config', str(self.path), '--image-config', str(ROOT / 'examples/layers/upgraded-image.json')]

    def invoke(self, *args, command=None):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'layers', *(command or self.command), *args],
                              cwd=ROOT, capture_output=True, text=True, timeout=60)

    def test_success_only_provenance_gate_and_optional_manifest(self):
        for options in ([], ['--base-manifest', str(ROOT / 'examples/layers/upgraded-base-manifest.json'),
                              '--base-digest-map', str(ROOT / 'examples/layers/upgraded-base-digest-map.json')]):
            pinned = self.invoke(*options, '--base-config-sha256', self.pin, '--gate', 'app')
            self.assertEqual(pinned.returncode, 1, pinned.stderr)
            result = json.loads(pinned.stdout)
            self.assertEqual(result['provenance'].pop('baseConfigDigest'), self.pin)
            self.assertEqual(result['provenance'].pop('baseConfigPinAgreement'), 'matched_local')
            self.assertEqual(result, json.loads(self.invoke(*options, '--gate', 'app').stdout))

    def test_errors_preserve_output_and_private_values(self):
        output = self.directory / 'out.json'
        for raw, pin, error in [(self.raw, 'SECRET', 'expected lowercase sha256'),
                                (self.raw, '', 'expected lowercase sha256'),
                                (self.raw.replace(b'amd64', b'arm64'), self.pin, 'config digest mismatch'),
                                (self.raw.replace(b'synthetic', b'changed!!'), self.pin, 'config digest mismatch'),
                                (self.raw.replace(b': ', b' :'), self.pin, 'config digest mismatch'),
                                (b'invalid', self.pin, 'config digest mismatch'),
                                (b'[]', digest(b'[]'), 'expected JSON object')]:
            self.path.write_bytes(raw); output.write_bytes(b'KEEP')
            result = self.invoke('--base-config-sha256', pin, '--output', str(output))
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stdout, ''); self.assertIn(error, result.stderr)
            self.assertNotIn('SECRET', result.stderr); self.assertNotIn(str(self.path), result.stderr)
            self.assertEqual(output.read_bytes(), b'KEEP')

    def test_compare_both_and_single_side_pins(self):
        command = ['compare']
        for side in ('before', 'after'):
            for flag, path in zip(self.command[1::2], self.command[2::2]):
                command += ['--' + side + '-' + flag[2:], path]
        flags = ['--before-base-config-sha256', self.pin, '--after-base-config-sha256', self.pin]
        result = self.invoke(*flags, command=command)
        self.assertEqual(result.returncode, 0, result.stderr)
        for side in ('before', 'after'):
            self.assertEqual(json.loads(result.stdout)['snapshots'][side]['provenance']['baseConfigDigest'], self.pin)
            mixed = self.invoke('--' + side + '-base-config-sha256', self.pin, command=command)
            self.assertEqual(mixed.returncode, 0, mixed.stderr)
            snaps = json.loads(mixed.stdout)['snapshots']
            self.assertIn('baseConfigDigest', snaps[side]['provenance'])
            self.assertNotIn('baseConfigDigest', snaps['after' if side == 'before' else 'before']['provenance'])
            output = self.directory / 'out.json'; output.write_bytes(b'KEEP')
            bad = self.invoke(*flags, '--' + side + '-base-config-sha256', digest(b'{}'), '--output', str(output), command=command)
            self.assertEqual(bad.returncode, 2); self.assertEqual(bad.stdout, '')
            self.assertEqual(output.read_bytes(), b'KEEP')

    def test_bounded_read_and_input_aliases(self):
        for kind in ('direct', 'symlink', 'hardlink'):
            output = self.path if kind == 'direct' else self.directory / kind
            if kind == 'symlink': output.symlink_to(self.path)
            if kind == 'hardlink': output.hardlink_to(self.path)
            result = self.invoke('--base-config-sha256', self.pin, '--output', str(output))
            self.assertEqual(result.returncode, 2); self.assertIn('output must not replace an input file', result.stderr)
            self.assertEqual(self.path.read_bytes(), self.raw)
        output = self.directory / 'out.json'; output.write_bytes(b'KEEP')
        self.path.write_bytes(self.raw + b' ' * 8192)
        with patch('vulnwrench.layers.cli.MAX_INPUT_BYTES', 8192), \
             redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
            code = main([*self.command, '--base-config-sha256', self.pin, '--output', str(output)])
        self.assertEqual(code, 2); self.assertEqual(stdout.getvalue(), '')
        self.assertIn('base config: input exceeds 32 MiB limit', stderr.getvalue())
        self.assertEqual(output.read_bytes(), b'KEEP')


if __name__ == '__main__':
    unittest.main()
