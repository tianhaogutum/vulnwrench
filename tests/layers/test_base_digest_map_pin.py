"""Exact base-map bytes: local agreement, separate from finding evidence.

Immutable bytes, size before hash, hash before strict map parse. Matching pins
retain manifest presence, ordered mappings and every snapshot/comparison check.
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


class BaseDigestMapPinTests(unittest.TestCase):
    def setUp(self):
        self.base = (ROOT / 'examples/layers/upgraded-base.json').read_bytes()
        self.image = json.loads((ROOT / 'examples/layers/upgraded-image.json').read_bytes())
        self.report = json.loads((ROOT / 'examples/layers/upgrade-after.json').read_bytes())
        self.manifest = json.loads((ROOT / 'examples/layers/upgraded-base-manifest.json').read_bytes())
        self.raw = (ROOT / 'examples/layers/upgraded-base-digest-map.json').read_bytes()
        self.mapping = json.loads(self.raw)
        self.pin = digest(self.raw)

    def options(self):
        return dict(report=self.report, base_config=self.base, image_config=self.image,
                    base_manifest=self.manifest, base_digest_map=self.raw,
                    base_digest_map_sha256=self.pin)

    def run_explain(self, **changes):
        return explain(**(self.options() | changes))

    def test_exact_bytes_add_only_local_pin_metadata(self):
        original = deepcopy((self.report, self.image, self.manifest, self.mapping))
        result = self.run_explain()
        self.assertEqual(result['provenance'].pop('baseDigestMapDigest'), self.pin)
        self.assertEqual(result['provenance'].pop('baseDigestMapPinAgreement'), 'matched_local')
        self.assertEqual(result, self.run_explain(base_digest_map=self.mapping, base_digest_map_sha256=None))
        self.assertEqual(result['counts'], dict(base=1, app=0, unknown=1, total=2))
        result['provenance']['baseDigestMap'].clear()
        result['provenance']['baseManifest'].clear()
        self.assertEqual((self.report, self.image, self.manifest, self.mapping), original)

    def test_same_length_valid_key_and_whitespace_edits_reject(self):
        changed_manifest = deepcopy(self.manifest)
        changed_manifest['layers'][0]['digest'] = A
        for raw, manifest in [(self.raw.replace(E.encode(), A.encode()), changed_manifest),
                              (self.raw.replace(b': ', b' :'), self.manifest)]:
            self.assertEqual(len(raw), len(self.raw))
            unpinned = self.run_explain(base_manifest=manifest, base_digest_map=json.loads(raw),
                                        base_digest_map_sha256=None)
            self.assertEqual(unpinned['counts']['total'], 2)
            with self.assertRaisesRegex(InputError, 'base_digest_map: digest map digest mismatch'):
                self.run_explain(base_manifest=manifest, base_digest_map=raw)

    def test_malformed_orphan_and_immutable_bytes_contract(self):
        for pin in ('', self.pin[7:], self.pin.upper(), self.pin + '\n', self.pin[:-1],
                    'sha512:' + 'a' * 128, 'SECRET', True, 1, {}, b'abc'):
            with self.subTest(pin=pin):
                with self.assertRaisesRegex(InputError, 'base_digest_map_sha256: expected lowercase sha256') as err:
                    self.run_explain(base_digest_map=b'invalid', base_digest_map_sha256=pin)
                self.assertNotIn('SECRET', str(err.exception))
        with self.assertRaisesRegex(InputError, 'base_digest_map_sha256: requires base_digest_map'):
            self.run_explain(base_digest_map=None)
        for value in (self.mapping, self.raw.decode(), bytearray(self.raw), memoryview(self.raw)):
            with self.subTest(type=type(value)):
                with self.assertRaisesRegex(InputError, 'requires raw digest map bytes'):
                    self.run_explain(base_digest_map=value)
        with self.assertRaisesRegex(InputError, 'expected JSON object'):
            self.run_explain(base_digest_map_sha256=None)
        with self.assertRaisesRegex(InputError, 'base_digest_map: requires base_manifest'):
            self.run_explain(base_manifest=None)

    def test_size_before_hash_and_hash_before_map_parse(self):
        # Keep unrelated config parsing below the patched boundary.
        with patch('vulnwrench.layers.core.MAX_INPUT_BYTES', len(self.raw)), \
             patch('vulnwrench.layers.core._manifest_config', return_value=json.loads(self.base)):
            self.run_explain()
        with patch('vulnwrench.layers.core.MAX_INPUT_BYTES', len(self.raw) - 1), \
             patch('vulnwrench.layers.core.hashlib.sha256') as hashed:
            with self.assertRaisesRegex(InputError, 'base digest map: input exceeds 32 MiB limit'):
                self.run_explain()
            hashed.assert_not_called()
        with patch('vulnwrench.layers.core.parse_json') as parse:
            with self.assertRaisesRegex(InputError, 'base_digest_map: digest map digest mismatch'):
                self.run_explain(base_digest_map=b'not JSON')
            parse.assert_not_called()

    def test_matching_pin_retains_strict_json_and_base_map_checks(self):
        for raw, error in [(b'{"x":1,"x":2}', 'duplicate object keys'),
                           (b'{"x":NaN}', 'non-finite'), (b'\xff', 'invalid UTF-8 JSON'),
                           (b'[]', 'expected JSON object'), (b'bad', 'invalid UTF-8 JSON')]:
            with self.subTest(raw=raw), self.assertRaisesRegex(InputError, error):
                self.run_explain(base_digest_map=raw, base_digest_map_sha256=digest(raw))
        for mapping, error in [({'SECRET': D}, 'expected lowercase sha256'),
                               ({E: 'SECRET'}, 'expected lowercase sha256'),
                               ({E: D, F: C}, 'absent from base rootfs'),
                               ({}, 'missing layer mapping'),
                               ({E: D}, 'missing layer mapping'),
                               ({E: B, F: D}, 'ordered layer mapping mismatch'),
                               ({E: D, F: B, A: D}, 'Digest is absent from manifest')]:
            raw = json.dumps(mapping).encode()
            with self.subTest(error=error), self.assertRaisesRegex(InputError, error) as err:
                self.run_explain(base_digest_map=raw, base_digest_map_sha256=digest(raw))
            self.assertNotIn('SECRET', str(err.exception))
        # Empty pinned maps work only for empty bases/manifests.
        base = json.dumps(dict(rootfs=dict(type='layers', diff_ids=[]))).encode()
        result = self.run_explain(base_config=base, base_manifest=manifest_for(base, []),
                                  base_digest_map=b'{}', base_digest_map_sha256=digest(b'{}'))
        self.assertEqual(result['provenance']['baseDigestMap'], {})

    def test_matching_pin_retains_config_prefix_report_and_finding_checks(self):
        with self.assertRaisesRegex(InputError, 'config digest mismatch'):
            self.run_explain(base_config=self.base.replace(b'amd64', b'arm64'))
        image = deepcopy(self.image); image['rootfs']['diff_ids'] = [A, B, C]
        with self.assertRaisesRegex(InputError, 'exact prefix'):
            self.run_explain(image_config=image)
        with self.assertRaisesRegex(InputError, 'conflicts with digest_map'):
            self.run_explain(digest_map={E: B})
        report = deepcopy(self.report); report['SchemaVersion'] = 1
        with self.assertRaisesRegex(InputError, 'only Trivy JSON schema 2'):
            self.run_explain(report=report)
        report = deepcopy(self.report); report['Metadata'] = {'DiffIDs': [A, B, C]}
        self.assertEqual(self.run_explain(report=report)['counts']['unknown'], 2)
        report = deepcopy(self.report)
        report['Results'][0]['Vulnerabilities'][0]['Layer'] = {'Digest': E}
        result = self.run_explain(report=report)
        self.assertTrue(any(row['reason'] == 'unmapped_compressed_digest' for row in result['groups']['unknown']))
        # Valid final mapping plus contradictory direct evidence stays unknown.
        report['Results'][0]['Vulnerabilities'][0]['Layer'] = {'Digest': E, 'DiffID': B}
        result = self.run_explain(report=report, digest_map={E: D})
        self.assertTrue(any(row['reason'] == 'conflicting_layer_evidence' for row in result['groups']['unknown']))

    def bound_inputs(self):
        options = self.options()
        options['image_config'] = json.dumps(self.image).encode()
        options['report'] = json.dumps(self.report).encode()
        options['base_manifest'] = json.dumps(self.manifest).encode()
        options['image_manifest'] = json.dumps(manifest_for(options['image_config'], [E, F, A])).encode()
        options['digest_map'] = json.dumps({E: D, F: B, A: C}).encode()
        for key in ('report', 'base_manifest', 'image_manifest', 'digest_map'):
            options[key + '_sha256'] = digest(options[key])
        return options

    def test_all_eleven_pins_independent_and_comparison_checks_retained(self):
        source = self.bound_inputs()
        options = dict(target_map=b'{}', target_map_sha256=digest(b'{}'))
        fields = ('report', 'base_manifest', 'image_manifest', 'digest_map', 'base_digest_map')
        for side, padding in [('before', b''), ('after', b'\n')]:
            for key, value in source.items():
                if not key.endswith('_sha256'):
                    options[side + '_' + key] = value + padding if key in fields else value
            for key in fields:
                name = side + '_' + key
                options[name + '_sha256'] = digest(options[name])
        result = compare(**options)
        for side in ('before', 'after'):
            self.assertEqual(result['snapshots'][side]['provenance']['baseDigestMapPinAgreement'], 'matched_local')
            other = 'after' if side == 'before' else 'before'
            for field in fields:
                key = side + '_' + field
                with self.subTest(key=key), self.assertRaisesRegex(InputError, 'digest mismatch'):
                    compare(**(options | {key + '_sha256': digest(options[other + '_' + field])}))
            key = side + '_base_digest_map'
            mixed = compare(**(options | {key: json.loads(options[key]), key + '_sha256': None}))
            self.assertNotIn('baseDigestMapDigest', mixed['snapshots'][side]['provenance'])
            self.assertIn('baseDigestMapDigest', mixed['snapshots'][other]['provenance'])
            with self.assertRaisesRegex(InputError, 'requires base_digest_map'):
                compare(**(options | {key: None}))
        with self.assertRaisesRegex(InputError, 'target map digest mismatch'):
            compare(**(options | dict(target_map=b'{ }')))
        raw = b'{"missing":"missing"}'
        with self.assertRaisesRegex(InputError, 'absent from before'):
            compare(**(options | dict(target_map=raw, target_map_sha256=digest(raw))))
        report = deepcopy(self.report); report['Results'][0]['Vulnerabilities'][0]['InstalledVersion'] = 1
        raw = json.dumps(report).encode()
        with self.assertRaisesRegex(InputError, 'comparison identity fields'):
            compare(**(options | dict(after_report=raw, after_report_sha256=digest(raw))))


class BaseDigestMapPinCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.path = self.directory / 'map.json'
        self.manifest_path = self.directory / 'manifest.json'
        self.raw = (ROOT / 'examples/layers/upgraded-base-digest-map.json').read_bytes()
        self.path.write_bytes(self.raw)
        self.manifest_raw = (ROOT / 'examples/layers/upgraded-base-manifest.json').read_bytes()
        self.manifest_path.write_bytes(self.manifest_raw)
        self.pin = digest(self.raw)
        self.command = ['explain', '--report', str(ROOT / 'examples/layers/upgrade-after.json'),
                        '--base-config', str(ROOT / 'examples/layers/upgraded-base.json'),
                        '--image-config', str(ROOT / 'examples/layers/upgraded-image.json'),
                        '--base-manifest', str(self.manifest_path), '--base-digest-map', str(self.path)]

    def invoke(self, *args, command=None):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'layers', *(command or self.command), *args],
                              cwd=ROOT, capture_output=True, text=True, timeout=60)

    def test_success_adds_only_provenance_and_preserves_gate(self):
        pinned = self.invoke('--base-digest-map-sha256', self.pin, '--gate', 'app')
        self.assertEqual(pinned.returncode, 1, pinned.stderr)
        result = json.loads(pinned.stdout)
        self.assertEqual(result['provenance'].pop('baseDigestMapDigest'), self.pin)
        self.assertEqual(result['provenance'].pop('baseDigestMapPinAgreement'), 'matched_local')
        self.assertEqual(result, json.loads(self.invoke('--gate', 'app').stdout))

    def test_errors_preserve_output_and_omit_private_values(self):
        output = self.directory / 'out.json'
        for raw, pin, error in [(self.raw, 'SECRET', 'expected lowercase sha256'),
                                (self.raw, '', 'expected lowercase sha256'),
                                (self.raw.replace(E.encode(), A.encode()), self.pin, 'digest map digest mismatch'),
                                (self.raw.replace(b': ', b' :'), self.pin, 'digest map digest mismatch'),
                                (b'invalid', self.pin, 'digest map digest mismatch'),
                                (b'[]', digest(b'[]'), 'expected JSON object')]:
            self.path.write_bytes(raw); output.write_bytes(b'KEEP')
            self.manifest_path.write_bytes(self.manifest_raw.replace(E.encode(), A.encode())
                                           if A.encode() in raw else self.manifest_raw)
            with self.subTest(error=error):
                result = self.invoke('--base-digest-map-sha256', pin, '--output', str(output))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertIn(error, result.stderr)
                self.assertNotIn('SECRET', result.stderr)
                self.assertNotIn(str(self.path), result.stderr)
                self.assertEqual(output.read_bytes(), b'KEEP')
        result = self.invoke('--base-digest-map-sha256', self.pin, command=self.command[:-2])
        self.assertEqual(result.returncode, 2); self.assertIn('requires base_digest_map', result.stderr)

    def test_compare_both_sides_and_one_side_only(self):
        command = ['compare']
        for side in ('before', 'after'):
            for flag, path in zip(self.command[1::2], self.command[2::2]):
                command += ['--' + side + '-' + flag[2:], path]
        flags = ['--before-base-digest-map-sha256', self.pin, '--after-base-digest-map-sha256', self.pin]
        result = self.invoke(*flags, command=command)
        self.assertEqual(result.returncode, 0, result.stderr)
        for side in ('before', 'after'):
            self.assertEqual(json.loads(result.stdout)['snapshots'][side]['provenance']['baseDigestMapDigest'], self.pin)
            mixed = self.invoke('--' + side + '-base-digest-map-sha256', self.pin, command=command)
            self.assertEqual(mixed.returncode, 0, mixed.stderr)
            snaps = json.loads(mixed.stdout)['snapshots']
            self.assertIn('baseDigestMapDigest', snaps[side]['provenance'])
            self.assertNotIn('baseDigestMapDigest', snaps['after' if side == 'before' else 'before']['provenance'])
            bad = self.invoke(*flags, '--' + side + '-base-digest-map-sha256', digest(b'{}'), command=command)
            self.assertEqual(bad.returncode, 2)

    def test_bounded_read_and_input_aliases(self):
        for kind in ('direct', 'symlink', 'hardlink'):
            output = self.path if kind == 'direct' else self.directory / kind
            if kind == 'symlink': output.symlink_to(self.path)
            if kind == 'hardlink': output.hardlink_to(self.path)
            result = self.invoke('--base-digest-map-sha256', self.pin, '--output', str(output))
            self.assertEqual(result.returncode, 2)
            self.assertIn('output must not replace an input file', result.stderr)
            self.assertEqual(self.path.read_bytes(), self.raw)
        output = self.directory / 'out.json'; output.write_bytes(b'KEEP')
        self.path.write_bytes(self.raw + b' ' * 8192)
        with patch('vulnwrench.layers.cli.MAX_INPUT_BYTES', 8192), \
             redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
            code = main([*self.command, '--base-digest-map-sha256', self.pin, '--output', str(output)])
        self.assertEqual(code, 2); self.assertEqual(stdout.getvalue(), '')
        self.assertIn('base digest map: input exceeds 32 MiB limit', stderr.getvalue())
        self.assertEqual(output.read_bytes(), b'KEEP')


if __name__ == '__main__':
    unittest.main()
