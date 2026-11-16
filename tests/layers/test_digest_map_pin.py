"""Bounded immutable digest-map bytes: syntax/size/hash before map parsing.

A matching pin preserves all map/snapshot/comparison validation; only snapshot
provenance gains local pin agreement. Unpinned behavior and evidence are unchanged.
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


class DigestMapPinTests(unittest.TestCase):
    def setUp(self):
        self.report = json.loads((ROOT / 'examples/layers/trivy.json').read_bytes())
        self.base = json.loads((ROOT / 'examples/layers/base.json').read_bytes())
        self.image = json.loads((ROOT / 'examples/layers/image.json').read_bytes())
        self.raw = (ROOT / 'examples/layers/digest-map.json').read_bytes()
        self.mapping = json.loads(self.raw)
        self.pin = digest(self.raw)

    def run_explain(self, **changes):
        options = dict(report=self.report, base_config=self.base, image_config=self.image,
                       digest_map=self.raw, digest_map_sha256=self.pin)
        return explain(**(options | changes))

    def test_exact_bytes_add_only_local_pin_metadata(self):
        original = deepcopy((self.report, self.base, self.image, self.mapping))
        result = self.run_explain()
        self.assertEqual(result['provenance'].pop('digestMapDigest'), self.pin)
        self.assertEqual(result['provenance'].pop('digestMapPinAgreement'), 'matched_local')
        self.assertEqual(result, self.run_explain(digest_map=self.mapping, digest_map_sha256=None))
        self.assertEqual(result['counts'], dict(base=1, app=3, unknown=4, total=8))
        result['provenance']['digestMap'].clear()
        result['provenance']['report'].clear()
        self.assertEqual((self.report, self.base, self.image, self.mapping), original)
        empty = self.run_explain(digest_map=b'{}', digest_map_sha256=digest(b'{}'))
        self.assertEqual(empty['provenance']['digestMap'], {})
        self.assertEqual(empty['counts'], explain(self.report, self.base, self.image)['counts'])

    def test_same_length_valid_mapping_and_whitespace_changes_reject_original_pin(self):
        for raw in (self.raw.replace(C.encode(), B.encode()),
                    self.raw.replace(D.encode(), E.encode()),
                    self.raw.replace(b': ', b' :'), self.raw + b'\n'):
            with self.subTest(raw=raw):
                unpinned = self.run_explain(digest_map=json.loads(raw), digest_map_sha256=None)
                self.assertEqual(unpinned['counts']['total'], 8)
                with self.assertRaisesRegex(InputError, 'digest_map: digest map digest mismatch'):
                    self.run_explain(digest_map=raw)
                if not raw.endswith(b'\n\n'):
                    self.assertEqual(len(raw), len(self.raw))

    def test_malformed_orphan_and_immutable_bytes_contract(self):
        for pin in ('', self.pin[7:], self.pin.upper(), self.pin + '\n', self.pin[:-1],
                    'sha512:' + 'a' * 128, 'SECRET', True, 1, {}, b'abc'):
            with self.subTest(pin=pin):
                with self.assertRaisesRegex(InputError, 'digest_map_sha256: expected lowercase sha256') as err:
                    self.run_explain(digest_map=b'invalid', digest_map_sha256=pin)
                self.assertNotIn('SECRET', str(err.exception))
        with self.assertRaisesRegex(InputError, 'digest_map_sha256: requires digest_map'):
            self.run_explain(digest_map=None)
        for value in (self.mapping, self.raw.decode(), bytearray(self.raw), memoryview(self.raw)):
            with self.subTest(type=type(value)):
                with self.assertRaisesRegex(InputError, 'requires raw digest map bytes'):
                    self.run_explain(digest_map=value)
        with self.assertRaisesRegex(InputError, 'expected JSON object'):
            self.run_explain(digest_map_sha256=None)

    def test_size_before_hash_and_hash_before_map_parse(self):
        with patch('vulnwrench.layers.core.MAX_INPUT_BYTES', len(self.raw)):
            self.run_explain()
        with patch('vulnwrench.layers.core.MAX_INPUT_BYTES', len(self.raw) - 1), \
             patch('vulnwrench.layers.core.hashlib.sha256') as hashed:
            with self.assertRaisesRegex(InputError, 'digest map: input exceeds 32 MiB limit'):
                self.run_explain()
            hashed.assert_not_called()
        with patch('vulnwrench.layers.core.parse_json') as parse:
            with self.assertRaisesRegex(InputError, 'digest map digest mismatch'):
                self.run_explain(digest_map=b'not JSON')
            parse.assert_not_called()

    def test_matching_pin_retains_strict_json_and_map_validation(self):
        for raw, error in [(b'{"x":1,"x":2}', 'duplicate object keys'),
                           (b'{"x":NaN}', 'non-finite'), (b'\xff', 'invalid UTF-8 JSON'),
                           (b'[]', 'expected JSON object'), (b'bad', 'invalid UTF-8 JSON')]:
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(InputError, error):
                    self.run_explain(digest_map=raw, digest_map_sha256=digest(raw))
        for mapping, error in [({'SECRET': C}, 'expected lowercase sha256'),
                               ({D: 'SECRET'}, 'expected lowercase sha256'),
                               ({D: D}, 'absent from image rootfs')]:
            raw = json.dumps(mapping).encode()
            with self.assertRaisesRegex(InputError, error) as err:
                self.run_explain(digest_map=raw, digest_map_sha256=digest(raw))
            self.assertNotIn('SECRET', str(err.exception))

    def test_matching_pin_preserves_unknown_evidence_schema_and_prefix_checks(self):
        self.report['Results'][0]['Vulnerabilities'][0]['Layer'] = {'Digest': D, 'DiffID': A}
        result = self.run_explain()
        self.assertEqual(result['groups']['unknown'][0]['reason'], 'conflicting_layer_evidence')
        self.report['Metadata']['DiffIDs'] = [C, B, A]
        self.assertEqual(self.run_explain()['counts']['unknown'], 8)
        self.report['SchemaVersion'] = 1
        with self.assertRaisesRegex(InputError, 'only Trivy JSON schema 2'):
            self.run_explain()
        self.setUp()
        self.base['rootfs']['diff_ids'] = [C]
        with self.assertRaisesRegex(InputError, 'exact prefix'):
            self.run_explain()

    def bound_inputs(self):
        base_raw = (ROOT / 'examples/layers/base.json').read_bytes()
        image_raw = (ROOT / 'examples/layers/image.json').read_bytes()
        raw = (ROOT / 'examples/layers/manifest-digest-map.json').read_bytes()
        mapping = json.loads(raw)
        manifest = manifest_for(image_raw, list(mapping))
        base_manifest = manifest_for(base_raw, list(mapping)[:1])
        return dict(report=(ROOT / 'examples/layers/trivy.json').read_bytes(), base_config=base_raw,
                    image_config=image_raw, digest_map=raw, digest_map_sha256=digest(raw),
                    report_sha256=digest((ROOT / 'examples/layers/trivy.json').read_bytes()),
                    image_manifest=json.dumps(manifest).encode(),
                    image_manifest_sha256=digest(json.dumps(manifest).encode()),
                    base_manifest=json.dumps(base_manifest).encode(),
                    base_manifest_sha256=digest(json.dumps(base_manifest).encode()),
                    base_digest_map={list(mapping)[0]: A})

    def test_matching_pin_keeps_ordered_manifest_shared_map_and_config_checks(self):
        options = self.bound_inputs()
        self.assertEqual(explain(**options)['ancestry']['imageManifestBinding']['status'], 'verified_local')
        mapping = json.loads(options['digest_map'])
        keys = list(mapping)
        for changed, error in [({}, 'missing layer mapping'),
                               (mapping | {keys[0]: B, keys[1]: A}, 'conflicts with digest_map'),
                               (mapping | {keys[1]: C}, 'ordered layer mapping mismatch'),
                               (mapping | {A: A}, 'Digest is absent from manifest')]:
            raw = json.dumps(changed).encode()
            with self.subTest(error=error):
                with self.assertRaisesRegex(InputError, error):
                    explain(**(options | dict(digest_map=raw, digest_map_sha256=digest(raw))))
        with self.assertRaisesRegex(InputError, 'config digest mismatch'):
            explain(**(options | dict(image_config=options['image_config'].replace(b'amd64', b'arm64'))))
        # A base map never supplies finding evidence, even with valid local pins.
        raw = b'{}'
        report = json.loads(options['report'])
        report['Results'][0]['Vulnerabilities'][0]['Layer'] = {'Digest': keys[0]}
        report_raw = json.dumps(report).encode()
        result = explain(**(options | dict(image_manifest=None, image_manifest_sha256=None,
                                          image_config=json.loads(options['image_config']),
                                          report=report_raw, report_sha256=digest(report_raw),
                                          digest_map=raw, digest_map_sha256=digest(raw))))
        self.assertEqual(result['groups']['unknown'][0]['finding']['VulnerabilityID'], 'DEMO-BASE')
        self.assertEqual(result['groups']['unknown'][0]['reason'], 'unmapped_compressed_digest')

    def test_all_nine_pins_remain_independent_per_snapshot(self):
        source = self.bound_inputs()
        options = dict(target_map=b'{}', target_map_sha256=digest(b'{}'))
        for side, padding in [('before', b''), ('after', b'\n')]:
            for key, value in source.items():
                if key.endswith('_sha256'):
                    continue
                options[side + '_' + key] = value
                if key in ('report', 'base_manifest', 'image_manifest', 'digest_map'):
                    options[side + '_' + key] = value + padding
                    options[side + '_' + key + '_sha256'] = digest(value + padding)
        result = compare(**options)
        for side in ('before', 'after'):
            self.assertEqual(result['snapshots'][side]['provenance']['digestMapPinAgreement'], 'matched_local')
            for field in ('report', 'base_manifest', 'image_manifest', 'digest_map'):
                key = side + '_' + field
                opposite = ('after' if side == 'before' else 'before') + '_' + field
                with self.subTest(key=key):
                    with self.assertRaisesRegex(InputError, 'digest mismatch'):
                        compare(**(options | {key + '_sha256': digest(options[opposite])}))
            key = side + '_digest_map'
            mixed = compare(**(options | {key: json.loads(options[key]), key + '_sha256': None}))
            self.assertNotIn('digestMapDigest', mixed['snapshots'][side]['provenance'])
            self.assertIn('digestMapDigest', mixed['snapshots']['after' if side == 'before' else 'before']['provenance'])
            with self.assertRaisesRegex(InputError, 'requires digest_map'):
                compare(**(options | {key: None}))
        with self.assertRaisesRegex(InputError, 'target map digest mismatch'):
            compare(**(options | dict(target_map=b'{ }')))
        raw = b'{"missing":"missing"}'
        with self.assertRaisesRegex(InputError, 'absent from before'):
            compare(**(options | dict(target_map=raw, target_map_sha256=digest(raw))))
        bad = json.loads(source['report'])
        bad['Results'][0]['Vulnerabilities'][0]['InstalledVersion'] = 1
        raw = json.dumps(bad).encode()
        with self.assertRaisesRegex(InputError, 'comparison identity fields'):
            compare(**(options | dict(after_report=raw, after_report_sha256=digest(raw))))


class DigestMapPinCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.path = self.directory / 'map.json'
        self.raw = (ROOT / 'examples/layers/digest-map.json').read_bytes()
        self.path.write_bytes(self.raw)
        self.pin = digest(self.raw)
        self.command = ['explain', '--report', str(ROOT / 'examples/layers/trivy.json'),
                        '--base-config', str(ROOT / 'examples/layers/base.json'),
                        '--image-config', str(ROOT / 'examples/layers/image.json'), '--digest-map', str(self.path)]

    def invoke(self, *args, command=None):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'layers', *(command or self.command), *args],
                              cwd=ROOT, capture_output=True, text=True, timeout=60)

    def test_success_adds_only_provenance_and_preserves_gate(self):
        pinned = self.invoke('--digest-map-sha256', self.pin, '--gate', 'app')
        self.assertEqual(pinned.returncode, 1, pinned.stderr)
        result = json.loads(pinned.stdout)
        self.assertEqual(result['provenance'].pop('digestMapDigest'), self.pin)
        self.assertEqual(result['provenance'].pop('digestMapPinAgreement'), 'matched_local')
        self.assertEqual(result, json.loads(self.invoke('--gate', 'app').stdout))

    def test_errors_preserve_output_and_omit_private_values(self):
        output = self.directory / 'out.json'
        for raw, pin, error in [(self.raw, 'SECRET', 'expected lowercase sha256'),
                                (self.raw, '', 'expected lowercase sha256'),
                                (self.raw.replace(C.encode(), B.encode()), self.pin, 'digest map digest mismatch'),
                                (self.raw.replace(b': ', b' :'), self.pin, 'digest map digest mismatch'),
                                (b'invalid', self.pin, 'digest map digest mismatch'),
                                (b'[]', digest(b'[]'), 'expected JSON object')]:
            with self.subTest(error=error):
                self.path.write_bytes(raw); output.write_bytes(b'KEEP')
                result = self.invoke('--digest-map-sha256', pin, '--output', str(output))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertIn(error, result.stderr)
                self.assertNotIn('SECRET', result.stderr)
                self.assertNotIn(str(self.path), result.stderr)
                self.assertEqual(output.read_bytes(), b'KEEP')
        result = self.invoke('--digest-map-sha256', self.pin, command=self.command[:-2])
        self.assertEqual(result.returncode, 2)
        self.assertIn('requires digest_map', result.stderr)

    def test_compare_both_sides_and_one_side_only(self):
        command = ['compare']
        for side in ('before', 'after'):
            for flag, path in zip(self.command[1::2], self.command[2::2]):
                command += ['--' + side + '-' + flag[2:], path]
        flags = ['--before-digest-map-sha256', self.pin, '--after-digest-map-sha256', self.pin]
        result = self.invoke(*flags, command=command)
        self.assertEqual(result.returncode, 0, result.stderr)
        snapshots = json.loads(result.stdout)['snapshots']
        for side in ('before', 'after'):
            self.assertEqual(snapshots[side]['provenance']['digestMapDigest'], self.pin)
            result = self.invoke('--' + side + '-digest-map-sha256', self.pin, command=command)
            self.assertEqual(result.returncode, 0, result.stderr)
            snaps = json.loads(result.stdout)['snapshots']
            self.assertIn('digestMapDigest', snaps[side]['provenance'])
            self.assertNotIn('digestMapDigest', snaps['after' if side == 'before' else 'before']['provenance'])
            result = self.invoke(*flags, '--' + side + '-digest-map-sha256', digest(b'{}'), command=command)
            self.assertEqual(result.returncode, 2)

    def test_bounded_read_and_input_aliases(self):
        for kind in ('direct', 'symlink', 'hardlink'):
            output = self.path if kind == 'direct' else self.directory / kind
            if kind == 'symlink':
                output.symlink_to(self.path)
            if kind == 'hardlink':
                output.hardlink_to(self.path)
            result = self.invoke('--digest-map-sha256', self.pin, '--output', str(output))
            self.assertEqual(result.returncode, 2)
            self.assertIn('output must not replace an input file', result.stderr)
            self.assertEqual(self.path.read_bytes(), self.raw)
        output = self.directory / 'out.json'; output.write_bytes(b'KEEP')
        self.path.write_bytes(self.raw + b' ' * 8192)
        with patch('vulnwrench.layers.cli.MAX_INPUT_BYTES', 8192), \
             redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
            code = main([*self.command, '--digest-map-sha256', self.pin, '--output', str(output)])
        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), '')
        self.assertIn('digest map: input exceeds 32 MiB limit', stderr.getvalue())
        self.assertEqual(output.read_bytes(), b'KEEP')


if __name__ == '__main__':
    unittest.main()
