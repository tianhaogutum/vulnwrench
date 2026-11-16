"""Optional exact image-manifest pin: hash before parse; local agreement only.

A pin is sha256: plus 64 lowercase hex digits. It requires image_manifest bytes,
not a reserialized object, bounded to 32 MiB. Check the hash before strict JSON
parsing, then retain all existing config/map/prefix checks. Only pinned success
adds manifestDigest and manifestPinAgreement=matched_local to imageManifestBinding.
Unpinned dictionaries keep their old output; unpinned bytes remain invalid.
Compare sides never borrow a pin or bytes. Invalid CLI input returns 2 with no
explanation and preserves existing output and input aliases.
"""
from copy import deepcopy
from contextlib import redirect_stderr
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

ROOT = Path(__file__).resolve().parents[2]


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


class ImageManifestPinTests(unittest.TestCase):
    def setUp(self):
        self.base = json.loads((ROOT / 'examples/layers/base.json').read_bytes())
        self.image = (ROOT / 'examples/layers/image.json').read_bytes()
        self.report = json.loads((ROOT / 'examples/layers/trivy.json').read_bytes())
        self.raw = (ROOT / 'examples/layers/image-manifest.json').read_bytes()
        self.manifest = json.loads(self.raw)
        self.mapping = json.loads((ROOT / 'examples/layers/manifest-digest-map.json').read_bytes())
        self.pin = digest(self.raw)

    def explain(self, **changes):
        args = dict(image_manifest=self.raw, image_manifest_sha256=self.pin, digest_map=self.mapping)
        args.update(changes)
        return explain(self.report, self.base, self.image, **args)

    def test_exact_bytes_record_local_pin_and_preserve_parsed_provenance(self):
        original = deepcopy((self.report, self.image, self.manifest, self.mapping))
        unpinned = self.explain(image_manifest=self.manifest, image_manifest_sha256=None)
        result = self.explain()
        binding = result['ancestry']['imageManifestBinding']
        self.assertEqual(binding.pop('manifestDigest'), self.pin)
        self.assertEqual(binding.pop('manifestPinAgreement'), 'matched_local')
        self.assertEqual(result, unpinned)
        self.assertEqual(result['provenance']['imageManifest'], self.manifest)
        result['provenance']['imageManifest']['layers'].clear()
        self.assertEqual((self.report, self.image, self.manifest, self.mapping), original)

    def test_same_length_metadata_and_whitespace_changes_need_original_pin(self):
        for raw in (self.raw.replace(b'Synthetic', b'Changed!!'), self.raw + b'\n'):
            with self.subTest(raw_length=len(raw)):
                # Unpinned content remains valid with the very same config and map.
                self.explain(image_manifest=json.loads(raw), image_manifest_sha256=None)
                with self.assertRaisesRegex(InputError, 'image_manifest: manifest digest mismatch'):
                    self.explain(image_manifest=raw)
        self.assertEqual(len(self.raw.replace(b'Synthetic', b'Changed!!')), len(self.raw))

    def test_hash_precedes_manifest_json_and_config_parsing(self):
        with self.assertRaisesRegex(InputError, 'manifest digest mismatch'):
            self.explain(image_manifest=b'not JSON')
        with self.assertRaisesRegex(InputError, 'manifest digest mismatch'):
            explain(self.report, self.base, b'not config JSON', image_manifest=b'not JSON',
                    image_manifest_sha256=self.pin, digest_map=self.mapping)

    def test_matching_hash_still_requires_strict_json(self):
        for raw, error in [(b'{"x":1,"x":2}', 'duplicate object keys'),
                           (b'{"x":NaN}', 'non-finite'), (b'\xff', 'invalid UTF-8 JSON'),
                           (b'[]', 'expected JSON object'), (b'not JSON', 'invalid UTF-8 JSON')]:
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(InputError, error):
                    self.explain(image_manifest=raw, image_manifest_sha256=digest(raw))

    def test_pin_syntax_is_strict_and_diagnostics_omit_values(self):
        for pin in ('', self.pin[7:], self.pin.upper(), self.pin + '\n', self.pin[:-1],
                    'sha512:' + 'a' * 128, 'SECRET', True, 1, {}, b'abc'):
            with self.subTest(pin=pin):
                with self.assertRaisesRegex(InputError, 'image_manifest_sha256: expected lowercase sha256') as error:
                    self.explain(image_manifest=b'not JSON', image_manifest_sha256=pin)
                self.assertNotIn('SECRET', str(error.exception))

    def test_pin_requires_manifest_and_exact_immutable_bytes(self):
        with self.assertRaisesRegex(InputError, 'image_manifest_sha256: requires image_manifest'):
            self.explain(image_manifest=None, digest_map=None)
        for manifest in (self.manifest, self.raw.decode(), bytearray(self.raw)):
            with self.subTest(type=type(manifest)):
                with self.assertRaisesRegex(InputError, 'raw manifest bytes'):
                    self.explain(image_manifest=manifest)
        with self.assertRaises(InputError):
            self.explain(image_manifest_sha256=None)  # existing unpinned bytes remain unsupported

    def test_manifest_byte_limit_precedes_hashing(self):
        with patch('vulnwrench.layers.core.MAX_INPUT_BYTES', len(self.raw) - 1):
            with patch('vulnwrench.layers.core.hashlib.sha256') as hashed:
                with self.assertRaisesRegex(InputError, 'image manifest: input exceeds 32 MiB limit'):
                    self.explain()
                hashed.assert_not_called()

    def test_matching_pin_does_not_waive_existing_checks(self):
        for mutate, error in [(lambda m: m['layers'].reverse(), 'ordered layer mapping mismatch'),
                              (lambda m: m.update(schemaVersion=1), 'only OCI schema 2'),
                              (lambda m: m['config'].update(digest='sha256:' + '0' * 64), 'config digest mismatch')]:
            manifest = deepcopy(self.manifest)
            mutate(manifest)
            raw = json.dumps(manifest).encode()
            with self.subTest(error=error):
                with self.assertRaisesRegex(InputError, error):
                    self.explain(image_manifest=raw, image_manifest_sha256=digest(raw))
        with self.assertRaisesRegex(InputError, 'missing layer mapping'):
            self.explain(digest_map={})
        self.base['rootfs']['diff_ids'] = ['sha256:' + '0' * 64]
        with self.assertRaisesRegex(InputError, 'exact prefix'):
            self.explain()

    def test_compare_pins_bytes_and_omissions_are_independent(self):
        other = self.raw.replace(b'Synthetic', b'Changed!!')
        args = dict(before_image_manifest=self.raw, before_image_manifest_sha256=self.pin,
                    before_digest_map=self.mapping, after_image_manifest=other,
                    after_image_manifest_sha256=digest(other), after_digest_map=self.mapping)
        def run(**changes):
            return compare(self.report, self.base, self.image, self.report, self.base, self.image,
                           **(args | changes))
        result = run()
        for side, pin in [('before', self.pin), ('after', digest(other))]:
            self.assertEqual(result['snapshots'][side]['ancestry']['imageManifestBinding']['manifestDigest'], pin)
        for side, wrong in [('before', digest(other)), ('after', self.pin)]:
            with self.subTest(side=side):
                with self.assertRaisesRegex(InputError, 'manifest digest mismatch'):
                    run(**{side + '_image_manifest_sha256': wrong})
                with self.assertRaisesRegex(InputError, 'requires image_manifest'):
                    run(**{side + '_image_manifest': None, side + '_digest_map': None})
                mixed = run(**{side + '_image_manifest': self.manifest,
                               side + '_image_manifest_sha256': None})
                self.assertNotIn('manifestDigest', mixed['snapshots'][side]['ancestry']['imageManifestBinding'])
                other_side = 'after' if side == 'before' else 'before'
                self.assertIn('manifestDigest', mixed['snapshots'][other_side]['ancestry']['imageManifestBinding'])

    def test_base_and_final_pins_are_independent_and_preserve_finding_checks(self):
        base_raw = (ROOT / 'examples/layers/base.json').read_bytes()
        base_manifest = deepcopy(self.manifest)
        base_manifest['config'].update(digest=digest(base_raw), size=len(base_raw))
        base_manifest['layers'] = base_manifest['layers'][:1]
        base_manifest_raw = json.dumps(base_manifest).encode()
        base_pin = digest(base_manifest_raw)
        args = dict(base_manifest=base_manifest_raw, base_manifest_sha256=base_pin,
                    base_digest_map={base_manifest['layers'][0]['digest']:
                                     self.base['rootfs']['diff_ids'][0]})
        self.base = base_raw
        def run(**changes):
            return self.explain(**(args | changes))
        result = run()
        self.assertEqual(result['ancestry']['baseManifestBinding']['manifestDigest'], base_pin)
        self.assertEqual(result['ancestry']['imageManifestBinding']['manifestDigest'], self.pin)
        for changes, error in [
                ({'image_manifest_sha256': base_pin}, 'image_manifest: manifest digest mismatch'),
                ({'base_manifest_sha256': self.pin}, 'base_manifest: manifest digest mismatch'),
                ({'base_manifest': None}, 'requires base_manifest'),
                ({'image_manifest': None}, 'requires image_manifest'),
                ({'base_digest_map': {}}, 'missing layer mapping'),
                ({'digest_map': {}}, 'missing layer mapping')]:
            with self.subTest(changes=list(changes)):
                with self.assertRaisesRegex(InputError, error):
                    run(**changes)
        for side, manifest in [('base', base_manifest), ('image', self.manifest)]:
            result = run(**{side + '_manifest': manifest, side + '_manifest_sha256': None})
            self.assertNotIn('manifestDigest', result['ancestry'][side + 'ManifestBinding'])
            other = 'image' if side == 'base' else 'base'
            self.assertIn('manifestDigest', result['ancestry'][other + 'ManifestBinding'])
        # Pin agreement cannot turn inconsistent report evidence into attribution.
        self.report['Metadata']['DiffIDs'].reverse()
        result = run()
        self.assertEqual(result['counts']['unknown'], result['counts']['total'])
        self.assertTrue(all(entry['reason'] == 'report_config_mismatch'
                            for entry in result['groups']['unknown']))


class ImageManifestPinCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.manifest = self.directory / 'manifest.json'
        self.raw = (ROOT / 'examples/layers/image-manifest.json').read_bytes()
        self.manifest.write_bytes(self.raw)
        self.pin = digest(self.raw)
        self.command = ['explain', '--report', str(ROOT / 'examples/layers/trivy.json'),
                        '--base-config', str(ROOT / 'examples/layers/base.json'),
                        '--image-config', str(ROOT / 'examples/layers/image.json'),
                        '--image-manifest', str(self.manifest),
                        '--digest-map', str(ROOT / 'examples/layers/manifest-digest-map.json')]

    def invoke(self, *extra, command=None):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'layers',
                               *(self.command if command is None else command), *extra], cwd=ROOT,
                              capture_output=True, text=True, timeout=60)

    def test_valid_pin_and_unpinned_output_contract(self):
        result = self.invoke('--image-manifest-sha256', self.pin, '--gate', 'app')
        self.assertEqual(result.returncode, 1, result.stderr)
        doc = json.loads(result.stdout)
        self.assertEqual(doc['ancestry']['imageManifestBinding']['manifestDigest'], self.pin)
        self.assertEqual(doc['ancestry']['imageManifestBinding']['manifestPinAgreement'], 'matched_local')
        self.assertEqual(doc['counts'], {'base': 1, 'app': 3, 'unknown': 4, 'total': 8})
        binding = doc['ancestry']['imageManifestBinding']
        del binding['manifestDigest'], binding['manifestPinAgreement']
        self.assertEqual(doc, json.loads(self.invoke('--gate', 'app').stdout))

    def test_tampering_and_malformed_or_orphan_pins_preserve_output(self):
        output = self.directory / 'out.json'
        output.write_bytes(b'preserved')
        no_manifest = self.command[:7]  # required report/base/image inputs only
        for raw, pin, command, error in [
                (self.raw.replace(b'Synthetic', b'Changed!!'), self.pin, self.command, 'manifest digest mismatch'),
                (self.raw + b'\n', self.pin, self.command, 'manifest digest mismatch'),
                (b'not JSON', self.pin, self.command, 'manifest digest mismatch'),
                (b'not JSON', 'SECRET', self.command, 'expected lowercase sha256'),
                (self.raw, '', self.command, 'expected lowercase sha256'),
                (self.raw, self.pin, no_manifest, 'requires image_manifest')]:
            with self.subTest(error=error, pin=pin):
                self.manifest.write_bytes(raw)
                result = self.invoke('--image-manifest-sha256', pin, '--output', str(output), command=command)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertIn(error, result.stderr)
                self.assertNotIn('SECRET', result.stderr)
                self.assertEqual(output.read_bytes(), b'preserved')
        output.unlink()
        self.manifest.write_bytes(self.raw + b'\n')
        self.assertEqual(self.invoke('--image-manifest-sha256', self.pin, '--output', str(output)).returncode, 2)
        self.assertFalse(output.exists())

    def test_compare_cli_different_pins_no_cross_side_fallback(self):
        other = self.directory / 'after.json'
        other.write_bytes(self.raw + b'\n')
        command = ['compare']
        for side, path, pin in [('before', self.manifest, self.pin), ('after', other, digest(other.read_bytes()))]:
            for i in range(1, len(self.command), 2):
                command.extend(['--' + side + '-' + self.command[i][2:],
                                str(path) if self.command[i] == '--image-manifest' else self.command[i + 1]])
            command.extend(['--' + side + '-image-manifest-sha256', pin])
        result = self.invoke(command=command)
        self.assertEqual(result.returncode, 0, result.stderr)
        snapshots = json.loads(result.stdout)['snapshots']
        self.assertEqual(snapshots['before']['ancestry']['imageManifestBinding']['manifestDigest'], self.pin)
        self.assertEqual(snapshots['after']['ancestry']['imageManifestBinding']['manifestDigest'], digest(other.read_bytes()))
        output = self.directory / 'out.json'
        output.write_text('preserved')
        for side, wrong in [('before', digest(other.read_bytes())), ('after', self.pin)]:
            with self.subTest(side=side):
                result = self.invoke('--' + side + '-image-manifest-sha256', wrong,
                                     '--output', str(output), command=command)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('manifest digest mismatch', result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertEqual(output.read_text(), 'preserved')

    def test_pin_mode_keeps_manifest_input_alias_protection(self):
        for kind in ('symlink', 'hardlink'):
            alias = self.directory / kind
            if kind == 'symlink':
                alias.symlink_to(self.manifest)
            else:
                alias.hardlink_to(self.manifest)
            result = self.invoke('--image-manifest-sha256', self.pin, '--output', str(alias))
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('must not replace an input', result.stderr)
            self.assertEqual(self.manifest.read_bytes(), self.raw)

    def test_pinned_cli_manifest_read_is_bounded(self):
        limit = max(Path(self.command[i]).stat().st_size for i in range(2, len(self.command), 2))
        self.manifest.write_bytes(self.raw + b' ' * (limit + 1))
        error = io.StringIO()
        with patch('vulnwrench.layers.cli.MAX_INPUT_BYTES', limit), redirect_stderr(error):
            self.assertEqual(main([*self.command, '--image-manifest-sha256', self.pin]), 2)
        self.assertIn('image manifest: input exceeds 32 MiB limit', error.getvalue())


if __name__ == '__main__':
    unittest.main()
