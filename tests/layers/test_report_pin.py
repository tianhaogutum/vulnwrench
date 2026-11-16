"""Report pins bind bounded original bytes before parsing; local agreement only.

Only pinned success adds provenance.reportDigest/reportPinAgreement=matched_local.
Every existing report/config/map/prefix/compare check still applies. Unpinned
objects/output remain unchanged; bytes require a pin; snapshots never borrow pins.
"""
from contextlib import redirect_stderr
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

ROOT = Path(__file__).resolve().parents[2]


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


class ReportPinTests(unittest.TestCase):
    def setUp(self):
        self.raw = (ROOT / 'examples/layers/trivy.json').read_bytes()
        self.report = json.loads(self.raw)
        self.pin = digest(self.raw)
        self.base = json.loads((ROOT / 'examples/layers/base.json').read_bytes())
        self.image = json.loads((ROOT / 'examples/layers/image.json').read_bytes())

    def explain(self, raw=None, **options):
        return explain(self.raw if raw is None else raw, self.base, self.image,
                       **({'report_sha256': self.pin} | options))

    def test_exact_bytes_preserve_everything_except_explicit_pin_metadata(self):
        original = deepcopy((self.report, self.base, self.image))
        result = self.explain()
        self.assertEqual(result['provenance'].pop('reportDigest'), self.pin)
        self.assertEqual(result['provenance'].pop('reportPinAgreement'), 'matched_local')
        self.assertEqual(result, explain(self.report, self.base, self.image))
        result['provenance']['report']['Results'].clear()
        self.assertEqual((self.report, self.base, self.image), original)

    def test_metadata_and_whitespace_tampering_rejected_even_with_valid_evidence(self):
        other = self.raw.replace(b'synthetic:local', b'synthetic:other')
        self.assertNotEqual(other, self.raw)
        self.assertEqual(len(other), len(self.raw))
        for raw in (other, self.raw + b'\n'):
            with self.subTest(length=len(raw)):
                self.assertEqual(explain(json.loads(raw), self.base, self.image)['counts'],
                                 explain(self.report, self.base, self.image)['counts'])
                with self.assertRaisesRegex(InputError, 'report: report digest mismatch'):
                    self.explain(raw)

    def test_hash_before_json_and_unrelated_config_validation(self):
        with patch('vulnwrench.layers.core.parse_json') as parse:
            with self.assertRaisesRegex(InputError, 'report digest mismatch'):
                explain(b'not JSON', None, None, report_sha256=self.pin)
            parse.assert_not_called()

    def test_matching_hash_still_requires_strict_object_json(self):
        for raw, error in [(b'{"x":1,"x":2}', 'duplicate object keys'),
                           (b'{"x":NaN}', 'non-finite'), (b'\xff', 'invalid UTF-8 JSON'),
                           (b'[]', 'expected JSON object'), (b'bad', 'invalid UTF-8 JSON')]:
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(InputError, error):
                    self.explain(raw, report_sha256=digest(raw))

    def test_pin_syntax_is_strict_and_private_values_are_not_echoed(self):
        for pin in ('', self.pin[7:], self.pin.upper(), self.pin + '\n', self.pin[:-1],
                    'sha512:' + 'a' * 128, 'SECRET', True, 1, {}, b'abc'):
            with self.subTest(pin=pin):
                with self.assertRaisesRegex(InputError, 'report_sha256: expected lowercase sha256') as err:
                    self.explain(b'not JSON', report_sha256=pin)
                self.assertNotIn('SECRET', str(err.exception))

    def test_orphan_and_raw_immutable_byte_contract(self):
        with self.assertRaisesRegex(InputError, 'report_sha256: requires report'):
            explain(None, self.base, self.image, report_sha256=self.pin)
        for report in (self.report, self.raw.decode(), bytearray(self.raw)):
            with self.subTest(type=type(report)):
                with self.assertRaisesRegex(InputError, 'raw report bytes'):
                    self.explain(report)
        with self.assertRaises(InputError):
            self.explain(report_sha256=None)

    def test_byte_limit_before_hashing_and_exact_limit_accepted(self):
        with patch('vulnwrench.layers.core.MAX_INPUT_BYTES', len(self.raw)):
            self.explain()
        with patch('vulnwrench.layers.core.MAX_INPUT_BYTES', len(self.raw) - 1):
            with patch('vulnwrench.layers.core.hashlib.sha256') as hashed:
                with self.assertRaisesRegex(InputError, 'report: input exceeds 32 MiB limit'):
                    self.explain()
                hashed.assert_not_called()

    def test_matching_pin_does_not_bypass_schema_prefix_or_report_binding(self):
        for mutate, error in [(lambda r: r.update(SchemaVersion=1), 'only Trivy JSON schema 2'),
                              (lambda r: r.update(ArtifactType='filesystem'), 'only container_image'),
                              (lambda r: r['Results'][0].update(Secrets=[{}]), 'unsupported finding')]:
            report = deepcopy(self.report)
            mutate(report)
            raw = json.dumps(report).encode()
            with self.subTest(error=error):
                with self.assertRaisesRegex(InputError, error):
                    self.explain(raw, report_sha256=digest(raw))
        self.base['rootfs']['diff_ids'] = ['sha256:' + '0' * 64]
        with self.assertRaisesRegex(InputError, 'exact prefix'):
            self.explain()
        self.base['rootfs']['diff_ids'] = self.image['rootfs']['diff_ids'][:1]
        self.report['Metadata']['DiffIDs'].reverse()
        raw = json.dumps(self.report).encode()
        result = self.explain(raw, report_sha256=digest(raw))
        self.assertEqual(result['counts']['unknown'], result['counts']['total'])
        self.assertTrue(all(e['reason'] == 'report_config_mismatch' for e in result['groups']['unknown']))

    def test_report_base_and_image_pins_stay_independent_and_maps_configs_checked(self):
        image_raw = (ROOT / 'examples/layers/image.json').read_bytes()
        base_raw = (ROOT / 'examples/layers/base.json').read_bytes()
        image_manifest_raw = (ROOT / 'examples/layers/image-manifest.json').read_bytes()
        manifest = json.loads(image_manifest_raw)
        mapping = json.loads((ROOT / 'examples/layers/manifest-digest-map.json').read_bytes())
        base_manifest = deepcopy(manifest)
        base_manifest['config'].update(digest=digest(base_raw), size=len(base_raw))
        base_manifest['layers'] = base_manifest['layers'][:1]
        base_manifest_raw = json.dumps(base_manifest).encode()
        options = dict(report_sha256=self.pin, image_manifest=image_manifest_raw,
                       image_manifest_sha256=digest(image_manifest_raw), digest_map=mapping,
                       base_manifest=base_manifest_raw, base_manifest_sha256=digest(base_manifest_raw),
                       base_digest_map={base_manifest['layers'][0]['digest']: self.base['rootfs']['diff_ids'][0]})
        def run(**changes):
            return explain(self.raw, base_raw, image_raw, **(options | changes))
        result = run()
        self.assertEqual(result['provenance']['reportDigest'], self.pin)
        for field, wrong in [('report_sha256', digest(image_manifest_raw)),
                             ('image_manifest_sha256', self.pin), ('base_manifest_sha256', self.pin)]:
            with self.subTest(field=field):
                with self.assertRaisesRegex(InputError, 'digest mismatch'):
                    run(**{field: wrong})
        for field in ('base_digest_map', 'digest_map'):
            with self.assertRaisesRegex(InputError, 'missing layer mapping'):
                run(**{field: {}})
        with self.assertRaisesRegex(InputError, 'config digest mismatch'):
            explain(self.raw, base_raw, image_raw.replace(b'amd64', b'arm64'), **options)
        for source, raw in [('base', base_manifest_raw), ('image', image_manifest_raw)]:
            unpinned = run(**{source + '_manifest': json.loads(raw), source + '_manifest_sha256': None})
            self.assertNotIn('manifestDigest', unpinned['ancestry'][source + 'ManifestBinding'])
            self.assertEqual(unpinned['provenance']['reportDigest'], self.pin)
        unpinned = explain(self.report, base_raw, image_raw, **(options | {'report_sha256': None}))
        self.assertNotIn('reportDigest', unpinned['provenance'])
        self.assertIn('manifestDigest', unpinned['ancestry']['imageManifestBinding'])

    def test_compare_report_bytes_pins_omissions_and_target_checks_are_independent(self):
        other = self.raw + b'\n'
        options = dict(before_report_sha256=self.pin, after_report_sha256=digest(other))
        def run(before=None, after=None, **changes):
            return compare(self.raw if before is None else before, self.base, self.image,
                           other if after is None else after, self.base, self.image, **(options | changes))
        result = run(target_map={})
        for side, pin in [('before', self.pin), ('after', digest(other))]:
            self.assertEqual(result['snapshots'][side]['provenance']['reportDigest'], pin)
        for side, wrong in [('before', digest(other)), ('after', self.pin)]:
            with self.subTest(side=side):
                with self.assertRaisesRegex(InputError, 'report digest mismatch'):
                    run(**{side + '_report_sha256': wrong})
                mixed = run(**{side: self.report, side + '_report_sha256': None})
                self.assertNotIn('reportDigest', mixed['snapshots'][side]['provenance'])
                self.assertIn('reportDigest', mixed['snapshots']['after' if side == 'before' else 'before']['provenance'])
        with self.assertRaises(InputError):
            run(target_map={'absent': 'absent'})
        invalid_identity = deepcopy(self.report)
        invalid_identity['Results'][0]['Vulnerabilities'][0]['InstalledVersion'] = 123
        raw = json.dumps(invalid_identity).encode()
        with self.assertRaisesRegex(InputError, 'comparison identity fields'):
            run(after=raw, after_report_sha256=digest(raw))


class ReportPinCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.path = self.directory / 'report.json'
        self.raw = (ROOT / 'examples/layers/trivy.json').read_bytes()
        self.path.write_bytes(self.raw)
        self.pin = digest(self.raw)
        self.command = ['explain', '--report', str(self.path),
                        '--base-config', str(ROOT / 'examples/layers/base.json'),
                        '--image-config', str(ROOT / 'examples/layers/image.json')]

    def invoke(self, *extra, command=None):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'layers',
                               *(self.command if command is None else command), *extra], cwd=ROOT,
                              capture_output=True, text=True, timeout=60)

    def test_valid_pin_preserves_unpinned_document_and_gate(self):
        result = self.invoke('--report-sha256', self.pin, '--gate', 'app')
        self.assertEqual(result.returncode, 1, result.stderr)
        doc = json.loads(result.stdout)
        self.assertEqual(doc['provenance'].pop('reportDigest'), self.pin)
        self.assertEqual(doc['provenance'].pop('reportPinAgreement'), 'matched_local')
        self.assertEqual(doc, json.loads(self.invoke('--gate', 'app').stdout))

    def test_tampering_malformed_and_matching_invalid_json_preserve_output(self):
        output = self.directory / 'out.json'
        output.write_bytes(b'preserved')
        for raw, pin, error in [
                (self.raw.replace(b'synthetic:local', b'synthetic:other'), self.pin, 'report digest mismatch'),
                (self.raw + b'\n', self.pin, 'report digest mismatch'),
                (b'bad', self.pin, 'report digest mismatch'),
                (b'bad', 'SECRET', 'expected lowercase sha256'),
                (self.raw, '', 'expected lowercase sha256'),
                (b'{"x":1,"x":2}', digest(b'{"x":1,"x":2}'), 'duplicate object keys')]:
            with self.subTest(error=error):
                self.path.write_bytes(raw)
                result = self.invoke('--report-sha256', pin, '--output', str(output))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertIn(error, result.stderr)
                self.assertNotIn('SECRET', result.stderr)
                self.assertEqual(output.read_bytes(), b'preserved')
        output.unlink()
        result = self.invoke('--report-sha256', self.pin, '--output', str(output))
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())
        # The required --report argument makes an orphan impossible at the CLI boundary.
        result = self.invoke('--report-sha256', self.pin, command=self.command[:1] + self.command[3:])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')

    def test_compare_cli_pins_are_independent_and_mixed_pinning_is_allowed(self):
        other = self.directory / 'after.json'
        other.write_bytes(self.raw + b'\n')
        command = ['compare']
        for side, path in [('before', self.path), ('after', other)]:
            for i in range(1, len(self.command), 2):
                command.extend(['--' + side + '-' + self.command[i][2:],
                                str(path) if self.command[i] == '--report' else self.command[i + 1]])
        extra = ['--before-report-sha256', self.pin, '--after-report-sha256', digest(other.read_bytes())]
        result = self.invoke(*extra, command=command)
        self.assertEqual(result.returncode, 0, result.stderr)
        snapshots = json.loads(result.stdout)['snapshots']
        self.assertEqual(snapshots['before']['provenance']['reportDigest'], self.pin)
        self.assertEqual(snapshots['after']['provenance']['reportDigest'], digest(other.read_bytes()))
        for side, wrong in [('before', digest(other.read_bytes())), ('after', self.pin)]:
            output = self.directory / (side + '-out.json')
            output.write_text('preserved')
            result = self.invoke(*extra, '--' + side + '-report-sha256', wrong,
                                 '--output', str(output), command=command)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('report digest mismatch', result.stderr)
            self.assertEqual(result.stdout, '')
            self.assertEqual(output.read_text(), 'preserved')
            only = ['--' + side + '-report-sha256', self.pin if side == 'before' else digest(other.read_bytes())]
            mixed = self.invoke(*only, command=command)
            self.assertEqual(mixed.returncode, 0, mixed.stderr)
            snaps = json.loads(mixed.stdout)['snapshots']
            self.assertIn('reportDigest', snaps[side]['provenance'])
            self.assertNotIn('reportDigest', snaps['after' if side == 'before' else 'before']['provenance'])

    def test_pin_keeps_alias_protection_and_bounded_reads(self):
        for kind in ('symlink', 'hardlink'):
            alias = self.directory / kind
            if kind == 'symlink':
                alias.symlink_to(self.path)
            else:
                alias.hardlink_to(self.path)
            result = self.invoke('--report-sha256', self.pin, '--output', str(alias))
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('must not replace an input', result.stderr)
            self.assertEqual(self.path.read_bytes(), self.raw)
        limit = len(self.raw)
        self.path.write_bytes(self.raw + b' ')
        error = io.StringIO()
        with patch('vulnwrench.layers.cli.MAX_INPUT_BYTES', limit), redirect_stderr(error):
            self.assertEqual(main([*self.command, '--report-sha256', self.pin]), 2)
        self.assertIn('report: input exceeds 32 MiB limit', error.getvalue())


if __name__ == '__main__':
    unittest.main()
