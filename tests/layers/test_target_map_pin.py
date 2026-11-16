"""Exact target-map pins bind immutable bounded bytes; local agreement only.

Pin syntax/presence/type/size/hash precede map JSON parsing. Matching pins retain
strict JSON, target bijection and independent attribution/identity validation.
Only targetMapDigest/targetMapPinAgreement are added; unpinned output is unchanged.
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

from vulnwrench.layers import InputError, compare
from vulnwrench.layers.cli import main
from test_target_map import A, B, C, config, report

ROOT = Path(__file__).resolve().parents[2]


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


class TargetMapPinTests(unittest.TestCase):
    def setUp(self):
        self.before = report('old')
        self.after = report('new', 'two')
        self.raw = b'{"old": "new"}\n'
        self.mapping = json.loads(self.raw)
        self.pin = digest(self.raw)

    def run_compare(self, **changes):
        options = dict(target_map=self.raw, target_map_sha256=self.pin)
        return compare(self.before, config([A]), config([A, B, C]),
                       self.after, config([A, B]), config([A, B, C]), **(options | changes))

    def test_exact_bytes_preserve_all_evidence_except_pin_metadata(self):
        original = deepcopy((self.before, self.after, self.mapping))
        result = self.run_compare()
        self.assertEqual(result.pop('targetMapDigest'), self.pin)
        self.assertEqual(result.pop('targetMapPinAgreement'), 'matched_local')
        self.assertEqual(result, self.run_compare(target_map=self.mapping, target_map_sha256=None))
        result['targetMap'].clear()
        result['snapshots']['before']['provenance']['report'].clear()
        self.assertEqual((self.before, self.after, self.mapping), original)

    def test_valid_same_length_correspondence_and_whitespace_edits_reject(self):
        for raw in (self.raw.replace(b'new', b'two'), self.raw.replace(b': ', b' :'), self.raw + b'\n'):
            with self.subTest(raw=raw):
                self.assertNotEqual(raw, self.raw)
                unpinned = self.run_compare(target_map=json.loads(raw), target_map_sha256=None)
                self.assertEqual(unpinned['counts']['total'], 4)
                with self.assertRaisesRegex(InputError, 'target_map: target map digest mismatch'):
                    self.run_compare(target_map=raw)
        self.assertEqual(len(self.raw), len(self.raw.replace(b'new', b'two')))
        self.assertEqual(len(self.raw), len(self.raw.replace(b': ', b' :')))

    def test_hash_precedes_json_and_snapshot_processing(self):
        with patch('vulnwrench.layers.comparison.parse_json') as parse, \
             patch('vulnwrench.layers.comparison.explain') as explain:
            with self.assertRaisesRegex(InputError, 'target map digest mismatch'):
                self.run_compare(target_map=b'not JSON')
            parse.assert_not_called()
            explain.assert_not_called()

    def test_malformed_orphan_and_immutable_raw_byte_contract(self):
        for pin in ('', self.pin[7:], self.pin.upper(), self.pin + '\n', self.pin[:-1],
                    'sha512:' + 'a' * 128, 'SECRET', True, 1, {}, b'abc'):
            with self.subTest(pin=pin):
                with self.assertRaisesRegex(InputError, 'target_map_sha256: expected lowercase sha256') as err:
                    self.run_compare(target_map=b'invalid', target_map_sha256=pin)
                self.assertNotIn('SECRET', str(err.exception))
        with self.assertRaisesRegex(InputError, 'target_map_sha256: requires target_map'):
            self.run_compare(target_map=None)
        for value in (self.mapping, self.raw.decode(), bytearray(self.raw), memoryview(self.raw)):
            with self.subTest(type=type(value)):
                with self.assertRaisesRegex(InputError, 'requires raw target map bytes'):
                    self.run_compare(target_map=value)
        with self.assertRaisesRegex(InputError, 'expected JSON object'):
            self.run_compare(target_map_sha256=None)

    def test_size_limit_before_hash_and_exact_limit_accepted(self):
        with patch('vulnwrench.layers.comparison.MAX_INPUT_BYTES', len(self.raw)):
            self.run_compare()
        with patch('vulnwrench.layers.comparison.MAX_INPUT_BYTES', len(self.raw) - 1), \
             patch('vulnwrench.layers.comparison.hashlib.sha256') as hashed:
            with self.assertRaisesRegex(InputError, 'target map: input exceeds 32 MiB limit'):
                self.run_compare()
            hashed.assert_not_called()

    def test_matching_hash_requires_strict_json_object(self):
        for raw, error in [(b'{"old":"new","old":"two"}', 'duplicate object keys'),
                           (b'{"old":NaN}', 'non-finite'), (b'\xff', 'invalid UTF-8 JSON'),
                           (b'[]', 'expected JSON object'), (b'bad', 'invalid UTF-8 JSON')]:
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(InputError, error):
                    self.run_compare(target_map=raw, target_map_sha256=digest(raw))

    def test_matching_hash_requires_endpoints_strings_and_effective_bijection(self):
        self.before, self.after = report('a', 'b'), report('b', 'c')
        for mapping, error in [({'a': 'b'}, 'non-bijective'),
                               ({'a': 'c', 'b': 'c'}, 'non-bijective'),
                               ({'SECRET': 'b'}, 'absent from before'),
                               ({'a': 'SECRET'}, 'absent from after'),
                               ({'a': ''}, 'nonempty strings'), ({'a': None}, 'nonempty strings')]:
            raw = json.dumps(mapping).encode()
            with self.subTest(mapping=mapping):
                with self.assertRaisesRegex(InputError, error) as err:
                    self.run_compare(target_map=raw, target_map_sha256=digest(raw))
                self.assertNotIn('SECRET', str(err.exception))
        for doc in (self.before, self.after):
            for result in doc['Results']:
                result['Vulnerabilities'] = []
        raw = b'{"a":"b"}'
        with self.assertRaisesRegex(InputError, 'non-bijective'):
            self.run_compare(target_map=raw, target_map_sha256=digest(raw))
        self.raw, self.pin = b'{}', digest(b'{}')
        self.assertEqual(self.run_compare()['counts']['total'], 0)
        self.assertEqual(len(self.run_compare()['targetCoverage']), 3)

    def test_matching_pin_keeps_other_identity_checks_duplicates_and_unknown(self):
        self.after['Results'][0]['Vulnerabilities'][0]['InstalledVersion'] = 123
        with self.assertRaisesRegex(InputError, 'comparison identity fields'):
            self.run_compare()
        self.setUp()
        entries = self.after['Results'][0]['Vulnerabilities']
        entries.append(deepcopy(entries[0]))
        del entries[1]['Layer']
        result = self.run_compare()
        self.assertEqual(result['rows'][0]['reason'], 'ambiguous_finding_identity')
        self.assertEqual(len(result['rows'][0]['after']), 2)
        self.assertEqual(result['rows'][1]['reason'], 'insufficient_attribution_evidence')

    def test_all_snapshot_pins_remain_independent_and_never_bypass_validation(self):
        base_raw = (ROOT / 'examples/layers/base.json').read_bytes()
        image_raw = (ROOT / 'examples/layers/image.json').read_bytes()
        manifest_raw = (ROOT / 'examples/layers/image-manifest.json').read_bytes()
        mapping = json.loads((ROOT / 'examples/layers/manifest-digest-map.json').read_bytes())
        base_manifest = json.loads(manifest_raw)
        base_manifest['config'].update(digest=digest(base_raw), size=len(base_raw))
        base_manifest['layers'] = base_manifest['layers'][:1]
        base_manifest_raw = json.dumps(base_manifest).encode()
        base_mapping = {base_manifest['layers'][0]['digest']: A}
        report_raw = (ROOT / 'examples/layers/trivy.json').read_bytes()
        raws, options = {}, dict(target_map=b'{}', target_map_sha256=digest(b'{}'))
        for side, padding in [('before', b''), ('after', b'\n')]:
            for field, raw in [('report', report_raw), ('base_manifest', base_manifest_raw),
                               ('image_manifest', manifest_raw)]:
                raws[side + '_' + field] = raw + padding
                options[side + '_' + field + '_sha256'] = digest(raw + padding)
                if field != 'report':
                    options[side + '_' + field] = raw + padding
            options[side + '_digest_map'] = mapping
            options[side + '_base_digest_map'] = base_mapping
        def run(**changes):
            values = dict(before_report=raws['before_report'], before_base_config=base_raw,
                          before_image_config=image_raw, after_report=raws['after_report'],
                          after_base_config=base_raw, after_image_config=image_raw) | options | changes
            return compare(**values)
        result = run()
        self.assertEqual(result['targetMapPinAgreement'], 'matched_local')
        for side in ('before', 'after'):
            for field in ('report', 'base_manifest', 'image_manifest'):
                key = side + '_' + field
                with self.subTest(key=key):
                    opposite = ('after' if side == 'before' else 'before') + '_' + field
                    with self.assertRaisesRegex(InputError, 'digest mismatch'):
                        run(**{key + '_sha256': digest(raws[opposite])})
                    mixed = run(**{key: json.loads(raws[key]), key + '_sha256': None})
                    self.assertEqual(mixed['targetMapPinAgreement'], 'matched_local')
            with self.assertRaisesRegex(InputError, 'config digest mismatch'):
                run(**{side + '_image_config': image_raw.replace(b'amd64', b'arm64')})
            for field in ('base_digest_map', 'digest_map'):
                with self.assertRaisesRegex(InputError, 'missing layer mapping'):
                    run(**{side + '_' + field: {}})
        for change, error in [('schema', 'only Trivy JSON schema 2'), ('prefix', 'exact prefix')]:
            if change == 'schema':
                bad = json.loads(report_raw); bad['SchemaVersion'] = 1
                raw = json.dumps(bad).encode()
                changes = dict(after_report=raw, after_report_sha256=digest(raw))
            else:
                changes = dict(after_base_config=config([C]), after_base_manifest=None,
                               after_base_manifest_sha256=None, after_base_digest_map=None)
            with self.assertRaisesRegex(InputError, error):
                run(**changes)
        unpinned_map = run(target_map={}, target_map_sha256=None)
        self.assertNotIn('targetMapDigest', unpinned_map)
        self.assertEqual(unpinned_map['snapshots'], result['snapshots'])


class TargetMapPinCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.path = self.directory / 'map.json'
        self.raw = (ROOT / 'examples/layers/target-map.json').read_bytes()
        self.path.write_bytes(self.raw)
        self.pin = digest(self.raw)
        self.command = ['compare', '--before-report', str(ROOT / 'examples/layers/upgrade-before.json'),
                        '--before-base-config', str(ROOT / 'examples/layers/base.json'),
                        '--before-image-config', str(ROOT / 'examples/layers/image.json'),
                        '--after-report', str(ROOT / 'examples/layers/upgrade-renamed-after.json'),
                        '--after-base-config', str(ROOT / 'examples/layers/upgraded-base.json'),
                        '--after-image-config', str(ROOT / 'examples/layers/upgraded-image.json'),
                        '--target-map', str(self.path)]

    def invoke(self, *extra, command=None):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'layers',
                               *(self.command if command is None else command), *extra],
                              cwd=ROOT, capture_output=True, text=True, timeout=60)

    def test_pinned_cli_preserves_unpinned_mapped_output(self):
        result = self.invoke('--target-map-sha256', self.pin)
        self.assertEqual(result.returncode, 0, result.stderr)
        doc = json.loads(result.stdout)
        self.assertEqual(doc.pop('targetMapDigest'), self.pin)
        self.assertEqual(doc.pop('targetMapPinAgreement'), 'matched_local')
        self.assertEqual(json.dumps(doc, sort_keys=True, indent=2) + '\n', self.invoke().stdout)
        self.assertEqual(doc['counts']['attribution_changed'], 1)
        self.assertEqual(doc['counts']['unknown'], 1)

    def test_bad_pin_tampering_strict_json_and_orphan_preserve_output(self):
        output = self.directory / 'out.json'
        output.write_text('preserved')
        for raw, pin, error in [(self.raw, 'SECRET', 'expected lowercase sha256'),
                                 (self.raw.replace(b': ', b' :'), self.pin, 'digest mismatch'),
                                 (self.raw + b'\n', self.pin, 'digest mismatch'),
                                 (b'{"x":1,"x":2}', digest(b'{"x":1,"x":2}'), 'duplicate object keys'),
                                 (b'{"SECRET":"x"}', digest(b'{"SECRET":"x"}'), 'absent from before')]:
            with self.subTest(error=error):
                self.path.write_bytes(raw)
                result = self.invoke('--target-map-sha256', pin, '--output', str(output))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertIn(error, result.stderr)
                self.assertNotIn('SECRET', result.stderr)
                self.assertNotIn(str(self.directory), result.stderr)
                self.assertEqual(output.read_text(), 'preserved')
        result = self.invoke('--target-map-sha256', self.pin, '--output', str(output),
                             command=self.command[:-2])
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('requires target_map', result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(output.read_text(), 'preserved')

    def test_pinning_keeps_alias_and_bounded_read_protections(self):
        symlink, hardlink = self.directory / 'symlink', self.directory / 'hardlink'
        symlink.symlink_to(self.path)
        hardlink.hardlink_to(self.path)
        for path in (self.path, symlink, hardlink):
            result = self.invoke('--target-map-sha256', self.pin, '--output', str(path))
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('must not replace an input', result.stderr)
            self.assertEqual(self.path.read_bytes(), self.raw)
        self.path.write_bytes(self.raw + b' ' * 4096)
        output = self.directory / 'out.json'
        output.write_text('preserved')
        with patch('vulnwrench.layers.cli.MAX_INPUT_BYTES', 4096), \
             redirect_stderr(io.StringIO()) as err, redirect_stdout(io.StringIO()) as out:
            code = main([*self.command, '--target-map-sha256', self.pin, '--output', str(output)])
        self.assertEqual(code, 2)
        self.assertIn('target map: input exceeds 32 MiB', err.getvalue())
        self.assertEqual(out.getvalue(), '')
        self.assertEqual(output.read_text(), 'preserved')


if __name__ == '__main__':
    unittest.main()
