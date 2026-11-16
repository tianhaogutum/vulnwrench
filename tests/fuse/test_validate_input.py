"""Single scanner validation counts only the fully validated supported profile."""

from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import vulnwrench.fuse as vf
from .test_core import grype, osv, trivy, tv
from .test_saved_explain import cli, ROOT


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def summary(scanner, raw, observations, findings):
    return {
        'schemaVersion': 'vulnfuse-input-validation-1',
        'validation': 'profile-valid',
        'scanner': scanner,
        'input': {'sha256': digest(raw), 'byteCount': len(raw), 'digestKind': 'file-bytes'},
        'observationCount': observations,
        'findingCount': findings,
    }


class ValidateInputTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.source, self.output = self.base / 'synthetic-secret.json', self.base / 'output.json'

    def args(self, scanner='trivy'):
        return ['validate-input', '--scanner', scanner, '--input', self.source]

    def assert_rejected(self, args):
        sentinel = b'private sentinel\x00\xff'
        for exists in (True, False):
            if exists:
                self.output.write_bytes(sentinel)
            elif self.output.exists():
                self.output.unlink()
            result = cli(*args, '--output', self.output)
            self.assertEqual((result.returncode, result.stdout), (2, ''), result.stderr)
            self.assertTrue(result.stderr.startswith('vulnwrench fuse: '))
            for value in ('Traceback', 'synthetic-secret', str(self.base), '0' * 64):
                self.assertNotIn(value, result.stderr)
            if exists:
                self.assertEqual(self.output.read_bytes(), sentinel)
            else:
                self.assertFalse(self.output.exists())
        return result

    def test_recognized_empty_and_nonempty_profiles_all_scanners(self):
        cases = [
            ('trivy', {'Results': []}, 0, 0),
            ('trivy', {'Results': None}, 0, 0),
            ('trivy', {'Results': [{'Target': 'synthetic-secret'}]}, 0, 0),
            ('trivy', {'Results': [{'Vulnerabilities': None}]}, 0, 0),
            ('grype', {'matches': []}, 0, 0),
            ('osv', {'results': []}, 0, 0),
            ('osv', {'results': [{'packages': []}]}, 0, 0),
            ('osv', osv([]), 0, 0),
            ('trivy', trivy([tv(), tv()]), 2, 1),
            ('grype', grype(), 1, 1),
            ('osv', osv([{'id': 'A', 'aliases': ['B']}, {'id': 'B'}]), 2, 1),
        ]
        for scanner, document, observations, findings in cases:
            with self.subTest(scanner=scanner, document=document):
                raw = vf.dumps(document).encode()
                self.source.write_bytes(raw)
                expected = summary(scanner, raw, observations, findings)
                for pin in ([], ['--input-sha256', digest(raw)]):
                    result = cli(*self.args(scanner), *pin)
                    self.assertEqual((result.returncode, result.stderr), (0, ''), result.stderr)
                    self.assertEqual(result.stdout, vf.dumps(expected))
                self.assertEqual(vf.validate_input(scanner, self.source), expected)
                self.assertEqual(vf.validate_input(scanner, self.source, expected_sha256=digest(raw)), expected)
        for scanner in ('trivy', 'grype', 'osv'):
            raw = (ROOT / 'examples' / 'fuse' / (scanner + '.json')).read_bytes()
            self.source.write_bytes(raw)
            result = cli(*self.args(scanner))
            self.assertEqual((result.returncode, result.stderr), (0, ''))
            self.assertEqual(json.loads(result.stdout), summary(scanner, raw, 2, 2))

    def test_exact_bytes_deterministic_private_output_without_path_or_evidence(self):
        document = trivy([tv()])
        document['synthetic-secret'] = 'raw evidence must not escape'
        raw = vf.dumps(document).encode()
        variants = [raw, raw.replace(b'\n', b'\r\n'),
                    json.dumps(document, separators=(',', ':')).encode(),
                    json.dumps(dict(reversed(list(document.items())))).encode()]
        for raw in variants:
            self.source.write_bytes(raw)
            expected = vf.dumps(summary('trivy', raw, 1, 1))
            plain = cli(*self.args())
            self.assertEqual((plain.returncode, plain.stderr), (0, ''))
            self.assertEqual(plain.stdout, expected)
            for exists in (True, False):
                if exists:
                    self.output.write_bytes(b'old output')
                else:
                    self.output.unlink()
                result = cli(*self.args(), '--input-sha256', digest(raw), '--output', self.output)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))
                self.assertEqual(self.output.read_text(), expected)
                self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
            moved = self.base / 'different-name.json'
            moved.write_bytes(raw)
            self.assertEqual(vf.validate_input('trivy', moved), json.loads(expected))
            self.assertLess(len(expected), 450)
        self.assertEqual(len({digest(raw) for raw in variants}), 4)
        self.source.write_bytes(variants[-1])
        self.assert_rejected([*self.args(), '--input-sha256', digest(variants[0])])

    def test_counts_keep_alias_and_identity_grouping_and_ignore_other_collections(self):
        g = grype('A', ['B'])
        g['matches'].extend(deepcopy(grype('B')['matches']))
        g['matches'].extend(deepcopy(grype('C')['matches']))
        g['ignoredMatches'] = [{'synthetic-secret': 'not an observation'}]
        t = trivy([tv('A'), tv('A', version='2.0'), tv('B')])
        t['Results'][0]['Secrets'] = [{'synthetic-secret': True}]
        unknown = trivy([tv(), tv()], type_='vendor-unknown')
        o = osv([{'id': 'A', 'aliases': ['B']}, {'id': 'B'}, {'id': 'C'}])
        o['groups'] = [{'ids': ['A', 'C']}]
        for scanner, document, observations, findings in [('grype', g, 3, 2), ('trivy', t, 3, 3),
                                                         ('trivy', unknown, 2, 2), ('osv', o, 3, 2)]:
            raw = vf.dumps(document).encode()
            self.source.write_bytes(raw)
            self.assertEqual(vf.validate_input(scanner, self.source), summary(scanner, raw, observations, findings))

    def test_malformed_mismatched_expectations_preserve_outputs_and_sanitize(self):
        self.source.write_bytes(b'{"Results":[]}')
        for expected in ['', 'a' * 63, 'a' * 65, 'A' * 64, 'g' * 64, '０' * 64,
                         'a' * 64 + '\n', ' ' + 'a' * 64, 'a' * 64 + ' ',
                         'sha256:' + 'a' * 64, 'synthetic-secret', '0' * 64]:
            result = self.assert_rejected([*self.args(), '--input-sha256', expected])
            if expected:
                self.assertNotIn(expected, result.stderr)
            self.assertNotIn(digest(self.source.read_bytes()), result.stderr)
            with self.assertRaises(vf.InputError):
                vf.validate_input('trivy', self.source, expected_sha256=expected)

    def test_matching_hash_requires_full_profile_including_empty_and_late_invalid_data(self):
        valid_t = trivy([tv()])
        valid_t['Results'].append({'Target': 123, 'Vulnerabilities': []})
        valid_g = grype()
        valid_g['matches'].append({'artifact': {'name': 'synthetic-secret'}, 'vulnerability': {'id': 123}})
        valid_o = osv([{'id': 'A'}])
        valid_o['results'].append({'source': {'path': 123}, 'packages': []})
        invalid = {
            'trivy': [{}, None, [], {'Results': [], 'matches': []},
                      {'Results': [{'Target': 123, 'Vulnerabilities': []}]},
                      {'Results': [{'Type': [], 'Vulnerabilities': None}]},
                      trivy([tv(PkgIdentifier={'PURL': 'pkg:npm/demo@2.0'})]), valid_t],
            'grype': [{'matches': None}, {'matches': {}}, {'matches': [{}]}, valid_g],
            'osv': [{'results': None}, {'results': [{}]}, {'results': [{'packages': [{}]}]},
                    {'results': [{'source': {'path': 123}, 'packages': []}]},
                    osv([], {'name': 'demo', 'version': '1.0', 'ecosystem': 'npm', 'purl': 'pkg:npm/demo@2.0'}), valid_o],
        }
        for scanner, documents in invalid.items():
            for document in documents:
                with self.subTest(scanner=scanner, document=document):
                    raw = vf.dumps(document).encode()
                    self.source.write_bytes(raw)
                    self.assert_rejected([*self.args(scanner), '--input-sha256', digest(raw)])
                    with self.assertRaises(vf.InputError):
                        vf.validate_input(scanner, self.source, expected_sha256=digest(raw))

    def test_matching_hash_strict_json_size_and_unreadable_inputs(self):
        for raw in [b'{"Results":[],"Results":[]}', b'{"Results":[],"x":NaN}',
                    b'{"Results":[],"x":Infinity}', b'{"Results":[],"x":1e9999}',
                    b'{"Results":[],"x":{"a":1,"a":2}}', b'\xff', b'{',
                    b'[' * 2000 + b']' * 2000, b' ' * (32 * 1024 * 1024 + 1)]:
            self.source.write_bytes(raw)
            self.assert_rejected([*self.args(), '--input-sha256', digest(raw)])
            with self.assertRaises(vf.InputError):
                vf.validate_input('trivy', self.source, expected_sha256=digest(raw))
        self.source.unlink()
        self.assert_rejected(self.args())
        self.source.mkdir()
        self.assert_rejected(self.args())
        with self.assertRaises(vf.InputError):
            vf.validate_input('trivy', self.source)

    def test_mode_restrictions_and_help(self):
        self.source.write_bytes(b'{"Results":[]}')
        for args in [[], ['--scanner', 'trivy'], ['--input', self.source],
                     ['--scanner', 'TRIVY', '--input', self.source],
                     ['--scanner', 'synthetic-secret', '--input', self.source],
                     [*self.args()[1:], '--input-sha256']]:
            self.assert_rejected(['validate-input', *args])
        for option in ['--trivy', '--grype', '--osv', '--coverage-manifest', '--coverage-manifest-sha256',
                       '--merged', '--merged-sha256', '--finding', '--advisory', '--package', '--markdown']:
            self.assert_rejected([*self.args(), option, 'synthetic-secret'])
        self.assert_rejected([*self.args(), '--expect-input-sha256', 'trivy', self.source, '0' * 64])
        for args in [['merge', '--trivy', self.source], ['explain', '--trivy', self.source, '--finding', 'f0001'],
                     ['validate', '--merged', self.source]]:
            self.assert_rejected([*args, '--input-sha256', '0' * 64])
        result = cli('validate-input', '--help')
        self.assertEqual(result.returncode, 0)
        for option in ('--scanner', '--input', '--input-sha256', '--output'):
            self.assertIn(option, result.stdout)

    def test_input_aliases_and_output_io_protection(self):
        raw = b'{"Results":[]}'
        self.source.write_bytes(raw)
        hard, sym = self.base / 'hard', self.base / 'sym'
        hard.hardlink_to(self.source)
        sym.symlink_to(self.source)
        for source in (self.source, hard, sym):
            for dest in (self.source, f'{self.source.parent}/./{self.source.name}', hard, sym):
                result = cli('validate-input', '--scanner', 'trivy', '--input', source, '--output', dest)
                self.assertEqual((result.returncode, result.stdout), (2, ''), result.stderr)
                self.assertEqual(self.source.read_bytes(), raw)
                self.assertNotIn(str(self.base), result.stderr)
        for dest in (self.base, self.base / 'synthetic-secret' / 'output.json'):
            result = cli(*self.args(), '--output', dest)
            self.assertEqual((result.returncode, result.stdout), (2, ''))
            self.assertNotIn('synthetic-secret', result.stderr)
            self.assertEqual(list(self.base.glob('.vulnwrench-fuse-*')), [])

    def test_single_bounded_read_and_validation_order(self):
        from vulnwrench.fuse import core
        raw = b'{"Results":[],"synthetic-secret":"one actual read"}\r\n'
        class Stream(io.BytesIO):
            reads = []
            def read(self, size=-1):
                self.reads.append(size)
                return super().read(size)
        stream = Stream(raw)
        with patch.object(Path, 'open', return_value=stream) as opened:
            result = vf.validate_input('trivy', 'not-opened', expected_sha256=digest(raw))
        opened.assert_called_once_with('rb')
        self.assertEqual(stream.reads, [core.MAX_INPUT_BYTES + 1])
        self.assertEqual(result, summary('trivy', raw, 0, 0))
        for invalid in ('synthetic-secret', False, 1, b'a' * 64, [], {}):
            with patch.object(core, '_read_input') as read:
                with self.assertRaises(vf.InputError):
                    vf.validate_input('trivy', 'not-opened', expected_sha256=invalid)
                read.assert_not_called()
        for scanner in ('synthetic-secret', None, [], {}):
            with patch.object(core, '_read_input') as read:
                with self.assertRaises(vf.InputError):
                    vf.validate_input(scanner, 'not-opened', expected_sha256=digest(raw))
                read.assert_not_called()
        report = vf.Report('trivy', {'Results': []}, 'not-opened', digest(raw), len(raw))
        with patch.object(core, '_read_input', return_value=report) as read, patch.object(core, 'merge_reports') as merge:
            with self.assertRaises(vf.InputError):
                vf.validate_input('trivy', 'not-opened', expected_sha256='0' * 64)
            read.assert_called_once_with('trivy', 'not-opened')
            merge.assert_not_called()


if __name__ == '__main__':
    unittest.main()
