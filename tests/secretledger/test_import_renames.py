"""Contracts for strict and opt-in mixed git diff --name-status -z bytes."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import vulnwrench.secretledger as secret_ledger
from vulnwrench.secretledger.core import MAX_JSON_BYTES, dumps
from test_ledger import KEY, SECRET, classes, finding

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / 'examples' / 'secrets'


class ImportRenamesTests(unittest.TestCase):
    def test_spaces_unicode_fixture_is_sorted_and_consumable(self):
        raw = (EXAMPLES / 'renames.name-status.z').read_bytes()
        expected = json.loads((EXAMPLES / 'renames-path-map.json').read_text())
        # Importing must not discover renames, resolve paths, or invoke Git.
        with patch('subprocess.Popen', side_effect=AssertionError('no subprocess')):
            mapping = secret_ledger.import_renames(raw)
        self.assertEqual(mapping, expected)
        self.assertEqual(dumps(mapping), (EXAMPLES / 'renames-path-map.json').read_text())
        before = secret_ledger.snapshot([finding(path=e['old_path']) for e in mapping], KEY)
        rows = [finding(path=e['new_path']) for e in mapping]
        result, _ = secret_ledger.compare(before, rows, KEY, path_map=mapping)
        self.assertEqual(classes(result), ['same_secret_moved'] * 2)

    def test_empty_normalized_swaps_and_score_boundaries(self):
        self.assertEqual(secret_ledger.import_renames(b''), [])
        self.assertEqual(secret_ledger.import_renames(
            b'R000\0./b\0a\0R100\0a\0./b\0'),
            [{'old_path': 'a', 'new_path': 'b'}, {'old_path': 'b', 'new_path': 'a'}])

    def test_mixed_records_are_validated_filtered_and_sorted_only_with_opt_in(self):
        raw = ('M\0README.md\0R100\0old name.py\0new name.py\0'
               'A\0凭据 file.py\0R000\0./a\0b\0D\0deleted\0T\0type\0').encode()
        expected = [{'old_path': 'a', 'new_path': 'b'},
                    {'old_path': 'old name.py', 'new_path': 'new name.py'}]
        with self.assertRaises(secret_ledger.LedgerError):
            secret_ledger.import_renames(raw)
        with patch('subprocess.Popen', side_effect=AssertionError('no subprocess')):
            self.assertEqual(secret_ledger.import_renames(raw, allow_non_renames=True), expected)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'mixed.z'
            source.write_bytes(raw)
            self.assertEqual(secret_ledger.load_renames(source, allow_non_renames=True), expected)
            with self.assertRaises(secret_ledger.LedgerError):
                secret_ledger.load_renames(source)

    def test_zero_renames_and_status_looking_paths_have_exact_arities(self):
        for raw in (b'', b'A\0added\0M\0modified\0D\0deleted\0T\0type\0',
                    b'M\0R100\0A\0M\0D\0D\0T\0T\0',
                    b'A\0added\0', b'M\0modified\0', b'D\0deleted\0', b'T\0type\0'):
            with self.subTest(raw=raw):
                self.assertEqual(secret_ledger.import_renames(raw, allow_non_renames=True), [])
                if raw:
                    with self.assertRaises(secret_ledger.LedgerError):
                        secret_ledger.import_renames(raw)
        # Ignored paths may repeat/overlap rename endpoints; they are not mappings.
        self.assertEqual(secret_ledger.import_renames(
            b'M\0old\0A\0new\0M\0./old\0R100\0old\0new\0', allow_non_renames=True),
            [{'old_path': 'old', 'new_path': 'new'}])
        # A status-looking filename in a rename is also consumed as a path.
        self.assertEqual(secret_ledger.import_renames(
            b'R100\0M\0A\0T\0R100\0', allow_non_renames=True),
            [{'old_path': 'M', 'new_path': 'A'}])
        mapping = secret_ledger.import_renames(b'M\0README.md\0', allow_non_renames=True)
        before = secret_ledger.snapshot([finding(path='shared'), finding(path='old')], KEY)
        result, _ = secret_ledger.compare(before, [finding(path='shared'), finding(path='new')],
                                          KEY, path_map=mapping)
        self.assertCountEqual(classes(result), ['unchanged', 'uncomparable', 'uncomparable'])

    def test_opt_in_never_guesses_record_boundaries_or_skips_invalid_paths(self):
        prefix = b'R100\0old\0new\0'
        tails = [b'M\0', b'M\0path', b'R100\0one\0', b'\0', b'M\0ok\0extra\0',
                 b'M\0R100\0old\0new\0',  # Missing M path must not resync to R100.
                 b'R100\0one\0M\0ordinary\0',  # M is the rename target, not a new record.
                 prefix + b'R100\0./old\0other\0', prefix + b'R100\0other\0./new\0']
        for status in (b'C', b'C100', b'U', b'UU', b'AA', b'X', b'B', b'R', b'R99',
                       b'R101', b'R1000', b'R\xef\xbc\x91\xef\xbc\x90\xef\xbc\x90',
                       b'M100', b'A100', b'D100', b'T100', b'm', b' M'):
            tails.append(status + b'\0PRIVATE_MARKER\0R100\0a\0b\0')
        for status in ('A', 'M', 'D', 'T'):
            for path in ('', '.', '..', '../PRIVATE_MARKER', '/PRIVATE_MARKER', 'C:/drive',
                         'archive!file', 'a:b', 'a\nb', 'a\tb', 'a\x7fb', 'a\\b', 'x' * 4097):
                tails.append((status + '\0' + path + '\0').encode())
            tails.extend([status.encode() + b'\0\xffPRIVATE_MARKER\0',
                          status.encode() + b'\0\xed\xa0\x80\0'])
        for tail in tails:
            for raw in (tail, prefix + tail):
                with self.subTest(raw=raw), self.assertRaises(secret_ledger.LedgerError):
                    secret_ledger.import_renames(raw, allow_non_renames=True)

    def test_invalid_framing_encoding_and_nonrename_statuses(self):
        invalid = [b'\0', b'R100', b'R100\0old\0new', b'R100\0old\0',
                   b'R100\0old\0new\0\0', b'R100\told\tnew\n',
                   b'R100\0old\0new\0R100\0incomplete\0',
                   b'R100\0\xff\0new\0', b'R100\0old\0\xed\xa0\x80\0']
        for status in (b'R', b'R1', b'R99', b'R101', b'R1000', b'R-01',
                       b'R+01', b'R1.0', b'r100', b'C100', b'M', b'A', b'D', b'U'):
            invalid.append(status + b'\0old\0new\0')
        # Do not silently extract a partial map from a mixed-status stream.
        invalid.append(b'R100\0old\0new\0M\0another\0')
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(secret_ledger.LedgerError):
                secret_ledger.import_renames(raw)
        with self.assertRaises(secret_ledger.LedgerError):
            secret_ledger.import_renames('R100\0old\0new\0')

    def test_unsafe_paths_and_normalized_duplicate_endpoints(self):
        # Git backslashes are literal filename bytes; never reinterpret as '/'.
        for path in ('', '.', '..', '../escape', '/absolute', 'C:/drive',
                     'archive!file', 'a:b', 'a\nb', 'a\tb', 'a\x7fb',
                     'a\\b', 'x' * 4097):
            for old, new in ((path, 'safe'), ('safe', path)):
                raw = ('R100\0' + old + '\0' + new + '\0').encode()
                with self.subTest(path=path), self.assertRaises(secret_ledger.LedgerError):
                    secret_ledger.import_renames(raw)
        for tail in (b'R100\0./old\0other\0', b'R100\0other\0./new\0',
                     b'R100\0old\0new\0'):
            with self.subTest(tail=tail), self.assertRaisesRegex(secret_ledger.LedgerError, 'bijective'):
                secret_ledger.import_renames(b'R100\0old\0new\0' + tail)

    def test_comparison_still_checks_imported_map_privacy_and_prior_collisions(self):
        for prefix, options in ((b'', {}), (b'M\0README.md\0', {'allow_non_renames': True})):
            mapping = secret_ledger.import_renames(prefix + ('R100\0old\0' + SECRET + '\0').encode(),
                                                   **options)
            with self.assertRaisesRegex(secret_ledger.LedgerError, 'sensitive'):
                secret_ledger.compare(secret_ledger.snapshot([], KEY), [finding()], KEY, path_map=mapping)
            mapping = secret_ledger.import_renames(prefix + b'R100\0old\0new\0', **options)
            before = secret_ledger.snapshot([finding(path='old'), finding(path='new')], KEY)
            with self.assertRaisesRegex(secret_ledger.LedgerError, 'collision'):
                secret_ledger.compare(before, [], KEY, path_map=mapping)


class ImportRenamesCliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / 'names.z'
        self.source.write_bytes((EXAMPLES / 'renames.name-status.z').read_bytes())
        self.output = self.root / 'paths.json'

    def run_cli(self, *args):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'secrets', 'import-renames',
                               '--name-status', str(self.source), *map(str, args)],
                              cwd=ROOT, capture_output=True, text=True, timeout=60)

    def test_file_stdout_and_empty_import_require_no_key(self):
        expected = (EXAMPLES / 'renames-path-map.json').read_text()
        result = self.run_cli('--output', self.output)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))
        self.assertEqual(self.output.read_text(), expected)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        result = self.run_cli()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, ''))
        self.source.write_bytes(b'')
        result = self.run_cli()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '[]\n', ''))

    def test_mixed_cli_opt_in_keeps_strict_default_and_only_emits_renames(self):
        self.source.write_bytes(('M\0README.md\0R100\0old name.py\0new name.py\0'
                                 'A\0凭据.py\0D\0gone\0T\0type\0').encode())
        for args in ((), ('--output', self.output)):
            result = self.run_cli(*args)
            self.assertEqual((result.returncode, result.stdout), (2, ''))
            self.assertFalse(self.output.exists())
        result = self.run_cli('--allow-non-renames')
        expected = dumps([{'old_path': 'old name.py', 'new_path': 'new name.py'}])
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, ''))
        result = self.run_cli('--allow-non-renames', '--output', self.output)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))
        self.assertEqual(self.output.read_text(), expected)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        for raw in (b'', 'M\0R100\0A\0space 凭据.py\0D\0deleted\0T\0type\0'.encode()):
            self.source.write_bytes(raw)
            result = self.run_cli('--allow-non-renames')
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '[]\n', ''))

    def test_mixed_cli_invalid_tail_is_sanitized_and_never_publishes(self):
        tails = [b'M\0', b'M\0PRIVATE_MARKER', b'R100\0PRIVATE_MARKER\0',
                 b'M\0R100\0PRIVATE_MARKER\0other\0', b'M\0safe\0extra\0',
                 b'R100\0./old\0PRIVATE_MARKER\0', b'R100\0PRIVATE_MARKER\0./new\0',
                 b'C100\0PRIVATE_MARKER\0other\0', b'U\0PRIVATE_MARKER\0',
                 b'M100\0PRIVATE_MARKER\0', b'X\0PRIVATE_MARKER\0', b'\0']
        for status in (b'A', b'M', b'D', b'T'):
            for path in (b'', b'../PRIVATE_MARKER', b'a\\PRIVATE_MARKER', b'\xffPRIVATE_MARKER',
                         b'PRIVATE_MARKER\nfile', b'/PRIVATE_MARKER', b'C:/PRIVATE_MARKER'):
                tails.append(status + b'\0' + path + b'\0')
        for tail in tails:
            self.source.write_bytes(b'R100\0old\0new\0' + tail)
            for args in ((), ('--output', self.output)):
                with self.subTest(tail=tail, args=args):
                    result = self.run_cli('--allow-non-renames', *args)
                    self.assertEqual((result.returncode, result.stdout), (2, ''))
                    self.assertTrue(result.stderr.startswith('vulnwrench secrets: '))
                    for private in ('PRIVATE_MARKER', str(self.source), 'Traceback'):
                        self.assertNotIn(private, result.stderr)
                    self.assertEqual(set(self.root.iterdir()), {self.source})

    def test_malformed_input_never_publishes_partial_map_or_values(self):
        for raw in (b'R100\0old\0new\0R101\0PRIVATE_MARKER\0bad\0',
                    b'R100\0PRIVATE_MARKER\0../bad\0',
                    b'R100\0old\0new\0R100\0other\0./new\0',
                    b'R100\0\xffPRIVATE_MARKER\0new\0'):
            self.source.write_bytes(raw)
            for args in ((), ('--output', self.output)):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, '')
                for private in ('PRIVATE_MARKER', str(self.source), '../bad'):
                    self.assertNotIn(private, result.stderr)
                self.assertFalse(self.output.exists())

    def test_input_alias_existing_outputs_and_missing_parent_preserve_inputs(self):
        original = self.source.read_bytes()
        alias = self.root / 'alias'
        alias.symlink_to(self.source)
        self.output.write_text('existing')
        for path in (self.source, alias, self.output, self.root / 'missing' / 'paths.json'):
            result = self.run_cli('--output', path)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, '')
            self.assertEqual(self.source.read_bytes(), original)
            self.assertEqual(self.output.read_text(), 'existing')

    def test_file_limit_nonregular_and_missing_input(self):
        # Sparse file exercises the actual CLI size boundary without a huge fixture.
        with self.source.open('wb') as stream:
            stream.truncate(MAX_JSON_BYTES + 1)
        for setup in ('oversize', 'directory', 'fifo', 'missing'):
            if setup != 'oversize':
                if self.source.is_dir():
                    self.source.rmdir()
                else:
                    self.source.unlink()
                if setup == 'directory':
                    self.source.mkdir()
                elif setup == 'fifo':
                    os.mkfifo(self.source)
            result = self.run_cli('--output', self.output)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, '')
            self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
