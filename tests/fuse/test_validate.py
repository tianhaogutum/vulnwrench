"""Whole-container validation accepts empty evidence without a selector."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import vulnwrench.fuse as vf
from .test_saved_explain import cli, SAVED, DANGLING


def summary(raw, merged):
    return {
        'schemaVersion': 'vulnfuse-validation-1',
        'validatedSchemaVersion': 'vulnfuse-1',
        'validation': 'internally-consistent',
        'container': {'sha256': hashlib.sha256(raw).hexdigest(),
                      'byteCount': len(raw), 'digestKind': 'file-bytes'},
        'inputCount': merged['inputCount'],
        'findingCount': merged['findingCount'],
        'observationCount': merged['observationCount'],
    }


class ValidateTests(unittest.TestCase):
    def assert_rejected(self, args, output):
        sentinel = b'private sentinel\x00\xff'
        for existing in (True, False):
            if existing:
                output.write_bytes(sentinel)
            else:
                output.unlink()
            result = cli(*args, '--output', output)
            self.assertEqual((result.returncode, result.stdout), (2, ''), result.stderr)
            self.assertTrue(result.stderr.startswith('vulnwrench fuse: '))
            self.assertNotIn('Traceback', result.stderr)
            self.assertNotIn('synthetic-secret', result.stderr)
            self.assertNotIn(str(output), result.stderr)
            if existing:
                self.assertEqual(output.read_bytes(), sentinel)
            else:
                self.assertFalse(output.exists())
        return result

    def test_empty_saved_merge_validates_without_selector(self):
        merged = vf.merge_reports([vf.Report.from_document('trivy', {'Results': []})])
        raw = vf.dumps(merged).encode()
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / 'empty.json'
            source.write_bytes(raw)
            result = cli('validate', '--merged', source,
                         '--merged-sha256', hashlib.sha256(raw).hexdigest())
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, '')
            self.assertEqual(json.loads(result.stdout), summary(raw, merged))
            self.assertEqual((merged['findingCount'], merged['observationCount']), (0, 0))

    def test_exact_container_summary_and_deterministic_private_output(self):
        merged = json.loads(SAVED.read_bytes())
        # Neither reserialization nor a reopened path can supply this metadata.
        variants = [SAVED.read_bytes(),
                    json.dumps(merged, separators=(',', ':')).encode(),
                    SAVED.read_bytes().replace(b'\n', b'\r\n')]
        with tempfile.TemporaryDirectory() as td:
            source, output = Path(td) / 'saved.json', Path(td) / 'summary.json'
            for raw in variants:
                source.write_bytes(raw)
                expected = summary(raw, merged)
                digest = expected['container']['sha256']
                for pin in ([], ['--merged-sha256', digest]):
                    args = ['validate', '--merged', source, *pin]
                    result = cli(*args)
                    self.assertEqual((result.returncode, result.stderr), (0, ''), result.stderr)
                    self.assertEqual(result.stdout, vf.dumps(expected))
                    written = cli(*args, '--output', output)
                    self.assertEqual((written.returncode, written.stdout, written.stderr), (0, '', ''))
                    self.assertEqual(output.read_bytes(), result.stdout.encode())
                    self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                self.assertEqual(vf.validate_merged(source), expected)
                self.assertEqual(vf.validate_merged(source, expected_sha256=digest), expected)

    def test_digest_failures_preserve_output_and_redact_values(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / 'output.json'
            for digest in ['', '0' * 63, 'A' * 64, 'g' * 64, '０' * 64,
                           'a' * 64 + '\n', 'synthetic-secret', '0' * 64]:
                result = self.assert_rejected(
                    ['validate', '--merged', SAVED, '--merged-sha256', digest], output)
                self.assertNotIn(hashlib.sha256(SAVED.read_bytes()).hexdigest(), result.stderr)
                if digest:
                    self.assertNotIn(digest, result.stderr)
                with self.assertRaises(vf.InputError):
                    vf.validate_merged(SAVED, expected_sha256=digest)
            self.assert_rejected(['validate', '--merged', SAVED, '--merged-sha256'], output)

    def test_saved_mode_only_no_selectors_or_scanner_arguments(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / 'output.json'
            for args in [[], ['--merged-sha256', '0' * 64]]:
                self.assert_rejected(['validate', *args], output)
            for option in ['--trivy', '--grype', '--osv', '--coverage-manifest',
                           '--finding', '--advisory', '--package', '--markdown']:
                self.assert_rejected(['validate', '--merged', SAVED, option, 'synthetic-secret'], output)
            help_result = cli('validate', '--help')
            self.assertEqual(help_result.returncode, 0)
            self.assertIn('--merged-sha256', help_result.stdout)

    def test_matching_hash_still_requires_strict_json_and_complete_graph(self):
        broken = json.loads(SAVED.read_bytes())
        broken['findings'][-1]['observations'].clear()
        invalid = [DANGLING.read_bytes(), vf.dumps(broken).encode(),
                   b'{"key":1,"key":2}', b'{"key":NaN}', b'\xff', b'null', b'{',
                   b' ' * (32 * 1024 * 1024 + 1)]
        with tempfile.TemporaryDirectory() as td:
            source, output = Path(td) / 'synthetic-secret.json', Path(td) / 'output.json'
            for raw in invalid:
                source.write_bytes(raw)
                digest = hashlib.sha256(raw).hexdigest()
                self.assert_rejected(['validate', '--merged', source, '--merged-sha256', digest], output)
                with self.assertRaises(vf.InputError):
                    vf.validate_merged(source, expected_sha256=digest)
            source.unlink()
            self.assert_rejected(['validate', '--merged', source], output)
            self.assert_rejected(['validate', '--merged', td], output)

    def test_input_alias_and_output_io_protection(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / 'saved.json'
            source.write_bytes(SAVED.read_bytes())
            hard, sym = Path(td) / 'hard', Path(td) / 'sym'
            hard.hardlink_to(source)
            sym.symlink_to(source)
            for dest in (source, hard, sym):
                failed = cli('validate', '--merged', source, '--output', dest)
                self.assertEqual((failed.returncode, failed.stdout), (2, ''))
                self.assertEqual(source.read_bytes(), SAVED.read_bytes())
            for dest in (Path(td), Path(td) / 'synthetic-secret' / 'out.json'):
                failed = cli('validate', '--merged', source, '--output', dest)
                self.assertEqual((failed.returncode, failed.stdout), (2, ''))
                self.assertNotIn('synthetic-secret', failed.stderr)
                self.assertEqual(list(Path(td).glob('.vulnwrench-fuse-*')), [])

    def test_summary_metadata_comes_from_same_single_validated_read(self):
        from vulnwrench.fuse.core import _read_input
        from vulnwrench.fuse import saved
        report = _read_input('merged', SAVED)
        with patch.object(saved, '_read_input', return_value=report) as read:
            result = vf.validate_merged('not-opened', expected_sha256=report.sha256)
            read.assert_called_once_with('merged', 'not-opened')
            self.assertEqual(result, summary(SAVED.read_bytes(), report.document))
        for invalid in ('synthetic-secret', False, 123, b'a' * 64, [], {}):
            with patch.object(saved, '_read_input') as read:
                with self.assertRaises(vf.InputError):
                    vf.validate_merged('not-opened', expected_sha256=invalid)
                read.assert_not_called()
        with patch.object(saved, '_read_input', return_value=report), patch.object(saved, 'merge_reports') as merge:
            with self.assertRaises(vf.InputError):
                vf.validate_merged('not-opened', expected_sha256='0' * 64)
            merge.assert_not_called()


if __name__ == '__main__':
    unittest.main()
