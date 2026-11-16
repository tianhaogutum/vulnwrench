"""Caller expectations bind saved container bytes, independently of graph validity."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import vulnwrench.fuse as vf
from .test_saved_explain import cli, ROOT, SAVED, DANGLING, SELECT


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class MergedSHA256Tests(unittest.TestCase):
    def assert_rejected(self, args, output):
        output.write_bytes(b'private sentinel\x00\xff')
        failed = cli(*args, '--output', output)
        self.assertEqual(failed.returncode, 2, failed.stderr)
        self.assertEqual(failed.stdout, '')
        self.assertEqual(output.read_bytes(), b'private sentinel\x00\xff')
        self.assertNotIn('Traceback', failed.stderr)
        self.assertNotIn('synthetic-secret', failed.stderr)
        self.assertNotIn(str(output), failed.stderr)
        # The same failure must not create an output that did not exist.
        output.unlink()
        absent = cli(*args, '--output', output)
        self.assertEqual(absent.returncode, 2, absent.stderr)
        self.assertEqual(absent.stdout, '')
        self.assertFalse(output.exists())
        return failed

    def test_matching_digest_keeps_exact_explanation_and_selectors(self):
        expected = (ROOT / 'examples/fuse/expected/explanation.json').read_text()
        digest = sha256(SAVED)
        selectors = [SELECT, ['--finding', json.loads(expected)['finding']['findingId']]]
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / 'output.json'
            for selector in selectors:
                args = ['explain', '--merged', SAVED, *selector]
                unpinned = cli(*args)
                pinned = cli(*args, '--merged-sha256', digest)
                self.assertEqual(unpinned.returncode, 0, unpinned.stderr)
                self.assertEqual(pinned.returncode, 0, pinned.stderr)
                self.assertEqual(pinned.stderr, '')
                self.assertEqual(pinned.stdout, expected)
                self.assertEqual(pinned.stdout, unpinned.stdout)
                written = cli(*args, '--merged-sha256', digest, '--output', output)
                self.assertEqual(written.returncode, 0, written.stderr)
                self.assertEqual(written.stdout, '')
                self.assertEqual(output.read_text(), expected)
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(vf.read_merged(SAVED, expected_sha256=digest), vf.read_merged(SAVED))

    def test_malformed_and_missing_digest_values_are_sanitized(self):
        invalid = ['', '0' * 63, '0' * 65, 'A' * 64, 'g' * 64, '０' * 64,
                   'a' * 63 + '\n', ' ' + 'a' * 64, 'a' * 64 + ' ',
                   'sha256:' + 'a' * 64, 'synthetic-secret-digest']
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / 'output.json'
            for digest in invalid:
                with self.subTest(digest=repr(digest)):
                    failed = self.assert_rejected(
                        ['explain', '--merged', SAVED, *SELECT, '--merged-sha256', digest], output)
                    self.assertIn('expected SHA-256', failed.stderr)
                    with self.assertRaises(vf.InputError):
                        vf.read_merged(SAVED, expected_sha256=digest)
            # Missing operand, including when another option follows it.
            self.assert_rejected(['explain', '--merged', SAVED, *SELECT, '--merged-sha256'], output)
            missing = cli('explain', '--merged', SAVED, *SELECT, '--merged-sha256')
            self.assertEqual((missing.returncode, missing.stdout), (2, ''))
            for digest in [False, 123, b'a' * 64, [], {}]:
                with self.subTest(library_type=type(digest).__name__), self.assertRaises(vf.InputError):
                    vf.read_merged(SAVED, expected_sha256=digest)

    def test_mismatch_precedes_selection_and_preserves_output(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / 'synthetic-secret-saved.json'
            source.write_bytes(SAVED.read_bytes())
            failed = self.assert_rejected(
                ['explain', '--merged', source, '--merged-sha256', '0' * 64, '--finding', 'missing'],
                Path(td) / 'output.json')
            self.assertIn('SHA-256 mismatch', failed.stderr)
            self.assertNotIn('no finding', failed.stderr)
            self.assertNotIn('0' * 64, failed.stderr)
            self.assertNotIn(sha256(source), failed.stderr)
            with self.assertRaisesRegex(vf.InputError, 'SHA-256 mismatch'):
                vf.read_merged(source, expected_sha256='0' * 64)

    def test_digest_option_requires_saved_mode(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / 'output.json'
            for args in [
                ['explain', '--trivy', 'examples/fuse/trivy.json', '--advisory', 'CVE-2025-0001'],
                ['explain', '--finding', 'f0001'],
                ['merge', '--trivy', 'examples/fuse/trivy.json'],
                ['explain', '--merged', SAVED, *SELECT, '--trivy', 'examples/fuse/trivy.json'],
                ['explain', '--merged', SAVED, *SELECT, '--coverage-manifest', 'examples/fuse/coverage.json'],
            ]:
                with self.subTest(args=args):
                    self.assert_rejected([*args, '--merged-sha256', sha256(SAVED)], output)

    def test_self_consistent_rewrite_needs_new_expectation(self):
        original = vf.read_merged(SAVED)
        reports = []
        for source in original['inputs']:
            document = source['rawReport']
            # Rebuild changed evidence and all derived summaries/provenance.
            document['synthetic-secret-extension'] = 'changed evidence'
            if source['scanner'] == 'trivy':
                document['Results'][0]['Vulnerabilities'][0]['Severity'] = 'NEGLIGIBLE'
                document['Results'][0]['Vulnerabilities'][0]['FixedVersion'] = '7.7'
            reports.append(vf.Report.from_document(source['scanner'], document, source['input']))
        rewritten = vf.merge_reports(reports)
        self.assertNotEqual(rewritten, original)
        with tempfile.TemporaryDirectory() as td:
            source, output = Path(td) / 'rewritten.json', Path(td) / 'output.json'
            source.write_text(vf.dumps(rewritten))
            self.assertEqual(vf.read_merged(source), rewritten)
            args = ['explain', '--merged', source, *SELECT]
            unpinned = cli(*args)
            self.assertEqual(unpinned.returncode, 0, unpinned.stderr)
            finding = json.loads(unpinned.stdout)['finding']
            self.assertIn('NEGLIGIBLE', finding['severityValues'])
            self.assertIn('7.7', finding['fixVersions'])
            self.assert_rejected([*args, '--merged-sha256', sha256(SAVED)], output)
            pinned = cli(*args, '--merged-sha256', sha256(source))
            self.assertEqual(pinned.returncode, 0, pinned.stderr)
            self.assertEqual(pinned.stdout, unpinned.stdout)

    def test_formatting_changes_require_their_own_byte_digest(self):
        document = json.loads(SAVED.read_bytes())
        variants = [json.dumps(document, separators=(',', ':')).encode(),
                    SAVED.read_bytes().replace(b'\n', b'\r\n'),
                    json.dumps(dict(reversed(list(document.items()))), indent=2).encode() + b'\n']
        with tempfile.TemporaryDirectory() as td:
            source, output = Path(td) / 'formatted.json', Path(td) / 'output.json'
            for raw in variants:
                with self.subTest(digest=hashlib.sha256(raw).hexdigest()):
                    source.write_bytes(raw)
                    self.assertNotEqual(sha256(source), sha256(SAVED))
                    self.assertEqual(vf.read_merged(source), document)
                    args = ['explain', '--merged', source, *SELECT]
                    self.assert_rejected([*args, '--merged-sha256', sha256(SAVED)], output)
                    pinned = cli(*args, '--merged-sha256', sha256(source))
                    self.assertEqual(pinned.returncode, 0, pinned.stderr)
                    self.assertEqual(pinned.stdout, (ROOT / 'examples/fuse/expected/explanation.json').read_text())

    def test_matching_digest_still_requires_valid_input_and_full_graph(self):
        invalid = [DANGLING.read_bytes(), b'{"key":1,"key":2}', b'\xff', b'null', b'{',
                   b' ' * (32 * 1024 * 1024 + 1)]
        with tempfile.TemporaryDirectory() as td:
            source, output = Path(td) / 'synthetic-secret-invalid.json', Path(td) / 'output.json'
            for raw in invalid:
                source.write_bytes(raw)
                digest = sha256(source)
                self.assert_rejected(['explain', '--merged', source, '--merged-sha256', digest,
                                      '--finding', 'missing'], output)
                with self.assertRaises(vf.InputError):
                    vf.read_merged(source, expected_sha256=digest)
            source.unlink()
            self.assert_rejected(['explain', '--merged', source, *SELECT, '--merged-sha256', '0' * 64], output)
            # A valid byte expectation still cannot authorize input replacement.
            source.write_bytes(SAVED.read_bytes())
            hard, sym = Path(td) / 'hard', Path(td) / 'sym'
            hard.hardlink_to(source)
            sym.symlink_to(source)
            for destination in (source, hard, sym):
                result = cli('explain', '--merged', source, *SELECT, '--merged-sha256', sha256(source),
                             '--output', destination)
                self.assertEqual((result.returncode, result.stdout), (2, ''))
                self.assertEqual(source.read_bytes(), SAVED.read_bytes())

    def test_one_read_for_digest_and_document_and_validation_order(self):
        from vulnwrench.fuse.core import _read_input
        from vulnwrench.fuse import saved
        report = _read_input('merged', SAVED)
        with patch.object(saved, '_read_input', return_value=report) as read:
            restored = vf.read_merged('not-opened', expected_sha256=report.sha256)
            read.assert_called_once_with('merged', 'not-opened')
            self.assertEqual(restored, report.document)
        with patch.object(saved, '_read_input') as read:
            with self.assertRaises(vf.InputError):
                vf.read_merged('not-opened', expected_sha256='synthetic-secret')
            read.assert_not_called()
        with patch.object(saved, '_read_input', return_value=report), patch.object(saved, 'merge_reports') as merge:
            with self.assertRaises(vf.InputError):
                vf.read_merged('not-opened', expected_sha256='0' * 64)
            merge.assert_not_called()


if __name__ == '__main__':
    unittest.main()
