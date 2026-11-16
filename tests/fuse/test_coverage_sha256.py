"""Exact manifest expectations bind bytes without trusting their declarations."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import vulnwrench.fuse as vf
from .test_coverage import manifest_document, reports
from .test_saved_explain import cli, SAVED, SELECT


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class CoverageSHA256Tests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.items = []
        for report in reports():
            path = self.base / report.input_name
            path.write_text(vf.dumps(report.document), encoding='utf-8')
            self.items.append(vf.read_report(report.scanner, path))
        self.document = manifest_document(self.items)
        self.raw = vf.dumps(self.document).encode()
        self.manifest = self.base / 'coverage.json'
        self.manifest.write_bytes(self.raw)
        self.scanners = [value for r in self.items for value in ('--' + r.scanner, r.input_name)]
        self.output, self.markdown = self.base / 'output.json', self.base / 'output.md'

    def args(self, mode='merge'):
        return [mode, *self.scanners, '--coverage-manifest', self.manifest,
                *(['--advisory', 'CVE-SYN'] if mode == 'explain' else [])]

    def assert_rejected(self, args, *, markdown=False):
        paths = [self.output, *([self.markdown] if markdown else [])]
        sentinel = b'private sentinel\x00\xff'
        for exists in (True, False):
            for path in paths:
                if exists:
                    path.write_bytes(sentinel)
                else:
                    path.unlink()
            failed = cli(*args, '--output', self.output,
                         *(['--markdown', self.markdown] if markdown else []))
            self.assertEqual((failed.returncode, failed.stdout), (2, ''), failed.stderr)
            self.assertTrue(failed.stderr.startswith('vulnwrench fuse: '))
            for value in ('Traceback', 'synthetic-secret', str(self.output), str(self.manifest),
                          digest(self.raw)):
                self.assertNotIn(value, failed.stderr)
            for path in paths:
                if exists:
                    self.assertEqual(path.read_bytes(), sentinel)
                else:
                    self.assertFalse(path.exists())
        return failed

    def test_matching_manifest_digest_keeps_merge_and_explanation_bytes(self):
        for mode in ('merge', 'explain'):
            args = self.args(mode)
            unpinned = cli(*args)
            pinned = cli(*args, '--coverage-manifest-sha256', digest(self.raw))
            self.assertEqual((unpinned.returncode, unpinned.stderr), (0, ''))
            self.assertEqual((pinned.returncode, pinned.stderr), (0, ''), pinned.stderr)
            self.assertEqual(pinned.stdout, unpinned.stdout)
            written = cli(*args, '--coverage-manifest-sha256', digest(self.raw), '--output', self.output,
                          *(['--markdown', self.markdown] if mode == 'merge' else []))
            self.assertEqual((written.returncode, written.stdout, written.stderr), (0, '', ''))
            self.assertEqual(self.output.read_bytes(), pinned.stdout.encode())
            self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
            merged = json.loads(pinned.stdout)
            if mode == 'merge':
                self.assertEqual((merged['findingCount'], merged['observationCount']), (1, 1))
                self.assertEqual(self.markdown.read_text(), vf.render_markdown(merged))
                self.assertFalse(next(iter(merged['findings'][0]['absenceAssessments'].values()))['canEstablishFixed'])
        self.assertEqual(vf.read_coverage_manifest(self.manifest, expected_sha256=digest(self.raw)),
                         vf.read_coverage_manifest(self.manifest))

    def test_invalid_expectations_and_mismatch_preserve_both_outputs(self):
        for expected in ['', 'a' * 63, 'a' * 65, 'A' * 64, 'g' * 64, '０' * 64,
                         'a' * 64 + '\n', ' ' + 'a' * 64, 'sha256:' + 'a' * 64,
                         'synthetic-secret', '0' * 64]:
            for mode in ('merge', 'explain'):
                self.assert_rejected([*self.args(mode), '--coverage-manifest-sha256', expected],
                                     markdown=mode == 'merge')
            with self.assertRaises(vf.InputError):
                vf.read_coverage_manifest(self.manifest, expected_sha256=expected)
        self.assert_rejected([*self.args(), '--coverage-manifest-sha256'], markdown=True)

    def test_digest_requires_manifest_and_scanner_mode(self):
        for args in [
            ['merge', *self.scanners],
            ['explain', *self.scanners, '--advisory', 'CVE-SYN'],
            ['explain', '--merged', SAVED, *SELECT],
            ['explain', '--merged', SAVED, *SELECT, '--coverage-manifest', self.manifest],
            ['validate', '--merged', SAVED],
            ['validate', '--merged', SAVED, '--coverage-manifest', self.manifest],
        ]:
            self.assert_rejected([*args, '--coverage-manifest-sha256', digest(self.raw)])

    def test_rewrites_and_formatting_require_their_own_digest(self):
        changed = deepcopy(self.document)
        changed['inputs'][1]['targetIdentity'] = 'synthetic-secret-different-target'
        variants = [vf.dumps(changed).encode(), json.dumps(self.document, separators=(',', ':')).encode(),
                    self.raw.replace(b'\n', b'\r\n'),
                    json.dumps(dict(reversed(list(self.document.items()))), indent=2).encode()]
        for raw in variants:
            self.manifest.write_bytes(raw)
            self.assertNotEqual(digest(raw), digest(self.raw))
            unpinned = cli(*self.args())
            self.assertEqual(unpinned.returncode, 0, unpinned.stderr)
            self.assert_rejected([*self.args(), '--coverage-manifest-sha256', digest(self.raw)], markdown=True)
            pinned = cli(*self.args(), '--coverage-manifest-sha256', digest(raw))
            self.assertEqual((pinned.returncode, pinned.stderr), (0, ''))
            self.assertEqual(pinned.stdout, unpinned.stdout)
            provenance = json.loads(pinned.stdout)['coverageManifest']
            self.assertEqual((provenance['sha256'], provenance['byteCount']), (digest(raw), len(raw)))
        self.manifest.write_text(vf.dumps(changed))
        rewritten = vf.merge_reports(self.items, coverage_manifest=vf.read_coverage_manifest(self.manifest))
        self.assertEqual(rewritten['coverageAssessment']['reasonCodes'], ['target-mismatch'])

    def test_matching_hash_still_requires_strict_json_schema_and_binding(self):
        stale = deepcopy(self.document)
        stale['inputs'][0]['sha256'] = '0' * 64
        malformed = deepcopy(self.document)
        malformed['inputs'][0]['scanComplete'] = 1
        invalid = [vf.dumps(stale).encode(), vf.dumps(malformed).encode(), b'{}', b'null',
                   b'{"key":1,"key":2}', b'{"key":NaN}', b'\xff', b'{',
                   b' ' * (32 * 1024 * 1024 + 1)]
        for raw in invalid:
            self.manifest.write_bytes(raw)
            self.assert_rejected([*self.args(), '--coverage-manifest-sha256', digest(raw)], markdown=True)
        self.manifest.unlink()
        self.assert_rejected([*self.args(), '--coverage-manifest-sha256', digest(self.raw)], markdown=True)

    def test_input_and_manifest_aliases_protected_with_matching_digest(self):
        for source in [self.manifest, *(Path(r.input_name) for r in self.items)]:
            raw = source.read_bytes()
            hard, sym = self.base / 'hard', self.base / 'sym'
            hard.hardlink_to(source)
            sym.symlink_to(source)
            for dest in (source, hard, sym):
                for flag in ('--output', '--markdown'):
                    failed = cli(*self.args(), '--coverage-manifest-sha256', digest(self.raw), flag, dest)
                    self.assertEqual((failed.returncode, failed.stdout), (2, ''))
                    self.assertEqual(source.read_bytes(), raw)
            hard.unlink()
            sym.unlink()

    def test_single_bounded_read_and_syntax_validation_before_io(self):
        from vulnwrench.fuse import core
        report = core._read_input('coverage', self.manifest)
        with patch.object(core, '_read_input', return_value=report) as read:
            manifest = vf.read_coverage_manifest('not-opened', expected_sha256=report.sha256)
            read.assert_called_once_with('coverage', 'not-opened')
            self.assertEqual((manifest.document, manifest.sha256, manifest.byte_count),
                             (self.document, digest(self.raw), len(self.raw)))
        for expected in ('synthetic-secret', False, 1, b'a' * 64, [], {}):
            with patch.object(core, '_read_input') as read:
                with self.assertRaises(vf.InputError):
                    vf.read_coverage_manifest('not-opened', expected_sha256=expected)
                read.assert_not_called()
        with patch.object(core, '_read_input', return_value=report) as read:
            with self.assertRaisesRegex(vf.InputError, 'SHA-256 mismatch'):
                vf.read_coverage_manifest('not-opened', expected_sha256='0' * 64)
            read.assert_called_once()


if __name__ == '__main__':
    unittest.main()
