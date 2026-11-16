"""Optional exact scanner-byte expectations; declarations never imply trust."""

from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import vulnwrench.fuse as vf
from .test_coverage import manifest_document, reports
from .test_saved_explain import cli, ROOT, SAVED, SELECT


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class InputSHA256Tests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.items = []
        for report in [*reports(), vf.Report.from_document('osv', {'results': []}, 'osv.json')]:
            path = self.base / report.input_name
            path.write_text(vf.dumps(report.document), encoding='utf-8')
            self.items.append(vf.read_report(report.scanner, path))
        self.scanners = [v for r in self.items for v in ('--' + r.scanner, r.input_name)]
        self.pins = [v for r in self.items for v in
                     ('--expect-input-sha256', r.scanner, r.input_name, r.sha256)]
        self.output, self.markdown = self.base / 'output.json', self.base / 'output.md'

    def args(self, mode='merge'):
        return [mode, *self.scanners, *(['--advisory', 'CVE-SYN'] if mode == 'explain' else [])]

    def assert_rejected(self, args, *, markdown=False):
        paths = [self.output, *([self.markdown] if markdown else [])]
        sentinel = b'private sentinel\x00\xff'
        for exists in (True, False):
            for path in paths:
                if exists:
                    path.write_bytes(sentinel)
                elif path.exists():
                    path.unlink()
            failed = cli(*args, '--output', self.output,
                         *(['--markdown', self.markdown] if markdown else []))
            self.assertEqual((failed.returncode, failed.stdout), (2, ''), failed.stderr)
            self.assertTrue(failed.stderr.startswith('vulnwrench fuse: '))
            for value in ('Traceback', 'synthetic-secret', str(self.base), '0' * 64,
                          *(r.sha256 for r in self.items)):
                self.assertNotIn(value, failed.stderr)
            for path in paths:
                if exists:
                    self.assertEqual(path.read_bytes(), sentinel)
                else:
                    self.assertFalse(path.exists())
        return failed

    def test_matching_and_partial_expectations_keep_merge_and_explanation_bytes(self):
        for mode in ('merge', 'explain'):
            unpinned = cli(*self.args(mode))
            self.assertEqual((unpinned.returncode, unpinned.stderr), (0, ''))
            for pins in (self.pins, self.pins[:4]):
                pinned = cli(*self.args(mode), *pins)
                self.assertEqual((pinned.returncode, pinned.stderr), (0, ''), pinned.stderr)
                self.assertEqual(pinned.stdout, unpinned.stdout)
            written = cli(*self.args(mode), *self.pins, '--output', self.output,
                          *(['--markdown', self.markdown] if mode == 'merge' else []))
            self.assertEqual((written.returncode, written.stdout, written.stderr), (0, '', ''))
            self.assertEqual(self.output.read_bytes(), unpinned.stdout.encode())
            self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
            if mode == 'merge':
                merged = json.loads(pinned.stdout)
                self.assertEqual((merged['inputCount'], merged['observationCount'], merged['findingCount']), (3, 1, 1))
                self.assertEqual(self.markdown.read_text(), vf.render_markdown(merged))
                self.assertIsNone(merged['coverageManifest'])
                self.assertEqual(merged['coverageAssessment']['status'], 'unknown')
                self.assertTrue(all(not a['canEstablishFixed'] for a in merged['findings'][0]['absenceAssessments'].values()))
            else:
                self.assertEqual(json.loads(pinned.stdout)['remediationAssessment'], 'not-evaluated')
        for report in self.items:
            self.assertEqual(vf.read_report(report.scanner, report.input_name, expected_sha256=report.sha256), report)
            self.assertEqual(vf.read_report(report.scanner, report.input_name, expected_sha256=None), report)

    def test_repeated_report_key_uses_one_expectation_retains_every_observation(self):
        report = self.items[0]
        repeat = ['--' + report.scanner, report.input_name]
        for mode in ('merge', 'explain'):
            plain = cli(*self.args(mode), *repeat)
            pinned = cli(*self.args(mode), *repeat, *self.pins)
            self.assertEqual((pinned.returncode, pinned.stderr), (0, ''), pinned.stderr)
            self.assertEqual(pinned.stdout, plain.stdout)
            result = json.loads(pinned.stdout)
            self.assertEqual(result['observationCount'] if mode == 'merge' else result['finding']['observationCount'], 2)
            if mode == 'merge':
                self.assertEqual(result['inputCount'], 4)
                self.assertEqual(len({o['observationId'] for o in result['findings'][0]['observations']}), 2)
        reverse = cli('merge', *sum((['--' + r.scanner, r.input_name] for r in reversed(self.items)), []),
                      *sum((['--expect-input-sha256', r.scanner, r.input_name, r.sha256]
                            for r in reversed(self.items)), []), *repeat)
        self.assertEqual(reverse.stdout, cli(*self.args(), *repeat, *self.pins).stdout)

    def test_malformed_mismatched_duplicate_and_unused_expectations_preserve_outputs(self):
        report = self.items[0]
        for expected in ['', 'a' * 63, 'a' * 65, 'A' * 64, 'g' * 64, '０' * 64,
                         'a' * 64 + '\n', ' ' + 'a' * 64, 'a' * 64 + ' ',
                         'sha256:' + 'a' * 64, 'synthetic-secret', '0' * 64]:
            for mode in ('merge', 'explain'):
                self.assert_rejected([*self.args(mode), '--expect-input-sha256', report.scanner,
                                      report.input_name, expected], markdown=mode == 'merge')
            with self.assertRaises(vf.InputError) as raised:
                vf.read_report(report.scanner, report.input_name, expected_sha256=expected)
            if expected:
                self.assertNotIn(expected, str(raised.exception))
        invalid = [
            ['--expect-input-sha256', 'synthetic-secret', report.input_name, report.sha256],
            ['--expect-input-sha256', report.scanner.upper(), report.input_name, report.sha256],
            ['--expect-input-sha256', 'osv', report.input_name, report.sha256],
            ['--expect-input-sha256', report.scanner, str(self.base / 'synthetic-secret'), report.sha256],
            [*self.pins[:4], *self.pins[:4]],
            [*self.pins[:4], '--expect-input-sha256', report.scanner, report.input_name, '0' * 64],
            ['--expect-input-sha256'], ['--expect-input-sha256', report.scanner],
            ['--expect-input-sha256', report.scanner, report.input_name],
        ]
        for extra in invalid:
            for mode in ('merge', 'explain'):
                self.assert_rejected([*self.args(mode), *extra], markdown=mode == 'merge')
        # Different path spellings refer to the same bytes but are different keys.
        relative, explicit = 'examples/fuse/trivy.json', './examples/trivy.json'
        sha = digest((ROOT / relative).read_bytes())
        self.assert_rejected(['merge', '--trivy', relative, '--expect-input-sha256', 'trivy', explicit, sha], markdown=True)
        both = cli('merge', '--trivy', relative, '--trivy', explicit,
                   '--expect-input-sha256', 'trivy', explicit, sha,
                   '--expect-input-sha256', 'trivy', relative, sha)
        self.assertEqual(both.returncode, 0, both.stderr)
        self.assertEqual({s['input'] for s in json.loads(both.stdout)['inputs']}, {relative, explicit})

    def test_saved_modes_and_missing_scanner_inputs_reject_expectations(self):
        for args in [
            ['explain', '--merged', SAVED, *SELECT],
            ['explain', '--merged', SAVED, *SELECT, *self.scanners],
            ['validate', '--merged', SAVED], ['merge'], ['explain', '--finding', 'f0001'],
        ]:
            self.assert_rejected([*args, *self.pins])

    def test_rewrites_and_formatting_require_own_digest(self):
        report = self.items[0]
        path = Path(report.input_name)
        original = path.read_bytes()
        rewritten = deepcopy(report.document)
        rewritten['synthetic-secret-extra'] = 'retained raw evidence'
        for raw in [json.dumps(report.document, separators=(',', ':')).encode(),
                    original.replace(b'\n', b'\r\n'),
                    json.dumps(dict(reversed(list(report.document.items())))).encode(),
                    vf.dumps(rewritten).encode()]:
            self.assertNotEqual(digest(raw), report.sha256)
            path.write_bytes(raw)
            self.assert_rejected([*self.args(), *self.pins], markdown=True)
            pinned = cli(*self.args(), '--expect-input-sha256', report.scanner, path, digest(raw))
            self.assertEqual(pinned.returncode, 0, pinned.stderr)
            self.assertEqual(pinned.stdout, cli(*self.args()).stdout)
            source = next(s for s in json.loads(pinned.stdout)['inputs'] if s['scanner'] == report.scanner)
            self.assertEqual((source['sha256'], source['byteCount'], source['rawReport']),
                             (digest(raw), len(raw), json.loads(raw)))

    def test_matching_hash_still_requires_full_scanner_profiles_and_strict_json(self):
        invalid = {
            'trivy': [b'{}', b'null', b'{"Results":[],"matches":[]}',
                      b'{"Results":[{"Vulnerabilities":[{"VulnerabilityID":123}]}]}'],
            'grype': [b'{"matches":{}}', b'{"matches":[{}]}'],
            'osv': [b'{"results":[{}]}', b'{"results":[{"packages":[{}]}]}'],
        }
        for scanner, raws in invalid.items():
            for raw in raws:
                path = self.base / ('synthetic-secret-' + scanner)
                path.write_bytes(raw)
                for mode in ('merge', 'explain'):
                    self.assert_rejected([*self.args(mode), '--' + scanner, path,
                                          '--expect-input-sha256', scanner, path, digest(raw)], markdown=mode == 'merge')
                with self.assertRaises(vf.InputError):
                    vf.merge_reports([vf.read_report(scanner, path, expected_sha256=digest(raw))])
        path = Path(self.items[0].input_name)
        for raw in [b'{"Results":[],"Results":[]}', b'{"Results":[],"x":NaN}',
                    b'{"Results":[],"x":1e9999}', b'\xff', b'{', b' ' * (32 * 1024 * 1024 + 1)]:
            path.write_bytes(raw)
            self.assert_rejected(['merge', '--trivy', path, '--expect-input-sha256', 'trivy', path, digest(raw)], markdown=True)
            with self.assertRaises(vf.InputError):
                vf.read_report('trivy', path, expected_sha256=digest(raw))
        path.unlink()
        self.assert_rejected([*self.args(), *self.pins], markdown=True)

    def test_input_pins_do_not_bypass_coverage_bindings_or_manifest_expectation(self):
        manifest = self.base / 'coverage.json'
        document = manifest_document(self.items)
        manifest.write_text(vf.dumps(document))
        args = [*self.args(), *self.pins, '--coverage-manifest', manifest]
        matching = cli(*args, '--coverage-manifest-sha256', digest(manifest.read_bytes()))
        self.assertEqual(matching.returncode, 0, matching.stderr)
        self.assertEqual(matching.stdout, cli(*self.args(), '--coverage-manifest', manifest).stdout)
        self.assert_rejected([*args, '--coverage-manifest-sha256', '0' * 64], markdown=True)
        for change in ('digest', 'name', 'declaration'):
            stale = deepcopy(document)
            stale['inputs'][0].update({'digest': {'sha256': '0' * 64},
                                      'name': {'input': './' + self.items[0].input_name},
                                      'declaration': {'scanComplete': 1}}[change])
            manifest.write_text(vf.dumps(stale))
            self.assert_rejected([*args, '--coverage-manifest-sha256', digest(manifest.read_bytes())], markdown=True)

    def test_all_input_and_manifest_output_aliases_protected(self):
        manifest = self.base / 'coverage.json'
        manifest.write_text(vf.dumps(manifest_document(self.items)))
        args = [*self.args(), *self.pins, '--coverage-manifest', manifest,
                '--coverage-manifest-sha256', digest(manifest.read_bytes())]
        for source in [manifest, *(Path(r.input_name) for r in self.items)]:
            raw = source.read_bytes()
            hard, sym = self.base / 'hard', self.base / 'sym'
            hard.hardlink_to(source)
            sym.symlink_to(source)
            for dest in (source, f'{source.parent}/./{source.name}', hard, sym):
                for flag in ('--output', '--markdown'):
                    failed = cli(*args, flag, dest)
                    self.assertEqual((failed.returncode, failed.stdout), (2, ''), failed.stderr)
                    self.assertEqual(source.read_bytes(), raw)
                    self.assertNotIn(str(source), failed.stderr)
            hard.unlink()
            sym.unlink()

    def test_single_bounded_read_and_validation_before_io(self):
        from vulnwrench.fuse import core
        report = self.items[0]
        raw = Path(report.input_name).read_bytes()
        # The digest and decoded object must both come from the one actual read.
        class Stream(io.BytesIO):
            reads = []
            def read(self, size=-1):
                self.reads.append(size)
                return super().read(size)
        stream = Stream(raw)
        with patch.object(Path, 'open', return_value=stream) as opened:
            result = vf.read_report(report.scanner, 'not-opened', expected_sha256=digest(raw))
        opened.assert_called_once_with('rb')
        self.assertEqual(stream.reads, [core.MAX_INPUT_BYTES + 1])
        self.assertEqual((result.document, result.sha256, result.byte_count, result.digest_kind),
                         (report.document, digest(raw), len(raw), 'file-bytes'))
        for expected in ('synthetic-secret', False, 1, b'a' * 64, [], {}):
            with patch.object(core, '_read_input') as read:
                with self.assertRaises(vf.InputError):
                    vf.read_report(report.scanner, 'not-opened', expected_sha256=expected)
                read.assert_not_called()
        with patch.object(core, '_read_input') as read:
            with self.assertRaises(vf.InputError):
                vf.read_report('synthetic-secret', 'not-opened', expected_sha256=digest(raw))
            read.assert_not_called()
        with patch.object(core, '_read_input', return_value=report) as read:
            with self.assertRaisesRegex(vf.InputError, 'SHA-256 mismatch'):
                vf.read_report(report.scanner, 'not-opened', expected_sha256='0' * 64)
            read.assert_called_once_with(report.scanner, 'not-opened')


if __name__ == '__main__':
    unittest.main()
