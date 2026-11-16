"""External raw-plan pin on report-only verification; no additional input trust."""
from copy import deepcopy
from hashlib import sha256
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_verify_cleanup_inputs as support


class VerifyCleanupReportPinTests(unittest.TestCase):
    run_cli = support.VerifyCleanupInputsTests.run_cli
    fixture = support.VerifyCleanupInputsTests.fixture

    def report_fixture(self, *args, **kwargs):
        files, data = self.fixture(*args, **kwargs)
        # Bound inputs are deliberately unavailable to report-only verification.
        for key in set(files) - {'plan', 'report'}:
            files.pop(key).unlink()
        return files, data

    def expected(self, files):
        return {'command': 'verify-cleanup-report', 'reportVerified': True,
                'reportSha256': sha256(files['report'].read_bytes()).hexdigest(), 'automaticChangesAllowed': False}

    def verify(self, files, pin=None, output=None):
        args = [v for k, p in files.items() for v in ('--' + k, p)]
        if pin is not None: args += ['--expected-plan-sha256', pin]
        if output is not None: args += ['--output', output]
        return self.run_cli('verify-cleanup-report', *args)

    def failure(self, files, pin, output):
        before = {p: p.read_bytes() for p in [*files.values(), output] if p.is_file()}
        proc = self.verify(files, pin, output)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(proc.stdout, '')
        self.assertTrue(proc.stderr.startswith('vulnwrench ignores: '), proc.stderr)
        for secret in ('PRIVATE', str(output.parent), 'Traceback'):
            self.assertNotIn(secret, proc.stderr)
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        self.assertEqual(list(output.parent.glob('.vulnwrench-ignores-*')), [])
        return proc

    def test_valid_pin_default_empty_and_unavailable_bound_inputs_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            for format in ('trivy', 'osv'):
                for metadata, aliases in ((False, False), (True, False), (False, True), (True, True)):
                    for empty in (False, True):
                        with self.subTest(format=format, metadata=metadata, aliases=aliases, empty=empty):
                            files, data = self.report_fixture(tmp, format, metadata, aliases, empty, incomplete=format == 'osv')
                            if format == 'osv':
                                self.assertEqual(data['coverage'], 'unknown')
                                self.assertEqual(data['groups']['report_local_orphans'], [])
                            before = {p: p.read_bytes() for p in files.values()}
                            expected = self.expected(files)
                            default = self.verify(files)
                            self.assertEqual(default.returncode, 0, default.stderr)
                            self.assertEqual(default.stdout, json.dumps(expected, indent=2, sort_keys=True) + '\n')
                            pin = sha256(before[files['plan']]).hexdigest()
                            proc = self.verify(files, pin)
                            self.assertEqual(proc.returncode, 0, proc.stderr)
                            self.assertEqual(proc.stderr, '')
                            self.assertEqual(proc.stdout, json.dumps({**expected, 'planSha256': pin}, indent=2, sort_keys=True) + '\n')
                            self.assertEqual(before, {p: p.read_bytes() for p in before})
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            proc = self.verify(files, pin, output)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout + proc.stderr, '')
            self.assertEqual(output.read_text(), json.dumps({**expected, 'planSha256': pin}, indent=2, sort_keys=True) + '\n')

    def test_raw_whitespace_context_and_manual_suggestion_edits_need_new_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            files, base = self.report_fixture(tmp, metadata=True, aliases=True)
            original = files['plan'].read_bytes(); pin = sha256(original).hexdigest()
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            context = deepcopy(base); context.update(asOf='PRIVATE-context', summary={'findingCount': -1}, coverage='PRIVATE-context')
            suggestion = deepcopy(base); suggestion['groups']['ownerless'][0]['suggestedManualAction'] = 'PRIVATE-suggestion'
            for raw in (original + b' ', json.dumps(context).encode(), json.dumps(suggestion).encode()):
                files['plan'].write_bytes(raw)
                self.assertEqual(self.verify(files).returncode, 0)
                self.failure(files, pin, output)
                proc = self.verify(files, sha256(raw).hexdigest())
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertFalse(json.loads(proc.stdout)['automaticChangesAllowed'])

    def test_invalid_digest_is_redacted_and_checked_before_parsing(self):
        from vulnwrench.ignoreaudit import verification
        from vulnwrench.ignoreaudit.model import InputError
        with tempfile.TemporaryDirectory() as tmp:
            files, _ = self.report_fixture(tmp, empty=True)
            pin = sha256(files['plan'].read_bytes()).hexdigest()
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            values = ('0' * 64, '', pin.upper(), pin[:-1], pin + '0', 'g' * 64,
                      ' ' + pin, pin + ' ', pin + '\n', '０' * 64, 'PRIVATE-' + 'a' * 56)
            for value in values:
                with self.subTest(value=value):
                    proc = self.failure(files, value, output)
                    if value: self.assertNotIn(value, proc.stderr)
            with patch.object(verification, '_plan_identity', side_effect=AssertionError('pin first')):
                for value in (*values, True, 123, b'a' * 64):
                    with self.assertRaises(InputError):
                        verification.verify_cleanup_report(b'PRIVATE-invalid-json', b'', expected_plan_sha256=value)

    def test_correct_pin_never_bypasses_schema_provenance_or_native_reports(self):
        from test_verify_cleanup_report import plan_for
        with tempfile.TemporaryDirectory() as tmp:
            files, base = self.report_fixture(tmp, 'osv', True, True, empty=True)
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            def reject():
                self.failure(files, sha256(files['plan'].read_bytes()).hexdigest(), output)
            for field, value in [('schemaVersion', 2), ('reviewOnly', False), ('automaticChangesAllowed', True),
                                 ('provenance', {**base['provenance'], 'format': 'grype'})]:
                data = deepcopy(base); data[field] = value
                files['plan'].write_text(json.dumps(data)); reject()
            for value in (None, '', '0' * 64, True, [], {}):
                data = deepcopy(base); data['provenance']['reportSha256'] = value
                files['plan'].write_text(json.dumps(data)); reject()
            data = deepcopy(base); del data['provenance']['reportSha256']
            files['plan'].write_text(json.dumps(data)); reject()
            reports = [('trivy', raw) for raw in (b'null', b'[]', b'{"PRIVATE":', b'\xff',
                b'{"SchemaVersion":2,"SchemaVersion":2}', b'{"SchemaVersion":NaN}', b'{"SchemaVersion":1}',
                b'{"SchemaVersion":2,"Results":{}}', b'{"SchemaVersion":2,"PRIVATE":"PRIVATE"}')]
            reports += [('osv', raw) for raw in (b'{"results":{}}',
                b'{"results":[{"source":{},"packages":null}]}',
                b'{"results":[{"source":{},"packages":[{"package":{},"vulnerabilities":{}}]}]}',
                b'{"results":[{"source":{},"packages":[{"package":{},"groups":[{"aliases":["PRIVATE INVALID"]}]}]}]}')]
            for format, raw in reports:
                # Empty plans still require complete hash-matching native parsing.
                files['report'].write_bytes(raw)
                files['plan'].write_text(json.dumps(plan_for(raw, format))); reject()
            files, base = self.report_fixture(tmp, metadata=True, aliases=True)
            files['report'].write_bytes(files['report'].read_bytes() + b' '); reject()
            for raw in (b'{"PRIVATE":', b'null', b'\xff', b'{"schemaVersion":1,"schemaVersion":1}'):
                files['plan'].write_bytes(raw); reject()

    def test_missing_null_empty_observations_keep_identity_only_contract(self):
        from test_verify_cleanup_report import plan_for
        from vulnwrench.ignoreaudit.inputs import load_report
        with tempfile.TemporaryDirectory() as tmp:
            files, _ = self.report_fixture(tmp, empty=True)
            reports = [('trivy', {'SchemaVersion': 2, **extra}, extra.get('Results', None) is not None)
                       for extra in ({}, {'Results': None}, {'Results': []})]
            reports += [('osv', extra, extra.get('results', None) is not None)
                        for extra in ({}, {'results': None}, {'results': []})]
            for extra in ({}, {'vulnerabilities': None}, {'vulnerabilities': []}):
                reports.append(('osv', {'results': [{'source': {}, 'packages': [{'package': {},
                    'groups': [{'ids': ['CVE-1'], 'aliases': ['GHSA-local']}], **extra}]}]},
                    extra.get('vulnerabilities', None) is not None))
            for format, data, known in reports:
                with self.subTest(format=format, data=data):
                    raw = json.dumps(data).encode(); files['report'].write_bytes(raw)
                    files['plan'].write_text(json.dumps(plan_for(raw, format)))
                    before = {p: p.read_bytes() for p in files.values()}
                    native = load_report(raw, format, report_unfiltered=True)
                    pin = sha256(before[files['plan']]).hexdigest()
                    for expected_pin in (None, pin):
                        proc = self.verify(files, expected_pin)
                        self.assertEqual(proc.returncode, 0, proc.stderr)
                        expected = self.expected(files)
                        if expected_pin: expected['planSha256'] = expected_pin
                        self.assertEqual(proc.stdout, json.dumps(expected, indent=2, sort_keys=True) + '\n')
                    self.assertEqual(native.coverage, 'asserted_unfiltered' if known else 'unknown')
                    self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_correct_pin_keeps_destinations_and_missing_inputs_protected(self):
        with tempfile.TemporaryDirectory() as tmp:
            files, _ = self.report_fixture(tmp, metadata=True, aliases=True)
            pin = sha256(files['plan'].read_bytes()).hexdigest()
            for path in files.values():
                for mode in ('direct', 'symlink', 'hardlink'):
                    dest = path if mode == 'direct' else Path(tmp, 'alias')
                    if mode == 'symlink': dest.symlink_to(path)
                    if mode == 'hardlink': dest.hardlink_to(path)
                    self.failure(files, pin, dest)
                    if mode != 'direct': dest.unlink()
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            for key in files:
                self.failure({**files, key: Path(tmp, 'PRIVATE-missing')}, pin, output)
            self.failure(files, pin, Path(tmp, 'missing-dir', 'out.json'))
            self.assertFalse(Path(tmp, 'missing-dir').exists())
            directory = Path(tmp, 'directory'); directory.mkdir()
            (directory / 'sentinel').write_bytes(b'keep')
            self.failure(files, pin, directory)
            self.assertEqual((directory / 'sentinel').read_bytes(), b'keep')

    def test_single_snapshot_before_parse_only_plan_report_reads_no_reaudit(self):
        from vulnwrench.ignoreaudit import cli, verification
        with tempfile.TemporaryDirectory() as tmp:
            files, base = self.report_fixture(tmp, 'osv', True, True, incomplete=True)
            # Report identity does not revalidate source references or decisions.
            base['groups'] = 'PRIVATE-unverified'; base['excludedFromOrphanReview'] = None
            files['plan'].write_text(json.dumps(base))
            raw = files['plan'].read_bytes(); pin = sha256(raw).hexdigest()
            original_read, original_digest = cli.read_bytes, verification.digest
            reads, hashed = [], []
            def read(path):
                self.assertIn(path, [str(p) for p in files.values()])
                self.assertNotIn(path, reads); reads.append(path)
                return raw if path == str(files['plan']) else original_read(path)
            def digest(value):
                hashed.append(value); return original_digest(value)
            original_identity = verification._plan_identity
            def identity(value):
                self.assertIs(value, raw); self.assertIs(hashed[0], raw)
                return original_identity(value)
            args = ['verify-cleanup-report', '--expected-plan-sha256', pin,
                    *[v for k, p in files.items() for v in ('--' + k, str(p))]]
            with patch.object(cli, 'read_bytes', side_effect=read), \
                 patch.object(verification, 'digest', side_effect=digest), \
                 patch.object(verification, '_plan_identity', side_effect=identity), \
                 patch.object(verification, 'load_report', wraps=verification.load_report) as native, \
                 patch.object(verification, 'load_rules', side_effect=AssertionError('no rules')), \
                 patch.object(verification, 'apply_metadata', side_effect=AssertionError('no sidecar')), \
                 patch.object(verification, 'load_aliases', side_effect=AssertionError('no map')), \
                 patch.object(cli, 'audit', side_effect=AssertionError('no matching')), \
                 patch('sys.stdout', new_callable=io.StringIO) as stdout:
                self.assertEqual(cli.main(args), 0)
                self.assertEqual(json.loads(stdout.getvalue()), {**self.expected(files), 'planSha256': pin})
                self.assertEqual(len(reads), 2); self.assertEqual(native.call_count, 1)


if __name__ == '__main__':
    unittest.main()
