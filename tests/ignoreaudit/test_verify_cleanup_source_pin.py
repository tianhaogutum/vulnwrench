"""External raw-plan pin on source-only verification; no additional input trust."""
from copy import deepcopy
from hashlib import sha256
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_verify_cleanup_inputs as support


class VerifyCleanupSourcePinTests(unittest.TestCase):
    run_cli = support.VerifyCleanupInputsTests.run_cli
    fixture = support.VerifyCleanupInputsTests.fixture

    def source_fixture(self, *args, **kwargs):
        files, data = self.fixture(*args, **kwargs)
        # Bound inputs are deliberately unavailable to source-only verification.
        for key in set(files) - {'plan', 'rules'}:
            files.pop(key).unlink()
        return files, data

    def expected(self, files, count):
        return {'command': 'verify-cleanup-source', 'sourceVerified': True,
                'rulesSha256': sha256(files['rules'].read_bytes()).hexdigest(),
                'verifiedReferenceCount': count, 'automaticChangesAllowed': False}

    def verify(self, files, pin=None, output=None):
        args = [v for k, p in files.items() for v in ('--' + k, p)]
        if pin is not None: args += ['--expected-plan-sha256', pin]
        if output is not None: args += ['--output', output]
        return self.run_cli('verify-cleanup-source', *args)

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
                            files, _ = self.source_fixture(tmp, format, metadata, aliases, empty, incomplete=format == 'osv')
                            before = {p: p.read_bytes() for p in files.values()}
                            expected = self.expected(files, 0 if empty else 2)
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
            files, base = self.source_fixture(tmp, metadata=True, aliases=True)
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
            files, _ = self.source_fixture(tmp, empty=True)
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
                        verification.verify_cleanup_source(b'PRIVATE-invalid-json', b'', expected_plan_sha256=value)

    def test_correct_pin_never_bypasses_schema_native_or_every_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            files, base = self.source_fixture(tmp, 'osv', True, True, empty=True)
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            def reject():
                self.failure(files, sha256(files['plan'].read_bytes()).hexdigest(), output)
            for field, value in [('schemaVersion', 2), ('reviewOnly', False), ('automaticChangesAllowed', True),
                                 ('provenance', {**base['provenance'], 'format': 'grype'})]:
                data = deepcopy(base); data[field] = value
                files['plan'].write_text(json.dumps(data)); reject()
            for format, raw in [('trivy', b'CVE-1 exp:PRIVATE-invalid'), ('trivy', b'\xff'),
                                ('osv', b'[[PRIVATE'), ('osv', b'[[IgnoredVulns]]\nid="PRIVATE INVALID"')]:
                # Zero references must still parse complete hash-matching native rules.
                files['rules'].write_bytes(raw)
                data = deepcopy(base); data['provenance'].update(format=format, rulesSha256=sha256(raw).hexdigest())
                files['plan'].write_text(json.dumps(data)); reject()
            files, base = self.source_fixture(tmp, metadata=True, aliases=True)
            for group in ('ownerless', 'expired'):
                data = deepcopy(base)
                data['groups'][group][0]['sourceReference']['locator'] = 'line:999'
                files['plan'].write_text(json.dumps(data)); reject()
            data = deepcopy(base); data['groups']['ownerless'][0]['rule']['rule'] = 'CVE-999'
            files['plan'].write_text(json.dumps(data)); reject()
            files, base = self.source_fixture(tmp, 'osv', incomplete=True)
            data = deepcopy(base); data['excludedFromOrphanReview'][-1]['sourceReference']['rulesByteLength'] = True
            files['plan'].write_text(json.dumps(data)); reject()
            files['plan'].write_text(json.dumps(base))
            files['rules'].write_bytes(files['rules'].read_bytes() + b' '); reject()
            for raw in (b'{"PRIVATE":', b'null', b'\xff'):
                files['plan'].write_bytes(raw); reject()

    def test_correct_pin_keeps_destinations_and_missing_inputs_protected(self):
        with tempfile.TemporaryDirectory() as tmp:
            files, _ = self.source_fixture(tmp, metadata=True, aliases=True)
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

    def test_single_snapshot_before_parse_only_plan_rules_reads_no_reaudit(self):
        from vulnwrench.ignoreaudit import cli, verification
        with tempfile.TemporaryDirectory() as tmp:
            files, base = self.source_fixture(tmp, 'osv', True, True, incomplete=True)
            # Nonempty valid rules and zero references still require native parsing.
            base['groups'] = {group: [] for group in base['groups']}; base['excludedFromOrphanReview'] = []
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
            args = ['verify-cleanup-source', '--expected-plan-sha256', pin,
                    *[v for k, p in files.items() for v in ('--' + k, str(p))]]
            with patch.object(cli, 'read_bytes', side_effect=read), \
                 patch.object(verification, 'digest', side_effect=digest), \
                 patch.object(verification, '_plan_identity', side_effect=identity), \
                 patch.object(verification, 'load_rules', wraps=verification.load_rules) as native, \
                 patch.object(verification, 'load_report', side_effect=AssertionError('no report')), \
                 patch.object(verification, 'apply_metadata', side_effect=AssertionError('no sidecar')), \
                 patch.object(verification, 'load_aliases', side_effect=AssertionError('no map')), \
                 patch.object(cli, 'audit', side_effect=AssertionError('no matching')), \
                 patch('sys.stdout', new_callable=io.StringIO) as stdout:
                self.assertEqual(cli.main(args), 0)
                self.assertEqual(json.loads(stdout.getvalue()), {**self.expected(files, 0), 'planSha256': pin})
                self.assertEqual(len(reads), 2); self.assertEqual(native.call_count, 1)


if __name__ == '__main__':
    unittest.main()
