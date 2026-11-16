"""External plan identity pin; never authentication or permission to edit."""
from copy import deepcopy
from hashlib import sha256
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_verify_cleanup_inputs as support


class VerifyCleanupPlanPinTests(unittest.TestCase):
    run_cli = support.VerifyCleanupInputsTests.run_cli
    fixture = support.VerifyCleanupInputsTests.fixture
    expected = support.VerifyCleanupInputsTests.expected

    def verify(self, files, expected=None, output=None):
        args = [v for k, p in files.items() for v in ('--' + k, p)]
        if expected is not None:
            args += ['--expected-plan-sha256', expected]
        if output is not None:
            args += ['--output', output]
        return self.run_cli('verify-cleanup-inputs', *args)

    def failure(self, files, expected, output):
        before = {p: p.read_bytes() for p in [*files.values(), output] if p.is_file()}
        proc = self.verify(files, expected, output)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(proc.stdout, '')
        self.assertTrue(proc.stderr.startswith('vulnwrench ignores: '), proc.stderr)
        for secret in ('PRIVATE', str(output.parent), 'Traceback'):
            self.assertNotIn(secret, proc.stderr)
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        self.assertEqual(list(output.parent.glob('.vulnwrench-ignores-*')), [])
        return proc

    def test_valid_digest_default_optional_empty_and_incomplete_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            for format in ('trivy', 'osv'):
                for metadata, aliases in ((False, False), (True, False), (False, True), (True, True)):
                    for empty in (False, True):
                        with self.subTest(format=format, metadata=metadata, aliases=aliases, empty=empty):
                            files, _ = self.fixture(tmp, format, metadata, aliases, empty, incomplete=format == 'osv')
                            before = {p: p.read_bytes() for p in files.values()}
                            expected = self.expected(files, 0 if empty else 2)
                            # Literal serialization, including absence of planSha256 by default.
                            default = self.verify(files)
                            self.assertEqual(default.returncode, 0, default.stderr)
                            self.assertEqual(default.stdout, json.dumps(expected, indent=2, ensure_ascii=True, sort_keys=True) + '\n')
                            pin = sha256(before[files['plan']]).hexdigest()
                            proc = self.verify(files, pin)
                            self.assertEqual(proc.returncode, 0, proc.stderr)
                            self.assertEqual(proc.stderr, '')
                            self.assertEqual(json.loads(proc.stdout), {**expected, 'planSha256': pin})
                            self.assertEqual(before, {p: p.read_bytes() for p in before})
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            proc = self.verify(files, pin, output)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout + proc.stderr, '')
            self.assertEqual(output.read_text(), json.dumps({**expected, 'planSha256': pin}, indent=2, sort_keys=True) + '\n')

    def test_plan_whitespace_decision_context_edits_need_new_external_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            files, base = self.fixture(tmp, metadata=True, aliases=True)
            original = files['plan'].read_bytes(); pin = sha256(original).hexdigest()
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            context = deepcopy(base); context.update(asOf='PRIVATE-context', summary={'findingCount': -1}, coverage='PRIVATE-context')
            decision = deepcopy(base); decision['groups']['report_local_orphans'][0]['suggestedManualAction'] = 'PRIVATE-decision'
            for raw in (original + b' ', json.dumps(context).encode(), json.dumps(decision).encode()):
                files['plan'].write_bytes(raw)
                # Existing identity verifiers intentionally do not validate these decisions/context.
                self.assertEqual(self.verify(files).returncode, 0)
                self.failure(files, pin, output)
                proc = self.verify(files, sha256(raw).hexdigest())
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertFalse(json.loads(proc.stdout)['automaticChangesAllowed'])

    def test_wrong_and_noncanonical_digest_redacted_before_plan_parsing(self):
        from vulnwrench.ignoreaudit import verification
        from vulnwrench.ignoreaudit.model import InputError
        with tempfile.TemporaryDirectory() as tmp:
            files, _ = self.fixture(tmp, empty=True)
            pin = sha256(files['plan'].read_bytes()).hexdigest()
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            values = ('0' * 64, '', pin.upper(), pin[:-1], pin + '0', 'g' * 64,
                      ' ' + pin, pin + ' ', pin + '\n', '０' * 64, 'PRIVATE-' + 'a' * 56)
            for value in values:
                with self.subTest(value=value):
                    proc = self.failure(files, value, output)
                    if value: self.assertNotIn(value, proc.stderr)
            # Parse/composition must not run, even if the retained plan is malformed.
            with patch.object(verification, '_plan_identity', side_effect=AssertionError('must check pin first')):
                for value in (*values, True, 123, b'a' * 64):
                    with self.assertRaises(InputError):
                        verification.verify_cleanup_inputs(b'PRIVATE-invalid-json', b'', b'', expected_plan_sha256=value)

    def test_correct_digest_never_bypasses_existing_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            files, base = self.fixture(tmp, 'osv', True, True, empty=True)
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            def reject(current):
                self.failure(current, sha256(current['plan'].read_bytes()).hexdigest(), output)
            for key in ('metadata', 'alias-map'):
                reject({k: p for k, p in files.items() if k != key})
            for field, value in [('schemaVersion', 2), ('reviewOnly', False), ('automaticChangesAllowed', True),
                                 ('provenance', {**base['provenance'], 'aliases': 'exact_ids_only'})]:
                data = deepcopy(base); data[field] = value
                files['plan'].write_text(json.dumps(data)); reject(files)
            for key, raw, field in [('rules', b'[[PRIVATE', 'rulesSha256'), ('report', b'{"results":{}}', 'reportSha256'),
                                    ('metadata', b'{"schemaVersion":2,"rules":{}}', 'metadataSha256'),
                                    ('alias-map', b'{"schemaVersion":1,"groups":[["CVE-1","CVE-2"],["CVE-1","GHSA-a"]]}', 'aliasMapSha256')]:
                original = files[key].read_bytes(); files[key].write_bytes(raw)
                data = deepcopy(base); data['provenance'][field] = sha256(raw).hexdigest()
                files['plan'].write_text(json.dumps(data)); reject(files)
                files[key].write_bytes(original)
            files['plan'].write_text(json.dumps(base))
            for key in ('rules', 'report', 'metadata', 'alias-map'):
                raw = files[key].read_bytes(); files[key].write_bytes(raw + b' ')
                reject(files); files[key].write_bytes(raw)
            files, data = self.fixture(tmp, metadata=True, aliases=True)
            data['groups']['report_local_orphans'][0]['sourceReference']['locator'] = 'line:999'
            files['plan'].write_text(json.dumps(data)); reject(files)
            for raw in (b'{"PRIVATE":', b'null', b'\xff'):
                files['plan'].write_bytes(raw); reject(files)

    def test_correct_pin_keeps_all_input_destination_and_io_protections(self):
        with tempfile.TemporaryDirectory() as tmp:
            files, _ = self.fixture(tmp, metadata=True, aliases=True)
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

    def test_single_snapshot_pin_and_existing_composition_without_reaudit(self):
        from vulnwrench.ignoreaudit import cli, verification
        with tempfile.TemporaryDirectory() as tmp:
            files, _ = self.fixture(tmp, 'osv', True, True, incomplete=True)
            raw = files['plan'].read_bytes(); pin = sha256(raw).hexdigest()
            # Fail a second plan read; keep the exact first object passed to every verifier.
            original_read = cli.read_bytes
            reads = []
            def read(path):
                reads.append(path)
                if path == str(files['plan']):
                    self.assertEqual(reads.count(path), 1)
                    return raw
                return original_read(path)
            args = ['verify-cleanup-inputs', '--expected-plan-sha256', pin,
                    *[v for k, p in files.items() for v in ('--' + k, str(p))]]
            with patch.object(cli, 'read_bytes', side_effect=read), \
                 patch.object(verification, 'verify_cleanup_source', wraps=verification.verify_cleanup_source) as source, \
                 patch.object(verification, 'verify_cleanup_report', wraps=verification.verify_cleanup_report) as report, \
                 patch.object(verification, 'verify_cleanup_metadata', wraps=verification.verify_cleanup_metadata) as metadata, \
                 patch.object(verification, 'verify_cleanup_alias_map', wraps=verification.verify_cleanup_alias_map) as aliases, \
                 patch.object(cli, 'audit', side_effect=AssertionError('must not re-audit')), \
                 patch('sys.stdout', new_callable=io.StringIO) as stdout:
                self.assertEqual(cli.main(args), 0)
                self.assertEqual(json.loads(stdout.getvalue()), {**self.expected(files, 2), 'planSha256': pin})
                for verifier in (source, report, metadata, aliases):
                    self.assertEqual(verifier.call_count, 1)
                    self.assertIs(verifier.call_args.args[0], raw)


if __name__ == '__main__':
    unittest.main()
