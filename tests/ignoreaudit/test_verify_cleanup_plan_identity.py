"""Standalone raw plan identity and supported envelope only; no semantic approval."""
from contextlib import ExitStack
from copy import deepcopy
from hashlib import sha256
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_verify_cleanup_inputs as support


class VerifyCleanupPlanIdentityTests(unittest.TestCase):
    run_cli = support.VerifyCleanupInputsTests.run_cli
    fixture = support.VerifyCleanupInputsTests.fixture

    def plan_fixture(self, tmp, format='trivy', aliases=True, empty=False):
        files, data = self.fixture(tmp, format, True, aliases, empty, incomplete=format == 'osv')
        for key in set(files) - {'plan'}:
            files.pop(key).unlink()
        self.assertEqual(list(Path(tmp).iterdir()), [files['plan']])
        return files['plan'], data

    def expected(self, pin):
        return json.dumps({'command': 'verify-cleanup-plan-identity', 'planIdentityVerified': True,
                           'planSha256': pin, 'automaticChangesAllowed': False}, indent=2, sort_keys=True) + '\n'

    def verify(self, plan, pin=None, output=None):
        args = ['--plan', plan]
        if pin is not None: args += ['--expected-plan-sha256', pin]
        if output is not None: args += ['--output', output]
        return self.run_cli('verify-cleanup-plan-identity', *args)

    def failure(self, plan, pin, output):
        before = {p: p.read_bytes() for p in (plan, output) if p.is_file()}
        proc = self.verify(plan, pin, output)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(proc.stdout, '')
        for value in ('PRIVATE', str(output.parent), 'Traceback'):
            self.assertNotIn(value, proc.stderr)
        self.assertTrue(proc.stderr)
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        self.assertEqual(list(output.parent.glob('.vulnwrench-ignores-*')), [])
        if output not in before and not output.is_dir(): self.assertFalse(output.exists())
        return proc

    def test_literal_success_empty_both_modes_and_unavailable_inputs(self):
        for format in ('trivy', 'osv'):
            for aliases in (False, True):
                for empty in (False, True):
                    with self.subTest(format=format, aliases=aliases, empty=empty), tempfile.TemporaryDirectory() as tmp:
                        plan, data = self.plan_fixture(tmp, format, aliases, empty)
                        self.assertEqual(data['provenance']['aliases'], 'explicit_local_groups' if aliases else 'exact_ids_only')
                        if format == 'osv': self.assertEqual(data['coverage'], 'unknown')
                        if empty: self.assertFalse(any(data['groups'].values()))
                        raw = plan.read_bytes(); pin = sha256(raw).hexdigest()
                        proc = self.verify(plan, pin)
                        self.assertEqual(proc.returncode, 0, proc.stderr)
                        self.assertEqual(proc.stderr, '')
                        self.assertEqual(proc.stdout, self.expected(pin))
                        self.assertEqual(plan.read_bytes(), raw)
                        output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
                        proc = self.verify(plan, pin, output)
                        self.assertEqual(proc.returncode, 0, proc.stderr)
                        self.assertEqual(proc.stdout + proc.stderr, '')
                        self.assertEqual(output.read_text(), self.expected(pin))
                        self.assertEqual(plan.read_bytes(), raw)

    def test_raw_edits_require_new_pin_without_semantic_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan, base = self.plan_fixture(tmp)
            original = plan.read_bytes(); pin = sha256(original).hexdigest()
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            context = deepcopy(base); context.update(asOf='PRIVATE-context', summary={'findingCount': -1}, coverage='PRIVATE-context')
            suggestion = deepcopy(base); suggestion['groups']['ownerless'][0]['suggestedManualAction'] = 'PRIVATE-suggestion'
            unverified = deepcopy(base)
            unverified.update(groups='PRIVATE-unverified', excludedFromOrphanReview=None)
            unverified['provenance'].update(rulesSha256=None, reportSha256='PRIVATE-unverified', metadataSha256={}, aliasMapSha256=[])
            for raw in (original + b' ', json.dumps(context).encode(), json.dumps(suggestion).encode(), json.dumps(unverified).encode()):
                plan.write_bytes(raw)
                self.failure(plan, pin, output)
                self.failure(plan, pin, Path(tmp, 'absent-output'))
                new_pin = sha256(raw).hexdigest(); proc = self.verify(plan, new_pin)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(proc.stderr, '')
                self.assertEqual(proc.stdout, self.expected(new_pin))

    def test_required_canonical_pin_checked_before_parsing(self):
        from vulnwrench.ignoreaudit import verification
        from vulnwrench.ignoreaudit.model import InputError
        with tempfile.TemporaryDirectory() as tmp:
            plan, _ = self.plan_fixture(tmp, empty=True)
            pin = sha256(plan.read_bytes()).hexdigest()
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            values = ('0' * 64, '', pin.upper(), pin[:-1], pin + '0', 'g' * 64,
                      ' ' + pin, pin + ' ', pin + '\n', '０' * 64, 'PRIVATE-' + 'a' * 56)
            self.failure(plan, None, output)
            for value in values:
                proc = self.failure(plan, value, output)
                self.assertTrue(proc.stderr.startswith('vulnwrench ignores: '))
                if value: self.assertNotIn(value, proc.stderr)
            with patch.object(verification, '_plan_identity', side_effect=AssertionError('must pin before parsing')):
                for value in (*values, None, True, 1, b'a' * 64, [], {}):
                    with self.assertRaisesRegex(InputError, 'expected plan SHA-256'):
                        verification.verify_cleanup_plan_identity(b'PRIVATE-invalid-json', expected_plan_sha256=value)

    def test_correct_pin_cannot_bypass_supported_identity_review_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan, base = self.plan_fixture(tmp, empty=True)
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            def reject(raw):
                plan.write_bytes(raw)
                proc = self.failure(plan, sha256(raw).hexdigest(), output)
                self.assertTrue(proc.stderr.startswith('vulnwrench ignores: '))
            for key, values in [('schemaVersion', (None, True, 1.0, 2)), ('tool', ('PRIVATE', None)),
                                ('command', ('audit', None)), ('reviewOnly', (False, 1, None)),
                                ('automaticChangesAllowed', (True, 0, None)), ('unusedRuleAssertionAllowed', (True, 0, None)),
                                ('provenance', (None, [], 'PRIVATE'))]:
                for value in values:
                    data = deepcopy(base); data[key] = value; reject(json.dumps(data).encode())
                data = deepcopy(base); del data[key]; reject(json.dumps(data).encode())
            for value in ('grype', None, [], {}, True, 'PRIVATE'):
                data = deepcopy(base); data['provenance']['format'] = value; reject(json.dumps(data).encode())
            data = deepcopy(base); del data['provenance']['format']; reject(json.dumps(data).encode())
            for raw in (b'{"PRIVATE":', b'null', b'[]', b'\xff', b'# Markdown cleanup plan',
                        b'{"schemaVersion":1,"schemaVersion":1}', b'{"schemaVersion":NaN}',
                        json.dumps(base).encode().replace(b'"format": "trivy"', b'"format": "trivy", "format": "trivy"')):
                reject(raw)

    def test_missing_plan_and_direct_symlink_hardlink_output_protection(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan, _ = self.plan_fixture(tmp)
            pin = sha256(plan.read_bytes()).hexdigest()
            for mode in ('direct', 'symlink', 'hardlink'):
                dest = plan if mode == 'direct' else Path(tmp, 'alias')
                if mode == 'symlink': dest.symlink_to(plan)
                if mode == 'hardlink': dest.hardlink_to(plan)
                self.failure(plan, pin, dest)
                if mode != 'direct': dest.unlink()
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            self.failure(Path(tmp, 'PRIVATE-missing'), pin, output)
            self.failure(plan, pin, Path(tmp, 'missing-dir', 'out.json'))
            self.assertFalse(Path(tmp, 'missing-dir').exists())
            directory = Path(tmp, 'directory'); directory.mkdir(); (directory / 'sentinel').write_bytes(b'keep')
            self.failure(plan, pin, directory)
            self.assertEqual((directory / 'sentinel').read_bytes(), b'keep')

    def test_one_complete_plan_snapshot_only_no_input_parsers_or_reaudit(self):
        from vulnwrench.ignoreaudit import cli, verification
        with tempfile.TemporaryDirectory() as tmp:
            plan, _ = self.plan_fixture(tmp, 'osv')
            raw = plan.read_bytes(); pin = sha256(raw).hexdigest()
            original_digest, original_identity = verification.digest, verification._plan_identity
            hashed = []
            def digest(value):
                self.assertIs(value, raw); hashed.append(value); return original_digest(value)
            def identity(value):
                self.assertIs(value, raw); self.assertEqual(len(hashed), 1); return original_identity(value)
            with ExitStack() as stack:
                read = stack.enter_context(patch.object(cli, 'read_bytes', return_value=raw))
                stack.enter_context(patch.object(verification, 'digest', side_effect=digest))
                stack.enter_context(patch.object(verification, '_plan_identity', side_effect=identity))
                for module, names in [(cli, ('audit', 'explain', 'cleanup_plan', 'load_rules', 'load_report', 'apply_metadata', 'load_aliases')),
                                      (verification, ('load_rules', 'load_report', 'apply_metadata', 'load_aliases', 'verify_cleanup_source',
                                                      'verify_cleanup_report', 'verify_cleanup_metadata', 'verify_cleanup_alias_map', 'verify_cleanup_inputs'))]:
                    for name in names:
                        stack.enter_context(patch.object(module, name, side_effect=AssertionError('plan identity only')))
                stdout = stack.enter_context(patch('sys.stdout', new_callable=io.StringIO))
                self.assertEqual(cli.main(['verify-cleanup-plan-identity', '--plan', str(plan), '--expected-plan-sha256', pin]), 0)
                self.assertEqual(stdout.getvalue(), self.expected(pin))
                read.assert_called_once_with(str(plan))
                self.assertEqual(len(hashed), 1)


if __name__ == '__main__':
    unittest.main()
