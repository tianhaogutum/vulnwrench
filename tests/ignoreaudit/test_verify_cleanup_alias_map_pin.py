"""External complete-plan identity pin for map-only verification; no equivalence trust."""
from copy import deepcopy
from hashlib import sha256
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_verify_cleanup_inputs as support
from test_verify_cleanup_alias_map import ALIASES, plan_for


class VerifyCleanupAliasMapPinTests(unittest.TestCase):
    run_cli = support.VerifyCleanupInputsTests.run_cli
    fixture = support.VerifyCleanupInputsTests.fixture

    def map_fixture(self, tmp, format='trivy', empty=False):
        files, data = self.fixture(tmp, format, True, True, empty, incomplete=format == 'osv')
        for key in set(files) - {'plan', 'alias-map'}:
            files.pop(key).unlink()
        return files, data

    def expected(self, files, pin=None):
        result = {'command': 'verify-cleanup-alias-map', 'aliasMapVerified': True,
                  'aliasMapSha256': sha256(files['alias-map'].read_bytes()).hexdigest(), 'automaticChangesAllowed': False}
        if pin is not None: result['planSha256'] = pin
        return json.dumps(result, indent=2, sort_keys=True) + '\n'

    def verify(self, files, pin=None, output=None):
        args = [v for k, p in files.items() for v in ('--' + k, p)]
        if pin is not None: args += ['--expected-plan-sha256', pin]
        if output is not None: args += ['--output', output]
        return self.run_cli('verify-cleanup-alias-map', *args)

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
        if output not in before and not output.is_dir(): self.assertFalse(output.exists())
        return proc

    def test_valid_pin_default_empty_and_unavailable_bound_inputs_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            for format in ('trivy', 'osv'):
                for empty in (False, True):
                    with self.subTest(format=format, empty=empty):
                        files, data = self.map_fixture(tmp, format, empty)
                        if format == 'osv': self.assertEqual(data['coverage'], 'unknown')
                        before = {p: p.read_bytes() for p in files.values()}
                        default = self.verify(files)
                        self.assertEqual(default.returncode, 0, default.stderr)
                        self.assertEqual(default.stderr, '')
                        self.assertEqual(default.stdout, self.expected(files))
                        pin = sha256(before[files['plan']]).hexdigest()
                        proc = self.verify(files, pin)
                        self.assertEqual(proc.returncode, 0, proc.stderr)
                        self.assertEqual(proc.stderr, '')
                        self.assertEqual(proc.stdout, self.expected(files, pin))
                        self.assertEqual(before, {p: p.read_bytes() for p in before})
            # Nonempty local groups must still parse when the plan has zero references.
            files['alias-map'].write_bytes(ALIASES)
            files['plan'].write_text(json.dumps(plan_for(ALIASES)))
            pin = sha256(files['plan'].read_bytes()).hexdigest()
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            proc = self.verify(files, pin, output)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout + proc.stderr, '')
            self.assertEqual(output.read_text(), self.expected(files, pin))

    def test_raw_whitespace_context_and_manual_suggestion_edits_need_new_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            files, base = self.map_fixture(tmp)
            original = files['plan'].read_bytes(); pin = sha256(original).hexdigest()
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            context = deepcopy(base); context.update(asOf='PRIVATE-context', summary={'findingCount': -1}, coverage='PRIVATE-context')
            suggestion = deepcopy(base); suggestion['groups']['ownerless'][0]['suggestedManualAction'] = 'PRIVATE-suggestion'
            for raw in (original + b' ', json.dumps(context).encode(), json.dumps(suggestion).encode()):
                files['plan'].write_bytes(raw)
                default = self.verify(files)
                self.assertEqual(default.returncode, 0, default.stderr)
                self.assertEqual(default.stdout, self.expected(files))
                self.failure(files, pin, output)
                self.failure(files, pin, Path(tmp, 'absent-output'))
                new_pin = sha256(raw).hexdigest()
                proc = self.verify(files, new_pin)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(proc.stdout, self.expected(files, new_pin))

    def test_invalid_digest_redacted_before_plan_parsing(self):
        from vulnwrench.ignoreaudit import verification
        from vulnwrench.ignoreaudit.model import InputError
        with tempfile.TemporaryDirectory() as tmp:
            files, _ = self.map_fixture(tmp, empty=True)
            pin = sha256(files['plan'].read_bytes()).hexdigest()
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            values = ('0' * 64, '', pin.upper(), pin[:-1], pin + '0', 'g' * 64,
                      ' ' + pin, pin + ' ', pin + '\n', '０' * 64, 'PRIVATE-' + 'a' * 56)
            for value in values:
                proc = self.failure(files, value, output)
                if value: self.assertNotIn(value, proc.stderr)
            with patch.object(verification, '_plan_identity', side_effect=AssertionError('must pin before parsing')):
                for value in (*values, True, 1, b'a' * 64, [], {}):
                    with self.assertRaisesRegex(InputError, 'expected plan SHA-256'):
                        verification.verify_cleanup_alias_map(b'PRIVATE-invalid-json', b'', expected_plan_sha256=value)

    def test_correct_pin_cannot_bypass_envelope_mode_or_map_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            files, base = self.map_fixture(tmp, empty=True)
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            def reject():
                self.failure(files, sha256(files['plan'].read_bytes()).hexdigest(), output)
            for key, value in [('schemaVersion', 2), ('schemaVersion', True), ('schemaVersion', 1.0), ('reviewOnly', False),
                               ('tool', 'PRIVATE'), ('command', 'audit'), ('automaticChangesAllowed', True),
                               ('unusedRuleAssertionAllowed', True), ('provenance', {'format': 'grype'})]:
                data = deepcopy(base); data[key] = value
                files['plan'].write_text(json.dumps(data)); reject()
            for key, values in [('aliasMapSha256', (None, '', '0' * 64, True, [], {})),
                                ('aliases', ('exact_ids_only', None, '', True, [], {})),
                                ('format', ('grype', None, [], {}))]:
                for value in values:
                    data = deepcopy(base); data['provenance'][key] = value
                    files['plan'].write_text(json.dumps(data)); reject()
                data = deepcopy(base); del data['provenance'][key]
                files['plan'].write_text(json.dumps(data)); reject()
            for raw in (b'{"PRIVATE":', b'null', b'\xff', b'{"schemaVersion":1,"schemaVersion":1}', b'{"schemaVersion":NaN}'):
                files['plan'].write_bytes(raw); reject()
            files, _ = self.map_fixture(tmp)
            files['alias-map'].write_bytes(files['alias-map'].read_bytes() + b' '); reject()

    def test_correct_pin_requires_complete_strict_disjoint_groups_even_with_zero_references(self):
        with tempfile.TemporaryDirectory() as tmp:
            files, _ = self.map_fixture(tmp, empty=True)
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            maps = [b'null', b'[]', b'{"PRIVATE":', b'\xff',
                    b'{"schemaVersion":1,"schemaVersion":1,"groups":[]}', b'{"schemaVersion":NaN,"groups":[]}']
            maps += [json.dumps({'schemaVersion': v, 'groups': []}).encode() for v in (None, True, 1.0, 2)]
            maps += [json.dumps({'schemaVersion': 1, 'groups': groups}).encode() for groups in (
                None, {}, [None], [[]], [['CVE-1']], [['CVE-1', 'CVE-1']],
                [['CVE-1', 'GHSA-local'], ['GHSA-local', 'CVE-2']],
                [['CVE-1', 'PRIVATE INVALID']], [['CVE-1', None]], [['CVE-1', {}]])]
            maps += [b'{"schemaVersion":1}', b'{"schemaVersion":1,"groups":[],"PRIVATE":"PRIVATE"}']
            for raw in maps:
                files['alias-map'].write_bytes(raw)
                files['plan'].write_text(json.dumps(plan_for(raw)))
                self.failure(files, sha256(files['plan'].read_bytes()).hexdigest(), output)

    def test_correct_pin_keeps_destinations_and_missing_inputs_protected(self):
        with tempfile.TemporaryDirectory() as tmp:
            files, _ = self.map_fixture(tmp)
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

    def test_single_snapshot_before_parse_only_plan_map_reads_no_reaudit(self):
        from vulnwrench.ignoreaudit import cli, verification
        with tempfile.TemporaryDirectory() as tmp:
            files, base = self.map_fixture(tmp, 'osv')
            base['groups'] = 'PRIVATE-unverified'; base['excludedFromOrphanReview'] = None
            files['plan'].write_text(json.dumps(base))
            raw = files['plan'].read_bytes(); pin = sha256(raw).hexdigest()
            original_read, original_digest, original_identity = cli.read_bytes, verification.digest, verification._plan_identity
            reads, hashed = [], []
            def read(path):
                self.assertIn(path, [str(p) for p in files.values()])
                self.assertNotIn(path, reads); reads.append(path)
                return raw if path == str(files['plan']) else original_read(path)
            def digest(value):
                hashed.append(value); return original_digest(value)
            def identity(value):
                self.assertIs(value, raw); self.assertIs(hashed[0], raw)
                return original_identity(value)
            args = ['verify-cleanup-alias-map', '--expected-plan-sha256', pin,
                    *[v for k, p in files.items() for v in ('--' + k, str(p))]]
            with patch.object(cli, 'read_bytes', side_effect=read), \
                 patch.object(verification, 'digest', side_effect=digest), \
                 patch.object(verification, '_plan_identity', side_effect=identity), \
                 patch.object(verification, 'load_aliases', wraps=verification.load_aliases) as aliases, \
                 patch.object(verification, 'load_rules', side_effect=AssertionError('no rules')), \
                 patch.object(verification, 'load_report', side_effect=AssertionError('no report')), \
                 patch.object(verification, 'apply_metadata', side_effect=AssertionError('no metadata')), \
                 patch.object(verification, 'verify_cleanup_source', side_effect=AssertionError('no source references')), \
                 patch.object(cli, 'audit', side_effect=AssertionError('no matching')), \
                 patch('sys.stdout', new_callable=io.StringIO) as stdout:
                self.assertEqual(cli.main(args), 0)
                self.assertEqual(stdout.getvalue(), self.expected(files, pin))
                self.assertEqual(len(reads), 2); self.assertEqual(aliases.call_count, 1)


if __name__ == '__main__':
    unittest.main()
