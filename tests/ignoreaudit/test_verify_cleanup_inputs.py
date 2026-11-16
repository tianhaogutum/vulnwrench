"""Composed retained-input contracts; every supplied byte remains read-only."""
from copy import deepcopy
from hashlib import sha256
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def sidecar(raw, entries=None):
    return json.dumps({'schemaVersion': 1, 'rulesSha256': sha256(raw).hexdigest(),
                       'rules': entries or {}}).encode()


class VerifyCleanupInputsTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'ignores', *map(str, args)],
                              cwd=ROOT, capture_output=True, timeout=60, text=True)

    def fixture(self, tmp, format='trivy', metadata=False, aliases=False, empty=False, incomplete=False):
        raw = b'' if empty else (b'# PRIVATE\r\nCVE-1 exp:2026-11-10\r\nCVE-1\r\n' if format == 'trivy' else
              b'[[IgnoredVulns]]\nid="CVE-1"\neffectiveUntil=2026-11-10\n[[IgnoredVulns]]\nid="CVE-1"\n')
        report = {'SchemaVersion': 2, 'Results': []} if format == 'trivy' else {'results': None if incomplete else []}
        files = {'plan': Path(tmp, 'plan.json'), 'rules': Path(tmp, 'PRIVATE.rules'), 'report': Path(tmp, 'PRIVATE.report.json')}
        files['rules'].write_bytes(raw)
        files['report'].write_text(json.dumps(report))
        if metadata:
            files['metadata'] = Path(tmp, 'PRIVATE.metadata.json')
            files['metadata'].write_bytes(sidecar(raw))
        if aliases:
            files['alias-map'] = Path(tmp, 'PRIVATE.aliases.json')
            files['alias-map'].write_bytes(b'{"schemaVersion":1,"groups":[]}' if empty else
                                           b'{"schemaVersion":1,"groups":[["CVE-1","GHSA-local"]]}')
        args = [v for k, p in files.items() if k != 'plan' for v in ('--' + k, p)]
        proc = self.run_cli('cleanup-plan', '--format', format, '--report-unfiltered', '--as-of', '2026-11-11',
                            *args, '--output', files['plan'])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return files, json.loads(files['plan'].read_bytes())

    def verify(self, files, output=None):
        args = [v for k, p in files.items() for v in ('--' + k, p)]
        return self.run_cli('verify-cleanup-inputs', *args, *(['--output', output] if output else []))

    def expected(self, files, count):
        result = {'command': 'verify-cleanup-inputs', 'inputsVerified': True, 'automaticChangesAllowed': False,
                  'rulesSha256': sha256(files['rules'].read_bytes()).hexdigest(),
                  'reportSha256': sha256(files['report'].read_bytes()).hexdigest(), 'verifiedReferenceCount': count}
        for key, field in [('metadata', 'metadataSha256'), ('alias-map', 'aliasMapSha256')]:
            if key in files:
                result[field] = sha256(files[key].read_bytes()).hexdigest()
        return result

    def success(self, files, count):
        before = {p: p.read_bytes() for p in files.values()}
        proc = self.verify(files)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stderr, '')
        self.assertEqual(json.loads(proc.stdout), self.expected(files, count))
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        return proc.stdout

    def failure(self, files, output):
        before = {p: p.read_bytes() for p in [*files.values(), output] if p.exists() and p.is_file()}
        proc = self.verify(files, output)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(proc.stdout, '')
        self.assertTrue(proc.stderr.startswith('vulnwrench ignores: '), proc.stderr)
        for secret in ('PRIVATE', str(output.parent), 'Traceback'):
            self.assertNotIn(secret, proc.stderr)
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_literal_exact_optional_empty_and_incomplete_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            for format in ('trivy', 'osv'):
                for metadata, aliases in ((False, False), (True, False), (False, True), (True, True)):
                    for empty in (False, True):
                        with self.subTest(format=format, metadata=metadata, aliases=aliases, empty=empty):
                            files, data = self.fixture(tmp, format, metadata, aliases, empty, incomplete=format == 'osv')
                            self.assertEqual(data['provenance']['aliases'], 'explicit_local_groups' if aliases else 'exact_ids_only')
                            if format == 'osv' and not empty:
                                self.assertEqual(data['coverage'], 'unknown')
                                self.assertEqual(data['groups']['report_local_orphans'], [])
                                self.assertEqual([c['key'] for c in data['excludedFromOrphanReview']], ['IgnoredVulns:0', 'IgnoredVulns:1'])
                            stdout = self.success(files, 0 if empty else 2)
            output = Path(tmp, 'verified.json')
            output.write_bytes(b'previous output')
            proc = self.verify(files, output)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout + proc.stderr, '')
            self.assertEqual(output.read_text(), stdout)
            files['report'].write_bytes(files['report'].read_bytes() + b' ')
            self.failure(files, output)

    def test_missing_unexpected_optional_inputs_and_alias_mode_consistency(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            files, base = self.fixture(tmp, metadata=True, aliases=True, empty=True)
            for key in ('metadata', 'alias-map'):
                missing = dict(files); missing.pop(key)
                self.failure(missing, output)
            cases = []
            for key in ('metadataSha256', 'aliasMapSha256'):
                for value in (None, '', [], {}, True):
                    cases.append((key, value))
                data = deepcopy(base); del data['provenance'][key]
                files['plan'].write_text(json.dumps(data)); self.failure(files, output)
            for value in ('exact_ids_only', None, '', [], {}, True, 'PRIVATE-mode'):
                cases.append(('aliases', value))
            for key, value in cases:
                data = deepcopy(base); data['provenance'][key] = value
                files['plan'].write_text(json.dumps(data)); self.failure(files, output)
            # Even absent optional CLI flags must reject inconsistent bound provenance.
            for mode, digest in [('exact_ids_only', '0' * 64), ('explicit_local_groups', None), (None, None)]:
                data = deepcopy(base); data['provenance']['aliases'] = mode
                if digest is None: del data['provenance']['aliasMapSha256']
                else: data['provenance']['aliasMapSha256'] = digest
                files['plan'].write_text(json.dumps(data))
                self.failure({k: v for k, v in files.items() if k != 'alias-map'}, output)
            files, data = self.fixture(tmp, empty=True)
            for key in ('metadata', 'alias-map'):
                extra = Path(tmp, 'extra.json'); extra.write_bytes(b'{}')
                self.failure({**files, key: extra}, output)
            for field in ('aliases', 'rulesSha256', 'reportSha256'):
                changed = deepcopy(data); del changed['provenance'][field]
                files['plan'].write_text(json.dumps(changed)); self.failure(files, output)

    def test_each_complete_input_digest_and_every_source_reference_are_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            files, base = self.fixture(tmp, metadata=True, aliases=True)
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            for key in ('rules', 'report', 'metadata', 'alias-map'):
                raw = files[key].read_bytes(); files[key].write_bytes(raw + b' ')
                self.failure(files, output); files[key].write_bytes(raw)
            for field in ('rulesSha256', 'reportSha256', 'metadataSha256', 'aliasMapSha256'):
                data = deepcopy(base); data['provenance'][field] = '0' * 64
                files['plan'].write_text(json.dumps(data)); self.failure(files, output)
            # A later repeated reference must fail despite a previously valid same locator.
            data = deepcopy(base)
            data['groups']['report_local_orphans'][0]['sourceReference']['rulesByteLength'] += 1
            files['plan'].write_text(json.dumps(data)); self.failure(files, output)
            files, data = self.fixture(tmp, 'osv', metadata=True, incomplete=True)
            data['excludedFromOrphanReview'][-1]['sourceReference']['locator'] = 'IgnoredVulns:99'
            files['plan'].write_text(json.dumps(data)); self.failure(files, output)

    def test_hash_matching_malformed_inputs_and_supported_schema_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            files, base = self.fixture(tmp, 'osv', True, True, empty=True)
            cases = [('rules', b'[[PRIVATE'), ('report', b'{"results":{}}'), ('report', b'{"PRIVATE":'),
                     ('metadata', b'{"schemaVersion":2,"rules":{}}'),
                     ('metadata', sidecar(b'', {'IgnoredVulns:0': {'owner': 'PRIVATE'}})),
                     ('metadata', b'{"schemaVersion":1,"rulesSha256":"wrong","rules":{}}'),
                     ('alias-map', b'{"schemaVersion":2,"groups":[]}'),
                     ('alias-map', b'{"schemaVersion":1,"groups":[["CVE-1","GHSA-local"],["CVE-1","CVE-2"]]}'),
                     ('alias-map', b'{"PRIVATE":')]
            for key, raw in cases:
                original = files[key].read_bytes(); files[key].write_bytes(raw)
                data = deepcopy(base); field = {'rules':'rulesSha256','report':'reportSha256','metadata':'metadataSha256','alias-map':'aliasMapSha256'}[key]
                data['provenance'][field] = sha256(raw).hexdigest()
                files['plan'].write_text(json.dumps(data)); self.failure(files, output)
                files[key].write_bytes(original)
            for key, value in [('schemaVersion', True), ('schemaVersion', 1.0), ('schemaVersion', 2),
                               ('reviewOnly', False), ('automaticChangesAllowed', True), ('groups', {}),
                               ('provenance', {'format': 'PRIVATE'})]:
                data = deepcopy(base); data[key] = value
                files['plan'].write_text(json.dumps(data)); self.failure(files, output)
            for raw in (b'{"PRIVATE":', b'null', b'\xff', b'{"schemaVersion":1,"schemaVersion":1}'):
                files['plan'].write_bytes(raw); self.failure(files, output)
            # Native and sidecar reason conflict still fails when all complete hashes agree.
            raw = b'[[IgnoredVulns]]\nid="CVE-1"\nreason="PRIVATE-native"\n'
            files['rules'].write_bytes(raw)
            metadata = sidecar(raw, {'IgnoredVulns:0': {'reason': 'PRIVATE-sidecar'}})
            files['metadata'].write_bytes(metadata)
            data = deepcopy(base); data['provenance'].update(rulesSha256=sha256(raw).hexdigest(), metadataSha256=sha256(metadata).hexdigest())
            files['plan'].write_text(json.dumps(data)); self.failure(files, output)

    def test_output_aliases_to_all_inputs_and_io_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            files, _ = self.fixture(tmp, metadata=True, aliases=True)
            for path in files.values():
                for mode in ('direct', 'symlink', 'hardlink'):
                    output = path if mode == 'direct' else Path(tmp, 'alias')
                    if mode == 'symlink': output.symlink_to(path)
                    if mode == 'hardlink': output.hardlink_to(path)
                    self.failure(files, output)
                    if mode != 'direct': output.unlink()
            output = Path(tmp, 'verified.json'); output.write_bytes(b'previous output')
            for key in files:
                self.failure({**files, key: Path(tmp, 'PRIVATE-missing')}, output)
            self.failure(files, Path(tmp, 'missing-dir', 'verified.json'))
            self.assertFalse(Path(tmp, 'missing-dir').exists())
            directory = Path(tmp, 'directory'); directory.mkdir()
            (directory / 'sentinel').write_bytes(b'keep directory')
            self.failure(files, directory)
            self.assertEqual((directory / 'sentinel').read_bytes(), b'keep directory')
            self.assertEqual(list(Path(tmp).glob('.vulnwrench-ignores-*')), [])

    def test_composition_uses_one_plan_read_and_no_matching_or_context_reaudit(self):
        from vulnwrench.ignoreaudit import cli, verification
        with tempfile.TemporaryDirectory() as tmp:
            files, data = self.fixture(tmp, 'osv', True, True, incomplete=True)
            # These contexts remain unverified by the composed identity command.
            data.update(summary={'findingCount': -1}, asOf='PRIVATE-unverified', coverage='PRIVATE-unverified')
            files['plan'].write_text(json.dumps(data))
            raw_plan = files['plan'].read_bytes()
            args = ['verify-cleanup-inputs', *[v for k, p in files.items() for v in ('--' + k, str(p))]]
            with patch.object(cli, 'read_bytes', wraps=cli.read_bytes) as reads, \
                 patch.object(verification, 'verify_cleanup_source', wraps=verification.verify_cleanup_source) as source, \
                 patch.object(verification, 'verify_cleanup_report', wraps=verification.verify_cleanup_report) as report, \
                 patch.object(verification, 'verify_cleanup_metadata', wraps=verification.verify_cleanup_metadata) as metadata, \
                 patch.object(verification, 'verify_cleanup_alias_map', wraps=verification.verify_cleanup_alias_map) as aliases, \
                 patch.object(cli, 'audit', side_effect=AssertionError('must not rerun matching')), \
                 patch('sys.stdout', new_callable=io.StringIO) as stdout:
                self.assertEqual(cli.main(args), 0)
                self.assertEqual(json.loads(stdout.getvalue()), self.expected(files, 2))
                self.assertEqual([c.args[0] for c in reads.call_args_list].count(str(files['plan'])), 1)
                for verifier in (source, report, metadata, aliases):
                    self.assertEqual(verifier.call_count, 1)
                    self.assertEqual(verifier.call_args.args[0], raw_plan)


if __name__ == '__main__':
    unittest.main()
