"""Retained rules/metadata identity only, including zero-reference plans."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
RULES = b'# retained PRIVATE comment\r\nCVE-1\r\n'
RULES_DIGEST = '17e5b81f2b342c9bfab850bbb1a98dd71674d5838e62f4686a7ef117333270c3'
METADATA = (b'{"schemaVersion":1,"rulesSha256":"' + RULES_DIGEST.encode() +
            b'","rules":{"line:2":{"owner":"PRIVATE-team","reason":"PRIVATE-review"}}}\n')
METADATA_DIGEST = 'f2038eaeda27f024befc2a51e9d7182bba0001ae85e96e451f0e3a411a38a16e'


def sidecar(raw_rules, entries=None):
    return json.dumps({'schemaVersion': 1, 'rulesSha256': sha256(raw_rules).hexdigest(),
                       'rules': entries or {}}).encode()


def plan_for(raw_rules, raw_metadata, format):
    return {'schemaVersion': 1, 'tool': 'ignore-audit', 'command': 'cleanup-plan',
            'reviewOnly': True, 'automaticChangesAllowed': False, 'unusedRuleAssertionAllowed': False,
            'provenance': {'format': format, 'rulesSha256': sha256(raw_rules).hexdigest(),
                           'metadataSha256': sha256(raw_metadata).hexdigest()},
            'groups': {'expired': [], 'ownerless': [], 'broad': [], 'report_local_orphans': []},
            'excludedFromOrphanReview': []}


class VerifyCleanupMetadataTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'ignores', *map(str, args)],
                              cwd=ROOT, capture_output=True, timeout=60, text=True)

    def fixtures(self, tmp, raw_rules=RULES, raw_metadata=METADATA, format='trivy'):
        plan, rules, metadata = (Path(tmp, name) for name in ('plan.json', 'PRIVATE.rules', 'PRIVATE.metadata.json'))
        rules.write_bytes(raw_rules)
        metadata.write_bytes(raw_metadata)
        data = plan_for(raw_rules, raw_metadata, format)
        plan.write_text(json.dumps(data))
        return plan, rules, metadata, data

    def verify(self, plan, rules, metadata, *args):
        return self.run_cli('verify-cleanup-metadata', '--plan', plan, '--rules', rules, '--metadata', metadata, *args)

    def success(self, plan, rules, metadata):
        before = {p: p.read_bytes() for p in (plan, rules, metadata)}
        proc = self.verify(plan, rules, metadata)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stderr, '')
        self.assertEqual(json.loads(proc.stdout), {
            'command': 'verify-cleanup-metadata', 'metadataVerified': True,
            'metadataSha256': sha256(before[metadata]).hexdigest(),
            'rulesSha256': sha256(before[rules]).hexdigest(), 'automaticChangesAllowed': False})
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        return proc.stdout

    def failure(self, plan, rules, metadata, output):
        before = {p: p.read_bytes() for p in (plan, rules, metadata, output) if p.is_file()}
        proc = self.verify(plan, rules, metadata, '--output', output)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(proc.stdout, '')
        self.assertTrue(proc.stderr.startswith('vulnwrench ignores: '), proc.stderr)
        for private in ('PRIVATE', str(plan.parent), 'Traceback'):
            self.assertNotIn(private, proc.stderr)
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_literal_valid_empty_and_mismatch_contract(self):
        self.assertEqual(sha256(RULES).hexdigest(), RULES_DIGEST)
        self.assertEqual(sha256(METADATA).hexdigest(), METADATA_DIGEST)
        with tempfile.TemporaryDirectory() as tmp:
            plan, rules, metadata, data = self.fixtures(tmp)
            self.assertFalse(any(data['groups'].values()))
            self.assertEqual(data['excludedFromOrphanReview'], [])
            stdout = self.success(plan, rules, metadata)
            output = Path(tmp, 'verified.json')
            output.write_bytes(b'keep previous output')
            proc = self.verify(plan, rules, metadata, '--output', output)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout + proc.stderr, '')
            self.assertEqual(output.read_text(), stdout)
            for raw in (METADATA + b' ', METADATA.replace(b'PRIVATE-team', b'PRIVATE-edit'),
                        METADATA.replace(b'PRIVATE-review', b'PRIVATE-edited')):
                metadata.write_bytes(raw)
                self.failure(plan, rules, metadata, output)
            metadata.write_bytes(METADATA)
            rules.write_bytes(RULES + b' ')
            self.failure(plan, rules, metadata, output)
            for format in ('trivy', 'osv'):
                plan, rules, metadata, _ = self.fixtures(tmp, b'', sidecar(b''), format)
                self.success(plan, rules, metadata)

    def test_actual_exports_preserve_coverage_and_exclusions(self):
        with tempfile.TemporaryDirectory() as tmp:
            for format, raw_rules, raw_report, raw_metadata in (
                ('trivy', (ROOT / 'examples/ignores/.trivyignore').read_bytes(),
                 (ROOT / 'examples/ignores/trivy.json').read_bytes(), (ROOT / 'examples/ignores/trivy-metadata.json').read_bytes()),
                ('osv', (ROOT / 'examples/ignores/osv-scanner.toml').read_bytes(),
                 (ROOT / 'examples/ignores/osv.json').read_bytes(), (ROOT / 'examples/ignores/osv-metadata.json').read_bytes()),
                ('osv', (ROOT / 'examples/ignores/osv-scanner.toml').read_bytes(),
                 b'{"results":null}', (ROOT / 'examples/ignores/osv-metadata.json').read_bytes()),
                ('osv', b'', b'{"results":[]}', sidecar(b''))):
                plan, rules, metadata, _ = self.fixtures(tmp, raw_rules, raw_metadata, format)
                report = Path(tmp, 'report.json')
                report.write_bytes(raw_report)
                proc = self.run_cli('cleanup-plan', '--format', format, '--rules', rules, '--report', report,
                                    '--metadata', metadata, '--report-unfiltered', '--as-of', '2026-11-11', '--output', plan)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                data = json.loads(plan.read_bytes())
                if raw_report == b'{"results":null}':
                    self.assertEqual(data['coverage'], 'unknown')
                    self.assertEqual(data['groups']['report_local_orphans'], [])
                    self.assertTrue(data['excludedFromOrphanReview'])
                self.success(plan, rules, metadata)

    def test_both_plan_digests_required_even_for_empty_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            for raw_rules, raw_metadata in ((RULES, METADATA), (b'', sidecar(b''))):
                plan, rules, metadata, original = self.fixtures(tmp, raw_rules, raw_metadata)
                output = Path(tmp, 'verified.json')
                output.write_bytes(b'keep previous output')
                for key in ('metadataSha256', 'rulesSha256'):
                    for value in (None, '', '0' * 64, original['provenance'][key].upper(), [], {}, True, 1):
                        data = deepcopy(original)
                        data['provenance'][key] = value
                        plan.write_text(json.dumps(data))
                        self.failure(plan, rules, metadata, output)
                    data = deepcopy(original)
                    del data['provenance'][key]
                    plan.write_text(json.dumps(data))
                    self.failure(plan, rules, metadata, output)

    def test_hash_matching_invalid_metadata_and_native_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp, 'verified.json')
            output.write_bytes(b'keep previous output')
            base = json.loads(METADATA)
            invalid = [b'null', b'[]', b'{"PRIVATE":', b'\xff',
                       b'{"schemaVersion":1,"schemaVersion":1}', b'{"schemaVersion":NaN}']
            for key, values in (
                ('schemaVersion', (None, True, 1.0, 2, 'PRIVATE')),
                ('rulesSha256', (None, '', '0' * 64, RULES_DIGEST.upper(), [], True)),
                ('rules', (None, [], {'line:99': {'owner': 'PRIVATE'}}, {'line:2': None},
                           {'line:2': {'PRIVATE': 'PRIVATE'}}, {'line:2': {'owner': 'PRIVATE\ntext'}},
                           {'line:2': {'reason': ''}}, {'line:2': {'reason': True}})),
                ('PRIVATE', ('PRIVATE',))):
                for value in values:
                    data = deepcopy(base)
                    data[key] = value
                    invalid.append(json.dumps(data).encode())
            for key in ('schemaVersion', 'rulesSha256', 'rules'):
                data = deepcopy(base)
                del data[key]
                invalid.append(json.dumps(data).encode())
            for raw in invalid:
                with self.subTest(raw=raw):
                    plan, rules, metadata, _ = self.fixtures(tmp, RULES, raw)
                    self.failure(plan, rules, metadata, output)
            for format, raw in (('trivy', b'PRIVATE invalid rule'), ('trivy', b'\xff'),
                                ('osv', b'[[PRIVATE'), ('osv', b'PackageOverrides=[]'),
                                ('osv', b'[[IgnoredVulns]]\nid="PRIVATE invalid"')):
                plan, rules, metadata, _ = self.fixtures(tmp, raw, sidecar(raw), format)
                self.failure(plan, rules, metadata, output)
            raw = b'[[IgnoredVulns]]\nid="CVE-1"\nreason="PRIVATE-native"\n'
            for reason in ('PRIVATE-native', 'PRIVATE-conflict'):
                plan, rules, metadata, _ = self.fixtures(tmp, raw,
                    sidecar(raw, {'IgnoredVulns:0': {'reason': reason, 'owner': 'PRIVATE-team'}}), 'osv')
                if reason == 'PRIVATE-native':
                    self.success(plan, rules, metadata)
                else:
                    self.failure(plan, rules, metadata, output)

    def test_unsupported_envelope_and_malformed_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan, rules, metadata, original = self.fixtures(tmp)
            output = Path(tmp, 'verified.json')
            output.write_bytes(b'keep previous output')
            for key, value in ([('schemaVersion', v) for v in (None, True, 1.0, 2, 'PRIVATE')] +
                [('tool', 'PRIVATE'), ('command', 'audit'), ('reviewOnly', False),
                 ('automaticChangesAllowed', True), ('unusedRuleAssertionAllowed', True), ('provenance', [])]):
                data = deepcopy(original)
                data[key] = value
                plan.write_text(json.dumps(data))
                self.failure(plan, rules, metadata, output)
            for value in (None, 'grype', 'PRIVATE', [], {}, True):
                data = deepcopy(original)
                data['provenance']['format'] = value
                plan.write_text(json.dumps(data))
                self.failure(plan, rules, metadata, output)
            for raw in (b'null', b'[]', b'{"PRIVATE":', b'\xff', b'{"schemaVersion":1,"schemaVersion":1}'):
                plan.write_bytes(raw)
                self.failure(plan, rules, metadata, output)

    def test_identity_does_not_certify_plan_decisions_or_read_report_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan, rules, metadata, data = self.fixtures(tmp)
            data.update(coverage='PRIVATE-UNVERIFIED', summary={'findingCount': -1}, groups={},
                        excludedFromOrphanReview=[{'key': 'PRIVATE-UNRESOLVED'}])
            data['provenance'].update(reportSha256='unverified', aliasMapSha256='unverified', aliases='unverified')
            plan.write_text(json.dumps(data))
            self.success(plan, rules, metadata)

    def test_output_aliases_and_io_errors_preserve_all_inputs_and_destinations(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan, rules, metadata, _ = self.fixtures(tmp)
            for path in (plan, rules, metadata):
                for mode in ('direct', 'symlink', 'hardlink'):
                    output = path if mode == 'direct' else Path(tmp, 'alias')
                    if mode == 'symlink':
                        output.symlink_to(path)
                    elif mode == 'hardlink':
                        output.hardlink_to(path)
                    self.failure(plan, rules, metadata, output)
                    if mode != 'direct':
                        output.unlink()
            output = Path(tmp, 'verified.json')
            output.write_bytes(b'keep previous output')
            for index in range(3):
                inputs = [plan, rules, metadata]
                inputs[index] = Path(tmp, 'missing-PRIVATE')
                self.failure(*inputs, output)
            self.failure(plan, rules, metadata, Path(tmp, 'missing-dir/output.json'))
            self.assertFalse(Path(tmp, 'missing-dir').exists())
            directory = Path(tmp, 'output-dir')
            directory.mkdir()
            (directory / 'sentinel').write_bytes(b'keep directory')
            self.failure(plan, rules, metadata, directory)
            self.assertEqual((directory / 'sentinel').read_bytes(), b'keep directory')
            self.assertEqual(list(Path(tmp).glob('.vulnwrench-ignores-*')), [])


if __name__ == '__main__':
    unittest.main()
