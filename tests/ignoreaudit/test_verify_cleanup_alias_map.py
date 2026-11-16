"""Complete retained explicit-local-map identity, without audit or trust claims."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ALIASES = b'{"schemaVersion":1,"groups":[["CVE-1","GHSA-local"],["CVE-2","GHSA-other"]]}\n'
DIGEST = 'db95088e5b406bd9f776d5fbb798985c88de6542b5b604c72013ae2b8027f4b7'


def plan_for(raw, format='trivy'):
    return {'schemaVersion': 1, 'tool': 'ignore-audit', 'command': 'cleanup-plan',
            'reviewOnly': True, 'automaticChangesAllowed': False, 'unusedRuleAssertionAllowed': False,
            'provenance': {'format': format, 'aliases': 'explicit_local_groups',
                           'aliasMapSha256': sha256(raw).hexdigest()},
            'groups': {'expired': [], 'ownerless': [], 'broad': [], 'report_local_orphans': []},
            'excludedFromOrphanReview': []}


class VerifyCleanupAliasMapTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'ignores', *map(str, args)],
                              cwd=ROOT, capture_output=True, timeout=60, text=True)

    def fixtures(self, tmp, raw=ALIASES, format='trivy'):
        plan, aliases = Path(tmp, 'plan.json'), Path(tmp, 'PRIVATE-aliases.json')
        aliases.write_bytes(raw)
        data = plan_for(raw, format)
        plan.write_text(json.dumps(data))
        return plan, aliases, data

    def verify(self, plan, aliases, *args):
        return self.run_cli('verify-cleanup-alias-map', '--plan', plan, '--alias-map', aliases, *args)

    def success(self, plan, aliases):
        before = {p: p.read_bytes() for p in (plan, aliases)}
        proc = self.verify(plan, aliases)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stderr, '')
        self.assertEqual(json.loads(proc.stdout), {
            'command': 'verify-cleanup-alias-map', 'aliasMapVerified': True,
            'aliasMapSha256': sha256(before[aliases]).hexdigest(), 'automaticChangesAllowed': False})
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        return proc.stdout

    def failure(self, plan, aliases, output):
        before = {p: p.read_bytes() for p in (plan, aliases, output) if p.exists()}
        proc = self.verify(plan, aliases, '--output', output)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(proc.stdout, '')
        self.assertTrue(proc.stderr.startswith('vulnwrench ignores: '), proc.stderr)
        for private in ('PRIVATE', str(plan.parent), 'Traceback'):
            self.assertNotIn(private, proc.stderr)
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_literal_valid_empty_and_mismatch_contract(self):
        self.assertEqual(sha256(ALIASES).hexdigest(), DIGEST)
        with tempfile.TemporaryDirectory() as tmp:
            plan, aliases, data = self.fixtures(tmp)
            self.assertFalse(any(data['groups'].values()))
            self.assertEqual(data['excludedFromOrphanReview'], [])
            stdout = self.success(plan, aliases)
            output = Path(tmp, 'verified.json')
            output.write_bytes(b'keep previous output')
            proc = self.verify(plan, aliases, '--output', output)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout + proc.stderr, '')
            self.assertEqual(output.read_text(), stdout)
            for raw in (ALIASES + b' ', ALIASES.replace(b'GHSA-other', b'GHSA-edited')):
                aliases.write_bytes(raw)
                self.failure(plan, aliases, output)
            plan, aliases, _ = self.fixtures(tmp, b'{"schemaVersion":1,"groups":[]}')
            self.success(plan, aliases)

    def test_actual_exports_with_aliases_preserve_coverage_and_exclusions(self):
        with tempfile.TemporaryDirectory() as tmp:
            for format, raw_rules, raw_report in (
                ('trivy', b'GHSA-synthetic-alias', (ROOT / 'examples/ignores/trivy.json').read_bytes()),
                ('osv', b'[[IgnoredVulns]]\nid="GHSA-synthetic-alias"', b'{"results":null}'),
                ('osv', b'[[IgnoredVulns]]\nid="CVE-1"', (ROOT / 'examples/ignores/osv.json').read_bytes()),
                ('osv', b'', b'{"results":[]}')):
                plan, aliases, _ = self.fixtures(tmp, (ROOT / 'examples/ignores/aliases.json').read_bytes(), format)
                rules, report = Path(tmp, 'original.rules'), Path(tmp, 'report.json')
                rules.write_bytes(raw_rules)
                report.write_bytes(raw_report)
                proc = self.run_cli('cleanup-plan', '--format', format, '--rules', rules, '--report', report,
                                    '--alias-map', aliases, '--report-unfiltered', '--as-of', '2026-11-11', '--output', plan)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                data = json.loads(plan.read_bytes())
                if raw_report == b'{"results":null}':
                    self.assertEqual(data['coverage'], 'unknown')
                    self.assertEqual(data['groups']['report_local_orphans'], [])
                    self.assertEqual([c['key'] for c in data['excludedFromOrphanReview']], ['IgnoredVulns:0'])
                self.success(plan, aliases)

    def test_provenance_required_even_with_no_references(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan, aliases, original = self.fixtures(tmp)
            output = Path(tmp, 'verified.json')
            output.write_bytes(b'keep previous output')
            for key, values in (
                ('aliasMapSha256', (None, '', '0' * 64, DIGEST.upper(), [], {}, True, 1)),
                ('aliases', ('exact_ids_only', None, '', [], {}, True, 'PRIVATE-MODE'))):
                for value in values:
                    data = deepcopy(original)
                    data['provenance'][key] = value
                    plan.write_text(json.dumps(data))
                    self.failure(plan, aliases, output)
                data = deepcopy(original)
                del data['provenance'][key]
                plan.write_text(json.dumps(data))
                self.failure(plan, aliases, output)

    def test_unsupported_schema_format_envelope_and_malformed_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan, aliases, original = self.fixtures(tmp)
            output = Path(tmp, 'verified.json')
            output.write_bytes(b'keep previous output')
            mutations = [('schemaVersion', v) for v in (None, True, 1.0, 2, 'PRIVATE-SCHEMA')]
            mutations += [('tool', 'PRIVATE-TOOL'), ('command', 'audit'), ('reviewOnly', False),
                          ('automaticChangesAllowed', True), ('unusedRuleAssertionAllowed', True), ('provenance', [])]
            for key, value in mutations:
                data = deepcopy(original)
                data[key] = value
                plan.write_text(json.dumps(data))
                self.failure(plan, aliases, output)
            for value in (None, 'grype', 'PRIVATE-FORMAT', [], {}, True):
                data = deepcopy(original)
                data['provenance']['format'] = value
                plan.write_text(json.dumps(data))
                self.failure(plan, aliases, output)
            for raw in (b'null', b'[]', b'{"PRIVATE":', b'\xff',
                        b'{"schemaVersion":1,"schemaVersion":1}', b'{"schemaVersion":NaN}'):
                plan.write_bytes(raw)
                self.failure(plan, aliases, output)

    def test_hash_matching_malformed_overlapping_and_unsupported_maps(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp, 'verified.json')
            output.write_bytes(b'keep previous output')
            maps = [b'null', b'[]', b'{"PRIVATE":', b'\xff',
                    b'{"schemaVersion":1,"schemaVersion":1,"groups":[]}', b'{"schemaVersion":NaN,"groups":[]}']
            maps += [json.dumps(data).encode() for data in (
                {'schemaVersion': v, 'groups': []} for v in (None, True, 1.0, 2, 'PRIVATE-SCHEMA'))]
            maps += [json.dumps({'schemaVersion': 1, 'groups': groups}).encode() for groups in (
                None, {}, [None], [[]], [['CVE-1']], [['CVE-1', 'CVE-1']],
                [['CVE-1', 'GHSA-local'], ['GHSA-local', 'CVE-2']],
                [['CVE-1', 'PRIVATE INVALID']], [['CVE-1', None]], [['CVE-1', {}]])]
            maps += [b'{"schemaVersion":1}', b'{"schemaVersion":1,"groups":[],"PRIVATE":"PRIVATE-VALUE"}']
            for raw in maps:
                with self.subTest(raw=raw):
                    plan, aliases, _ = self.fixtures(tmp, raw)
                    self.failure(plan, aliases, output)

    def test_only_alias_identity_is_checked_no_matching_or_report_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan, aliases, data = self.fixtures(tmp)
            # Identity deliberately does not certify these contexts or references.
            data.update(coverage='PRIVATE-UNVERIFIED', summary={'findingCount': -1}, groups={},
                        excludedFromOrphanReview=[{'key': 'PRIVATE-UNRESOLVED'}])
            data['provenance'].update(reportSha256='unverified', rulesSha256='unverified')
            plan.write_text(json.dumps(data))
            self.success(plan, aliases)

    def test_output_aliases_and_io_errors_preserve_inputs_and_destinations(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan, aliases, _ = self.fixtures(tmp)
            for path in (plan, aliases):
                for mode in ('direct', 'symlink', 'hardlink'):
                    output = path if mode == 'direct' else Path(tmp, 'alias')
                    if mode == 'symlink':
                        output.symlink_to(path)
                    elif mode == 'hardlink':
                        output.hardlink_to(path)
                    self.failure(plan, aliases, output)
                    if mode != 'direct':
                        output.unlink()
            output = Path(tmp, 'verified.json')
            output.write_bytes(b'keep previous output')
            self.failure(Path(tmp, 'missing-plan'), aliases, output)
            self.failure(plan, Path(tmp, 'missing-aliases'), output)
            self.failure(plan, aliases, Path(tmp, 'missing-dir', 'output.json'))
            self.assertFalse(Path(tmp, 'missing-dir').exists())
            output_dir = Path(tmp, 'output-dir')
            output_dir.mkdir()
            (output_dir / 'sentinel').write_bytes(b'keep directory')
            proc = self.verify(plan, aliases, '--output', output_dir)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertEqual(proc.stdout, '')
            self.assertEqual((output_dir / 'sentinel').read_bytes(), b'keep directory')
            self.assertEqual(list(Path(tmp).glob('.vulnwrench-ignores-*')), [])


if __name__ == '__main__':
    unittest.main()
