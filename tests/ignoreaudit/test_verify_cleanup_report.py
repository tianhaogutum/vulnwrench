"""Retained report identity contracts, independent of coverage and review decisions."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TRIVY = b'{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1","Title":"PRIVATE-TITLE"}]}]}\n'
DIGEST = '4ed478a4fdb0d741dfe6c789bcee4c98e09087b3523f248e9ff8179086daf34f'


def plan_for(raw, format='trivy'):
    return {'schemaVersion': 1, 'tool': 'ignore-audit', 'command': 'cleanup-plan',
            'reviewOnly': True, 'automaticChangesAllowed': False, 'unusedRuleAssertionAllowed': False,
            'provenance': {'format': format, 'reportSha256': sha256(raw).hexdigest()},
            'groups': {'expired': [], 'ownerless': [], 'broad': [], 'report_local_orphans': []},
            'excludedFromOrphanReview': []}


class VerifyCleanupReportTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'ignores', *map(str, args)],
                              cwd=ROOT, capture_output=True, timeout=60, text=True)

    def fixtures(self, tmp, raw=TRIVY, format='trivy'):
        plan, report = Path(tmp, 'plan.json'), Path(tmp, 'PRIVATE-report.json')
        report.write_bytes(raw)
        data = plan_for(raw, format)
        plan.write_text(json.dumps(data))
        return plan, report, data

    def verify(self, plan, report, *args):
        return self.run_cli('verify-cleanup-report', '--plan', plan, '--report', report, *args)

    def success(self, plan, report):
        before = {p: p.read_bytes() for p in (plan, report)}
        proc = self.verify(plan, report)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stderr, '')
        # Exact output excludes coverage, findings, source status and permission claims.
        self.assertEqual(json.loads(proc.stdout), {
            'command': 'verify-cleanup-report', 'reportVerified': True,
            'reportSha256': sha256(before[report]).hexdigest(), 'automaticChangesAllowed': False})
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        return proc.stdout

    def failure(self, plan, report, output, *args):
        before = {p: p.read_bytes() for p in (plan, report, output) if p.exists()}
        proc = self.verify(plan, report, '--output', output, *args)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(proc.stdout, '')
        self.assertTrue(proc.stderr.startswith('vulnwrench ignores: '), proc.stderr)
        self.assertNotIn('PRIVATE', proc.stderr)
        self.assertNotIn(str(plan.parent), proc.stderr)
        self.assertNotIn('Traceback', proc.stderr)
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_literal_valid_empty_and_mismatch_contract(self):
        self.assertEqual(sha256(TRIVY).hexdigest(), DIGEST)
        with tempfile.TemporaryDirectory() as tmp:
            plan, report, data = self.fixtures(tmp)
            self.assertTrue(all(not entries for entries in data['groups'].values()))
            stdout = self.success(plan, report)
            output = Path(tmp, 'verified.json')
            output.write_bytes(b'keep previous output')
            proc = self.verify(plan, report, '--output', output)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout + proc.stderr, '')
            self.assertEqual(output.read_text(), stdout)
            for raw in (TRIVY.replace(b'TITLE', b'TITLX'), TRIVY + b' '):
                report.write_bytes(raw)
                self.failure(plan, report, output)

    def test_incomplete_and_empty_native_collections_verify_identity_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            reports = [('trivy', {'SchemaVersion': 2, **extra}) for extra in ({}, {'Results': None}, {'Results': []})]
            reports += [('osv', extra) for extra in ({}, {'results': None}, {'results': []})]
            for extra in ({}, {'vulnerabilities': None}, {'vulnerabilities': []}):
                reports.append(('osv', {'results': [{'source': {'path': 'app/lock'}, 'packages': [
                    {'package': {'name': 'demo'}, 'groups': [{'ids': ['CVE-1'], 'aliases': ['GHSA-local']}], **extra},
                    {'package': {'name': 'other'}, 'vulnerabilities': [{'id': 'CVE-2'}]}]}]}))
            for format, report_data in reports:
                with self.subTest(format=format, report=report_data):
                    plan, report, _ = self.fixtures(tmp, json.dumps(report_data).encode(), format)
                    self.success(plan, report)

    def test_actual_cleanup_exports_preserve_unknown_coverage_and_exclusions(self):
        with tempfile.TemporaryDirectory() as tmp:
            for format, raw, report_data in (
                ('trivy', b'CVE-1', {'SchemaVersion': 2, 'Results': []}),
                ('osv', b'[[IgnoredVulns]]\nid="CVE-1"', {'results': None}),
                ('osv', b'', {'results': []})):
                plan, report, _ = self.fixtures(tmp, json.dumps(report_data).encode(), format)
                rules = Path(tmp, 'original.rules')
                rules.write_bytes(raw)
                proc = self.run_cli('cleanup-plan', '--format', format, '--rules', rules, '--report', report,
                                    '--report-unfiltered', '--as-of', '2026-11-11', '--output', plan)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                data = json.loads(plan.read_bytes())
                if report_data == {'results': None}:
                    self.assertEqual(data['coverage'], 'unknown')
                    self.assertEqual(data['summary']['findingCount'], 0)
                    self.assertEqual(data['groups']['report_local_orphans'], [])
                    self.assertEqual([c['key'] for c in data['excludedFromOrphanReview']], ['IgnoredVulns:0'])
                self.success(plan, report)

    def test_missing_wrong_and_type_invalid_provenance_even_with_zero_references(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan, report, original = self.fixtures(tmp)
            output = Path(tmp, 'verified.json')
            output.write_bytes(b'keep previous output')
            for value in (None, '', '0' * 64, DIGEST.upper(), [], {}, True, 1):
                data = deepcopy(original)
                data['provenance']['reportSha256'] = value
                plan.write_text(json.dumps(data))
                self.failure(plan, report, output)
            del original['provenance']['reportSha256']
            plan.write_text(json.dumps(original))
            self.failure(plan, report, output)

    def test_unknown_plan_schema_format_and_unsafe_envelope_fail_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan, report, original = self.fixtures(tmp)
            output = Path(tmp, 'verified.json')
            output.write_bytes(b'keep previous output')
            mutations = [('schemaVersion', v) for v in (None, True, 1.0, 2, 'PRIVATE-SCHEMA')]
            mutations += [('tool', 'PRIVATE-TOOL'), ('command', 'audit'), ('reviewOnly', False),
                          ('automaticChangesAllowed', True), ('unusedRuleAssertionAllowed', True), ('provenance', [])]
            for key, value in mutations:
                data = deepcopy(original)
                data[key] = value
                plan.write_text(json.dumps(data))
                self.failure(plan, report, output)
            for value in (None, 'grype', 'PRIVATE-FORMAT', [], {}, True):
                data = deepcopy(original)
                data['provenance']['format'] = value
                plan.write_text(json.dumps(data))
                self.failure(plan, report, output)
            for raw in (b'null', b'[]', b'{"PRIVATE":', b'\xff',
                        b'{"schemaVersion":1,"schemaVersion":1}', b'{"schemaVersion":NaN}'):
                plan.write_bytes(raw)
                self.failure(plan, report, output)

    def test_hash_matching_malformed_or_wrong_native_reports_still_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp, 'verified.json')
            output.write_bytes(b'keep previous output')
            reports = [('trivy', raw) for raw in (b'null', b'[]', b'{"PRIVATE":', b'\xff',
                b'{"SchemaVersion":2,"SchemaVersion":2}', b'{"SchemaVersion":NaN}', b'{"SchemaVersion":1}',
                b'{"results":[]}', b'{"SchemaVersion":2,"Results":{}}',
                b'{"SchemaVersion":2,"PRIVATE-STRUCTURE":"PRIVATE-VALUE"}',
                b'{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"PRIVATE INVALID"}]}]}')]
            reports += [('osv', raw) for raw in (b'{"SchemaVersion":2,"Results":[]}',
                b'{"results":{}}', b'{"results":[{"source":{},"packages":null}]}',
                b'{"results":[{"source":{},"packages":[{"package":{},"vulnerabilities":{}}]}]}',
                b'{"results":[{"source":{},"packages":[{"package":{},"groups":[{"aliases":["PRIVATE INVALID"]}]}]}]}')]
            for format, raw in reports:
                with self.subTest(format=format, raw=raw):
                    plan, report, _ = self.fixtures(tmp, raw, format)
                    self.failure(plan, report, output)

    def test_output_aliases_and_io_errors_preserve_inputs_and_destinations(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan, report, _ = self.fixtures(tmp)
            for path in (plan, report):
                for mode in ('direct', 'symlink', 'hardlink'):
                    output = path if mode == 'direct' else Path(tmp, 'alias')
                    if mode == 'symlink':
                        output.symlink_to(path)
                    elif mode == 'hardlink':
                        output.hardlink_to(path)
                    self.failure(plan, report, output)
                    if mode != 'direct':
                        output.unlink()
            output = Path(tmp, 'verified.json')
            output.write_bytes(b'keep previous output')
            self.failure(Path(tmp, 'missing-plan'), report, output)
            self.failure(plan, Path(tmp, 'missing-report'), output)
            self.failure(plan, report, Path(tmp, 'missing-dir', 'output.json'))
            self.assertFalse(Path(tmp, 'missing-dir').exists())
            output_dir = Path(tmp, 'output-dir')
            output_dir.mkdir()
            (output_dir / 'sentinel').write_bytes(b'keep directory')
            proc = self.verify(plan, report, '--output', output_dir)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertEqual(proc.stdout, '')
            self.assertEqual((output_dir / 'sentinel').read_bytes(), b'keep directory')
            self.assertEqual(list(Path(tmp).glob('.vulnwrench-ignores-*')), [])


if __name__ == '__main__':
    unittest.main()
