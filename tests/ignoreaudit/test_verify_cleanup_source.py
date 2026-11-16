"""Literal retained-source identity contracts; no report/cleanup decision attestation."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TRIVY = '# café PRIVATE-COMMENT\r\n CVE-1 exp:2026-11-10 # PRIVATE-NOTE\r\nCVE-2\r\nCVE-1'.encode()
OSV = ('# PRIVATE-COMMENT\r\n[["IgnoredVulns"]]\r\nid="CVE-1"\r\neffectiveUntil=2026-11-10\r\n'
       'reason="PRIVATE-REASON"\r\n[[IgnoredVulns]]\r\nid="CVE-1"\r\n'
       '[[IgnoredVulns]]\r\nid="CVE-2"\r\nreason="PRIVATE-REASON"').encode()


class VerifyCleanupSourceTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'ignores', *map(str, args)],
                              cwd=ROOT, capture_output=True, timeout=60, text=True)

    def export(self, tmp, raw=TRIVY, format='trivy', report=None, annotate=False, metadata_rules=None):
        rules, report_path, plan_path = (Path(tmp, name) for name in ('retained-original-rules', 'report.json', 'cleanup.json'))
        rules.write_bytes(raw)
        report_path.write_text(json.dumps(report if report is not None else {'SchemaVersion': 2, 'Results': []}))
        options = []
        if annotate or metadata_rules:
            metadata = Path(tmp, 'metadata.json')
            metadata.write_text(json.dumps({'schemaVersion': 1, 'rulesSha256': sha256(raw).hexdigest(),
                                            'rules': metadata_rules or {'IgnoredVulns:2': {'owner': 'PRIVATE-OWNER'}}}))
            options = ['--metadata', metadata]
        proc = self.run_cli('cleanup-plan', '--format', format, '--rules', rules, '--report', report_path,
                            '--report-unfiltered', '--as-of', '2026-11-11', '--output', plan_path, *options)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return rules, plan_path, json.loads(plan_path.read_text())

    def verify(self, rules, plan, *args):
        return self.run_cli('verify-cleanup-source', '--plan', plan, '--rules', rules, *args)

    def success(self, rules, plan, count):
        before = {p: p.read_bytes() for p in (rules, plan)}
        proc = self.verify(rules, plan)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stderr, '')
        self.assertEqual(json.loads(proc.stdout), {
            'command': 'verify-cleanup-source', 'sourceVerified': True,
            'rulesSha256': sha256(rules.read_bytes()).hexdigest(),
            'verifiedReferenceCount': count, 'automaticChangesAllowed': False})
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        return proc.stdout

    def failure(self, rules, plan, output):
        output.write_bytes(b'keep previous result')
        before = {p: p.read_bytes() for p in (rules, plan, output)}
        proc = self.verify(rules, plan, '--output', output)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(proc.stdout, '')
        self.assertTrue(proc.stderr.startswith('vulnwrench ignores: '))
        self.assertNotIn('PRIVATE', proc.stderr)
        self.assertNotIn('Traceback', proc.stderr)
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_literal_trivy_contract_duplicate_locators_and_repeated_groups(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules, plan, data = self.export(tmp)
            self.assertEqual([c['rule']['key'] for c in data['groups']['ownerless']], ['line:2', 'line:3', 'line:4'])
            self.assertEqual([c['rule']['rule'] for c in data['groups']['ownerless']], ['CVE-1', 'CVE-2', 'CVE-1'])
            self.assertEqual(sha256(TRIVY).hexdigest(), 'ae0cb06414170bd161efb160579c88a7318ffb65abcd62a218d09777214679f1')
            stdout = self.success(rules, plan, 3)
            self.assertEqual(stdout, self.success(rules, plan, 3))
            output = Path(tmp, 'verified.json')
            proc = self.verify(rules, plan, '--output', output)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, '')
            self.assertEqual(output.read_text(), stdout)

    def test_osv_native_indices_include_exclusion_only_and_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules, plan, data = self.export(tmp, OSV, 'osv', {'results': None}, annotate=True)
            self.assertEqual([c['rule']['key'] for c in data['groups']['ownerless']], ['IgnoredVulns:0', 'IgnoredVulns:1'])
            self.assertEqual([c['key'] for c in data['excludedFromOrphanReview']],
                             ['IgnoredVulns:0', 'IgnoredVulns:1', 'IgnoredVulns:2'])
            self.success(rules, plan, 3)

    def test_comment_byte_and_line_endings_are_source_mismatches(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules, plan, _ = self.export(tmp)
            for raw in (TRIVY.replace(b'COMMENT', b'COMMENX'), TRIVY.replace(b'\r\n', b'\n')):
                with self.subTest(raw=raw):
                    rules.write_bytes(raw)
                    self.failure(rules, plan, Path(tmp, 'verified.json'))

    def test_every_reference_is_checked_before_deduplication(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules, plan, original = self.export(tmp, OSV, 'osv', {'results': None})
            positions = [(g, i) for g, entries in original['groups'].items() for i in range(len(entries))]
            positions += [(None, i) for i in range(len(original['excludedFromOrphanReview']))]
            mutations = [('rulesSha256', '0' * 64), ('rulesByteLength', len(OSV) + 1),
                         ('rulesByteLength', True), ('rulesByteLength', float(len(OSV))),
                         ('format', 'trivy'), ('locatorConvention', 'utf8_splitlines_1_based'),
                         ('locator', 'IgnoredVulns:1'), ('locator', 'IgnoredVulns:99'),
                         ('locator', 'IgnoredVulns:-1'), ('locator', 'IgnoredVulns:00'),
                         ('locator', 'IgnoredVulns:+0'), ('locator', 'IgnoredVulns:０'),
                         ('locator', 'IgnoredVulns:0\n'), ('locator', []), ('locator', 'PRIVATE-LOCATOR')]
            for group, index in positions:
                for key, value in mutations:
                    if key == 'locator' and value == 'IgnoredVulns:1' and index == 1 and group != 'expired':
                        value = 'IgnoredVulns:0'
                    with self.subTest(group=group, index=index, key=key, value=value):
                        data = deepcopy(original)
                        entry = data['groups'][group][index] if group else data['excludedFromOrphanReview'][index]
                        entry['sourceReference'][key] = value
                        plan.write_text(json.dumps(data))
                        self.failure(rules, plan, Path(tmp, 'verified.json'))
            for group, entries in original['groups'].items():
                for i in range(len(entries)):
                    data = deepcopy(original)
                    data['groups'][group][i]['rule']['rule'] = 'PRIVATE-ADVISORY'
                    plan.write_text(json.dumps(data))
                    self.failure(rules, plan, Path(tmp, 'verified.json'))

    def test_trivy_locators_must_resolve_rules_and_match_recorded_advisory(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules, plan, original = self.export(tmp)
            for locator in ('line:0', 'line:02', 'line:1', 'line:5', 'line:-1', 'line:٢', 'line:2\n', 'IgnoredVulns:0'):
                data = deepcopy(original)
                entry = data['groups']['expired'][0]
                entry['sourceReference']['locator'] = entry['rule']['key'] = locator
                plan.write_text(json.dumps(data))
                self.failure(rules, plan, Path(tmp, 'verified.json'))
            data = deepcopy(original)
            data['groups']['expired'][0]['sourceReference']['locator'] = 'line:3'
            data['groups']['expired'][0]['rule']['key'] = 'line:3'
            plan.write_text(json.dumps(data))
            self.failure(rules, plan, Path(tmp, 'verified.json'))

    def test_empty_plans_still_verify_complete_source_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            for format, report in (('trivy', {'SchemaVersion': 2, 'Results': []}), ('osv', {'results': []})):
                rules, plan, _ = self.export(tmp, b'', format, report)
                self.success(rules, plan, 0)
                rules.write_bytes(b'# PRIVATE-COMMENT')
                self.failure(rules, plan, Path(tmp, 'verified.json'))
            # Zero references can also occur for a nonempty, fully annotated matched rule.
            rules, plan, original = self.export(tmp, b'CVE-1', report={
                'SchemaVersion': 2, 'Results': [{'Vulnerabilities': [{'VulnerabilityID': 'CVE-1', 'PkgName': 'demo'}]}]},
                metadata_rules={'line:1': {'owner': 'PRIVATE-OWNER', 'reason': 'PRIVATE-REASON'}})
            self.assertTrue(all(not entries for entries in original['groups'].values()))
            self.assertEqual(original['excludedFromOrphanReview'], [])
            self.success(rules, plan, 0)
            original['provenance']['rulesSha256'] = '0' * 64
            plan.write_text(json.dumps(original))
            self.failure(rules, plan, Path(tmp, 'verified.json'))

    def test_unsupported_or_malformed_plan_is_redacted_and_preserves_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules, plan, original = self.export(tmp)
            changes = [('schemaVersion', v) for v in (None, True, 1.0, 2, 'PRIVATE-SCHEMA')]
            changes += [('command', 'audit'), ('tool', 'other'), ('reviewOnly', False),
                        ('automaticChangesAllowed', True), ('unusedRuleAssertionAllowed', True),
                        ('groups', {}), ('groups', []), ('excludedFromOrphanReview', None), ('provenance', [])]
            for key, value in changes:
                with self.subTest(key=key, value=value):
                    data = deepcopy(original)
                    data[key] = value
                    plan.write_text(json.dumps(data))
                    self.failure(rules, plan, Path(tmp, 'verified.json'))
            for raw in (b'null', b'[]', b'{"PRIVATE":', b'\xff',
                        b'{"schemaVersion":1,"schemaVersion":1}', b'{"schemaVersion":NaN}'):
                plan.write_bytes(raw)
                self.failure(rules, plan, Path(tmp, 'verified.json'))
            for container, key in ((original, 'groups'), (original['provenance'], 'rulesSha256'),
                                   (original['groups']['expired'][0], 'sourceReference')):
                value = container.pop(key)
                plan.write_text(json.dumps(original))
                self.failure(rules, plan, Path(tmp, 'verified.json'))
                container[key] = value

    def test_malformed_nested_entries_and_hash_matching_invalid_rules_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules, plan, original = self.export(tmp, OSV, 'osv', {'results': None})
            for container in ('candidate', 'rule', 'reference', 'exclusion'):
                for value in (None, [], 'PRIVATE-INVALID'):
                    data = deepcopy(original)
                    if container == 'candidate':
                        data['groups']['expired'][0] = value
                    elif container == 'exclusion':
                        data['excludedFromOrphanReview'][0] = value
                    else:
                        data['groups']['expired'][0]['rule' if container == 'rule' else 'sourceReference'] = value
                    plan.write_text(json.dumps(data))
                    self.failure(rules, plan, Path(tmp, 'verified.json'))
            for format, raw in (('trivy', b'CVE-1 exp:PRIVATE-INVALID'), ('trivy', b'\xff'),
                                ('osv', b'[[IgnoredVulns]]\nid="PRIVATE INVALID"'),
                                ('osv', b'PRIVATE-KEY="PRIVATE-VALUE"'), ('osv', b'[[PRIVATE')):
                rules, plan, data = self.export(tmp, b'', format,
                                               {'SchemaVersion': 2, 'Results': []} if format == 'trivy' else {'results': []})
                rules.write_bytes(raw)
                data['provenance']['rulesSha256'] = sha256(raw).hexdigest()
                plan.write_text(json.dumps(data))
                self.failure(rules, plan, Path(tmp, 'verified.json'))

    def test_output_aliases_cannot_mutate_plan_or_retained_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules, plan, _ = self.export(tmp)
            for path in (rules, plan):
                for mode in ('direct', 'symlink', 'hardlink'):
                    output = path if mode == 'direct' else Path(tmp, 'alias')
                    if mode == 'symlink':
                        output.symlink_to(path)
                    elif mode == 'hardlink':
                        output.hardlink_to(path)
                    before = {p: p.read_bytes() for p in (rules, plan)}
                    proc = self.verify(rules, plan, '--output', output)
                    self.assertEqual(proc.returncode, 2, proc.stderr)
                    self.assertEqual(proc.stdout, '')
                    self.assertEqual(before, {p: p.read_bytes() for p in before})
                    if mode != 'direct':
                        output.unlink()


if __name__ == '__main__':
    unittest.main()
