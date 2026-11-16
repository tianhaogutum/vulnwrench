"""Literal contracts for declarations that cannot attach to observations."""
from copy import deepcopy
from datetime import date
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from vulnwrench.ignoreaudit import Rule, audit, explain, load_report
from vulnwrench.ignoreaudit.cleanup import cleanup_plan

ROOT = Path(__file__).resolve().parents[2]
ASOF = date(2026, 11, 11)
RULES = b'[[IgnoredVulns]]\nid="GHSA-local"\n'
LOCATOR = 'results[0].packages[0].groups[0].aliases'


def payload():
    return json.loads((ROOT / 'examples/ignores/unbound-osv.json').read_bytes())


def expected_hint(reason='vulnerability_collection_absent_or_null', **overrides):
    return {'ids': ['CVE-1'], 'aliases': ['GHSA-local'], 'locator': LOCATOR,
            'trust': 'untrusted', 'affectsMatching': False, 'ruleAdvisoryListed': True,
            'reason': reason, **overrides}


def parse(value):
    return load_report(json.dumps(value).encode(), 'osv', report_unfiltered=True)


class UnboundAliasHintTests(unittest.TestCase):
    def result(self, value, rule=None, aliases=None):
        rule = rule or Rule('selected', 'GHSA-local')
        return explain([rule], parse(value), rule.key, as_of=ASOF,
                       report_unfiltered=True, aliases=aliases)

    def test_group_only_literal_contract_and_coverage_controls(self):
        for state in ('missing', 'null', 'empty'):
            value = payload()
            package = value['results'][0]['packages'][0]
            if state != 'missing':
                package['vulnerabilities'] = None if state == 'null' else []
            with self.subTest(state=state):
                result = self.result(value)
                self.assertEqual(result['unboundReportAliasHints'], [expected_hint(
                    'no_same_package_id_observation' if state == 'empty' else
                    'vulnerability_collection_absent_or_null')])
                self.assertEqual(result['evidence'], [])
                self.assertEqual(result['matchedEvidenceIds'], [])
                self.assertEqual(result['unknownEvidenceIds'], [])
                self.assertEqual(result['rule']['matchCount'], 0)
                self.assertEqual(result['rule']['unknownMatchCount'], 0)
                self.assertEqual(result['coverage'], 'asserted_unfiltered' if state == 'empty' else 'unknown')
                self.assertEqual('orphan_candidate' in result['rule']['status'], state == 'empty')
                self.assertFalse(result['unusedRuleAssertionAllowed'])

    def test_same_package_binding_only_and_no_duplicate_declarations(self):
        value = payload()
        package = value['results'][0]['packages'][0]
        package['vulnerabilities'] = [{'id': 'CVE-unrelated'}]
        # Neither an alias used as a primary ID nor the same ID in another
        # package binds groups[0]. No reverse or transitive binding.
        package['groups'] += [
            {'ids': ['GHSA-local'], 'aliases': ['GHSA-transitive']},
            {'aliases': ['GHSA-no-ids']},
            {'ids': ['CVE-unrelated', 'CVE-absent', 'CVE-unrelated'], 'aliases': ['GHSA-bound']},
            {'ids': ['CVE-absent'], 'aliases': []},
            {'ids': ['CVE-absent']}]
        value['results'][0]['packages'] += [
            {'package': {'name': 'demo'}, 'vulnerabilities': [{'id': 'CVE-1'}, {'id': 'GHSA-no-ids'}]}]
        result = self.result(value)
        unbound = result['unboundReportAliasHints']
        self.assertEqual(unbound, [
            expected_hint('no_same_package_id_observation'),
            expected_hint('no_same_package_id_observation', ids=['GHSA-local'], aliases=['GHSA-transitive'],
                          locator=LOCATOR.replace('groups[0]', 'groups[1]'), ruleAdvisoryListed=False),
            expected_hint('no_same_package_id_observation', ids=[], aliases=['GHSA-no-ids'],
                          locator=LOCATOR.replace('groups[0]', 'groups[2]'), ruleAdvisoryListed=False)])
        self.assertEqual([len(e['reportAliasHints']) for e in result['evidence']], [1, 0, 0])
        bound_locators = {h['locator'] for e in result['evidence'] for h in e['reportAliasHints']}
        self.assertEqual(bound_locators, {LOCATOR.replace('groups[0]', 'groups[3]')})
        self.assertTrue(bound_locators.isdisjoint(h['locator'] for h in unbound))
        self.assertEqual(result['matchedEvidenceIds'], [])
        self.assertTrue(all(e['decision'] == 'no_match' for e in result['evidence']))
        package['vulnerabilities'] += [{'id': 'CVE-1'}, {'id': 'CVE-1'}]
        result = self.result(value)
        self.assertNotIn(LOCATOR, [h['locator'] for h in result['unboundReportAliasHints']])
        self.assertEqual([e['reportAliasHints'][0]['locator'] for e in result['evidence'][1:3]],
                         [LOCATOR, LOCATOR])
        package['vulnerabilities'] = [{'id': 'GHSA-local'}]
        result = self.result(value, Rule('selected', 'GHSA-transitive'))
        self.assertEqual(result['unboundReportAliasHints'][0]['locator'], LOCATOR)
        self.assertEqual([h['locator'] for h in result['evidence'][0]['reportAliasHints']],
                         [LOCATOR.replace('groups[0]', 'groups[1]')])
        self.assertEqual(result['matchedEvidenceIds'], [])
        self.assertEqual(result['unknownEvidenceIds'], [])

    def test_hints_preserve_audit_evidence_scope_and_cleanup(self):
        for state in ('missing', 'null', 'empty', 'unrelated'):
            value = payload()
            package = value['results'][0]['packages'][0]
            if state != 'missing':
                package['vulnerabilities'] = {'null': None, 'empty': [],
                                              'unrelated': [{'id': 'CVE-other'}]}[state]
            value['results'] += [
                {'source': {}, 'packages': [{'package': {'name': 'demo'}, 'vulnerabilities': [{'id': 'CVE-1'}]}]},
                {'source': {'path': 'app/lock'}, 'packages': [
                    {'package': {'name': 'demo'}, 'vulnerabilities': [{'id': 'CVE-1'}]}]},
                {'source': {'path': 'other/lock'}, 'packages': [
                    {'package': {'name': 'demo'}, 'vulnerabilities': [{'id': 'CVE-1'}]}]}]
            stripped = deepcopy(value)
            del stripped['results'][0]['packages'][0]['groups'][0]['aliases']
            for advisory in ('GHSA-local', 'CVE-1'):
                for aliases in (None, {ident: frozenset({'GHSA-local', 'CVE-1'})
                                       for ident in ('GHSA-local', 'CVE-1')}):
                    rule = Rule('selected', advisory, package='demo', source_dir='app')
                    with self.subTest(state=state, advisory=advisory, mapped=aliases is not None):
                        outputs, audits, plans = [], [], []
                        for data in (value, stripped):
                            report = parse(data)
                            output = self.result(data, rule, aliases)
                            output.pop('unboundReportAliasHints')
                            outputs.append(output)
                            result = audit([rule], report, as_of=ASOF, report_unfiltered=True, aliases=aliases)
                            audits.append(result)
                            result['provenance'] = {'rulesSha256': hashlib.sha256(RULES).hexdigest()}
                            plans.append(cleanup_plan(result, RULES, 'osv'))
                        self.assertEqual(outputs[0], outputs[1])
                        self.assertEqual(audits[0], audits[1])
                        self.assertEqual(plans[0], plans[1])
                        self.assertFalse(plans[0]['unusedRuleAssertionAllowed'])
                        if state in ('missing', 'null'):
                            self.assertEqual(plans[0]['groups']['report_local_orphans'], [])
                        if advisory == 'CVE-1' or aliases:
                            offset = int(state == 'unrelated')
                            self.assertEqual(outputs[0]['matchedEvidenceIds'], [f'finding:{offset + 1}'])
                            self.assertEqual(outputs[0]['unknownEvidenceIds'], [f'finding:{offset}'])

    def test_declaration_order_duplicates_empty_and_non_osv_controls(self):
        value = payload()
        groups = value['results'][0]['packages'][0]['groups']
        groups[0]['ids'] *= 2
        groups[0]['aliases'] *= 2
        groups += [deepcopy(groups[0]), {'ids': ['CVE-1'], 'aliases': []}, {'ids': ['CVE-1']}]
        result = self.result(value)
        self.assertEqual(result['unboundReportAliasHints'], [
            expected_hint(ids=['CVE-1', 'CVE-1'], aliases=['GHSA-local', 'GHSA-local']),
            expected_hint(ids=['CVE-1', 'CVE-1'], aliases=['GHSA-local', 'GHSA-local'],
                          locator=LOCATOR.replace('groups[0]', 'groups[1]'))])
        for data in ({}, {'results': None}, {'results': []}):
            self.assertEqual(self.result(data)['unboundReportAliasHints'], [])
        report = load_report(b'{"SchemaVersion":2,"Results":[]}', 'trivy', report_unfiltered=True)
        self.assertEqual(explain([Rule('line:1', 'CVE-1')], report, 'line:1', as_of=ASOF,
                                 report_unfiltered=True)['unboundReportAliasHints'], [])

    def cli(self, report, *extra):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'ignores', 'explain', '--format', 'osv',
                               '--rules', 'examples/ignores/unbound-osv.toml', '--report', str(report),
                               '--report-unfiltered', '--as-of', ASOF.isoformat(),
                               '--rule-key', 'IgnoredVulns:0', *extra],
                              cwd=ROOT, capture_output=True, timeout=60, text=True)

    def test_cli_exact_locator_digest_and_failure_preservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            report, output = Path(tmp, 'report.json'), Path(tmp, 'output.json')
            raw = (ROOT / 'examples/ignores/unbound-osv.json').read_bytes()
            report.write_bytes(raw)
            proc = self.cli(report, '--output', str(output))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, '')
            result = json.loads(output.read_bytes())
            self.assertEqual(result['unboundReportAliasHints'], [expected_hint()])
            self.assertEqual(result['provenance']['reportSha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(result['provenance']['rulesSha256'], hashlib.sha256(RULES).hexdigest())
            self.assertEqual(result['provenance']['aliases'], 'exact_ids_only')
            self.assertEqual(json.loads(raw)['results'][0]['packages'][0]['groups'][0]['aliases'],
                             result['unboundReportAliasHints'][0]['aliases'])
            for state in ('missing', 'null', 'empty'):
                for field in ('ids', 'aliases'):
                    for bad in (None, {}, 'SECRET', [None], [17], ['SECRET\n'], ['SECRET-*']):
                        value = payload()
                        package = value['results'][0]['packages'][0]
                        if state != 'missing':
                            package['vulnerabilities'] = None if state == 'null' else []
                        package['groups'][0][field] = bad
                        report.write_text(json.dumps(value))
                        output.write_text('keep')
                        with self.subTest(state=state, field=field, bad=bad):
                            proc = self.cli(report, '--output', str(output))
                            self.assertEqual(proc.returncode, 2)
                            self.assertEqual(proc.stdout, '')
                            self.assertNotIn('SECRET', proc.stderr)
                            self.assertNotIn('Traceback', proc.stderr)
                            self.assertEqual(output.read_text(), 'keep')


if __name__ == '__main__':
    unittest.main()
