"""Structural coverage diagnostics must not become observation evidence."""
from copy import deepcopy
from dataclasses import replace
from datetime import date
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from vulnwrench.ignoreaudit import Rule, audit, explain, load_report
from vulnwrench.ignoreaudit.cleanup import cleanup_plan

ROOT = Path(__file__).resolve().parents[2]
ASOF = date(2026, 11, 11)
RULES = b'[[IgnoredVulns]]\nid="GHSA-local"\n'
COLLECTION = 'results[0].packages[0].vulnerabilities'


def package(**fields):
    return {'package': {'name': 'demo'}, **fields}


def group_only():
    return {'results': [{'source': {'path': 'app/lock'}, 'packages': [package(
        groups=[{'ids': ['CVE-1'], 'aliases': ['GHSA-local']}])]}]}


def mixed():
    return {'results': [
        {'source': {'path': 'app/lock'}, 'packages': [
            package(vulnerabilities=[{'id': 'CVE-1', 'aliases': ['GHSA-direct']}],
                    groups=[{'ids': ['CVE-1'], 'aliases': ['GHSA-local']}]),
            group_only()['results'][0]['packages'][0],
            package(vulnerabilities=[{'id': 'CVE-other'}]),
            package(vulnerabilities=None), package(vulnerabilities=[])]},
        {'source': {}, 'packages': [package(vulnerabilities=None),
                                   package(vulnerabilities=[{'id': 'CVE-1'}])]},
        {'source': {'path': 'app/lock'}, 'packages': [
            package(vulnerabilities=[{'id': 'CVE-1'}]), package()]}]}


MIXED_GAPS = [
    {'locator': 'results[0].packages[1].vulnerabilities', 'state': 'absent'},
    {'locator': 'results[0].packages[3].vulnerabilities', 'state': 'null'},
    {'locator': 'results[1].packages[0].vulnerabilities', 'state': 'null'},
    {'locator': 'results[2].packages[1].vulnerabilities', 'state': 'absent'}]


def parse(value, format='osv'):
    return load_report(json.dumps(value).encode(), format, report_unfiltered=True)


class CoverageGapTests(unittest.TestCase):
    def result(self, report, rule=None, aliases=None):
        rule = rule or Rule('selected', 'GHSA-local')
        return explain([rule], report, rule.key, as_of=ASOF,
                       report_unfiltered=True, aliases=aliases)

    def test_package_absent_null_empty_literal_contract(self):
        for state in ('absent', 'null', 'empty'):
            value = group_only()
            if state != 'absent':
                value['results'][0]['packages'][0]['vulnerabilities'] = None if state == 'null' else []
            with self.subTest(state=state):
                result = self.result(parse(value))
                self.assertEqual(result['coverageGaps'], [] if state == 'empty' else [
                    {'locator': COLLECTION, 'state': state}])
                self.assertEqual(result['coverage'], 'asserted_unfiltered' if state == 'empty' else 'unknown')
                self.assertEqual(result['evidence'], [])
                self.assertEqual(result['matchedEvidenceIds'], [])
                self.assertEqual(result['unknownEvidenceIds'], [])
                self.assertEqual(result['rule']['matchCount'], 0)
                self.assertEqual(result['rule']['unknownMatchCount'], 0)
                self.assertEqual('orphan_candidate' in result['rule']['status'], state == 'empty')
                self.assertFalse(result['unusedRuleAssertionAllowed'])
                self.assertEqual(result['unboundReportAliasHints'], [{
                    'ids': ['CVE-1'], 'aliases': ['GHSA-local'],
                    'locator': 'results[0].packages[0].groups[0].aliases',
                    'trust': 'untrusted', 'affectsMatching': False, 'ruleAdvisoryListed': True,
                    'reason': 'no_same_package_id_observation' if state == 'empty' else
                              'vulnerability_collection_absent_or_null'}])
                expected_notes = [
                    'Coverage is a caller assertion, not independently verifiable; candidates are limited to this report.',
                    'Matching uses exact advisory IDs unless an explicit local alias map is supplied; unmatched aliases are not proof of unused suppressions.']
                if state != 'empty':
                    expected_notes.append('OSV vulnerability collections absent/null at: ' + COLLECTION +
                                          '; coverage is unknown and no orphan candidates can be established.')
                self.assertEqual(result['notes'], expected_notes)

    def test_root_absent_null_empty_and_trivy_optional_boundary(self):
        for format, field, base in (('osv', 'results', {}), ('trivy', 'Results', {'SchemaVersion': 2})):
            for state in ('absent', 'null', 'empty'):
                value = dict(base)
                if state != 'absent':
                    value[field] = None if state == 'null' else []
                with self.subTest(format=format, state=state):
                    result = self.result(parse(value, format))
                    self.assertEqual(result['coverageGaps'], [] if state == 'empty' else [
                        {'locator': field, 'state': state}])
                    self.assertEqual(result['coverage'], 'asserted_unfiltered' if state == 'empty' else 'unknown')
                    self.assertEqual(result['evidence'], [])
                    self.assertEqual(result['unboundReportAliasHints'], [])
                    self.assertFalse(result['unusedRuleAssertionAllowed'])
                    self.assertEqual('Result collection is absent/null: no orphan candidates can be established.'
                                     in result['notes'], state != 'empty')
        # Trivy's per-result optional arrays already mean known-empty. Diagnostics
        # describe existing coverage gaps; they must not change that convention.
        result = self.result(parse({'SchemaVersion': 2, 'Results': [{}, {'Vulnerabilities': None},
                                   {'Vulnerabilities': []}]}, 'trivy'))
        self.assertEqual(result['coverageGaps'], [])
        self.assertEqual(result['coverage'], 'asserted_unfiltered')

    def test_mixed_order_evidence_and_diagnostic_removal_parity(self):
        report = parse(mixed())
        plain = replace(report, coverage_gaps=())
        explicit = {ident: frozenset({'CVE-1', 'GHSA-local'}) for ident in ('CVE-1', 'GHSA-local')}
        for advisory in ('CVE-1', 'GHSA-local', 'CVE-unobserved'):
            for aliases in (None, explicit):
                for scope in (None, 'app'):
                    with self.subTest(advisory=advisory, mapped=bool(aliases), scope=scope):
                        rule = Rule('selected', advisory, package='demo', source_dir=scope)
                        result = self.result(report, rule, aliases)
                        self.assertEqual(result.pop('coverageGaps'), MIXED_GAPS)
                        without = self.result(plain, rule, aliases)
                        self.assertEqual(without.pop('coverageGaps'), [])
                        self.assertEqual(result, without)
                        audits = [audit([rule], r, as_of=ASOF, report_unfiltered=True, aliases=aliases)
                                  for r in (report, plain)]
                        self.assertEqual(audits[0], audits[1])
                        plans = []
                        for a in audits:
                            a['provenance'] = {'rulesSha256': hashlib.sha256(RULES).hexdigest()}
                            plans.append(cleanup_plan(a, RULES, 'osv'))
                        self.assertEqual(plans[0], plans[1])
                        self.assertEqual(plans[0]['groups']['report_local_orphans'], [])
                        self.assertFalse(plans[0]['unusedRuleAssertionAllowed'])
                        self.assertEqual(result['coverage'], 'unknown')
                        if advisory == 'CVE-unobserved' or advisory == 'GHSA-local' and aliases is None:
                            self.assertEqual(result['matchedEvidenceIds'], [])
                            self.assertEqual(result['unknownEvidenceIds'], [])
                            self.assertEqual(len(plans[0]['excludedFromOrphanReview']), 1)
                        elif scope == 'app':
                            self.assertEqual(result['matchedEvidenceIds'], ['finding:0', 'finding:3'])
                            self.assertEqual(result['unknownEvidenceIds'], ['finding:2'])
                            self.assertEqual([e['decision'] for e in result['evidence']],
                                             ['match', 'no_match', 'unknown', 'match'])
        self.assertEqual([f.locator for f in report.findings], [
            'results[0].packages[0].vulnerabilities[0]', 'results[0].packages[2].vulnerabilities[0]',
            'results[1].packages[1].vulnerabilities[0]', 'results[2].packages[0].vulnerabilities[0]'])
        self.assertEqual(len(report.findings[0].alias_hints), 2)
        self.assertEqual(len(report.unbound_alias_hints), 1)

    def cli(self, report, output):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'ignores', 'explain', '--format', 'osv',
                               '--rules', 'examples/ignores/unbound-osv.toml', '--report', str(report),
                               '--report-unfiltered', '--as-of', ASOF.isoformat(),
                               '--rule-key', 'IgnoredVulns:0', '--output', str(output)],
                              cwd=ROOT, capture_output=True, timeout=60)

    def test_cli_digest_and_locators_resolve_retained_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            report, output = Path(tmp, 'report.json'), Path(tmp, 'output.json')
            for value, gaps in ((mixed(), MIXED_GAPS), ({}, [{'locator': 'results', 'state': 'absent'}]),
                                ({'results': None}, [{'locator': 'results', 'state': 'null'}]),
                                ({'results': []}, [])):
                raw = (json.dumps(value, indent=3) + '\r\n').encode()
                report.write_bytes(raw)
                proc = self.cli(report, output)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(proc.stdout, b'')
                result = json.loads(output.read_bytes())
                self.assertEqual(result['coverageGaps'], gaps)
                self.assertEqual(result['provenance']['reportSha256'], hashlib.sha256(raw).hexdigest())
                retained = json.loads(raw)
                for gap in result['coverageGaps']:
                    tokens = re.findall(r'[A-Za-z_]+|\d+', gap['locator'])
                    parent = retained
                    for token in tokens[:-1]:
                        parent = parent[int(token)] if token.isdigit() else parent[token]
                    if gap['state'] == 'absent':
                        self.assertNotIn(tokens[-1], parent)
                    else:
                        self.assertIn(tokens[-1], parent)
                        self.assertIsNone(parent[tokens[-1]])

    def test_malformed_collections_fail_closed_preserving_output_and_inputs(self):
        bad_reports = []
        for bad in ({'SECRET': 1}, 'SECRET', False, 0, [None], ['SECRET']):
            bad_reports.append({'results': bad})
            value = group_only()
            value['results'][0]['packages'][0]['vulnerabilities'] = deepcopy(bad)
            bad_reports.append(value)
            value = group_only()
            value['results'][0]['packages'] = deepcopy(bad)
            bad_reports.append(value)
        for state in ('absent', 'null'):
            value = group_only()
            if state == 'null':
                value['results'][0]['packages'] = None
            else:
                del value['results'][0]['packages']
            bad_reports.append(value)
        with tempfile.TemporaryDirectory() as tmp:
            report, output = Path(tmp, 'report.json'), Path(tmp, 'output.json')
            rules_before = (ROOT / 'examples/ignores/unbound-osv.toml').read_bytes()
            for value in bad_reports:
                with self.subTest(value=value):
                    raw = json.dumps(value).encode()
                    report.write_bytes(raw)
                    output.write_bytes(b'keep')
                    proc = self.cli(report, output)
                    self.assertEqual(proc.returncode, 2)
                    self.assertEqual(proc.stdout, b'')
                    self.assertNotIn(b'SECRET', proc.stderr)
                    self.assertNotIn(b'Traceback', proc.stderr)
                    self.assertEqual(output.read_bytes(), b'keep')
                    self.assertEqual(report.read_bytes(), raw)
                    self.assertEqual((ROOT / 'examples/ignores/unbound-osv.toml').read_bytes(), rules_before)


if __name__ == '__main__':
    unittest.main()
