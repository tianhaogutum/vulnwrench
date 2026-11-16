"""Exact adapter-code membership selects whole unknown explanation entries."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

from vulnwrench.scandelta import InputError, compare

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts' / 'delta'))
from verify_reason_filter import CONTRACT, paths_for, check_selection, verify


def documents():
    return [json.loads(p.read_text()) for p in paths_for()]


class ReasonFilterTests(unittest.TestCase):
    def test_default_contract(self):
        docs = documents()
        batch = compare(*docs)
        default = compare(*docs, explain_advisory=CONTRACT['advisory'])
        self.assertEqual(len(default['explanation']['findings']), 1)
        self.assertEqual(len(default['explanation']['unknown_findings']), 14)
        default.pop('explanation')
        self.assertEqual(default, batch)
        for side in ('before', 'after'):
            self.assertEqual(batch['accounting'][side + '_findings'], 9)
            self.assertEqual(batch['accounting'][side + '_records_accounted'], 9)
            unknown = batch['unknown_findings'][side]
            self.assertEqual(unknown[2]['reasons'], ['artifact_id_conflict', 'ambiguous_package_location', 'scope_binding_missing'])
            self.assertEqual(unknown[5]['reasons'], ['artifact_id_conflict', 'scope_binding_missing'])
            self.assertEqual(unknown[7]['reasons'], ['artifact_id_conflict', 'unsupported_package_type',
                                                   'unsupported_package_location', 'scope_binding_missing'])
        self.assertFalse(batch['comparable'])
        self.assertFalse(any(r['fixed'] or r['classification'] == 'package_removed' for r in batch['transitions']))

    def test_reason_membership_whole_entry_contract(self):
        docs = documents()
        original = deepcopy(docs)
        default = compare(*docs, explain_advisory=CONTRACT['advisory'])
        batch = compare(*docs)
        for case in CONTRACT['positive']:
            with self.subTest(case=case):
                selected = compare(*docs, explain_advisory=CONTRACT['advisory'], explain_side=case['side'],
                                   explain_artifact_id=case['artifact_id'], explain_reason_code=case['reason_code'])
                check_selection(selected, default, batch, case)
        self.assertEqual(docs, original)

    def test_negative_contract(self):
        for case in CONTRACT['negative']:
            with self.subTest(case=case), self.assertRaises(InputError):
                compare(*documents(), explain_advisory=case.get('advisory', CONTRACT['advisory']),
                        explain_side=case['side'], explain_artifact_id=case['artifact_id'],
                        explain_reason_code=case['reason_code'])
        for code in ([], {}, True, 1, 'bad\0CODE'):
            with self.subTest(code=code), self.assertRaises(InputError):
                compare(*documents(), explain_advisory=CONTRACT['advisory'], explain_side='after',
                        explain_artifact_id='native/~shared ID', explain_reason_code=code)
        with self.assertRaises(InputError):
            compare(*documents(), explain_reason_code='scope_binding_missing')

    def test_none_preserves_default_and_artifact_filter(self):
        for kwargs in ({}, dict(explain_advisory=CONTRACT['advisory']),
                       dict(explain_advisory=CONTRACT['advisory'], explain_side='after', explain_artifact_id='native/~shared ID')):
            self.assertEqual(compare(*documents(), **kwargs), compare(*documents(), **kwargs, explain_reason_code=None))

    def test_unknown_only_and_mixed_scanner(self):
        docs = documents()
        for doc in docs[:2]:
            del doc['matches'][0]
        result = compare(*docs, explain_advisory=CONTRACT['advisory'], explain_side='after',
                         explain_artifact_id='native/~shared ID', explain_reason_code='ambiguous_package_location')
        self.assertEqual(result['transitions'], [])
        self.assertEqual([e['source'] for e in result['explanation']['unknown_findings']],
                         ['/after_report/matches/2', '/after_report/matches/3'])
        self.assertEqual([e['unknown_index'] for e in result['explanation']['unknown_findings']], [2, 3])
        docs = documents()
        docs[0] = json.loads((ROOT / 'examples/delta/grype/trivy-before.json').read_text())
        docs[4]['before'] = json.loads((ROOT / 'examples/delta/grype/trivy-scans.json').read_text())['before']
        batch = compare(*docs)
        result = compare(*docs, explain_advisory=CONTRACT['advisory'], explain_side='after',
                         explain_artifact_id='native/~shared ID', explain_reason_code='ambiguous_package_location')
        self.assertEqual(result.pop('explanation')['findings'], [])
        self.assertEqual(result, batch)
        with self.assertRaises(InputError):
            compare(*docs, explain_advisory=CONTRACT['advisory'], explain_side='before',
                    explain_artifact_id='native/~shared ID', explain_reason_code='scope_binding_missing')

    def test_cli_contract(self):
        verify()


if __name__ == '__main__':
    unittest.main()
