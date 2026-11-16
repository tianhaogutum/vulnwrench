"""Native report match indexes select one complete unknown explanation entry."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

from vulnwrench.scandelta import InputError, compare

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts' / 'delta'))
from verify_match_index import CONTRACT, paths_for, selection_kwargs, check_selection, verify


def documents():
    return [json.loads(p.read_text()) for p in paths_for()]


class MatchIndexTests(unittest.TestCase):
    def test_single_native_entry_contract(self):
        docs = documents()
        original = deepcopy(docs)
        default = compare(*docs, explain_advisory=CONTRACT['advisory'])
        batch = compare(*docs)
        for case in CONTRACT['positive']:
            with self.subTest(case=case):
                selected = compare(*docs, **selection_kwargs(case))
                check_selection(selected, default, batch, case)
        self.assertEqual(docs, original)
        self.assertFalse(batch['comparable'])
        self.assertFalse(any(r['fixed'] or r['classification'] == 'package_removed' for r in batch['transitions']))

    def test_negative_contract(self):
        for case in CONTRACT['negative']:
            with self.subTest(case=case), self.assertRaises(InputError):
                compare(*documents(), **selection_kwargs(case))
        for index in ([], {}, True, False, 3.0, 3.5, -1, '3', float('nan'), float('inf'), 10**5000):
            with self.subTest(index=index), self.assertRaises(InputError):
                compare(*documents(), explain_advisory=CONTRACT['advisory'], explain_side='after',
                        explain_artifact_id='native/~shared ID', explain_match_index=index)
        with self.assertRaises(InputError):
            compare(*documents(), explain_match_index=0)

    def test_none_preserves_every_existing_mode(self):
        for kwargs in ({}, dict(explain_advisory=CONTRACT['advisory']),
                       dict(explain_advisory=CONTRACT['advisory'], explain_side='after', explain_artifact_id='native/~shared ID'),
                       dict(explain_advisory=CONTRACT['advisory'], explain_side='after', explain_artifact_id='native/~shared ID',
                            explain_reason_code='ambiguous_package_location')):
            self.assertEqual(compare(*documents(), **kwargs), compare(*documents(), **kwargs, explain_match_index=None))

    def test_zero_unknown_only_and_report_local_index(self):
        # Removing known records shifts native indexes; an index is not a persistent ID.
        docs = documents()
        for doc in docs[:2]:
            del doc['matches'][0]
        batch = compare(*docs)
        selected = compare(*docs, explain_advisory=CONTRACT['advisory'], explain_side='after',
                           explain_artifact_id='native/~shared ID', explain_match_index=3,
                           explain_reason_code='ambiguous_package_location')
        explanation = selected.pop('explanation')
        self.assertEqual(selected, batch)
        self.assertEqual(selected['transitions'], [])
        self.assertEqual(explanation['findings'], [])
        self.assertEqual(explanation['unknown_findings'][0]['source'], '/after_report/matches/3')
        self.assertEqual(explanation['unknown_findings'][0]['unknown_index'], 3)
        # Index zero is valid when an unknown native record really occupies it.
        result = compare(*docs, explain_advisory='UNSELECTED-CONFLICT', explain_side='after',
                         explain_artifact_id='native/~shared ID', explain_match_index=0)
        self.assertEqual(result['explanation']['unknown_filter']['match_index'], 0)
        self.assertEqual(result['explanation']['unknown_findings'][0]['source'], '/after_report/matches/0')
        self.assertEqual(result['explanation']['unknown_findings'][0]['unknown_index'], 0)
        # Same native index on opposite sides has different exact native identity.
        with self.assertRaises(InputError):
            compare(*documents(), explain_advisory=CONTRACT['advisory'], explain_side='after',
                    explain_artifact_id='only-before', explain_match_index=5)

    def test_mixed_scanner_and_full_validation(self):
        docs = documents()
        docs[0] = json.loads((ROOT / 'examples/delta/grype/trivy-before.json').read_text())
        docs[4]['before'] = json.loads((ROOT / 'examples/delta/grype/trivy-scans.json').read_text())['before']
        batch = compare(*docs)
        selected = compare(*docs, explain_advisory=CONTRACT['advisory'], explain_side='after',
                           explain_artifact_id='native/~shared ID', explain_match_index=4)
        explanation = selected.pop('explanation')
        self.assertEqual(selected, batch)
        self.assertEqual(explanation['findings'], [])
        self.assertEqual(explanation['unknown_findings'][0]['unknown_index'], 3)
        with self.assertRaises(InputError):
            compare(*docs, explain_advisory=CONTRACT['advisory'], explain_side='before',
                    explain_artifact_id='native/~shared ID', explain_match_index=4)
        for index in (1, 7):
            changed = documents()
            del changed[1]['matches'][index]['artifact']['id']
            with self.subTest(index=index), self.assertRaises(InputError):
                compare(*changed, explain_advisory=CONTRACT['advisory'], explain_side='after',
                        explain_artifact_id='native/~shared ID', explain_match_index=4)

    def test_cli_contract(self):
        verify()


if __name__ == '__main__':
    unittest.main()
