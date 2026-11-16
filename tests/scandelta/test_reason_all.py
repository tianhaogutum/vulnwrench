"""ALL exact reason membership selects whole unknown Grype entries."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

from vulnwrench.scandelta import InputError, compare

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts' / 'delta'))
from verify_reason_all import CONTRACT, paths_for, selection_kwargs, check_selection, verify


def documents():
    return [json.loads(p.read_text()) for p in paths_for()]


class ReasonAllTests(unittest.TestCase):
    def test_all_membership_contract(self):
        docs = documents()
        original = deepcopy(docs)
        batch = compare(*docs)
        default = compare(*docs, explain_advisory=CONTRACT['advisory'])
        for case in CONTRACT['positive']:
            with self.subTest(case=case):
                check_selection(compare(*docs, **selection_kwargs(case)), default, batch, case)
        self.assertEqual(docs, original)
        self.assertFalse(batch['comparable'])
        self.assertFalse(any(r['fixed'] or r['classification'] == 'package_removed' for r in batch['transitions']))

    def test_negative_contract(self):
        for case in CONTRACT['negative']:
            with self.subTest(case=case), self.assertRaises(InputError):
                compare(*documents(), **selection_kwargs(case))
        kwargs = selection_kwargs(CONTRACT['positive'][0])
        for codes in ([], (), '', 'scope_binding_missing', {}, {'scope_binding_missing'}, True, 1,
                      [None], [True], [1], [{}], [[]], ['bad\0CODE'], ['scope_binding_missing', None]):
            with self.subTest(codes=codes), self.assertRaises(InputError):
                compare(*documents(), **(kwargs | dict(explain_reason_codes_all=codes)))
        with self.assertRaises(InputError):
            compare(*documents(), explain_reason_codes_all=['scope_binding_missing'])

    def test_tuple_duplicates_and_request_order(self):
        case = CONTRACT['positive'][2]
        kwargs = selection_kwargs(case)
        codes = case['reason_codes_all'].copy()
        result = compare(*documents(), **(kwargs | dict(explain_reason_codes_all=tuple(codes))))
        self.assertEqual(codes, case['reason_codes_all'])
        self.assertEqual(result, compare(*documents(), **kwargs))
        self.assertEqual(result['explanation']['unknown_filter']['reason_codes_all'],
                         ['scope_binding_missing', 'ambiguous_package_location'])
        # Reordering the request changes only filter metadata, never native reason order.
        reversed_result = compare(*documents(), **(kwargs | dict(explain_reason_codes_all=list(reversed(codes[:2])))))
        self.assertEqual(result['explanation']['unknown_findings'], reversed_result['explanation']['unknown_findings'])

    def test_none_preserves_existing_modes(self):
        for kwargs in ({}, dict(explain_advisory=CONTRACT['advisory']),
                       dict(explain_advisory=CONTRACT['advisory'], explain_side='after', explain_artifact_id='native/~shared ID'),
                       dict(explain_advisory=CONTRACT['advisory'], explain_side='after', explain_artifact_id='native/~shared ID',
                            explain_reason_code='ambiguous_package_location', explain_match_index=4)):
            self.assertEqual(compare(*documents(), **kwargs), compare(*documents(), **kwargs, explain_reason_codes_all=None))

    def test_unknown_only_original_native_index_and_zero(self):
        docs = documents()
        for doc in docs[:2]:
            del doc['matches'][0]
        kwargs = selection_kwargs(CONTRACT['positive'][5]) | dict(explain_match_index=3)
        result = compare(*docs, **kwargs)
        explanation = result.pop('explanation')
        self.assertEqual(result, compare(*docs))
        self.assertEqual(result['transitions'], [])
        self.assertEqual(explanation['findings'], [])
        self.assertEqual(explanation['unknown_findings'][0]['source'], '/before_report/matches/3')
        self.assertEqual(explanation['unknown_findings'][0]['unknown_index'], 3)
        zero = compare(*docs, explain_advisory='UNSELECTED-CONFLICT', explain_side='after',
                       explain_artifact_id='native/~shared ID', explain_match_index=0,
                       explain_reason_codes_all=['artifact_id_conflict', 'scope_binding_missing'])
        self.assertEqual(zero['explanation']['unknown_findings'][0]['source'], '/after_report/matches/0')
        self.assertEqual(zero['explanation']['unknown_filter']['match_index'], 0)

    def test_mixed_scanner_and_full_validation(self):
        kwargs = selection_kwargs(CONTRACT['positive'][12])
        docs = documents()
        docs[0] = json.loads((ROOT / 'examples/delta/grype/trivy-before.json').read_text())
        docs[4]['before'] = json.loads((ROOT / 'examples/delta/grype/trivy-scans.json').read_text())['before']
        selected = compare(*docs, **kwargs)
        self.assertEqual(selected.pop('explanation')['findings'], [])
        self.assertEqual(selected, compare(*docs))
        with self.assertRaises(InputError):
            compare(*docs, **(kwargs | dict(explain_side='before')))
        for side, index in ((0, 0), (1, 1), (1, 7)):
            docs = documents()
            del docs[side]['matches'][index]['artifact']['id']
            with self.subTest(side=side, index=index), self.assertRaises(InputError):
                compare(*docs, **kwargs)

    def test_cli_contract(self):
        verify()


if __name__ == '__main__':
    unittest.main()
