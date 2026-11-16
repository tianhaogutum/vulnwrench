"""Normalized target selection must never scope unknown native records."""
from copy import deepcopy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts' / 'delta'))
from verify_target import CONTRACT, check_selection, documents, verify
from vulnwrench.scandelta import InputError, compare
from vulnwrench.scandelta.cli import markdown


class TargetTests(unittest.TestCase):
    def test_whole_entries_both_scanners_mixed_and_alias(self):
        for case in CONTRACT['cases']:
            docs = documents(case)
            original = deepcopy(docs)
            batch = compare(*docs)
            for advisory in (CONTRACT['advisory'], CONTRACT['alias'], 'GHSA-SYNTH-001'):
                with self.subTest(case=case['name'], advisory=advisory):
                    default = compare(*docs, explain_advisory=advisory)
                    selected = compare(*docs, explain_advisory=advisory, explain_target=CONTRACT['target'])
                    check_selection(selected, default, batch, case)
                    self.assertEqual(selected['explanation']['requested_advisory'], advisory)
            self.assertEqual(docs, original)

    def test_none_is_default_and_exact_other_target(self):
        for case in CONTRACT['cases']:
            docs = documents(case)
            default = compare(*docs, explain_advisory=CONTRACT['advisory'])
            self.assertEqual(default, compare(*docs, explain_advisory=CONTRACT['advisory'], explain_target=None))
            self.assertEqual(markdown(default), markdown(compare(*docs, explain_advisory=CONTRACT['advisory'], explain_target=None)))
            selected = compare(*docs, explain_advisory=CONTRACT['advisory'], explain_target='zeta.lock')
            self.assertEqual([e['transition_index'] for e in selected['explanation']['findings']], [4])

    def test_invalid_or_inexact_target_and_missing_advisory(self):
        for case in CONTRACT['cases']:
            for target in ('', ' ', [], {}, 1, True, 'bad\0SYNTHETIC_SECRET', 'bad\nSYNTHETIC_SECRET',
                           CONTRACT['target'].strip(), './' + CONTRACT['target'], CONTRACT['target'].upper(),
                           'SYNTHETIC_SECRET_ABSENT', 'one'):
                with self.subTest(case=case['name'], target=target), self.assertRaises(InputError) as raised:
                    compare(*documents(case), explain_advisory=CONTRACT['advisory'], explain_target=target)
                self.assertNotIn('SYNTHETIC_SECRET', str(raised.exception))
            with self.assertRaises(InputError):
                compare(*documents(case), explain_target=CONTRACT['target'])

    def test_native_selectors_incompatible_even_empty_or_zero(self):
        for field, value in [('explain_side', 'after'), ('explain_artifact_id', 'unknown-0'),
                             ('explain_reason_code', 'ambiguous_package_location'), ('explain_match_index', 0),
                             ('explain_reason_codes_all', []), ('explain_reason_codes_any', ()),
                             ('explain_reason_codes_any', ['ambiguous_package_location'])]:
            with self.subTest(field=field), self.assertRaises(InputError):
                compare(*documents(CONTRACT['cases'][1]), explain_advisory=CONTRACT['advisory'],
                        explain_target=CONTRACT['target'], **{field: value})

    def test_unknown_only_or_wrong_advisory_does_not_satisfy_target(self):
        for case in CONTRACT['cases'][1:]:
            for advisory in ('UNKNOWN-ONLY', 'OTHER'):
                with self.subTest(case=case['name'], advisory=advisory), self.assertRaises(InputError):
                    compare(*documents(case), explain_advisory=advisory, explain_target=CONTRACT['target'])
            docs = documents(case)
            # Turn every selected normalized native advisory into an unbound unknown.
            if 'matches' in docs[0]:
                docs[0]['matches'] = []
            if case['name'] == 'mixed':
                for result in docs[0]['Results']:
                    result['Vulnerabilities'] = []
            docs[1]['matches'] = docs[1]['matches'][-2:]
            with self.assertRaises(InputError):
                compare(*docs, explain_advisory=CONTRACT['advisory'], explain_target=CONTRACT['target'])

    def test_cli_contract(self):
        verify()


if __name__ == '__main__':
    unittest.main()
