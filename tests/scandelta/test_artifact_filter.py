"""Exact report-local unknown-artifact selection, without batch reinterpretation."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

from vulnwrench.scandelta import InputError, compare

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts' / 'delta'))
from verify_artifact_filter import CONTRACT, paths_for, verify


def documents():
    return [json.loads(p.read_text()) for p in paths_for()]


class ArtifactFilterTests(unittest.TestCase):
    def test_default_fixture_contract(self):
        docs = documents()
        batch = compare(*docs)
        default = compare(*docs, explain_advisory=CONTRACT['advisory'])
        explanation = default.pop('explanation')
        self.assertEqual(default, batch)
        self.assertEqual(len(explanation['findings']), CONTRACT['default']['normalized'])
        self.assertEqual(len(explanation['unknown_findings']), CONTRACT['default']['selected_unknown'])
        for side in ('before', 'after'):
            self.assertEqual(batch['accounting'][side + '_findings'], CONTRACT['default'][side + '_findings'])
            self.assertEqual(batch['accounting'][side + '_records_accounted'], CONTRACT['default'][side + '_findings'])
        self.assertFalse(batch['comparable'])
        self.assertFalse(any(r['fixed'] or r['classification'] == 'package_removed' for r in batch['transitions']))

    def test_filtered_fixture_contract(self):
        docs = documents()
        original = deepcopy(docs)
        default = compare(*docs, explain_advisory=CONTRACT['advisory'])
        batch = compare(*docs)
        for case in CONTRACT['positive']:
            with self.subTest(case=case):
                selected = compare(*docs, explain_advisory=CONTRACT['advisory'],
                                   explain_side=case['side'], explain_artifact_id=case['artifact_id'])
                explanation = selected.pop('explanation')
                self.assertEqual(selected, batch)
                self.assertEqual(explanation['findings'], [])
                self.assertEqual(explanation['unknown_filter'], {k: case[k] for k in ('side', 'artifact_id')})
                entries = explanation['unknown_findings']
                expected = [e for e in default['explanation']['unknown_findings']
                            if e['side'] == case['side'] and e['unknown_index'] in case['unknown_indexes']]
                self.assertEqual(entries, expected)  # Shape, duplicate/order and all context unchanged.
                self.assertEqual([e['unknown_index'] for e in entries], case['unknown_indexes'])
                self.assertEqual([e['source'] for e in entries],
                                 [f"/{case['side']}_report/matches/{i}" for i in case['native_indexes']])
                for entry in entries:
                    native = batch['unknown_findings'][case['side']][entry['unknown_index']]
                    self.assertEqual(native['artifact_id'], case['artifact_id'])
                    if case['artifact_id'] == 'native/~shared ID':
                        self.assertEqual([r['code'] for r in entry['reasons']],
                                         ['artifact_id_conflict', 'ambiguous_package_location', 'scope_binding_missing'])
                        self.assertEqual(entry['reasons'][0]['sources'], [entry['source'], entry['source'] + '/artifact/id']
                                         + [f"/{case['side']}_report/matches/{i}/artifact" for i in (1, 3, 4)])
        self.assertEqual(docs, original)

    def test_invalid_filters(self):
        for case in CONTRACT['negative']:
            with self.subTest(case=case), self.assertRaises(InputError):
                compare(*documents(), explain_advisory=case.get('advisory', CONTRACT['advisory']),
                        explain_side=case['side'], explain_artifact_id=case['artifact_id'])
        for side, identity, advisory in [('after', 'native/~shared ID', None),
                                         ([], 'x', 'GHSA-SYNTH-001'), (True, 'x', 'GHSA-SYNTH-001'),
                                         ('after', {}, 'GHSA-SYNTH-001'), ('after', 1, 'GHSA-SYNTH-001'),
                                         ('after', 'bad\nID', 'GHSA-SYNTH-001'), ('after', 'bad\0ID', 'GHSA-SYNTH-001')]:
            with self.subTest(side=side, identity=identity), self.assertRaises(InputError):
                compare(*documents(), explain_advisory=advisory, explain_side=side, explain_artifact_id=identity)

    def test_unknown_only_and_mixed_scanner_filter(self):
        docs = documents()
        # A selected Grype side remains eligible when the other side is Trivy.
        docs[0] = json.loads((ROOT / 'examples/delta/grype/trivy-before.json').read_text())
        docs[4]['before'] = json.loads((ROOT / 'examples/delta/grype/trivy-scans.json').read_text())['before']
        batch = compare(*docs)
        selected = compare(*docs, explain_advisory=CONTRACT['advisory'], explain_side='after',
                           explain_artifact_id='native/~shared ID')
        self.assertEqual(selected.pop('explanation')['findings'], [])
        self.assertEqual(selected, batch)
        with self.assertRaises(InputError):
            compare(*docs, explain_advisory=CONTRACT['advisory'], explain_side='before',
                    explain_artifact_id='native/~shared ID')
        # No normalized transition is needed for a valid unknown selection.
        docs = documents()
        for doc in docs[:2]:
            del doc['matches'][0]
        selected = compare(*docs, explain_advisory=CONTRACT['advisory'], explain_side='after',
                           explain_artifact_id='native/~shared ID')
        self.assertEqual(selected['transitions'], [])
        self.assertEqual([e['unknown_index'] for e in selected['explanation']['unknown_findings']], [2, 3])
        self.assertEqual([e['source'] for e in selected['explanation']['unknown_findings']],
                         ['/after_report/matches/2', '/after_report/matches/3'])

    def test_reports_validated_before_filter(self):
        for change in ('unsupported-version', 'unselected-artifact', 'unselected-advisory', 'other-side'):
            docs = documents()
            if change == 'unsupported-version':
                docs[1]['descriptor']['version'] = 'SYNTHETIC_SECRET_VERSION'
            elif change == 'unselected-artifact':
                del docs[1]['matches'][1]['artifact']['id']
            elif change == 'unselected-advisory':
                del docs[1]['matches'][1]['vulnerability']
            else:
                docs[0]['matches'][0]['artifact']['locations'] = None
            with self.subTest(change=change), self.assertRaises(InputError):
                compare(*docs, explain_advisory=CONTRACT['advisory'], explain_side='after',
                        explain_artifact_id='native/~shared ID')
        cases = json.loads((ROOT / 'examples/delta/explain/cases.json').read_text())
        docs = [json.loads((ROOT / 'examples' / 'delta' / p).read_text()) for p in cases[0]['inputs']]
        with self.assertRaises(InputError):
            compare(*docs, explain_advisory='GHSA-SYNTH-001', explain_side='after', explain_artifact_id='x')

    def test_cli_contract(self):
        verify()


if __name__ == '__main__':
    unittest.main()
