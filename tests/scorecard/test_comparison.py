"""Local native Scorecard bundles: raw changes, evidence gaps and commit identity."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'examples/scorecard/compare'
REPO = 'https://github.com/example/demo'


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
                    'components': [{'type': 'library', 'name': 'demo', 'purl': 'pkg:npm/demo@1'}]}
        self.mapping = {'pkg:npm/demo@1': REPO}
        self.before = {'demo.json': self.snapshot('2026-11-01', 3, '1')}
        self.after = {'demo.json': self.snapshot('2026-11-11', 8, '2')}
        for side in ('before', 'after'):
            (self.root / side).mkdir()
        self.write()

    @staticmethod
    def snapshot(date, score, commit):
        return {'date': date, 'repo': {'name': 'github.com/example/demo', 'commit': commit * 40},
                'scorecard': {'version': 'v5.0.0', 'commit': 'a' * 40}, 'score': 9.9,
                'checks': [{'name': 'Code-Review', 'score': score, 'reason': 'Synthetic evidence'}]}

    def write(self):
        for name, document in (('bom.json', self.bom), ('repos.json', self.mapping)):
            (self.root / name).write_text(json.dumps(document))
        for side in ('before', 'after'):
            for path in (self.root / side).iterdir():
                path.unlink()
            for name, document in getattr(self, side).items():
                (self.root / side / name).write_text(json.dumps(document))

    def cli(self, *extra):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'scorecard', 'compare', str(self.root / 'bom.json'),
                               '--map', str(self.root / 'repos.json'), '--before', str(self.root / 'before'),
                               '--after', str(self.root / 'after'), '--before-as-of', '2026-11-01',
                               '--after-as-of', '2026-11-11', '--max-age-days', '2', *map(str, extra)],
                              cwd=ROOT, capture_output=True, text=True, timeout=120)

    def report(self):
        self.write()
        run = self.cli()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stderr, '')
        return json.loads(run.stdout)

    def row(self):
        return self.report()['repositories'][0]

    def library_report(self, max_age_days=2):
        from vulnwrench.scorecard import compare
        self.write()
        return compare(self.root / 'bom.json', self.root / 'repos.json', self.root / 'before',
                       self.root / 'after', '2026-11-01', '2026-11-11', max_age_days=max_age_days)

    def assert_scanner_summary(self, report, expected):
        self.assertEqual(report['summary']['scannerChanges'], expected)
        for counts in report['summary']['scannerChanges'].values():
            self.assertEqual(sum(counts.values()), report['summary']['comparedRepositories'])

    def assert_comparison_summary(self, report, expected):
        self.assertEqual(report['summary']['comparisonStatuses'], expected)
        self.assertEqual(sum(expected.values()), report['summary']['comparedRepositories'])

    def assert_snapshot_summary(self, report, expected):
        self.assertEqual(report['summary']['snapshotChanges'], expected)
        self.assertEqual(sum(expected.values()), report['summary']['comparedRepositories'])

    def assert_check_summary(self, report, expected):
        self.assertEqual(report['summary']['checkChanges'], expected)
        self.assertEqual(sum(expected.values()), sum(len(row['checks']) for row in report['repositories']))

    def assert_check_score_summary(self, report, expected):
        self.assertEqual(report['summary']['checkScoreChanges'], expected)
        self.assertEqual(sum(expected.values()), sum(report['summary']['checkChanges'].values()))

    def assert_check_observations(self, report, before, after):
        self.assertEqual(report['summary']['checkObservations'], {'before': before, 'after': after})
        for counts in (before, after):
            self.assertEqual(set(counts), {'known', 'negative_score', 'missing_score',
                                           'missing_check', 'missing_snapshot'})
            self.assertEqual(sum(counts.values()), sum(report['summary']['checkChanges'].values()))
            self.assertEqual(sum(counts.values()), sum(report['summary']['checkScoreChanges'].values()))

    def assert_check_transitions(self, report, nonzero):
        labels = ('known', 'negative_score', 'missing_score', 'missing_check', 'missing_snapshot')
        expected = {before: dict.fromkeys(labels, 0) for before in labels}
        for (before, after), count in nonzero.items():
            expected[before][after] = count
        actual = report['summary']['checkObservationTransitions']
        self.assertEqual(actual, expected)
        self.assertEqual(sum(sum(row.values()) for row in actual.values()),
                         sum(report['summary']['checkChanges'].values()))
        self.assertEqual(sum(sum(row.values()) for row in actual.values()),
                         sum(report['summary']['checkScoreChanges'].values()))
        for label in labels:
            self.assertEqual(sum(actual[label].values()), report['summary']['checkObservations']['before'][label])
            self.assertEqual(sum(row[label] for row in actual.values()),
                             report['summary']['checkObservations']['after'][label])

    def assert_check_comparability(self, report, comparable, evidence, observation):
        counts = report['summary']['checkScoreComparability']
        self.assertEqual(counts, {'comparable': comparable, 'evidence_blocked': evidence,
                                  'observation_blocked': observation})
        total = sum(counts.values())
        for partition in ('checkChanges', 'checkScoreChanges'):
            self.assertEqual(total, sum(report['summary'][partition].values()))
        self.assertEqual(total, sum(sum(row.values()) for row in
                         report['summary']['checkObservationTransitions'].values()))
        self.assertEqual(total, sum(len(row['checks']) for row in report['repositories']))
        self.assertEqual(evidence + observation, report['summary']['checkScoreChanges']['not_comparable'])

    def assert_check_comparability_by_check(self, report, expected):
        actual = report['summary']['checkScoreComparabilityByCheck']
        self.assertEqual(actual, expected)
        self.assertEqual([row['name'] for row in actual], sorted({
            check['name'] for repo in report['repositories'] for check in repo['checks']}))
        for row in actual:
            self.assertEqual(set(row), {'name', 'comparable', 'evidence_blocked', 'observation_blocked'})
            self.assertEqual(sum(row[key] for key in report['summary']['checkScoreComparability']),
                sum(check['name'] == row['name'] for repo in report['repositories'] for check in repo['checks']))
        for key, count in report['summary']['checkScoreComparability'].items():
            self.assertEqual(sum(row[key] for row in actual), count)

    def assert_check_score_changes_by_check(self, report, expected):
        summary = report['summary']
        actual = summary['checkScoreChangesByCheck']
        self.assertEqual(actual, expected)
        self.assertEqual([row['name'] for row in actual], sorted({
            check['name'] for repo in report['repositories'] for check in repo['checks']}))
        support = {row['name']: row for row in summary['checkScoreComparabilityByCheck']}
        for row in actual:
            self.assertEqual(set(row), {'name', 'increased', 'decreased', 'unchanged', 'not_comparable'})
            self.assertTrue(all(type(row[key]) is int and row[key] >= 0 for key in summary['checkScoreChanges']))
            self.assertEqual(sum(row[key] for key in summary['checkScoreChanges']),
                sum(check['name'] == row['name'] for repo in report['repositories'] for check in repo['checks']))
            self.assertEqual(row['increased'] + row['decreased'] + row['unchanged'], support[row['name']]['comparable'])
            self.assertEqual(row['not_comparable'],
                support[row['name']]['evidence_blocked'] + support[row['name']]['observation_blocked'])
        for key, count in summary['checkScoreChanges'].items():
            self.assertEqual(sum(row[key] for row in actual), count)

    def test_check_score_changes_by_check_literal_fixture(self):
        from vulnwrench.scorecard import compare
        report = compare(FIXTURE / 'bom.json', FIXTURE / 'repos.json', FIXTURE / 'before',
                         FIXTURE / 'after', '2026-11-01', '2026-11-11', max_age_days=2)
        self.assert_check_score_changes_by_check(report, [{'name': 'Code-Review', 'increased': 2, 'decreased': 0, 'unchanged': 0, 'not_comparable': 2}, {'name': 'Future-Check', 'increased': 0, 'decreased': 0, 'unchanged': 0, 'not_comparable': 1}, {'name': 'License', 'increased': 0, 'decreased': 0, 'unchanged': 1, 'not_comparable': 0}, {'name': 'Maintained', 'increased': 0, 'decreased': 0, 'unchanged': 0, 'not_comparable': 1}, {'name': 'Security-Policy', 'increased': 0, 'decreased': 0, 'unchanged': 0, 'not_comparable': 1}])

    def test_check_score_changes_by_check_one_name_spans_all_directions(self):
        # Same exact name across five repositories: four directions, one simultaneous blocker.
        for i, (old, new) in enumerate(((0, 10), (10, 0), (5, 5), (-1, 10), (0, 10))):
            repo = f'github.com/example/repo-{i}'
            purl = f'pkg:npm/repo-{i}@1'
            self.bom['components'].append({'type': 'library', 'name': str(i), 'purl': purl})
            self.mapping[purl] = repo
            for side, score, date in (('before', old, '2026-11-01'), ('after', new, '2026-11-11')):
                doc = self.snapshot(date, score, '1' if side == 'before' else '2')
                doc['repo']['name'] = repo
                doc['checks'][0]['name'] = 'Shared'
                getattr(self, side)[f'{i}.json'] = doc
        self.after['4.json']['date'] = '2026-11-02'
        self.after['4.json']['checks'][0]['score'] = -1
        self.before['demo.json']['checks'] = [{'name': name, 'score': 5} for name in ('é', 'shared', ' Shared')]
        self.after['demo.json']['checks'] = copy.deepcopy(self.before['demo.json']['checks'])
        report = self.library_report()
        self.assert_check_score_changes_by_check(report, [
            {'name': ' Shared', 'increased': 0, 'decreased': 0, 'unchanged': 1, 'not_comparable': 0},
            {'name': 'Shared', 'increased': 1, 'decreased': 1, 'unchanged': 1, 'not_comparable': 2},
            {'name': 'shared', 'increased': 0, 'decreased': 0, 'unchanged': 1, 'not_comparable': 0},
            {'name': 'é', 'increased': 0, 'decreased': 0, 'unchanged': 1, 'not_comparable': 0}])

    def test_check_comparability_by_check_literal_fixture(self):
        from vulnwrench.scorecard import compare
        report = compare(FIXTURE / 'bom.json', FIXTURE / 'repos.json', FIXTURE / 'before',
                         FIXTURE / 'after', '2026-11-01', '2026-11-11', max_age_days=2)
        self.assert_check_comparability_by_check(report, [
            {'name': 'Code-Review', 'comparable': 2, 'evidence_blocked': 2, 'observation_blocked': 0},
            {'name': 'Future-Check', 'comparable': 0, 'evidence_blocked': 0, 'observation_blocked': 1},
            {'name': 'License', 'comparable': 1, 'evidence_blocked': 0, 'observation_blocked': 0},
            {'name': 'Maintained', 'comparable': 0, 'evidence_blocked': 0, 'observation_blocked': 1},
            {'name': 'Security-Policy', 'comparable': 0, 'evidence_blocked': 0, 'observation_blocked': 1}])

    def test_check_comparability_by_check_exact_names_and_mixed_repositories(self):
        # One exact name spans all three buckets; case/whitespace/Unicode stay distinct.
        self.bom['components'] += [copy.deepcopy(self.bom['components'][0]),
            {'type': 'library', 'name': 'alias', 'purl': 'pkg:npm/alias@1'},
            {'type': 'library', 'name': 'other', 'purl': 'pkg:npm/other@1'},
            {'type': 'library', 'name': 'stale', 'purl': 'pkg:npm/stale@1'}]
        self.mapping.update({'pkg:npm/alias@1': 'github.com/EXAMPLE/Demo.git',
                             'pkg:npm/other@1': 'github.com/example/other',
                             'pkg:npm/stale@1': 'github.com/example/stale'})
        for side in ('before', 'after'):
            docs = getattr(self, side)
            docs['demo.json']['checks'] = [{'name': name, 'score': 5}
                for name in ('é', 'check', 'Check', ' Check')]
            docs['other.json'] = copy.deepcopy(docs['demo.json'])
            docs['other.json']['repo']['name'] = 'github.com/example/other'
            docs['other.json']['checks'] = [{'name': 'Check', 'score': -1}]
            docs['stale.json'] = copy.deepcopy(docs['other.json'])
            docs['stale.json']['repo']['name'] = 'github.com/example/stale'
        self.after['stale.json']['date'] = '2026-11-02'
        report = self.library_report()
        self.assert_check_comparability(report, 4, 1, 1)
        self.assert_check_comparability_by_check(report, [
            {'name': ' Check', 'comparable': 1, 'evidence_blocked': 0, 'observation_blocked': 0},
            {'name': 'Check', 'comparable': 1, 'evidence_blocked': 1, 'observation_blocked': 1},
            {'name': 'check', 'comparable': 1, 'evidence_blocked': 0, 'observation_blocked': 0},
            {'name': 'é', 'comparable': 1, 'evidence_blocked': 0, 'observation_blocked': 0}])

    def test_check_comparability_evidence_priority_over_simultaneous_observation_gaps(self):
        old = [{'name': 'Known', 'score': 0}, {'name': 'Negative', 'score': -1},
               {'name': 'Null', 'score': None}, {'name': 'Absent'}, {'name': 'Deleted', 'score': 5}]
        new = [{'name': 'Known', 'score': 10}, {'name': 'Negative', 'score': -1},
               {'name': 'Null', 'score': None}, {'name': 'Absent'}, {'name': 'Added', 'score': 5}]
        for before, after, age, status in (
                ('2026-11-01', '2026-11-11', 2, 'comparable'),
                ('2026-10-01', '2026-11-11', 2, 'stale_before'),
                ('2026-11-01', '2026-11-02', 2, 'stale_after'),
                ('2026-11-01', '2026-10-31', 30, 'snapshot_time_regressed'),
                ('2026-11-01', '2026-11-01', 30, 'snapshot_time_ambiguous')):
            with self.subTest(status=status):
                self.before = {'demo.json': self.snapshot(before, 0, '1')}
                self.after = {'demo.json': self.snapshot(after, 10, '2')}
                self.before['demo.json']['checks'], self.after['demo.json']['checks'] = old, new
                report = self.library_report(age)
                row = report['repositories'][0]
                self.assertEqual(row['comparison'], status)
                self.assert_check_comparability(report, 1, 0, 5) if status == 'comparable' else \
                    self.assert_check_comparability(report, 0, 6, 0)
                self.assert_check_comparability_by_check(report, [
                    {'name': name, 'comparable': int(status == 'comparable' and name == 'Known'),
                     'evidence_blocked': int(status != 'comparable'),
                     'observation_blocked': int(status == 'comparable' and name != 'Known')}
                    for name in ('Absent', 'Added', 'Deleted', 'Known', 'Negative', 'Null')])
                self.assert_check_score_changes_by_check(report, [
                    {'name': name, 'increased': int(status == 'comparable' and name == 'Known'),
                     'decreased': 0, 'unchanged': 0,
                     'not_comparable': int(status != 'comparable' or name != 'Known')}
                    for name in ('Absent', 'Added', 'Deleted', 'Known', 'Negative', 'Null')])
                checks = {check['name']: check for check in row['checks']}
                self.assertEqual([checks[item['name']]['before'] for item in old], old)
                self.assertEqual([checks[item['name']]['after'] for item in new], new)
                self.assertEqual(checks['Known']['scoreChange'],
                                 'increased' if status == 'comparable' else 'not_comparable')
                self.assertEqual(checks['Negative']['beforeObservation'], 'negative_score')
                self.assertEqual(checks['Null']['afterObservation'], 'missing_score')

    def test_check_score_summary_known_boundaries_and_unknown_transitions(self):
        # Six score states on each side: nine known pairs, 27 unknown pairs.
        old, new = [], []
        for i, before in enumerate(('absent', None, -1, 0, 5, 10)):
            for j, after in enumerate(('absent', None, -1, 0, 5, 10)):
                name = f'States-{i}-{j}'
                old.append({'name': name, **({} if before == 'absent' else {'score': before})})
                new.append({'name': name, **({} if after == 'absent' else {'score': after})})
        old.append({'name': 'DeletedKnown', 'score': 10})
        new.append({'name': 'AddedKnown', 'score': 10})
        self.before['demo.json']['checks'], self.after['demo.json']['checks'] = old, new
        report = self.library_report()
        self.assert_check_score_summary(report, {
            'increased': 3, 'decreased': 3, 'unchanged': 3, 'not_comparable': 29})
        self.assert_check_summary(report, {
            'changed': 30, 'unchanged': 6, 'added': 1, 'deleted': 1, 'not_comparable': 0})
        self.assert_check_observations(report,
            {'known': 19, 'negative_score': 6, 'missing_score': 12, 'missing_check': 1, 'missing_snapshot': 0},
            {'known': 19, 'negative_score': 6, 'missing_score': 12, 'missing_check': 1, 'missing_snapshot': 0})
        self.assert_check_transitions(report, {
            ('known', 'known'): 9, ('known', 'negative_score'): 3, ('known', 'missing_score'): 6,
            ('known', 'missing_check'): 1, ('negative_score', 'known'): 3,
            ('negative_score', 'negative_score'): 1, ('negative_score', 'missing_score'): 2,
            ('missing_score', 'known'): 6, ('missing_score', 'negative_score'): 2,
            ('missing_score', 'missing_score'): 4, ('missing_check', 'known'): 1})
        self.assert_check_comparability(report, 9, 0, 29)
        self.assert_check_comparability_by_check(report, [
            {'name': 'AddedKnown', 'comparable': 0, 'evidence_blocked': 0, 'observation_blocked': 1},
            {'name': 'DeletedKnown', 'comparable': 0, 'evidence_blocked': 0, 'observation_blocked': 1},
            *[{'name': f'States-{i}-{j}', 'comparable': int(i >= 3 and j >= 3),
               'evidence_blocked': 0, 'observation_blocked': int(i < 3 or j < 3)}
              for i in range(6) for j in range(6)]])
        self.assert_check_score_changes_by_check(report, [
            {'name': 'AddedKnown', 'increased': 0, 'decreased': 0, 'unchanged': 0, 'not_comparable': 1},
            {'name': 'DeletedKnown', 'increased': 0, 'decreased': 0, 'unchanged': 0, 'not_comparable': 1},
            *[{'name': f'States-{i}-{j}', 'increased': int(i >= 3 and j > i),
               'decreased': int(j >= 3 and i > j), 'unchanged': int(i >= 3 and i == j),
               'not_comparable': int(i < 3 or j < 3)} for i in range(6) for j in range(6)]])
        checks = {row['name']: row for row in report['repositories'][0]['checks']}
        self.assertEqual([checks[item['name']]['before'] for item in old], old)
        self.assertEqual([checks[item['name']]['after'] for item in new], new)
        for name in ('AddedKnown', 'DeletedKnown'):
            self.assertEqual(checks[name]['scoreChange'], 'not_comparable')

    def test_check_summary_fixture_literal_contract(self):
        from vulnwrench.scorecard import compare
        report = compare(FIXTURE / 'bom.json', FIXTURE / 'repos.json', FIXTURE / 'before',
                         FIXTURE / 'after', '2026-11-01', '2026-11-11', max_age_days=2)
        self.assert_check_summary(report, {
            'changed': 5, 'unchanged': 0, 'added': 1, 'deleted': 1, 'not_comparable': 1})
        self.assert_check_score_summary(report, {
            'increased': 2, 'decreased': 0, 'unchanged': 1, 'not_comparable': 5})
        self.assert_check_observations(report,
            {'known': 6, 'negative_score': 1, 'missing_score': 0, 'missing_check': 1, 'missing_snapshot': 0},
            {'known': 6, 'negative_score': 0, 'missing_score': 0, 'missing_check': 1, 'missing_snapshot': 1})
        self.assert_check_transitions(report, {
            ('known', 'known'): 4, ('known', 'missing_check'): 1, ('known', 'missing_snapshot'): 1,
            ('negative_score', 'known'): 1, ('missing_check', 'known'): 1})
        self.assert_check_comparability(report, 3, 2, 3)
        self.assertEqual(report['summary'], json.loads((FIXTURE / 'expected-summary.json').read_text()))

    def test_check_summary_raw_records_and_unknown_score_direction_are_independent(self):
        old = [
            {'name': 'ChangedScore', 'score': 3},
            {'name': 'ReasonOnly', 'score': 5, 'reason': 'old'},
            {'name': 'ExtensionOnly', 'score': -1, 'extension': {'raw': 'old'}},
            {'name': 'AbsentToNull'},
            {'name': 'UnknownSame', 'score': -1},
            {'name': 'AbsentSame'},
            {'name': 'NullSame', 'score': None},
            {'name': 'KnownSame', 'score': 5},
            {'name': 'Deleted'}]
        new = copy.deepcopy(old[:-1]) + [{'name': 'Added', 'score': -1}]
        new[0]['score'] = 8
        new[1]['reason'] = 'new'
        new[2]['extension']['raw'] = 'new'
        new[3]['score'] = None
        self.before['demo.json']['checks'], self.after['demo.json']['checks'] = old, new
        report = self.library_report()
        self.assert_check_summary(report, {
            'changed': 4, 'unchanged': 4, 'added': 1, 'deleted': 1, 'not_comparable': 0})
        self.assert_check_score_summary(report, {
            'increased': 1, 'decreased': 0, 'unchanged': 2, 'not_comparable': 7})
        self.assert_check_observations(report,
            {'known': 3, 'negative_score': 2, 'missing_score': 4, 'missing_check': 1, 'missing_snapshot': 0},
            {'known': 3, 'negative_score': 3, 'missing_score': 3, 'missing_check': 1, 'missing_snapshot': 0})
        self.assert_check_transitions(report, {
            ('known', 'known'): 3, ('negative_score', 'negative_score'): 2,
            ('missing_score', 'missing_score'): 3, ('missing_score', 'missing_check'): 1,
            ('missing_check', 'negative_score'): 1})
        self.assert_check_comparability(report, 3, 0, 7)
        checks = {row['name']: row for row in report['repositories'][0]['checks']}
        for name in ('ExtensionOnly', 'AbsentToNull', 'UnknownSame', 'AbsentSame', 'NullSame', 'Added', 'Deleted'):
            self.assertEqual(checks[name]['scoreChange'], 'not_comparable')
        self.assertEqual(checks['ChangedScore']['scoreChange'], 'increased')
        self.assertEqual(checks['ReasonOnly']['scoreChange'], 'unchanged')
        self.assertEqual(checks['KnownSame']['scoreChange'], 'unchanged')
        self.assertEqual([checks[item['name']]['before'] for item in old], old)
        self.assertEqual([checks[item['name']]['after'] for item in new], new)

    def test_check_summary_missing_future_and_chronology_blockers_keep_raw_classifications(self):
        for before, after, age, comparison, bucket, count in (
                (None, '2026-11-11', 2, 'missing_before', 'not_comparable', 1),
                ('2026-11-12', '2026-11-11', 2, 'missing_before', 'not_comparable', 1),
                ('2026-11-01', None, 2, 'missing_after', 'not_comparable', 1),
                ('2026-11-01', '2026-11-12', 2, 'missing_after', 'not_comparable', 1),
                (None, None, 2, 'missing_both', 'not_comparable', 0),
                ('2026-11-12', '2026-11-12', 2, 'missing_both', 'not_comparable', 0),
                ('2026-10-01', '2026-11-11', 2, 'stale_before', 'changed', 1),
                ('2026-11-01', '2026-11-02', 2, 'stale_after', 'changed', 1),
                ('2026-11-01', '2026-10-31', 30, 'snapshot_time_regressed', 'changed', 1),
                ('2026-11-01', '2026-11-01T01:00:00+01:00', 30,
                 'snapshot_time_ambiguous', 'changed', 1)):
            with self.subTest(before=before, after=after):
                self.before = {} if before is None else {'demo.json': self.snapshot(before, 3, '1')}
                self.after = {} if after is None else {'demo.json': self.snapshot(after, 8, '2')}
                report = self.library_report(age)
                expected = {'changed': 0, 'unchanged': 0, 'added': 0, 'deleted': 0, 'not_comparable': 0}
                expected[bucket] = count
                self.assert_check_summary(report, expected)
                self.assert_check_score_summary(report, {
                    'increased': 0, 'decreased': 0, 'unchanged': 0, 'not_comparable': count})
                self.assert_check_comparability(report, 0, count, 0)
                self.assert_check_comparability_by_check(report, [
                    {'name': 'Code-Review', 'comparable': 0, 'evidence_blocked': 1, 'observation_blocked': 0}
                ] if count else [])
                self.assert_check_score_changes_by_check(report, [
                    {'name': 'Code-Review', 'increased': 0, 'decreased': 0, 'unchanged': 0, 'not_comparable': 1}
                ] if count else [])
                observations = []
                for date, cutoff in ((before, '2026-11-01'), (after, '2026-11-11')):
                    available = date is not None and date <= cutoff
                    observations.append({'known': count if available else 0, 'negative_score': 0,
                        'missing_score': 0, 'missing_check': 0,
                        'missing_snapshot': count if not available else 0})
                self.assert_check_observations(report, *observations)
                self.assert_check_transitions(report, {} if not count else {
                    (next(key for key, n in observations[0].items() if n),
                     next(key for key, n in observations[1].items() if n)): 1})
                row = report['repositories'][0]
                self.assertEqual(row['comparison'], comparison)
                for check in row['checks']:
                    self.assertEqual((check['change'], check['scoreChange']), (bucket, 'not_comparable'))

    def test_check_summary_counts_canonical_repository_check_pairs_only(self):
        self.bom['components'] += [copy.deepcopy(self.bom['components'][0]),
            {'type': 'library', 'name': 'helper', 'purl': 'pkg:npm/helper@1'},
            {'type': 'library', 'name': 'other', 'purl': 'pkg:npm/other@1'},
            {'type': 'library', 'name': 'unmapped', 'purl': 'pkg:npm/unmapped@1'},
            {'type': 'file', 'name': 'local'}]
        self.mapping.update({'pkg:npm/helper@1': 'https://GitHub.com/EXAMPLE/Demo.git/',
                             'pkg:npm/other@1': 'github.com/example/other',
                             'pkg:npm/unused@1': 'github.com/example/unused'})
        for side in ('before', 'after'):
            docs = getattr(self, side)
            docs['other.json'] = copy.deepcopy(docs['demo.json'])
            docs['other.json']['repo']['name'] = 'github.com/example/other'
            docs['unused.json'] = copy.deepcopy(docs['demo.json'])
            docs['unused.json']['repo']['name'] = 'github.com/example/unused'
            docs['unused.json']['checks'] = [{'name': 'Excluded'}]
            docs['duplicate.json'] = copy.deepcopy(docs['demo.json'])
            for name, date in (('historical', '2026-10-31'), ('future', '2026-11-12')):
                docs[name + '.json'] = copy.deepcopy(docs['demo.json'])
                docs[name + '.json']['date'] = date
                docs[name + '.json']['checks'] = [{'name': 'Excluded'}]
        report = self.library_report()
        self.assertEqual(report['summary']['comparedRepositories'], 2)
        self.assertEqual(report['summary']['mappedComponents'], 4)
        self.assertEqual(len(report['components']), 6)
        self.assertEqual(report['summary']['unusedMappings'], ['pkg:npm/unused@1'])
        self.assert_check_summary(report, {
            'changed': 2, 'unchanged': 0, 'added': 0, 'deleted': 0, 'not_comparable': 0})
        self.assert_check_score_summary(report, {
            'increased': 2, 'decreased': 0, 'unchanged': 0, 'not_comparable': 0})
        self.assert_check_observations(report,
            {'known': 2, 'negative_score': 0, 'missing_score': 0, 'missing_check': 0, 'missing_snapshot': 0},
            {'known': 2, 'negative_score': 0, 'missing_score': 0, 'missing_check': 0, 'missing_snapshot': 0})
        self.assert_check_transitions(report, {('known', 'known'): 2})
        self.assert_check_comparability(report, 2, 0, 0)
        self.assert_check_comparability_by_check(report, [
            {'name': 'Code-Review', 'comparable': 2, 'evidence_blocked': 0, 'observation_blocked': 0}])
        self.assert_check_score_changes_by_check(report, [
            {'name': 'Code-Review', 'increased': 2, 'decreased': 0, 'unchanged': 0, 'not_comparable': 0}])
        for side in ('before', 'after'):
            self.assertEqual(len(report[side]['snapshots']), 5)
            self.assertTrue(any(s['document']['checks'] == [{'name': 'Excluded'}]
                                for s in report[side]['snapshots']))

    def test_check_summary_empty_observations_have_five_zero_counts(self):
        for state in ('empty_inventory', 'unmapped', 'missing_both', 'empty_checks'):
            with self.subTest(state=state):
                self.bom['components'] = ([] if state == 'empty_inventory' else
                    [{'type': 'file', 'name': 'local'}] if state == 'unmapped' else
                    [{'type': 'library', 'name': 'demo', 'purl': 'pkg:npm/demo@1'}])
                self.before = {} if state == 'missing_both' else {'demo.json': self.snapshot('2026-11-01', 3, '1')}
                self.after = {} if state == 'missing_both' else {'demo.json': self.snapshot('2026-11-11', 8, '2')}
                if state == 'empty_checks':
                    self.before['demo.json']['checks'] = self.after['demo.json']['checks'] = []
                report = self.library_report()
                self.assert_check_summary(report, {
                    'changed': 0, 'unchanged': 0, 'added': 0, 'deleted': 0, 'not_comparable': 0})
                self.assert_check_score_summary(report, {
                    'increased': 0, 'decreased': 0, 'unchanged': 0, 'not_comparable': 0})
                self.assert_check_observations(report,
                    {'known': 0, 'negative_score': 0, 'missing_score': 0, 'missing_check': 0, 'missing_snapshot': 0},
                    {'known': 0, 'negative_score': 0, 'missing_score': 0, 'missing_check': 0, 'missing_snapshot': 0})
                self.assert_check_transitions(report, {})
                self.assert_check_comparability(report, 0, 0, 0)
                self.assert_check_comparability_by_check(report, [])
                self.assert_check_score_changes_by_check(report, [])

    def test_check_transitions_unknown_scores_against_absent_checks_and_snapshots(self):
        checks = [{'name': 'Absent'}, {'name': 'Null', 'score': None},
                  {'name': 'Negative', 'score': -1}, {'name': 'Zero', 'score': 0}]
        for gap in ('empty_checks', 'missing_snapshot', 'future_snapshot'):
            for side in ('before', 'after'):
                with self.subTest(gap=gap, side=side):
                    self.before = {'demo.json': self.snapshot('2026-11-01', 3, '1')}
                    self.after = {'demo.json': self.snapshot('2026-11-11', 8, '2')}
                    getattr(self, 'after' if side == 'before' else 'before')['demo.json']['checks'] = checks
                    if gap == 'missing_snapshot':
                        setattr(self, side, {})
                    else:
                        getattr(self, side)['demo.json']['checks'] = []
                        if gap == 'future_snapshot':
                            getattr(self, side)['demo.json']['date'] = '2026-11-12'
                    report = self.library_report()
                    label = 'missing_check' if gap == 'empty_checks' else 'missing_snapshot'
                    nonzero = {(label, value) if side == 'before' else (value, label): count
                               for value, count in [('known', 1), ('negative_score', 1), ('missing_score', 2)]}
                    self.assert_check_transitions(report, nonzero)
                    self.assert_check_comparability(report, 0, 0, 4) if gap == 'empty_checks' else \
                        self.assert_check_comparability(report, 0, 4, 0)
                    self.assert_check_comparability_by_check(report, [
                        {'name': name, 'comparable': 0, 'evidence_blocked': int(gap != 'empty_checks'),
                         'observation_blocked': int(gap == 'empty_checks')}
                        for name in ('Absent', 'Negative', 'Null', 'Zero')])
                    self.assert_check_score_summary(report, {
                        'increased': 0, 'decreased': 0, 'unchanged': 0, 'not_comparable': 4})
                    self.assert_check_score_changes_by_check(report, [
                        {'name': name, 'increased': 0, 'decreased': 0, 'unchanged': 0, 'not_comparable': 1}
                        for name in ('Absent', 'Negative', 'Null', 'Zero')])
                    self.assertEqual([row['after' if side == 'before' else 'before']
                                      for row in report['repositories'][0]['checks']],
                                     sorted(checks, key=lambda check: check['name']))

    def test_snapshot_summary_fixture_literal_contract(self):
        from vulnwrench.scorecard import compare
        report = compare(FIXTURE / 'bom.json', FIXTURE / 'repos.json', FIXTURE / 'before',
                         FIXTURE / 'after', '2026-11-01', '2026-11-11', max_age_days=2)
        self.assert_snapshot_summary(report, {
            'advanced': 3, 'unchanged': 0, 'regressed': 0,
            'same_timestamp_changed': 0, 'not_comparable': 1})
        self.assertEqual(report['summary'], json.loads((FIXTURE / 'expected-summary.json').read_text()))

    def test_snapshot_summary_chronology_survives_comparison_blockers(self):
        for before, after, identical, age, snapshot_change, comparison in (
                ('2026-11-01', '2026-11-11', False, 2, 'advanced', 'comparable'),
                ('2026-11-01', '2026-11-01', True, 30, 'unchanged', 'comparable'),
                ('2026-11-01', '2026-11-01', True, 2, 'unchanged', 'stale_after'),
                ('2026-11-01', '2026-10-31', False, 30, 'regressed', 'snapshot_time_regressed'),
                ('2026-11-01', '2026-10-31', False, 2, 'regressed', 'stale_after'),
                ('2026-11-01', '2026-11-01T01:00:00+01:00', False, 30,
                 'same_timestamp_changed', 'snapshot_time_ambiguous'),
                ('2026-11-01', '2026-11-01', False, 2, 'same_timestamp_changed', 'stale_after'),
                ('2026-10-01', '2026-10-02', False, 2, 'advanced', 'stale_after'),
                ('2026-10-01', '2026-11-11', False, 2, 'advanced', 'stale_before'),
                (None, None, False, 2, 'not_comparable', 'missing_both'),
                ('2026-11-12', '2026-11-12', False, 2, 'not_comparable', 'missing_both'),
                ('2026-11-01', None, False, 2, 'not_comparable', 'missing_after'),
                ('2026-10-01', '2026-11-12', False, 2, 'not_comparable', 'missing_after'),
                (None, '2026-11-11', False, 2, 'not_comparable', 'missing_before'),
                ('2026-11-12', '2026-10-01', False, 2, 'not_comparable', 'missing_before')):
            with self.subTest(before=before, after=after, identical=identical, age=age):
                self.before = {} if before is None else {'demo.json': self.snapshot(before, 3, '1')}
                self.after = (copy.deepcopy(self.before) if identical else
                              {} if after is None else {'demo.json': self.snapshot(after, 8, '2')})
                report = self.library_report(age)
                expected = {'advanced': 0, 'unchanged': 0, 'regressed': 0,
                            'same_timestamp_changed': 0, 'not_comparable': 0}
                expected[snapshot_change] = 1
                self.assert_snapshot_summary(report, expected)
                row = report['repositories'][0]
                self.assertEqual((row['snapshotChange'], row['comparison']), (snapshot_change, comparison))
                direction = ('unchanged' if identical else 'increased') if comparison == 'comparable' else 'not_comparable'
                self.assertTrue(all(check['scoreChange'] == direction for check in row['checks']))
                # Raw check objects and scanner identities stay visible, even with blocked score direction.
                if before is not None and after is not None and before != '2026-11-12' and after != '2026-11-12':
                    self.assertEqual(row['checks'][0]['before']['score'], 3)
                    self.assertEqual(row['checks'][0]['after']['score'], 3 if identical else 8)
                    self.assertEqual(row['scannerChange']['versionChange'], 'unchanged')

    def test_snapshot_summary_counts_canonical_repositories_and_selected_documents_once(self):
        self.bom['components'] = []
        self.mapping, self.before, self.after = {}, {}, {}
        for name, date in (('advanced', '2026-11-11'), ('unchanged', '2026-11-01'),
                           ('regressed', '2026-10-31'), ('same_timestamp_changed', '2026-11-01'),
                           ('not_comparable', '2026-11-12')):
            purl = f'pkg:npm/{name}@1'
            self.bom['components'].append({'type': 'library', 'name': name, 'purl': purl})
            self.mapping[purl] = f'github.com/example/{name}'
            old = self.snapshot('2026-11-01', 3, '1')
            old['repo']['name'] = f'github.com/example/{name}'
            new = copy.deepcopy(old) if name == 'unchanged' else self.snapshot(date, 8, '2')
            new['repo']['name'] = old['repo']['name']
            self.before[name + '.json'], self.after[name + '.json'] = old, new
        self.bom['components'] += [copy.deepcopy(self.bom['components'][0]),
            {'type': 'library', 'name': 'helper', 'purl': 'pkg:npm/helper@1'},
            {'type': 'library', 'name': 'unmapped', 'purl': 'pkg:npm/unmapped@1'},
            {'type': 'file', 'name': 'local'}]
        self.mapping['pkg:npm/helper@1'] = 'https://GitHub.com/EXAMPLE/Advanced.git/'
        self.mapping['pkg:npm/unused@1'] = REPO
        self.after['unused.json'] = self.snapshot('2026-11-11', 10, '2')
        self.after['duplicate.json'] = copy.deepcopy(self.after['advanced.json'])
        for name, date in (('old', '2026-11-10'), ('future', '2026-11-12')):
            self.after[name + '.json'] = copy.deepcopy(self.after['advanced.json'])
            self.after[name + '.json']['date'] = date
        report = self.library_report(30)
        self.assertEqual(report['summary']['mappedComponents'], 7)
        self.assertEqual(report['summary']['unmappedComponents'], 2)
        self.assertEqual(report['summary']['unusedMappings'], ['pkg:npm/unused@1'])
        self.assert_snapshot_summary(report, {
            'advanced': 1, 'unchanged': 1, 'regressed': 1,
            'same_timestamp_changed': 1, 'not_comparable': 1})
        self.assert_comparison_summary(report, {
            'comparable': 2, 'missing_both': 0, 'missing_after': 1, 'missing_before': 0,
            'stale_after': 0, 'stale_before': 0, 'snapshot_time_regressed': 1,
            'snapshot_time_ambiguous': 1})
        self.assert_scanner_summary(report, {
            'version': {'changed': 0, 'unchanged': 4, 'not_comparable': 1},
            'commit': {'changed': 0, 'unchanged': 4, 'not_comparable': 1}})

    def test_snapshot_summary_empty_mapped_inventory_has_five_zero_counts(self):
        for components in ([], [{'type': 'file', 'name': 'local'},
                                {'type': 'library', 'name': 'unknown', 'purl': 'pkg:npm/unknown@1'}]):
            with self.subTest(components=components):
                self.bom['components'] = components
                report = self.library_report()
                self.assertEqual(report['repositories'], [])
                self.assertEqual(report['summary']['unusedMappings'], ['pkg:npm/demo@1'])
                self.assert_snapshot_summary(report, {
                    'advanced': 0, 'unchanged': 0, 'regressed': 0,
                    'same_timestamp_changed': 0, 'not_comparable': 0})

    def test_comparison_summary_fixture_literal_contract(self):
        from vulnwrench.scorecard import compare
        report = compare(FIXTURE / 'bom.json', FIXTURE / 'repos.json', FIXTURE / 'before',
                         FIXTURE / 'after', '2026-11-01', '2026-11-11', max_age_days=2)
        self.assertEqual(report['summary'], json.loads((FIXTURE / 'expected-summary.json').read_text()))
        self.assert_comparison_summary(report, {
            'comparable': 2, 'missing_both': 0, 'missing_after': 1, 'missing_before': 0,
            'stale_after': 1, 'stale_before': 0, 'snapshot_time_regressed': 0,
            'snapshot_time_ambiguous': 0})

    def test_comparison_summary_statuses_and_blocker_priority(self):
        for before, after, age, status in (
                ('2026-11-01', '2026-11-11', 2, 'comparable'),
                (None, None, 2, 'missing_both'),
                ('2026-11-12', '2026-11-12', 2, 'missing_both'),
                (None, '2026-11-12', 2, 'missing_both'),
                ('2026-11-12', None, 2, 'missing_both'),
                ('2026-11-01', None, 2, 'missing_after'),
                ('2026-10-01', '2026-11-12', 2, 'missing_after'),
                (None, '2026-11-11', 2, 'missing_before'),
                ('2026-11-12', '2026-10-01', 2, 'missing_before'),
                ('2026-11-01', '2026-11-02', 2, 'stale_after'),
                ('2026-10-01', '2026-10-02', 2, 'stale_after'),
                ('2026-11-01', '2026-10-31', 2, 'stale_after'),
                ('2026-11-01', '2026-11-01', 2, 'stale_after'),
                ('2026-10-01', '2026-11-11', 2, 'stale_before'),
                ('2026-11-01', '2026-10-31', 30, 'snapshot_time_regressed'),
                ('2026-11-01', '2026-11-01T01:00:00+01:00', 30, 'snapshot_time_ambiguous')):
            with self.subTest(before=before, after=after, age=age, status=status):
                self.before = {} if before is None else {'demo.json': self.snapshot(before, 3, '1')}
                self.after = {} if after is None else {'demo.json': self.snapshot(after, 8, '2')}
                report = self.library_report(age)
                expected = {'comparable': 0, 'missing_both': 0, 'missing_after': 0, 'missing_before': 0,
                            'stale_after': 0, 'stale_before': 0, 'snapshot_time_regressed': 0,
                            'snapshot_time_ambiguous': 0}
                expected[status] = 1
                self.assert_comparison_summary(report, expected)
                row = report['repositories'][0]
                self.assertEqual(row['comparison'], status)
                self.assertTrue(all(check['scoreChange'] == ('increased' if status == 'comparable'
                                                            else 'not_comparable') for check in row['checks']))
                known = row['before']['snapshotId'] is not None and row['after']['snapshotId'] is not None
                self.assert_scanner_summary(report, {
                    'version': {'changed': 0, 'unchanged': int(known), 'not_comparable': int(not known)},
                    'commit': {'changed': 0, 'unchanged': int(known), 'not_comparable': int(not known)}})

        # Comparable evidence does not guarantee a directional check comparison.
        self.before = {'demo.json': self.snapshot('2026-11-01', -1, '1')}
        self.after = {'demo.json': self.snapshot('2026-11-11', 8, '2')}
        report = self.library_report()
        self.assert_comparison_summary(report, {
            'comparable': 1, 'missing_both': 0, 'missing_after': 0, 'missing_before': 0,
            'stale_after': 0, 'stale_before': 0, 'snapshot_time_regressed': 0,
            'snapshot_time_ambiguous': 0})
        self.assertEqual(report['repositories'][0]['checks'][0]['scoreChange'], 'not_comparable')

    def test_comparison_summary_mixed_statuses_count_canonical_repositories_once(self):
        self.bom['components'] = []
        self.mapping, self.before, self.after = {}, {}, {}
        for name, before, after in (
                ('comparable', '2026-11-01', '2026-11-11'),
                ('missing_both', None, None),
                ('missing_after', '2026-11-01', '2026-11-12'),
                ('missing_before', '2026-11-12', '2026-11-11'),
                ('stale_after', '2026-11-01', '2026-10-01'),
                ('stale_before', '2026-10-01', '2026-11-11'),
                ('snapshot_time_regressed', '2026-11-01', '2026-10-31'),
                ('snapshot_time_ambiguous', '2026-11-01', '2026-11-01')):
            purl = f'pkg:npm/{name}@1'
            self.bom['components'].append({'type': 'library', 'name': name, 'purl': purl})
            self.mapping[purl] = f'github.com/example/{name}'
            for side, date, score, commit in (('before', before, 3, '1'), ('after', after, 8, '2')):
                if date is not None:
                    snapshot = self.snapshot(date, score, commit)
                    snapshot['repo']['name'] = f'github.com/example/{name}'
                    getattr(self, side)[name + '.json'] = snapshot
        self.bom['components'] += [copy.deepcopy(self.bom['components'][0]),
            {'type': 'library', 'name': 'helper', 'purl': 'pkg:npm/helper@1'},
            {'type': 'library', 'name': 'unmapped', 'purl': 'pkg:npm/unmapped@1'},
            {'type': 'file', 'name': 'local'}]
        self.mapping['pkg:npm/helper@1'] = 'https://GitHub.com/EXAMPLE/Comparable.git/'
        self.mapping['pkg:npm/unused@1'] = REPO
        self.after['unused.json'] = self.snapshot('2026-11-11', 8, '2')
        self.after['duplicate.json'] = copy.deepcopy(self.after['comparable.json'])
        self.after['old.json'] = copy.deepcopy(self.after['comparable.json'])
        self.after['old.json']['date'] = '2026-11-10'
        report = self.library_report(30)
        self.assertEqual(report['summary']['mappedComponents'], 10)
        self.assertEqual(report['summary']['unmappedComponents'], 2)
        self.assertEqual(report['summary']['unusedMappings'], ['pkg:npm/unused@1'])
        self.assertEqual(report['summary']['comparedRepositories'], 8)
        self.assert_comparison_summary(report, {
            'comparable': 1, 'missing_both': 1, 'missing_after': 1, 'missing_before': 1,
            'stale_after': 1, 'stale_before': 1, 'snapshot_time_regressed': 1,
            'snapshot_time_ambiguous': 1})

    def test_comparison_summary_empty_mapped_inventory_has_all_zero_counts(self):
        for components in ([], [{'type': 'file', 'name': 'local'},
                                {'type': 'library', 'name': 'unknown', 'purl': 'pkg:npm/unknown@1'}]):
            with self.subTest(components=components):
                self.bom['components'] = components
                report = self.library_report()
                self.assertEqual(report['repositories'], [])
                self.assert_comparison_summary(report, {
                    'comparable': 0, 'missing_both': 0, 'missing_after': 0, 'missing_before': 0,
                    'stale_after': 0, 'stale_before': 0, 'snapshot_time_regressed': 0,
                    'snapshot_time_ambiguous': 0})

    def test_scanner_summary_fixture_literal_contract(self):
        from vulnwrench.scorecard import compare
        report = compare(FIXTURE / 'bom.json', FIXTURE / 'repos.json', FIXTURE / 'before',
                         FIXTURE / 'after', '2026-11-01', '2026-11-11', max_age_days=2)
        expected = json.loads((FIXTURE / 'expected-summary.json').read_text())
        self.assertEqual(report['summary'], expected)
        self.assert_scanner_summary(report, {
            'version': {'changed': 1, 'unchanged': 2, 'not_comparable': 1},
            'commit': {'changed': 1, 'unchanged': 2, 'not_comparable': 1}})

    def test_scanner_summary_counts_each_canonical_mapped_repository_once(self):
        demo = self.bom['components'][0]
        self.bom['components'] += [copy.deepcopy(demo),
            {'type': 'library', 'name': 'helper', 'purl': 'pkg:npm/helper@2'},
            {'type': 'library', 'name': 'unmapped', 'purl': 'pkg:npm/unmapped@1'},
            {'type': 'file', 'name': 'local'}]
        self.mapping['pkg:npm/helper@2'] = 'https://GitHub.com/EXAMPLE/Demo.git/'
        self.mapping['pkg:npm/unused@1'] = 'github.com/example/unused'
        self.after['demo.json']['scorecard']['version'] = 'v5.1.0'
        self.after['copy.json'] = copy.deepcopy(self.after['demo.json'])
        self.after['unmapped.json'] = self.snapshot('2026-11-11', 10, '3')
        self.after['unmapped.json']['repo']['name'] = 'github.com/example/unused'
        report = self.library_report()
        self.assertEqual(report['summary']['mappedComponents'], 3)
        self.assertEqual(report['summary']['comparedRepositories'], 1)
        self.assertEqual(len(report['after']['snapshots']), 2)
        self.assert_scanner_summary(report, {
            'version': {'changed': 1, 'unchanged': 0, 'not_comparable': 0},
            'commit': {'changed': 0, 'unchanged': 1, 'not_comparable': 0}})

    def test_scanner_summary_partial_and_unknown_fields_are_independent(self):
        changed = {'changed': 1, 'unchanged': 0, 'not_comparable': 0}
        unchanged = {'changed': 0, 'unchanged': 1, 'not_comparable': 0}
        unknown = {'changed': 0, 'unchanged': 0, 'not_comparable': 1}
        for old, new, version, commit in (
                ({'version': 'v5', 'commit': 'a'}, {'version': 'v5', 'commit': 'a'}, unchanged, unchanged),
                ({'version': 'v5', 'commit': 'a'}, {'version': 'v6', 'commit': 'b'}, changed, changed),
                ({'version': 'v5'}, {'version': 'v6'}, changed, unknown),
                ({'version': 'v5'}, {'version': 'v5', 'commit': 'a'}, unchanged, unknown),
                ({'commit': 'a'}, {'version': 'v5', 'commit': 'b'}, unknown, changed),
                ({'version': 'v5', 'commit': 'a'}, {'commit': 'a'}, unknown, unchanged)):
            with self.subTest(old=old, new=new):
                self.before['demo.json']['scorecard'] = old
                self.after['demo.json']['scorecard'] = new
                self.assert_scanner_summary(self.library_report(), {'version': version, 'commit': commit})
        for field, other in (('version', 'commit'), ('commit', 'version')):
            for value in (None, '', '  ', 5, False, [], {}):
                for side in ('before', 'after', 'both'):
                    with self.subTest(field=field, value=value, side=side):
                        self.before['demo.json']['scorecard'] = {'version': 'v5', 'commit': 'a'}
                        self.after['demo.json']['scorecard'] = {'version': 'v5', 'commit': 'a'}
                        for selected in ('before', 'after') if side == 'both' else (side,):
                            getattr(self, selected)['demo.json']['scorecard'][field] = value
                        self.assert_scanner_summary(self.library_report(), {field: unknown, other: unchanged})
        for metadata in ('absent', None, [], 'v5', 5, False, {}):
            for side in ('before', 'after', 'both'):
                with self.subTest(metadata=metadata, side=side):
                    self.before['demo.json']['scorecard'] = {'version': 'v5', 'commit': 'a'}
                    self.after['demo.json']['scorecard'] = {'version': 'v5', 'commit': 'a'}
                    for selected in ('before', 'after') if side == 'both' else (side,):
                        if metadata == 'absent':
                            getattr(self, selected)['demo.json'].pop('scorecard')
                        else:
                            getattr(self, selected)['demo.json']['scorecard'] = metadata
                    self.assert_scanner_summary(self.library_report(), {'version': unknown, 'commit': unknown})

    def test_scanner_summary_missing_and_future_only_selections(self):
        for before, after in (('missing', 'known'), ('future', 'known'),
                              ('known', 'missing'), ('known', 'future'),
                              ('missing', 'missing'), ('future', 'future')):
            with self.subTest(before=before, after=after):
                for side, status, date in (('before', before, '2026-11-01'),
                                           ('after', after, '2026-11-11')):
                    setattr(self, side, {} if status == 'missing' else {
                        'demo.json': self.snapshot('2026-11-12' if status == 'future' else date, 8, '1')})
                self.assert_scanner_summary(self.library_report(), {
                    'version': {'changed': 0, 'unchanged': 0, 'not_comparable': 1},
                    'commit': {'changed': 0, 'unchanged': 0, 'not_comparable': 1}})

    def test_scanner_summary_zero_for_empty_mapped_inventory(self):
        for components in ([], [{'type': 'file', 'name': 'local'},
                                {'type': 'library', 'name': 'unknown', 'purl': 'pkg:npm/unknown@1'}]):
            with self.subTest(components=components):
                self.bom['components'] = components
                report = self.library_report()
                self.assertEqual(report['repositories'], [])
                self.assertEqual(report['summary']['comparedRepositories'], 0)
                self.assertEqual(report['summary']['unusedMappings'], ['pkg:npm/demo@1'])
                self.assertEqual(len(report['after']['snapshots']), 1)
                self.assert_scanner_summary(report, {
                    'version': {'changed': 0, 'unchanged': 0, 'not_comparable': 0},
                    'commit': {'changed': 0, 'unchanged': 0, 'not_comparable': 0}})

    def test_scanner_fields_change_independently_of_repository_and_checks(self):
        self.after['demo.json']['repo']['commit'] = '1' * 40
        self.after['demo.json']['checks'] = copy.deepcopy(self.before['demo.json']['checks'])
        for version, commit, version_change, commit_change in (
                ('v5.0.0', 'a' * 40, 'unchanged', 'unchanged'),
                ('v5.1.0', 'a' * 40, 'changed', 'unchanged'),
                ('v5.0.0', 'b' * 40, 'unchanged', 'changed'),
                ('v5.1.0', 'b' * 40, 'changed', 'changed'),
                (' v5.0.0 ', 'a' * 7, 'changed', 'changed')):
            with self.subTest(version=version, commit=commit):
                self.after['demo.json']['scorecard'] = {'version': version, 'commit': commit, 'extra': 'retained'}
                row = self.row()
                self.assertEqual(row['scannerChange'], {
                    'before': {'version': 'v5.0.0', 'commit': 'a' * 40},
                    'after': {'version': version, 'commit': commit},
                    'versionChange': version_change, 'commitChange': commit_change})
                self.assertEqual(row['commitChange'], 'unchanged')
                self.assertEqual((row['checks'][0]['change'], row['checks'][0]['scoreChange']),
                                 ('unchanged', 'unchanged'))

    def test_scanner_unknown_metadata_never_implies_unchanged_or_added_revision(self):
        unknown = {'version': None, 'commit': None}
        for metadata in ('absent', None, [], 'v5', 5, False, {},
                         {'version': '', 'commit': '  '},
                         {'version': 5, 'commit': ['a']},
                         {'version': False, 'commit': {'hash': 'a'}}):
            for side in ('before', 'after', 'both'):
                with self.subTest(metadata=metadata, side=side):
                    self.before['demo.json']['scorecard'] = {'version': 'v5.0.0', 'commit': 'a' * 40}
                    self.after['demo.json']['scorecard'] = {'version': 'v5.0.0', 'commit': 'a' * 40}
                    for selected in ('before', 'after') if side == 'both' else (side,):
                        doc = getattr(self, selected)['demo.json']
                        if metadata == 'absent':
                            doc.pop('scorecard')
                        else:
                            doc['scorecard'] = metadata
                    report = self.report()
                    scanner = report['repositories'][0]['scannerChange']
                    self.assertEqual(scanner['versionChange'], 'not_comparable')
                    self.assertEqual(scanner['commitChange'], 'not_comparable')
                    for selected in ('before', 'after') if side == 'both' else (side,):
                        self.assertEqual(scanner[selected], unknown)
                        raw = report[selected]['snapshots'][0]['document']
                        if metadata == 'absent':
                            self.assertNotIn('scorecard', raw)
                        else:
                            self.assertEqual(raw['scorecard'], metadata)
        self.before['demo.json']['scorecard'] = {'version': 'v5.0.0'}
        self.after['demo.json']['scorecard'] = {'version': 'v5.1.0', 'commit': 'b' * 40}
        self.assertEqual(self.row()['scannerChange'], {
            'before': {'version': 'v5.0.0', 'commit': None},
            'after': {'version': 'v5.1.0', 'commit': 'b' * 40},
            'versionChange': 'changed', 'commitChange': 'not_comparable'})
        self.before['demo.json']['scorecard'] = {'commit': 'b' * 40}
        self.assertEqual(self.row()['scannerChange']['commitChange'], 'unchanged')
        self.assertEqual(self.row()['scannerChange']['versionChange'], 'not_comparable')

    def test_scanner_missing_or_future_only_snapshots_have_null_identity(self):
        for before, after in ((False, True), (True, False), (False, False)):
            with self.subTest(before=before, after=after):
                self.before = {'demo.json': self.snapshot('2026-11-01', 3, '1')} if before else {}
                # A future snapshot is retained but cannot supply scanner identity.
                self.after = {'demo.json': self.snapshot('2026-11-11' if after else '2026-11-12', 8, '2')}
                row = self.row()
                scanner = row['scannerChange']
                self.assertEqual(scanner['versionChange'], 'not_comparable')
                self.assertEqual(scanner['commitChange'], 'not_comparable')
                self.assertEqual(scanner['before'], {'version': 'v5.0.0', 'commit': 'a' * 40} if before else None)
                self.assertEqual(scanner['after'], {'version': 'v5.0.0', 'commit': 'a' * 40} if after else None)
                if before or after:
                    self.assertEqual(row['checks'][0]['scoreChange'], 'not_comparable')
                else:
                    self.assertEqual(row['checks'], [])

    def test_scanner_changes_remain_visible_with_stale_or_ambiguous_evidence(self):
        self.after['demo.json']['scorecard'] = {'version': 'v5.1.0', 'commit': 'b' * 40}
        for date, age, comparison in (('2026-11-02', '2', 'stale_after'),
                                      ('2026-11-01', '30', 'snapshot_time_ambiguous'),
                                      ('2026-10-31', '30', 'snapshot_time_regressed')):
            with self.subTest(comparison=comparison):
                self.after['demo.json']['date'] = date
                self.write()
                result = self.cli('--max-age-days', age)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assert_scanner_summary(report, {
                    'version': {'changed': 1, 'unchanged': 0, 'not_comparable': 0},
                    'commit': {'changed': 1, 'unchanged': 0, 'not_comparable': 0}})
                row = report['repositories'][0]
                self.assertEqual(row['comparison'], comparison)
                self.assertEqual(row['scannerChange']['versionChange'], 'changed')
                self.assertEqual(row['scannerChange']['commitChange'], 'changed')
                self.assertEqual(row['checks'][0]['scoreChange'], 'not_comparable')

    def test_scanner_identity_uses_only_selected_snapshots(self):
        self.after['old.json'] = self.snapshot('2026-11-10', 1, '3')
        self.after['future.json'] = self.snapshot('2026-11-12', 10, '4')
        for name in ('old.json', 'future.json'):
            self.after[name]['scorecard'] = {'version': 'v99.0', 'commit': 'f' * 40}
        report = self.report()
        row = report['repositories'][0]
        self.assertEqual(len(report['after']['snapshots']), 3)
        self.assertEqual(row['scannerChange']['after'], {'version': 'v5.0.0', 'commit': 'a' * 40})
        self.assertEqual(row['scannerChange']['versionChange'], 'unchanged')
        self.assertEqual(row['scannerChange']['commitChange'], 'unchanged')

    def test_scanner_fixture_changed_checks_at_same_repository_commit(self):
        from vulnwrench.scorecard import compare
        report = compare(FIXTURE / 'bom.json', FIXTURE / 'repos.json', FIXTURE / 'before',
                         FIXTURE / 'after', '2026-11-01', '2026-11-11', max_age_days=2)
        row = next(row for row in report['repositories'] if row['repository'].endswith('/scanner'))
        self.assertEqual(row['commitChange'], 'unchanged')
        self.assertEqual(row['before']['commit'], '3' * 40)
        self.assertEqual(row['after']['commit'], '3' * 40)
        self.assertEqual(row['scannerChange'], {
            'before': {'version': 'v5.0.0', 'commit': 'a' * 40},
            'after': {'version': 'v5.1.0', 'commit': 'b' * 40},
            'versionChange': 'changed', 'commitChange': 'changed'})
        self.assertEqual(row['comparison'], 'comparable')
        self.assertEqual((row['checks'][0]['change'], row['checks'][0]['scoreChange']), ('changed', 'increased'))

    def test_fresh_score_reason_deletion_addition_and_commit_are_independent(self):
        self.before['demo.json']['checks'] += [
            {'name': 'Security-Policy', 'score': 10},
            {'name': 'License', 'score': 5, 'reason': 'old explanation'},
            {'name': 'Maintained', 'score': 10}]
        self.after['demo.json']['checks'] += [
            {'name': 'License', 'score': 5, 'reason': 'new explanation'},
            {'name': 'Maintained', 'score': 2},
            {'name': 'Future-Check', 'score': 10}]
        self.after['demo.json']['checks'][0]['reason'] = 'More review evidence'
        row = self.row()
        self.assertEqual(row['comparison'], 'comparable')
        self.assertEqual(row['commitChange'], 'changed')
        self.assertEqual(row['snapshotChange'], 'advanced')
        checks = {item['name']: item for item in row['checks']}
        self.assertEqual(list(checks), sorted(checks))
        self.assertEqual((checks['Code-Review']['change'], checks['Code-Review']['scoreChange'],
                          checks['Code-Review']['scoreChanged'], checks['Code-Review']['reasonChanged']),
                         ('changed', 'increased', True, True))
        self.assertEqual((checks['License']['scoreChange'], checks['License']['scoreChanged'],
                          checks['License']['reasonChanged']), ('unchanged', False, True))
        self.assertEqual(checks['Maintained']['scoreChange'], 'decreased')
        self.assertEqual((checks['Security-Policy']['change'], checks['Security-Policy']['after']), ('deleted', None))
        self.assertEqual(checks['Security-Policy']['scoreChange'], 'not_comparable')
        self.assertEqual(checks['Future-Check']['change'], 'added')
        self.assertEqual(checks['Future-Check']['scoreChange'], 'not_comparable')

    def test_stale_and_missing_newer_evidence_never_establish_increase(self):
        for date, status in (('2026-11-02', 'stale'), (None, 'missing_scorecard'),
                             ('2026-11-12', 'no_snapshot_as_of')):
            with self.subTest(status=status):
                self.after = {} if date is None else {'demo.json': self.snapshot(date, 10, '2')}
                row = self.row()
                self.assertEqual(row['after']['status'], status)
                self.assertEqual(row['checks'][0]['scoreChange'], 'not_comparable')
                if status != 'stale':
                    self.assertEqual(row['checks'][0]['change'], 'not_comparable')
                    self.assertIsNone(row['checks'][0]['reasonChanged'])
                    self.assertEqual(row['commitChange'], 'not_comparable')
                else:
                    self.assertEqual(row['checks'][0]['change'], 'changed')
                    self.assertEqual(row['commitChange'], 'changed')

    def test_missing_and_stale_older_evidence_do_not_create_a_baseline(self):
        for before in ({}, {'demo.json': self.snapshot('2026-10-01', 1, '1')}):
            with self.subTest(before=before):
                self.before = before
                row = self.row()
                self.assertNotEqual(row['comparison'], 'comparable')
                self.assertEqual(row['checks'][0]['scoreChange'], 'not_comparable')

    def test_unknown_scores_remain_distinct_from_deleted_checks(self):
        for value, observation in ((-1, 'negative_score'), (None, 'missing_score'), ('absent', 'missing_score')):
            with self.subTest(value=value):
                check = self.after['demo.json']['checks'][0]
                if value == 'absent':
                    check.pop('score')
                else:
                    check['score'] = value
                row = self.row()['checks'][0]
                self.assertEqual(row['afterObservation'], observation)
                self.assertEqual(row['scoreChange'], 'not_comparable')
                self.assertEqual(row['change'], 'changed')
        self.after['demo.json']['checks'] = []
        row = self.row()['checks'][0]
        self.assertEqual((row['change'], row['afterObservation']), ('deleted', 'missing_check'))

    def test_missing_reason_and_null_reason_are_different(self):
        del self.before['demo.json']['checks'][0]['reason']
        self.after['demo.json']['checks'][0]['reason'] = None
        row = self.row()['checks'][0]
        self.assertTrue(row['reasonChanged'])
        self.assertNotIn('reason', row['before'])
        self.assertIsNone(row['after']['reason'])

    def test_raw_detail_changes_and_unchanged_checks(self):
        self.after['demo.json']['checks'] = copy.deepcopy(self.before['demo.json']['checks'])
        row = self.row()['checks'][0]
        self.assertEqual((row['change'], row['scoreChange'], row['reasonChanged']), ('unchanged', 'unchanged', False))
        self.after['demo.json']['checks'][0]['details'] = ['Synthetic detail']
        row = self.row()['checks'][0]
        self.assertEqual((row['change'], row['scoreChange'], row['reasonChanged']), ('changed', 'unchanged', False))

    def test_reused_or_regressed_snapshot_time_is_explicit(self):
        self.after = copy.deepcopy(self.before)
        row = self.row()
        self.assertEqual(row['snapshotChange'], 'unchanged')
        self.assertEqual(row['commitChange'], 'unchanged')
        self.assertEqual(row['comparison'], 'stale_after')
        self.before['demo.json']['date'] = '2026-11-01T00:00:00.000001Z'
        self.after = {'demo.json': self.snapshot('2026-11-01', 10, '2')}
        self.write()
        run = self.cli('--max-age-days', '30')
        self.assertEqual(run.returncode, 0, run.stderr)
        row = json.loads(run.stdout)['repositories'][0]
        self.assertEqual((row['snapshotChange'], row['comparison']), ('regressed', 'snapshot_time_regressed'))
        self.assertEqual(row['checks'][0]['scoreChange'], 'not_comparable')

    def test_same_timestamp_changed_document_does_not_claim_increase(self):
        self.after['demo.json']['date'] = '2026-11-01T01:00:00+01:00'
        self.write()
        run = self.cli('--max-age-days', '30')
        self.assertEqual(run.returncode, 0, run.stderr)
        row = json.loads(run.stdout)['repositories'][0]
        self.assertEqual(row['snapshotChange'], 'same_timestamp_changed')
        self.assertEqual(row['comparison'], 'snapshot_time_ambiguous')
        self.assertEqual(row['checks'][0]['scoreChange'], 'not_comparable')

    def test_selection_offsets_age_boundary_all_evidence_and_provenance(self):
        self.after = {'old.json': self.snapshot('2026-11-09T23:00:00Z', 9, '2'),
                      'future.json': self.snapshot('2026-11-12', 1, '3')}
        self.after['old.json']['extension'] = {'kept': True}
        report = self.report()
        row = report['repositories'][0]
        self.assertEqual((row['after']['ageDays'], row['after']['status']), (2, 'fresh'))
        self.assertEqual(row['checks'][0]['scoreChange'], 'increased')
        self.assertEqual(len(report['after']['snapshots']), 2)
        self.assertEqual(len(report['after']['repositoryIndex'][REPO]['futureSnapshots']), 1)
        selected = next(s for s in report['after']['snapshots'] if s['id'] == row['after']['snapshotId'])
        self.assertEqual(selected['document']['extension'], {'kept': True})
        self.assertEqual(selected['document']['score'], 9.9)
        self.assertTrue(selected['sources'][0]['sha256'].startswith('sha256:'))
        self.assertEqual(report['inputs']['mapping']['document'], self.mapping)
        for key in ('score', 'overallScore', 'securityScore', 'decision', 'gate'):
            self.assertNotIn(key, report)
            self.assertNotIn(key, row)

    def test_same_inventory_mapping_shared_repository_and_unknowns(self):
        self.bom['components'] += [
            {'type': 'library', 'name': 'helper', 'purl': 'pkg:npm/helper@2'},
            {'type': 'library', 'name': 'unmapped', 'purl': 'pkg:npm/demo@2'},
            {'type': 'file', 'name': 'local'}]
        self.mapping['pkg:npm/helper@2'] = 'https://GitHub.com/EXAMPLE/Demo.git/'
        self.mapping['pkg:npm/unused@1'] = 'github.com/example/unused'
        report = self.report()
        self.assertEqual(len(report['repositories']), 1)
        self.assertEqual([r['repository'] for r in report['components']], [REPO, REPO, None, None])
        self.assertEqual([r['mappingStatus'] for r in report['components']],
                         ['mapped', 'mapped', 'unmapped', 'missing_purl'])
        self.assertEqual(report['summary']['unusedMappings'], ['pkg:npm/unused@1'])
        self.before.clear()
        self.after.clear()
        self.assertEqual(self.row()['comparison'], 'missing_both')

    def test_library_cli_determinism_and_single_snapshot_file(self):
        from vulnwrench.scorecard import compare
        run = self.cli()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout, self.cli().stdout)
        report = compare(self.root / 'bom.json', self.root / 'repos.json', self.root / 'before',
                         self.root / 'after', '2026-11-01', '2026-11-11', max_age_days=2)
        self.assertEqual(report, json.loads(run.stdout))
        single = self.cli('--before', self.root / 'before/demo.json', '--after', self.root / 'after/demo.json')
        self.assertEqual(single.returncode, 0, single.stderr)
        self.assertEqual(single.stdout, run.stdout)

    def test_invalid_dates_mapping_snapshot_and_output_preservation(self):
        output = self.root / 'out.json'
        output.write_text('previous')
        for flags in (('--before-as-of', '2026-11-12'), ('--after-as-of', '2026-11-01'),
                      ('--after-as-of', '2026-11-11T00:00:00'), ('--max-age-days', '-1')):
            with self.subTest(flags=flags):
                run = self.cli(*flags, '--output', output)
                self.assertEqual(run.returncode, 2)
                self.assertEqual(run.stdout, '')
                self.assertEqual(output.read_text(), 'previous')
        for path, raw in ((self.root / 'repos.json', '{"pkg:npm/demo@1":"github.com/example/demo","pkg:npm/demo@1":"github.com/example/other"}'),
                          (self.root / 'after/unmapped.json', '{"SECRET": "invalid snapshot"}')):
            self.write()
            path.write_text(raw)
            run = self.cli('--output', output)
            self.assertEqual(run.returncode, 2)
            self.assertNotIn('SECRET', run.stderr)
            self.assertNotIn('Traceback', run.stderr)
            self.assertEqual(output.read_text(), 'previous')

    def test_observation_summary_rejects_invalid_score_types_without_output(self):
        output = self.root / 'out.json'
        output.write_text('previous')
        for value in (True, 1.5, '5', [], {}, -2, 11):
            for side in ('before', 'after'):
                with self.subTest(value=value, side=side):
                    doc = getattr(self, side)['demo.json']
                    doc['checks'][0]['score'] = value
                    self.write()
                    for format in ('json', 'markdown'):
                        run = self.cli('--format', format, '--output', output)
                        self.assertEqual((run.returncode, run.stdout), (2, ''))
                        self.assertIn('Scorecard check score must be', run.stderr)
                        self.assertNotIn('Traceback', run.stderr)
                        self.assertEqual(output.read_text(), 'previous')
                    doc['checks'][0]['score'] = 3 if side == 'before' else 8

    def test_internal_conflicts_rejected_and_identical_documents_deduplicated(self):
        self.after['copy.json'] = copy.deepcopy(self.after['demo.json'])
        report = self.report()
        self.assertEqual(len(report['after']['snapshots']), 1)
        self.assertEqual(len(report['after']['snapshots'][0]['sources']), 2)
        self.after['copy.json']['checks'][0]['score'] = 1
        self.write()
        self.assertEqual(self.cli().returncode, 2)

    def test_output_protects_both_bundles_inputs_and_aliases(self):
        for source in (self.root / 'bom.json', self.root / 'repos.json',
                       self.root / 'before/demo.json', self.root / 'after/demo.json'):
            with self.subTest(source=source):
                before = source.read_bytes()
                self.assertEqual(self.cli('--output', source).returncode, 2)
                self.assertEqual(source.read_bytes(), before)
        alias = self.root / 'alias.json'
        os.link(self.root / 'after/demo.json', alias)
        self.assertEqual(self.cli('--output', alias).returncode, 2)
        alias.unlink()
        alias.symlink_to(self.root / 'before/demo.json')
        self.assertEqual(self.cli('--output', alias).returncode, 2)
        output = self.root / 'out.json'
        run = self.cli('--output', output)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout, '')
        self.assertEqual(output.read_text(), self.cli().stdout)

    def test_shared_total_input_budget_and_invalid_library_arguments(self):
        from vulnwrench.scorecard import compare, InputError
        args = (self.root / 'bom.json', self.root / 'repos.json', self.root / 'before',
                self.root / 'after', '2026-11-01', '2026-11-11')
        for age in (True, -1, 1.5, '2'):
            with self.subTest(age=age), self.assertRaises(InputError):
                compare(*args, max_age_days=age)
        size = sum(p.stat().st_size for p in self.root.rglob('*.json'))
        with patch('vulnwrench.scorecard.core.MAX_TOTAL_BYTES', size - 1), self.assertRaises(InputError):
            compare(*args, max_age_days=2)

    def test_documented_fixture_matches_independent_expected_changes(self):
        from vulnwrench.scorecard import compare
        report = compare(FIXTURE / 'bom.json', FIXTURE / 'repos.json', FIXTURE / 'before',
                         FIXTURE / 'after', '2026-11-01', '2026-11-11', max_age_days=2)
        actual = {row['repository'].rsplit('/', 1)[1]: {
            'comparison': row['comparison'], 'commitChange': row['commitChange'],
            'scannerChange': row['scannerChange'],
            'checks': {check['name']: [check['change'], check['scoreChange'],
                                       check['scoreChanged'], check['reasonChanged']]
                       for check in row['checks']}} for row in report['repositories']}
        self.assertEqual(actual, json.loads((FIXTURE / 'expected-changes.json').read_text()))
        self.assertEqual(report['summary'], json.loads((FIXTURE / 'expected-summary.json').read_text()))


if __name__ == '__main__':
    unittest.main()
