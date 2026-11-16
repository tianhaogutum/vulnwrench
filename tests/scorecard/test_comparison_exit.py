"""Literal opt-in exit contracts; complete successful output is independent of flags."""

import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from . import test_comparison as fixtures


class ComparisonExitTests(unittest.TestCase):
    setUp = fixtures.ComparisonTests.setUp
    snapshot = staticmethod(fixtures.ComparisonTests.snapshot)
    write = fixtures.ComparisonTests.write
    cli = fixtures.ComparisonTests.cli

    def assert_exit_contract(self, expected_exit, expected_counts, *extra):
        self.write()
        for format in ('json', 'markdown'):
            with self.subTest(format=format):
                plain = self.cli('--format', format, *extra)
                flagged = self.cli('--format', format, *extra, '--fail-on-decrease')
                self.assertEqual((plain.returncode, plain.stderr), (0, ''))
                self.assertEqual((flagged.returncode, flagged.stderr), (expected_exit, ''))
                self.assertEqual(flagged.stdout, plain.stdout)
                raw = plain.stdout if format == 'json' else plain.stdout.split('```json\n', 1)[1].rsplit('\n```', 1)[0]
                report = json.loads(raw)
                self.assertEqual(report['summary']['checkScoreChanges'], expected_counts)
                self.assertEqual(report['reportType'], 'snapshot-comparison')
                self.assertEqual(report['inputs']['bom']['document'], self.bom)
                self.assertNotIn('gate', report)
                output = self.root / 'out.txt'
                output.write_text('previous complete report')
                saved = self.cli('--format', format, *extra, '--fail-on-decrease', '--output', output)
                self.assertEqual((saved.returncode, saved.stdout, saved.stderr), (expected_exit, '', ''))
                self.assertEqual(output.read_bytes(), flagged.stdout.encode())
                self.assertEqual(list(self.root.glob('.scorecard-join-*')), [])
        return report

    def test_fail_on_decrease_literal_fixture_stays_byte_identical(self):
        command = [sys.executable, '-m', 'vulnwrench', 'scorecard', 'compare', str(fixtures.FIXTURE / 'bom.json'),
                   '--map', str(fixtures.FIXTURE / 'repos.json'), '--before', str(fixtures.FIXTURE / 'before'),
                   '--after', str(fixtures.FIXTURE / 'after'), '--before-as-of', '2026-11-01',
                   '--after-as-of', '2026-11-11', '--max-age-days', '2']
        for format, filename in (('json', 'expected.json'), ('markdown', 'expected.md')):
            for flags in ([], ['--fail-on-decrease']):
                with self.subTest(format=format, flags=flags):
                    result = subprocess.run([*command, '--format', format, *flags], cwd=fixtures.ROOT,
                                            capture_output=True, timeout=120)
                    self.assertEqual((result.returncode, result.stderr), (0, b''))
                    self.assertEqual(result.stdout, (fixtures.FIXTURE / filename).read_bytes())

    def test_fail_on_decrease_literal_numeric_and_unknown_score_contracts(self):
        # Explicit expected classifications/exits, including both valid numeric bounds.
        cases = [(10, 0, 'decreased', 1), (1, 0, 'decreased', 1), (10, 9, 'decreased', 1),
                 (0, 10, 'increased', 0), (0, 0, 'unchanged', 0), (10, 10, 'unchanged', 0),
                 (10, -1, 'not_comparable', 0), (-1, 0, 'not_comparable', 0),
                 (10, None, 'not_comparable', 0), (None, 0, 'not_comparable', 0),
                 (10, 'absent', 'not_comparable', 0), ('absent', 0, 'not_comparable', 0)]
        for before, after, direction, exit_code in cases:
            with self.subTest(before=before, after=after):
                for side, score in (('before', before), ('after', after)):
                    check = getattr(self, side)['demo.json']['checks'][0]
                    if score == 'absent':
                        check.pop('score', None)
                    else:
                        check['score'] = score
                counts = {'increased': 0, 'decreased': 0, 'unchanged': 0, 'not_comparable': 0}
                counts[direction] = 1
                report = self.assert_exit_contract(exit_code, counts)
                self.assertEqual(report['repositories'][0]['checks'][0]['scoreChange'], direction)

    def test_fail_on_decrease_any_pair_in_mixed_population_with_canonical_deduplication(self):
        self.bom['components'] += [copy.deepcopy(self.bom['components'][0]),
            {'type': 'library', 'name': 'alias', 'purl': 'pkg:npm/alias@1'}]
        self.mapping['pkg:npm/alias@1'] = 'https://GitHub.com/EXAMPLE/Demo.git/'
        self.before['demo.json']['checks'] = [
            {'name': 'Code-Review', 'score': 10}, {'name': 'License', 'score': 5},
            {'name': 'Maintained', 'score': 0}, {'name': 'Deleted', 'score': 10}]
        self.after['demo.json']['checks'] = [
            {'name': 'Code-Review', 'score': 0}, {'name': 'License', 'score': 5},
            {'name': 'Maintained', 'score': 10}, {'name': 'Added', 'score': 0}]
        self.before['copy.json'] = copy.deepcopy(self.before['demo.json'])
        self.after['copy.json'] = copy.deepcopy(self.after['demo.json'])
        report = self.assert_exit_contract(1, {'increased': 1, 'decreased': 1, 'unchanged': 1, 'not_comparable': 2})
        self.assertEqual((report['summary']['components'], report['summary']['comparedRepositories']), (3, 1))
        self.assertEqual(len(report['after']['snapshots']), 1)
        self.assertEqual(len(report['after']['snapshots'][0]['sources']), 2)
        # A decrease in another repository also triggers, even with an increase here.
        self.before['demo.json']['checks'] = [{'name': 'Code-Review', 'score': 0}]
        self.after['demo.json']['checks'] = [{'name': 'Code-Review', 'score': 10}]
        self.before.pop('copy.json'); self.after.pop('copy.json')
        self.bom['components'].append({'type': 'library', 'name': 'second', 'purl': 'pkg:npm/second@1'})
        self.mapping['pkg:npm/second@1'] = 'github.com/example/second'
        for side, score, date in (('before', 10, '2026-11-01'), ('after', 0, '2026-11-11')):
            doc = self.snapshot(date, score, '1')
            doc['repo']['name'] = 'github.com/example/second'
            getattr(self, side)['second.json'] = doc
        self.assert_exit_contract(1, {'increased': 1, 'decreased': 1, 'unchanged': 0, 'not_comparable': 0})

    def test_fail_on_decrease_added_deleted_and_evidence_blockers_do_not_fail(self):
        for case, expected_status, age in (
                ('added', 'comparable', 2), ('deleted', 'comparable', 2),
                ('missing_before', 'missing_before', 2), ('missing_after', 'missing_after', 2),
                ('future_before', 'missing_before', 2), ('future_after', 'missing_after', 2),
                ('stale_before', 'stale_before', 2), ('stale_after', 'stale_after', 2),
                ('regressed', 'snapshot_time_regressed', 30),
                ('ambiguous', 'snapshot_time_ambiguous', 30)):
            with self.subTest(case=case):
                self.before = {'demo.json': self.snapshot('2026-11-01', 10, '1')}
                self.after = {'demo.json': self.snapshot('2026-11-11', 0, '2')}
                if case in ('added', 'deleted'):
                    (self.before if case == 'added' else self.after)['demo.json']['checks'] = []
                elif case.startswith('missing'):
                    (self.before if case.endswith('before') else self.after).clear()
                elif case.startswith('future'):
                    (self.before if case.endswith('before') else self.after)['demo.json']['date'] = '2026-11-12'
                elif case.startswith('stale'):
                    (self.before if case.endswith('before') else self.after)['demo.json']['date'] = '2026-10-01' if case.endswith('before') else '2026-11-02'
                else:
                    self.after['demo.json']['date'] = '2026-10-31' if case == 'regressed' else '2026-11-01'
                report = self.assert_exit_contract(0, {'increased': 0, 'decreased': 0, 'unchanged': 0, 'not_comparable': 1},
                                                   '--max-age-days', age)
                self.assertEqual(report['repositories'][0]['comparison'], expected_status)
                self.assertEqual(report['repositories'][0]['checks'][0]['scoreChange'], 'not_comparable')

    def test_fail_on_decrease_empty_and_unselected_observations_do_not_fail(self):
        for case in ('empty_checks', 'empty_inventory', 'unmapped', 'missing_both', 'unselected_decreases'):
            with self.subTest(case=case):
                self.bom['components'] = [{'type': 'library', 'name': 'demo', 'purl': 'pkg:npm/demo@1'}]
                self.mapping = {'pkg:npm/demo@1': fixtures.REPO}
                self.before = {'demo.json': self.snapshot('2026-11-01', 0, '1')}
                self.after = {'demo.json': self.snapshot('2026-11-11', 10, '2')}
                if case == 'empty_checks':
                    self.before['demo.json']['checks'] = []; self.after['demo.json']['checks'] = []
                elif case == 'empty_inventory':
                    self.bom['components'] = []
                elif case == 'unmapped':
                    self.mapping.clear()
                elif case == 'missing_both':
                    self.before.clear(); self.after.clear()
                else:
                    self.after['old.json'] = self.snapshot('2026-11-10', 0, '3')
                    self.after['future.json'] = self.snapshot('2026-11-12', 0, '4')
                    for side, score, date in (('before', 10, '2026-11-01'), ('after', 0, '2026-11-11')):
                        doc = self.snapshot(date, score, '5'); doc['repo']['name'] = 'github.com/example/unused'
                        getattr(self, side)['unused.json'] = doc
                    self.mapping['pkg:npm/unused@1'] = 'github.com/example/unused'
                self.assert_exit_contract(0, {'increased': int(case == 'unselected_decreases'), 'decreased': 0,
                                              'unchanged': 0, 'not_comparable': 0})

    def test_fail_on_decrease_invalid_input_and_protected_outputs_take_exit_two(self):
        self.before['demo.json']['checks'][0]['score'] = 10
        self.after['demo.json']['checks'][0]['score'] = 0
        self.write()
        output = self.root / 'out.txt'; output.write_text('previous')
        for format in ('json', 'markdown'):
            for flags in (('--max-age-days', '-1'), ('--after-as-of', '2026-11-01'),
                          ('--format', 'invalid'), ('--fail-on-decrease=1',)):
                with self.subTest(format=format, flags=flags):
                    result = self.cli('--fail-on-decrease', '--format', format, *flags, '--output', output)
                    self.assertEqual((result.returncode, result.stdout), (2, ''))
                    self.assertEqual(output.read_text(), 'previous')
            for score in (-2, 11, True, 1.5, '0'):
                self.after['demo.json']['checks'][0]['score'] = score; self.write()
                result = self.cli('--fail-on-decrease', '--format', format, '--output', output)
                self.assertEqual((result.returncode, result.stdout), (2, ''))
                self.assertIn('Scorecard check score must be', result.stderr)
                self.assertEqual(output.read_text(), 'previous')
            self.after['demo.json']['checks'][0]['score'] = 0; self.write()
            sources = [self.root / name for name in ('bom.json', 'repos.json', 'before/demo.json', 'after/demo.json')]
            hard = self.root / 'hard.json'; os.link(sources[-1], hard)
            link = self.root / 'link.json'; link.symlink_to(sources[-2])
            for path in (*sources, hard, link):
                saved = path.read_bytes()
                result = self.cli('--fail-on-decrease', '--format', format, '--output', path)
                self.assertEqual((result.returncode, result.stdout), (2, ''))
                self.assertIn('output must not overwrite', result.stderr)
                self.assertEqual(path.read_bytes(), saved)
            hard.unlink(); link.unlink()
            result = self.cli('--fail-on-decrease', '--format', format, '--output', self.root / 'absent/out')
            self.assertEqual((result.returncode, result.stdout), (2, ''))
            self.assertIn('cannot write output file', result.stderr)

    def test_fail_on_decrease_atomic_and_stdout_write_errors_take_exit_two(self):
        from vulnwrench.scorecard.cli import main
        self.before['demo.json']['checks'][0]['score'] = 10
        self.after['demo.json']['checks'][0]['score'] = 0
        self.write()
        args = ['compare', str(self.root / 'bom.json'), '--map', str(self.root / 'repos.json'),
                '--before', str(self.root / 'before'), '--after', str(self.root / 'after'),
                '--before-as-of', '2026-11-01', '--after-as-of', '2026-11-11',
                '--max-age-days', '2', '--fail-on-decrease']
        output = self.root / 'out.txt'; output.write_text('previous')
        for format in ('json', 'markdown'):
            for operation in ('tempfile.NamedTemporaryFile', 'os.replace'):
                with self.subTest(format=format, operation=operation), \
                     patch('vulnwrench.scorecard.cli.' + operation, side_effect=OSError('SECRET')), \
                     patch('sys.stdout', new_callable=io.StringIO) as stdout, \
                     patch('sys.stderr', new_callable=io.StringIO) as stderr:
                    self.assertEqual(main([*args, '--format', format, '--output', str(output)]), 2)
                    self.assertEqual(stdout.getvalue(), '')
                    self.assertEqual(stderr.getvalue(), 'vulnwrench scorecard: cannot write output file\n')
                    self.assertEqual(output.read_text(), 'previous')
                    self.assertEqual(list(self.root.glob('.scorecard-join-*')), [])
            with patch('sys.stdout.write', side_effect=BrokenPipeError('SECRET')), \
                 patch('sys.stderr', new_callable=io.StringIO) as stderr:
                self.assertEqual(main([*args, '--format', format]), 2)
                self.assertEqual(stderr.getvalue(), 'vulnwrench scorecard: cannot render or write report\n')


if __name__ == '__main__':
    unittest.main()
