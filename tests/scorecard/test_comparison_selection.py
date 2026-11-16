"""Exact selected-population contracts, established before selector implementation."""

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
from .test_comparison_markdown import evidence, table_rows


class ComparisonSelectionTests(unittest.TestCase):
    setUp = fixtures.ComparisonTests.setUp
    snapshot = staticmethod(fixtures.ComparisonTests.snapshot)
    write = fixtures.ComparisonTests.write
    cli = fixtures.ComparisonTests.cli
    assert_check_transitions = fixtures.ComparisonTests.assert_check_transitions
    assert_check_comparability = fixtures.ComparisonTests.assert_check_comparability
    assert_check_comparability_by_check = fixtures.ComparisonTests.assert_check_comparability_by_check
    assert_check_score_changes_by_check = fixtures.ComparisonTests.assert_check_score_changes_by_check

    def library(self, checks=None, **kwargs):
        from vulnwrench.scorecard import compare
        return compare(self.root / 'bom.json', self.root / 'repos.json', self.root / 'before',
                       self.root / 'after', '2026-11-01', '2026-11-11',
                       max_age_days=kwargs.pop('max_age_days', 2), checks=checks, **kwargs)

    def selected(self, names, **kwargs):
        self.write()
        plain = self.library(**kwargs)
        selected = self.library(names, **kwargs)
        self.assertEqual(selected['checkSelection'], {'names': sorted(set(names))})
        self.assertNotIn('checkSelection', plain)
        # Exact full evidence and repository/scanner population remain independent.
        for key in ('before', 'after', 'components', 'inputs'):
            self.assertEqual(selected[key], plain[key])
        for key in ('components', 'comparedRepositories', 'mappedComponents', 'unmappedComponents',
                    'unusedMappings', 'scannerChanges', 'snapshotChanges', 'comparisonStatuses'):
            self.assertEqual(selected['summary'][key], plain['summary'][key])
        for old, new in zip(plain['repositories'], selected['repositories']):
            self.assertEqual(new['checks'], [row for row in old['checks'] if row['name'] in names])
            self.assertEqual({k: v for k, v in old.items() if k != 'checks'},
                             {k: v for k, v in new.items() if k != 'checks'})
        summary = selected['summary']
        self.assert_check_comparability(selected, **dict(zip(('comparable', 'evidence', 'observation'),
            [summary['checkScoreComparability'][k] for k in ('comparable', 'evidence_blocked', 'observation_blocked')])))
        self.assert_check_comparability_by_check(selected, summary['checkScoreComparabilityByCheck'])
        self.assert_check_score_changes_by_check(selected, summary['checkScoreChangesByCheck'])
        nonzero = {(a, b): count for a, row in summary['checkObservationTransitions'].items()
                   for b, count in row.items() if count}
        self.assert_check_transitions(selected, nonzero)
        return selected

    def test_literal_selected_and_default_cli_reports(self):
        base = [sys.executable, '-m', 'vulnwrench', 'scorecard', 'compare', str(fixtures.FIXTURE / 'bom.json'),
                '--map', str(fixtures.FIXTURE / 'repos.json'), '--before', str(fixtures.FIXTURE / 'before'),
                '--after', str(fixtures.FIXTURE / 'after'), '--before-as-of', '2026-11-01',
                '--after-as-of', '2026-11-11', '--max-age-days', '2']
        for format, suffix in (('json', 'json'), ('markdown', 'md')):
            for selected in (False, True):
                flags = ['--check', 'License', '--check', 'Not-Observed', '--check', 'Future-Check',
                         '--check', 'License'] if selected else []
                literal = fixtures.FIXTURE / (('expected-selected.' if selected else 'expected.') + suffix)
                for gate in ([], ['--fail-on-decrease']):
                    with self.subTest(format=format, selected=selected, gate=gate):
                        result = subprocess.run([*base, '--format', format, *flags, *gate],
                                                cwd=fixtures.ROOT, capture_output=True, timeout=120)
                        self.assertEqual((result.returncode, result.stderr), (0, b''))
                        self.assertEqual(result.stdout, literal.read_bytes())
                        out = self.root / 'out'
                        out.write_bytes(b'previous')
                        saved = subprocess.run([*base, '--format', format, *flags, *gate, '--output', str(out)],
                                               cwd=fixtures.ROOT, capture_output=True, timeout=120)
                        self.assertEqual((saved.returncode, saved.stdout, saved.stderr), (0, b'', b''))
                        self.assertEqual(out.read_bytes(), literal.read_bytes())
        selected = json.loads((fixtures.FIXTURE / 'expected-selected.json').read_text())
        self.assertEqual(evidence((fixtures.FIXTURE / 'expected-selected.md').read_text()), selected)

    def test_exact_names_future_unicode_whitespace_and_canonical_deduplication(self):
        names = ['Future-X', 'future-x', ' Future-X ', 'é', 'e\u0301', '-Option', 'a|<`\u2028b']
        for side, score in (('before', 10), ('after', 0)):
            doc = getattr(self, side)['demo.json']
            doc['checks'] = [{'name': name, 'score': score, 'details': ['retained']} for name in names]
            getattr(self, side)['copy.json'] = copy.deepcopy(doc)
        self.bom['components'] += [copy.deepcopy(self.bom['components'][0]),
            {'type': 'library', 'name': 'alias', 'purl': 'pkg:npm/alias@1'}]
        self.mapping['pkg:npm/alias@1'] = 'https://GitHub.com/EXAMPLE/Demo.git/'
        for name in names:
            with self.subTest(name=name):
                report = self.selected([name, name, 'ABSENT'])
                self.assertEqual(report['summary']['checkScoreChanges'],
                                 {'increased': 0, 'decreased': 1, 'unchanged': 0, 'not_comparable': 0})
                self.assertEqual(report['summary']['comparedRepositories'], 1)
                self.assertEqual(len(report['before']['snapshots'][0]['sources']), 2)
                result = self.cli('--check=' + name, '--check=' + name, '--check', 'ABSENT', '--fail-on-decrease')
                self.assertEqual((result.returncode, result.stderr), (1, ''))
                self.assertEqual(json.loads(result.stdout), report)
                markdown = self.cli('--check=' + name, '--check', 'ABSENT', '--format', 'markdown')
                self.assertEqual((markdown.returncode, markdown.stderr), (0, ''))
                self.assertEqual(evidence(markdown.stdout), report)
                # JSON literals in scope preserve whitespace/control distinctions safely.
                self.assertIn('Check scope: explicitly selected exact names;', markdown.stdout)
                rows = table_rows(markdown.stdout.split('## Coverage', 1)[0])
                self.assertEqual([json.loads(row[0]) for row in rows[1:]], sorted([name, 'ABSENT']))

    def test_empty_matches_and_empty_library_selection_zero_every_check_partition(self):
        for case in ('unobserved', 'empty_selection', 'empty_inventory', 'unmapped', 'missing_both', 'empty_checks'):
            with self.subTest(case=case):
                self.bom['components'] = [{'type': 'library', 'name': 'demo', 'purl': 'pkg:npm/demo@1'}]
                self.mapping = {'pkg:npm/demo@1': fixtures.REPO}
                self.before = {'demo.json': self.snapshot('2026-11-01', 10, '1')}
                self.after = {'demo.json': self.snapshot('2026-11-11', 0, '2')}
                names = ['Code-Review']
                if case == 'unobserved': names = ['code-review', ' Code-Review ', 'NOT-OBSERVED']
                elif case == 'empty_selection': names = []
                elif case == 'empty_inventory': self.bom['components'] = []
                elif case == 'unmapped': self.mapping.clear()
                elif case == 'missing_both': self.before.clear(); self.after.clear()
                else: self.before['demo.json']['checks'] = []; self.after['demo.json']['checks'] = []
                report = self.selected(names)
                for key in ('checkChanges', 'checkScoreChanges', 'checkScoreComparability'):
                    self.assertTrue(all(count == 0 for count in report['summary'][key].values()))
                for key in ('checkScoreChangesByCheck', 'checkScoreComparabilityByCheck'):
                    self.assertEqual(report['summary'][key], [])
                self.assert_check_transitions(report, {})
                if names:
                    result = self.cli(*[arg for name in names for arg in ('--check', name)], '--fail-on-decrease')
                    self.assertEqual((result.returncode, result.stderr), (0, ''))
                    self.assertEqual(json.loads(result.stdout), report)

    def test_selected_unknowns_and_all_evidence_blockers_preserve_classification(self):
        cases = [('negative', 'comparable', 2), ('null', 'comparable', 2), ('absent', 'comparable', 2),
                 ('added', 'comparable', 2), ('deleted', 'comparable', 2),
                 ('missing_before', 'missing_before', 2), ('missing_after', 'missing_after', 2),
                 ('future_before', 'missing_before', 2), ('future_after', 'missing_after', 2),
                 ('stale_before', 'stale_before', 2), ('stale_after', 'stale_after', 2),
                 ('regressed', 'snapshot_time_regressed', 30), ('ambiguous', 'snapshot_time_ambiguous', 30)]
        for case, status, age in cases:
            with self.subTest(case=case):
                self.before = {'demo.json': self.snapshot('2026-11-01', 10, '1')}
                self.after = {'demo.json': self.snapshot('2026-11-11', 0, '2')}
                if case == 'negative': self.after['demo.json']['checks'][0]['score'] = -1
                elif case == 'null': self.after['demo.json']['checks'][0]['score'] = None
                elif case == 'absent': del self.after['demo.json']['checks'][0]['score']
                elif case in ('added', 'deleted'):
                    (self.before if case == 'added' else self.after)['demo.json']['checks'] = []
                elif case.startswith('missing'):
                    (self.before if case.endswith('before') else self.after).clear()
                elif case.startswith('future'):
                    (self.before if case.endswith('before') else self.after)['demo.json']['date'] = '2026-11-12'
                elif case.startswith('stale'):
                    (self.before if case.endswith('before') else self.after)['demo.json']['date'] = '2026-10-01'
                else: self.after['demo.json']['date'] = '2026-10-31' if case == 'regressed' else '2026-11-01'
                report = self.selected(['Code-Review', 'Not-Observed'], max_age_days=age)
                self.assertEqual(report['repositories'][0]['comparison'], status)
                self.assertEqual(report['summary']['checkScoreChanges'],
                                 {'increased': 0, 'decreased': 0, 'unchanged': 0, 'not_comparable': 1})
                for format in ('json', 'markdown'):
                    result = self.cli('--check', 'Code-Review', '--check', 'Not-Observed', '--format', format,
                                      '--fail-on-decrease', '--max-age-days', age)
                    self.assertEqual((result.returncode, result.stderr), (0, ''))
                    self.assertEqual(json.loads(result.stdout) if format == 'json' else evidence(result.stdout), report)

    def test_fail_on_decrease_uses_only_selected_observed_pairs(self):
        self.before['demo.json']['checks'] = [{'name': 'Decline', 'score': 10}, {'name': 'Future-Up', 'score': 0}]
        self.after['demo.json']['checks'] = [{'name': 'Decline', 'score': 0}, {'name': 'Future-Up', 'score': 10}]
        self.write()
        for names, code, directions in [(['Future-Up'], 0, (1, 0)), (['Decline'], 1, (0, 1)),
                                         (['Future-Up', 'Decline', 'Decline'], 1, (1, 1)),
                                         (['Absent'], 0, (0, 0))]:
            for format in ('json', 'markdown'):
                with self.subTest(names=names, format=format):
                    flags = [arg for name in names for arg in ('--check', name)]
                    plain = self.cli(*flags, '--format', format)
                    gated = self.cli(*flags, '--format', format, '--fail-on-decrease')
                    self.assertEqual((plain.returncode, plain.stderr), (0, ''))
                    self.assertEqual((gated.returncode, gated.stderr), (code, ''))
                    self.assertEqual(gated.stdout, plain.stdout)
                    report = json.loads(plain.stdout) if format == 'json' else evidence(plain.stdout)
                    self.assertEqual(report['summary']['checkScoreChanges'],
                        dict(zip(('increased', 'decreased', 'unchanged', 'not_comparable'), (*directions, 0, 0))))
                    self.assertEqual(len(report['after']['snapshots'][0]['document']['checks']), 2)
                    out = self.root / 'out'; out.write_text('previous')
                    saved = self.cli(*flags, '--format', format, '--fail-on-decrease', '--output', out)
                    self.assertEqual((saved.returncode, saved.stdout, saved.stderr), (code, '', ''))
                    self.assertEqual(out.read_bytes(), gated.stdout.encode())
                    self.assertEqual(list(self.root.glob('.scorecard-join-*')), [])

    def test_selection_does_not_skip_validation_or_create_rows_from_unselected_snapshots(self):
        self.after['future.json'] = self.snapshot('2026-11-12', 0, '3')
        self.after['future.json']['checks'][0]['name'] = 'Future-Only'
        self.after['old.json'] = self.snapshot('2026-11-10', 0, '4')
        self.after['old.json']['checks'][0]['name'] = 'Old-Only'
        self.after['unused.json'] = self.snapshot('2026-11-11', 0, '5')
        self.after['unused.json']['repo']['name'] = 'github.com/example/unused'
        self.after['unused.json']['checks'][0]['name'] = 'Unused-Only'
        report = self.selected(['Future-Only', 'Old-Only', 'Unused-Only'])
        self.assertEqual(report['summary']['checkScoreChangesByCheck'], [])
        out = self.root / 'out'; out.write_text('previous')
        for path in ('demo.json', 'future.json', 'old.json', 'unused.json'):
            saved = copy.deepcopy(self.after[path])
            self.after[path]['checks'][0]['score'] = 11
            self.write()
            result = self.cli('--check', 'Not-Observed', '--output', out)
            self.assertEqual((result.returncode, result.stdout), (2, ''))
            self.assertIn('Scorecard check score must be', result.stderr)
            self.assertEqual(out.read_text(), 'previous')
            self.after[path] = saved
        self.after['conflict.json'] = copy.deepcopy(self.after['old.json'])
        self.after['conflict.json']['checks'][0]['reason'] = 'conflict'
        self.write()
        result = self.cli('--check', 'Not-Observed', '--output', out)
        self.assertEqual((result.returncode, result.stdout), (2, ''))
        self.assertIn('conflicting', result.stderr)
        self.assertEqual(out.read_text(), 'previous')

    def test_invalid_selectors_and_protected_outputs_remain_exit_two(self):
        from vulnwrench.scorecard import InputError
        for value in ('Code-Review', {}, 1, True, [None], [1], [''], [' \t\n'], ['Code-Review', False]):
            with self.subTest(value=value), self.assertRaises(InputError):
                self.library(value)
        self.assertEqual(self.library(('Code-Review',))['checkSelection'], {'names': ['Code-Review']})
        out = self.root / 'out'; out.write_text('previous')
        for format in ('json', 'markdown'):
            for extra in (('--check',), ('--check=',), ('--check', ' \t'),
                          ('--check', 'Code-Review', '--max-age-days', '-1')):
                result = self.cli('--format', format, '--output', out, *extra)
                self.assertEqual((result.returncode, result.stdout), (2, ''))
                self.assertEqual(out.read_text(), 'previous')
            sources = [self.root / p for p in ('bom.json', 'repos.json', 'before/demo.json', 'after/demo.json')]
            hard = self.root / 'hard'; os.link(sources[-1], hard)
            link = self.root / 'link'; link.symlink_to(sources[-2])
            for target in (*sources, hard, link, self.root / 'absent/out'):
                saved = target.read_bytes() if target.exists() else None
                result = self.cli('--check', 'Not-Observed', '--fail-on-decrease', '--format', format, '--output', target)
                self.assertEqual((result.returncode, result.stdout), (2, ''))
                self.assertNotIn('invalid command-line arguments', result.stderr)
                self.assertEqual(target.read_bytes() if target.exists() else None, saved)
            hard.unlink(); link.unlink()

    def test_selected_output_create_replace_and_stdout_failures(self):
        from vulnwrench.scorecard.cli import main
        args = ['compare', str(self.root / 'bom.json'), '--map', str(self.root / 'repos.json'),
                '--before', str(self.root / 'before'), '--after', str(self.root / 'after'),
                '--before-as-of', '2026-11-01', '--after-as-of', '2026-11-11', '--max-age-days', '2',
                '--check', 'Not-Observed', '--fail-on-decrease']
        out = self.root / 'out'; out.write_text('previous')
        for format in ('json', 'markdown'):
            for operation in ('tempfile.NamedTemporaryFile', 'os.replace'):
                with self.subTest(format=format, operation=operation), \
                     patch('vulnwrench.scorecard.cli.' + operation, side_effect=OSError('SECRET')), \
                     patch('sys.stdout', new_callable=io.StringIO) as stdout, \
                     patch('sys.stderr', new_callable=io.StringIO) as stderr:
                    self.assertEqual(main([*args, '--format', format, '--output', str(out)]), 2)
                    self.assertEqual(stdout.getvalue(), '')
                    self.assertEqual(stderr.getvalue(), 'vulnwrench scorecard: cannot write output file\n')
                    self.assertEqual(out.read_text(), 'previous')
                    self.assertEqual(list(self.root.glob('.scorecard-join-*')), [])
            with patch('sys.stdout.write', side_effect=BrokenPipeError('SECRET')), \
                 patch('sys.stderr', new_callable=io.StringIO) as stderr:
                self.assertEqual(main([*args, '--format', format]), 2)
                self.assertEqual(stderr.getvalue(), 'vulnwrench scorecard: cannot render or write report\n')


if __name__ == '__main__':
    unittest.main()
