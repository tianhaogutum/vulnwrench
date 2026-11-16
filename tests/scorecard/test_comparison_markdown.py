"""Literal comparison view contract; JSON semantics and failure exits stay shared."""

import contextlib
import copy
import html
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from vulnwrench.scorecard.cli import main

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'examples/scorecard/compare'
REPO = 'https://github.com/example/demo'


def evidence(markdown):
    match = re.search(r'(?m)^(`{3,})json\n([\s\S]*)\n\1\n\Z', markdown)
    if match is None:
        raise AssertionError('missing safely fenced complete JSON appendix')
    return json.loads(match[2])


def table_rows(text):
    return [[html.unescape(cell.strip()) for cell in line.split('|')[1:-1]]
            for line in text.splitlines() if line.startswith('| ') and not line.startswith('| ---')]


class ComparisonMarkdownTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('bom.json', 'repos.json', 'before', 'after'):
            source, target = FIXTURE / name, self.root / name
            shutil.copytree(source, target) if source.is_dir() else shutil.copyfile(source, target)

    def args(self, *extra):
        return ['compare', str(self.root / 'bom.json'), '--map', str(self.root / 'repos.json'),
                '--before', str(self.root / 'before'), '--after', str(self.root / 'after'),
                '--before-as-of', '2026-11-01', '--after-as-of', '2026-11-11',
                '--max-age-days', '2', *map(str, extra)]

    def cli(self, *extra):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'scorecard', *self.args(*extra)],
                              cwd=ROOT, capture_output=True, text=True, timeout=120)

    def write(self, path, document):
        path.write_text(json.dumps(document), encoding='utf-8')

    def views(self, *extra):
        default = self.cli(*extra)
        explicit = self.cli(*extra, '--format', 'json')
        markdown = self.cli(*extra, '--format', 'markdown')
        for run in (default, explicit, markdown):
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stderr, '')
        self.assertEqual(default.stdout, explicit.stdout)
        report = json.loads(default.stdout)
        self.assertEqual(evidence(markdown.stdout), report)
        human = markdown.stdout.split('## Evidence\n')[0]
        coverage = human.split('## Coverage\n')[1].split('## Components\n')[0]
        repositories, pairs = coverage.split('Raw check changes count observed repository/check pairs', 1)
        pairs, directions = pairs.split('Score directions count the same observed repository/check pairs', 1)
        directions, by_direction = directions.split('Score directions by check group the same pairs', 1)
        by_direction, comparability = by_direction.split('Check score comparability counts each observed pair once', 1)
        comparability, by_check = comparability.split('Check score comparability by check groups the same pairs', 1)
        by_check, observations = by_check.split('Check observations count the same pairs separately on each side', 1)
        observations, transitions = observations.split('Check observation transitions count each pair once', 1)
        rows = table_rows(repositories)[1:]
        self.assertEqual(table_rows(pairs)[0], ['Raw check change', 'Repository/check pairs'])
        self.assertEqual(table_rows(pairs)[1:], [
            [key, str(count)] for key, count in sorted(report['summary']['checkChanges'].items())])
        self.assertEqual(sum(report['summary']['checkChanges'].values()),
                         sum(len(row['checks']) for row in report['repositories']))
        self.assertEqual(table_rows(directions)[0], ['Check score direction', 'Repository/check pairs'])
        self.assertEqual(table_rows(directions)[1:], [
            [key, str(count)] for key, count in sorted(report['summary']['checkScoreChanges'].items())])
        self.assertEqual(sum(report['summary']['checkScoreChanges'].values()),
                         sum(report['summary']['checkChanges'].values()))
        self.assertEqual(table_rows(by_direction), [
            ['Check', 'Score direction', 'Repository/check pairs'],
            *[[row['name'].translate(str.maketrans({c: ' ' for c in
                '\r\n\t\v\f\x1c\x1d\x1e\x85\u2028\u2029'})), key, str(row[key])]
              for row in report['summary']['checkScoreChangesByCheck']
              for key in ('increased', 'decreased', 'unchanged', 'not_comparable')]])
        self.assertIn('not score quality, security or causality', by_direction)
        counts = report['summary']['checkScoreComparability']
        self.assertEqual(set(counts), {'comparable', 'evidence_blocked', 'observation_blocked'})
        self.assertEqual(table_rows(comparability), [
            ['Check score comparability', 'Repository/check pairs'],
            *[[key, str(count)] for key, count in sorted(counts.items())]])
        self.assertEqual(sum(counts.values()), sum(report['summary']['checkChanges'].values()))
        self.assertEqual(counts['evidence_blocked'] + counts['observation_blocked'],
                         report['summary']['checkScoreChanges']['not_comparable'])
        self.assertEqual(table_rows(by_check), [
            ['Check', 'Comparability', 'Repository/check pairs'],
            *[[row['name'].translate(str.maketrans({c: ' ' for c in
                '\r\n\t\v\f\x1c\x1d\x1e\x85\u2028\u2029'})), key, str(row[key])]
              for row in report['summary']['checkScoreComparabilityByCheck']
              for key in ('comparable', 'evidence_blocked', 'observation_blocked')]])
        expected_counts = dict.fromkeys(counts, 0)
        for repository in report['repositories']:
            for check in repository['checks']:
                key = ('comparable' if check['scoreChange'] != 'not_comparable' else
                       'evidence_blocked' if repository['comparison'] != 'comparable' else 'observation_blocked')
                expected_counts[key] += 1
        self.assertEqual(counts, expected_counts)
        self.assertIn('Evidence blockers take priority over observation gaps', comparability)
        self.assertIn('counts do not enumerate every simultaneous blocker', comparability)
        self.assertIn('Comparable describes support for numeric direction, not security or causality', comparability)
        self.assertEqual(table_rows(observations)[0], ['Side', 'Observation', 'Repository/check pairs'])
        self.assertEqual(table_rows(observations)[1:], [
            [side.title(), key, str(count)] for side in ('before', 'after')
            for key, count in sorted(report['summary']['checkObservations'][side].items())])
        for side in ('before', 'after'):
            counts = report['summary']['checkObservations'][side]
            self.assertEqual(set(counts), {'known', 'negative_score', 'missing_score', 'missing_check', 'missing_snapshot'})
            self.assertEqual(sum(counts.values()), sum(report['summary']['checkChanges'].values()))
            self.assertEqual(sum(counts.values()), sum(report['summary']['checkScoreChanges'].values()))
            for label, count in counts.items():
                self.assertEqual(count, sum(check[side + 'Observation'] == label
                    for repository in report['repositories'] for check in repository['checks']))
        matrix = report['summary']['checkObservationTransitions']
        labels = {'known', 'negative_score', 'missing_score', 'missing_check', 'missing_snapshot'}
        self.assertEqual(set(matrix), labels)
        self.assertEqual(table_rows(transitions), [
            ['Before observation', 'After observation', 'Repository/check pairs'],
            *[[before, after, str(count)] for before, counts in sorted(matrix.items())
              for after, count in sorted(counts.items())]])
        for before, counts in matrix.items():
            self.assertEqual(set(counts), labels)
            self.assertEqual(sum(counts.values()), report['summary']['checkObservations']['before'][before])
            self.assertEqual(sum(row[before] for row in matrix.values()),
                             report['summary']['checkObservations']['after'][before])
            for after, count in counts.items():
                self.assertEqual(count, sum((check['beforeObservation'], check['afterObservation']) == (before, after)
                    for repository in report['repositories'] for check in repository['checks']))
        self.assertIn('known to known does not establish score direction', transitions)
        expected = [['Comparison status', key, str(count)]
                    for key, count in sorted(report['summary']['comparisonStatuses'].items())]
        expected += [['Snapshot change', key, str(count)]
                     for key, count in sorted(report['summary']['snapshotChanges'].items())]
        for field in ('version', 'commit'):
            expected += [['Scanner '+field, key, str(count)]
                         for key, count in sorted(report['summary']['scannerChanges'][field].items())]
        self.assertEqual(rows, expected)
        for counts in [report['summary']['comparisonStatuses'], report['summary']['snapshotChanges'],
                       *report['summary']['scannerChanges'].values()]:
            self.assertEqual(sum(counts.values()), report['summary']['comparedRepositories'])
        return report, human, markdown.stdout

    def test_markdown_literal_fixture_stdout_atomic_file_and_json_bytes(self):
        report, human, markdown = self.views()
        self.assertEqual(self.cli().stdout, (FIXTURE / 'expected.json').read_text())
        self.assertEqual(markdown, (FIXTURE / 'expected.md').read_text())
        self.assertEqual(report['summary']['checkChanges'], {
            'changed': 5, 'unchanged': 0, 'added': 1, 'deleted': 1, 'not_comparable': 1})
        self.assertEqual(report['summary']['checkScoreChanges'], {
            'increased': 2, 'decreased': 0, 'unchanged': 1, 'not_comparable': 5})
        coverage = human.split('Raw check changes count observed repository/check pairs', 1)[1]
        raw, directions = coverage.split('Score directions count the same observed repository/check pairs', 1)
        self.assertEqual(table_rows(raw)[1:], [
            ['added', '1'], ['changed', '5'], ['deleted', '1'],
            ['not_comparable', '1'], ['unchanged', '0']])
        directions, by_direction = directions.split('Score directions by check group the same pairs', 1)
        by_direction, comparability = by_direction.split('Check score comparability counts each observed pair once', 1)
        comparability, by_check = comparability.split('Check score comparability by check groups the same pairs', 1)
        by_check, observations = by_check.split('Check observations count the same pairs separately on each side', 1)
        observations, transitions = observations.split('Check observation transitions count each pair once', 1)
        self.assertEqual(table_rows(by_direction), [
            ['Check', 'Score direction', 'Repository/check pairs'],
            ['Code-Review', 'increased', '2'],
            ['Code-Review', 'decreased', '0'],
            ['Code-Review', 'unchanged', '0'],
            ['Code-Review', 'not_comparable', '2'],
            ['Future-Check', 'increased', '0'],
            ['Future-Check', 'decreased', '0'],
            ['Future-Check', 'unchanged', '0'],
            ['Future-Check', 'not_comparable', '1'],
            ['License', 'increased', '0'],
            ['License', 'decreased', '0'],
            ['License', 'unchanged', '1'],
            ['License', 'not_comparable', '0'],
            ['Maintained', 'increased', '0'],
            ['Maintained', 'decreased', '0'],
            ['Maintained', 'unchanged', '0'],
            ['Maintained', 'not_comparable', '1'],
            ['Security-Policy', 'increased', '0'],
            ['Security-Policy', 'decreased', '0'],
            ['Security-Policy', 'unchanged', '0'],
            ['Security-Policy', 'not_comparable', '1'],
        ])
        self.assertEqual(table_rows(comparability), [
            ['Check score comparability', 'Repository/check pairs'],
            ['comparable', '3'], ['evidence_blocked', '2'], ['observation_blocked', '3']])
        self.assertEqual(table_rows(by_check), [
            ['Check', 'Comparability', 'Repository/check pairs'],
            ['Code-Review', 'comparable', '2'], ['Code-Review', 'evidence_blocked', '2'],
            ['Code-Review', 'observation_blocked', '0'],
            ['Future-Check', 'comparable', '0'], ['Future-Check', 'evidence_blocked', '0'],
            ['Future-Check', 'observation_blocked', '1'],
            ['License', 'comparable', '1'], ['License', 'evidence_blocked', '0'],
            ['License', 'observation_blocked', '0'],
            ['Maintained', 'comparable', '0'], ['Maintained', 'evidence_blocked', '0'],
            ['Maintained', 'observation_blocked', '1'],
            ['Security-Policy', 'comparable', '0'], ['Security-Policy', 'evidence_blocked', '0'],
            ['Security-Policy', 'observation_blocked', '1']])
        self.assertEqual(table_rows(observations.split('## Components')[0]), [
            ['Side', 'Observation', 'Repository/check pairs'],
            ['Before', 'known', '6'], ['Before', 'missing_check', '1'], ['Before', 'missing_score', '0'],
            ['Before', 'missing_snapshot', '0'], ['Before', 'negative_score', '1'],
            ['After', 'known', '6'], ['After', 'missing_check', '1'], ['After', 'missing_score', '0'],
            ['After', 'missing_snapshot', '1'], ['After', 'negative_score', '0']])
        self.assertEqual(table_rows(directions)[1:], [
            ['decreased', '0'], ['increased', '2'], ['not_comparable', '5'], ['unchanged', '1']])
        output = self.root / 'report.md'
        output.write_text('previous')
        run = self.cli('--format', 'markdown', '--output', output)
        self.assertEqual((run.returncode, run.stdout, run.stderr), (0, '', ''))
        self.assertEqual(output.read_text(), markdown)
        self.assertEqual(list(self.root.glob('.scorecard-join-*')), [])
        from vulnwrench.scorecard.comparison_markdown import render_comparison_markdown
        self.assertEqual(render_comparison_markdown(report), markdown)
        self.assertIn('not score quality, a security gate or causal attribution', human)

    def test_markdown_evidence_blocker_matrix_keeps_raw_checks_and_scanner_independent(self):
        original = json.loads((FIXTURE / 'before/demo.json').read_text())
        cases = [
            ('missing_both', None, None, 'missing_scorecard', 'missing_scorecard', 'not_comparable'),
            ('missing_after', '2026-11-01', None, 'fresh', 'missing_scorecard', 'not_comparable'),
            ('missing_before', None, '2026-11-11', 'missing_scorecard', 'fresh', 'not_comparable'),
            ('missing_before', '2026-11-12', '2026-11-11', 'no_snapshot_as_of', 'fresh', 'not_comparable'),
            ('missing_after', '2026-11-01', '2026-11-12', 'fresh', 'no_snapshot_as_of', 'not_comparable'),
            ('stale_after', '2026-11-01', '2026-11-02', 'fresh', 'stale', 'advanced'),
            ('stale_before', '2026-10-01', '2026-11-11', 'stale', 'fresh', 'advanced'),
            ('snapshot_time_regressed', '2026-11-01', '2026-10-31', 'fresh', 'fresh', 'regressed'),
            ('snapshot_time_ambiguous', '2026-11-01', '2026-11-01T01:00:00+01:00',
             'fresh', 'fresh', 'same_timestamp_changed'),
            ('comparable', '2026-11-01', '2026-11-11', 'fresh', 'fresh', 'advanced'),
        ]
        self.write(self.root / 'bom.json', {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
                   'components': [{'type': 'library', 'name': 'demo', 'purl': 'pkg:npm/demo@1'}]})
        for status, before_date, after_date, before_status, after_status, chronology in cases:
            with self.subTest(status=status, before=before_status, after=after_status):
                for side, date, score in (('before', before_date, 3), ('after', after_date, 8)):
                    for path in (self.root / side).iterdir():
                        path.unlink()
                    if date:
                        document = copy.deepcopy(original)
                        document['date'] = date
                        document['checks'] = [{'name': 'Code-Review', 'score': score, 'reason': side}]
                        document['scorecard']['version'] = 'old' if side == 'before' else 'new'
                        self.write(self.root / side / 'demo.json', document)
                report, human, _ = self.views('--max-age-days', 30 if status.startswith('snapshot_time') else 2)
                row = report['repositories'][0]
                self.assertEqual((row['comparison'], row['snapshotChange']), (status, chronology))
                self.assertEqual((row['before']['status'], row['after']['status']), (before_status, after_status))
                rows = table_rows(human)
                self.assertIn([REPO, status, chronology, row['commitChange']], rows)
                for side, expected_status in (('Before', before_status), ('After', after_status)):
                    self.assertTrue(any(r[:2] == [side, expected_status] for r in rows))
                if row['checks']:
                    check = row['checks'][0]
                    self.assertEqual(check['scoreChange'], 'increased' if status == 'comparable' else 'not_comparable')
                    self.assertTrue(any(r[:3] == ['Code-Review', check['change'], check['scoreChange']] for r in rows))
                else:
                    self.assertIn('No observed checks.', human)
                self.assertEqual(report['summary']['checkScoreChanges'], {
                    'increased': int(status == 'comparable'), 'decreased': 0, 'unchanged': 0,
                    'not_comparable': int(status != 'comparable' and bool(row['checks']))})
                self.assertEqual(row['scannerChange']['versionChange'],
                                 'changed' if before_status in ('fresh', 'stale') and after_status in ('fresh', 'stale')
                                 else 'not_comparable')

    def test_markdown_empty_mapped_inventories_and_unavailable_scanner_metadata(self):
        for components in ([], [{'type': 'file', 'name': 'local'}]):
            self.write(self.root / 'bom.json', {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
                                               'components': components})
            report, human, _ = self.views()
            self.assertEqual(report['repositories'], [])
            self.assertEqual(report['summary']['comparedRepositories'], 0)
            self.assertEqual(report['summary']['checkChanges'], {
                'changed': 0, 'unchanged': 0, 'added': 0, 'deleted': 0, 'not_comparable': 0})
            self.assertEqual(report['summary']['checkScoreChanges'], {
                'increased': 0, 'decreased': 0, 'unchanged': 0, 'not_comparable': 0})
            self.assertIn('No mapped repositories.', human)
            if not components:
                self.assertIn('No components.', human)
        shutil.copyfile(FIXTURE / 'bom.json', self.root / 'bom.json')
        for value in (None, {}, {'version': ' ', 'commit': 123}):
            for side in ('before', 'after'):
                path = self.root / side / 'demo.json'
                document = json.loads(path.read_text())
                document['scorecard'] = value
                self.write(path, document)
            report, human, _ = self.views()
            self.assertEqual(report['repositories'][0]['scannerChange']['versionChange'], 'not_comparable')
            self.assertIn(['version', '—', '—', 'not_comparable'], table_rows(human))

    def test_markdown_escapes_names_reasons_check_identifiers_metadata_and_fences(self):
        unsafe = '<img src=x>|[click](url)*_`\\\u2028next\u2029line & "é" ~~ ````'
        self.write(self.root / 'bom.json', {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
                   'components': [{'type': 'library', 'name': unsafe, 'purl': 'pkg:npm/demo@1'}]})
        for side in ('before', 'after'):
            path = self.root / side / 'demo.json'
            document = json.loads(path.read_text())
            document['checks'] = [{'name': unsafe, 'score': 5, 'reason': unsafe + '\r\n\t', 'extension': {'raw': unsafe}}]
            document['scorecard'] = {'version': unsafe + '\r\n\t', 'commit': unsafe, 'extension': unsafe}
            document['repo']['commit'] = unsafe
            self.write(path, document)
        report, human, markdown = self.views()
        self.assertNotIn('<img', markdown)
        for syntax in ('[click]', '````', '*_', '~~', '\u2028', '\u2029'):
            self.assertNotIn(syntax, human)
        self.assertIn('&lt;img src=x&gt;&#124;&#91;click&#93;&#40;url&#41;&#42;&#95;&#96;&#92;', human)
        self.assertIn('next line &amp; &quot;é&quot; &#126;&#126;', human)
        appendix = markdown.split('## Evidence\n')[1]
        self.assertIn('\n`````json\n', appendix)
        self.assertIn('\\u003cimg', appendix)
        self.assertIn('\\u0026', appendix)
        self.assertEqual(report['components'][0]['name'], unsafe)
        self.assertEqual(report['repositories'][0]['checks'][0]['after']['extension']['raw'], unsafe)
        rows = [line for line in human.splitlines() if line.startswith('| ')]
        # Supplied pipes/line breaks cannot make extra columns or table rows.
        checks = human.split('## Repositories', 1)[1].split('| Check |', 1)[1]
        self.assertEqual([line.count('|') for line in checks.splitlines() if line.startswith('| ')], [12, 12])
        self.assertEqual(len([r for r in rows if '&lt;img' in r]), 13)

    def test_markdown_raw_absent_null_negative_and_missing_scores_remain_distinct(self):
        path = self.root / 'before/demo.json'
        document = json.loads(path.read_text())
        document['checks'] = [{'name': 'Absent'}, {'name': 'Null', 'score': None, 'reason': None},
                              {'name': 'Negative', 'score': -1}, {'name': 'Known', 'score': 5},
                              {'name': 'Decreased', 'score': 10}, {'name': 'Increased', 'score': 0}]
        self.write(path, document)
        document['date'] = '2026-11-11'
        document['checks'][-2]['score'], document['checks'][-1]['score'] = 0, 10
        self.write(self.root / 'after/demo.json', document)
        report, human, _ = self.views()
        self.assertEqual(report['summary']['checkScoreChanges'], {
            'increased': 2, 'decreased': 1, 'unchanged': 1, 'not_comparable': 5})
        self.assertEqual(report['summary']['checkObservations'], {
            'before': {'known': 6, 'negative_score': 1, 'missing_score': 2, 'missing_check': 0, 'missing_snapshot': 0},
            'after': {'known': 5, 'negative_score': 1, 'missing_score': 2, 'missing_check': 0, 'missing_snapshot': 1}})
        checks = {row[0]: row for row in table_rows(human) if row[0] in ('Absent', 'Null', 'Negative', 'Known')}
        self.assertEqual(checks['Absent'][2:8], ['not_comparable', 'missing_score', 'missing_score', 'absent', 'absent', 'false'])
        self.assertEqual(checks['Null'][5:10], ['null', 'null', 'false', 'null', 'null'])
        self.assertEqual(checks['Negative'][2:7], ['not_comparable', 'negative_score', 'negative_score', '-1', '-1'])
        self.assertEqual(checks['Known'][2], 'unchanged')
        self.assertEqual(report['repositories'][0]['checks'][0]['before'], {'name': 'Absent'})

    def test_markdown_invalid_inputs_formats_and_cutoffs_preserve_output(self):
        output = self.root / 'out.md'
        output.write_text('previous')
        cases = [(self.root / 'repos.json', '{'), (self.root / 'bom.json', '{"bomFormat":"SPDX"}'),
                 (self.root / 'after/demo.json', '{}'),
                 (self.root / 'repos.json', '{"pkg:npm/demo@1":"https://SECRET@github.com/a/b"}')]
        for path, raw in cases:
            saved = path.read_bytes()
            path.write_text(raw)
            for format in ('json', 'markdown'):
                run = self.cli('--format', format, '--output', output)
                self.assertEqual(run.returncode, 2)
                self.assertEqual(run.stdout, '')
                self.assertIn('vulnwrench scorecard:', run.stderr)
                self.assertNotIn('invalid command-line arguments', run.stderr)
                self.assertNotIn('SECRET', run.stderr)
                self.assertNotIn('Traceback', run.stderr)
                self.assertEqual(output.read_text(), 'previous')
            path.write_bytes(saved)
        for extra in (('--format', 'html'), ('--format', 'markdown', '--after-as-of', '2026-10-31'),
                      ('--format', 'markdown', '--max-age-days', '-1'), ('--format', 'markdown', '--gate')):
            run = self.cli(*extra, '--output', output)
            self.assertEqual(run.returncode, 2)
            self.assertEqual(run.stdout, '')
            self.assertEqual(output.read_text(), 'previous')

    def test_markdown_protected_paths_and_atomic_failure_preserve_evidence(self):
        alias, symlink = self.root / 'alias.json', self.root / 'link.json'
        os.link(self.root / 'before/demo.json', alias)
        symlink.symlink_to(self.root / 'after/demo.json')
        inputs = [self.root / 'bom.json', self.root / 'repos.json', self.root / 'before/demo.json',
                  self.root / 'after/demo.json']
        saved = [p.read_bytes() for p in inputs]
        for output in (*inputs, alias, symlink, self.root / 'before', self.root / 'absent/out.md'):
            run = self.cli('--format', 'markdown', '--output', output)
            self.assertEqual(run.returncode, 2)
            self.assertEqual(run.stdout, '')
            self.assertNotIn('Traceback', run.stderr)
            self.assertEqual([p.read_bytes() for p in inputs], saved)
            self.assertTrue(symlink.is_symlink())
        output = self.root / 'out.md'
        output.write_text('previous')
        for operation in ('os.replace', 'tempfile.NamedTemporaryFile'):
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch('vulnwrench.scorecard.cli.'+operation, side_effect=OSError('SECRET')), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main(self.args('--format', 'markdown', '--output', output))
            self.assertEqual(code, 2)
            self.assertEqual(stdout.getvalue(), '')
            self.assertIn('cannot write output file', stderr.getvalue())
            self.assertNotIn('SECRET', stderr.getvalue())
            self.assertEqual(output.read_text(), 'previous')
            self.assertEqual(list(self.root.glob('.scorecard-join-*')), [])


if __name__ == '__main__':
    unittest.main()
