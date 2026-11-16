#!/usr/bin/env python3
"""Measure replacement and skipped buckets on PUBLIC synthetic inputs.

Warmup + repeated untraced comparison times, separate Python allocation peak;
fixture/prior construction, JSON I/O and tracing excluded from timing.
"""
import argparse
import cProfile
import hashlib
import importlib.util
import json
import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]  # run from a clone, installed or not
from vulnwrench.secretledger import core
from scripts.secrets.benchmark_privacy import KEY, digest, measure


def empty_candidate_fixture(size, mapped=False, buckets=1, lines_per_group=16, mixed=False):
    """Public empty buckets plus optional nonempty/precedence controls."""
    old, new, mapping = [], [], [] if mapped else None

    def add(rows, secret, path, rule, lines):
        rows.extend({'RuleID': rule, 'File': path, 'StartLine': line, 'Commit': '',
                     'Fingerprint': f'{path}:{rule}:{line}', 'Secret': secret} for line in lines)

    for bucket in range(buckets):
        for kind in ('rule-change', 'vacant', 'brand-new', 'unrelated') + (
                ('needed', 'exact', 'blocked', 'unknown-only') if mixed else ()):
            source = f'src/{kind}-{bucket:05d}.py'
            target = source.replace('src/', 'lib/') if mapped and kind != 'brand-new' else source
            if mapped and kind != 'brand-new':
                mapping.append({'old_path': source, 'new_path': target})
            if kind in ('blocked', 'unknown-only'):
                add(old, None, source, 'generic-api-key', [900001, 900001])
            for i in range(size):
                secret = f'SYNTHETIC_BEFORE_{i:08d}_END'
                lines = list(range(i * lines_per_group + 1, (i + 1) * lines_per_group + 1))
                lines.append(lines[-1])  # duplicate evidence is never collapsed
                if kind in ('rule-change', 'unrelated', 'needed', 'exact', 'blocked'):
                    add(old, secret, source, 'old-rule' if kind == 'rule-change' else 'generic-api-key', lines)
                if kind != 'unrelated':
                    current_secret = secret if kind == 'exact' or kind == 'blocked' and i == 0 else secret.replace('BEFORE', 'AFTER')
                    query_lines = [i * lines_per_group + 1, 800001 + i, 800001 + i] if kind == 'needed' else lines
                    add(new, current_secret, target, 'generic-api-key', query_lines)
            if kind == 'blocked':
                add(new, None, target, 'generic-api-key', [900002, 900002])
    return old, new, mapping


def verify_empty_candidates(comparison, current, before, size, buckets, mapped, mixed):
    """Fixture-specific semantic/evidence checks, outside measurement."""
    assert current['summary']['groups'] == buckets * (7 * size + 1 if mixed else 3 * size)
    by_ident = {(g['rule_id'], g['path'].replace('src/', 'lib/') if mapped else g['path'],
                 g['content_hmac']): g for g in before['groups'] if g['content_hmac']}
    for event in comparison['changes']:
        group = event['current']
        if group is None:
            assert event['classification'] == ('uncomparable' if group_unknown(event['previous'][0])
                                               or '/blocked-' in event['previous'][0]['path'] else 'absent')
            continue
        kind = group['path'].split('/')[-1].rsplit('-', 1)[0]
        prior = by_ident.get((group['rule_id'], group['path'], group['content_hmac']))
        expected = ('uncomparable' if group_unknown(group) or kind == 'brand-new' and mapped else
                    'same_secret_moved' if prior and mapped else 'unchanged' if prior else
                    'uncomparable' if kind in ('blocked', 'unknown-only') else
                    'new_content_same_location' if kind == 'needed' else 'new_content')
        assert event['classification'] == expected
        if prior:
            assert event['previous'] == [prior]
        elif expected == 'new_content' or kind == 'brand-new' or group_unknown(group):
            assert event['previous'] == []
        elif kind in ('blocked', 'unknown-only'):
            assert len(event['previous']) == 1 and group_unknown(event['previous'][0])
            assert event['reason'] == 'prior_content_unavailable'
        else:
            assert len(event['previous']) == 1
            old = event['previous'][0]
            assert old['path'].replace('src/', 'lib/') == group['path'].replace('src/', 'lib/')
            assert old['occurrences'][0]['start_line'] == group['occurrences'][0]['start_line']
            assert len(old['occurrences']) >= 2


def group_unknown(group):
    return group['content_hmac'] is None


def empty_index_fixture(size, mapped=False, buckets=1, lines_per_group=16, mixed=False):
    """Nonempty prior buckets with many multi-line misses; optional hit/skip controls."""
    old, new, mapping = (empty_candidate_fixture(size, mapped, buckets, lines_per_group, True)
                         if mixed else ([], [], [] if mapped else None))

    def add(rows, secret, path, rule, lines):
        rows.extend({'RuleID': rule, 'File': path, 'StartLine': line, 'Commit': '',
                     'Fingerprint': f'{path}:{rule}:{line}', 'Secret': secret} for line in lines)

    for bucket in range(buckets):
        for kind in ('all-miss', 'dense-hit') if mixed else ('all-miss',):
            source = f'src/{kind}-{bucket:05d}.py'
            target = source.replace('src/', 'lib/') if mapped else source
            if mapped:
                mapping.append({'old_path': source, 'new_path': target})
            for rule in ('generic-api-key', 'other-rule'):
                for i in range(size):
                    secret = f'SYNTHETIC_BEFORE_{i:08d}_END'
                    lines = list(range(i * lines_per_group + 1, (i + 1) * lines_per_group + 1))
                    misses = [800001 + line for line in lines]
                    if kind == 'dense-hit':
                        lines.append(700001)
                        misses.append(700001)
                    add(old, secret, source, rule, [*lines, lines[-1]])
                    add(new, secret.replace('BEFORE', 'AFTER'), target, rule, [*misses, misses[-1]])
                    if mixed and i == 0:
                        # Exact and current unknown groups cannot add query lines.
                        add(new, secret, target, rule, [*lines, lines[-1]])
                        add(new, None, target, rule, [900002, 900002])
    return old, new, mapping


def partial_hit_fixture(size, mapped=False, buckets=1, lines_per_group=16, mixed=False, single_hit=False):
    """Many misses in nonempty indexes, including fully missing queries."""
    old, new, mapping = (empty_index_fixture(size, mapped, buckets, lines_per_group, True)
                         if mixed else ([], [], [] if mapped else None))
    for bucket in range(buckets):
        for kind in ('partial-hit', 'dense-partial'):
            source = f'src/{kind}-{bucket:05d}.py'
            target = source.replace('src/', 'lib/') if mapped else source
            if mapped:
                mapping.append({'old_path': source, 'new_path': target})
            for rule in ('generic-api-key', 'other-rule'):
                for i in range(size):
                    secret = f'SYNTHETIC_BEFORE_{i:08d}_END'
                    lines = list(range(i * lines_per_group + 1, (i + 1) * lines_per_group + 1))
                    queries = [800001 + line for line in lines]
                    if i % 2 == 0:
                        queries += lines[:1] if single_hit and not (mixed and i == 2) else lines[:2]
                    if kind == 'dense-partial':
                        lines.append(700001)
                        if i % 2 == 0:
                            if single_hit and not (mixed and i == 2):
                                queries = [line for line in queries if line >= 800001]
                            queries.append(700001)
                    for rows, value, path, positions in ((old, secret, source, lines),
                            (new, secret.replace('BEFORE', 'AFTER'), target, queries)):
                        rows.extend({'RuleID': rule, 'File': path, 'StartLine': line, 'Commit': '',
                                     'Fingerprint': f'{path}:{rule}:{line}', 'Secret': value}
                                    for line in [*positions, positions[-1]])
    return old, new, mapping


def verify_empty_index(comparison, current, before, size, buckets, mapped, mixed, partial=False):
    """Independent exhaustive evidence checks, outside measured operations."""
    assert current['summary']['groups'] == buckets * ((15 * size + 9 if mixed else 4 * size)
                                                    if partial else (11 * size + 9 if mixed else 2 * size))
    forward = {p['old_path']: p['new_path'] for p in comparison.get('path_map', [])}
    by_path = {}
    for group in before['groups']:
        by_path.setdefault((group['rule_id'], forward.get(group['path'], group['path'])), []).append(group)
    for event in comparison['changes']:
        group = event['current']
        if group is None:
            assert event['classification'] in ('absent', 'uncomparable')
            continue
        kind = group['path'].split('/')[-1].rsplit('-', 1)[0]
        candidates = by_path.get((group['rule_id'], group['path']), [])
        exact = [g for g in candidates if g['content_hmac'] == group['content_hmac']]
        unknown = [g for g in candidates if group_unknown(g)]
        if group_unknown(group) or mapped and kind == 'brand-new':
            expected, evidence = 'uncomparable', []
        elif exact:
            expected, evidence = ('same_secret_moved' if mapped else 'unchanged'), exact
        elif unknown:
            expected, evidence = 'uncomparable', unknown
        else:
            lines = {o['start_line'] for o in group['occurrences']}
            evidence = [g for g in candidates if any(o['start_line'] in lines for o in g['occurrences'])]
            expected = 'new_content_same_location' if evidence else 'new_content'
            if kind in ('partial-hit', 'dense-partial'):
                hits = any(line < 800001 for line in lines)
                assert len(evidence) == ((size if kind == 'dense-partial' else 1) if hits else 0)
            else:
                assert len(evidence) == (size if kind == 'dense-hit' else 1 if kind == 'needed' else 0)
        assert event['classification'] == expected
        assert event['previous'] == evidence


def fixture(size, mapped=False, workload='replacement', buckets=1, lines_per_group=32):
    if workload in ('single-hit', 'mixed-single'):
        return partial_hit_fixture(size, mapped, buckets, lines_per_group, workload == 'mixed-single', True)
    if workload in ('partial-hit', 'mixed-partial'):
        return partial_hit_fixture(size, mapped, buckets, lines_per_group, workload == 'mixed-partial')
    if workload in ('many-miss', 'mixed-miss'):
        return empty_index_fixture(size, mapped, buckets, lines_per_group, workload == 'mixed-miss')
    if workload in ('empty-candidates', 'mixed-empty'):
        return empty_candidate_fixture(size, mapped, buckets, lines_per_group, workload == 'mixed-empty')
    if buckets != 1:
        old, new, mapping = [], [], [] if mapped else None
        for bucket in range(buckets):
            prior_rows, current_rows, paths = fixture(size, mapped, workload, lines_per_group=lines_per_group)
            for rows in (prior_rows, current_rows):
                for row in rows:
                    row['File'] = row['File'].replace('shared.py', f'shared-{bucket:05d}.py')
                    row['Fingerprint'] = f"{row['File']}:generic-api-key:{row['StartLine']}"
            old.extend(prior_rows)
            new.extend(current_rows)
            if mapped:
                mapping.extend({k: v.replace('shared.py', f'shared-{bucket:05d}.py')
                                for k, v in pair.items()} for pair in paths)
        return old, new, mapping
    old, new = [], []
    old_path, new_path = 'src/shared.py', 'lib/shared.py' if mapped else 'src/shared.py'
    if workload in ('sparse-lines', 'dense-lines', 'all-miss'):
        common = size * lines_per_group + 1
        for i in range(size):
            lines = list(range(i * lines_per_group + 1, (i + 1) * lines_per_group + 1))
            if workload == 'dense-lines':
                lines.append(common)
            for line in [*lines, lines[-1]]:
                old.append({'RuleID': 'generic-api-key', 'File': old_path, 'StartLine': line,
                            'Commit': '', 'Fingerprint': f'{old_path}:generic-api-key:{line}',
                            'Secret': f'SYNTHETIC_BEFORE_{i:08d}_END'})
        for i in range(min(4, size)):
            miss = common + 100 + i
            hit = common if workload == 'dense-lines' else i * lines_per_group + 1
            for line in ([miss, miss] if workload == 'all-miss' else [hit, miss, miss]):
                new.append({'RuleID': 'generic-api-key', 'File': new_path, 'StartLine': line,
                            'Commit': '', 'Fingerprint': f'{new_path}:generic-api-key:{line}',
                            'Secret': f'SYNTHETIC_AFTER_{i:08d}_END'})
        mapping = [{'old_path': old_path, 'new_path': new_path}] if mapped else None
        return old, new, mapping
    for i in range(size):
        for rows, path, phase, lines in (
            (old, old_path, 'BEFORE', [2 * i + 1, 2 * i + 2]),
            (new, new_path, 'AFTER' if workload == 'replacement' else 'BEFORE',
             [2 * i + 2, 2 * size + i + 1] if workload == 'replacement' else [2 * i + 1, 2 * i + 2])):
            for line in lines:
                row = {'RuleID': 'generic-api-key', 'File': path, 'StartLine': line,
                       'Commit': '', 'Fingerprint': f'{path}:generic-api-key:{line}',
                       'Secret': (None if rows is new and workload == 'unknown' else
                                  f'SYNTHETIC_{phase}_{i:08d}_END')}
                rows.append(row)
            if i % 29 == 0:
                rows.append(dict(row))
    mapping = [{'old_path': old_path, 'new_path': new_path}] if mapped else None
    return old, new, mapping


def verify(comparison, current, before, size, occurrences, workload='replacement', mapped=False,
           buckets=1):
    if workload in ('single-hit', 'mixed-single'):
        assert current['summary']['occurrences'] == occurrences
        return verify_empty_index(comparison, current, before, size, buckets, mapped,
                                  workload == 'mixed-single', partial=True)
    if workload in ('partial-hit', 'mixed-partial'):
        assert current['summary']['occurrences'] == occurrences
        return verify_empty_index(comparison, current, before, size, buckets, mapped,
                                  workload == 'mixed-partial', partial=True)
    if workload in ('many-miss', 'mixed-miss'):
        assert current['summary']['occurrences'] == occurrences
        return verify_empty_index(comparison, current, before, size, buckets, mapped, workload == 'mixed-miss')
    if workload in ('empty-candidates', 'mixed-empty'):
        return verify_empty_candidates(comparison, current, before, size, buckets, mapped, workload == 'mixed-empty')
    if workload in ('sparse-lines', 'dense-lines', 'all-miss'):
        assert current['summary'] == {'groups': min(4, size) * buckets,
                                      'occurrences': occurrences, 'uncomparable_occurrences': 0}
        forward = {p['old_path']: p['new_path'] for p in comparison.get('path_map', [])}
        for event in comparison['changes']:
            if event['current']:
                group = event['current']
                lines = {o['start_line'] for o in group['occurrences']}
                expected = [g for g in before['groups'] if g['rule_id'] == group['rule_id']
                            and forward.get(g['path'], g['path']) == group['path']
                            and any(o['start_line'] in lines for o in g['occurrences'])]
                assert event['previous'] == expected
                assert len(expected) == (0 if workload == 'all-miss' else
                                         size if workload == 'dense-lines' else 1)
                assert event['classification'] == ('new_content_same_location' if expected else 'new_content')
        assert comparison['summary']['absent'] == size * buckets
        return
    size *= buckets
    if workload != 'replacement':
        unknown = workload in ('redacted', 'unknown')
        kind = 'uncomparable' if unknown else 'same_secret_moved' if mapped else 'unchanged'
        assert {k: v for k, v in comparison['summary'].items() if v} == {kind: size + buckets if unknown else size}
        assert current['summary'] == {'groups': buckets if unknown else size, 'occurrences': occurrences,
                                      'uncomparable_occurrences': occurrences if unknown else 0}
        if unknown:
            assert all(e['previous'] == [] and e['reason'] == 'current_content_unavailable'
                       for e in comparison['changes'][:buckets])
            assert [e['previous'][0] for e in comparison['changes'][buckets:]] == before['groups']
        else:
            assert [e['previous'][0] for e in comparison['changes']] == before['groups']
            for event in comparison['changes']:
                assert [o['start_line'] for o in event['current']['occurrences']] == [
                    o['start_line'] for o in event['previous'][0]['occurrences']]
        return
    assert {k: v for k, v in comparison['summary'].items() if v} == {
        'new_content_same_location': size, 'absent': size}
    assert current['summary'] == {'groups': size, 'occurrences': occurrences,
                                  'uncomparable_occurrences': 0}
    forward = {p['old_path']: p['new_path'] for p in comparison.get('path_map', [])}
    by_line = {(g['rule_id'], forward.get(g['path'], g['path']), o['start_line']): g
               for g in before['groups'] for o in g['occurrences']}
    for event in comparison['changes']:
        if event['current']:
            group = event['current']
            overlaps = {(group['rule_id'], group['path'], o['start_line'])
                        for o in group['occurrences']} & by_line.keys()
            assert len(overlaps) == 1
            assert event['previous'] == [by_line[overlaps.pop()]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path, help='archived core.py for identical-input baseline')
    parser.add_argument('--sizes', type=int, nargs='+', default=[1000, 4000])
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--buckets', type=int, default=1, help='rule/path buckets; sizes are per bucket')
    parser.add_argument('--lines-per-group', type=int, default=32)
    parser.add_argument('--workloads', nargs='+', choices=('replacement', 'exact', 'redacted', 'unknown',
                                                                   'sparse-lines', 'dense-lines', 'all-miss',
                                                                   'empty-candidates', 'mixed-empty',
                                                                   'many-miss', 'mixed-miss',
                                                                   'partial-hit', 'mixed-partial', 'single-hit', 'mixed-single'),
                        default=['replacement'])
    args = parser.parse_args()
    if args.repeats < 1 or args.buckets < 1 or args.lines_per_group < 1 or any(n < 1 for n in args.sizes):
        parser.error('sizes, buckets and repeats must be positive')
    implementation = core
    if args.core:
        spec = importlib.util.spec_from_file_location('measured_core', args.core)
        implementation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(implementation)
    results = []
    for size in args.sizes:
        for workload in args.workloads:
            for mapped in (False, True):
                old, report, mapping = fixture(size, mapped, workload, args.buckets, args.lines_per_group)
                before = implementation.snapshot(old, KEY)
                redacted = workload == 'redacted'
                operation = lambda: implementation.compare(before, report, KEY, path_map=mapping,
                                                            redacted=redacted)
                comparison, current = operation()
                verify(comparison, current, before, size, len(report), workload, mapped, args.buckets)
                results.append({'prior_groups': len(before['groups']),
                                'buckets': args.buckets, 'groups_per_bucket': size,
                                'current_groups': len(current['groups']),
                                'prior_occurrences': len(old), 'current_occurrences': len(report),
                                'lines_per_group': args.lines_per_group, 'workload': workload,
                                'comparison_sha256': hashlib.sha256(core.dumps(comparison).encode()).hexdigest(),
                                'current_sha256': hashlib.sha256(core.dumps(current).encode()).hexdigest(),
                                'operation': 'mapped' if mapped else 'same_path',
                                'input_sha256': digest([before, report, mapping, redacted]),
                                **measure(operation, args.repeats)})
    profile = cProfile.Profile()
    profile.runcall(operation)
    rows = [{'function': e.code.co_name, 'calls': e.callcount, 'self_seconds': e.inlinetime,
             'cumulative_seconds': e.totaltime} for e in profile.getstats()
            if hasattr(e.code, 'co_name')]
    print(json.dumps({'python': sys.version, 'platform': platform.platform(),
                      'core_sha256': hashlib.sha256(Path(implementation.__file__).read_bytes()).hexdigest(),
                      'method': __doc__, 'results': results,
                      'largest_mapped_profile': sorted(rows, key=lambda r: r['cumulative_seconds'],
                                                        reverse=True)[:15]}, indent=2))


if __name__ == '__main__':
    main()
