#!/usr/bin/env python3
"""Measure position fingerprints vs HMAC groups on synthetic full reports.

Correctness/triage comparison only, not a scanner benchmark or security proof.
"""
from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))  # run from a clone, installed or not
from vulnwrench.secretledger import compare, snapshot

TEST_KEY = b'0123456789abcdef0123456789abcdef'  # PUBLIC TEST ONLY


def finding(secret, path, line, commit=''):
    return {'RuleID': 'generic-api-key', 'File': path, 'StartLine': line,
            'Commit': commit, 'Secret': secret, 'Match': 'test_token=' + secret,
            'Fingerprint': f'{commit+":" if commit else ""}{path}:generic-api-key:{line}'}


def corpus():
    before, after = [], []
    # 40 replacements retain exact native position-only fingerprints.
    for n in range(40):
        path = f'src/replaced-{n}.py'
        before.append(finding(f'SYNTHETIC_OLD_CONTENT_{n:04d}', path, 4))
        after.append(finding(f'SYNTHETIC_NEW_CONTENT_{n:04d}', path, 4))
    # 25 content identities recur 12 times each in distinct commits/locations.
    for n in range(25):
        secret, path = f'SYNTHETIC_CHURN_CONTENT_{n:04d}', f'src/churn-{n}.py'
        before.append(finding(secret, path, 1, 'a'*40))
        for version in range(12):
            after.append(finding(secret, path, version + 2, f'{version+1:040x}'))
    return before, after


def naive(before, after):
    known = {row['Fingerprint'] for row in before}
    return [row for row in after if row['Fingerprint'] not in known]


def measure(repeat=5):
    before, after = corpus()
    naive_ms, ledger_ms = [], []
    for _ in range(repeat):
        start = time.perf_counter_ns()
        new_rows = naive(before, after)
        naive_ms.append((time.perf_counter_ns() - start) / 1e6)
        start = time.perf_counter_ns()
        result, current = compare(snapshot(before, TEST_KEY), after, TEST_KEY)
        ledger_ms.append((time.perf_counter_ns() - start) / 1e6)
    baseline_changed = sum('/replaced-' in row['File'] for row in new_rows)
    baseline_churn = sum('/churn-' in row['File'] for row in new_rows)
    ledger_changed = result['summary']['new_content_same_location']
    ledger_churn = result['summary']['same_secret_moved']
    assert (baseline_changed, ledger_changed) == (0, 40), 'changed-content detection mismatch'
    assert (baseline_churn, ledger_churn) == (300, 25), 'duplicate-review measurement mismatch'
    assert current['summary']['occurrences'] == len(after) == 340
    assert current['summary']['groups'] == 65
    assert result['summary']['uncomparable'] == 0
    assert result['summary']['absent'] == 40
    # Confirm no churn content became a false new-content triage group.
    assert result['summary']['new_content'] == 0
    return {
        'schema': 'secret-ledger-synthetic-comparison/v1',
        'environment': {'python': platform.python_version(), 'system': platform.system(),
                        'machine': platform.machine()},
        'corpus': {'before_occurrences': len(before), 'after_occurrences': len(after),
                   'changed_content_cases': 40, 'churn_content_groups': 25,
                   'occurrences_per_churn_group': 12},
        'position_fingerprint_baseline': {'changed_content_detected': baseline_changed,
                                          'churn_review_units': baseline_churn,
                                          'repeated_churn_units_beyond_one_per_content': baseline_churn - 25},
        'content_ledger': {'changed_content_detected': ledger_changed,
                           'churn_review_units': ledger_churn,
                           'repeated_churn_units_beyond_one_per_content': ledger_churn - 25,
                           'retained_occurrences': current['summary']['occurrences'],
                           'content_groups': current['summary']['groups']},
        'median_wall_ms': {'repetitions': repeat, 'position_fingerprint_baseline': round(statistics.median(naive_ms), 6),
                           'ledger_including_before_snapshot': round(statistics.median(ledger_ms), 6)},
        'scope': 'Synthetic correctness and duplicate-review counts; timing includes computation, not CLI I/O. No speedup or security-proof claim.',
        'assertions': 'passed',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repeat', type=int, default=5)
    parser.add_argument('--output', help='optional new local measurement JSON (never overwrites)')
    args = parser.parse_args()
    if not 1 <= args.repeat <= 100:
        parser.error('repeat must be between 1 and 100')
    output = json.dumps(measure(args.repeat), indent=2, sort_keys=True) + '\n'
    if args.output:
        with open(args.output, 'x', encoding='utf-8') as stream:
            stream.write(output)
    print(output, end='')


if __name__ == '__main__':
    main()
