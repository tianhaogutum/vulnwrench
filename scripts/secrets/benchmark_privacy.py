#!/usr/bin/env python3
"""Measure snapshot/rename comparison on deterministic PUBLIC synthetic inputs.

Timing runs do not enable tracemalloc; one separate run records Python allocation
peak (not process RSS). Fixture/prior-ledger construction and JSON I/O are excluded.
Use --core to measure an archived core.py with the exact same fixtures and runner.
"""
import argparse
import cProfile
import gc
import hashlib
import importlib.util
import json
import platform
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]  # run from a clone, installed or not
from vulnwrench.secretledger import core

KEY = b'0123456789abcdef0123456789abcdef'  # PUBLIC TEST ONLY


def synthetic_report(size, prefix='src'):
    rows = []
    for i in range(size):
        path = f'{prefix}/file-{i:08d}.py'
        secret = f'SYNTHETIC_CONTENT_{i:08d}_END'
        row = {'RuleID': 'generic-api-key', 'File': path, 'StartLine': 4,
               'Commit': '', 'Fingerprint': f'{path}:generic-api-key:4',
               'Secret': None if i % 13 == 0 else '[masked]' if i % 17 == 0 else secret,
               'Match': 'SYNTHETIC_MATCH_' + secret}
        rows.append(row)
        if i % 29 == 0:
            rows.append(dict(row))  # exact duplicates must survive
    return rows


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                      separators=(',', ':')).encode()).hexdigest()


def measure(operation, repeats):
    operation()  # untimed warmup
    times = []
    for _ in range(repeats):
        gc.collect()
        start = time.perf_counter()
        result = operation()
        times.append(time.perf_counter() - start)
        del result
    gc.collect()
    tracemalloc.start()
    result = operation()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {'seconds': times, 'median_seconds': statistics.median(times),
            'peak_python_bytes': peak, 'output_sha256': digest(result)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path, help='archived core.py to measure instead')
    parser.add_argument('--sizes', nargs='+', type=int, default=[1000, 4000])
    parser.add_argument('--repeats', type=int, default=3)
    args = parser.parse_args()
    if args.repeats < 1 or any(n < 1 for n in args.sizes):
        parser.error('sizes and repeats must be positive')
    implementation = core
    if args.core:
        spec = importlib.util.spec_from_file_location('measured_core', args.core)
        implementation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(implementation)
    results = []
    for size in args.sizes:
        prior_report, report = synthetic_report(size), synthetic_report(size, 'lib')
        mapping = [{'old_path': f'src/file-{i:08d}.py', 'new_path': f'lib/file-{i:08d}.py'}
                   for i in range(size)]
        before = implementation.snapshot(prior_report, KEY)
        snap = lambda: implementation.snapshot(report, KEY)
        cmp = lambda: implementation.compare(before, report, KEY, path_map=mapping)
        snapshot_result = snap()
        comparison, current = cmp()
        assert current == snapshot_result
        assert current['summary']['occurrences'] == len(report)
        unknown = current['summary']['uncomparable_occurrences']
        groups_unknown = sum(g['content_hmac'] is None for g in current['groups'])
        assert unknown > 0 and comparison['summary']['uncomparable'] == 2 * groups_unknown
        assert comparison['summary']['same_secret_moved'] == size - groups_unknown
        assert comparison['summary']['absent'] == comparison['summary']['new_content'] == 0
        results.append({'size': size, 'occurrences': len(report),
                        'input_sha256': digest([prior_report, report, mapping]),
                        'snapshot': measure(snap, args.repeats),
                        'compare_mapped': measure(cmp, args.repeats)})
    profile = cProfile.Profile()
    profile.runcall(cmp)
    profile_rows = []
    for entry in profile.getstats():
        if hasattr(entry.code, 'co_name'):
            profile_rows.append({'function': entry.code.co_name, 'calls': entry.callcount,
                                 'self_seconds': entry.inlinetime, 'cumulative_seconds': entry.totaltime})
    print(json.dumps({'python': sys.version, 'platform': platform.platform(),
                      'core_sha256': hashlib.sha256(Path(implementation.__file__).read_bytes()).hexdigest(),
                      'method': 'warmup + repeated untraced wall times; separate tracemalloc peak; '
                                'fixture/prior construction and I/O excluded; no production credentials',
                      'results': results,
                      'largest_compare_profile': sorted(profile_rows, key=lambda r: r['cumulative_seconds'],
                                                        reverse=True)[:15]}, indent=2))


if __name__ == '__main__':
    main()
