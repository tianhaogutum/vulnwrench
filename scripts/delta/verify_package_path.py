#!/usr/bin/env python3
"""Exact normalized target/package-path contracts, also for installed consoles."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
CONTRACT = json.loads((ROOT / 'examples/delta/explain/package-path-cases.json').read_text())
FLAGS = ('--before', '--after', '--before-bom', '--after-bom', '--metadata')


def documents(case):
    return [json.loads((ROOT / 'examples' / 'delta' / p).read_text()) for p in case['inputs']]


def check_selection(selected, default, batch, request):
    from verify_target import resolve
    assert {k: v for k, v in selected.items() if k != 'explanation'} == batch
    explanation = selected['explanation']
    assert set(explanation) == {'schema_version', 'requested_advisory', 'normalized_filter', 'findings'}
    assert explanation['normalized_filter'] == {k: request[k] for k in ('target', 'package_path')}
    expected = [e for e in default['explanation']['findings']
                if batch['transitions'][e['transition_index']]['package']['target'] == request['target']
                and batch['transitions'][e['transition_index']]['package']['path'] == request['package_path']]
    assert explanation['findings'] == expected  # Whole decisions, reasons, prerequisites and sources, in order.
    assert [e['transition_index'] for e in expected] == request['indexes']
    assert explanation['requested_advisory'] == request['advisory']
    if request['indexes'] == [1, 2]:
        assert [batch['transitions'][i]['package']['qualifiers'] for i in request['indexes']] == [{}, {'arch': 'test'}]
    sources = {k: v['document'] for k, v in batch['evidence'].items()}
    for entry in expected:
        for item in [entry['decision']] + entry['reasons'] + entry['fix_prerequisites']:
            for pointer in item['sources']:
                resolve(sources, pointer)
    for side in ('before', 'after'):
        assert batch['accounting'][side + '_findings'] == batch['accounting'][side + '_records_accounted']
    if any(batch.get('unknown_findings', {}).values()):
        assert not batch['comparable']
        assert not any(row['fixed'] or row['classification'] == 'package_removed' for row in batch['transitions'])
        assert all('report_identity_unknown' in row['reasons'] for row in batch['transitions'])


def verify(command=None, cwd=ROOT):
    command = command or [sys.executable, '-m', 'vulnwrench', 'delta']
    records = []
    with tempfile.TemporaryDirectory(prefix='vulnwrench-delta-package-path-') as temporary:
        folder = Path(os.environ.get('SCAN_DELTA_PATH_LOG_DIR', temporary))
        folder.mkdir(parents=True, exist_ok=True)

        def run(paths, extra=(), expected=0, mode='explain'):
            args = [*command, mode]
            for flag, path in zip(FLAGS, paths):
                args.extend([flag, str(path)])
            args.extend(extra)
            p = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=60)
            prefix = folder / f'command-{len(records) + 1:03}'
            prefix.with_suffix('.stdout').write_text(p.stdout)
            prefix.with_suffix('.stderr').write_text(p.stderr)
            record = dict(argv=args, command=shlex.join(args), cwd=str(cwd), exitCode=p.returncode,
                          expectedExitCode=expected, testedTree=os.environ.get('SCAN_DELTA_TESTED_TREE'),
                          stdout=str(prefix.with_suffix('.stdout')), stderr=str(prefix.with_suffix('.stderr')))
            if '--output' in args:
                snapshot = prefix.with_suffix('.output')
                snapshot.write_bytes(Path(args[args.index('--output') + 1]).read_bytes())
                record['outputSnapshot'] = str(snapshot)
            records.append(record)
            (folder / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
            assert p.returncode == expected, (args, p.returncode, p.stderr)
            if expected:
                assert not p.stdout and 'SYNTHETIC_SECRET' not in p.stderr and 'Traceback' not in p.stderr
            else:
                assert not p.stderr
            return p.stdout

        for case in CONTRACT['cases']:
            paths = [ROOT / 'examples' / 'delta' / p for p in case['inputs']]
            batch = json.loads(run(paths, mode='compare'))
            for request in CONTRACT['positive']:
                default = json.loads(run(paths, ['--advisory', request['advisory']]))
                extra = ['--advisory', request['advisory'], '--target', request['target'],
                         '--package-path', request['package_path']]
                selected = json.loads(run(paths, extra))
                check_selection(selected, default, batch, request)
                from vulnwrench.scandelta.cli import markdown
                text = run(paths, [*extra, '--format', 'markdown'])
                assert text == markdown(selected)
                caption = 'Normalized package path filter: ' + ('""' if request['package_path'] == '' else ' node_modules/~demo&#124;copy ' if request['package_path'] == CONTRACT['package_path'] else 'two')
                assert caption in text and '## Selected unknown evidence' not in text
                output = folder / f'{case["name"]}-success.out'
                output.write_text('SENTINEL\n')
                assert not run(paths, [*extra, '--format', 'markdown', '--output', str(output)])
                assert output.read_text() == text
            base = ['--advisory', CONTRACT['advisory'], '--target', CONTRACT['target']]
            failures = [base + ['--package-path', p] for p in (
                '', ' ', 'bad\nSYNTHETIC_SECRET', CONTRACT['package_path'].strip(),
                './' + CONTRACT['package_path'], CONTRACT['package_path'].upper(),
                CONTRACT['package_path'] + '/child', 'node_modules', '/workspace/2/package.json',
                'pkg:npm/demo@1.0', 'SYNTHETIC_SECRET_ABSENT')]
            failures += [ ['--package-path', CONTRACT['package_path']],
                          ['--advisory', CONTRACT['advisory'], '--package-path', CONTRACT['package_path']],
                          ['--target', CONTRACT['target'], '--package-path', CONTRACT['package_path']],
                          ['--advisory', 'UNKNOWN-ONLY', '--target', CONTRACT['target'], '--package-path', CONTRACT['package_path']],
                          ['--advisory', 'OTHER', '--target', CONTRACT['target'], '--package-path', ''],
                          ['--advisory', CONTRACT['advisory'], '--target', 'zeta.lock', '--package-path', 'two']]
            for native in (['--side', 'after'], ['--artifact-id', 'unknown-0'],
                           ['--reason-code', 'ambiguous_package_location'], ['--match-index', '0'],
                           ['--reason-code-all', 'ambiguous_package_location'],
                           ['--reason-code-any', 'ambiguous_package_location'],
                           ['--side', 'after', '--artifact-id', 'unknown-0']):
                failures.append([*base, '--package-path', CONTRACT['package_path'], *native])
            for n, extra in enumerate(failures):
                run(paths, extra, expected=2)
                for fmt in ('json', 'markdown'):
                    output = folder / f'{case["name"]}-failure-{n}-{fmt}.out'
                    output.write_text('SENTINEL\n')
                    run(paths, [*extra, '--format', fmt, '--output', str(output)], expected=2)
                    assert output.read_text() == 'SENTINEL\n'
            # Fully validate all five documents, including records outside the selected target/path.
            for index in range(5):
                docs = documents(case)
                if index < 2:
                    if 'matches' in docs[index]:
                        del docs[index]['matches'][0]['artifact']['id']
                    else:
                        del docs[index]['Results'][0]['Vulnerabilities'][0]['VulnerabilityID']
                elif index < 4:
                    docs[index]['components'][0]['purl'] = 'SYNTHETIC_SECRET'
                else:
                    docs[index]['after']['report_complete'] = 'SYNTHETIC_SECRET'
                changed = list(paths)
                path = folder / f'{case["name"]}-invalid-{index}.json'
                path.write_text(json.dumps(docs[index]))
                changed[index] = path
                output = folder / f'{case["name"]}-invalid-{index}.out'
                output.write_text('SENTINEL\n')
                run(changed, [*base, '--package-path', CONTRACT['package_path'], '--output', str(output)], expected=2)
                assert output.read_text() == 'SENTINEL\n'
            if 'matches' in documents(case)[1]:
                docs = documents(case)
                del docs[1]['matches'][-2]['artifact']['id']  # Unselected unknown native record.
                changed = list(paths)
                path = folder / f'{case["name"]}-invalid-unknown.json'
                path.write_text(json.dumps(docs[1])); changed[1] = path
                run(changed, [*base, '--package-path', CONTRACT['package_path']], expected=2)
        print(f'Exact package-path contracts passed: {len(records)} CLI commands; JSON/Markdown, empty path, aliases, qualifiers, whole entries, full batch/blockers and safe output-preserving failures.')


if __name__ == '__main__':
    verify()
