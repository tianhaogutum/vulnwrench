#!/usr/bin/env python3
"""Exact normalized target contracts for source and offline installed consoles."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
CONTRACT = json.loads((ROOT / 'examples/delta/explain/target-cases.json').read_text())
FLAGS = ('--before', '--after', '--before-bom', '--after-bom', '--metadata')


def documents(case):
    return [json.loads((ROOT / 'examples' / 'delta' / p).read_text()) for p in case['inputs']]


def resolve(documents, pointer):
    value = documents
    for token in pointer.lstrip('/').split('/'):
        token = token.replace('~1', '/').replace('~0', '~')
        value = value[int(token)] if isinstance(value, list) else value[token]
    return value


def check_selection(selected, default, batch, case, target=CONTRACT['target']):
    assert {k: v for k, v in selected.items() if k != 'explanation'} == batch
    explanation = selected['explanation']
    assert set(explanation) == {'schema_version', 'requested_advisory', 'normalized_filter', 'findings'}
    assert explanation['normalized_filter'] == {'target': target}
    expected = [e for e in default['explanation']['findings']
                if batch['transitions'][e['transition_index']]['package']['target'] == target]
    assert explanation['findings'] == expected  # Entire entries, ordered reasons/prerequisites/sources.
    assert [e['transition_index'] for e in expected] == case['expected_indexes']
    assert [batch['transitions'][e['transition_index']]['package']['path'] for e in expected] == ['one', 'two']
    sources = {k: v['document'] for k, v in batch['evidence'].items()}
    for entry in expected:
        for item in [entry['decision']] + entry['reasons'] + entry['fix_prerequisites']:
            for pointer in item['sources']:
                resolve(sources, pointer)
    if case['name'] != 'trivy':
        assert batch['unknown_findings']['after']
        assert not batch['comparable']
        assert not any(row['fixed'] or row['classification'] == 'package_removed' for row in batch['transitions'])
        assert all('report_identity_unknown' in row['reasons'] for row in batch['transitions'])


def verify(command=None, cwd=ROOT):
    command = command or [sys.executable, '-m', 'vulnwrench', 'delta']
    logdir = os.environ.get('SCAN_DELTA_TARGET_LOG_DIR')
    records = []
    with tempfile.TemporaryDirectory(prefix='vulnwrench-delta-target-') as temporary:
        folder = Path(logdir) if logdir else Path(temporary)
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
            for advisory in (CONTRACT['advisory'], CONTRACT['alias']):
                default = json.loads(run(paths, ['--advisory', advisory]))
                extra = ['--advisory', advisory, '--target', CONTRACT['target']]
                selected = json.loads(run(paths, extra))
                check_selection(selected, default, batch, case)
                text = run(paths, [*extra, '--format', 'markdown'])
                from vulnwrench.scandelta.cli import markdown
                assert text == markdown(selected)
                assert 'Normalized target filter:  apps/~web&#124;lock.json ' in text
                assert '## Selected unknown evidence' not in text
            failures = [[], ['--advisory', CONTRACT['advisory'], '--target', ''],
                        ['--advisory', CONTRACT['advisory'], '--target', ' '],
                        ['--advisory', CONTRACT['advisory'], '--target', 'bad\nSYNTHETIC_SECRET'],
                        ['--advisory', CONTRACT['advisory'], '--target', CONTRACT['target'].strip()],
                        ['--advisory', CONTRACT['advisory'], '--target', './' + CONTRACT['target']],
                        ['--advisory', 'UNKNOWN-ONLY', '--target', CONTRACT['target']],
                        ['--advisory', 'OTHER', '--target', CONTRACT['target']],
                        ['--advisory', 'SYNTHETIC_SECRET_ABSENT', '--target', CONTRACT['target']]]
            failures[0] = ['--target', CONTRACT['target']]  # Missing required advisory.
            for native in (['--side', 'after'], ['--artifact-id', 'native-2'],
                           ['--reason-code', 'ambiguous_package_location'], ['--match-index', '0'],
                           ['--reason-code-all', 'ambiguous_package_location'],
                           ['--reason-code-any', 'ambiguous_package_location'],
                           ['--side', 'after', '--artifact-id', 'unknown-0']):
                failures.append(['--advisory', CONTRACT['advisory'], '--target', CONTRACT['target'], *native])
            for n, extra in enumerate(failures):
                run(paths, extra, expected=2)
                output = folder / f'{case["name"]}-failure-{n}.out'
                output.write_text('SENTINEL\n')
                run(paths, [*extra, '--output', str(output)], expected=2)
                assert output.read_text() == 'SENTINEL\n'
            # Valid selector must not skip malformed unselected targets/opposite side or inventory.
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
                extra = ['--advisory', CONTRACT['advisory'], '--target', CONTRACT['target']]
                output = folder / f'{case["name"]}-invalid-{index}.out'
                output.write_text('SENTINEL\n')
                run(changed, [*extra, '--output', str(output)], expected=2)
                assert output.read_text() == 'SENTINEL\n'
        print(f'Exact target contracts passed: {len(records)} CLI commands; JSON/Markdown, aliases, whole-entry parity, full evidence/blockers and safe output-preserving failures.')


if __name__ == '__main__':
    verify()
