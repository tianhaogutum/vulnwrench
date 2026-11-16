#!/usr/bin/env python3
"""Source/installed CLI contracts for exact unknown Grype artifact selection."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads((ROOT / 'examples/delta/explain/artifact-filter-cases.json').read_text())
FLAGS = ('--before', '--after', '--before-bom', '--after-bom', '--metadata')


def paths_for():
    return [ROOT / 'examples' / 'delta' / p for p in CONTRACT['inputs']]


def verify(command=None, cwd=ROOT):
    command = command or [sys.executable, '-m', 'vulnwrench', 'delta']
    logdir = os.environ.get('SCAN_DELTA_FILTER_LOG_DIR')
    records = []

    def run(paths, *extra, expected=0, mode='explain'):
        args = [*command, mode]
        for flag, path in zip(FLAGS, paths):
            args.extend([flag, str(path)])
        args.extend(extra)
        result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=60)
        if logdir:
            folder = Path(logdir)
            folder.mkdir(parents=True, exist_ok=True)
            prefix = folder / f'command-{len(records) + 1:03}'
            prefix.with_suffix('.stdout').write_text(result.stdout)
            prefix.with_suffix('.stderr').write_text(result.stderr)
            records.append(dict(argv=args, command=shlex.join(args), cwd=str(cwd), exitCode=result.returncode,
                                expectedExitCode=expected, stdout=str(prefix.with_suffix('.stdout')),
                                stderr=str(prefix.with_suffix('.stderr')),
                                testedTree=os.environ.get('SCAN_DELTA_TESTED_TREE')))
            (folder / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
        assert result.returncode == expected, (args, result.returncode, result.stderr)
        if expected == 0:
            assert not result.stderr
        else:
            assert not result.stdout and 'SYNTHETIC_SECRET' not in result.stderr and 'Traceback' not in result.stderr
        return result

    paths = paths_for()
    batch = json.loads(run(paths, mode='compare').stdout)
    default = json.loads(run(paths, '--advisory', CONTRACT['advisory']).stdout)
    assert default == dict(batch, explanation=default['explanation'])
    assert len(default['explanation']['findings']) == CONTRACT['default']['normalized']
    assert len(default['explanation']['unknown_findings']) == CONTRACT['default']['selected_unknown']
    assert not batch['comparable'] and 'report_identity_unknown' in batch['comparability_reasons']
    assert not any(r['fixed'] or r['classification'] == 'package_removed' for r in batch['transitions'])
    for side in ('before', 'after'):
        assert batch['accounting'][side + '_findings'] == batch['accounting'][side + '_records_accounted'] == 6
    with tempfile.TemporaryDirectory(prefix='vulnwrench-delta-filter-') as folder:
        output = Path(folder) / 'existing.txt'
        for case in CONTRACT['positive']:
            flags = ['--advisory', CONTRACT['advisory'], '--side', case['side'], '--artifact-id', case['artifact_id']]
            selected = json.loads(run(paths, *flags).stdout)
            explanation = selected.pop('explanation')
            assert selected == batch
            assert explanation['findings'] == []
            assert explanation['unknown_filter'] == {k: case[k] for k in ('side', 'artifact_id')}
            expected = [e for e in default['explanation']['unknown_findings']
                        if e['side'] == case['side'] and e['unknown_index'] in case['unknown_indexes']]
            assert explanation['unknown_findings'] == expected
            for entry in expected:
                for reason in entry['reasons']:
                    for pointer in reason['sources']:
                        value = {k: v['document'] for k, v in batch['evidence'].items()}
                        for token in pointer.lstrip('/').split('/'):
                            token = token.replace('~1', '/').replace('~0', '~')
                            value = value[int(token)] if isinstance(value, list) else value[token]
            for format in ('json', 'markdown'):
                run(paths, *flags, '--format', format, '--output', str(output))
                content = output.read_text()
                if format == 'json':
                    assert json.loads(content) == dict(batch, explanation=explanation)
                else:
                    tables, appendix = content.split('## Full evidence and accounting', 1)
                    assert '## Selected unknown evidence' in tables
                    assert 'Unknown artifact filter: ' + case['side'] + ' / ' + case['artifact_id'] in tables
                    for entry in expected:
                        assert entry['source'] in tables
                        assert all(p in tables for r in entry['reasons'] for p in r['sources'])
                    assert json.loads(appendix.split('```json\n', 1)[1].rsplit('```', 1)[0]) == dict(batch, explanation=explanation)
        negatives = list(CONTRACT['negative']) + [dict(side='after', artifact_id='bad\nID')]
        for case in negatives:
            flags = ['--advisory', case.get('advisory', CONTRACT['advisory'])]
            for key, flag in (('side', '--side'), ('artifact_id', '--artifact-id')):
                if case[key] is not None:
                    flags.extend([flag, case[key]])
            for format in ('json', 'markdown'):
                output.write_text('previous output')
                run(paths, *flags, '--format', format, '--output', str(output), expected=2)
                assert output.read_text() == 'previous output'
                assert not list(Path(folder).glob('.vulnwrench-delta-*'))
        for change in ('version', 'unselected-id', 'unselected-advisory', 'other-side', 'trivy'):
            changed_paths = list(paths)
            if change == 'trivy':
                changed_paths = [ROOT / 'examples/delta/grype' / p for p in
                                 ('trivy-before.json', 'trivy-after.json', 'before-bom.json', 'after-bom.json', 'trivy-scans.json')]
            else:
                side_index = 0 if change == 'other-side' else 1
                doc = json.loads(paths[side_index].read_text())
                if change == 'version':
                    doc['descriptor']['version'] = 'SYNTHETIC_SECRET_VERSION'
                elif change == 'unselected-id':
                    del doc['matches'][1]['artifact']['id']
                elif change == 'unselected-advisory':
                    del doc['matches'][1]['vulnerability']
                else:
                    doc['matches'][0]['artifact']['locations'] = None
                invalid = Path(folder) / 'invalid.json'
                invalid.write_text(json.dumps(doc))
                changed_paths[side_index] = invalid
            for format in ('json', 'markdown'):
                output.write_text('previous output')
                run(changed_paths, '--advisory', CONTRACT['advisory'], '--side', 'after',
                    '--artifact-id', 'native/~shared ID', '--format', format, '--output', str(output), expected=2)
                assert output.read_text() == 'previous output'
                assert not list(Path(folder).glob('.vulnwrench-delta-*'))
    print('verified 6 exact side/artifact selections, complete batch/context parity, JSON/Markdown, atomic output and safe invalid/no-match/unsupported/unselected failures')


if __name__ == '__main__':
    verify()
