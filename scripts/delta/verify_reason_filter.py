#!/usr/bin/env python3
"""Source/installed CLI contracts for whole-entry unknown reason selection."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads((ROOT / 'examples/delta/explain/reason-filter-cases.json').read_text())
FLAGS = ('--before', '--after', '--before-bom', '--after-bom', '--metadata')


def paths_for():
    return [ROOT / 'examples' / 'delta' / p for p in CONTRACT['inputs']]


def check_selection(selected, default, batch, case):
    explanation = selected['explanation']
    assert {k: v for k, v in selected.items() if k != 'explanation'} == batch
    assert explanation['findings'] == []
    assert explanation['unknown_filter'] == {k: case[k] for k in ('side', 'artifact_id', 'reason_code')}
    entries = explanation['unknown_findings']
    expected = [e for e in default['explanation']['unknown_findings']
                if e['side'] == case['side'] and e['unknown_index'] in case['unknown_indexes']]
    assert entries == expected  # Every reason, pointer, index and duplicate survives.
    assert [e['unknown_index'] for e in entries] == case['unknown_indexes']
    assert [e['source'] for e in entries] == [f"/{case['side']}_report/matches/{i}" for i in case['native_indexes']]
    for entry in entries:
        assert set(entry) == {'side', 'unknown_index', 'advisory', 'source', 'reasons'}
        native = batch['unknown_findings'][entry['side']][entry['unknown_index']]
        assert [r['code'] for r in entry['reasons']] == native['reasons']
        assert case['reason_code'] in native['reasons']
        assert entry['reasons'][0]['code'] == 'artifact_id_conflict'
        assert entry['reasons'][0]['sources'] == [entry['source'], entry['source'] + '/artifact/id'] + [
            f"/{case['side']}_report/matches/{i}/artifact" for i in (1, 3, 4, 6, 7, 8)]
        for reason in entry['reasons']:
            for pointer in reason['sources']:
                value = {k: v['document'] for k, v in batch['evidence'].items()}
                for token in pointer.lstrip('/').split('/'):
                    token = token.replace('~1', '/').replace('~0', '~')
                    value = value[int(token)] if isinstance(value, list) else value[token]


def verify(command=None, cwd=ROOT):
    command = command or [sys.executable, '-m', 'vulnwrench', 'delta']
    records = []
    logdir = os.environ.get('SCAN_DELTA_REASON_LOG_DIR')

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
        return result.stdout

    paths = paths_for()
    batch = json.loads(run(paths, mode='compare'))
    default = json.loads(run(paths, '--advisory', CONTRACT['advisory']))
    assert len(default['explanation']['findings']) == CONTRACT['default']['normalized']
    assert len(default['explanation']['unknown_findings']) == CONTRACT['default']['selected_unknown']
    assert not batch['comparable'] and 'report_identity_unknown' in batch['comparability_reasons']
    assert not any(r['fixed'] or r['classification'] == 'package_removed' for r in batch['transitions'])
    for side in ('before', 'after'):
        assert batch['accounting'][side + '_findings'] == batch['accounting'][side + '_records_accounted'] == 9
    with tempfile.TemporaryDirectory(prefix='vulnwrench-delta-reason-') as folder:
        output = Path(folder) / 'existing.txt'
        for case in CONTRACT['positive']:
            flags = ['--advisory', CONTRACT['advisory'], '--side', case['side'], '--artifact-id', case['artifact_id'],
                     '--reason-code', case['reason_code']]
            selected = json.loads(run(paths, *flags))
            check_selection(selected, default, batch, case)
            for fmt in ('json', 'markdown'):
                run(paths, *flags, '--format', fmt, '--output', str(output))
                content = output.read_text()
                if fmt == 'json':
                    assert json.loads(content) == selected
                else:
                    tables, appendix = content.split('## Full evidence and accounting', 1)
                    assert 'Unknown reason filter: ' + case['reason_code'] in tables
                    for entry in selected['explanation']['unknown_findings']:
                        assert all(r['code'] in tables and all(p in tables for p in r['sources']) for r in entry['reasons'])
                    assert json.loads(appendix.split('```json\n', 1)[1].rsplit('```', 1)[0]) == selected
        for case in CONTRACT['negative']:
            flags = []
            for key, flag in (('advisory', '--advisory'), ('side', '--side'),
                              ('artifact_id', '--artifact-id'), ('reason_code', '--reason-code')):
                value = case.get(key, CONTRACT['advisory'] if key == 'advisory' else None)
                if value is not None:
                    flags.extend([flag, value])
            for fmt in ('json', 'markdown'):
                output.write_text('previous output')
                run(paths, *flags, '--format', fmt, '--output', str(output), expected=2)
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
            for fmt in ('json', 'markdown'):
                output.write_text('previous output')
                run(changed_paths, '--advisory', CONTRACT['advisory'], '--side', 'after', '--artifact-id', 'native/~shared ID',
                    '--reason-code', 'ambiguous_package_location', '--format', fmt, '--output', str(output), expected=2)
                assert output.read_text() == 'previous output'
                assert not list(Path(folder).glob('.vulnwrench-delta-*'))
    print('verified 10 exact reason selections on both sides, whole-entry/context/batch parity, JSON/Markdown and safe output-preserving failures')


if __name__ == '__main__':
    verify()
