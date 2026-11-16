#!/usr/bin/env python3
"""Execute documented CLI examples offline and check the committed real outputs."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
# Run against this repository's sources even when vulnwrench is not installed.
ENV = {**os.environ, 'PYTHONPATH': os.pathsep.join(filter(None, [str(ROOT / 'src'), os.environ.get('PYTHONPATH')]))}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(*args, expected=0):
    process = subprocess.run([sys.executable, '-m', 'vulnwrench', 'path', *args],
                             cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=60)
    require(process.returncode == expected, 'CLI exit code differed from expectation')
    return process


def main():
    with tempfile.TemporaryDirectory(prefix='.verify-examples-', dir=ROOT) as directory:
        # Temporary outputs live in this worktree, not in a production destination.
        out = str(Path(directory) / 'out.json')
        run('explain', 'examples/path/bom.json', '--grype', 'examples/path/grype.json', '--output', out)
        actual = Path(out).read_bytes()
        require(actual == (ROOT / 'examples/path/out.json').read_bytes(), 'committed JSON example is stale')
        report = json.loads(actual)
        require(report['results'][0]['affectedRoots'] == [{'root': 'app', 'path': ['app', 'a', 'b']}],
                'simple shortest witness differs')
        require(report['provenance']['inferredEdges'] == 0, 'unexpected inferred edges')
        require(report['evidence']['grype'] == json.loads((ROOT / 'examples/path/grype.json').read_text()),
                'finding evidence was lost')

        spdx_bytes = run('explain', 'examples/path/bom.spdx.json', '--grype', 'examples/path/grype.json').stdout.encode()
        require(spdx_bytes == (ROOT / 'examples/path/out.spdx.json').read_bytes(), 'committed SPDX example is stale')
        spdx_report = json.loads(spdx_bytes)
        require(spdx_report['results'][0]['affectedRoots'] == [
            {'root': 'SPDXRef-app', 'path': ['SPDXRef-app', 'SPDXRef-a', 'SPDXRef-b']}],
            'SPDX shortest witness differs')
        require(spdx_report['graph']['edgeCount'] == 2, 'SPDX containment was inferred as dependency')
        require(any(w['code'] == 'spdx_relationship_not_projected' for w in spdx_report['warnings']),
                'SPDX unsupported relationship diagnostic was lost')

        for name, status, count in (('markers.spdx.json', 'reachable', 1),
                                    ('markers-no-roots.spdx.json', 'roots_unknown', None)):
            markers = json.loads(run('explain', 'examples/path/' + name, '--grype', 'examples/path/grype.json').stdout)
            require(markers['graph']['edgeCount'] == 2 and markers['provenance']['inferredEdges'] == 0,
                    'SPDX markers changed declared dependency edges')
            require((markers['results'][0]['status'], markers['results'][0]['affectedRootCount']) == (status, count),
                    'SPDX markers changed reachability or inferred a root')
            require([w['to'] for w in markers['warnings'] if w['code'].startswith('spdx_dependency_')] ==
                    ['NONE', 'NOASSERTION'], 'SPDX marker diagnostics were lost')
            require(not markers['graph']['missingDependencyDeclarations'], 'SPDX marker declaration was lost')

        for name, status, count in (('contains-markers.spdx.json', 'reachable', 1),
                                    ('contains-markers-no-roots.spdx.json', 'roots_unknown', None)):
            containment = json.loads(run('explain', 'examples/path/' + name, '--grype', 'examples/path/grype.json').stdout)
            require(containment['graph']['edgeCount'] == 2 and containment['provenance']['inferredEdges'] == 0,
                    'SPDX containment markers changed dependency edges')
            result = containment['results'][0]
            require((result['status'], result['affectedRootCount']) == (status, count),
                    'SPDX containment markers changed reachability or inferred a root')
            expected_roots = [{'root': 'SPDXRef-app',
                'path': ['SPDXRef-app', 'SPDXRef-a', 'SPDXRef-b']}] if count else []
            require(result['affectedRoots'] == expected_roots, 'SPDX containment markers changed witnesses')
            require(containment['graph']['missingDependencyDeclarations'] == ['SPDXRef-b'],
                    'SPDX containment marker became a dependency declaration')
            require([(w['relationshipIndex'], w['to']) for w in containment['warnings']
                     if w['code'] == 'spdx_relationship_not_projected'] == [(0, 'NONE'), (3, 'NOASSERTION')],
                    'SPDX containment marker indexes or meanings were lost')
            require(containment['evidence']['bom'] == json.loads((ROOT / 'examples' / 'path' / name).read_text()),
                    'SPDX containment evidence was lost')

        args = ['explain', 'examples/path/graph.json', '--grype', 'examples/path/graph-grype.json',
                '--mapping', 'examples/path/mapping.json', '--root', 'app', '--root', 'worker']
        md = run(*args, '--format', 'markdown').stdout
        require(md == (ROOT / 'examples/path/graph.md').read_text(), 'committed Markdown example is stale')
        graph_report = json.loads(run(*args).stdout)
        results = {result['artifactId']: result for result in graph_report['results']}
        require(results['v1']['affectedRootCount'] == 2, 'two-root reachability differs')
        require(results['orphan-id']['status'] == 'unreachable', 'orphan was not classified')
        require(results['absent']['status'] == 'unmapped', 'unmapped PURL disappeared')
        require(results['unknown-artifact']['status'] == 'unknown_identity', 'unknown identity disappeared')
        require(results['local-artifact']['join']['method'] == 'explicit-artifact-id', 'mapping not applied')
        require(graph_report['graph']['cycles']['detected'], 'cycle not detected')
        require(len(graph_report['graph']['danglingDependencies']) == 3, 'dangling evidence lost')
        require(run(*args).stdout == run(*args).stdout, 'output is nondeterministic')

        capped = json.loads(run(*args, '--max-roots', '1', '--max-paths', '1').stdout)
        require(capped['summary']['witnessPaths'] == 1 and capped['summary']['rootsOmitted'] == 1,
                'caps are not enforced')
        require(capped['summary']['pathsOmitted'] == 2, 'path omission not reported')
        require(capped['results'][0]['affectedRootCount'] == 2, 'cap corrupted affected-root count')

        dot = run(*args, '--format', 'dot', '--finding-index', '0').stdout
        require(dot == (ROOT / 'examples/path/graph.dot').read_text(), 'committed DOT example is stale')
        require('nodes_total="4"' in dot and 'edges_total="3"' in dot and 'truncated="false"' in dot,
                'DOT witness union differs')
        require('alternate paths not enumerated' in dot, 'DOT scope missing')
        clipped_dot = run(*args, '--format', 'dot', '--finding-index', '0',
                          '--max-nodes', '2', '--max-edges', '1').stdout
        require('nodes_omitted="2"' in clipped_dot and 'edges_omitted="3"' in clipped_dot and
                'truncated="true"' in clipped_dot, 'DOT caps are not explicit')
        later_dot = run(*args, '--format', 'dot', '--finding-index', '1', '--max-paths', '1').stdout
        require('edges_total="1"' in later_dot and 'report_paths_omitted="0"' in later_dot and
                'truncated="false"' in later_dot, 'unselected findings consumed DOT path budget')
        selected = json.loads(run(*args, '--format', 'json', '--finding-index', '1', '--max-paths', '1').stdout)
        result, = selected['results']
        require((result['findingIndex'], result['vulnerableRef'], result['affectedRootCount']) == (1, 'lib-v2', 1),
                'JSON selection changed original finding index or full affected count')
        require(result['affectedRoots'] == [{'root': 'worker', 'path': ['worker', 'lib-v2']}],
                'unselected findings consumed JSON path budget')
        require(selected['provenance']['selectedFindingIndexes'] == [1] and
                selected['summary']['activeFindings'] == 6 and selected['summary']['results'] == 1,
                'JSON selected scope or total finding count differs')
        require(selected['evidence'] == graph_report['evidence'] and
                selected['provenance']['inputDigests'] == graph_report['provenance']['inputDigests'],
                'JSON selection lost original input evidence or digests')
        selected_md = run(*args, '--format', 'markdown', '--finding-index', '1', '--max-paths', '1').stdout
        require('finding 1: reachable' in selected_md and 'worker → lib-v2' in selected_md and
                'finding 0:' not in selected_md and 'Witness paths: 1; roots omitted: 0; paths omitted: 0.' in selected_md,
                'Markdown selected result or witness differs')
        require('Selected original finding indexes (Grype matches, zero-based): 1. '
                'Total active input findings: 6; selected results: 1.' in selected_md,
                'Markdown explicit selection scope is missing')
        run(*args, '--root', 'not-present', expected=2)
        run('explain', 'examples/path/grype.json', '--grype', 'examples/path/grype.json', expected=2)
    print('PASS: 15 example scenarios (simple JSON, SPDX JSON, SPDX markers with/without roots, SPDX containment markers with/without roots, graph Markdown/JSON, determinism, caps, DOT, DOT caps, DOT selection before path caps, selected JSON, selected Markdown, rejection).')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        sys.exit(1)
