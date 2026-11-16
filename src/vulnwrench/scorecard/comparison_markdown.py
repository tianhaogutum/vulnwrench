"""Presentation of an existing comparison; never recompute evidence classifications."""

import html
import json
import re


def render_comparison_markdown(report: dict) -> str:
    """Render coverage and raw changes, followed by the complete lossless report."""
    def cell(value):
        text = str(value) if value is not None else '—'
        # Entities keep supplied punctuation from creating Markdown/HTML syntax.
        # Flatten every Unicode line separator in tables; the appendix is exact.
        return ''.join(' ' if char in '\r\n\t\v\f\x1c\x1d\x1e\x85\u2028\u2029' else f'&#{ord(char)};'
                       if char in '\\`*_{}[]()#+!|~' else html.escape(char) for char in text)

    def row(values):
        return '| ' + ' | '.join(cell(value) for value in values) + ' |'

    def table(headers, rows):
        lines.extend([row(headers), row(['---'] * len(headers))])
        lines.extend(row(values) for values in rows)
        lines.append('')

    def raw(check, field):
        if check is None:
            return None
        if field not in check:
            return 'absent'
        # JSON literals distinguish a supplied null or string from an absent key.
        return json.dumps(check[field], ensure_ascii=False, sort_keys=True, allow_nan=False)

    summary = report['summary']
    lines = ['# Snapshot comparison', '',
             f"Before cutoff: {cell(report['before']['asOf'])}; after cutoff: {cell(report['after']['asOf'])}; "
             f"maximum age: {report['maxAgeDays']} UTC calendar days.", '',
             f"Components: **{summary['components']}**; mapped: **{summary['mappedComponents']}**; "
             f"unmapped or missing PURL: **{summary['unmappedComponents']}**; "
             f"compared repositories: **{summary['comparedRepositories']}**; "
             f"unused mappings: **{len(summary['unusedMappings'])}**.", '',
             'Counts describe supplied evidence coverage, not score quality, a security gate or causal attribution. '
             'Score direction requires fresh, chronologically comparable snapshots and known scores on both sides. '
             'An em dash means unavailable; absent means the raw field was not supplied; null is a supplied JSON null. '
             'Full evidence, including unselected and future snapshots, is in the JSON appendix.', '']
    if 'checkSelection' in report:
        lines.extend(['Check scope: explicitly selected exact names; only observed matches contribute to check rows '
                      'and counts. Repository counts and full snapshots are unchanged.', ''])
        table(['Selected exact name (JSON literal)'],
              ([json.dumps(name, ensure_ascii=True)] for name in report['checkSelection']['names']))
    lines.extend(['## Coverage', ''])
    partitions = [('Comparison status', summary['comparisonStatuses']),
                  ('Snapshot change', summary['snapshotChanges']),
                  *[('Scanner ' + field, summary['scannerChanges'][field]) for field in ('version', 'commit')]]
    table(['Partition', 'Classification', 'Repositories'],
          ([label, key, count] for label, counts in partitions for key, count in sorted(counts.items())))
    lines.extend(['Raw check changes count observed repository/check pairs, including unknown scores; '
                  'they do not measure score quality.', ''])
    table(['Raw check change', 'Repository/check pairs'], sorted(summary['checkChanges'].items()))
    lines.extend(['Score directions count the same observed repository/check pairs; '
                  'not_comparable includes unknown scores, added/deleted checks and evidence blockers.', ''])
    table(['Check score direction', 'Repository/check pairs'], sorted(summary['checkScoreChanges'].items()))
    lines.extend(['Score directions by check group the same pairs by exact observed name; '
                  'unobserved names are omitted. Counts describe supplied numeric direction, '
                  'not score quality, security or causality.', ''])
    table(['Check', 'Score direction', 'Repository/check pairs'],
          ([counts['name'], key, counts[key]] for counts in summary['checkScoreChangesByCheck']
           for key in ('increased', 'decreased', 'unchanged', 'not_comparable')))
    lines.extend(['Check score comparability counts each observed pair once: '
                  'a scoreChange other than not_comparable counts comparable; '
                  'otherwise a repository comparison other than comparable counts evidence_blocked; '
                  'remaining pairs count observation_blocked. '
                  'Evidence blockers take priority over observation gaps; '
                  'counts do not enumerate every simultaneous blocker. '
                  'Comparable describes support for numeric direction, not security or causality.', ''])
    table(['Check score comparability', 'Repository/check pairs'], sorted(summary['checkScoreComparability'].items()))
    lines.extend(['Check score comparability by check groups the same pairs by exact observed name '
                  'and uses the same priority; unobserved names are omitted.', ''])
    table(['Check', 'Comparability', 'Repository/check pairs'],
          ([counts['name'], key, counts[key]] for counts in summary['checkScoreComparabilityByCheck']
           for key in ('comparable', 'evidence_blocked', 'observation_blocked')))
    lines.extend(['Check observations count the same pairs separately on each side; '
                  'missing scores, absent checks and unavailable snapshots remain distinct. '
                  'Freshness and chronology do not relabel observations.', ''])
    table(['Side', 'Observation', 'Repository/check pairs'],
          ([side.title(), key, count] for side in ('before', 'after')
           for key, count in sorted(summary['checkObservations'][side].items())))
    lines.extend(['Check observation transitions count each pair once by its before and after labels; '
                  'known to known does not establish score direction.', ''])
    table(['Before observation', 'After observation', 'Repository/check pairs'],
          ([before, after, count] for before, counts in sorted(summary['checkObservationTransitions'].items())
           for after, count in sorted(counts.items())))
    lines.extend(['## Components', ''])
    table(['Name', 'PURL', 'Repository', 'Mapping status', 'Role', 'JSON Pointer'],
          ([component[key] for key in ('name', 'purl', 'repository', 'mappingStatus', 'role', 'path')]
           for component in report['components']))
    if not report['components']:
        lines.extend(['No components.', ''])
    lines.extend(['## Repositories', ''])
    table(['Repository', 'Comparison status', 'Snapshot change', 'Repository commit change'],
          ([repository[key] for key in ('repository', 'comparison', 'snapshotChange', 'commitChange')]
           for repository in report['repositories']))
    if not report['repositories']:
        lines.extend(['No mapped repositories.', ''])
    for repository in report['repositories']:
        lines.extend(['### ' + cell(repository['repository']), ''])
        table(['Side', 'Evidence status', 'Timestamp', 'Age days', 'Repository commit'],
              ([side.title(), *[repository[side][key] for key in ('status', 'timestamp', 'ageDays', 'commit')]]
               for side in ('before', 'after')))
        scanner = repository['scannerChange']
        table(['Scanner field', 'Before', 'After', 'Change'],
              ([field, (scanner['before'] or {}).get(field), (scanner['after'] or {}).get(field),
                scanner[field + 'Change']] for field in ('version', 'commit')))
        table(['Check', 'Raw change', 'Score direction', 'Before observation', 'After observation',
               'Before score', 'After score', 'Score field changed', 'Before reason', 'After reason',
               'Reason field changed'],
              ([check['name'], check['change'], check['scoreChange'],
                check['beforeObservation'], check['afterObservation'],
                raw(check['before'], 'score'), raw(check['after'], 'score'),
                str(check['scoreChanged']).lower() if check['scoreChanged'] is not None else None,
                raw(check['before'], 'reason'), raw(check['after'], 'reason'),
                str(check['reasonChanged']).lower() if check['reasonChanged'] is not None else None]
               for check in repository['checks']))
        if not repository['checks']:
            lines.extend(['No observed checks.', ''])
    lines.extend(['## Evidence', '',
                  'Complete comparison JSON, including original inputs, raw checks, scanner metadata, '
                  'source digests and all supplied snapshots.', ''])
    appendix = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
    fence = '`' * max(3, 1 + max((len(run) for run in re.findall(r'`+', appendix)), default=0))
    appendix = appendix.replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e')
    lines.extend([fence + 'json', appendix, fence, ''])
    return '\n'.join(lines)
