"""Pure Markdown presentation of an already validated selected explanation."""

import json
import re

from .core import dumps


def _cell(value):
    # No dynamic string is Markdown syntax, HTML, a link, or a line boundary.
    # Escape ampersands too, so pre-existing entities remain literal evidence.
    rendered = value if isinstance(value, str) else json.dumps(value, sort_keys=True, ensure_ascii=True)
    return ''.join(c if c.isalnum() or c == ' ' else f'&#{ord(c)};' for c in rendered)


def _fields(value):
    return ['| Field | Reported value |', '| --- | --- |'] + [
        f'| {_cell(key)} | {_cell(item)} |' for key, item in sorted(value.items())]


def render_explanation_markdown(explanation):
    """Render an unmodified vulnfuse-explain-1 result from explain_finding.

    Validation and selection are the caller's responsibility, as for the merge
    Markdown renderer. Does no I/O, merging, selection or remediation evaluation.
    Every dynamic table value is escaped. The complete unredacted selected
    object is serialized in a fence longer than any backtick run in its JSON.
    """
    finding = explanation['finding']
    lines = ['# vulnwrench fuse selected explanation', '',
             'Reported evidence only. Alias assertions are not independently verified; '
             'reported fix candidates are not remediation advice.', '',
             '## Explanation contract', '']
    lines += _fields({k: v for k, v in explanation.items()
                      if k not in ('finding', 'aliasLinks', 'evidence', 'inputs', 'coverageManifest', 'coverageAssessment')})
    lines += ['', '## Selected finding', '']
    lines += _fields({k: v for k, v in finding.items() if k not in ('observations', 'absenceAssessments')})
    lines += ['', '## Coverage and absence assessments', '']
    lines += _fields({'coverageAssessment': explanation['coverageAssessment'],
                      'absenceAssessments': finding['absenceAssessments']})
    lines += ['', '## Direct alias assertions', '',
              'Each row is a reported direct assertion. Transitive component membership '
              'does not create additional direct links.', '']
    links = explanation['aliasLinks']
    if links:
        columns = ('from', 'to', 'basis', 'sourceId', 'observationId', 'primaryIdPointer', 'pointer')
        lines += ['| ' + ' | '.join(columns) + ' |', '| ' + ' | '.join('---' for _ in columns) + ' |']
        lines += ['| ' + ' | '.join(_cell(edge[key]) for key in columns) + ' |' for edge in links]
    else:
        lines += ['None reported.']
    for contributes, title in ((True, 'Contributing observations'), (False, 'Noncontributing alias witnesses')):
        lines += ['', '## ' + title, '']
        evidence = [e for e in explanation['evidence'] if e['contributesToFinding'] is contributes]
        if not evidence:
            lines += ['None reported.']
        for entry in evidence:
            # Raw observation extensions remain complete in the fenced appendix.
            # All interpreted observations and original package/path fields appear
            # here, including fix/severity evidence from noncontributing witnesses.
            lines += _fields({k: v for k, v in entry.items() if k != 'rawObservation'}) + ['']
    lines += ['', '## Input provenance', '',
              'Recorded paths are evidence only. Saved file-byte provenance is asserted; '
              'canonical-json-bytes provenance is recomputed during saved validation.', '']
    for source in explanation['inputs']:
        lines += _fields(source) + ['']
    lines += ['', '## Coverage manifest provenance', '']
    manifest = explanation['coverageManifest']
    lines += _fields({k: v for k, v in manifest.items() if k != 'rawManifest'}) if manifest is not None else ['None supplied.']
    payload = dumps(explanation)
    fence = '`' * max(3, 1 + max((len(m[0]) for m in re.finditer(r'`+', payload)), default=0))
    lines += ['', '## Complete explanation JSON', '', fence + 'json', payload.rstrip('\n'), fence]
    return '\n'.join(lines) + '\n'
