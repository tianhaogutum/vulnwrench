"""Read complete saved merges, checking consistency against embedded evidence."""

import hashlib
import re
from collections import Counter

from .core import CoverageManifest, Report, _read_input, dumps, merge_reports
from .coverage import _pair
from .identity import InputError, text


def _provenance(value, document):
    name = value['input']
    if not isinstance(name, str) or not name:
        raise InputError('invalid saved input name')
    digest, size, kind = (value[k] for k in ('sha256', 'byteCount', 'digestKind'))
    if (not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest)
            or type(size) is not int or size <= 0
            or kind not in ('file-bytes', 'canonical-json-bytes')):
        raise InputError('invalid saved provenance')
    # Original file formatting is unavailable. File-byte digests are assertions,
    # whereas canonical JSON provenance can be independently recomputed here.
    if kind == 'canonical-json-bytes':
        raw = dumps(document).encode('utf-8')
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise InputError('inconsistent canonical provenance')
    return name, digest, size, kind


def read_merged(path, *, expected_sha256=None):
    """Validate a <=32 MiB current-profile vulnfuse-1 file before selection.

    Rebuild all derived data using embedded raw reports and the raw manifest;
    require exact typed JSON equality, including source/observation/alias IDs,
    pointers, counts, grouping and assessments. Never open recorded input paths.
    This establishes internal consistency, not authenticity of saved evidence.
    Optional expected_sha256 binds the exact file bytes to a caller expectation
    (64 lowercase hex digits); matching bytes must still pass all validation.
    """
    merged, _ = _read_validated(path, expected_sha256=expected_sha256)
    return merged


def validate_merged(path, *, expected_sha256=None):
    """Summarize internal consistency and exact container bytes, even if empty.

    Shares read_merged's single bounded read, byte expectation and full graph
    validation. This does not establish authenticity or advisory truth.
    """
    merged, report = _read_validated(path, expected_sha256=expected_sha256)
    return {
        'schemaVersion': 'vulnfuse-validation-1',
        'validatedSchemaVersion': merged['schemaVersion'],
        'validation': 'internally-consistent',
        'container': {'sha256': report.sha256, 'byteCount': report.byte_count,
                      'digestKind': 'file-bytes'},
        'inputCount': merged['inputCount'],
        'findingCount': merged['findingCount'],
        'observationCount': merged['observationCount'],
    }


def _recorded_provenance(value):
    return {**{k: value[k] for k in ('sha256', 'byteCount', 'digestKind')},
            'provenanceVerification': ('asserted-original-file-bytes'
                                       if value['digestKind'] == 'file-bytes'
                                       else 'recomputed-canonical-json-bytes')}


def validate_saved_coverage(path, *, expected_sha256=None):
    """Summarize coverage assertions after complete saved-graph validation.

    Read only the saved container, once and boundedly, with optional exact byte
    expectation. Original file-byte provenance remains asserted; canonical JSON
    provenance is recomputed during reconstruction. Counts include repeated
    report occurrences and distinct declarations, including empty/absent
    manifests and zero findings. No raw evidence, labels or paths are returned.
    Internal consistency establishes neither authenticity nor coverage truth;
    compatible declarations and absence cannot establish remediation.
    """
    merged, report = _read_validated(path, expected_sha256=expected_sha256)
    sources, manifest = merged['inputs'], merged['coverageManifest']
    declared = sum(s['coverage']['status'] == 'declared' for s in sources)
    return {
        'schemaVersion': 'vulnfuse-saved-coverage-validation-1',
        'validatedSchemaVersion': merged['schemaVersion'],
        'validation': 'internally-consistent',
        'container': {'sha256': report.sha256, 'byteCount': report.byte_count,
                      'digestKind': 'file-bytes'},
        'coverageManifest': None if manifest is None else _recorded_provenance(manifest),
        'inputCount': merged['inputCount'],
        'declarationCount': 0 if manifest is None else len(manifest['rawManifest']['inputs']),
        'declaredInputCount': declared,
        'undeclaredInputCount': len(sources) - declared,
        'observationCount': merged['observationCount'],
        'findingCount': merged['findingCount'],
        'coverageAssessment': merged['coverageAssessment'],
        'canEstablishFixed': False,
        'inputs': [{**{k: s[k] for k in ('sourceId', 'scanner', 'observationCount')},
                    **_recorded_provenance(s),
                    'coverage': {k: s['coverage'][k] for k in ('status', 'reasonCodes', 'manifestPointer')}}
                   for s in sources],
    }


def validate_saved_finding_coverage(path, *, finding_id, expected_sha256=None):
    """Summarize one exact finding's existing absence comparisons, without evidence.

    Fully validate the saved archive before exact ID selection, using the same
    single bounded read and optional container expectation as read_merged. Counts
    describe selected observations and report occurrences, including repetitions.
    Recorded provenance has the same asserted/canonical trust as aggregate saved
    coverage. No originals are opened; no paths, labels or raw evidence returned.
    Internal consistency and compatible coverage never establish remediation.
    """
    merged, report = _read_validated(path, expected_sha256=expected_sha256)
    text(finding_id)
    finding = next((f for f in merged['findings'] if f['findingId'] == finding_id), None)
    if finding is None:
        raise InputError('coverage: no finding matches the ID')
    counts = Counter(o['sourceId'] for o in finding['observations'])
    manifest = merged['coverageManifest']
    return {
        'schemaVersion': 'vulnfuse-saved-finding-coverage-validation-1',
        'validatedSchemaVersion': merged['schemaVersion'],
        'validation': 'internally-consistent',
        'container': {'sha256': report.sha256, 'byteCount': report.byte_count,
                      'digestKind': 'file-bytes'},
        'coverageManifest': None if manifest is None else _recorded_provenance(manifest),
        'findingId': finding['findingId'],
        'observationCount': finding['observationCount'],
        'inputCount': merged['inputCount'],
        'observedInputCount': len(counts),
        'absentInputCount': len(finding['absenceAssessments']),
        'canEstablishFixed': False,
        'inputs': [{**{k: s[k] for k in ('sourceId', 'scanner')}, **_recorded_provenance(s),
                    'presence': finding['inputPresence'][s['sourceId']],
                    'observationCount': counts[s['sourceId']]}
                   for s in merged['inputs']],
        'absenceAssessments': finding['absenceAssessments'],
    }


def compare_saved_input_coverage(path, *, source_a, source_b, expected_sha256=None):
    """Compare two exact distinct saved source occurrences, even without findings.

    Fully validate the archive from one bounded strict read before either source
    is selected. Return sources in caller order with recorded digest trust and
    the existing symmetric coverage pair assessment. No evidence, labels, paths
    or finding matrices are emitted; recorded originals are never opened.
    Internal consistency and comparable assertions cannot establish remediation.
    """
    merged, report = _read_validated(path, expected_sha256=expected_sha256)
    text(source_a)
    text(source_b)
    sources = {s['sourceId']: s for s in merged['inputs']}
    if source_a == source_b or source_a not in sources or source_b not in sources:
        raise InputError('coverage: expected two distinct saved source IDs')
    selected = [sources[source_a], sources[source_b]]
    manifest = merged['coverageManifest']
    return {
        'schemaVersion': 'vulnfuse-saved-input-coverage-comparison-1',
        'validatedSchemaVersion': merged['schemaVersion'],
        'validation': 'internally-consistent',
        'container': {'sha256': report.sha256, 'byteCount': report.byte_count,
                      'digestKind': 'file-bytes'},
        'coverageManifest': None if manifest is None else _recorded_provenance(manifest),
        'inputs': [{**{k: s[k] for k in ('sourceId', 'scanner')}, **_recorded_provenance(s)}
                   for s in selected],
        'coverageAssessment': _pair(selected[0]['coverage'], selected[1]['coverage']),
        'canEstablishFixed': False,
    }


def list_saved_finding_coverage(path, *, expected_sha256=None):
    """Index exact finding IDs and occurrence counts after full saved validation.

    Uses the same single bounded strict read and optional container expectation
    as saved coverage summaries, including for zero findings. No evidence, paths,
    labels or comparison matrices are returned; original paths are never opened.
    Repeated report occurrences and multiple observations retain their counts.
    Internal consistency and absence cannot establish authenticity or remediation.
    """
    merged, report = _read_validated(path, expected_sha256=expected_sha256)
    return {
        'schemaVersion': 'vulnfuse-saved-finding-coverage-index-1',
        'validatedSchemaVersion': merged['schemaVersion'],
        'validation': 'internally-consistent',
        'container': {'sha256': report.sha256, 'byteCount': report.byte_count,
                      'digestKind': 'file-bytes'},
        'inputCount': merged['inputCount'],
        'findingCount': merged['findingCount'],
        'observationCount': merged['observationCount'],
        'findings': [{'findingId': f['findingId'], 'observationCount': f['observationCount'],
                      'observedInputCount': sum(p == 'observed' for p in f['inputPresence'].values()),
                      'absentInputCount': len(f['absenceAssessments'])}
                     for f in merged['findings']],
        'canEstablishFixed': False,
    }


def _read_validated(path, *, expected_sha256):
    if expected_sha256 is not None and (not isinstance(expected_sha256, str)
                                       or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256)):
        raise InputError('merged: invalid expected SHA-256')
    # Digest and document come from the same bounded read, never a second open.
    report = _read_input('merged', path)
    if expected_sha256 is not None and report.sha256 != expected_sha256:
        raise InputError('merged: SHA-256 mismatch')
    saved = report.document
    try:
        if not isinstance(saved, dict) or saved.get('schemaVersion') != 'vulnfuse-1':
            raise InputError('unsupported saved schema')
        if not isinstance(saved['inputs'], list):
            raise InputError('invalid saved inputs')
        reports = []
        for source in saved['inputs']:
            document = source['rawReport']
            name, digest, size, kind = _provenance(source, document)
            reports.append(Report(source['scanner'], document, name, digest, size, kind))
        manifest = None
        if saved['coverageManifest'] is not None:
            value = saved['coverageManifest']
            document = value['rawManifest']
            name, digest, size, kind = _provenance(value, document)
            manifest = CoverageManifest(document, name, digest, size, kind)
        reconstructed = merge_reports(reports, coverage_manifest=manifest)
        # JSON comparison distinguishes bool/int and requires the full supported
        # shape. No damaged references or omitted derived fields are repaired.
        if dumps(saved) != dumps(reconstructed):
            raise InputError('inconsistent saved merge')
        return reconstructed, report
    except (InputError, KeyError, TypeError, ValueError, AttributeError, RecursionError, UnicodeError):
        raise InputError('merged: invalid or inconsistent saved report') from None
