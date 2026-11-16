"""Compare two independently explained snapshots without inferring remediation."""
from __future__ import annotations

from copy import deepcopy
import hashlib

from ._inputs import MAX_INPUT_BYTES, parse_json
from .core import InputError, _digest, explain

_RESULT_FIELDS = ('Target', 'Class', 'Type')
_FINDING_FIELDS = ('VulnerabilityID', 'PkgName', 'InstalledVersion', 'PkgPath', 'PkgID')
_STATUSES = ('attribution_changed', 'unknown', 'unchanged', 'before_only', 'after_only')


def _pinned_target_map(mapping: bytes, pin: str) -> dict:
    """Verify bounded original map bytes before parsing or snapshot processing."""
    _digest(pin, 'target_map_sha256')
    if mapping is None:
        raise InputError('target_map_sha256: requires target_map')
    if not isinstance(mapping, bytes):
        raise InputError('target_map_sha256: verification requires raw target map bytes')
    if len(mapping) > MAX_INPUT_BYTES:
        raise InputError('target map: input exceeds 32 MiB limit')
    if 'sha256:' + hashlib.sha256(mapping).hexdigest() != pin:
        raise InputError('target_map: target map digest mismatch')
    return parse_json(mapping, 'target map')


def _target_keys(snapshots: dict, mapping: dict) -> dict:
    """Validate a partial bijection, including unchanged target correspondences."""
    if not isinstance(mapping, dict):
        raise InputError('target_map: expected JSON object')
    targets = {side: {result['Target'] for result in
                     snapshot['provenance']['report'].get('Results') or []}
               for side, snapshot in snapshots.items()}
    for old, new in mapping.items():
        if not isinstance(old, str) or not old or not isinstance(new, str) or not new:
            raise InputError('target_map: keys and values must be nonempty strings')
        if old not in targets['before']:
            raise InputError('target_map: target absent from before snapshot')
        if new not in targets['after']:
            raise InputError('target_map: target absent from after snapshot')
    effective = {old: mapping.get(old, old) for old in targets['before']
                 if old in mapping or old in targets['after']}
    if len(set(effective.values())) != len(effective):
        raise InputError('target_map: non-bijective target correspondence')
    reverse = {new: old for old, new in effective.items()}
    # Pair keys distinguish a renamed target from an unclaimed original name in
    # the other snapshot. This also allows explicit swaps without transitive matching.
    return {'before': {old: (old, effective.get(old)) for old in targets['before']},
            'after': {new: (reverse.get(new), new) for new in targets['after']}}


def _target_coverage(snapshots: dict, target_keys: dict, mapping: dict) -> list[dict]:
    """List target correspondences, retaining every original Results reference.

    Insertion order is distinct before targets, then unclaimed after targets, each
    in report order. Reference arrays describe target membership, not result pairs.
    """
    indexed = {}
    for side, snapshot in snapshots.items():
        for index, result in enumerate(snapshot['provenance']['report'].get('Results') or []):
            key = target_keys[side][result['Target']]
            refs = indexed.setdefault(key, {'before': [], 'after': []})
            refs[side].append(f'#/snapshots/{side}/provenance/report/Results/{index}')
    coverage = []
    for (old, new), refs in indexed.items():
        paired = old is not None and new is not None
        coverage.append({
            'status': 'paired' if paired else 'before_only' if old is not None else 'after_only',
            'match': ('explicit_map' if old in mapping else 'exact_name') if paired else None,
            'beforeTarget': old, 'afterTarget': new, **refs,
        })
    return coverage


def _entries(snapshot: dict, side: str, target_keys: dict | None = None) -> dict:
    """Index exact identities; retain duplicates rather than pairing by position."""
    ordered = []
    results = snapshot['provenance']['report'].get('Results') or []
    for origin, findings in snapshot['groups'].items():
        for index, entry in enumerate(findings):
            source = entry['source']
            result = results[source['resultIndex']]
            identity = {field: result.get(field) for field in _RESULT_FIELDS}
            identity.update({field: entry['finding'].get(field) for field in _FINDING_FIELDS})
            if any(value is not None and not isinstance(value, str) for value in identity.values()):
                raise InputError('comparison identity fields: expected string or null')
            ordered.append((source['resultIndex'], source['findingIndex'], identity,
                            f'#/snapshots/{side}/groups/{origin}/{index}', origin))
    indexed = {}
    for _, _, identity, ref, origin in sorted(ordered, key=lambda item: item[:2]):
        key = tuple(identity.values())
        if target_keys is not None:
            key = (target_keys[identity['Target']], *key[1:])
        indexed.setdefault(key, {'identity': identity, 'refs': [], 'origins': []})
        indexed[key]['refs'].append(ref)
        indexed[key]['origins'].append(origin)
    return indexed


def compare(before_report: dict | bytes, before_base_config: dict | bytes, before_image_config: dict | bytes,
            after_report: dict | bytes, after_base_config: dict | bytes, after_image_config: dict | bytes, *,
            before_digest_map: dict | bytes | None = None, after_digest_map: dict | bytes | None = None,
            before_image_manifest: dict | bytes | None = None,
            after_image_manifest: dict | bytes | None = None,
            before_base_manifest: dict | bytes | None = None,
            after_base_manifest: dict | bytes | None = None,
            before_base_digest_map: dict | bytes | None = None,
            after_base_digest_map: dict | bytes | None = None,
            before_base_manifest_sha256: str | None = None,
            after_base_manifest_sha256: str | None = None,
            before_image_manifest_sha256: str | None = None,
            after_image_manifest_sha256: str | None = None,
            before_report_sha256: str | None = None, after_report_sha256: str | None = None,
            before_digest_map_sha256: str | None = None, after_digest_map_sha256: str | None = None,
            before_base_digest_map_sha256: str | None = None, after_base_digest_map_sha256: str | None = None,
            before_base_config_sha256: str | None = None, after_base_config_sha256: str | None = None,
            before_image_config_sha256: str | None = None, after_image_config_sha256: str | None = None,
            target_map: dict | bytes | None = None, target_map_sha256: str | None = None) -> dict:
    """Attribute both inputs independently, then compare exact finding identities.

    Snapshot inputs and optional manifest byte requirements are those of explain().
    All findings, proofs, warnings and provenance are retained under snapshots.
    Row references are local JSON Pointers into those snapshots. Non-unique keys
    stay ambiguous, and absence or attribution change never proves remediation.
    target_map optionally asserts before->after Target correspondences; all other
    identity fields stay exact. Explicit and implicit same-name matches must form
    a partial bijection. Original targets and snapshots are never rewritten.
    Map-enabled targetCoverage includes zero-finding targets and all original
    Results references; it asserts no result-level pairing or scanner completeness.
    With target_map_sha256, target_map must be exact bounded immutable bytes;
    verify the hash before strict parsing. Only local byte agreement is established.
    """
    if target_map_sha256 is not None:
        target_map = _pinned_target_map(target_map, target_map_sha256)
    snapshots = {
        'before': explain(before_report, before_base_config, before_image_config,
                          digest_map=before_digest_map, image_manifest=before_image_manifest,
                          base_manifest=before_base_manifest, base_digest_map=before_base_digest_map,
                          base_manifest_sha256=before_base_manifest_sha256,
                          base_config_sha256=before_base_config_sha256,
                          image_config_sha256=before_image_config_sha256,
                          image_manifest_sha256=before_image_manifest_sha256,
                          report_sha256=before_report_sha256,
                          digest_map_sha256=before_digest_map_sha256,
                          base_digest_map_sha256=before_base_digest_map_sha256),
        'after': explain(after_report, after_base_config, after_image_config,
                         digest_map=after_digest_map, image_manifest=after_image_manifest,
                         base_manifest=after_base_manifest, base_digest_map=after_base_digest_map,
                         base_manifest_sha256=after_base_manifest_sha256,
                         base_config_sha256=after_base_config_sha256,
                          image_config_sha256=after_image_config_sha256,
                         image_manifest_sha256=after_image_manifest_sha256,
                         report_sha256=after_report_sha256,
                         digest_map_sha256=after_digest_map_sha256,
                         base_digest_map_sha256=after_base_digest_map_sha256),
    }
    target_keys = _target_keys(snapshots, target_map) if target_map is not None else {}
    before = _entries(snapshots['before'], 'before', target_keys.get('before'))
    after = _entries(snapshots['after'], 'after', target_keys.get('after'))
    rows = []
    # Stable original finding order: before identities, then after-only identities.
    for key in dict.fromkeys([*before, *after]):
        old, new = before.get(key), after.get(key)
        old_origin = old['origins'][0] if old and len(old['refs']) == 1 else None
        new_origin = new['origins'][0] if new and len(new['refs']) == 1 else None
        if (old and len(old['refs']) > 1) or (new and len(new['refs']) > 1):
            status, reason = 'unknown', 'ambiguous_finding_identity'
        elif old is None:
            status, reason = 'after_only', 'not_observed_in_before_snapshot'
        elif new is None:
            status, reason = 'before_only', 'not_observed_in_after_snapshot'
        elif 'unknown' in (old_origin, new_origin):
            status, reason = 'unknown', 'insufficient_attribution_evidence'
        elif old_origin != new_origin:
            status, reason = 'attribution_changed', 'origin_changed'
        else:
            status, reason = 'unchanged', 'same_origin'
        rows.append({'identity': (old or new)['identity'], 'status': status, 'reason': reason,
                     'beforeOrigin': old_origin, 'afterOrigin': new_origin,
                     'before': old['refs'] if old else [], 'after': new['refs'] if new else []})
        if target_map is not None:
            rows[-1].update({'beforeTarget': old['identity']['Target'] if old else None,
                             'afterTarget': new['identity']['Target'] if new else None})
    old_ids = snapshots['before']['provenance']['baseConfig']['rootfs']['diff_ids']
    new_ids = snapshots['after']['provenance']['baseConfig']['rootfs']['diff_ids']
    counts = dict.fromkeys(_STATUSES, 0)
    for row in rows:
        counts[row['status']] += 1
    output = {
        'schemaVersion': 1, 'kind': 'base_upgrade_comparison',
        'basePrefixChange': {'changed': old_ids != new_ids, 'before': old_ids, 'after': new_ids},
        'identityFields': {'result': list(_RESULT_FIELDS), 'finding': list(_FINDING_FIELDS)},
        'counts': {**counts, 'total': len(rows)}, 'rows': rows, 'snapshots': snapshots,
        'warnings': [{'code': 'comparison_does_not_establish_remediation'},
                     {'code': 'exact_identity_matching_only'}],
    }
    if target_map is not None:
        output['targetMap'] = deepcopy(target_map)
        output['targetCoverage'] = _target_coverage(snapshots, target_keys, target_map)
        output['warnings'][1:] = [{'code': 'exact_identity_except_explicit_target_map'},
                                  {'code': 'target_map_is_caller_assertion'}]
        if target_map_sha256 is not None:
            output.update(targetMapDigest=target_map_sha256, targetMapPinAgreement='matched_local')
    return output
