"""Compare raw checks, evidence availability, repository and scanner identities."""

from pathlib import Path

from .core import (
    InputError, _canonical, _inventory, _iso, _load_snapshots, _need, _purl,
    _read, _text, _timestamp, normalize_repository,
)


def compare(bom_path, mapping_path, before_path, after_path, before_as_of: str,
            after_as_of: str, *, max_age_days: int, checks=None) -> dict:
    """Compare two local bundles for one inventory and one exact mapping.

    No policy or overall score is computed. Raw changes remain visible even when
    the evidence cannot support a directional comparison. Invalid inputs raise
    InputError; neither missing nor stale snapshots are invalid input. checks=None
    covers all observed names; a list/tuple selects exact names (empty selects none).
    Full snapshots are validated and retained regardless of check selection.
    """
    try:
        _need(checks is None or isinstance(checks, (list, tuple)) and all(_text(name) for name in checks),
              'check selection must be a list or tuple of nonempty strings')
        checks = None if checks is None else frozenset(checks)
        return _compare(Path(bom_path), Path(mapping_path), Path(before_path), Path(after_path),
                        before_as_of, after_as_of, max_age_days, checks)
    except InputError:
        raise
    except (OSError, ValueError, TypeError, RecursionError, OverflowError):
        raise InputError('invalid or excessively nested input') from None


def _selection(repository, snapshots, index, instant, max_age_days):
    entry = index.get(repository, {})
    snapshot = snapshots.get(entry.get('selectedSnapshot'))
    if snapshot is None:
        return {'snapshotId': None, 'timestamp': None, 'ageDays': None, 'commit': None,
                'status': 'no_snapshot_as_of' if entry.get('futureSnapshots') else 'missing_scorecard'}
    age = (instant.date() - _timestamp(snapshot['timestamp']).date()).days
    return {'snapshotId': snapshot['id'], 'timestamp': snapshot['timestamp'], 'ageDays': age,
            'commit': snapshot['document']['repo']['commit'],
            'status': 'stale' if age > max_age_days else 'fresh'}


def _observation(item, snapshot):
    if snapshot is None:
        return 'missing_snapshot'
    if item is None:
        return 'missing_check'
    score = item.get('score')
    return 'missing_score' if score is None else 'negative_score' if score == -1 else 'known'


def _check_changes(before_snapshot, after_snapshot, comparable, checks):
    before = {item['name']: item for item in before_snapshot['document']['checks']} if before_snapshot else {}
    after = {item['name']: item for item in after_snapshot['document']['checks']} if after_snapshot else {}
    both_snapshots = before_snapshot is not None and after_snapshot is not None
    rows = []
    names = before.keys() | after.keys()
    if checks is not None:
        names &= checks
    for name in sorted(names):
        old, new = before.get(name), after.get(name)
        old_observation = _observation(old, before_snapshot)
        new_observation = _observation(new, after_snapshot)
        change = ('not_comparable' if not both_snapshots else 'added' if old is None else
                  'deleted' if new is None else 'unchanged' if _canonical(old) == _canonical(new) else 'changed')
        direction = 'not_comparable'
        if comparable and old_observation == new_observation == 'known':
            direction = ('increased' if new['score'] > old['score'] else
                         'decreased' if new['score'] < old['score'] else 'unchanged')

        def field_changed(field):
            # Compare presence as well as value; a missing reason/score is not null.
            if not both_snapshots:
                return None
            return _canonical({field: old[field]} if old is not None and field in old else {}) != _canonical(
                {field: new[field]} if new is not None and field in new else {})

        rows.append({'name': name, 'change': change, 'scoreChange': direction,
                     'scoreChanged': field_changed('score'), 'reasonChanged': field_changed('reason'),
                     'beforeObservation': old_observation, 'afterObservation': new_observation,
                     'before': old, 'after': new})
    return rows


def _scanner_change(before_snapshot, after_snapshot):
    def identity(snapshot):
        if snapshot is None:
            return None
        metadata = snapshot['document'].get('scorecard')
        metadata = metadata if isinstance(metadata, dict) else {}
        # Optional metadata is not evidence of equality when absent or unusable.
        return {field: value if isinstance(value := metadata.get(field), str) and value.strip() else None
                for field in ('version', 'commit')}

    before, after = identity(before_snapshot), identity(after_snapshot)

    def change(field):
        if before is None or after is None or before[field] is None or after[field] is None:
            return 'not_comparable'
        return 'unchanged' if before[field] == after[field] else 'changed'

    return {'before': before, 'after': after,
            'versionChange': change('version'), 'commitChange': change('commit')}


def _repository_change(repository, before, after, before_snapshot, after_snapshot, checks):
    both = before_snapshot is not None and after_snapshot is not None
    snapshot_change = 'not_comparable'
    if both:
        old_time, new_time = _timestamp(before['timestamp']), _timestamp(after['timestamp'])
        snapshot_change = ('unchanged' if before['snapshotId'] == after['snapshotId'] else
                           'advanced' if new_time > old_time else 'regressed' if new_time < old_time else
                           'same_timestamp_changed')
    # Both side statuses are retained; this field explains the first blocker.
    comparison = ('missing_both' if before_snapshot is None and after_snapshot is None else
                  'missing_after' if after_snapshot is None else 'missing_before' if before_snapshot is None else
                  'stale_after' if after['status'] == 'stale' else 'stale_before' if before['status'] == 'stale' else
                  'snapshot_time_regressed' if snapshot_change == 'regressed' else
                  'snapshot_time_ambiguous' if snapshot_change == 'same_timestamp_changed' else 'comparable')
    return {'repository': repository, 'before': before, 'after': after, 'comparison': comparison,
            'snapshotChange': snapshot_change,
            'commitChange': ('unchanged' if before['commit'] == after['commit'] else 'changed') if both else 'not_comparable',
            'scannerChange': _scanner_change(before_snapshot, after_snapshot),
            'checks': _check_changes(before_snapshot, after_snapshot, comparison == 'comparable', checks)}


def _compare(bom_path, mapping_path, before_path, after_path, before_as_of, after_as_of, max_age_days, checks):
    before_instant = _timestamp(before_as_of, as_of=True)
    after_instant = _timestamp(after_as_of, as_of=True)
    _need(after_instant > before_instant, 'after-as-of must be later than before-as-of')
    _need(type(max_age_days) is int and max_age_days >= 0, 'max-age-days must be a nonnegative integer')
    budget = [0]
    bom, bom_source = _read(bom_path, 'SBOM', budget)
    inventory = _inventory(bom)
    mapping, mapping_source = _read(mapping_path, 'mapping', budget)
    normalized = {_purl(purl): normalize_repository(repo) for purl, repo in mapping.items()}
    before_snapshots, before_index = _load_snapshots(before_path, before_instant, budget)
    after_snapshots, after_index = _load_snapshots(after_path, after_instant, budget)
    components = []
    for component in inventory:
        repository = normalized.get(component['purl'])
        components.append(dict(component, repository=repository,
                               mappingStatus='missing_purl' if component['purl'] is None else
                               'unmapped' if repository is None else 'mapped'))
    repositories = []
    for repository in sorted({row['repository'] for row in components if row['repository'] is not None}):
        before = _selection(repository, before_snapshots, before_index, before_instant, max_age_days)
        after = _selection(repository, after_snapshots, after_index, after_instant, max_age_days)
        repositories.append(_repository_change(repository, before, after,
                                                before_snapshots.get(before['snapshotId']),
                                                after_snapshots.get(after['snapshotId']), checks))
    scanner_changes = {field: {'changed': 0, 'unchanged': 0, 'not_comparable': 0}
                       for field in ('version', 'commit')}
    comparison_statuses = dict.fromkeys((
        'comparable', 'missing_both', 'missing_after', 'missing_before',
        'stale_after', 'stale_before', 'snapshot_time_regressed', 'snapshot_time_ambiguous'), 0)
    snapshot_changes = dict.fromkeys((
        'advanced', 'unchanged', 'regressed', 'same_timestamp_changed', 'not_comparable'), 0)
    check_changes = dict.fromkeys(('changed', 'unchanged', 'added', 'deleted', 'not_comparable'), 0)
    check_score_changes = dict.fromkeys(('increased', 'decreased', 'unchanged', 'not_comparable'), 0)
    check_score_comparability = dict.fromkeys(('comparable', 'evidence_blocked', 'observation_blocked'), 0)
    check_score_changes_by_check = {}
    check_score_comparability_by_check = {}
    check_observations = {side: dict.fromkeys((
        'known', 'negative_score', 'missing_score', 'missing_check', 'missing_snapshot'), 0)
        for side in ('before', 'after')}
    check_observation_transitions = {before: dict.fromkeys(check_observations['after'], 0)
                                     for before in check_observations['before']}
    for row in repositories:
        snapshot_changes[row['snapshotChange']] += 1
        comparison_statuses[row['comparison']] += 1
        for check in row['checks']:
            check_changes[check['change']] += 1
            check_score_changes[check['scoreChange']] += 1
            if check['name'] not in check_score_changes_by_check:
                check_score_changes_by_check[check['name']] = dict.fromkeys(check_score_changes, 0)
            check_score_changes_by_check[check['name']][check['scoreChange']] += 1
            # Evidence blockers take priority when observation gaps also apply.
            comparability = ('comparable' if check['scoreChange'] != 'not_comparable' else
                             'evidence_blocked' if row['comparison'] != 'comparable' else 'observation_blocked')
            check_score_comparability[comparability] += 1
            if check['name'] not in check_score_comparability_by_check:
                check_score_comparability_by_check[check['name']] = dict.fromkeys(check_score_comparability, 0)
            check_score_comparability_by_check[check['name']][comparability] += 1
            check_observation_transitions[check['beforeObservation']][check['afterObservation']] += 1
            for side, counts in check_observations.items():
                counts[check[side + 'Observation']] += 1
        for field, counts in scanner_changes.items():
            counts[row['scannerChange'][field + 'Change']] += 1
    return {
        'reportVersion': '1', 'reportType': 'snapshot-comparison',
        'tool': {'name': 'scorecard-join', 'version': '0.1.0'}, 'maxAgeDays': max_age_days,
        **({'checkSelection': {'names': sorted(checks)}} if checks is not None else {}),
        'summary': {'components': len(components), 'comparedRepositories': len(repositories),
                    'mappedComponents': sum(row['repository'] is not None for row in components),
                    'unmappedComponents': sum(row['repository'] is None for row in components),
                    'scannerChanges': scanner_changes,
                    'comparisonStatuses': comparison_statuses,
                    'snapshotChanges': snapshot_changes,
                    'checkChanges': check_changes,
                    'checkScoreChanges': check_score_changes,
                    'checkScoreChangesByCheck': [dict(name=name, **counts) for name, counts in
                                                 sorted(check_score_changes_by_check.items())],
                    'checkScoreComparability': check_score_comparability,
                    'checkScoreComparabilityByCheck': [dict(name=name, **counts) for name, counts in
                                                       sorted(check_score_comparability_by_check.items())],
                    'checkObservations': check_observations,
                    'checkObservationTransitions': check_observation_transitions,
                    'unusedMappings': sorted(set(normalized) - {row['purl'] for row in components})},
        'components': components, 'repositories': repositories,
        'before': {'asOf': _iso(before_instant), 'repositoryIndex': before_index,
                   'snapshots': [before_snapshots[key] for key in sorted(before_snapshots)]},
        'after': {'asOf': _iso(after_instant), 'repositoryIndex': after_index,
                  'snapshots': [after_snapshots[key] for key in sorted(after_snapshots)]},
        'inputs': {'bom': bom_source, 'mapping': mapping_source},
    }
