"""Replacement evidence contracts and deterministic candidate-search work budget."""
import copy
import random
import sys
import unittest
from unittest.mock import patch

from vulnwrench.secretledger import compare, snapshot
from vulnwrench.secretledger.core import CLASSIFICATIONS, _group_sort, _occ_sort
from test_ledger import KEY, OTHER, SECRET, finding


def slow_changes(previous, current, mapping):
    """Exhaustive semantic oracle: no candidate index, test-sized inputs only."""
    forward = {p['old_path']: p['new_path'] for p in mapping or []}
    shared = ({g['path'] for g in previous} & {g['path'] for g in current}) - forward.keys()
    old_paths, new_paths = set(forward) | shared, set(forward.values()) | shared

    def path(g):
        return forward.get(g['path'], g['path'])

    def exact(old, new):
        return (old['content_hmac'] is not None and new['content_hmac'] is not None
                and old['content_hmac'] == new['content_hmac']
                and old['rule_id'] == new['rule_id'] and path(old) == new['path'])

    changes = []
    for new in current:
        candidates = [old for old in previous
                      if old['rule_id'] == new['rule_id'] and path(old) == new['path']]
        matches = [old for old in previous if exact(old, new)]
        unknowns = [old for old in candidates if old['content_hmac'] is None]
        evidence = []
        if new['content_hmac'] is None:
            kind, reason = 'uncomparable', 'current_content_unavailable'
        elif mapping is not None and new['path'] not in new_paths:
            kind, reason = 'uncomparable', 'current_path_unmapped'
        elif matches:
            old = matches[0]
            renamed = old['path'] != new['path']
            kind = ('unchanged' if not renamed and sorted(old['occurrences'], key=_occ_sort)
                    == sorted(new['occurrences'], key=_occ_sort) else 'same_secret_moved')
            reason = 'same_content_rule_and_mapped_path' if renamed else 'same_content_rule_and_path'
            evidence = [old]
        elif unknowns:
            kind, reason, evidence = 'uncomparable', 'prior_content_unavailable', unknowns
        else:
            evidence = [old for old in candidates if any(
                a['start_line'] == b['start_line'] for a in old['occurrences']
                for b in new['occurrences'])]
            kind = 'new_content_same_location' if evidence else 'new_content'
            reason = 'different_content_at_prior_location' if evidence else 'no_prior_content_identity'
        changes.append({'classification': kind, 'reason': reason, 'current': new,
                        'previous': sorted(evidence, key=_group_sort)})
    for old in sorted(previous, key=_group_sort):
        if any(exact(old, new) for new in current):
            continue
        unmapped = mapping is not None and old['path'] not in old_paths
        uncertain = (old['content_hmac'] is None or unmapped or any(
            new['content_hmac'] is None and new['rule_id'] == old['rule_id']
            and new['path'] == path(old) for new in current))
        reason = ('prior_path_unmapped' if unmapped and old['content_hmac'] is not None else
                  'content_unavailable_cannot_prove_absence' if uncertain else 'not_in_current_full_report')
        changes.append({'classification': 'uncomparable' if uncertain else 'absent',
                        'reason': reason, 'current': None, 'previous': [old]})
    return changes


class ReplacementTests(unittest.TestCase):
    @unittest.skipUnless(sys.implementation.name == 'cpython', 'CPython builtin call observation')
    def test_exact_reuses_sorted_current_occurrences(self):
        """Real sort/key counts enforce a proposed work boundary, not a bug fix."""
        from vulnwrench.secretledger import core

        for mode in ('same', 'empty-map', 'identity', 'mapped'):
            for change in ('none', 'line', 'commit', 'fingerprint', 'drop-duplicate', 'add-duplicate'):
                for redacted in (False, True):
                    with self.subTest(mode=mode, change=change, redacted=redacted):
                        old = [finding(line=9, commit='b' * 40),
                               finding(line=2, commit='b' * 40),
                               finding(line=2, commit='a' * 40),
                               finding(line=2, commit='a' * 40)]
                        rows = copy.deepcopy(old)
                        if change == 'line':
                            rows[0] = finding(line=10, commit='b' * 40)
                        elif change == 'commit':
                            rows[0] = finding(line=9, commit='c' * 40)
                        elif change == 'fingerprint':
                            # Equivalent normalized path, different native metadata.
                            rows[0]['Fingerprint'] = 'b' * 40 + ':./src/config.py:generic-api-key:9'
                        elif change == 'drop-duplicate':
                            rows.pop()
                        elif change == 'add-duplicate':
                            rows.append(copy.deepcopy(rows[-1]))
                        # Exact precedence amid unknowns and same-line content.
                        old += [finding(None), finding(OTHER)]
                        rows += [finding(None), finding(OTHER, path='replacement.py')]
                        old += [finding(path='replacement.py')]
                        mapping = None if mode == 'same' else []
                        if mode == 'identity':
                            mapping = [{'old_path': 'src/config.py', 'new_path': 'src/config.py'}]
                        elif mode == 'mapped':
                            mapping = [{'old_path': 'src/config.py', 'new_path': 'lib/config.py'}]
                            for row in rows:
                                if row['File'] == 'src/config.py':
                                    row['File'] = 'lib/config.py'
                                    row['Fingerprint'] = row['Fingerprint'].replace('src/config.py', 'lib/config.py')
                        rows.reverse()  # Only the internal snapshot guarantees order.
                        before = snapshot(old, KEY)
                        before['groups'].reverse()
                        for group in before['groups']:
                            group['occurrences'].reverse()
                        original = copy.deepcopy((before, rows, mapping))
                        expected = snapshot(rows, KEY, redacted=redacted)
                        oracle = slow_changes(before['groups'], expected['groups'], mapping)
                        prior_ids = {id(o) for g in before['groups'] for o in g['occurrences']}
                        calls, prior_keys, current_keys = [], [], []

                        def profile(frame, event, function):
                            if (frame.f_code is compare.__code__ and event == 'c_call'
                                    and function is sorted):
                                calls.append(True)

                        def key(occurrence):
                            if sys._getframe(1).f_code is compare.__code__:
                                (prior_keys if id(occurrence) in prior_ids else current_keys).append(occurrence)
                            return _occ_sort(occurrence)

                        previous_profile = sys.getprofile()
                        try:
                            with patch.object(core, '_occ_sort', key):
                                sys.setprofile(profile)
                                result, current = compare(before, rows, KEY, path_map=mapping, redacted=redacted)
                        finally:
                            sys.setprofile(previous_profile)
                        self.assertEqual(result['changes'], oracle)
                        self.assertEqual(current, expected)
                        self.assertEqual((before, rows, mapping), original)
                        exact = [event for event in result['changes'] if event['current'] is not None
                                 and event['classification'] in ('unchanged', 'same_secret_moved')
                                 and event['previous'][0]['path'] == event['current']['path']]
                        self.assertEqual(len(prior_keys), sum(len(e['previous'][0]['occurrences']) for e in exact))
                        # Final prior-group and optional mapping sorts remain required.
                        self.assertEqual((len(current_keys), len(calls)),
                                         (0, 1 + int(mapping is not None) + len(exact)))

    @unittest.skipUnless(sys.implementation.name == 'cpython', 'CPython builtin call observation')
    def test_final_evidence_sort_only_for_multiple_members(self):
        """Observe real sort invocations and keys, including key-free empty sorts.

        This is a proposed work boundary, not a semantic defect. Neither the
        builtin sorter nor the output allocator is replaced by the observer.
        """
        from scripts.secrets.benchmark_replacements import fixture
        from vulnwrench.secretledger import core

        for mode in ('same', 'mapped', 'empty-map'):
            for workload in ('mixed-single', 'mixed-partial', 'many-miss',
                             'empty-candidates', 'empty-prior', 'empty-report', 'empty-both'):
                for redacted in (False, True):
                    with self.subTest(mode=mode, workload=workload, redacted=redacted):
                        old, rows, mapping = fixture(5, mode == 'mapped',
                            workload if workload in ('mixed-single', 'mixed-partial',
                                'many-miss', 'empty-candidates') else 'single-hit', 2, 4)
                        if workload in ('empty-prior', 'empty-both'):
                            old = []
                        if workload in ('empty-report', 'empty-both'):
                            rows = []
                        if mode == 'empty-map':
                            mapping = []
                        before = snapshot(old, KEY)
                        before['groups'].reverse()
                        for group in before['groups']:
                            group['occurrences'].reverse()
                        original = copy.deepcopy((before, rows, mapping))
                        expected_current = snapshot(rows, KEY, redacted=redacted)
                        oracle = slow_changes(before['groups'], expected_current['groups'], mapping)
                        calls, active = [], None

                        def profile(frame, event, function):
                            nonlocal active
                            if (frame.f_code is compare.__code__
                                    and event in ('c_call', 'c_return', 'c_exception')
                                    and getattr(function, '__name__', None) == 'sort'
                                    and getattr(function, '__self__', None)
                                    is frame.f_locals.get('evidence')):
                                if event == 'c_call':
                                    active = {'query': frame.f_locals['current_index'],
                                              'members': len(function.__self__), 'keys': 0}
                                    calls.append(active)
                                else:
                                    active = None

                        def sort_key(group):
                            if active is not None:
                                active['keys'] += 1
                            return _group_sort(group)

                        prior_profile = sys.getprofile()
                        try:
                            with patch.object(core, '_group_sort', sort_key):
                                sys.setprofile(profile)
                                result, current = compare(before, rows, KEY,
                                    path_map=mapping, redacted=redacted)
                        finally:
                            sys.setprofile(prior_profile)
                        self.assertEqual(result['changes'], oracle)
                        self.assertEqual(current, expected_current)
                        self.assertEqual((before, rows, mapping), original)
                        values = [event['previous'] for event in result['changes']]
                        self.assertEqual(len({id(value) for value in values}), len(values))
                        self.assertTrue(all(value == sorted(value, key=_group_sort) for value in values))
                        expected = [{'query': i, 'members': len(event['previous']),
                                     'keys': len(event['previous'])}
                                    for i, event in enumerate(oracle)
                                    if event['current'] is not None and len(event['previous']) >= 2]
                        # Assert work only after semantic/ownership/immutability checks.
                        self.assertEqual(calls, expected)

    @unittest.skipUnless(sys.implementation.name == 'cpython', 'CPython retained list storage')
    def test_final_evidence_storage_matches_candidate_cardinality(self):
        """Proposed retained-storage bound, independent of output semantics.

        Compare real returned lists with an exactly preallocated list of the
        same cardinality. No allocator/sorter substitution or timing threshold.
        Odd dense sizes expose spare capacity as well as sparse singletons.
        """
        from scripts.secrets.benchmark_replacements import fixture

        for mode in ('same', 'mapped', 'empty-map'):
            for size in (5, 9):
                for workload in ('mixed-single', 'mixed-partial'):
                    with self.subTest(mode=mode, size=size, workload=workload):
                        old, rows, mapping = fixture(size, mode == 'mapped', workload, 2, 8)
                        if mode == 'empty-map':
                            mapping = []
                        before = snapshot(old, KEY)
                        before['groups'].reverse()
                        for group in before['groups']:
                            group['occurrences'].reverse()
                        original = copy.deepcopy((before, rows, mapping))
                        result, current = compare(before, rows, KEY, path_map=mapping)
                        self.assertEqual(result['changes'], slow_changes(
                            before['groups'], current['groups'], mapping))
                        self.assertEqual(current, snapshot(rows, KEY))
                        self.assertEqual((before, rows, mapping), original)
                        evidence = [event['previous'] for event in result['changes']]
                        # Independent lists even for identical candidate sets,
                        # unknown-prior evidence, exact matches and empty lists.
                        self.assertEqual(len({id(value) for value in evidence}), len(evidence))
                        self.assertTrue(all(value is not before['groups'] for value in evidence))
                        self.assertTrue(all(value == sorted(value, key=_group_sort) for value in evidence))
                        replacements = [event['previous'] for event in result['changes']
                                        if event['classification'] == 'new_content_same_location']
                        self.assertEqual({len(value) for value in replacements}, {1, size})
                        self.assertGreater(result['summary']['new_content'], 0)
                        self.assertGreater(result['summary']['uncomparable'], 0)
                        # Check the boundary only after oracle/order/multisets,
                        # snapshots, ownership and immutability pass unchanged.
                        violations = [(len(value), sys.getsizeof(value),
                                       sys.getsizeof([None] * len(value)))
                                      for value in evidence
                                      if sys.getsizeof(value) != sys.getsizeof([None] * len(value))]
                        self.assertEqual(violations[:3], [])

    def test_replacement_sort_retains_no_unsorted_evidence_copy(self):
        """Proposed live-reference bound, not a timing or semantic defect test.

        During sort-key evaluation, CPython temporarily empties the list being
        sorted. A second query-local list still holding those group references
        is therefore an unnecessary retained copy, separate from input/output.
        Observe real key calls; do not substitute a sorter or allocator.
        """
        from scripts.secrets.benchmark_replacements import fixture
        from vulnwrench.secretledger import core

        for mode in ('same', 'mapped', 'empty-map'):
            for workload in ('single-hit', 'mixed-single', 'partial-hit', 'mixed-partial'):
                with self.subTest(mode=mode, workload=workload):
                    old, rows, mapping = fixture(6, mode == 'mapped', workload, 4, 8)
                    if mode == 'empty-map':
                        mapping = []
                    before = snapshot(old, KEY)
                    before['groups'].reverse()
                    for group in before['groups']:
                        group['occurrences'].reverse()
                    original = copy.deepcopy((before, rows, mapping))
                    expected_current = snapshot(rows, KEY)
                    oracle = slow_changes(before['groups'], expected_current['groups'], mapping)
                    replacements = {_group_sort(c['current']): {id(g) for g in c['previous']}
                                    for c in oracle if c['classification'] == 'new_content_same_location'}
                    observed, retained = set(), set()
                    key_calls = 0

                    def sort_key(group):
                        nonlocal key_calls
                        frame = sys._getframe(1)
                        if frame.f_code is compare.__code__:
                            state = frame.f_locals
                            query = state.get('g')
                            ident = _group_sort(query) if query is not None else None
                            expected = replacements.get(ident, set())
                            if (id(group) in expected and
                                    len(state['changes']) < len(state['current']['groups'])):
                                key_calls += 1
                                observed.add((ident, id(group)))
                                # Exclude the mandatory prior input and already
                                # finalized changes. Inspect only live locals;
                                # neither the oracle nor the observer holds a
                                # second list of the query's group references.
                                for name, value in state.items():
                                    if (isinstance(value, list) and value is not before['groups']
                                            and any(id(item) in expected for item in value)):
                                        retained.add((ident, name, len(value)))
                        return _group_sort(group)

                    with patch.object(core, '_group_sort', sort_key):
                        result, current = compare(before, rows, KEY, path_map=mapping)
                    self.assertEqual(result['changes'], oracle)
                    self.assertEqual(current, expected_current)
                    self.assertEqual((before, rows, mapping), original)
                    self.assertGreater(result['summary']['new_content'], 0)
                    self.assertTrue(any(len(ids) == 1 for ids in replacements.values()))
                    self.assertTrue(any(len(ids) > 1 for ids in replacements.values()))
                    expected_keys = {(ident, group) for ident, ids in replacements.items()
                                     if len(ids) >= 2 for group in ids}
                    self.assertEqual(observed, expected_keys)
                    self.assertEqual(key_calls, len(expected_keys))
                    # Assert only after output/order/multiset/immutability and
                    # observation-coverage checks pass on the prior runtime.
                    self.assertEqual(sorted(retained)[:3], [])

    def test_empty_candidate_buckets_do_not_visit_current_occurrences(self):
        from scripts.secrets.benchmark_replacements import fixture
        from vulnwrench.secretledger import core

        class Metered(list):
            visits = 0
            reads = 0

            def __iter__(self):
                for value in super().__iter__():
                    self.visits += 1
                    yield value

            def __getitem__(self, key):
                self.reads += 1
                return super().__getitem__(key)

        for mode in ('same', 'mapped', 'empty-map'):
            for mixed in (False, True):
                with self.subTest(mode=mode, mixed=mixed):
                    old, rows, mapping = fixture(6, mode == 'mapped',
                        'mixed-empty' if mixed else 'empty-candidates', 4, 8)
                    if mode == 'empty-map':
                        mapping = []
                    before = snapshot(old, KEY)
                    before['groups'].reverse()
                    for group in before['groups']:
                        group['occurrences'].reverse()
                    prepared, matcher = core._snapshot(rows, KEY)
                    original = copy.deepcopy((before, prepared, rows, mapping))
                    for group in before['groups'] + prepared['groups']:
                        group['occurrences'] = Metered(group['occurrences'])
                    before['groups'] = Metered(before['groups'])
                    prepared['groups'] = Metered(prepared['groups'])
                    with patch.object(core, '_snapshot', return_value=(prepared, matcher)):
                        result, current = compare(before, rows, KEY, path_map=mapping)
                    # Capture search work before the exhaustive oracle traverses
                    # occurrences. Snapshot work is excluded, never bypassed in production.
                    prior_visits = [(g, g['occurrences'].visits) for g in before['groups']]
                    query_visits = [(g, g['occurrences'].visits) for g in current['groups']]
                    group_visits = before['groups'].visits
                    current_reads = prepared['groups'].reads + prepared['groups'].visits
                    self.assertEqual(result['changes'], slow_changes(before['groups'], current['groups'], mapping))
                    self.assertEqual(current, snapshot(rows, KEY))
                    self.assertEqual((before, prepared, rows, mapping), original)
                    self.assertEqual(result['summary'], {k: sum(c['classification'] == k for c in result['changes'])
                                                         for k in CLASSIFICATIONS})
                    self.assertGreater(result['summary']['new_content'], 0)
                    if mixed:
                        self.assertGreater(result['summary']['new_content_same_location'], 0)
                        self.assertGreater(result['summary']['uncomparable'], 0)
                    if mode == 'mapped':
                        self.assertTrue(any(c['reason'] == 'current_path_unmapped' for c in result['changes']))
                    # Validation/privacy are mandatory. Only needed buckets get
                    # one prior indexing pass; same-path exact gets one sort pass.
                    forward = {p['old_path']: p['new_path'] for p in mapping or []}
                    known = {(g['rule_id'], forward.get(g['path'], g['path']), g['content_hmac'])
                             for g in before['groups'] if g['content_hmac']}
                    current_ids = {core._group_sort(g) for g in current['groups'] if g['content_hmac']}
                    for group, visits in prior_visits:
                        ident = (group['rule_id'], forward.get(group['path'], group['path']), group['content_hmac'])
                        passes = 2 + int('/needed-' in group['path']) + int(
                            ident in current_ids and group['path'] == ident[1])
                        self.assertEqual(visits, passes * len(group['occurrences']), group['path'])
                    self.assertLessEqual(group_visits, 12 * len(before['groups']))
                    self.assertLessEqual(current_reads, 7 * len(current['groups']))
                    violations = []
                    for group, visits in query_visits:
                        exact = core._group_sort(group) in known
                        passes = 0 if exact else (
                            2 if '/needed-' in group['path'] else 0)
                        if visits != passes * len(group['occurrences']):
                            violations.append((group['path'], visits, passes * len(group['occurrences'])))
                    # Empty, unknown-blocked, current unknown and unmapped
                    # buckets require zero query occurrence visits, even when
                    # other buckets are nonempty. No timing threshold.
                    self.assertEqual(violations, [])

    def test_empty_filtered_indexes_collect_queries_without_lookup_visits(self):
        from scripts.secrets.benchmark_replacements import fixture
        from vulnwrench.secretledger import core

        class Metered(list):
            visits = 0
            reads = 0

            def __iter__(self):
                for value in super().__iter__():
                    self.visits += 1
                    yield value

            def __getitem__(self, key):
                self.reads += 1
                return super().__getitem__(key)

        for mode in ('same', 'mapped', 'empty-map'):
            for mixed in (False, True):
                with self.subTest(mode=mode, mixed=mixed):
                    old, rows, mapping = fixture(6, mode == 'mapped',
                        'mixed-miss' if mixed else 'many-miss', 4, 8)
                    if mode == 'empty-map':
                        mapping = []
                    before = snapshot(old, KEY)
                    before['groups'].reverse()
                    for group in before['groups']:
                        group['occurrences'].reverse()
                    prepared, matcher = core._snapshot(rows, KEY)
                    original = copy.deepcopy((before, prepared, rows, mapping))
                    for group in before['groups'] + prepared['groups']:
                        group['occurrences'] = Metered(group['occurrences'])
                    before['groups'] = Metered(before['groups'])
                    prepared['groups'] = Metered(prepared['groups'])
                    with patch.object(core, '_snapshot', return_value=(prepared, matcher)):
                        result, current = compare(before, rows, KEY, path_map=mapping)
                    # Capture search work before the exhaustive oracle traverses
                    # occurrences. Snapshot work is excluded, never bypassed in production.
                    prior_visits = [(g, g['occurrences'].visits) for g in before['groups']]
                    query_visits = [(g, g['occurrences'].visits) for g in current['groups']]
                    group_visits = before['groups'].visits
                    current_reads = prepared['groups'].reads + prepared['groups'].visits
                    self.assertEqual(result['changes'], slow_changes(before['groups'], current['groups'], mapping))
                    self.assertEqual(current, snapshot(rows, KEY))
                    self.assertEqual((before, prepared, rows, mapping), original)
                    self.assertEqual(result['summary'], {k: sum(c['classification'] == k for c in result['changes'])
                                                         for k in CLASSIFICATIONS})
                    self.assertGreater(result['summary']['new_content'], 0)
                    if mixed:
                        self.assertGreater(result['summary']['new_content_same_location'], 0)
                        self.assertGreater(result['summary']['uncomparable'], 0)
                    if mode == 'mapped' and mixed:
                        self.assertTrue(any(c['reason'] == 'current_path_unmapped' for c in result['changes']))
                    # Validation/privacy are mandatory. Only needed buckets get
                    # one prior indexing pass; same-path exact gets one sort pass.
                    forward = {p['old_path']: p['new_path'] for p in mapping or []}
                    known = {(g['rule_id'], forward.get(g['path'], g['path']), g['content_hmac'])
                             for g in before['groups'] if g['content_hmac']}
                    current_ids = {core._group_sort(g) for g in current['groups'] if g['content_hmac']}
                    for group, visits in prior_visits:
                        ident = (group['rule_id'], forward.get(group['path'], group['path']), group['content_hmac'])
                        passes = 2 + int(any(kind in group['path'] for kind in
                            ('/needed-', '/all-miss-', '/dense-hit-'))) + int(
                            ident in current_ids and group['path'] == ident[1])
                        self.assertEqual(visits, passes * len(group['occurrences']), group['path'])
                    self.assertLessEqual(group_visits, 12 * len(before['groups']))
                    self.assertLessEqual(current_reads, 7 * len(current['groups']))
                    violations = []
                    for group, visits in query_visits:
                        exact = core._group_sort(group) in known
                        passes = 0 if exact else (
                            0 if not group['content_hmac'] else
                            1 if '/all-miss-' in group['path'] else
                            2 if any(kind in group['path'] for kind in ('/needed-', '/dense-hit-')) else 0)
                        if visits != passes * len(group['occurrences']):
                            violations.append((group['path'], visits, passes * len(group['occurrences'])))
                    # An empty filtered index still requires ONE query collection
                    # pass, but no lookup line sets. Empty prior, blocked and
                    # unmapped buckets require zero search visits. No timing threshold.
                    self.assertEqual(violations, [])

    def test_lookup_line_metadata_contains_only_active_index_hits(self):
        self.check_lookup_metadata(single_hit=False)

    def test_single_hit_reuses_candidate_list_without_union_metadata(self):
        self.check_lookup_metadata(single_hit=True)

    def check_lookup_metadata(self, single_hit):
        from scripts.secrets.benchmark_replacements import fixture
        from vulnwrench.secretledger import core

        class Metered(list):
            visits = 0
            reads = 0

            def __iter__(self):
                for value in super().__iter__():
                    self.visits += 1
                    yield value

            def __getitem__(self, key):
                self.reads += 1
                return super().__getitem__(key)

        for mode in ('same', 'mapped', 'empty-map'):
            for mixed in (False, True):
                with self.subTest(mode=mode, mixed=mixed):
                    old, rows, mapping = fixture(6, mode == 'mapped',
                        (('mixed-single' if mixed else 'single-hit') if single_hit else
                         ('mixed-partial' if mixed else 'partial-hit')), 4, 8)
                    if mode == 'empty-map':
                        mapping = []
                    before = snapshot(old, KEY)
                    before['groups'].reverse()
                    for group in before['groups']:
                        group['occurrences'].reverse()
                    prepared, matcher = core._snapshot(rows, KEY)
                    original = copy.deepcopy((before, prepared, rows, mapping))
                    # Expected active collection metadata, excluding exact/unknown/
                    # blocked/unmapped queries. The oracle remains exhaustive.
                    forward = {p['old_path']: p['new_path'] for p in mapping or []}
                    known = {(g['rule_id'], forward.get(g['path'], g['path']), g['content_hmac'])
                             for g in before['groups'] if g['content_hmac']}
                    oracle = slow_changes(before['groups'], prepared['groups'], mapping)
                    requested = {}
                    query_lines = {}
                    for change in oracle:
                        group = change['current']
                        if group and change['classification'] in ('new_content', 'new_content_same_location'):
                            ident = core._group_sort(group)
                            query_lines[ident] = {o['start_line'] for o in group['occurrences']}
                            requested.setdefault(ident[:2], set()).update(query_lines[ident])
                    metadata_violations, observed = set(), set()
                    peak_lookup = peak_index = 0
                    union_violations, union_hits = set(), set()
                    candidate_copies = {}

                    def trace(frame, event, arg):
                        nonlocal peak_lookup, peak_index
                        if frame.f_code is compare.__code__ and event == 'line':
                            state = frame.f_locals
                            bucket = state.get('path_ident')
                            collected = state.get('requested_lines', set())
                            if collected - requested.get(bucket, set()):
                                metadata_violations.add(('collection outside active bucket', bucket))
                            if single_hit:
                                index = state.get('candidates')
                                if index and 'lines' in state:
                                    for line, values in index.items():
                                        key = (bucket, line)
                                        if key not in candidate_copies:
                                            candidate_copies[key] = (values, tuple(values))
                                        if tuple(values) != candidate_copies[key][1]:
                                            union_violations.add(('candidate mutated', bucket, line))
                                if 'indexes' in state:
                                    lines = state.get('lines')
                                    if lines is None or index is None:
                                        union_violations.add(('indexes outlived query', bucket))
                                    else:
                                        indexes = state['indexes']
                                        union_hits.add(len(lines))
                                        expected_indexes = {i for line in lines for i in index[line]}
                                        if set(indexes) != expected_indexes:
                                            union_violations.add(('wrong candidate indexes', bucket))
                                        if len(lines) == 1 and indexes is not index[next(iter(lines))]:
                                            union_violations.add(('single hit retains union instead of list', bucket))
                            if 'lines' in state:
                                lines = state['lines']
                                index = state.get('candidates') or {}
                                ident = core._group_sort(state['g'])
                                expected = query_lines.get(ident, set()) & index.keys()
                                peak_lookup = max(peak_lookup, len(lines))
                                peak_index = max(peak_index, len(index))
                                observed.add((len(lines), len(expected)))
                                if lines != expected:
                                    metadata_violations.add(('lookup lines versus indexed hits', bucket,
                                                    len(lines), len(expected), len(index)))
                                if state.get('candidates') is None:
                                    metadata_violations.add(('lookup state outlived index', bucket))
                        return trace if frame.f_code is compare.__code__ else None

                    for group in before['groups'] + prepared['groups']:
                        group['occurrences'] = Metered(group['occurrences'])
                    before['groups'] = Metered(before['groups'])
                    prepared['groups'] = Metered(prepared['groups'])
                    original_trace = sys.gettrace()
                    try:
                        with patch.object(core, '_snapshot', return_value=(prepared, matcher)):
                            sys.settrace(trace)
                            result, current = compare(before, rows, KEY, path_map=mapping)
                    finally:
                        sys.settrace(original_trace)
                    # Capture search work before the exhaustive oracle traverses
                    # occurrences. Snapshot work is excluded, never bypassed in production.
                    prior_visits = [(g, g['occurrences'].visits) for g in before['groups']]
                    query_visits = [(g, g['occurrences'].visits) for g in current['groups']]
                    group_visits = before['groups'].visits
                    current_reads = prepared['groups'].reads + prepared['groups'].visits
                    self.assertEqual(result['changes'], slow_changes(before['groups'], current['groups'], mapping))
                    self.assertEqual(current, snapshot(rows, KEY))
                    self.assertEqual((before, prepared, rows, mapping), original)
                    self.assertEqual(result['summary'], {k: sum(c['classification'] == k for c in result['changes'])
                                                         for k in CLASSIFICATIONS})
                    self.assertGreater(result['summary']['new_content'], 0)
                    if mixed:
                        self.assertGreater(result['summary']['new_content_same_location'], 0)
                        self.assertGreater(result['summary']['uncomparable'], 0)
                    if mode == 'mapped' and mixed:
                        self.assertTrue(any(c['reason'] == 'current_path_unmapped' for c in result['changes']))
                    # Validation/privacy are mandatory. Only needed buckets get
                    # one prior indexing pass; same-path exact gets one sort pass.
                    forward = {p['old_path']: p['new_path'] for p in mapping or []}
                    known = {(g['rule_id'], forward.get(g['path'], g['path']), g['content_hmac'])
                             for g in before['groups'] if g['content_hmac']}
                    current_ids = {core._group_sort(g) for g in current['groups'] if g['content_hmac']}
                    for group, visits in prior_visits:
                        ident = (group['rule_id'], forward.get(group['path'], group['path']), group['content_hmac'])
                        passes = 2 + int(any(kind in group['path'] for kind in
                            ('/needed-', '/all-miss-', '/dense-hit-', '/partial-hit-', '/dense-partial-'))) + int(
                            ident in current_ids and group['path'] == ident[1])
                        self.assertEqual(visits, passes * len(group['occurrences']), group['path'])
                    self.assertLessEqual(group_visits, 12 * len(before['groups']))
                    self.assertLessEqual(current_reads, 7 * len(current['groups']))
                    violations = []
                    for group, visits in query_visits:
                        exact = core._group_sort(group) in known
                        passes = 0 if exact else (
                            0 if not group['content_hmac'] else
                            1 if '/all-miss-' in group['path'] else
                            2 if any(kind in group['path'] for kind in ('/needed-', '/dense-hit-', '/partial-hit-', '/dense-partial-')) else 0)
                        if visits != passes * len(group['occurrences']):
                            violations.append((group['path'], visits, passes * len(group['occurrences'])))
                    # An empty filtered index still requires ONE query collection
                    # pass, but no lookup line sets. Empty prior, blocked and
                    # unmapped buckets require zero search visits. No timing threshold.
                    self.assertEqual(violations, [])

                    # No timing threshold: all prior checks must pass before the
                    # proposed live metadata boundary is asserted on old runtime.
                    self.assertTrue(any(expected for actual, expected in observed))
                    self.assertTrue(any(not expected for actual, expected in observed))
                    self.assertGreater(peak_index, 0)
                    self.assertLessEqual(peak_lookup, peak_index)
                    self.assertEqual(sorted(metadata_violations, key=str)[:10], [])
                    if single_hit:
                        # Assert the resource proposal only AFTER all semantic,
                        # immutability, occurrence-pass and group-read contracts.
                        self.assertTrue({0, 1}.issubset(union_hits))
                        if mixed:
                            self.assertTrue(any(count > 1 for count in union_hits))
                        self.assertTrue(any(len(values) == 1 for values, _ in candidate_copies.values()))
                        self.assertTrue(any(len(values) > 1 for values, _ in candidate_copies.values()))
                        self.assertTrue(all(tuple(values) == original for values, original in candidate_copies.values()))
                        self.assertEqual(sorted(union_violations, key=str)[:10], [])

    def test_only_one_live_line_index_across_many_needed_buckets(self):
        class Metered(list):
            visits = 0

            def __iter__(self):
                for value in super().__iter__():
                    self.visits += 1
                    yield value

        for mapped in (False, True):
            with self.subTest(mapped=mapped):
                old, rows, mapping = [], [], [] if mapped else None
                buckets, size = 12, 8
                for bucket in range(buckets + 3):
                    source = f'src/bucket-{bucket:03d}.py'
                    target = source.replace('src/', 'lib/') if mapped else source
                    if mapped:
                        mapping.append({'old_path': source, 'new_path': target})
                    # Two rules at the same path exercise the full bucket key.
                    for rule in ('rule-a', 'rule-b'):
                        for i in range(size):
                            secret = f'SYNTHETIC_OLD_{bucket:03d}_{i:03d}'
                            old += [finding(secret, path=source, rule=rule, line=line)
                                    for line in (2 * i + 1, 2 * i + 2, 2 * i + 2)]
                            current_secret = secret if bucket == buckets else f'SYNTHETIC_NEW_{i:03d}'
                            if bucket == buckets + 1:
                                current_secret = None
                            rows += [finding(current_secret, path=target, rule=rule, line=line)
                                     for line in (2 * i + 1, 2 * i + 2, 2 * i + 2)]
                        if bucket == buckets + 2:
                            old.append(finding(None, path=source, rule=rule, line=100))
                before = snapshot(old, KEY)
                # Valid caller ledgers need not be sorted.
                before['groups'].reverse()
                for group in before['groups']:
                    group['occurrences'].reverse()
                    group['occurrences'] = Metered(group['occurrences'])
                before['groups'] = Metered(before['groups'])
                peak_indexes = peak_memberships = 0

                def trace(frame, event, arg):
                    nonlocal peak_indexes, peak_memberships
                    if frame.f_code is compare.__code__ and event == 'line':
                        # Observe real line->group-index dictionaries, deduplicating
                        # aliases. No mocked allocation, tracemalloc or time limit.
                        live = {}
                        for value in frame.f_locals.values():
                            if not isinstance(value, dict):
                                continue
                            for candidate in (value, *value.values()):
                                if (isinstance(candidate, dict) and candidate
                                        and all(type(k) is int and isinstance(v, list)
                                                and all(type(i) is int for i in v)
                                                for k, v in candidate.items())):
                                    live[id(candidate)] = sum(map(len, candidate.values()))
                        peak_indexes = max(peak_indexes, len(live))
                        peak_memberships = max(peak_memberships, sum(live.values()))
                    return trace if frame.f_code is compare.__code__ else None

                original_trace = sys.gettrace()
                try:
                    sys.settrace(trace)
                    result, current = compare(before, rows, KEY, path_map=mapping)
                finally:
                    sys.settrace(original_trace)
                group_visits = before['groups'].visits
                occurrence_visits = [(g, g['occurrences'].visits) for g in before['groups']]
                self.assertEqual(result['changes'], slow_changes(before['groups'], current['groups'], mapping))
                self.assertEqual(current, snapshot(rows, KEY))
                self.assertEqual(result['summary']['new_content_same_location'], buckets * 2 * size)
                # Each prior bucket is indexed once; no repeated full-ledger scans.
                self.assertLessEqual(group_visits, 12 * len(before['groups']))
                for group, visits in occurrence_visits:
                    bucket = int(group['path'].split('-')[-1][:-3])
                    passes = 2 + int(bucket < buckets) + int(bucket == buckets and not mapped)
                    self.assertEqual(visits, passes * len(group['occurrences']))
                self.assertEqual(peak_indexes, 1)
                self.assertEqual(peak_memberships, size * 2)

    def test_memberships_only_for_requested_replacement_lines(self):
        from scripts.secrets.benchmark_replacements import fixture
        from vulnwrench.secretledger import core

        class Metered(list):
            visits = 0
            reads = 0

            def __iter__(self):
                for value in super().__iter__():
                    self.visits += 1
                    yield value

            def __getitem__(self, key):
                self.reads += 1
                return super().__getitem__(key)

        for mapped in (False, True):
            for workload in ('sparse-lines', 'dense-lines', 'all-miss'):
                with self.subTest(mapped=mapped, workload=workload):
                    size, buckets = 8, 4
                    old, rows, mapping = fixture(size, mapped, workload, buckets, 16)
                    # Exact groups in needed buckets have many irrelevant lines;
                    # their lines must not expand the replacement index.
                    rows += [dict(r, File=r['File'].replace('src/', 'lib/') if mapped else r['File'],
                                  Fingerprint=r['Fingerprint'].replace('src/', 'lib/') if mapped else r['Fingerprint'])
                             for r in old if r['Secret'] == 'SYNTHETIC_BEFORE_00000000_END']
                    # Coexisting current unknowns also do not request lines.
                    for bucket in range(buckets):
                        path = f"{'lib' if mapped else 'src'}/shared-{bucket:05d}.py"
                        rows.append(finding(None, path=path, line=9000))
                    before = snapshot(old, KEY)
                    before['groups'].reverse()
                    for group in before['groups']:
                        group['occurrences'].reverse()
                        group['occurrences'] = Metered(group['occurrences'])
                    before['groups'] = Metered(before['groups'])
                    prepared, matcher = core._snapshot(rows, KEY)
                    requested = {}
                    known = {(g['rule_id'], g['path'].replace('src/', 'lib/') if mapped else g['path'],
                              g['content_hmac']) for g in before['groups']}
                    for group in prepared['groups']:
                        if group['content_hmac'] and core._group_sort(group) not in known:
                            requested.setdefault((group['rule_id'], group['path']), set()).update(
                                o['start_line'] for o in group['occurrences'])
                        group['occurrences'] = Metered(group['occurrences'])
                    prepared['groups'] = Metered(prepared['groups'])
                    peak_indexes = peak_memberships = peak_requested = 0
                    unexpected = set()

                    def trace(frame, event, arg):
                        nonlocal peak_indexes, peak_memberships, peak_requested
                        if frame.f_code is compare.__code__ and event == 'line':
                            live = {}
                            collected = frame.f_locals.get('requested_lines', set())
                            peak_requested = max(peak_requested, len(collected))
                            unexpected.update(collected - requested.get(frame.f_locals.get('path_ident'), set()))
                            for value in frame.f_locals.values():
                                if isinstance(value, dict):
                                    for candidate in (value, *value.values()):
                                        if (isinstance(candidate, dict) and candidate
                                                and all(type(k) is int and isinstance(v, list)
                                                        and all(type(i) is int for i in v)
                                                        for k, v in candidate.items())):
                                            live[id(candidate)] = sum(map(len, candidate.values()))
                                            unexpected.update(candidate.keys() - requested.get(
                                                frame.f_locals['path_ident'], set()))
                            peak_indexes = max(peak_indexes, len(live))
                            peak_memberships = max(peak_memberships, sum(live.values()))
                        return trace if frame.f_code is compare.__code__ else None

                    original_trace = sys.gettrace()
                    try:
                        with patch.object(core, '_snapshot', return_value=(prepared, matcher)):
                            sys.settrace(trace)
                            result, current = compare(before, rows, KEY, path_map=mapping)
                    finally:
                        sys.settrace(original_trace)
                    group_visits = before['groups'].visits
                    prior_visits = [g['occurrences'].visits for g in before['groups']]
                    query_visits = [g['occurrences'].visits for g in prepared['groups']]
                    current_reads = prepared['groups'].reads + prepared['groups'].visits
                    self.assertEqual(result['changes'], slow_changes(before['groups'], current['groups'], mapping))
                    self.assertEqual(current, snapshot(rows, KEY))
                    for group, visits in zip(before['groups'], prior_visits):
                        exact = group['content_hmac'] == snapshot([old[0]], KEY)['groups'][0]['content_hmac']
                        self.assertEqual(visits, (3 + int(exact and not mapped)) * len(group['occurrences']))
                    for group, visits in zip(prepared['groups'], query_visits):
                        ident = core._group_sort(group)
                        # One collection and one lookup pass; exact current lists are reused.
                        passes = 2 if group['content_hmac'] and ident not in known else 0
                        # Before implementation, the single lookup pass is also allowed.
                        self.assertLessEqual(visits, passes * len(group['occurrences']))
                    self.assertLessEqual(group_visits, 12 * len(before['groups']))
                    self.assertLessEqual(current_reads, 6 * len(prepared['groups']))
                    self.assertLessEqual(peak_indexes, 1)
                    self.assertEqual(peak_memberships, 0 if workload == 'all-miss' else
                                     size if workload == 'dense-lines' else 4)
                    self.assertEqual(unexpected, set())
                    self.assertLessEqual(peak_requested, max(map(len, requested.values())))

    def test_unused_buckets_do_not_visit_occurrences_for_line_indexing(self):
        class MeteredOccurrences(list):
            visits = 0

            def __iter__(self):
                for occurrence in super().__iter__():
                    self.visits += 1
                    yield occurrence

        # Validation and privacy each require one pass. Same-path exact
        # comparison additionally sorts the prior multiset; nothing else in
        # these cases needs prior occurrence visits. Count work, never time.
        for mapped in (False, True):
            path = 'lib/config.py' if mapped else 'src/config.py'
            mapping = [{'old_path': 'src/config.py', 'new_path': path}] if mapped else None
            for case in ('exact', 'redacted', 'missing', 'prior_unknown', 'empty', 'unmapped'):
                with self.subTest(mapped=mapped, case=case):
                    old = [finding(f'SYNTHETIC_KNOWN_{i:06d}', line=line)
                           for i in range(64) for line in (2 * i + 1, 2 * i + 2, 2 * i + 2)]
                    rows = [dict(row, File=path, Fingerprint=f"{path}:generic-api-key:{row['StartLine']}")
                            for row in old]
                    if case == 'missing':
                        rows = [finding(None, path=path, line=2)]
                    elif case == 'prior_unknown':
                        old.append(finding(None, line=200))
                        rows.append(finding('SYNTHETIC_UNMATCHED', path=path, line=1))
                    elif case == 'empty':
                        rows = []
                    elif case == 'unmapped':
                        mapping = []
                        rows = [finding('SYNTHETIC_UNMATCHED', path='unmapped.py', line=1)]
                    before = snapshot(old, KEY)
                    for group in before['groups']:
                        group['occurrences'] = MeteredOccurrences(group['occurrences'])
                    result, current = compare(before, rows, KEY, path_map=mapping,
                                              redacted=case == 'redacted')
                    for group in before['groups']:
                        exact_sort = case in ('exact', 'prior_unknown') and not mapped and group['content_hmac']
                        self.assertEqual(group['occurrences'].visits,
                                         (3 if exact_sort else 2) * len(group['occurrences']))
                    self.assertEqual(current, snapshot(rows, KEY, redacted=case == 'redacted'))
                    self.assertEqual(result['changes'], slow_changes(before['groups'], current['groups'], mapping))
                    if case == 'exact':
                        kind = 'same_secret_moved' if mapped else 'unchanged'
                        self.assertEqual({k: v for k, v in result['summary'].items() if v}, {kind: 64})
                    elif case in ('redacted', 'missing'):
                        self.assertEqual(result['summary']['uncomparable'], 65)
                        self.assertEqual(result['summary']['absent'], 0)

    def test_only_needed_rule_path_bucket_is_indexed_once(self):
        class MeteredOccurrences(list):
            visits = 0

            def __iter__(self):
                for occurrence in super().__iter__():
                    self.visits += 1
                    yield occurrence

        for mapped in (False, True):
            target = 'lib/needed.py' if mapped else 'src/needed.py'
            mapping = [{'old_path': 'src/needed.py', 'new_path': target}] if mapped else None
            old = [finding(f'SYNTHETIC_{rule}_{i:06d}', path=path, rule=rule, line=line)
                   for path, rule in [('src/needed.py', 'rule-a'), ('src/needed.py', 'rule-b'),
                                      ('src/unused.py', 'rule-a')]
                   for i in range(64) for line in (i + 1, 100, 100)]
            before = snapshot(old, KEY)
            for group in before['groups']:
                group['occurrences'] = MeteredOccurrences(group['occurrences'])
            # Many replacements share one bucket and overlap ALL 64 prior
            # groups on line 100. Other rule/path buckets must stay unindexed.
            rows = [finding(f'SYNTHETIC_REPLACEMENT_{i:06d}', path=target, rule='rule-a', line=line)
                    for i in range(32) for line in (i + 1, 100, 100)]
            rows += [finding('SYNTHETIC_rule-a_000000', path=target, rule='rule-a', line=1)]
            result, current = compare(before, rows, KEY, path_map=mapping)
            for group in before['groups']:
                needed = group['path'] == 'src/needed.py' and group['rule_id'] == 'rule-a'
                exact = needed and group['content_hmac'] == snapshot(rows[-1:], KEY)['groups'][0]['content_hmac']
                passes = 2 + int(needed) + int(exact and not mapped)
                self.assertEqual(group['occurrences'].visits, passes * len(group['occurrences']))
            self.assertEqual(result['changes'], slow_changes(before['groups'], current['groups'], mapping))
            replacements = [c for c in result['changes'] if c['classification'] == 'new_content_same_location']
            self.assertEqual(len(replacements), 32)
            self.assertTrue(all(len(c['previous']) == 64 for c in replacements))

    def test_sparse_replacements_do_not_rescan_all_prior_occurrences(self):
        class MeteredOccurrences(list):
            visits = 0

            def __iter__(self):
                for occurrence in super().__iter__():
                    type(self).visits += 1
                    yield occurrence

        size = 256
        before = snapshot([finding(f'SYNTHETIC_BEFORE_{i:06d}', line=i + 1)
                           for i in range(size)], KEY)
        for group in before['groups']:
            group['occurrences'] = MeteredOccurrences(group['occurrences'])
        rows = [finding(f'SYNTHETIC_AFTER_{i:06d}', line=i + 1) for i in range(size)]
        result, _ = compare(before, rows, KEY)
        self.assertEqual(result['summary']['new_content_same_location'], size)
        self.assertEqual(result['summary']['absent'], size)
        self.assertTrue(all(len(c['previous']) == 1 for c in result['changes']))
        # Validation, privacy and one indexing pass are allowed; all-pairs
        # occurrence visits are not. No wall-clock threshold or mocked matcher.
        self.assertLessEqual(MeteredOccurrences.visits, 8 * size)

    def test_all_overlaps_once_sorted_with_original_occurrence_multisets(self):
        old_rows = [finding(SECRET, line=4), finding(SECRET, line=4), finding(SECRET, line=9),
                    finding(OTHER, line=9), finding(OTHER, line=12),
                    finding('SYNTHETIC_NO_OVERLAP', line=13),
                    finding('SYNTHETIC_OTHER_RULE', line=4, rule='other-rule'),
                    finding('SYNTHETIC_OTHER_PATH', line=4, path='other.py')]
        before = snapshot(old_rows, KEY)
        rows = [finding('SYNTHETIC_REPLACED', line=4), finding('SYNTHETIC_REPLACED', line=9),
                finding('SYNTHETIC_REPLACED', line=9)]
        result, current = compare(before, rows, KEY)
        event = next(c for c in result['changes'] if c['current'])
        self.assertEqual(event['classification'], 'new_content_same_location')
        expected = [g for g in before['groups'] if len(g['occurrences']) >= 2]
        self.assertEqual(event['previous'], expected)
        self.assertEqual(len(event['previous']), 2)
        self.assertEqual(current['summary']['occurrences'], 3)
        self.assertEqual([len(g['occurrences']) for g in expected],
                         [len(g['occurrences']) for g in event['previous']])
        miss, _ = compare(before, [finding('SYNTHETIC_REPLACED', line=14)], KEY)
        self.assertEqual(miss['changes'][0]['classification'], 'new_content')
        self.assertEqual(miss['changes'][0]['previous'], [])

    def test_exact_then_unknown_then_line_precedence_across_mapped_path(self):
        before = snapshot([finding(SECRET, line=4), finding(OTHER, line=9), finding(None, line=50)], KEY)
        mapping = [{'old_path': 'src/config.py', 'new_path': 'lib/config.py'}]
        rows = [finding(SECRET, path='lib/config.py', line=9),
                finding('SYNTHETIC_NEW_KNOWN', path='lib/config.py', line=4),
                finding(None, path='lib/config.py', line=9)]
        result, _ = compare(before, rows, KEY, path_map=mapping)
        known = [c for c in result['changes'] if c['current'] and c['current']['content_hmac']]
        exact = next(c for c in known if c['classification'] == 'same_secret_moved')
        self.assertEqual([o['start_line'] for o in exact['previous'][0]['occurrences']], [4])
        uncertain = next(c for c in known if c['classification'] == 'uncomparable')
        self.assertEqual(uncertain['reason'], 'prior_content_unavailable')
        self.assertEqual([g['content_hmac'] for g in uncertain['previous']], [None])
        self.assertEqual(result['summary']['absent'], 0)
        self.assertEqual(result['summary']['new_content_same_location'], 0)
        self.assertEqual(result['summary']['uncomparable'], 4)

    def test_exhaustive_oracle_mapping_unknowns_order_and_immutability(self):
        rng = random.Random(6905)
        for iteration in range(60):
            mapping = [None, [], [{'old_path': 'a.py', 'new_path': 'b.py'},
                                 {'old_path': 'b.py', 'new_path': 'a.py'}]][iteration % 3]

            def report():
                rows = [finding(rng.choice([SECRET, OTHER, 'SYNTHETIC_THIRD', None, '[masked]']),
                                path=rng.choice(['a.py', 'b.py', 'c.py']), line=rng.randint(1, 4),
                                rule=rng.choice(['rule-a', 'rule-b'])) for _ in range(22)]
                rows += copy.deepcopy(rows[:3])
                return rows

            before, rows = snapshot(report(), KEY), report()
            redacted = iteration % 7 == 0
            original = copy.deepcopy((before, rows, mapping))
            result, current = compare(before, rows, KEY, path_map=mapping, redacted=redacted)
            expected = slow_changes(before['groups'], current['groups'], mapping)
            with self.subTest(iteration=iteration):
                self.assertEqual(result['changes'], expected)
                self.assertEqual(result['summary'], {k: sum(c['classification'] == k for c in expected)
                                                     for k in CLASSIFICATIONS})
                self.assertEqual(current['summary']['occurrences'], len(rows))
                self.assertEqual((before, rows, mapping), original)
                shuffled = copy.deepcopy(before)
                rng.shuffle(shuffled['groups'])
                rng.shuffle(rows)
                self.assertEqual(compare(shuffled, rows, KEY, path_map=mapping, redacted=redacted),
                                 (result, current))
                # Valid caller ledgers may have unsorted occurrence lists.
                # Prior evidence must preserve those lists exactly as supplied.
                for group in shuffled['groups']:
                    rng.shuffle(group['occurrences'])
                reordered, next_ledger = compare(shuffled, rows, KEY, path_map=mapping,
                                                  redacted=redacted)
                self.assertEqual(reordered['changes'],
                                 slow_changes(shuffled['groups'], next_ledger['groups'], mapping))


if __name__ == '__main__':
    unittest.main()
