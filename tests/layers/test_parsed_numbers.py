"""Parsed metadata must contain finite floats before any caller content is copied."""
from copy import deepcopy
import json
import math
import sys
import unittest
from unittest.mock import patch

from vulnwrench.layers import InputError, compare, explain
import test_parsed_cycles as fixtures
from test_parsed_cycles import FIELDS, PRIVATE, PROVENANCE, graph

NONFINITE = (float('nan'), float('inf'), float('-inf'))
FINITE = [None, True, False, 0, -42, 123456789012345678901234567890,
          0.0, -0.0, 1.25, -2.5e-2, 5e-324, 1.7976931348623157e308, '雪', {}, []]


class ParsedNumberTests(unittest.TestCase):
    inputs = fixtures.ParsedCycleTests.inputs

    def bad_inputs(self, field, number, shape='mixed'):
        values = self.inputs(field)
        metadata = {'scalar': number, 'object': {'inert': number},
                    'array': [0, number], 'mixed': [None, {PRIVATE: [number]}]}[shape]
        values[field][PRIVATE] = metadata
        return values

    def reject_unchanged(self, call, values):
        original = graph(values)
        limit = sys.getrecursionlimit()
        with self.assertRaisesRegex(InputError, 'non-finite numeric metadata') as caught:
            call(**values)
        self.assertIn(str(caught.exception).split(':')[0],
                      ('report', 'base config', 'image config', 'base manifest', 'image manifest'))
        self.assertNotIn(PRIVATE, str(caught.exception))
        self.assertNotIn('/caller/', str(caught.exception))
        for token in ('nan', 'inf', 'Infinity'):
            self.assertNotIn(token, str(caught.exception))
        self.assertEqual(graph(values), original)
        self.assertEqual(sys.getrecursionlimit(), limit)

    def test_each_document_rejects_all_nonfinite_float_values_in_objects_and_arrays(self):
        # Prior runtime returns provenance for every case; strict serialization fails.
        for field in FIELDS:
            for number in NONFINITE:
                for shape in ('scalar', 'object', 'array', 'mixed'):
                    with self.subTest(field=field, number=number, shape=shape):
                        self.reject_unchanged(explain, self.bad_inputs(field, number, shape))

    def test_both_compare_snapshots_reject_each_document_independently(self):
        for side in ('before', 'after'):
            for field in FIELDS:
                for number in NONFINITE:
                    good, bad = self.inputs(field), self.bad_inputs(field, number)
                    values = {s+'_'+key: value for s, docs in
                              [(side, bad), ('after' if side == 'before' else 'before', good)]
                              for key, value in docs.items()}
                    with self.subTest(side=side, field=field, number=number):
                        self.reject_unchanged(compare, values)

    def test_rejects_before_any_finding_or_provenance_copy(self):
        for field in FIELDS:
            with self.subTest(field=field), patch('vulnwrench.layers.core.deepcopy',
                                                  side_effect=AssertionError('copied before validation')):
                self.reject_unchanged(explain, self.bad_inputs(field, float('nan')))

    def test_nonfinite_metadata_in_nested_schema_objects_is_not_skipped(self):
        for field in FIELDS:
            for number in NONFINITE:
                values = self.inputs(field); document = values[field]
                if field == 'report':
                    locations = [document['Metadata'], document['Results'][0],
                                 document['Results'][0]['Vulnerabilities'][0]]
                elif field.endswith('_config'):
                    locations = [document['rootfs'], document['history'][0]]
                else:
                    locations = [document['config'], document['layers'][0]]
                for index, location in enumerate(locations):
                    location[PRIVATE] = [number]
                    with self.subTest(field=field, number=number, location=index):
                        self.reject_unchanged(explain, values)
                    del location[PRIVATE]

    def test_deep_nonfinite_detection_is_iterative_without_a_parsed_depth_limit(self):
        for field in FIELDS:
            values = self.inputs(field); root = []; node = root
            for _ in range(2 * sys.getrecursionlimit()):
                child = {}; node.append(child); child['next'] = []; node = child['next']
            node.append(float('-inf')); values[field][PRIVATE] = root
            with self.subTest(field=field), patch('sys.setrecursionlimit',
                                                  side_effect=AssertionError('changed recursion limit')):
                self.reject_unchanged(explain, values)

    def test_shared_completed_metadata_does_not_hide_a_later_nonfinite_value(self):
        for field in FIELDS:
            values = self.bad_inputs(field, float('nan'))
            shared = {'finite': FINITE.copy()}
            values[field][PRIVATE] = [shared, shared, values[field][PRIVATE]]
            with self.subTest(field=field):
                self.reject_unchanged(explain, values)

    def test_finite_values_types_aliases_and_serialization_survive_explain_and_compare(self):
        for field in FIELDS:
            values = self.inputs(field); shared = {'finite': deepcopy(FINITE)}
            values[field][PRIVATE] = {'first': shared, 'again': [shared, shared]}
            original = deepcopy(values)
            expected = json.dumps(values[field], allow_nan=False)
            output = explain(**values)
            both = {side+'_'+key: value for side in ('before', 'after') for key, value in values.items()}
            result = compare(**both)
            with self.subTest(field=field):
                json.dumps(output, allow_nan=False); json.dumps(result, allow_nan=False)
                for doc in [output, *result['snapshots'].values()]:
                    provenance = doc['provenance'][PROVENANCE[field]]
                    self.assertEqual(json.dumps(provenance, allow_nan=False), expected)
                    metadata = provenance[PRIVATE]
                    self.assertIs(metadata['first'], metadata['again'][0])
                    self.assertIs(metadata['again'][0], metadata['again'][1])
                    self.assertIsNot(metadata['first'], shared)
                    finite = metadata['first']['finite']
                    self.assertEqual([type(x) for x in finite], [type(x) for x in FINITE])
                    self.assertEqual(math.copysign(1, finite[7]), -1)
                    finite.append('output mutation')
                self.assertEqual(values, original)


if __name__ == '__main__':
    unittest.main()
