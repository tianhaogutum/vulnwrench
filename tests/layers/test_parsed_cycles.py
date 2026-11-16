"""Reject cyclic caller metadata while retaining shared acyclic JSON values."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from vulnwrench.layers import InputError, compare, explain
from test_base_manifest import A, B, C, D, E, F, manifest_for

ROOT = Path(__file__).resolve().parents[2]
PRIVATE = 'PRIVATE /caller/metadata/path'
FIELDS = ('report', 'base_config', 'image_config', 'base_manifest', 'image_manifest')
PROVENANCE = dict(zip(FIELDS, ('report', 'baseConfig', 'imageConfig', 'baseManifest', 'imageManifest')))


def graph(value):
    """Record caller graph identities/edges without recursive equality on cycles."""
    seen, pending = {}, [value]
    while pending:
        node = pending.pop()
        if not isinstance(node, (dict, list)) or id(node) in seen:
            continue
        children = list(node.values()) if isinstance(node, dict) else node
        seen[id(node)] = (type(node), tuple(node) if isinstance(node, dict) else len(node),
                          tuple(id(child) for child in children))
        pending.extend(children)
    return seen


class ParsedCycleTests(unittest.TestCase):
    def inputs(self, manifest=None):
        values = {key: json.loads((ROOT / 'examples' / 'layers' / name).read_bytes())
                  for key, name in [('report', 'upgrade-after.json'),
                                    ('base_config', 'upgraded-base.json'),
                                    ('image_config', 'upgraded-image.json')]}
        for field, digests, mapping in [('base_manifest', [E, F], {E: D, F: B}),
                                         ('image_manifest', [E, F, A], {E: D, F: B, A: C})]:
            if manifest not in (field, 'both'):
                continue
            config = field.replace('manifest', 'config')
            raw = json.dumps(values[config]).encode()
            values[config] = raw
            values[field] = manifest_for(raw, digests)
            values['base_digest_map' if field == 'base_manifest' else 'digest_map'] = mapping
        return values

    def cyclic_inputs(self, field, kind):
        values = self.inputs(field)
        document = values[field]
        if kind == 'root':
            document[PRIVATE] = document
        else:
            cycle = {}
            if kind == 'object':
                cycle[PRIVATE] = cycle
            elif kind == 'array':
                cycle = []
                cycle.append(cycle)
            elif kind == 'mixed':
                cycle[PRIVATE] = [cycle]
            elif kind == 'shared_then_cycle':
                shared = {'finite': [1, None, '雪']}
                cycle.update(first=shared, second=shared, late=[cycle])
            else:
                raise AssertionError(kind)
            document[PRIVATE] = cycle
        return values

    def reject_unchanged(self, call, values):
        original = graph(values)
        limit = sys.getrecursionlimit()
        with self.assertRaisesRegex(InputError, 'cyclic') as caught:
            call(**values)
        self.assertNotIn(PRIVATE, str(caught.exception))
        self.assertNotIn('/caller/', str(caught.exception))
        self.assertEqual(graph(values), original)
        self.assertEqual(sys.getrecursionlimit(), limit)

    def test_each_parsed_document_rejects_object_array_and_indirect_cycles(self):
        # Prior implementation returns cyclic provenance; json.dumps then fails.
        for field in FIELDS:
            for kind in ('root', 'object', 'array', 'mixed', 'shared_then_cycle'):
                with self.subTest(field=field, kind=kind):
                    self.reject_unchanged(explain, self.cyclic_inputs(field, kind))

    def test_both_compare_snapshots_reject_each_document_independently(self):
        for side in ('before', 'after'):
            for field in FIELDS:
                for kind in ('object', 'array', 'mixed'):
                    bad = self.cyclic_inputs(field, kind)
                    good = self.inputs(field)
                    values = {s + '_' + k: v for s, docs in
                              [(side, bad), ('after' if side == 'before' else 'before', good)]
                              for k, v in docs.items()}
                    with self.subTest(side=side, field=field, kind=kind):
                        self.reject_unchanged(compare, values)

    def test_rejects_before_any_finding_or_provenance_copy(self):
        for field in FIELDS:
            values = self.cyclic_inputs(field, 'mixed')
            with self.subTest(field=field), patch('vulnwrench.layers.core.deepcopy',
                                                  side_effect=AssertionError('copied before validation')):
                self.reject_unchanged(explain, values)

    def test_cycles_in_nested_metadata_are_not_skipped(self):
        for field in FIELDS:
            values = self.inputs(field)
            document = values[field]
            if field == 'report':
                locations = [document['Metadata'], document['Results'][0],
                             document['Results'][0]['Vulnerabilities'][0]]
            elif field.endswith('_config'):
                locations = [document['rootfs'], document['history'][0]]
            else:
                locations = [document['config'], document['layers'][0]]
            for index in range(len(locations)):
                # Remove each rejected cycle before checking the next location.
                cycle = []; cycle.append({PRIVATE: cycle})
                locations[index][PRIVATE] = cycle
                with self.subTest(field=field, location=index):
                    self.reject_unchanged(explain, values)
                del locations[index][PRIVATE]

    def test_deep_cycle_is_iterative_and_does_not_change_recursion_limit(self):
        for field in FIELDS:
            values = self.inputs(field)
            root = []; node = root
            for _ in range(2 * sys.getrecursionlimit()):
                child = {}; node.append(child); child['next'] = []; node = child['next']
            node.append(root)
            values[field][PRIVATE] = root
            with self.subTest(field=field), patch('sys.setrecursionlimit',
                                                  side_effect=AssertionError('changed recursion limit')):
                self.reject_unchanged(explain, values)

    def test_shared_acyclic_metadata_is_preserved_and_independently_copied(self):
        for field in FIELDS:
            values = self.inputs(field)
            shared = {'nested': [None, True, False, 1, -0.0, 1.25, '雪', {}, []]}
            values[field][PRIVATE] = {'first': shared, 'second': [shared, shared]}
            original = deepcopy(values)
            expected = json.dumps(json.loads(json.dumps(values[field])), sort_keys=True, allow_nan=False)
            output = explain(**values)
            provenance = output['provenance'][PROVENANCE[field]]
            with self.subTest(field=field):
                self.assertEqual(json.dumps(provenance, sort_keys=True, allow_nan=False), expected)
                metadata = provenance[PRIVATE]
                self.assertIs(metadata['first'], metadata['second'][0])
                self.assertIs(metadata['second'][0], metadata['second'][1])
                self.assertIsNot(metadata['first'], shared)
                json.dumps(output, allow_nan=False)
                metadata['first']['nested'].append('output mutation')
                self.assertEqual(values, original)

    def test_compare_retains_shared_metadata_in_all_parsed_documents(self):
        for side in ('before', 'after'):
            values = {s + '_' + k: v for s in ('before', 'after') for k, v in self.inputs('both').items()}
            # Configs must be raw when manifests are supplied; the other test covers parsed configs.
            for field in ('report', 'base_manifest', 'image_manifest'):
                shared = {'inert': [0, 'metadata']}
                values[side + '_' + field][PRIVATE] = [shared, shared]
            original = deepcopy(values)
            output = compare(**values)
            with self.subTest(side=side):
                json.dumps(output, allow_nan=False)
                for field in ('report', 'base_manifest', 'image_manifest'):
                    copied = output['snapshots'][side]['provenance'][PROVENANCE[field]][PRIVATE]
                    self.assertIs(copied[0], copied[1])
                    copied[0]['inert'].append('output mutation')
                self.assertEqual(values, original)
        # Without manifests, both parsed configs are retained on both snapshots too.
        values = self.inputs()
        shared = {'inert': []}
        for value in values.values():
            value[PRIVATE] = [shared, shared]
        original = deepcopy(values)
        output = compare(**{s + '_' + k: v for s in ('before', 'after') for k, v in values.items()})
        json.dumps(output, allow_nan=False)
        for snapshot in output['snapshots'].values():
            for field in ('report', 'baseConfig', 'imageConfig'):
                copied = snapshot['provenance'][field][PRIVATE]
                self.assertIs(copied[0], copied[1])
                self.assertIsNot(copied[0], shared)
        self.assertEqual(values, original)


if __name__ == '__main__':
    unittest.main()
