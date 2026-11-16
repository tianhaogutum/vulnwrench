"""Literal region messages have provenance separate from location messages."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulnwrench.sarifgate import InputError, Policy, compare_bytes, evaluate, markdown_summary
from .test_cli import cli
from .test_line_ranges import MISSING, entry, ranged
from .test_primary_messages import ESCAPED, PAYLOAD


def invalid_messages():
    cases = [(v, '', 'expected object') for v in (None, [], True, 7, 'SYNTHETIC_SECRET')]
    cases += [(v, '', 'text or markdown required; id-only messages are unsupported')
              for v in ({}, {'id': 'SYNTHETIC_SECRET'}, {'arguments': ['raw']})]
    for field in ('text', 'markdown', 'id'):
        for value in (None, [], {}, True, 7, ''):
            cases.append(({'text': 'valid', 'markdown': 'valid', field: value},
                          '/' + field, 'expected nonempty string'))
    return cases


class RegionMessageTests(unittest.TestCase):
    def test_literals_preference_provenance_and_escaping(self):
        for collection in ('locations', 'relatedLocations'):
            for mode in ('inline', 'index', 'dual'):
                for message, selected in (({'text': PAYLOAD}, 'text'), ({'markdown': PAYLOAD}, 'markdown'),
                    ({'text': PAYLOAD, 'markdown': 'DO_NOT_RENDER', 'id': 'ignored',
                      'arguments': ['DO_NOT_EXPAND']}, 'text')):
                    with self.subTest(collection=collection, mode=mode, selected=selected):
                        data = ranged({'message': message}, collection, mode)
                        data['runs'][0]['columnKind'] = {'raw': True}
                        location = data['runs'][0]['results'][0][collection][0]
                        location['message'] = {'markdown': 'LOCATION_MESSAGE'}
                        report = evaluate(data)
                        resolved = entry(report, collection)
                        pointer = f'/runs/0/results/0/{collection}/0'
                        self.assertEqual(resolved.get('regionMessage'), PAYLOAD)
                        self.assertEqual(resolved['regionMessageSourcePointer'],
                                         pointer + '/physicalLocation/region/message/' + selected)
                        self.assertEqual(resolved['message'], 'LOCATION_MESSAGE')
                        self.assertEqual(resolved['messageSourcePointer'], pointer + '/message/markdown')
                        self.assertEqual(resolved['sourcePointer'], pointer + '/physicalLocation/artifactLocation')
                        self.assertEqual(resolved.get('artifactSourcePointer'),
                                         '/runs/0/artifacts/0/location' if mode != 'inline' else None)
                        for key in ('sourceLineRange', 'sourceColumnRange', 'sourceColumnUnit',
                                    'sourceByteRange', 'sourceCharacterRange', 'regionSourcePointer'):
                            self.assertNotIn(key, resolved)
                        md = markdown_summary(report)
                        self.assertIn('| Message | Region message | Region message source pointer |', md)
                        self.assertIn('| LOCATION_MESSAGE'.replace('_', '&#95;') + ' | ' + ESCAPED + ' |', md)
                        self.assertIn(pointer.replace('/', '&#47;') +
                                      '&#47;physicalLocation&#47;region&#47;message&#47;' + selected, md)
                        for text in ('<script>', 'DO_NOT_RENDER', 'DO_NOT_EXPAND'):
                            self.assertNotIn(text, md)
                        self.assertEqual(report['evidence']['document'], data)
                        self.assertIn('/runs/0/columnKind', report['evidence']['uninterpretedFields'])

    def test_absence_and_independent_tables_and_blank_cells(self):
        for collection in ('locations', 'relatedLocations'):
            expected = evaluate(ranged(collection=collection))
            for region in (MISSING, {}, {'charLength': 'raw', 'snippet': {'message': None}}):
                report = evaluate(ranged(region, collection))
                self.assertEqual(entry(report, collection), entry(expected, collection))
                self.assertEqual(markdown_summary(report), markdown_summary(expected))
            data = ranged({'message': {'text': 'region only'}}, collection)
            result = data['runs'][0]['results'][0]
            plain = {'physicalLocation': {'artifactLocation': {'uri': 'plain.py'}}}
            result[collection].append(copy.deepcopy(plain))
            other = 'relatedLocations' if collection == 'locations' else 'locations'
            result[other] = [copy.deepcopy(plain)]
            md = markdown_summary(evaluate(data))
            self.assertEqual(md.count('| Region message | Region message source pointer |'), 1)
            self.assertIn('plain&#46;py |', md)
            table = md.split('## Locations' if collection == 'locations' else '## Related locations')[1]
            self.assertTrue(any('plain&#46;py' in row and row.endswith(' |  |  |') for row in table.splitlines()))

    def test_invalid_consumed_messages_have_fixed_diagnostics(self):
        for collection in ('locations', 'relatedLocations'):
            for mode in ('inline', 'index', 'dual'):
                for message, suffix, reason in invalid_messages():
                    with self.subTest(collection=collection, mode=mode, message=message):
                        with self.assertRaises(InputError) as caught:
                            evaluate(ranged({'message': message}, collection, mode))
                        self.assertEqual(str(caught.exception),
                            f'/runs/0/results/0/{collection}/0/physicalLocation/region/message{suffix}: {reason}')
        resolved = entry(evaluate(ranged({'message': {'text': ' \n\t'}})), 'locations')
        self.assertEqual(resolved['regionMessage'], ' \n\t')

    def test_coordinates_units_and_shifted_exact_pointers(self):
        for collection in ('locations', 'relatedLocations'):
            for coordinates in ({'charOffset': 0, 'charLength': 4}, {'byteOffset': 0, 'byteLength': 0},
                                {'startLine': 7}, {'startLine': 7, 'endLine': 9, 'startColumn': 3,
                                 'endColumn': 1, 'byteOffset': 21, 'charOffset': 0}):
                data = ranged({**coordinates, 'message': {'markdown': PAYLOAD}}, collection, 'dual')
                run = data['runs'][0]
                run['columnKind'] = 'unicodeCodePoints'
                run['results'][0][collection].insert(0, {'physicalLocation': {'region': {'message': None}}})
                run['results'].insert(0, {'message': {'text': 'unlocated'}})
                data['runs'].insert(0, {'tool': {'driver': {'name': 'Empty'}}, 'results': []})
                report = evaluate(data)
                resolved = report['results'][1]['resolvedLocations' if collection == 'locations' else
                                                 'resolvedRelatedLocations'][0]
                self.assertEqual(resolved['regionMessageSourcePointer'],
                                 f'/runs/1/results/1/{collection}/1/physicalLocation/region/message/markdown')
                self.assertEqual(resolved['artifactSourcePointer'], '/runs/1/artifacts/0/location')
                for field, keys in (('sourceLineRange', ('startLine', 'endLine')),
                                    ('sourceByteRange', ('byteOffset', 'byteLength')),
                                    ('sourceCharacterRange', ('charOffset', 'charLength')),
                                    ('sourceColumnRange', ('startColumn', 'endColumn'))):
                    values = {k: coordinates[k] for k in keys if k in coordinates}
                    self.assertEqual(resolved.get(field), values or None)
                if 'startColumn' in coordinates:
                    self.assertEqual(resolved['sourceColumnUnit'], 'unicodeCodePoints')
                    self.assertEqual(resolved['columnKindSourcePointer'], '/runs/1/columnKind')
                self.assertIn(ESCAPED, markdown_summary(report))

    def test_pathless_context_catalog_codeflows_raw_and_no_io(self):
        for collection in ('locations', 'relatedLocations'):
            data = ranged({'message': {'text': PAYLOAD}, 'snippet': {'text': 'DO_NOT_RENDER'}}, collection, 'index')
            run = data['runs'][0]
            bad = {'message': {'id': 'SYNTHETIC_SECRET'}}
            run['artifacts'][0]['region'] = copy.deepcopy(bad)
            result = run['results'][0]
            result[collection][0]['physicalLocation']['contextRegion'] = copy.deepcopy(bad)
            result[collection].extend({'physicalLocation': {'region': {'message': message}}}
                                     for message, _, _ in invalid_messages())
            result['codeFlows'] = [{'threadFlows': [{'locations': [{'location': {'physicalLocation': {
                'artifactLocation': {'uri': 'https://invalid'}, 'region': copy.deepcopy(bad)}}}]}]}]
            original = copy.deepcopy(data)
            with patch('builtins.open', side_effect=AssertionError('file access')), \
                    patch('os.open', side_effect=AssertionError('file access')), \
                    patch('os.stat', side_effect=AssertionError('file access')), \
                    patch('os.getcwd', side_effect=AssertionError('CWD access')), \
                    patch('socket.socket', side_effect=AssertionError('network access')):
                report = evaluate(data)
                md = markdown_summary(report)
            self.assertEqual(entry(report, collection)['regionMessage'], PAYLOAD)
            self.assertEqual(data, original)
            self.assertEqual(report['evidence']['document'], original)
            self.assertIn(f'/runs/0/results/0/{collection}', report['evidence']['uninterpretedFields'])
            self.assertEqual(report['results'][0]['hasLocation'], collection == 'locations')
            self.assertEqual(report['totals']['unlocated'], int(collection != 'locations'))
            self.assertNotIn('DO_NOT_RENDER', md)
            self.assertNotIn('SYNTHETIC_SECRET', md)

    def test_messages_preserve_policy_component_fingerprint_and_digest_pairing(self):
        for collection in ('locations', 'relatedLocations'):
            for suppressed in (False, True):
                before = ranged({'startLine': 7, 'startColumn': 3, 'charOffset': 0, 'byteOffset': 0}, collection, 'dual')
                run = before['runs'][0]
                run['columnKind'] = 'utf16CodeUnits'
                run['tool']['extensions'] = [{'name': 'Pack', 'rules': [
                    {'id': 'R1', 'defaultConfiguration': {'level': 'error'}}]}]
                result = run['results'][0]
                result['rule'] = {'index': 0, 'toolComponent': {'index': 0}}
                result['baselineState'] = 'unchanged'
                result[collection][0]['message'] = {'text': 'location message'}
                if suppressed:
                    result['suppressions'] = [{'kind': 'external', 'status': 'accepted'}]
                after = copy.deepcopy(before)
                after['runs'][0]['results'][0][collection][0]['physicalLocation']['region']['message'] = {'text': PAYLOAD}
                for policy in (Policy(), Policy(level='error'), Policy(ignore_unchanged=True),
                               Policy(require_execution_success=True)):
                    old, new = evaluate(before, policy), evaluate(after, policy)
                    self.assertEqual(old['totals'], new['totals'])
                    self.assertEqual(old['decision'], new['decision'])
                    for key in ('regionMessage', 'regionMessageSourcePointer'):
                        del entry(new, collection)[key]
                    self.assertEqual(old['results'], new['results'])
                old, new = (json.dumps(d).encode() for d in (before, after))
                manifest = {side: [{'runIndex': 0, 'pairId': 'only'}] for side in ('baseline', 'current')}
                manifest['inputSha256'] = {'baseline': hashlib.sha256(old).hexdigest(),
                                           'current': hashlib.sha256(new).hexdigest()}
                report = compare_bytes(new, old, fingerprint='primary/v1', run_pairing=manifest)
                self.assertTrue(report['baselineComparison']['runPairing']['applied'])
                self.assertEqual(report['baselineComparison']['counts'],
                                 {'retained': 1, 'newly_observed': 0, 'absent': 0, 'ambiguous': 0})
                stale = compare_bytes(new + b' ', old, fingerprint='primary/v1', run_pairing=manifest)
                self.assertFalse(stale['baselineComparison']['runPairing']['applied'])

    def test_cli_invalid_region_messages_preserve_both_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            out, md = Path(directory) / 'out.json', Path(directory) / 'out.md'
            for collection in ('locations', 'relatedLocations'):
                for message, suffix, reason in invalid_messages():
                    out.write_text('keep json')
                    md.write_text('keep markdown')
                    data = ranged({'message': message}, collection)
                    proc = cli('check', '-', '--output', str(out), '--markdown', str(md), data=json.dumps(data))
                    self.assertEqual(proc.returncode, 2)
                    self.assertEqual(proc.stdout, '')
                    self.assertEqual(proc.stderr,
                        f'vulnwrench sarif: /runs/0/results/0/{collection}/0/physicalLocation/region/message{suffix}: {reason}\n')
                    self.assertEqual(out.read_text(), 'keep json')
                    self.assertEqual(md.read_text(), 'keep markdown')


if __name__ == '__main__':
    unittest.main()
