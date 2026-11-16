"""Explicit known character offsets decorate resolved paths without text conversion."""

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

ROOT = Path(__file__).resolve().parents[2]
INVALID_OFFSET = (None, False, True, -2, 0.0, -1.0, 'SYNTHETIC_SECRET<script>|\n', [], {})
INVALID_LENGTH = (None, False, True, -1, 4.0, 'SYNTHETIC_SECRET<script>|\n', [], {})


class CharacterRangeTests(unittest.TestCase):
    def test_explicit_character_ranges_and_exact_provenance(self):
        for collection in ('locations', 'relatedLocations'):
            for mode in ('inline', 'index', 'dual'):
                for region in ({'charOffset': 0}, {'charOffset': 0, 'charLength': 4},
                               {'charOffset': 0, 'charLength': 0}, {'charOffset': 9, 'charLength': 0},
                               {'charOffset': 2**64, 'charLength': 2**64}):
                    with self.subTest(collection=collection, mode=mode, region=region):
                        data = ranged(region, collection, mode)
                        data['runs'][0]['columnKind'] = {'unconsumed': True}
                        data['runs'][0]['results'][0][collection][0]['message'] = {'text': PAYLOAD}
                        report = evaluate(data)
                        resolved = entry(report, collection)
                        self.assertEqual(resolved.get('sourceCharacterRange'), region)
                        pointer = f'/runs/0/results/0/{collection}/0'
                        self.assertEqual(resolved['regionSourcePointer'], pointer + '/physicalLocation/region')
                        self.assertEqual(resolved['sourcePointer'], pointer + '/physicalLocation/artifactLocation')
                        self.assertEqual(resolved.get('artifactSourcePointer'),
                                         '/runs/0/artifacts/0/location' if mode != 'inline' else None)
                        self.assertEqual(resolved['messageSourcePointer'], pointer + '/message/text')
                        self.assertEqual(resolved['message'], PAYLOAD)
                        self.assertEqual(resolved['displayPath'], '/workspace/link/../a<script>|[click].py')
                        for field in ('sourceLineRange', 'sourceColumnRange', 'sourceColumnUnit',
                                      'columnKindSourcePointer', 'sourceByteRange'):
                            self.assertNotIn(field, resolved)
                        self.assertEqual(report['evidence']['document'], data)
                        self.assertIn('/runs/0/columnKind', report['evidence']['uninterpretedFields'])
                        md = markdown_summary(report)
                        label = ', '.join(f'{k}={v}' for k, v in region.items())
                        self.assertIn('| ' + label.replace('=', '&#61;').replace(',', '&#44;') + ' |', md)
                        self.assertIn(pointer.replace('/', '&#47;') + '&#47;physicalLocation&#47;region', md)
                        self.assertIn('| ' + ESCAPED + ' |', md)
                        self.assertNotIn('<script>', md)

    def test_missing_offset_unset_sentinel_and_unconsumed_lengths(self):
        for collection in ('locations', 'relatedLocations'):
            for mode in ('inline', 'index', 'dual'):
                expected = evaluate(ranged(collection=collection, mode=mode))
                for region in (MISSING, {}, {'charLength': 4}, {'charLength': -1},
                               {'charOffset': -1}, {'charOffset': -1, 'charLength': 'raw'},
                               {'charLength': None}, {'charLength': False}, {'charLength': []},
                               {'charOffset': -1, 'charLength': None},
                               {'charLength': 'raw', 'startColumn': False}):
                    with self.subTest(collection=collection, mode=mode, region=region):
                        report = evaluate(ranged(region, collection, mode))
                        self.assertEqual(entry(report, collection), entry(expected, collection))
                        self.assertEqual(markdown_summary(report), markdown_summary(expected))
                        self.assertNotIn('Character range', markdown_summary(report))

    def test_invalid_consumed_character_values_have_fixed_diagnostics(self):
        for collection in ('locations', 'relatedLocations'):
            for mode in ('inline', 'index', 'dual'):
                for key, values, error in (('charOffset', INVALID_OFFSET, 'expected integer at least -1'),
                                           ('charLength', INVALID_LENGTH, 'expected nonnegative integer')):
                    for value in values:
                        with self.subTest(collection=collection, mode=mode, key=key, value=value):
                            with self.assertRaises(InputError) as caught:
                                evaluate(ranged({'charOffset': 0, key: value}, collection, mode))
                            self.assertEqual(str(caught.exception),
                                             f'/runs/0/results/0/{collection}/0/physicalLocation/region/{key}: {error}')
                with self.assertRaisesRegex(InputError, '/endLine: requires startLine$'):
                    evaluate(ranged({'endLine': 9, 'charOffset': 0}, collection, mode))

    def test_coexisting_coordinates_units_and_independent_markdown_tables(self):
        data = ranged({'startLine': 7, 'startColumn': 3, 'endColumn': 5,
                       'byteOffset': 21, 'byteLength': 8, 'charOffset': 0, 'charLength': 4})
        run = data['runs'][0]
        run['columnKind'] = 'utf16CodeUnits'
        location = run['results'][0]['locations'][0]
        location['message'] = {'markdown': PAYLOAD}
        run['results'][0]['locations'].append({'physicalLocation': {'artifactLocation': {'uri': 'plain.py'}}})
        run['results'][0]['relatedLocations'] = [{'physicalLocation': {'artifactLocation': {'index': 0},
                                                                    'region': {'startLine': 9}}}]
        report = evaluate(data)
        resolved = entry(report, 'locations')
        self.assertEqual(resolved['sourceCharacterRange'], {'charOffset': 0, 'charLength': 4})
        self.assertEqual(resolved['sourceByteRange'], {'byteOffset': 21, 'byteLength': 8})
        self.assertEqual(resolved['sourceLineRange'], {'startLine': 7})
        self.assertEqual(resolved['sourceColumnRange'], {'startColumn': 3, 'endColumn': 5})
        self.assertEqual(resolved['sourceColumnUnit'], 'utf16CodeUnits')
        self.assertEqual(resolved['columnKindSourcePointer'], '/runs/0/columnKind')
        md = markdown_summary(report)
        self.assertEqual(md.count('| Character range | Character region source pointer |'), 1)
        self.assertIn('&#46;py&#58;7 &#40;startColumn&#61;3&#44; endColumn&#61;5&#41; |', md)
        self.assertIn('charOffset&#61;0&#44; charLength&#61;4', md)
        self.assertIn('byteOffset&#61;21&#44; byteLength&#61;8', md)
        self.assertIn('|  |  |  |  |  |  |  |', md)
        self.assertIn('| ' + ESCAPED + ' |', md)
        # Defensive escaping also applies to externally constructed reports.
        resolved['sourceCharacterRange']['charLength'] = '<b>|[byte]\n'
        self.assertIn('&#60;b&#62;&#124;&#91;byte&#93; ', markdown_summary(report))

    def test_pathless_context_catalog_flows_snippets_stay_raw_without_io(self):
        for collection in ('locations', 'relatedLocations'):
            data = ranged({'charOffset': 0, 'charLength': 4, 'sourceLanguage': {'raw': True},
                           'snippet': {'text': 'DO_NOT_RENDER_😀'}}, collection, 'index')
            run = data['runs'][0]
            run['artifacts'][0]['region'] = {'charOffset': False}
            result = run['results'][0]
            result[collection][0]['physicalLocation']['contextRegion'] = {
                'charOffset': False, 'message': {'id': 'raw-region-message'}}
            for region in (None, {'charOffset': 'SYNTHETIC_SECRET', 'charLength': -1}):
                result[collection].append({'physicalLocation': {'region': region}, 'message': {'id': 'raw'}})
            result['codeFlows'] = [{'threadFlows': [{'locations': [{'location': {'physicalLocation': {
                'artifactLocation': {'uri': 'https://invalid'}, 'region': {'charOffset': False}}}}]}]}]
            original = copy.deepcopy(data)
            with patch('builtins.open', side_effect=AssertionError('file access')), \
                    patch('os.open', side_effect=AssertionError('file access')), \
                    patch('os.stat', side_effect=AssertionError('file access')), \
                    patch('os.getcwd', side_effect=AssertionError('CWD access')), \
                    patch('socket.socket', side_effect=AssertionError('network access')):
                report = evaluate(data)
                md = markdown_summary(report)
            self.assertEqual(entry(report, collection)['sourceCharacterRange'], {'charOffset': 0, 'charLength': 4})
            self.assertEqual(data, original)
            self.assertEqual(report['evidence']['document'], original)
            self.assertNotIn('DO_NOT_RENDER', md)
            self.assertNotIn('SYNTHETIC_SECRET', md)
            self.assertEqual(report['results'][0]['hasLocation'], collection == 'locations')
            self.assertEqual(report['totals']['unlocated'], int(collection != 'locations'))

    def test_characters_preserve_policy_component_fingerprint_and_digest_pairing(self):
        for collection in ('locations', 'relatedLocations'):
            for suppressed in (False, True):
                before = ranged({'startLine': 7, 'startColumn': 3}, collection, 'dual')
                run = before['runs'][0]
                run['columnKind'] = 'unicodeCodePoints'
                run['tool']['extensions'] = [{'name': 'Pack', 'rules': [
                    {'id': 'R1', 'defaultConfiguration': {'level': 'error'}}]}]
                result = run['results'][0]
                result['rule'] = {'index': 0, 'toolComponent': {'index': 0}}
                result['baselineState'] = 'unchanged'
                result[collection][0]['message'] = {'text': PAYLOAD}
                if suppressed:
                    result['suppressions'] = [{'kind': 'external', 'status': 'accepted'}]
                after = copy.deepcopy(before)
                after['runs'][0]['results'][0][collection][0]['physicalLocation']['region'].update(
                    charOffset=0, charLength=4)
                for policy in (Policy(), Policy(level='error'), Policy(ignore_unchanged=True),
                               Policy(require_execution_success=True)):
                    old, new = evaluate(before, policy), evaluate(after, policy)
                    self.assertEqual(old['totals'], new['totals'])
                    self.assertEqual(old['decision'], new['decision'])
                    del entry(new, collection)['sourceCharacterRange']
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

    def test_cli_invalid_characters_preserve_both_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            out, md = Path(directory) / 'out.json', Path(directory) / 'out.md'
            for collection in ('locations', 'relatedLocations'):
                for key, values, error in (('charOffset', INVALID_OFFSET, 'expected integer at least -1'),
                                           ('charLength', INVALID_LENGTH, 'expected nonnegative integer')):
                    for value in values:
                        out.write_text('keep json')
                        md.write_text('keep markdown')
                        data = ranged({'charOffset': 0, key: value}, collection)
                        proc = cli('check', '-', '--output', str(out), '--markdown', str(md), data=json.dumps(data))
                        self.assertEqual(proc.returncode, 2)
                        self.assertEqual(proc.stdout, '')
                        self.assertEqual(proc.stderr,
                                         f'vulnwrench sarif: /runs/0/results/0/{collection}/0/physicalLocation/region/{key}: {error}\n')
                        self.assertEqual(out.read_text(), 'keep json')
                        self.assertEqual(md.read_text(), 'keep markdown')


if __name__ == '__main__':
    unittest.main()
