"""Synthetic privacy and deterministic work-budget regressions."""
import copy
import itertools
import random
import unittest
from unittest.mock import patch

from vulnwrench.secretledger import LedgerError, compare, snapshot
from vulnwrench.secretledger.core import dumps
from vulnwrench.secretledger import core
from scripts.secrets.benchmark_privacy import KEY, synthetic_report


class PrivacyTests(unittest.TestCase):
    def test_large_report_does_not_rescan_metadata_for_every_sensitive_value(self):
        # Count complete substring searches, not elapsed time. This caught the
        # all-pairs bottleneck without a machine-dependent timing assertion.
        class MeteredText(str):
            searches = 0

            def __contains__(self, value):
                type(self).searches += 1
                return super().__contains__(value)

        rows = synthetic_report(256)
        for row in rows:
            row['RuleID'] = MeteredText(row['RuleID'])
        ledger = snapshot(rows, KEY)
        self.assertEqual(ledger['summary']['occurrences'], len(rows))
        self.assertLessEqual(MeteredText.searches, 16 * len(rows))

    def test_optimized_privacy_rejects_every_retained_field_and_sensitive_source(self):
        # Many distinct patterns force the scalable path; valid fingerprints
        # ensure privacy, rather than schema validation, rejects each injection.
        for source in ('Secret', 'Match'):
            for field in ('RuleID', 'File', 'Commit', 'Fingerprint'):
                rows = synthetic_report(80)
                target = rows[-1]
                raw = 'a' * 40 if field == 'Commit' else 'SYNTHETIC_INJECTED_Ω'
                if field == 'RuleID':
                    raw = 'SYNTHETIC-INJECTED'
                    target['RuleID'] = raw
                elif field == 'File':
                    target['File'] = 'src/' + raw + '.py'
                elif field == 'Commit':
                    target['Commit'] = raw
                # Leading ':' with empty commit is a supported fingerprint form.
                prefix = target['Commit'] + ':' if target['Commit'] else ':'
                target['Fingerprint'] = f"{prefix}{target['File']}:{target['RuleID']}:4"
                if field == 'Fingerprint':
                    raw = ':src/'  # exists only in fingerprint, not normalized path
                rows[0][source] = raw
                for redacted in (False, True):
                    with self.subTest(source=source, field=field, redacted=redacted):
                        with self.assertRaisesRegex(LedgerError, 'metadata overlaps'):
                            snapshot(rows, KEY, redacted=redacted)

    def test_prior_and_unused_map_paths_still_checked(self):
        rows = synthetic_report(80)
        raw = 'SYNTHETIC_PRIOR_OR_MAP_069'
        old_rows = synthetic_report(80)
        old_rows[-1]['File'] = raw
        old_rows[-1]['Fingerprint'] = raw + ':generic-api-key:4'
        before = snapshot(old_rows, KEY)
        rows[0]['Match'] = raw
        with self.assertRaisesRegex(LedgerError, 'metadata overlaps'):
            compare(before, rows, KEY)
        safe_before = snapshot(synthetic_report(80), KEY)
        for field in ('old_path', 'new_path'):
            mapping = [{'old_path': 'unused-old.py', 'new_path': 'unused-new.py'}]
            mapping[0][field] = raw
            with self.subTest(field=field), self.assertRaisesRegex(LedgerError, 'path map overlaps'):
                compare(safe_before, rows, KEY, path_map=mapping)
        collision = [{'old_path': 'src/file-00000000.py', 'new_path': 'src/file-00000001.py'}]
        with self.assertRaisesRegex(LedgerError, 'collision'):
            compare(safe_before, synthetic_report(80), KEY, path_map=collision)

    def test_unknowns_duplicates_order_and_inputs_preserved(self):
        rows = synthetic_report(80)
        before_rows = synthetic_report(80)
        # Match-only and arbitrary placeholders with explicit redaction.
        del rows[1]['Secret']
        rows[2]['Secret'] = '[redacted]'
        original = copy.deepcopy(rows)
        before = snapshot(before_rows, KEY)
        before_copy = copy.deepcopy(before)
        result, current = compare(before, rows, KEY)
        self.assertEqual(result['summary']['absent'], 0)
        self.assertEqual(result['summary']['new_content'], 0)
        self.assertEqual(current['summary']['occurrences'], len(rows))
        self.assertEqual(snapshot(rows[::-1], KEY), current)
        self.assertEqual(rows, original)
        self.assertEqual(before, before_copy)
        forced = snapshot(rows, KEY, redacted=True)
        self.assertEqual(forced['summary']['uncomparable_occurrences'], len(rows))
        output = dumps(result) + dumps(current)
        for row in rows:
            for field in ('Secret', 'Match'):
                if row.get(field):
                    self.assertNotIn(row[field], output)


class MatcherTests(unittest.TestCase):
    def test_exact_unicode_substrings_against_naive_oracle(self):
        rng = random.Random(69)
        values = [''.join(chars) for n in range(5)
                  for chars in itertools.product('abΩ', repeat=n)]
        values += ['she', 'a' * 200 + 'b', 'e\u0301', 'é', 'pre🌍post', 'a\x00b', '\ud800']
        for size in (0, 1, 16, 17, 40):
            for _ in range(12):
                patterns = {''.join(rng.choices('abΩx', k=rng.randrange(1, 9)))
                            for _ in range(size)}
                if size > 16:
                    patterns.update(['he', 'sheX', '🌍', 'e\u0301', '\ud800'])
                matcher = core._SensitiveMatcher(patterns)
                for value in values:
                    self.assertEqual(matcher.overlaps(value),
                                     any(raw in value for raw in patterns))

    def test_suffix_terminal_inheritance_and_field_boundaries(self):
        patterns = {'SYNTHETIC_PADDING_' + str(i) for i in range(20)} | {'he', 'sheX', 'pathrule'}
        matcher = core._SensitiveMatcher(patterns)
        self.assertTrue(matcher.overlaps('she'))  # failure link to terminal 'he'
        self.assertFalse(matcher.overlaps('path'))
        self.assertFalse(matcher.overlaps('rule'))  # no match across separate fields
        self.assertTrue(matcher.overlaps('pathrule'))
        self.assertFalse(matcher.overlaps('HE'))  # exact, case-sensitive semantics

    def test_maximum_field_length_and_impossible_patterns(self):
        patterns = {'SYNTHETIC_PADDING_' + str(i) for i in range(20)}
        patterns.update({'Ω' * 8192, 'x' * 8193})
        matcher = core._SensitiveMatcher(patterns)
        self.assertTrue(matcher.overlaps('Ω' * 8192))
        self.assertFalse(matcher.overlaps('Ω' * 8191))
        # Longer secrets cannot fit in any retained field, and do not consume
        # index states. Filtering never changes valid-metadata results.
        self.assertFalse(matcher.overlaps('x' * 8192))
        with patch.object(core, 'MAX_PRIVACY_STATES', 18):
            core._SensitiveMatcher({'x' * 8193} | {chr(0x400 + i) for i in range(17)})

    def test_index_limit_exact_boundary_and_sanitized_actionable_diagnostic(self):
        patterns = {chr(0x400 + i) for i in range(17)}
        with patch.object(core, 'MAX_PRIVACY_STATES', 18):
            matcher = core._SensitiveMatcher(patterns)
            self.assertTrue(matcher.overlaps(chr(0x400)))
        with patch.object(core, 'MAX_PRIVACY_STATES', 17):
            with self.assertRaises(LedgerError) as caught:
                core._SensitiveMatcher(patterns)
        message = str(caught.exception)
        self.assertIn('exceeds 17 states', message)
        self.assertIn('complete scan scope consistently', message)
        self.assertIn('rebuild the prior ledger', message)
        self.assertFalse(any(raw in message for raw in patterns))


if __name__ == '__main__':
    unittest.main()
