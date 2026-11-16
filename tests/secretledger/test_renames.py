"""Synthetic full-report regressions for explicitly mapped file renames."""
import copy
import json
import stat
import unittest

from vulnwrench.secretledger import LedgerError, compare, key_id, snapshot, validate_ledger
from vulnwrench.secretledger.core import dumps, markdown
import test_ledger as fixtures
from test_ledger import KEY, OTHER, SECRET, classes, finding


# Reuse CLI setup/assertions without inheriting/rerunning its test methods.
class RenameCliTests(unittest.TestCase):
    setUp = fixtures.CliTests.setUp
    run_cli = fixtures.CliTests.run_cli
    assert_private = fixtures.CliTests.assert_private
    assert_error = fixtures.CliTests.assert_error

    def test_mapping_cli_artifacts_and_invalid_inputs(self):
        new = finding(path='lib/config.py')
        self.report.write_text(json.dumps([new]))
        mapping = self.root / 'paths.json'
        mapping.write_text(json.dumps([{'old_path': 'src/config.py', 'new_path': 'lib/config.py'}]))
        output, ledger, md = (self.root / name for name in ('result.json', 'next.json', 'summary.md'))
        result = self.run_cli('compare', '--key-file', self.key, '--before', self.before,
                              '--report', self.report, '--path-map', mapping, '--output', output,
                              '--ledger-output', ledger, '--markdown', md)
        self.assertEqual(result.returncode, 0, result.stderr)
        comparison = json.loads(output.read_text())
        self.assertEqual(classes(comparison), ['same_secret_moved'])
        self.assertEqual(json.loads(ledger.read_text()), snapshot([new], KEY))
        for path in (output, ledger, md):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            for raw in (SECRET, OTHER, new['Match'], KEY.decode()):
                self.assertNotIn(raw, path.read_text())
        self.assert_private(result)
        for raw in ('null', '{}', 'not JSON',
                    '[{"old_path":"src/config.py","new_path":"../' + SECRET + '"}]',
                    '[{"old_path":"src/config.py","old_path":"' + SECRET + '","new_path":"lib/config.py"}]',
                    '[{"old_path":"src/config.py","new_path":"lib/config.py"},'
                    '{"old_path":"other.py","new_path":"lib/config.py"}]',
                    json.dumps([{'old_path': SECRET, 'new_path': 'unobserved.py'}])):
            mapping.write_text(raw)
            bad_output = self.root / 'bad.json'
            with self.subTest(raw=raw):
                self.assert_error(self.run_cli('compare', '--key-file', self.key, '--before', self.before,
                                                '--report', self.report, '--path-map', mapping,
                                                '--output', bad_output, '--ledger-output', self.root / 'bad-ledger.json',
                                                '--markdown', self.root / 'bad.md'))
                self.assertFalse(bad_output.exists())
                self.assertFalse((self.root / 'bad-ledger.json').exists())
                self.assertFalse((self.root / 'bad.md').exists())
        original = mapping.read_bytes()
        self.assert_error(self.run_cli('compare', '--key-file', self.key, '--before', self.before,
                                        '--report', self.report, '--path-map', mapping, '--output', mapping))
        self.assertEqual(mapping.read_bytes(), original)

    def test_implicit_collision_cli_fails_before_any_output(self):
        self.before.write_text(dumps(snapshot([finding(), finding(OTHER, path='lib/config.py')], KEY)))
        self.report.write_text(json.dumps([finding(path='lib/config.py')]))
        mapping = self.root / 'paths.json'
        mapping.write_text(json.dumps([{'old_path': 'src/config.py', 'new_path': 'lib/config.py'}]))
        output = self.root / 'bad.json'
        result = self.run_cli('compare', '--key-file', self.key, '--before', self.before,
                              '--report', self.report, '--path-map', mapping, '--output', output)
        self.assert_error(result)
        self.assertIn('collision', result.stderr)
        self.assertFalse(output.exists())

    def test_empty_or_missing_map_filename_is_not_silently_ignored(self):
        for path in ('', self.root / SECRET):
            with self.subTest(path=path):
                self.assert_error(self.run_cli('compare', '--key-file', self.key, '--before', self.before,
                                                '--report', self.report, '--path-map', path))


class RenameTests(unittest.TestCase):
    def setUp(self):
        self.mapping = [{'old_path': 'src/config.py', 'new_path': 'lib/config.py'}]
        self.before = snapshot([finding()], KEY)

    def compare(self, rows, *, before=None, mapping=None, **kwargs):
        return compare(self.before if before is None else before, rows, KEY,
                       path_map=self.mapping if mapping is None else mapping, **kwargs)

    def test_pure_rename_requires_explicit_mapping_and_preserves_evidence(self):
        rows = [finding(path='lib/config.py')]
        self.assertEqual(classes(compare(self.before, rows, KEY)[0]), ['new_content', 'absent'])
        original_before, original_map = copy.deepcopy(self.before), copy.deepcopy(self.mapping)
        result, current = self.compare(rows)
        self.assertEqual(classes(result), ['same_secret_moved'])
        self.assertEqual(result['changes'][0]['reason'], 'same_content_rule_and_mapped_path')
        self.assertEqual(result['changes'][0]['previous'], self.before['groups'])
        self.assertEqual(current, snapshot(rows, KEY))
        self.assertEqual(validate_ledger(current, key_id(KEY)), current)
        self.assertEqual(self.before, original_before)
        self.assertEqual(self.mapping, original_map)
        self.assertEqual(classes(compare(current, rows, KEY)[0]), ['unchanged'])

    def test_mapped_content_change_and_rule_boundary(self):
        result, _ = self.compare([finding(OTHER, path='lib/config.py')])
        self.assertEqual(classes(result), ['new_content_same_location', 'absent'])
        self.assertEqual(result['changes'][0]['previous'], self.before['groups'])
        result, _ = self.compare([finding(OTHER, path='lib/config.py', line=8)])
        self.assertEqual(classes(result), ['new_content', 'absent'])
        result, _ = self.compare([finding(path='lib/config.py', rule='different-rule')])
        self.assertEqual(classes(result), ['new_content', 'absent'])
        with self.assertRaisesRegex(LedgerError, 'key ID mismatch'):
            compare(self.before, [finding(path='lib/config.py')], b'x'*32, path_map=self.mapping)

    def test_redacted_or_missing_content_never_deduplicates(self):
        for old, new in ((None, SECRET), (SECRET, None), (None, None)):
            before = snapshot([finding(old)], KEY)
            result, _ = self.compare([finding(new, path='lib/config.py')], before=before)
            self.assertEqual(classes(result), ['uncomparable', 'uncomparable'])
        result, _ = self.compare([finding(path='lib/config.py')], redacted=True)
        self.assertEqual(classes(result), ['uncomparable', 'uncomparable'])

    def test_unmapped_paths_are_unknown_only_in_mapping_mode(self):
        result, _ = self.compare([finding(path='unmapped.py')], mapping=[])
        self.assertEqual(classes(result), ['uncomparable', 'uncomparable'])
        self.assertEqual([c['reason'] for c in result['changes']],
                         ['current_path_unmapped', 'prior_path_unmapped'])
        # Unchanged paths remain an implicit identity; empty reports remain valid.
        result, _ = self.compare([finding()], mapping=[])
        self.assertEqual(classes(result), ['unchanged'])
        self.assertEqual(classes(self.compare([], mapping=[])[0]), ['uncomparable'])
        # A declared target has a correspondence even if one side has no findings.
        self.assertEqual(classes(self.compare([])[0]), ['absent'])
        self.assertEqual(classes(self.compare([finding(path='lib/config.py')], before=snapshot([], KEY))[0]),
                         ['new_content'])

    def test_exact_content_precedence_and_occurrence_preservation(self):
        before = snapshot([finding(), finding(None)], KEY)
        rows = [finding(path='lib/config.py'), finding(path='lib/config.py', line=9),
                finding(path='lib/config.py', line=9), finding(None, path='lib/config.py')]
        result, current = self.compare(rows, before=before)
        self.assertEqual(result['summary']['same_secret_moved'], 1)
        self.assertEqual(result['summary']['uncomparable'], 2)
        self.assertEqual(result['summary']['absent'], 0)
        self.assertEqual(current['summary']['occurrences'], 4)

    def test_partial_mapping_never_infers_other_renames_or_changes_shared_paths(self):
        before = snapshot([finding(), finding(path='unmapped-old.py'), finding(path='stable.py')], KEY)
        rows = [finding(path='lib/config.py'), finding(path='unmapped-new.py'), finding(path='stable.py')]
        result, _ = self.compare(rows, before=before)
        self.assertEqual(result['summary']['same_secret_moved'], 1)
        self.assertEqual(result['summary']['unchanged'], 1)
        self.assertEqual(result['summary']['uncomparable'], 2)
        self.assertEqual(result['summary']['absent'], 0)
        self.assertEqual(result['summary']['new_content'], 0)

    def test_normalization_and_simultaneous_swaps(self):
        mapping = [{'old_path': './src//config.py', 'new_path': r'.\lib\config.py'}]
        result, _ = self.compare([finding(path='lib/config.py')], mapping=mapping)
        self.assertEqual(result['path_map'], self.mapping)
        self.assertEqual(classes(result), ['same_secret_moved'])
        before = snapshot([finding(path='a.py'), finding(OTHER, path='b.py')], KEY)
        rows = [finding(path='b.py'), finding(OTHER, path='a.py')]
        swap = [{'old_path': 'a.py', 'new_path': 'b.py'}, {'old_path': 'b.py', 'new_path': 'a.py'}]
        result, _ = self.compare(rows, before=before, mapping=swap)
        self.assertEqual(classes(result), ['same_secret_moved', 'same_secret_moved'])
        self.assertEqual(result, self.compare(list(reversed(rows)), before=before, mapping=list(reversed(swap)))[0])

    def test_ambiguous_mappings_and_traversal_reject(self):
        for mapping in ({}, ['src/config.py'], [{'old_path': 'a.py'}],
                        [{'old_path': 'a.py', 'new_path': 'b.py', 'extra': SECRET}],
                        [{'old_path': 'a.py', 'new_path': 'b.py'}, {'old_path': './a.py', 'new_path': 'c.py'}],
                        [{'old_path': 'a.py', 'new_path': 'b.py'}, {'old_path': 'c.py', 'new_path': './b.py'}],
                        [{'old_path': 'a.py', 'new_path': 'b.py'}, {'old_path': 'a.py', 'new_path': 'b.py'}]):
            with self.subTest(mapping=mapping), self.assertRaises(LedgerError):
                self.compare([], mapping=mapping)
        for path in ('../bad', r'a\..\bad', '/etc/config', r'C:\config', r'\\host\share',
                     'a.tar!inner', '.', 'a\nb', 'a\x00b', 'a:b', '', None):
            for field in ('old_path', 'new_path'):
                mapping = copy.deepcopy(self.mapping)
                mapping[0][field] = path
                with self.subTest(path=path, field=field), self.assertRaises(LedgerError):
                    self.compare([], mapping=mapping)

    def test_mapping_colliding_with_implicit_prior_identity_rejects(self):
        before = snapshot([finding(), finding(OTHER, path='lib/config.py')], KEY)
        with self.assertRaisesRegex(LedgerError, 'collision'):
            self.compare([finding(path='lib/config.py')], before=before)

    def test_map_metadata_privacy_and_markdown_escaping(self):
        for field in ('old_path', 'new_path'):
            mapping = [{'old_path': 'unobserved.py', 'new_path': 'other.py'}]
            mapping[0][field] = SECRET
            with self.subTest(field=field), self.assertRaisesRegex(LedgerError, 'sensitive'):
                self.compare([finding(path='lib/config.py')], mapping=mapping)
        target = 'lib/<script>|[x].py'
        result, current = self.compare([finding(path=target)],
                                       mapping=[{'old_path': 'src/config.py', 'new_path': target}])
        text = markdown(result)
        self.assertNotIn('<script>', text)
        self.assertIn('&#60;script&#62;&#124;&#91;x&#93;', text)
        for raw in (SECRET, OTHER, KEY.decode(), 'source_token='):
            self.assertNotIn(raw, dumps(result) + dumps(current) + text)


if __name__ == '__main__':
    unittest.main()
