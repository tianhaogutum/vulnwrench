from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from vulnwrench.secretledger import LedgerError, compare, key_id, snapshot, validate_ledger
from vulnwrench.secretledger.core import dumps, load_json, markdown, normalize_path

ROOT = Path(__file__).resolve().parents[2]
KEY = b'0123456789abcdef0123456789abcdef'  # PUBLIC TEST ONLY
SECRET = 'SYNTHETIC_NOT_A_REAL_CREDENTIAL_123'
OTHER = 'SYNTHETIC_REPLACEMENT_CREDENTIAL_456'


def finding(secret=SECRET, path='src/config.py', line=4, commit='', rule='generic-api-key'):
    return {'RuleID': rule, 'File': path, 'StartLine': line, 'Commit': commit,
            'Secret': secret, 'Match': 'source_token=' + str(secret),
            'Fingerprint': f'{commit+":" if commit else ""}{path}:{rule}:{line}',
            'Description': 'SYNTHETIC_DESCRIPTION', 'Author': 'SYNTHETIC_AUTHOR',
            'Email': 'synthetic@example.invalid', 'Message': 'SYNTHETIC_MESSAGE',
            'Line': 'SYNTHETIC_RAW_SOURCE', 'Tags': ['synthetic']}


def classes(result):
    return [change['classification'] for change in result['changes']]


class CoreTests(unittest.TestCase):
    def test_hmac_exact_and_grouping(self):
        rows = [finding(), finding(line=9, commit='a'*40)]
        ledger = snapshot(rows, KEY)
        self.assertEqual(ledger['summary'], {'groups': 1, 'occurrences': 2, 'uncomparable_occurrences': 0})
        self.assertEqual(ledger['groups'][0]['content_hmac'], hmac.new(KEY, SECRET.encode(), hashlib.sha256).hexdigest())
        self.assertEqual(len(ledger['key_id']), 64)
        self.assertEqual(validate_ledger(ledger, key_id(KEY)), ledger)

    def test_rule_and_path_are_identity_boundaries(self):
        ledger = snapshot([finding(), finding(path='other.py'), finding(rule='other-rule')], KEY)
        self.assertEqual(ledger['summary']['groups'], 3)

    def test_unchanged(self):
        result, current = compare(snapshot([finding()], KEY), [finding()], KEY)
        self.assertEqual(classes(result), ['unchanged'])
        self.assertEqual(current, snapshot([finding()], KEY))

    def test_moves_and_commit_churn_group(self):
        result, current = compare(snapshot([finding(commit='a'*40)], KEY),
                                  [finding(line=10, commit='b'*40), finding(line=11, commit='c'*40)], KEY)
        self.assertEqual(classes(result), ['same_secret_moved'])
        self.assertEqual(len(current['groups'][0]['occurrences']), 2)

    def test_new_secret_same_fingerprint(self):
        old = finding()
        new = finding(OTHER)
        self.assertEqual(old['Fingerprint'], new['Fingerprint'])
        result, _ = compare(snapshot([old], KEY), [new], KEY)
        self.assertEqual(classes(result), ['new_content_same_location', 'absent'])

    def test_new_and_absent(self):
        result, _ = compare(snapshot([finding()], KEY), [finding(OTHER, path='new.py')], KEY)
        self.assertEqual(classes(result), ['new_content', 'absent'])

    def test_renamed_file_is_new_and_absent(self):
        result, _ = compare(snapshot([finding()], KEY), [finding(path='renamed.py')], KEY)
        self.assertEqual(classes(result), ['new_content', 'absent'])

    def test_absence_is_not_remediation(self):
        result, _ = compare(snapshot([finding()], KEY), [], KEY)
        self.assertEqual(classes(result), ['absent'])

    def test_empty_reports(self):
        result, ledger = compare(snapshot([], KEY), [], KEY)
        self.assertEqual(result['changes'], [])
        self.assertEqual(ledger['summary']['groups'], 0)

    def test_common_redactions_and_match_only_remain_unknown(self):
        for value in (None, '', ' ', 'REDACTED', '<redacted>', '***', 'abc***xyz', '[masked]', '[removed]'):
            with self.subTest(value=value):
                row = finding(value)
                ledger = snapshot([row], KEY)
                self.assertIsNone(ledger['groups'][0]['content_hmac'])
                result, _ = compare(ledger, [row], KEY)
                self.assertTrue(all(c == 'uncomparable' for c in classes(result)))
        row = finding()
        del row['Secret']
        self.assertIsNone(snapshot([row], KEY)['groups'][0]['content_hmac'])

    def test_explicit_redacted_for_arbitrary_placeholder(self):
        ledger = snapshot([finding('CUSTOM-HIDDEN-VALUE')], KEY, redacted=True)
        self.assertIsNone(ledger['groups'][0]['content_hmac'])
        result, _ = compare(snapshot([finding()], KEY), [finding()], KEY, redacted=True)
        self.assertEqual(classes(result), ['uncomparable', 'uncomparable'])

    def test_prior_unknown_cannot_match_clear_content(self):
        result, _ = compare(snapshot([finding(None)], KEY), [finding(line=9)], KEY)
        self.assertEqual(classes(result), ['uncomparable', 'uncomparable'])

    def test_current_unknown_prevents_absence_claim(self):
        result, _ = compare(snapshot([finding()], KEY), [finding('REDACTED', line=50)], KEY)
        self.assertEqual(classes(result), ['uncomparable', 'uncomparable'])

    def test_changed_key_rejected(self):
        with self.assertRaisesRegex(LedgerError, 'key ID mismatch'):
            compare(snapshot([finding()], KEY), [finding()], b'x'*32)

    def test_path_normalization(self):
        self.assertEqual(normalize_path('./src//config.py'), 'src/config.py')
        self.assertEqual(normalize_path(r'.\src\config.py'), 'src/config.py')
        result, _ = compare(snapshot([finding(path='./src//config.py')], KEY), [finding()], KEY)
        self.assertEqual(classes(result), ['same_secret_moved'])  # retained native fingerprint changed

    def test_bad_paths(self):
        for value in ('../bad', 'src/../bad', '/etc/config', r'C:\config', r'\\host\share',
                      'a.tar!inner.txt', '.', 'a\nb', 'a\x00b', 'a:b', ''):
            with self.subTest(path=value), self.assertRaises(LedgerError):
                snapshot([finding(path=value)], KEY)

    def test_unknown_schema_and_missing_fields(self):
        for report in ({}, {'findings': []}, [1], [dict(finding(), UnsupportedField=SECRET)]):
            with self.subTest(report_type=type(report).__name__), self.assertRaises(LedgerError):
                snapshot(report, KEY)
        for field in ('RuleID', 'File', 'StartLine', 'Commit', 'Fingerprint'):
            row = finding()
            del row[field]
            with self.subTest(field=field), self.assertRaises(LedgerError):
                snapshot([row], KEY)

    def test_invalid_required_values(self):
        for field, value in [('StartLine', True), ('StartLine', 0), ('StartLine', -1),
                             ('StartLine', 1.0), ('StartLine', 2**31), ('RuleID', 'bad rule'),
                             ('Commit', '1234'), ('Fingerprint', ''), ('Secret', 1),
                             ('Match', []), ('Secret', '\ud800')]:
            row = finding()
            row[field] = value
            with self.subTest(field=field), self.assertRaises(LedgerError):
                snapshot([row], KEY)

    def test_no_secret_match_source_or_author_in_artifacts(self):
        rows = [finding(), finding(OTHER)]
        ledger = snapshot(rows, KEY)
        result, current = compare(ledger, [finding(line=7)], KEY)
        output = dumps(ledger) + dumps(result) + dumps(current) + markdown(result)
        for row in rows:
            for field in ('Secret', 'Match', 'Author', 'Email', 'Message', 'Line', 'Description'):
                self.assertNotIn(row[field], output)
        self.assertNotIn('"Secret"', output)
        self.assertNotIn('"Match"', output)

    def test_sensitive_metadata_rejected_including_cross_row(self):
        for field in ('File', 'Fingerprint', 'RuleID'):
            row = finding(OTHER)
            row[field] = SECRET
            with self.subTest(field=field), self.assertRaises(LedgerError):
                snapshot([finding(), row], KEY)

    def test_consistent_cross_row_sensitive_path_rejected(self):
        with self.assertRaisesRegex(LedgerError, 'metadata overlaps'):
            snapshot([finding(), finding(OTHER, path=SECRET)], KEY)

    def test_both_native_fingerprint_variants(self):
        for commit in ('', 'a'*40, 'b'*64):
            row = finding(commit=commit)
            self.assertEqual(snapshot([row], KEY)['summary']['groups'], 1)
            row['Fingerprint'] = 'src/config.py:generic-api-key:4'
            self.assertEqual(snapshot([row], KEY)['summary']['groups'], 1)
        row = finding()
        row['Fingerprint'] = ':src/config.py:generic-api-key:4'
        self.assertEqual(snapshot([row], KEY)['summary']['groups'], 1)

    def test_inconsistent_fingerprints_rejected(self):
        for fp in ('other.py:generic-api-key:4', 'src/config.py:other:4',
                   'src/config.py:generic-api-key:5', '../bad:generic-api-key:4',
                   SECRET, 'a'*40 + ':src/config.py:generic-api-key:4'):
            row = finding()
            row['Fingerprint'] = fp
            with self.subTest(fingerprint=fp), self.assertRaises(LedgerError):
                snapshot([row], KEY)

    def test_prior_metadata_overlapping_current_secret_rejected(self):
        before = snapshot([finding(OTHER, path=SECRET)], KEY)
        with self.assertRaises(LedgerError):
            compare(before, [finding()], KEY)

    def test_ledger_schema_tampering(self):
        original = snapshot([finding()], KEY)
        mutations = [lambda x: x.update(extra=SECRET),
                     lambda x: x.update(schema='other'),
                     lambda x: x['summary'].update(groups=999),
                     lambda x: x['groups'][0].update(content_hmac='not-a-digest'),
                     lambda x: x['groups'][0].update(comparability='unknown'),
                     lambda x: x['groups'][0].update(path='../escape'),
                     lambda x: x['groups'][0].update(occurrences=[]),
                     lambda x: x['groups'].append(copy.deepcopy(x['groups'][0])),
                     lambda x: x['groups'][0]['occurrences'][0].update(Secret=SECRET)]
        for mutate in mutations:
            data = copy.deepcopy(original)
            mutate(data)
            with self.subTest(mutation=mutate), self.assertRaises(LedgerError):
                compare(data, [], KEY)

    def test_order_is_deterministic_and_exact_duplicates_retained(self):
        rows = [finding(), finding(OTHER, path='z.py'), finding(line=3), finding()]
        self.assertEqual(snapshot(rows, KEY), snapshot(list(reversed(rows)), KEY))
        self.assertEqual(snapshot(rows, KEY)['summary']['occurrences'], 4)

    def test_markdown_escapes_html_and_table_injection(self):
        result, _ = compare(snapshot([], KEY), [finding(path='src/<script>|[x].py')], KEY)
        text = markdown(result)
        self.assertNotIn('<script>', text)
        self.assertIn('&#60;script&#62;&#124;&#91;x&#93;', text)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root / 'private.key'
        self.key.write_bytes(KEY)
        self.key.chmod(0o600)
        self.report = self.root / 'report.json'
        self.report.write_text(json.dumps([finding()]))
        self.before = self.root / 'before.json'
        self.before.write_text(dumps(snapshot([finding()], KEY)))

    def run_cli(self, *args):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'secrets', *map(str, args)],
                              cwd=ROOT, capture_output=True, text=True, timeout=60)

    def assert_private(self, result):
        text = result.stdout + result.stderr
        for raw in (SECRET, OTHER, 'source_token=', 'SYNTHETIC_AUTHOR', 'SYNTHETIC_RAW_SOURCE'):
            self.assertNotIn(raw, text)
        self.assertNotIn('Traceback', text)

    def assert_error(self, result):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assert_private(result)

    def test_help_and_bad_arguments(self):
        result = self.run_cli('--help')
        self.assertEqual(result.returncode, 0)
        self.assertIn('snapshot', result.stdout)
        self.assert_error(self.run_cli('--unknown=' + SECRET))
        self.assert_error(self.run_cli(SECRET))

    def test_init_creates_key_permissions_and_gitignore_without_overwrite(self):
        new = self.root / 'local.key'
        result = self.run_cli('init', '--key-file', new)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(new.read_bytes()), 32)
        self.assertEqual(stat.S_IMODE(new.stat().st_mode), 0o600)
        self.assertEqual((self.root / '.gitignore').read_text(), '/local.key\n')
        original = new.read_bytes()
        self.assert_error(self.run_cli('init', '--key-file', new))
        self.assertEqual(new.read_bytes(), original)

    def test_init_keeps_ignore_rules_and_counters_negation(self):
        (self.root / '.gitignore').write_text('!local.key')
        result = self.run_cli('init', '--key-file', self.root / 'local.key')
        self.assertEqual(result.returncode, 0)
        self.assertEqual((self.root / '.gitignore').read_text(), '!local.key\n/local.key\n')

    def test_init_symlink_ignore_rejected(self):
        target = self.root / 'target'
        target.write_text('unchanged')
        (self.root / '.gitignore').symlink_to(target)
        self.assert_error(self.run_cli('init', '--key-file', self.root / 'new.key'))
        self.assertEqual(target.read_text(), 'unchanged')
        self.assertFalse((self.root / 'new.key').exists())

    def test_snapshot_and_compare_e2e(self):
        new = finding(OTHER)
        self.report.write_text(json.dumps([new]))
        output, ledger, md = (self.root / name for name in ('result.json', 'next.json', 'summary.md'))
        result = self.run_cli('compare', '--key-file', self.key, '--before', self.before,
                              '--report', self.report, '--output', output,
                              '--ledger-output', ledger, '--markdown', md)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(classes(json.loads(output.read_text())), ['new_content_same_location', 'absent'])
        self.assertEqual(json.loads(ledger.read_text()), snapshot([new], KEY))
        for path in (output, ledger, md):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            for raw in (SECRET, OTHER, new['Match'], new['Author']):
                self.assertNotIn(raw, path.read_text())
        self.assert_private(result)
        stdout = self.run_cli('snapshot', '--key-file', self.key, '--report', self.report)
        self.assertEqual(stdout.returncode, 0)
        self.assertEqual(json.loads(stdout.stdout), snapshot([new], KEY))
        self.assert_private(stdout)

    def test_snapshot_redacted_cli(self):
        result = self.run_cli('snapshot', '--key-file', self.key, '--report', self.report, '--redacted')
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(json.loads(result.stdout)['groups'][0]['content_hmac'])

    def test_missing_key_and_report(self):
        for key, report in ((self.root / SECRET, self.report), (self.key, self.root / SECRET)):
            self.assert_error(self.run_cli('snapshot', '--key-file', key, '--report', report))

    def test_insecure_key_permissions(self):
        self.key.chmod(0o644)
        self.assert_error(self.run_cli('snapshot', '--key-file', self.key, '--report', self.report))

    def test_symlink_key_rejected(self):
        link = self.root / 'link.key'
        link.symlink_to(self.key)
        self.assert_error(self.run_cli('snapshot', '--key-file', link, '--report', self.report))

    def test_bad_key_length(self):
        for length in (0, 31, 33):
            self.key.write_bytes(b'x'*length)
            self.assert_error(self.run_cli('snapshot', '--key-file', self.key, '--report', self.report))

    def test_mixed_key_ids_failure_does_not_create_output(self):
        self.key.write_bytes(b'x'*32)
        out = self.root / 'result.json'
        self.assert_error(self.run_cli('compare', '--key-file', self.key, '--report', self.report,
                                        '--before', self.before, '--output', out))
        self.assertFalse(out.exists())

    def test_failure_redaction_malformed_unsupported_duplicate_and_nonfinite(self):
        bad = [SECRET, '{"'+SECRET+'":', json.dumps({'findings':[finding()]}),
               '[{"Secret":"'+SECRET+'","Secret":"'+SECRET+'"}]',
               '[NaN]', '[Infinity]', json.dumps([dict(finding(), Unsupported=SECRET)]),
               json.dumps([finding(path='../' + SECRET)]), json.dumps([finding(path=SECRET)])]
        for raw in bad:
            self.report.write_text(raw)
            out = self.root / 'result.json'
            with self.subTest(index=bad.index(raw)):
                self.assert_error(self.run_cli('snapshot', '--key-file', self.key,
                                                '--report', self.report, '--output', out))
                self.assertFalse(out.exists())

    def test_no_clobber_inputs_outputs_or_symlinks(self):
        for target in (self.report, self.key, self.before):
            original = target.read_bytes()
            self.assert_error(self.run_cli('snapshot', '--key-file', self.key, '--report', self.report, '--output', target))
            self.assertEqual(target.read_bytes(), original)
        link = self.root / 'link.json'
        link.symlink_to(self.report)
        self.assert_error(self.run_cli('snapshot', '--key-file', self.key, '--report', self.report, '--output', link))
        output = self.root / 'output.json'
        self.assert_error(self.run_cli('compare', '--key-file', self.key, '--report', self.report,
                                        '--before', self.before, '--output', output, '--ledger-output', output))
        self.assertFalse(output.exists())

    def test_output_io_error_never_echoes_filename(self):
        self.assert_error(self.run_cli('snapshot', '--key-file', self.key, '--report', self.report,
                                        '--output', self.root / SECRET / 'out.json'))

    def test_nonregular_inputs_fail_without_hanging(self):
        fifo = self.root / 'input.fifo'
        os.mkfifo(fifo)
        self.assert_error(self.run_cli('snapshot', '--key-file', self.key, '--report', fifo))
        self.assert_error(self.run_cli('snapshot', '--key-file', fifo, '--report', self.report))

    def test_duplicate_json_and_invalid_utf8_library(self):
        for raw in (b'{"x":1,"x":2}', b'\xff'):
            self.report.write_bytes(raw)
            with self.assertRaises(LedgerError):
                load_json(self.report)


if __name__ == '__main__':
    unittest.main()
