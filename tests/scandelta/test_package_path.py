"""Normalized package-path selection refines target selection without changing evidence."""
from copy import deepcopy
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts' / 'delta'))
from verify_package_path import CONTRACT, check_selection, documents, verify
from vulnwrench.scandelta import InputError, compare
from vulnwrench.scandelta.cli import markdown


class PackagePathTests(unittest.TestCase):
    def test_whole_entries_qualifiers_aliases_empty_and_other_path(self):
        for case in CONTRACT['cases']:
            docs = documents(case)
            original = deepcopy(docs)
            batch = compare(*docs)
            for request in CONTRACT['positive']:
                with self.subTest(case=case['name'], request=request):
                    default = compare(*docs, explain_advisory=request['advisory'])
                    selected = compare(*docs, explain_advisory=request['advisory'], explain_target=request['target'],
                                       explain_package_path=request['package_path'])
                    check_selection(selected, default, batch, request)
            self.assertEqual(docs, original)

    def test_none_preserves_default_target_and_native_bytes(self):
        docs = documents(CONTRACT['cases'][1])
        for selectors in ({}, {'explain_advisory': CONTRACT['advisory']},
                          {'explain_advisory': CONTRACT['advisory'], 'explain_target': CONTRACT['target']},
                          {'explain_advisory': CONTRACT['advisory'], 'explain_side': 'after', 'explain_artifact_id': 'unknown-0'}):
            default = compare(*docs, **selectors)
            omitted = compare(*docs, **selectors, explain_package_path=None)
            self.assertEqual(default, omitted)
            self.assertEqual(markdown(default), markdown(omitted))

    def test_invalid_and_inexact_paths(self):
        for path in ([], {}, 1, True, False, 0, 1.2, ' ', '\t', 'bad\0SYNTHETIC_SECRET', 'bad\nSYNTHETIC_SECRET',
                     CONTRACT['package_path'].strip(), './' + CONTRACT['package_path'],
                     CONTRACT['package_path'].upper(), CONTRACT['package_path'] + '/child', '', 'node_modules',
                     '/workspace/2/package.json', 'pkg:npm/demo@1.0', 'SYNTHETIC_SECRET_ABSENT'):
            with self.subTest(path=path), self.assertRaises(InputError) as raised:
                compare(*documents(CONTRACT['cases'][1]), explain_advisory=CONTRACT['advisory'],
                        explain_target=CONTRACT['target'], explain_package_path=path)
            self.assertNotIn('SYNTHETIC_SECRET', str(raised.exception))

    def test_missing_and_native_selectors(self):
        for path in ('', CONTRACT['package_path']):
            for selectors in ({}, {'explain_advisory': CONTRACT['advisory']}, {'explain_target': CONTRACT['target']}):
                with self.subTest(path=path, selectors=selectors), self.assertRaises(InputError):
                    compare(*documents(CONTRACT['cases'][0]), explain_package_path=path, **selectors)
        for field, value in [('explain_side', 'after'), ('explain_artifact_id', 'unknown-0'),
                             ('explain_reason_code', 'ambiguous_package_location'), ('explain_match_index', 0),
                             ('explain_reason_codes_all', []), ('explain_reason_codes_any', ()),
                             ('explain_reason_codes_any', ['ambiguous_package_location'])]:
            with self.subTest(field=field), self.assertRaises(InputError):
                compare(*documents(CONTRACT['cases'][1]), explain_advisory=CONTRACT['advisory'],
                        explain_target=CONTRACT['target'], explain_package_path=CONTRACT['package_path'], **{field: value})

    def test_unknown_only_or_mismatched_normalized_selection(self):
        for case in CONTRACT['cases'][1:]:
            docs = documents(case)
            for advisory, target, path in [('UNKNOWN-ONLY', CONTRACT['target'], CONTRACT['package_path']),
                                           ('OTHER', CONTRACT['target'], ''),
                                           (CONTRACT['advisory'], 'zeta.lock', 'two')]:
                with self.subTest(case=case['name'], advisory=advisory), self.assertRaises(InputError):
                    compare(*docs, explain_advisory=advisory, explain_target=target, explain_package_path=path)
            # Same advisory is present, but only in unknown records; no normalized path exists.
            for index in (0, 1):
                if 'matches' in docs[index]:
                    docs[index]['matches'] = [m for m in docs[index]['matches'] if m['artifact']['id'].startswith('unknown-')]
                else:
                    for result in docs[index]['Results']:
                        result['Vulnerabilities'] = []
            with self.assertRaises(InputError):
                compare(*docs, explain_advisory=CONTRACT['advisory'], explain_target=CONTRACT['target'],
                        explain_package_path=CONTRACT['package_path'])

    def test_no_match_diagnostic_names_package_path(self):
        with self.assertRaises(InputError) as raised:
            compare(*documents(CONTRACT['cases'][1]), explain_advisory=CONTRACT['advisory'],
                    explain_target=CONTRACT['target'], explain_package_path='SYNTHETIC_SECRET_ABSENT')
        self.assertIn('package path', str(raised.exception))
        self.assertNotIn('SYNTHETIC_SECRET', str(raised.exception))

    def test_readme_verifier_scripts_run_directly_from_any_directory(self):
        env = {k: v for k, v in os.environ.items() if k != 'PYTHONPATH'}
        for script in ('verify_target.py', 'verify_package_path.py'):
            with self.subTest(script=script), tempfile.TemporaryDirectory() as folder:
                done = subprocess.run([sys.executable, str(ROOT / 'scripts' / 'delta' / script)], cwd=folder, env=env,
                                      capture_output=True, text=True, timeout=120)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertIn('contracts passed', done.stdout)

    def test_cli_contract(self):
        verify()


if __name__ == '__main__':
    unittest.main()
