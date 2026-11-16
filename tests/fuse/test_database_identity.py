"""Database snapshot labels are exact caller assertions, never proof of a fix."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import vulnwrench.fuse as vf

ROOT = Path(__file__).resolve().parents[2]
DATE = "2026-11-10T12:00:00Z"
SNAPSHOT = "synthetic:snapshot:A"


def reports():
    return [vf.Report.from_document("trivy", {"Results": [{"Type": "npm", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-SNAPSHOT-1", "PkgName": "demo", "InstalledVersion": "1.0"}]}]}, "found.json"),
        vf.Report.from_document("trivy", {"Results": []}, "absent.json")]


def manifest(items):
    return {"schemaVersion": "vulnfuse-coverage-1", "inputs": [
        {"scanner": r.scanner, "input": r.input_name, "sha256": r.sha256,
         "targetIdentity": "synthetic:target", "scanComplete": True, "databaseTimestamp": DATE,
         "scanPolicyIdentity": "synthetic:policy", "databaseIdentity": SNAPSHOT} for r in items]}


def merge(items, doc):
    return vf.merge_reports(items, coverage_manifest=vf.CoverageManifest.from_document(doc))


class DatabaseIdentityTests(unittest.TestCase):
    def test_equal_time_different_snapshots_retain_finding_and_provenance(self):
        items = reports()
        doc = manifest(items)
        doc["inputs"][1]["databaseIdentity"] = "synthetic:snapshot:B"
        result = merge(items, doc)
        expected = {"status": "incomparable", "reasonCodes": ["database-identity-mismatch"]}
        self.assertEqual(result["coverageAssessment"], expected)
        self.assertEqual((result["inputCount"], result["observationCount"], result["findingCount"]), (2, 1, 1))
        finding, = result["findings"]
        absence, = finding["absenceAssessments"].values()
        self.assertEqual({k: absence[k] for k in expected}, expected)
        self.assertEqual(absence["comparedTo"], [{"sourceId": finding["observations"][0]["sourceId"], **expected}])
        self.assertIs(absence["canEstablishFixed"], False)
        self.assertEqual(finding["ids"], ["CVE-SNAPSHOT-1"])
        for source in result["inputs"]:
            index = int(source["coverage"]["manifestPointer"].split("/")[-1])
            entry = result["coverageManifest"]["rawManifest"]["inputs"][index]
            self.assertEqual(source["coverage"]["databaseIdentity"], entry["databaseIdentity"])
            original = next(r for r in items if r.input_name == entry["input"])
            self.assertEqual(source["sha256"], entry["sha256"])
            self.assertEqual(source["rawReport"], original.document)
        self.assertEqual(result, merge(reversed(items), doc))
        explanation = vf.explain_finding(result, advisory="CVE-SNAPSHOT-1")
        self.assertEqual(explanation["coverageManifest"], result["coverageManifest"])
        self.assertEqual(explanation["coverageAssessment"], expected)
        self.assertEqual(explanation["finding"], finding)
        self.assertEqual(explanation["remediationAssessment"], "not-evaluated")
        self.assertIn("database-identity-mismatch", vf.render_markdown(result))

    def test_exact_labels_null_and_omission_contract(self):
        for value in [None, SNAPSHOT, 'Synthetic:snapshot:A', 'synthetic:snapshot:a',
                      'snapshot é', 'snapshot e\u0301', '<snapshot>| A']:
            for sides in [(0,), (1,), (0, 1)]:
                for omitted in (False, True) if value is None else (False,):
                    with self.subTest(value=value, sides=sides, omitted=omitted):
                        items = reports()
                        doc = manifest(items)
                        for side in sides:
                            if omitted:
                                del doc['inputs'][side]['databaseIdentity']
                            else:
                                doc['inputs'][side]['databaseIdentity'] = value
                        result = merge(items, doc)
                        if value is None:
                            expected = {'status': 'unknown', 'reasonCodes': ['database-identity-missing']}
                        elif value == SNAPSHOT or len(sides) == 2:
                            expected = {'status': 'comparable', 'reasonCodes': []}
                        else:
                            expected = {'status': 'incomparable', 'reasonCodes': ['database-identity-mismatch']}
                        self.assertEqual(result['coverageAssessment'], expected)
                        absence, = result['findings'][0]['absenceAssessments'].values()
                        self.assertEqual({k: absence[k] for k in expected}, expected)
                        self.assertIs(absence['canEstablishFixed'], False)
                        for source in result['inputs']:
                            index = int(source['coverage']['manifestPointer'].split('/')[-1])
                            self.assertEqual(source['coverage']['databaseIdentity'], doc['inputs'][index].get('databaseIdentity'))
                        if value == '<snapshot>| A':
                            md = vf.render_markdown(result)
                            self.assertNotIn('<snapshot>', md)
                            self.assertIn('&lt;snapshot&gt;', md)
        # Unicode normalization is not applied, even for visually equal labels.
        items = reports()
        doc = manifest(items)
        for entry, value in zip(doc['inputs'], ['snapshot é', 'snapshot e\u0301']):
            entry['databaseIdentity'] = value
        self.assertEqual(merge(items, doc)['coverageAssessment']['reasonCodes'], ['database-identity-mismatch'])

    def test_aggregate_empty_fully_observed_and_single_input(self):
        for kind in ('empty', 'observed', 'single'):
            items = reports()
            if kind == 'empty':
                items[0] = vf.Report.from_document('trivy', {'Results': []}, 'found.json')
            elif kind == 'observed':
                items[1] = vf.Report.from_document('trivy', items[0].document, 'absent.json')
            else:
                items = items[:1]
            for value in (SNAPSHOT, 'other', None):
                with self.subTest(kind=kind, value=value):
                    doc = manifest(items)
                    doc['inputs'][-1]['databaseIdentity'] = value
                    result = merge(items, doc)
                    expected = ({'status': 'unknown', 'reasonCodes': ['database-identity-missing']} if value is None
                                else {'status': 'incomparable', 'reasonCodes': ['database-identity-mismatch']}
                                if value != SNAPSHOT and kind != 'single' else {'status': 'comparable', 'reasonCodes': []})
                    self.assertEqual(result['coverageAssessment'], expected)
                    self.assertEqual(result['observationCount'], 0 if kind == 'empty' else len(items))
                    self.assertTrue(all(not f['absenceAssessments'] for f in result['findings']))

    def test_all_observers_and_reason_precedence(self):
        items = reports()
        items.append(vf.Report.from_document('trivy', items[0].document, 'also-found.json'))
        items.append(items[0])  # Repeated observations must remain counted.
        doc = manifest(items[:3])
        doc['inputs'][2]['databaseIdentity'] = 'other'
        result = merge(items, doc)
        absence, = result['findings'][0]['absenceAssessments'].values()
        self.assertEqual(len(absence['comparedTo']), 3)
        self.assertEqual(result['observationCount'], 3)
        self.assertEqual({c['status'] for c in absence['comparedTo']}, {'comparable', 'incomparable'})
        self.assertEqual(absence['reasonCodes'], ['database-identity-mismatch'])
        self.assertIs(absence['canEstablishFixed'], False)
        self.assertEqual(result, merge(reversed(items), doc))
        # A missing label must not conceal other known mismatches.
        doc['inputs'][1].update(databaseIdentity=None, scanComplete=False)
        result = merge(items, doc)
        self.assertEqual(result['coverageAssessment'], {'status': 'incomparable', 'reasonCodes':
            ['database-identity-mismatch', 'database-identity-missing', 'scan-incomplete']})
        absence, = result['findings'][0]['absenceAssessments'].values()
        self.assertEqual(absence['reasonCodes'], ['database-identity-missing', 'scan-incomplete'])
        self.assertEqual(absence['status'], 'incomparable')
        self.assertIs(absence['canEstablishFixed'], False)
        # Equal snapshots cannot override different declared instants.
        items = reports()
        doc = manifest(items)
        doc['inputs'][1]['databaseTimestamp'] = '2026-11-09T12:00:00Z'
        self.assertEqual(merge(items, doc)['coverageAssessment']['reasonCodes'], ['database-timestamp-mismatch'])
        doc['inputs'][1]['databaseTimestamp'] = '2026-11-10T13:00:00.000000+01:00'
        self.assertEqual(merge(items, doc)['coverageAssessment'], {'status': 'comparable', 'reasonCodes': []})

    def test_no_manifest_and_missing_entry_keep_existing_unknown_reasons(self):
        items = reports()
        doc = manifest(items)
        doc['inputs'].pop()
        for result, reason in [(vf.merge_reports(items), 'manifest-not-supplied'),
                               (merge(items, doc), 'manifest-entry-missing')]:
            self.assertEqual(result['coverageAssessment'], {'status': 'unknown', 'reasonCodes': [reason]})
            absence, = result['findings'][0]['absenceAssessments'].values()
            self.assertEqual(absence['reasonCodes'], [reason])
            self.assertIs(absence['canEstablishFixed'], False)
            undeclared = [s for s in result['inputs'] if s['coverage']['manifestPointer'] is None]
            self.assertTrue(undeclared)
            self.assertTrue(all(s['coverage']['databaseIdentity'] is None for s in undeclared))

    def test_malformed_labels_and_stale_bindings_preserve_both_outputs(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            for r in reports():
                (base / r.input_name).write_text(vf.dumps(r.document))
            items = [vf.read_report('trivy', base / r.input_name) for r in reports()]
            path, output, markdown = [base / name for name in ('coverage.json', 'out.json', 'out.md')]
            invalid = ['', ' ', ' snapshot', 'snapshot ', 'private-snapshot\nvalue', 'private-snapshot\x00',
                       'private-snapshot\x7f', 'private-snapshot\ud800', 0, 1.5, True, [], {}]
            cases = []
            for value in invalid:
                doc = manifest(items)
                doc['inputs'][1]['databaseIdentity'] = value
                cases.append(doc)
            stale = manifest(items)
            stale['inputs'][1]['sha256'] = '0' * 64
            cases.append(stale)
            unused = manifest(items)
            unused['inputs'][1]['input'] = 'private-snapshot-unused.json'
            cases.append(unused)
            for i, doc in enumerate(cases):
                with self.subTest(case=i):
                    with self.assertRaises(vf.InputError):
                        merge(items, doc)
                    path.write_text(json.dumps(doc))
                    output.write_text('json sentinel')
                    markdown.write_text('markdown sentinel')
                    failed = subprocess.run([sys.executable, '-m', 'vulnwrench', 'fuse', 'merge',
                        '--trivy', items[0].input_name, '--trivy', items[1].input_name,
                        '--coverage-manifest', str(path), '--output', str(output), '--markdown', str(markdown)],
                        cwd=ROOT, text=True, capture_output=True, timeout=60)
                    self.assertEqual(failed.returncode, 2, failed.stderr)
                    self.assertEqual(failed.stdout, '')
                    self.assertNotIn('private-snapshot', failed.stderr)
                    self.assertNotIn(str(path), failed.stderr)
                    self.assertNotIn('Traceback', failed.stderr)
                    self.assertEqual(output.read_text(), 'json sentinel')
                    self.assertEqual(markdown.read_text(), 'markdown sentinel')

    def test_file_byte_provenance_saved_roundtrip_and_tamper_rejection(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            for r in reports():
                (base / r.input_name).write_text(vf.dumps(r.document))
            items = [vf.read_report('trivy', base / r.input_name) for r in reports()]
            doc = manifest(items)
            doc['inputs'][1]['databaseIdentity'] = 'other'
            path = base / 'coverage.json'
            path.write_text(json.dumps(doc, indent=3) + '\n')
            result = vf.merge_reports(items, coverage_manifest=vf.read_coverage_manifest(path))
            provenance = result['coverageManifest']
            self.assertEqual(provenance['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(provenance['byteCount'], len(path.read_bytes()))
            self.assertEqual(provenance['digestKind'], 'file-bytes')
            self.assertEqual(provenance['rawManifest'], doc)
            saved = base / 'saved.json'
            saved.write_text(vf.dumps(result))
            for r in items:
                Path(r.input_name).unlink()
            path.unlink()
            self.assertEqual(vf.read_merged(saved), result)
            mutations = [lambda d: d['inputs'][0]['coverage'].update(databaseIdentity='tampered'),
                         lambda d: d['inputs'][0]['coverage'].pop('databaseIdentity'),
                         lambda d: d['coverageManifest']['rawManifest']['inputs'][0].update(databaseIdentity='tampered'),
                         lambda d: d.update(coverageAssessment={'status': 'comparable', 'reasonCodes': []})]
            for mutate in mutations:
                damaged = deepcopy(result)
                mutate(damaged)
                saved.write_text(vf.dumps(damaged))
                with self.assertRaises(vf.InputError):
                    vf.read_merged(saved)
